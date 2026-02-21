//! STARK Prover Library
//!
//! Generates STARK proofs for Sharpe ratio verification.
//! Can be used as a library (native or WASM) or via the CLI binary.

pub mod channel;
pub mod commit;
pub mod domain;
pub mod field;
pub mod fri;
pub mod keccak;
pub mod mock_data;
pub mod proof;
pub mod receipt_proof;
pub mod sharpe_compose;
pub mod sharpe_trace;

#[cfg(feature = "cli")]
pub mod gmx_fetcher;

#[cfg(feature = "wasm")]
pub mod wasm;

use alloy_primitives::U256;

use crate::channel::Channel;
use crate::commit::{commit_column, commit_trace_multi};
use crate::domain::{domain_generator, get_domain};
use crate::field::BN254Field;
use crate::fri::{fri_commit, fri_query_proofs};
use crate::keccak::keccak_hash_two;
use crate::mock_data::{GmxTradeRecord, SHARPE_SCALE};
use crate::proof::SerializedProof;
use crate::sharpe_compose::evaluate_sharpe_composition_on_lde;
use crate::sharpe_trace::SharpeTrace;

/// Progress stage during proof generation.
pub struct ProveProgress {
    pub stage: &'static str,
    pub detail: &'static str,
    pub percent: u8,
}

/// Horner's method: evaluate polynomial at a single point.
/// O(n) with only mul/add — no inversions.
fn eval_poly_at(coeffs: &[U256], x: U256) -> U256 {
    let mut result = U256::ZERO;
    for &c in coeffs.iter().rev() {
        result = BN254Field::add(BN254Field::mul(result, x), c);
    }
    result
}

/// Generate a STARK proof for Sharpe ratio verification.
pub fn prove_sharpe(
    trades: &[GmxTradeRecord],
    claimed_sharpe_sq_scaled: U256,
    num_queries: usize,
    dataset_commitment: Option<U256>,
) -> SerializedProof {
    prove_sharpe_with_progress(trades, claimed_sharpe_sq_scaled, num_queries, dataset_commitment, |_| {})
}

/// Generate a STARK proof for Sharpe ratio verification with progress callbacks.
pub fn prove_sharpe_with_progress(
    trades: &[GmxTradeRecord],
    claimed_sharpe_sq_scaled: U256,
    num_queries: usize,
    dataset_commitment: Option<U256>,
    on_progress: impl Fn(ProveProgress),
) -> SerializedProof {
    let blowup: u32 = 4;

    // Step 1: Generate Sharpe trace
    on_progress(ProveProgress {
        stage: "trace",
        detail: "Generating Sharpe ratio trace",
        percent: 0,
    });

    let trace = SharpeTrace::generate(trades, dataset_commitment);
    let public_inputs = trace.public_inputs(claimed_sharpe_sq_scaled);
    let log_trace_len = trace.log_len();
    let trace_len = trace.len;

    // Step 2: Compute LDE (6 columns)
    on_progress(ProveProgress {
        stage: "trace",
        detail: "Computing Low Degree Extension (6 columns)",
        percent: 10,
    });

    let log_blowup: u32 = match blowup {
        2 => 1,
        4 => 2,
        8 => 3,
        _ => 2,
    };
    let log_lde_size = log_trace_len + log_blowup;
    let lde_size = 1usize << log_lde_size;
    let lde_domain = get_domain(log_lde_size);

    // IFFT each trace column → polynomial coefficients (cached for OOD eval later)
    let mut coeffs_0 = trace.col_return.clone();
    domain::ifft(&mut coeffs_0, log_trace_len);
    let mut coeffs_1 = trace.col_return_sq.clone();
    domain::ifft(&mut coeffs_1, log_trace_len);
    let mut coeffs_2 = trace.col_cumulative_return.clone();
    domain::ifft(&mut coeffs_2, log_trace_len);
    let mut coeffs_3 = trace.col_cumulative_sq.clone();
    domain::ifft(&mut coeffs_3, log_trace_len);
    let mut coeffs_4 = trace.col_trade_count.clone();
    domain::ifft(&mut coeffs_4, log_trace_len);
    let mut coeffs_5 = trace.col_dataset_commitment.clone();
    domain::ifft(&mut coeffs_5, log_trace_len);

    // Zero-pad coefficients and FFT → LDE evaluations
    let lde_from_coeffs = |coeffs: &[U256]| -> Vec<U256> {
        let mut padded = coeffs.to_vec();
        padded.resize(lde_size, U256::ZERO);
        domain::fft(&mut padded, log_lde_size);
        padded
    };
    let trace_lde_0 = lde_from_coeffs(&coeffs_0);
    let trace_lde_1 = lde_from_coeffs(&coeffs_1);
    let trace_lde_2 = lde_from_coeffs(&coeffs_2);
    let trace_lde_3 = lde_from_coeffs(&coeffs_3);
    let trace_lde_4 = lde_from_coeffs(&coeffs_4);
    let trace_lde_5 = lde_from_coeffs(&coeffs_5);

    // Step 3: Commit to trace (6-column Merkle)
    on_progress(ProveProgress {
        stage: "commit",
        detail: "Committing to trace polynomials",
        percent: 30,
    });

    let trace_tree = commit_trace_multi(&[
        &trace_lde_0, &trace_lde_1, &trace_lde_2,
        &trace_lde_3, &trace_lde_4, &trace_lde_5,
    ]);
    let trace_commitment = trace_tree.root();

    // Step 4: Fiat-Shamir + OOD evaluation
    on_progress(ProveProgress {
        stage: "commit",
        detail: "Running Fiat-Shamir protocol",
        percent: 40,
    });

    let mut seed = public_inputs[0];
    for i in 1..4 {
        seed = keccak_hash_two(seed, public_inputs[i]);
    }
    let mut channel = Channel::new(seed);
    channel.commit(trace_commitment);
    let z = channel.draw_felt();

    let trace_gen = domain_generator(log_trace_len);
    let zg = BN254Field::mul(z, trace_gen);

    // Evaluate 6 columns at z and zg using Horner on cached coefficients
    let all_coeffs: [&[U256]; 6] = [
        &coeffs_0, &coeffs_1, &coeffs_2,
        &coeffs_3, &coeffs_4, &coeffs_5,
    ];

    let mut trace_ood_evals = [U256::ZERO; 6];
    let mut trace_ood_evals_next = [U256::ZERO; 6];
    for (j, coeffs) in all_coeffs.iter().enumerate() {
        trace_ood_evals[j] = eval_poly_at(coeffs, z);
        trace_ood_evals_next[j] = eval_poly_at(coeffs, zg);
    }

    // Draw 9 alphas
    let mut alphas = [U256::ZERO; 9];
    for i in 0..9 {
        alphas[i] = channel.draw_felt();
    }

    let composition_ood_eval = compute_sharpe_composition_at_z(
        &trace_ood_evals,
        &trace_ood_evals_next,
        z,
        trace_gen,
        trace_len as u64,
        &public_inputs,
        &alphas,
    );

    // Step 5: Composition polynomial on LDE
    on_progress(ProveProgress {
        stage: "compose",
        detail: "Computing composition polynomial on LDE",
        percent: 50,
    });

    let composition_lde = evaluate_sharpe_composition_on_lde(
        &[&trace_lde_0, &trace_lde_1, &trace_lde_2,
          &trace_lde_3, &trace_lde_4, &trace_lde_5],
        &lde_domain,
        trace_gen,
        trace_len as u64,
        &public_inputs,
        &alphas,
    );

    let composition_tree = commit_column(&composition_lde);
    let composition_commitment = composition_tree.root();
    channel.commit(composition_commitment);

    // Step 6: FRI protocol
    on_progress(ProveProgress {
        stage: "fri",
        detail: "Running FRI protocol",
        percent: 65,
    });

    let num_fri_layers = log_lde_size as usize - 2;
    let fri_commitment = fri_commit(
        &composition_lde,
        &mut channel,
        log_lde_size,
        num_fri_layers,
    );

    let query_indices = channel.draw_queries(num_queries, lde_size);

    on_progress(ProveProgress {
        stage: "fri",
        detail: "Generating query proofs",
        percent: 80,
    });

    let (query_values, query_paths, _query_path_indices) = fri_query_proofs(
        &fri_commitment,
        &query_indices,
    );

    let fri_layer_roots: Vec<U256> = fri_commitment.layers.iter()
        .map(|l| l.tree.root())
        .collect();

    // Step 7: Serialize proof
    on_progress(ProveProgress {
        stage: "done",
        detail: "Serializing proof",
        percent: 95,
    });

    let serialized = SerializedProof::new_sharpe(
        public_inputs,
        trace_commitment,
        composition_commitment,
        &fri_layer_roots,
        trace_ood_evals,
        trace_ood_evals_next,
        composition_ood_eval,
        &fri_commitment.final_poly,
        &query_indices,
        &query_values,
        &query_paths,
        num_fri_layers,
        log_trace_len,
    );

    on_progress(ProveProgress {
        stage: "done",
        detail: "Proof generation complete",
        percent: 100,
    });

    serialized
}

/// Compute Sharpe composition polynomial value at OOD point z.
fn compute_sharpe_composition_at_z(
    trace_ood_evals: &[U256; 6],
    trace_ood_evals_next: &[U256; 6],
    z: U256,
    trace_gen: U256,
    trace_len: u64,
    public_inputs: &[U256; 4],
    alphas: &[U256; 9],
) -> U256 {
    let one = U256::from(1u64);
    let scale = U256::from(SHARPE_SCALE);

    // TC0: cum_ret_next - cum_ret - ret_next
    let tc0 = BN254Field::sub(
        trace_ood_evals_next[2],
        BN254Field::add(trace_ood_evals[2], trace_ood_evals_next[0]),
    );

    // TC1: ret_sq - ret * ret
    let tc1 = BN254Field::sub(
        trace_ood_evals[1],
        BN254Field::mul(trace_ood_evals[0], trace_ood_evals[0]),
    );

    // TC2: cum_sq_next - cum_sq - ret_sq_next
    let tc2 = BN254Field::sub(
        trace_ood_evals_next[3],
        BN254Field::add(trace_ood_evals[3], trace_ood_evals_next[1]),
    );

    // TC3: trade_count_next - trade_count (immutability)
    let tc3 = BN254Field::sub(trace_ood_evals_next[4], trace_ood_evals[4]);

    // TC4: dataset_commitment_next - dataset_commitment = 0 (immutability)
    let tc4 = BN254Field::sub(trace_ood_evals_next[5], trace_ood_evals[5]);

    // Transition zerofier at z
    let z_n = BN254Field::pow(z, U256::from(trace_len));
    let zerofier_num = BN254Field::sub(z_n, one);
    let g_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));
    let zerofier_den = BN254Field::sub(z, g_last);
    let zerofier = BN254Field::div(zerofier_num, zerofier_den);

    let tq0 = BN254Field::div(tc0, zerofier);
    let tq1 = BN254Field::div(tc1, zerofier);
    let tq2 = BN254Field::div(tc2, zerofier);
    let tq3 = BN254Field::div(tc3, zerofier);
    let tq4 = BN254Field::div(tc4, zerofier);

    // Boundary constraints
    let trace_first = one;
    let den_first = BN254Field::sub(z, trace_first);
    let den_last = BN254Field::sub(z, g_last);

    // BC0: (cum_ret - ret) / (z - 1)
    let bq0 = BN254Field::div(
        BN254Field::sub(trace_ood_evals[2], trace_ood_evals[0]),
        den_first,
    );

    // BC1: (cum_sq - ret_sq) / (z - 1)
    let bq1 = BN254Field::div(
        BN254Field::sub(trace_ood_evals[3], trace_ood_evals[1]),
        den_first,
    );

    // BC2: (cum_ret - total_return) / (z - g^(N-1))
    let bq2 = BN254Field::div(
        BN254Field::sub(trace_ood_evals[2], public_inputs[1]),
        den_last,
    );

    // BC3: (cum_ret^2 * SCALE - sharpe_sq * (n * cum_sq - cum_ret^2)) / (z - g^(N-1))
    let cum_ret_sq = BN254Field::mul(trace_ood_evals[2], trace_ood_evals[2]);
    let bc3_lhs = BN254Field::mul(cum_ret_sq, scale);
    let n_cum_sq = BN254Field::mul(public_inputs[0], trace_ood_evals[3]);
    let denom_inner = BN254Field::sub(n_cum_sq, cum_ret_sq);
    let bc3_rhs = BN254Field::mul(public_inputs[2], denom_inner);
    let bc3_num = BN254Field::sub(bc3_lhs, bc3_rhs);
    let bq3 = BN254Field::div(bc3_num, den_last);

    // Combine: 5 TC + 4 BC = 9 alphas
    let mut comp = BN254Field::mul(alphas[0], tq0);
    comp = BN254Field::add(comp, BN254Field::mul(alphas[1], tq1));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[2], tq2));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[3], tq3));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[4], tq4));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[5], bq0));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[6], bq1));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[7], bq2));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[8], bq3));

    comp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_data::GmxTradeRecord;
    use crate::sharpe_trace::SharpeTrace;
    use std::time::Instant;

    #[test]
    fn test_200_trades_perf() {
        let pattern: [i64; 5] = [100, -50, 200, -100, 150];
        let trades: Vec<GmxTradeRecord> = (0..200)
            .map(|i| GmxTradeRecord::from_return_bps(pattern[i % 5]))
            .collect();

        let trace = SharpeTrace::generate(&trades, None);
        let claimed_sharpe_sq_scaled = trace.compute_sharpe_sq_scaled();

        let start = Instant::now();
        let proof = prove_sharpe(&trades, claimed_sharpe_sq_scaled, 4, None);
        let elapsed = start.elapsed();

        println!("200 trades: {:.3}s ({} ms)", elapsed.as_secs_f64(), elapsed.as_millis());

        // Verify proof structure
        assert_eq!(proof.public_inputs.len(), 4);
        assert_eq!(proof.public_inputs[0], U256::from(200u64));
        assert_eq!(proof.public_inputs[2], claimed_sharpe_sq_scaled);
        assert!(proof.commitments.len() >= 2);
        assert_eq!(proof.ood_values.len(), 13);
    }

    #[test]
    fn test_5000_trades_perf() {
        let pattern: [i64; 5] = [100, -50, 200, -100, 150];
        let trades: Vec<GmxTradeRecord> = (0..5000)
            .map(|i| GmxTradeRecord::from_return_bps(pattern[i % 5]))
            .collect();

        let trace = SharpeTrace::generate(&trades, None);
        let claimed_sharpe_sq_scaled = trace.compute_sharpe_sq_scaled();

        let start = Instant::now();
        let proof = prove_sharpe(&trades, claimed_sharpe_sq_scaled, 4, None);
        let elapsed = start.elapsed();

        println!("5000 trades: {:.3}s ({} ms)", elapsed.as_secs_f64(), elapsed.as_millis());

        assert_eq!(proof.public_inputs.len(), 4);
        assert_eq!(proof.public_inputs[0], U256::from(5000u64));
        assert_eq!(proof.public_inputs[2], claimed_sharpe_sq_scaled);
        assert!(proof.commitments.len() >= 2);
        assert_eq!(proof.ood_values.len(), 13);
    }
}
