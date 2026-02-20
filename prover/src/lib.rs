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
pub mod sharpe_compose;
pub mod sharpe_trace;

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

/// Evaluate trace polynomials on the LDE domain using barycentric interpolation.
fn evaluate_trace_on_lde(
    trace_col: &[U256],
    trace_domain: &[U256],
    lde_domain: &[U256],
) -> Vec<U256> {
    let n = trace_col.len();
    let lde_size = lde_domain.len();

    let mut weights = vec![U256::from(1u64); n];
    for j in 0..n {
        for k in 0..n {
            if k != j {
                let diff = BN254Field::sub(trace_domain[j], trace_domain[k]);
                weights[j] = BN254Field::mul(weights[j], diff);
            }
        }
        weights[j] = BN254Field::inv(weights[j]);
    }

    let mut result = Vec::with_capacity(lde_size);

    for i in 0..lde_size {
        let x = lde_domain[i];

        let mut is_domain_point = false;
        for j in 0..n {
            if x == trace_domain[j] {
                result.push(trace_col[j]);
                is_domain_point = true;
                break;
            }
        }
        if is_domain_point {
            continue;
        }

        let mut numerator = U256::ZERO;
        let mut denominator = U256::ZERO;

        for j in 0..n {
            let diff = BN254Field::sub(x, trace_domain[j]);
            let diff_inv = BN254Field::inv(diff);
            let term = BN254Field::mul(weights[j], diff_inv);

            let num_term = BN254Field::mul(term, trace_col[j]);
            numerator = BN254Field::add(numerator, num_term);
            denominator = BN254Field::add(denominator, term);
        }

        result.push(BN254Field::div(numerator, denominator));
    }

    result
}

/// Evaluate trace polynomial at a single point using barycentric interpolation.
fn eval_at_point(values: &[U256], domain: &[U256], x: U256) -> U256 {
    let n = values.len();

    for i in 0..n {
        if x == domain[i] {
            return values[i];
        }
    }

    let mut weights = vec![U256::from(1u64); n];
    for j in 0..n {
        for k in 0..n {
            if k != j {
                let diff = BN254Field::sub(domain[j], domain[k]);
                weights[j] = BN254Field::mul(weights[j], diff);
            }
        }
        weights[j] = BN254Field::inv(weights[j]);
    }

    let mut numerator = U256::ZERO;
    let mut denominator = U256::ZERO;
    for j in 0..n {
        let diff = BN254Field::sub(x, domain[j]);
        let diff_inv = BN254Field::inv(diff);
        let term = BN254Field::mul(weights[j], diff_inv);

        numerator = BN254Field::add(numerator, BN254Field::mul(term, values[j]));
        denominator = BN254Field::add(denominator, term);
    }

    BN254Field::div(numerator, denominator)
}

/// Generate a STARK proof for Sharpe ratio verification.
pub fn prove_sharpe(
    trades: &[GmxTradeRecord],
    claimed_sharpe_sq_scaled: U256,
    num_queries: usize,
) -> SerializedProof {
    prove_sharpe_with_progress(trades, claimed_sharpe_sq_scaled, num_queries, |_| {})
}

/// Generate a STARK proof for Sharpe ratio verification with progress callbacks.
pub fn prove_sharpe_with_progress(
    trades: &[GmxTradeRecord],
    claimed_sharpe_sq_scaled: U256,
    num_queries: usize,
    on_progress: impl Fn(ProveProgress),
) -> SerializedProof {
    let blowup: u32 = 4;

    // Step 1: Generate Sharpe trace
    on_progress(ProveProgress {
        stage: "trace",
        detail: "Generating Sharpe ratio trace",
        percent: 0,
    });

    let trace = SharpeTrace::generate(trades);
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

    let trace_domain = get_domain(log_trace_len);
    let lde_domain = get_domain(log_lde_size);

    let trace_lde_0 = evaluate_trace_on_lde(&trace.col_return, &trace_domain, &lde_domain);
    let trace_lde_1 = evaluate_trace_on_lde(&trace.col_return_sq, &trace_domain, &lde_domain);
    let trace_lde_2 = evaluate_trace_on_lde(&trace.col_cumulative_return, &trace_domain, &lde_domain);
    let trace_lde_3 = evaluate_trace_on_lde(&trace.col_cumulative_sq, &trace_domain, &lde_domain);
    let trace_lde_4 = evaluate_trace_on_lde(&trace.col_trade_count, &trace_domain, &lde_domain);
    let trace_lde_5 = evaluate_trace_on_lde(&trace.col_dataset_commitment, &trace_domain, &lde_domain);

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

    // Evaluate 6 columns at z and zg
    let cols: [&[U256]; 6] = [
        &trace.col_return[..],
        &trace.col_return_sq[..],
        &trace.col_cumulative_return[..],
        &trace.col_cumulative_sq[..],
        &trace.col_trade_count[..],
        &trace.col_dataset_commitment[..],
    ];

    let mut trace_ood_evals = [U256::ZERO; 6];
    let mut trace_ood_evals_next = [U256::ZERO; 6];
    for (j, col) in cols.iter().enumerate() {
        trace_ood_evals[j] = eval_at_point(col, &trace_domain, z);
        trace_ood_evals_next[j] = eval_at_point(col, &trace_domain, zg);
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

    // TC4: 0 (placeholder)
    let tc4 = U256::ZERO;

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
