//! STARK Prover Library
//!
//! Generates STARK proofs for Fibonacci computation.
//! Can be used as a library (native or WASM) or via the CLI binary.

pub mod channel;
pub mod commit;
pub mod compose;
pub mod domain;
pub mod field;
pub mod fri;
pub mod keccak;
pub mod poseidon;
pub mod proof;
pub mod trace;

#[cfg(feature = "wasm")]
pub mod wasm;

use alloy_primitives::U256;

use crate::channel::Channel;
use crate::commit::{commit_column, commit_trace};
use crate::compose::evaluate_composition_on_lde;
use crate::domain::{domain_generator, get_domain};
use crate::field::BN254Field;
use crate::fri::{fri_commit, fri_query_proofs};
use crate::keccak::keccak_hash_two;
use crate::proof::SerializedProof;
use crate::trace::FibonacciTrace;

/// Progress stage during proof generation.
pub struct ProveProgress {
    pub stage: &'static str,
    pub detail: &'static str,
    pub percent: u8,
}

/// Generate a STARK proof for Fibonacci computation.
///
/// # Arguments
/// * `fib_n` - Number of Fibonacci steps
/// * `num_queries` - Number of FRI queries (more = more secure)
///
/// # Returns
/// A `SerializedProof` ready for on-chain submission.
pub fn prove_fibonacci(fib_n: usize, num_queries: usize) -> SerializedProof {
    prove_fibonacci_with_progress(fib_n, num_queries, |_| {})
}

/// Generate a STARK proof with progress callbacks.
///
/// # Arguments
/// * `fib_n` - Number of Fibonacci steps
/// * `num_queries` - Number of FRI queries
/// * `on_progress` - Callback for progress updates
pub fn prove_fibonacci_with_progress(
    fib_n: usize,
    num_queries: usize,
    on_progress: impl Fn(ProveProgress),
) -> SerializedProof {
    let blowup: u32 = 4;

    // Step 1: Generate Fibonacci trace
    on_progress(ProveProgress {
        stage: "trace",
        detail: "Generating Fibonacci trace",
        percent: 0,
    });

    let trace = FibonacciTrace::generate(fib_n);
    let public_inputs = trace.public_inputs();
    let log_trace_len = trace.log_len();
    let trace_len = trace.len;

    // Step 2: Compute LDE
    on_progress(ProveProgress {
        stage: "trace",
        detail: "Computing Low Degree Extension",
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

    let trace_lde_a = evaluate_trace_on_lde(&trace.col_a, &trace_domain, &lde_domain);
    let trace_lde_b = evaluate_trace_on_lde(&trace.col_b, &trace_domain, &lde_domain);

    // Step 3: Commit to trace
    on_progress(ProveProgress {
        stage: "commit",
        detail: "Committing to trace polynomials",
        percent: 30,
    });

    let trace_tree = commit_trace(&trace_lde_a, &trace_lde_b);
    let trace_commitment = trace_tree.root();

    // Step 4: Fiat-Shamir + OOD evaluation
    on_progress(ProveProgress {
        stage: "commit",
        detail: "Running Fiat-Shamir protocol",
        percent: 40,
    });

    let mut seed = public_inputs[0];
    for i in 1..3 {
        seed = keccak_hash_two(seed, public_inputs[i]);
    }
    let mut channel = Channel::new(seed);
    channel.commit(trace_commitment);
    let z = channel.draw_felt();

    let trace_gen = domain_generator(log_trace_len);
    let zg = BN254Field::mul(z, trace_gen);

    let trace_ood_a_z = eval_at_point(&trace.col_a, &trace_domain, z);
    let trace_ood_b_z = eval_at_point(&trace.col_b, &trace_domain, z);
    let trace_ood_a_zg = eval_at_point(&trace.col_a, &trace_domain, zg);
    let trace_ood_b_zg = eval_at_point(&trace.col_b, &trace_domain, zg);

    let trace_ood_evals = [trace_ood_a_z, trace_ood_b_z];
    let trace_ood_evals_next = [trace_ood_a_zg, trace_ood_b_zg];

    let alpha_t0 = channel.draw_felt();
    let alpha_t1 = channel.draw_felt();
    let alpha_b0 = channel.draw_felt();
    let alpha_b1 = channel.draw_felt();
    let alpha_b2 = channel.draw_felt();
    let alphas = [alpha_t0, alpha_t1, alpha_b0, alpha_b1, alpha_b2];

    let composition_ood_eval = compute_composition_at_z(
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

    let composition_lde = evaluate_composition_on_lde(
        &trace_lde_a,
        &trace_lde_b,
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

    let serialized = SerializedProof::new(
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

/// Compute composition polynomial value at OOD point z.
fn compute_composition_at_z(
    trace_ood_evals: &[U256; 2],
    trace_ood_evals_next: &[U256; 2],
    z: U256,
    trace_gen: U256,
    trace_len: u64,
    public_inputs: &[U256; 3],
    alphas: &[U256; 5],
) -> U256 {
    let tc0 = BN254Field::sub(trace_ood_evals_next[0], trace_ood_evals[1]);
    let tc1 = BN254Field::sub(
        trace_ood_evals_next[1],
        BN254Field::add(trace_ood_evals[0], trace_ood_evals[1]),
    );

    let z_n = BN254Field::pow(z, U256::from(trace_len));
    let zerofier_num = BN254Field::sub(z_n, U256::from(1u64));
    let g_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));
    let zerofier_den = BN254Field::sub(z, g_last);
    let zerofier = BN254Field::div(zerofier_num, zerofier_den);

    let tq0 = BN254Field::div(tc0, zerofier);
    let tq1 = BN254Field::div(tc1, zerofier);

    let trace_first = U256::from(1u64);
    let trace_last = g_last;

    let den_first = BN254Field::sub(z, trace_first);
    let den_last = BN254Field::sub(z, trace_last);

    let bq0 = BN254Field::div(BN254Field::sub(trace_ood_evals[0], public_inputs[0]), den_first);
    let bq1 = BN254Field::div(BN254Field::sub(trace_ood_evals[1], public_inputs[1]), den_first);
    let bq2 = BN254Field::div(BN254Field::sub(trace_ood_evals[1], public_inputs[2]), den_last);

    let mut comp = BN254Field::mul(alphas[0], tq0);
    comp = BN254Field::add(comp, BN254Field::mul(alphas[1], tq1));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[2], bq0));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[3], bq1));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[4], bq2));

    comp
}
