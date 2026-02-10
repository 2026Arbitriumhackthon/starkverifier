//! STARK Prover CLI
//!
//! Generates STARK proofs for Fibonacci computation.
//! The generated proof can be submitted to the on-chain verifier.
//!
//! Usage:
//!   cargo run -- --fib-n 64
//!   cargo run -- --fib-n 64 --num-queries 20

mod channel;
mod commit;
mod compose;
mod domain;
mod field;
mod fri;
mod poseidon;
mod proof;
mod trace;

use alloy_primitives::U256;
use clap::Parser;

use crate::channel::Channel;
use crate::commit::{commit_column, commit_trace, MerkleTree};
use crate::compose::evaluate_composition_on_lde;
use crate::domain::{domain_generator, evaluate_at, get_domain};
use crate::field::BN254Field;
use crate::fri::{fri_commit, fri_query_proofs};
use crate::poseidon::PoseidonHasher;
use crate::proof::SerializedProof;
use crate::trace::FibonacciTrace;

/// STARK Prover for Fibonacci computation
#[derive(Parser, Debug)]
#[command(name = "stark-prover")]
#[command(about = "Generate STARK proofs for Fibonacci computation")]
struct Args {
    /// Number of Fibonacci steps (will be padded to power of 2)
    #[arg(long, default_value_t = 64)]
    fib_n: usize,

    /// Number of FRI queries (more = more secure, ~4 bits per query)
    #[arg(long, default_value_t = 20)]
    num_queries: usize,

    /// FRI blowup factor (LDE domain size = trace_len * blowup)
    #[arg(long, default_value_t = 4)]
    blowup: u32,

    /// Output format: json or hex
    #[arg(long, default_value = "json")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Evaluate trace polynomials on the LDE domain using naive interpolation.
///
/// For a trace of length N on domain D, evaluates the interpolation
/// polynomial on the extended LDE domain of size N * blowup.
fn evaluate_trace_on_lde(
    trace_col: &[U256],
    trace_domain: &[U256],
    lde_domain: &[U256],
) -> Vec<U256> {
    let n = trace_col.len();
    let lde_size = lde_domain.len();

    // Barycentric interpolation weights
    // For domain D = {d_0, ..., d_{n-1}}, weight w_j = 1 / prod_{k!=j}(d_j - d_k)
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

        // Check if x is one of the trace domain points
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

        // Barycentric formula: f(x) = L(x) * sum_j (w_j * f_j / (x - d_j))
        // where L(x) = prod_j (x - d_j)
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

fn main() {
    let args = Args::parse();

    println!("=== STARK Prover for Fibonacci ===");
    println!("Fibonacci steps: {}", args.fib_n);
    println!("FRI queries: {}", args.num_queries);
    println!("Blowup factor: {}", args.blowup);
    println!();

    // Step 1: Generate Fibonacci trace
    println!("[1/7] Generating Fibonacci trace...");
    let trace = FibonacciTrace::generate(args.fib_n);
    let public_inputs = trace.public_inputs();
    let log_trace_len = trace.log_len();
    let trace_len = trace.len;

    if args.verbose {
        println!("  Trace length: {} (2^{})", trace_len, log_trace_len);
        println!("  Public inputs: a[0]={}, b[0]={}, b[N-1]={}",
            public_inputs[0], public_inputs[1], public_inputs[2]);
    }

    // Step 2: Compute LDE (Low Degree Extension)
    println!("[2/7] Computing Low Degree Extension...");
    let log_blowup = match args.blowup {
        2 => 1u32,
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

    if args.verbose {
        println!("  LDE size: {} (2^{})", lde_size, log_lde_size);
    }

    // Step 3: Commit to trace
    println!("[3/7] Committing to trace polynomials...");
    let trace_tree = commit_trace(&trace_lde_a, &trace_lde_b);
    let trace_commitment = trace_tree.root();

    if args.verbose {
        println!("  Trace commitment: 0x{:064x}", trace_commitment);
    }

    // Step 4: Initialize Fiat-Shamir and draw challenges
    println!("[4/7] Running Fiat-Shamir protocol...");
    let mut seed = public_inputs[0];
    for i in 1..3 {
        seed = PoseidonHasher::hash_two(seed, public_inputs[i]);
    }
    let mut channel = Channel::new(seed);

    channel.commit(trace_commitment);
    let z = channel.draw_felt(); // OOD evaluation point

    if args.verbose {
        println!("  OOD point z: 0x{:064x}", z);
    }

    // Evaluate trace at OOD point z and z*g
    let trace_gen = domain_generator(log_trace_len);
    let zg = BN254Field::mul(z, trace_gen);

    // Evaluate trace columns at z and zg using barycentric interpolation
    let trace_ood_a_z = eval_at_point(&trace.col_a, &trace_domain, z);
    let trace_ood_b_z = eval_at_point(&trace.col_b, &trace_domain, z);
    let trace_ood_a_zg = eval_at_point(&trace.col_a, &trace_domain, zg);
    let trace_ood_b_zg = eval_at_point(&trace.col_b, &trace_domain, zg);

    let trace_ood_evals = [trace_ood_a_z, trace_ood_b_z];
    let trace_ood_evals_next = [trace_ood_a_zg, trace_ood_b_zg];

    // Draw composition challenge coefficients
    let alpha_t0 = channel.draw_felt();
    let alpha_t1 = channel.draw_felt();
    let alpha_b0 = channel.draw_felt();
    let alpha_b1 = channel.draw_felt();
    let alpha_b2 = channel.draw_felt();
    let alphas = [alpha_t0, alpha_t1, alpha_b0, alpha_b1, alpha_b2];

    // Compute composition polynomial value at OOD point
    let composition_ood_eval = compute_composition_at_z(
        &trace_ood_evals,
        &trace_ood_evals_next,
        z,
        trace_gen,
        trace_len as u64,
        &public_inputs,
        &alphas,
    );

    // Step 5: Evaluate composition on LDE domain
    println!("[5/7] Computing composition polynomial on LDE...");
    let composition_lde = evaluate_composition_on_lde(
        &trace_lde_a,
        &trace_lde_b,
        &lde_domain,
        trace_gen,
        trace_len as u64,
        &public_inputs,
        &alphas,
    );

    // Commit to composition polynomial
    let composition_tree = commit_column(&composition_lde);
    let composition_commitment = composition_tree.root();
    channel.commit(composition_commitment);

    if args.verbose {
        println!("  Composition commitment: 0x{:064x}", composition_commitment);
    }

    // Step 6: FRI protocol
    println!("[6/7] Running FRI protocol...");
    let num_fri_layers = log_lde_size as usize - 2; // Leave final domain of size 4
    let fri_commitment = fri_commit(
        &composition_lde,
        &mut channel,
        log_lde_size,
        num_fri_layers,
    );

    // Draw query indices
    let query_indices = channel.draw_queries(args.num_queries, lde_size);

    // Generate query proofs
    let (query_values, query_paths, _query_path_indices) = fri_query_proofs(
        &fri_commitment,
        &query_indices,
    );

    let fri_layer_roots: Vec<U256> = fri_commitment.layers.iter()
        .map(|l| l.tree.root())
        .collect();

    if args.verbose {
        println!("  FRI layers: {}", num_fri_layers);
        println!("  Final polynomial degree: {}", fri_commitment.final_poly.len() - 1);
        println!("  Query indices: {:?}", &query_indices[..5.min(query_indices.len())]);
    }

    // Step 7: Serialize proof
    println!("[7/7] Serializing proof...");
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

    println!();
    println!("{}", serialized.summary());
    println!();

    match args.format.as_str() {
        "json" => {
            println!("{}", serialized.to_json());
        }
        "hex" => {
            println!("{}", crate::proof::encode_calldata_hex(&serialized));
        }
        _ => {
            eprintln!("Unknown format: {}", args.format);
        }
    }
}

/// Evaluate trace polynomial at a single point using barycentric interpolation.
fn eval_at_point(values: &[U256], domain: &[U256], x: U256) -> U256 {
    let n = values.len();

    // Check if x is a domain point
    for i in 0..n {
        if x == domain[i] {
            return values[i];
        }
    }

    // Barycentric weights
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
    // Transition constraints at z
    let tc0 = BN254Field::sub(trace_ood_evals_next[0], trace_ood_evals[1]);
    let tc1 = BN254Field::sub(
        trace_ood_evals_next[1],
        BN254Field::add(trace_ood_evals[0], trace_ood_evals[1]),
    );

    // Transition zerofier at z
    let z_n = BN254Field::pow(z, U256::from(trace_len));
    let zerofier_num = BN254Field::sub(z_n, U256::from(1u64));
    let g_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));
    let zerofier_den = BN254Field::sub(z, g_last);
    let zerofier = BN254Field::div(zerofier_num, zerofier_den);

    let tq0 = BN254Field::div(tc0, zerofier);
    let tq1 = BN254Field::div(tc1, zerofier);

    // Boundary quotients at z
    let trace_first = U256::from(1u64);
    let trace_last = g_last;

    let den_first = BN254Field::sub(z, trace_first);
    let den_last = BN254Field::sub(z, trace_last);

    let bq0 = BN254Field::div(BN254Field::sub(trace_ood_evals[0], public_inputs[0]), den_first);
    let bq1 = BN254Field::div(BN254Field::sub(trace_ood_evals[1], public_inputs[1]), den_first);
    let bq2 = BN254Field::div(BN254Field::sub(trace_ood_evals[1], public_inputs[2]), den_last);

    // Combine
    let mut comp = BN254Field::mul(alphas[0], tq0);
    comp = BN254Field::add(comp, BN254Field::mul(alphas[1], tq1));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[2], bq0));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[3], bq1));
    comp = BN254Field::add(comp, BN254Field::mul(alphas[4], bq2));

    comp
}
