//! Full STARK Verifier
//!
//! Integrates all components (AIR, FRI, Channel, Domain) to verify
//! STARK proofs of Fibonacci computation.
//!
//! Verification pipeline:
//! 1. Initialize Fiat-Shamir channel with public inputs
//! 2. Commit trace polynomial Merkle root
//! 3. Draw OOD evaluation point z
//! 4. Verify AIR constraints at OOD point
//! 5. Compose constraint polynomials
//! 6. Verify FRI proof on composition polynomial
//! 7. Verify query consistency via Merkle paths

pub mod air;
pub mod btc_air;
pub mod channel;
pub mod domain;
pub mod fri;
pub mod proof;
pub mod sharpe_air;

use alloy_primitives::U256;

use crate::field::Fp;
use crate::keccak_hash_two;
use crate::field::BN254Field;

use self::air::{evaluate_transition_ood, evaluate_boundary_quotients, transition_zerofier_at};
use self::channel::Channel;
use self::domain::domain_generator;
use self::fri::verify_fri;
use self::proof::{parse_stark_proof, StarkProof, parse_btc_lock_proof, BtcLockStarkProof, parse_sharpe_proof, SharpeStarkProof};

/// Default FRI blowup factor
pub const BLOWUP_FACTOR: u32 = 4;

/// Default number of FRI queries (provides ~80-bit security)
pub const NUM_QUERIES: usize = 20;

/// Verify a full STARK proof of Fibonacci computation.
///
/// # Arguments
/// * `public_inputs` - [first_a, first_b, claimed_fib_result]
///   - first_a: Initial value a[0] (typically 1)
///   - first_b: Initial value b[0] (typically 1)
///   - claimed_fib_result: The claimed Fibonacci output b[N-1]
/// * `commitments` - Merkle commitments [trace_root, comp_root, fri_roots...]
/// * `ood_values` - OOD evaluations [a(z), b(z), a(zg), b(zg), comp(z)]
/// * `fri_final_poly` - Final low-degree polynomial coefficients
/// * `query_values` - Query evaluation data (flattened)
/// * `query_paths` - Merkle authentication paths (flattened)
/// * `query_metadata` - [num_queries, num_fri_layers, log_trace_len, indices...]
///
/// # Returns
/// `true` if the STARK proof is valid
pub fn verify_stark(
    public_inputs: &[U256],
    commitments: &[U256],
    ood_values: &[U256],
    fri_final_poly: &[U256],
    query_values: &[U256],
    query_paths: &[U256],
    query_metadata: &[U256],
) -> bool {
    // Parse the proof
    let proof = match parse_stark_proof(
        commitments,
        ood_values,
        fri_final_poly,
        query_values,
        query_paths,
        query_metadata,
    ) {
        Some(p) => p,
        None => return false,
    };

    // Validate public inputs
    if public_inputs.len() < 3 {
        return false;
    }

    let pub_fp = [
        Fp::from_u256(public_inputs[0]),
        Fp::from_u256(public_inputs[1]),
        Fp::from_u256(public_inputs[2]),
    ];

    verify_parsed_proof(&proof, &pub_fp)
}

/// Verify a parsed STARK proof.
///
/// This is the core verification logic after proof parsing.
fn verify_parsed_proof(proof: &StarkProof, public_inputs: &[Fp; 3]) -> bool {
    let log_trace_len = proof.log_trace_len;
    let trace_len = 1u64 << log_trace_len;

    // =============================
    // Step 1: Initialize Fiat-Shamir channel
    // =============================
    // Seed with hash of public inputs
    let mut seed = public_inputs[0];
    for i in 1..public_inputs.len() {
        seed = keccak_hash_two(seed, public_inputs[i]);
    }
    let mut channel = Channel::new(seed);

    // =============================
    // Step 2: Commit trace and draw OOD point
    // =============================
    channel.commit(proof.trace_commitment);
    let z = channel.draw_felt();

    // =============================
    // Step 3: Verify AIR constraints at OOD point z
    // =============================
    let trace_gen = domain_generator(log_trace_len);

    // Evaluate transition constraints at z
    let transition_evals = evaluate_transition_ood(
        proof.trace_ood_evals,
        proof.trace_ood_evals_next,
    );

    // Compute transition zerofier at z
    let zerofier = transition_zerofier_at(z, trace_len, trace_gen);

    // Compute transition quotients
    let tq0 = BN254Field::div(transition_evals[0], zerofier);
    let tq1 = BN254Field::div(transition_evals[1], zerofier);

    // =============================
    // Step 4: Verify boundary constraints
    // =============================
    let trace_domain_first = Fp::ONE; // g^0 = 1
    let trace_domain_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));

    let boundary_quotients = evaluate_boundary_quotients(
        proof.trace_ood_evals,
        z,
        trace_domain_first,
        trace_domain_last,
        *public_inputs,
    );

    // =============================
    // Step 5: Compose all constraints into composition polynomial
    // =============================
    // Draw random coefficients for combining constraints
    let alpha_t0 = channel.draw_felt(); // transition constraint 0
    let alpha_t1 = channel.draw_felt(); // transition constraint 1
    let alpha_b0 = channel.draw_felt(); // boundary constraint 0
    let alpha_b1 = channel.draw_felt(); // boundary constraint 1
    let alpha_b2 = channel.draw_felt(); // boundary constraint 2

    // Composition value = sum of alpha_i * quotient_i
    let composition_at_z = {
        let mut comp = BN254Field::mul(alpha_t0, tq0);
        comp = BN254Field::add(comp, BN254Field::mul(alpha_t1, tq1));
        comp = BN254Field::add(comp, BN254Field::mul(alpha_b0, boundary_quotients[0]));
        comp = BN254Field::add(comp, BN254Field::mul(alpha_b1, boundary_quotients[1]));
        comp = BN254Field::add(comp, BN254Field::mul(alpha_b2, boundary_quotients[2]));
        comp
    };

    // =============================
    // Step 6: Verify composition commitment
    // =============================
    // The prover's claimed composition evaluation at z should match
    if composition_at_z != proof.composition_ood_eval {
        return false;
    }

    channel.commit(proof.composition_commitment);

    // Verify composition commitment equals FRI layer 0 commitment
    // (FRI operates on the composition polynomial)
    if proof.fri_layer_commitments.is_empty()
        || proof.composition_commitment != proof.fri_layer_commitments[0]
    {
        return false;
    }

    // =============================
    // Step 7: Verify FRI proof
    // =============================
    let fri_params = fri::FriParams::new(
        log_trace_len,
        proof.num_fri_layers,
        proof.query_indices.len(),
        BLOWUP_FACTOR,
    );

    let fri_valid = verify_fri(
        &mut channel,
        &proof.fri_layer_commitments,
        &proof.query_values,
        &proof.query_paths,
        &proof.query_indices,
        &proof.fri_final_poly,
        &fri_params,
    );

    if !fri_valid {
        return false;
    }

    true
}

/// Verify a full STARK proof of BTC lock verification.
///
/// # Arguments
/// * `public_inputs` - [lock_amount, timelock_height, current_height, script_type]
/// * `commitments` - Merkle commitments [trace_root, comp_root, fri_roots...]
/// * `ood_values` - OOD evaluations [5 trace at z, 5 trace at zg, comp(z)] = 11 values
/// * `fri_final_poly` - Final low-degree polynomial coefficients
/// * `query_values` - Query evaluation data (flattened)
/// * `query_paths` - Merkle authentication paths (flattened)
/// * `query_metadata` - [num_queries, num_fri_layers, log_trace_len, indices...]
pub fn verify_btc_lock_stark(
    public_inputs: &[U256],
    commitments: &[U256],
    ood_values: &[U256],
    fri_final_poly: &[U256],
    query_values: &[U256],
    query_paths: &[U256],
    query_metadata: &[U256],
) -> bool {
    let proof = match parse_btc_lock_proof(
        commitments,
        ood_values,
        fri_final_poly,
        query_values,
        query_paths,
        query_metadata,
    ) {
        Some(p) => p,
        None => return false,
    };

    if public_inputs.len() < 4 {
        return false;
    }

    // C1 fix: reject expired timelocks
    // public_inputs[1] = timelock_height, public_inputs[2] = current_height
    if public_inputs[2] >= public_inputs[1] {
        return false;
    }

    let pub_fp = [
        Fp::from_u256(public_inputs[0]),
        Fp::from_u256(public_inputs[1]),
        Fp::from_u256(public_inputs[2]),
        Fp::from_u256(public_inputs[3]),
    ];

    verify_btc_lock_parsed_proof(&proof, &pub_fp)
}

/// Verify a parsed BTC Lock STARK proof.
fn verify_btc_lock_parsed_proof(proof: &BtcLockStarkProof, public_inputs: &[Fp; 4]) -> bool {
    let log_trace_len = proof.log_trace_len;
    let trace_len = 1u64 << log_trace_len;

    // Step 1: Initialize Fiat-Shamir channel
    let mut seed = public_inputs[0];
    for i in 1..public_inputs.len() {
        seed = keccak_hash_two(seed, public_inputs[i]);
    }
    let mut channel = Channel::new(seed);

    // Step 2: Commit trace and draw OOD point
    channel.commit(proof.trace_commitment);
    let z = channel.draw_felt();

    // Step 3: Verify AIR constraints at OOD point z
    let trace_gen = domain_generator(log_trace_len);

    let transition_evals = btc_air::evaluate_transition_ood(
        proof.trace_ood_evals,
        proof.trace_ood_evals_next,
    );

    let zerofier = transition_zerofier_at(z, trace_len, trace_gen);

    // Compute 8 transition quotients
    let mut tqs = [Fp::ZERO; 8];
    for i in 0..8 {
        tqs[i] = BN254Field::div(transition_evals[i], zerofier);
    }

    // Step 4: Verify boundary constraints
    let trace_domain_first = Fp::ONE;
    let trace_domain_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));

    let boundary_quotients = btc_air::evaluate_boundary_quotients(
        proof.trace_ood_evals,
        z,
        trace_domain_first,
        trace_domain_last,
        *public_inputs,
    );

    // Step 5: Draw 12 alphas and compose
    let mut alphas = [Fp::ZERO; 12];
    for i in 0..12 {
        alphas[i] = channel.draw_felt();
    }

    let composition_at_z = {
        let mut comp = Fp::ZERO;
        // 8 transition quotients
        for i in 0..8 {
            comp = BN254Field::add(comp, BN254Field::mul(alphas[i], tqs[i]));
        }
        // 4 boundary quotients
        for i in 0..4 {
            comp = BN254Field::add(comp, BN254Field::mul(alphas[8 + i], boundary_quotients[i]));
        }
        comp
    };

    // Step 6: Verify composition commitment
    if composition_at_z != proof.composition_ood_eval {
        return false;
    }

    channel.commit(proof.composition_commitment);

    if proof.fri_layer_commitments.is_empty()
        || proof.composition_commitment != proof.fri_layer_commitments[0]
    {
        return false;
    }

    // Step 7: Verify FRI proof
    let fri_params = fri::FriParams::new(
        log_trace_len,
        proof.num_fri_layers,
        proof.query_indices.len(),
        BLOWUP_FACTOR,
    );

    let fri_valid = verify_fri(
        &mut channel,
        &proof.fri_layer_commitments,
        &proof.query_values,
        &proof.query_paths,
        &proof.query_indices,
        &proof.fri_final_poly,
        &fri_params,
    );

    if !fri_valid {
        return false;
    }

    true
}

/// Verify a full STARK proof of Sharpe ratio verification.
///
/// # Arguments
/// * `public_inputs` - [trade_count, total_return, sharpe_sq_scaled, merkle_root]
/// * `commitments` - Merkle commitments [trace_root, comp_root, fri_roots...]
/// * `ood_values` - OOD evaluations [6 trace at z, 6 trace at zg, comp(z)] = 13 values
/// * `fri_final_poly` - Final low-degree polynomial coefficients
/// * `query_values` - Query evaluation data (flattened)
/// * `query_paths` - Merkle authentication paths (flattened)
/// * `query_metadata` - [num_queries, num_fri_layers, log_trace_len, indices...]
pub fn verify_sharpe_stark(
    public_inputs: &[U256],
    commitments: &[U256],
    ood_values: &[U256],
    fri_final_poly: &[U256],
    query_values: &[U256],
    query_paths: &[U256],
    query_metadata: &[U256],
) -> bool {
    let proof = match parse_sharpe_proof(
        commitments,
        ood_values,
        fri_final_poly,
        query_values,
        query_paths,
        query_metadata,
    ) {
        Some(p) => p,
        None => return false,
    };

    if public_inputs.len() < 4 {
        return false;
    }

    let pub_fp = [
        Fp::from_u256(public_inputs[0]),
        Fp::from_u256(public_inputs[1]),
        Fp::from_u256(public_inputs[2]),
        Fp::from_u256(public_inputs[3]),
    ];

    verify_sharpe_parsed_proof(&proof, &pub_fp)
}

/// Verify a parsed Sharpe STARK proof.
fn verify_sharpe_parsed_proof(proof: &SharpeStarkProof, public_inputs: &[Fp; 4]) -> bool {
    let log_trace_len = proof.log_trace_len;
    let trace_len = 1u64 << log_trace_len;

    // Step 1: Initialize Fiat-Shamir channel
    let mut seed = public_inputs[0];
    for i in 1..public_inputs.len() {
        seed = keccak_hash_two(seed, public_inputs[i]);
    }
    let mut channel = Channel::new(seed);

    // Step 2: Commit trace and draw OOD point
    channel.commit(proof.trace_commitment);
    let z = channel.draw_felt();

    // Step 3: Verify AIR constraints at OOD point z
    let trace_gen = domain_generator(log_trace_len);

    let transition_evals = sharpe_air::evaluate_transition_ood(
        proof.trace_ood_evals,
        proof.trace_ood_evals_next,
    );

    let zerofier = transition_zerofier_at(z, trace_len, trace_gen);

    // Compute 5 transition quotients
    let mut tqs = [Fp::ZERO; 5];
    for i in 0..5 {
        tqs[i] = BN254Field::div(transition_evals[i], zerofier);
    }

    // Step 4: Verify boundary constraints
    let trace_domain_first = Fp::ONE;
    let trace_domain_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));

    let boundary_quotients = sharpe_air::evaluate_boundary_quotients(
        proof.trace_ood_evals,
        z,
        trace_domain_first,
        trace_domain_last,
        *public_inputs,
    );

    // Step 5: Draw 9 alphas and compose
    let mut alphas = [Fp::ZERO; 9];
    for i in 0..9 {
        alphas[i] = channel.draw_felt();
    }

    let composition_at_z = {
        let mut comp = Fp::ZERO;
        // 5 transition quotients
        for i in 0..5 {
            comp = BN254Field::add(comp, BN254Field::mul(alphas[i], tqs[i]));
        }
        // 4 boundary quotients
        for i in 0..4 {
            comp = BN254Field::add(comp, BN254Field::mul(alphas[5 + i], boundary_quotients[i]));
        }
        comp
    };

    // Step 6: Verify composition commitment
    if composition_at_z != proof.composition_ood_eval {
        return false;
    }

    channel.commit(proof.composition_commitment);

    if proof.fri_layer_commitments.is_empty()
        || proof.composition_commitment != proof.fri_layer_commitments[0]
    {
        return false;
    }

    // Step 7: Verify FRI proof
    let fri_params = fri::FriParams::new(
        log_trace_len,
        proof.num_fri_layers,
        proof.query_indices.len(),
        BLOWUP_FACTOR,
    );

    let fri_valid = verify_fri(
        &mut channel,
        &proof.fri_layer_commitments,
        &proof.query_values,
        &proof.query_paths,
        &proof.query_indices,
        &proof.fri_final_poly,
        &fri_params,
    );

    if !fri_valid {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compute the Fibonacci value at position N using the naive method.
    fn fibonacci_field(n: u64) -> (Fp, Fp) {
        let mut a = Fp::from_u256(U256::from(1u64));
        let mut b = Fp::from_u256(U256::from(1u64));
        for _ in 0..n.saturating_sub(1) {
            let new_b = BN254Field::add(a, b);
            a = b;
            b = new_b;
        }
        (a, b)
    }

    #[test]
    fn test_fibonacci_field_small() {
        // fib(1) = (1, 1)
        let (a, b) = fibonacci_field(1);
        assert_eq!(a, Fp::from_u256(U256::from(1u64)));
        assert_eq!(b, Fp::from_u256(U256::from(1u64)));

        // fib(2) = (1, 2)
        let (a, b) = fibonacci_field(2);
        assert_eq!(a, Fp::from_u256(U256::from(1u64)));
        assert_eq!(b, Fp::from_u256(U256::from(2u64)));

        // fib(5) = (5, 8)
        let (a, b) = fibonacci_field(5);
        assert_eq!(a, Fp::from_u256(U256::from(5u64)));
        assert_eq!(b, Fp::from_u256(U256::from(8u64)));

        // fib(10) = (55, 89)
        let (a, b) = fibonacci_field(10);
        assert_eq!(a, Fp::from_u256(U256::from(55u64)));
        assert_eq!(b, Fp::from_u256(U256::from(89u64)));
    }

    #[test]
    fn test_fibonacci_field_larger() {
        // fib(20): a=6765, b=10946
        let (a, b) = fibonacci_field(20);
        assert_eq!(a, Fp::from_u256(U256::from(6765u64)));
        assert_eq!(b, Fp::from_u256(U256::from(10946u64)));
    }

    #[test]
    fn test_channel_initialization_deterministic() {
        let pub_inputs = [
            Fp::from_u256(U256::from(1u64)),
            Fp::from_u256(U256::from(1u64)),
            Fp::from_u256(U256::from(89u64)),
        ];

        let mut seed1 = pub_inputs[0];
        for i in 1..pub_inputs.len() {
            seed1 = keccak_hash_two(seed1, pub_inputs[i]);
        }

        let mut seed2 = pub_inputs[0];
        for i in 1..pub_inputs.len() {
            seed2 = keccak_hash_two(seed2, pub_inputs[i]);
        }

        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_air_constraints_at_ood() {
        // Create a valid Fibonacci transition pair
        let current = [Fp::from_u256(U256::from(5u64)), Fp::from_u256(U256::from(8u64))];
        let next = [Fp::from_u256(U256::from(8u64)), Fp::from_u256(U256::from(13u64))];

        let evals = evaluate_transition_ood(current, next);
        assert_eq!(evals[0], Fp::ZERO);
        assert_eq!(evals[1], Fp::ZERO);
    }

    fn u(hex: &str) -> U256 {
        U256::from_str_radix(hex, 16).unwrap()
    }

    /// Integration test: verify a real STARK proof generated by the Keccak prover.
    /// Proof: cargo run --release -- --fib-n 8 --num-queries 4
    #[test]
    fn test_verify_stark_proof_fib8() {
        use alloc::vec;

        let public_inputs = vec![
            U256::from(1u64), U256::from(1u64), U256::from(0x22u64), // fib(8) = 34
        ];

        let commitments = vec![
            u("0851bac39abc8f236d555a4bd822341f4dbb404eb75728edf6fd03e428548d72"),
            u("13b2c342499bf021bc575dffd88c4583a22388045d836c0a8858e2dfc2557504"),
            u("13b2c342499bf021bc575dffd88c4583a22388045d836c0a8858e2dfc2557504"),
            u("19ae0862d2f6dc5d829b73d5cce8b5e3cb9f71c953ecf6c5a800d7797a3d4231"),
            u("00755d07539dbda999da81c7ff730d975a84b27a8740e157f8e21003e9fc25ff"),
        ];

        let ood_values = vec![
            u("09f752137992240d067d994588c0828f5def10ad86327737f6e29592517b5341"),
            u("2681e345b10916301c19ee31a1d1b655e619581fa670915fc5f3ccb0951e9138"),
            u("059f1e3daa5abbd611bfcbf0d136f9b625707ffcdfa0863f0b7d1a2c6d1e5690"),
            u("197481f23a9d80ad129435f59bfe998f7f723dd9a921b261885e203d2699847e"),
            u("2222745d85bfa98d89736b3dbf13a468cfb2ae62fb39017e5fd38975a5383342"),
        ];

        let fri_final_poly = vec![
            u("1cfb9b0560be7dc39787a3691c6c59e5d6aad1439f6b304ea409f070388be9f4"),
            u("0aaed5152e3e618d4ef5d0ccda0aa9d781d3d3c0c7a6145025734b4fa2d6f134"),
            u("0aaed5152e3e618d4ef5d0ccda0aa9d781d3d3c0c7a6145025734b4fa2d6f134"),
            u("0aaed5152e3e618d4ef5d0ccda0aa9d781d3d3c0c7a6145025734b4fa2d6f134"),
        ];

        let query_values = vec![
            u("1995704fa65668ffb7fd580bb520449d9ff0e0b576d3c517493971a2d9dbd13a"),
            u("176ed7e9da0f734544e12cbd0db7700b59425bf2ea31bee20872fdf018df661a"),
            u("079214552401573a84845acb62efb8cd951cdef673d1ed56e7b41bb7a578094b"),
            u("1e2bf2422e9023ea88aa4049246bbd657b6e954321145dd661d195637b5ab858"),
            u("1eac8146bc2760120060f928836ae9f2b162357fd37776a7731ab28f888ad4cf"),
            u("05633faeeceaa110ed1c3ec6e65bf96455e7b27d306873efc903b6379fb17752"),
            u("113a38f8e587d77f1f7178b4c28e07b9b95adb9ad3d4d0ec8bfb78469293dde3"),
            u("0e05b9ec3849c6d163d57615125f5c143f60de1a20cc48c888eaf731f90b0e4b"),
            u("227f54033b8c021e62b79f13b193615706cfbae18e681cd21843ff5d2fb96379"),
            u("199e5b51bb7b64d4287a01bbb607fd5b3eebc5b331f5bf479a4afd21a4f40f73"),
            u("06b65bffff8ee7116a458d8a989edf3f3d8290450b655de40abca49f8b2e78b6"),
            u("1d5964f5a9831a118337aa64d1280417c9c757b7f87a8cb33161c4279d0dd36b"),
            u("2eb28cd40518ab6b5b89e55319e5fecde6d79553ef07ba75d9865c136d48e4a1"),
            u("2179097e3a43d8c8b6c8168e844e1b2365cd6e609e627d7a39af199b267b158f"),
            u("1e2bf2422e9023ea88aa4049246bbd657b6e954321145dd661d195637b5ab858"),
            u("079214552401573a84845acb62efb8cd951cdef673d1ed56e7b41bb7a578094b"),
            u("1eac8146bc2760120060f928836ae9f2b162357fd37776a7731ab28f888ad4cf"),
            u("05633faeeceaa110ed1c3ec6e65bf96455e7b27d306873efc903b6379fb17752"),
            u("2707620b0d259fbe06e35f9aaf2ac1ac0f7df753f753f3b7fa008d4dcf78eb79"),
            u("0170450c6b12f23c5f521a8845d811b77ec93ee297d1158c1a9f076886f1a364"),
            u("2a994594324ca8ebc6bfbdf1fcd251fb89122fdef685e31bb2a0ccd999c294fa"),
            u("20753cdfefd6c482b63df1a802ea64d31e3d767012ffc1057c8daf5b2bb7e5e8"),
            u("1d5964f5a9831a118337aa64d1280417c9c757b7f87a8cb33161c4279d0dd36b"),
            u("06b65bffff8ee7116a458d8a989edf3f3d8290450b655de40abca49f8b2e78b6"),
        ];

        let query_paths = vec![
            u("2a7a316c364d8bfaceaa1f9681f5992df5a194fb8342c8405d667b803a21c045"),
            u("2dbcd630cde8a0c03636885ed882f9ec965ba35bb64d0d4a02b8171aadd46687"),
            u("036ff48b841edce39b8356b40b18d880e1d46b1e9bec52417e166e5e58e36482"),
            u("115d6910eabb6680e4609dea5236595be973525878d24b4722eb1f8d887a3b73"),
            u("0cd8d10b8687c6bf0563f8240671ba8bf185a0fe07539aced3b8eda6aa2196c4"),
            u("039334c5a8e44e02a07ed1737747db3377b3a2f7ce1ad4375140c957f72c6f4b"),
            u("07d0be044465f5c745014906ceadc6953d3cee201b3eeb2445a60d6762a88c6d"),
            u("1314bd6bdffcd0f674f628216ca6b70f7c90af6517f0a72384d13cf52ea7b637"),
            u("1f7e32aceeb5e4479e39efb00f3fc09f45919d25eebfb329d207d074e42f2858"),
            u("2760520b5ec3144a8aef0bd42b1088a00559581bfce3b6c9936cc091be83921a"),
            u("024b4ce94e9a25165dcf4c76a54541ac0b6b6c2460141119e115893c4aab5227"),
            u("1c05bcb0dfa121d791f6b07fca193dfb4a04edf7aca15b820b054c56541f2167"),
            u("1db6ac4ad7c88b4b26e75e48306e922b2483d92a8ebe2be3402f99af47c6785f"),
            u("28834e5ae5b54b55b09c96fe41433f1f557b7a8c90533786e5a9a0b23a12de7d"),
            u("036ff48b841edce39b8356b40b18d880e1d46b1e9bec52417e166e5e58e36482"),
            u("115d6910eabb6680e4609dea5236595be973525878d24b4722eb1f8d887a3b73"),
            u("0cd8d10b8687c6bf0563f8240671ba8bf185a0fe07539aced3b8eda6aa2196c4"),
            u("0babcd9596679f5365d85c4fd7d49cc531e57f1d0f6f005dd9d6daef4abc1cec"),
            u("05ddef5e29e074ca95116cfb04797b2462635ed036b433817000c7e170e655fc"),
            u("1314bd6bdffcd0f674f628216ca6b70f7c90af6517f0a72384d13cf52ea7b637"),
            u("1f7e32aceeb5e4479e39efb00f3fc09f45919d25eebfb329d207d074e42f2858"),
            u("20ed4e32d066fe31cf59b07d7cdd11308fa6b5ae361223a8a68ef99137e43805"),
            u("05be27a97513d2863fa1037bfdcca001ae724fdebf690a2da801db94f5e0c6ec"),
            u("1c05bcb0dfa121d791f6b07fca193dfb4a04edf7aca15b820b054c56541f2167"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("24d5bff2b83689c16b1c07a6ea2fa9443c00ae298cf754f1c5de8a2d217c8f79"),
            u("11e5afe1000ab3ceddc78a7a81108d65ac126ed41e0522d7ec1346a5c941da77"),
            u("16c44dca59660961a7545bfa1f145e328078bd83a441fff8d528269ba1ef2165"),
            u("097347b86219c19b7463dc82000b1f70f6dacbfa8c7deefc0afa3549ffc51611"),
            u("278326b729b7aa495840f163b2bda823ed1ea9cb8f1014c519de2a3c41fe59b8"),
            u("15ad0ef630fa1b252b28326b33589f737322f9f4901cdad1e17d79ccf2b1abde"),
            u("02b61548efbf3d626a2d29106b733e83081daf3f2cee4fbbe8de62e6b98f4035"),
            u("1cebefa9d9c4fbe2b260421a622c4d3e1f9a298ca663f11ddd92cd248669b021"),
            u("2760520b5ec3144a8aef0bd42b1088a00559581bfce3b6c9936cc091be83921a"),
            u("024b4ce94e9a25165dcf4c76a54541ac0b6b6c2460141119e115893c4aab5227"),
            u("1c05bcb0dfa121d791f6b07fca193dfb4a04edf7aca15b820b054c56541f2167"),
            u("21217c2afd49501d6798003ce33bcd3f7beb80755fec88fc27dae1dc76d4e844"),
            u("05229fbc71489d1f79eb01f2851db905d000b048d1689f364ef146cc5307c5dc"),
            u("2efe23b823aadefed41285e72f28454f435323df67f349bdfc1e418c204672e9"),
            u("115d6910eabb6680e4609dea5236595be973525878d24b4722eb1f8d887a3b73"),
            u("0cd8d10b8687c6bf0563f8240671ba8bf185a0fe07539aced3b8eda6aa2196c4"),
            u("1fd907a35d9d60c8c84215423bba398d5862790dfc6bb48d6f208d26a751be9f"),
            u("073d8da131dfd7b875aeaf55264fe0adefe98d289f1a33e68e7139dcb6a7282b"),
            u("032df72b4bc257a8cc81fc41bb4c7473dee0e311a1d208b27e0d4a9e9ebb19da"),
            u("1f7e32aceeb5e4479e39efb00f3fc09f45919d25eebfb329d207d074e42f2858"),
            u("032272c2d8ab02f11e238771ece9d22677a3324ecdcdc6ee958f6f35f058141c"),
            u("1d53332f3254c213f65cb92e928085960cdab8ec74e40bdd9d4005f552aaa47b"),
            u("0726e86feeb2eb3128cd7f0ffce2da34d645e09926de1fe5678b4cdaf1b1a85a"),
        ];

        let query_metadata = vec![
            U256::from(4u64), U256::from(3u64), U256::from(3u64),
            U256::from(5u64), U256::from(6u64), U256::from(29u64), U256::from(2u64),
        ];

        // Valid proof should return true
        assert!(
            verify_stark(&public_inputs, &commitments, &ood_values, &fri_final_poly,
                &query_values, &query_paths, &query_metadata),
            "Valid STARK proof should verify"
        );

        // Tampered public input should return false
        let bad_inputs = vec![U256::from(1u64), U256::from(1u64), U256::from(35u64)];
        assert!(
            !verify_stark(&bad_inputs, &commitments, &ood_values, &fri_final_poly,
                &query_values, &query_paths, &query_metadata),
            "Tampered proof should fail"
        );
    }

    /// Integration test: verify a real BTC Lock STARK proof.
    /// Proof: cargo run --features cli --release -- --mode btclock \
    ///   --lock-amount 100000 --timelock-height 900000 --current-height 850000 \
    ///   --script-type 2 --num-queries 4
    #[test]
    fn test_verify_btc_lock_proof() {
        use alloc::vec;

        let public_inputs = vec![
            U256::from(0x186a0u64),  // lock_amount = 100000
            U256::from(0xdbba0u64),  // timelock_height = 900000
            U256::from(0xcf850u64),  // current_height = 850000
            U256::from(2u64),        // script_type = P2WSH
        ];

        let commitments = vec![
            u("2a10e251a3af82569f347dc9cc13100affa2d856b1442cb9b18abb3d1a644f1e"),
            u("28cd57eb223f17d37f20f86a8168a59ad161567d925e86e751a9b1493d27aa00"),
            u("28cd57eb223f17d37f20f86a8168a59ad161567d925e86e751a9b1493d27aa00"),
            u("19dcd5ea3705cc53d3063136623f6d5b1585ef6e74614338b52e74d7e138f6c0"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
        ];

        let ood_values = vec![
            u("00000000000000000000000000000000000000000000000000000000000186a0"),
            u("08bbb7b8c841b9540ae038f0d64561208fa8ed6a1ecb62e4ed52cbd0abb6f7e4"),
            u("000000000000000000000000000000000000000000000000000000000000c350"),
            u("11776f71908372a815c071e1ac8ac2411f51dad43d96c5c9daa597a1576defc8"),
            u("0000000000000000000000000000000000000000000000000000000000000002"),
            u("00000000000000000000000000000000000000000000000000000000000186a0"),
            u("08bbb7b8c841b9540ae038f0d64561208fa8ed6a1ecb62e4ed52cbd0abb6f7e4"),
            u("000000000000000000000000000000000000000000000000000000000000c350"),
            u("11776f71908372a815c071e1ac8ac2411f51dad43d96c5c9daa597a1576defc8"),
            u("0000000000000000000000000000000000000000000000000000000000000002"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
        ];

        let fri_final_poly = vec![U256::ZERO; 4];

        let query_values = vec![U256::ZERO; 24];

        let query_paths = vec![
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("19dcd5ea3705cc53d3063136623f6d5b1585ef6e74614338b52e74d7e138f6c0"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("19dcd5ea3705cc53d3063136623f6d5b1585ef6e74614338b52e74d7e138f6c0"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("19dcd5ea3705cc53d3063136623f6d5b1585ef6e74614338b52e74d7e138f6c0"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("19dcd5ea3705cc53d3063136623f6d5b1585ef6e74614338b52e74d7e138f6c0"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
            u("28d78349cf1e996a8c9e843aca183cc6c02698676320aa051ce6fdfa9c62d042"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"),
            u("0681ccb0c2257b0735276ebdde4e1ea661b473fe8aa3f428e29b9ff332918e74"),
        ];

        let query_metadata = vec![
            U256::from(4u64), U256::from(3u64), U256::from(3u64),
            U256::from(2u64), U256::from(15u64), U256::from(21u64), U256::from(31u64),
        ];

        // Valid BTC lock proof should verify
        assert!(
            verify_btc_lock_stark(&public_inputs, &commitments, &ood_values, &fri_final_poly,
                &query_values, &query_paths, &query_metadata),
            "Valid BTC Lock STARK proof should verify"
        );

        // Tampered lock amount should fail
        let bad_inputs = vec![
            U256::from(999u64), U256::from(0xdbba0u64),
            U256::from(0xcf850u64), U256::from(2u64),
        ];
        assert!(
            !verify_btc_lock_stark(&bad_inputs, &commitments, &ood_values, &fri_final_poly,
                &query_values, &query_paths, &query_metadata),
            "Tampered BTC Lock proof should fail"
        );
    }

    /// Integration test: verify a real Sharpe ratio STARK proof (Bot A).
    /// Proof: cargo run --features cli --release -- --mode sharpe --bot a --num-queries 4
    #[test]
    fn test_verify_sharpe_proof_bot_a() {
        use alloc::vec;

        let public_inputs = vec![
            U256::from(0x0fu64),    // trade_count = 15
            U256::from(0x0bb8u64),  // total_return = 3000
            U256::from(0xea60u64),  // sharpe_sq_scaled = 60000
            u("19dcd5ea3705cc53d3063136623f6d5b1585ef6e74614338b52e74d7e138f6c0"),
        ];

        let commitments = vec![
            u("062ed9349522508b27b7d6148f471e9b077dfcc20f1330a444244dc6e7a56030"),
            u("244819fa40dde78f4c2748fdd2c9fa136aafb3d4fdecce74332d241a718db811"),
            u("244819fa40dde78f4c2748fdd2c9fa136aafb3d4fdecce74332d241a718db811"),
            u("0b60f889bfd3efdc5928b7600cc79bf7d8be2c1ec58f3161d2b01dc8008aa29c"),
            u("226d4eb16e8e60ce7b47100b50419f83fcc289cfbbf27f191ae4fd30ea464dd2"),
            u("1fe598f686a1a184d666ab7cc9a57388e1f439cd34b95148310bc96c9a632fbf"),
        ];

        let ood_values = vec![
            u("17fb3ac794657f70086eb82dbeb62854f5114bf61f6e37149d85836b32a33628"),
            u("02a3f27d8b10c8dcf06d4ea547eeb46bbdd64008aa58c10e9dc0acd49c6fcebd"),
            u("1ff66a989af152e5ff6bfd064e697c223586be4b5a6320f8fc42c3b9cd4a8b66"),
            u("23c1263bd474e1cc6a026cc40da1c088d7387942457670acef0e3983b3274d85"),
            u("000000000000000000000000000000000000000000000000000000000000000f"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("09359af957ba389fcab7a6c46690d33b2cf976ec7439db494b4306b12863af43"),
            u("1586b525e18b11cec3b07d4288f6022c7bbda82729622d29aeb1b7f2e3340088"),
            u("2f165d3b8c18a820620b5d708b098d4fb0fb73ed5c07ecca7790bc29e4b3ddf8"),
            u("222d899e0ad43673c1258f81062a8baca2bf4eaddfa4c42db720cc6642297c9c"),
            u("000000000000000000000000000000000000000000000000000000000000000f"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("0a8f238d9240981dae876615bbebbf95b01884f411650edaf12d1acc3b25843c"),
        ];

        let fri_final_poly = vec![
            u("0df610fe64dd1287bd92c2d7b6d96c3dfe0bcd93f13741d6f293e7a441a7229b"),
            u("0d6c8ec87fcf8b9288267e66309337076e388d3f0aa4aeef9c70bc82c32a2683"),
            u("11033b2d4db38fe43eed02aaf3abb0af8c2149f499ce182c613b62075bb5de73"),
            u("11033b2d4db38fe43eed02aaf3abb0af8c2149f499ce182c613b62075bb5de73"),
        ];

        let query_values = vec![
            u("27d9ecca997691cbed1114760d8f945690a410002dbe33753bd6ba75d954749c"),
            u("19f8559767ad23ecfcbb09abe21fb2ebc3c3e0adf44fe574edadf0048aeabdc3"),
            u("15aad4fe0223527912cff7f9f483f40a2ceecf1754293eb5efee74ddf9f87469"),
            u("2a0afad4aa15b6cba4a48295e7d41e1617968a00d99605afd78af4b3e730571c"),
            u("2b8124628d15379bad511b06ff875aaf32659177e5259a7d1ae9591968338d9f"),
            u("300f93ff3672538ad6d8710e7d3059c54c737629de136a4d1828b75f285207b9"),
            u("0c5e608824fbfc6f606e87d5e9bfa50ce5d6ace82e4d2506aef0620368ea3110"),
            u("2c47880a70e59be93ddda00085e5d270094cfd73e1ed9fd1afe14479b3d5a1eb"),
            u("131e1b1e153dfb4d054e17bfa4fa6329623298166cb8b66cbe5833e944cc242b"),
            u("2492949530a38462d10eedce381df8a59de0f255c96142658b5e5b8f61f4a8b8"),
            u("1ea4c0ba7ca7ada00f53ac91e610417eccb2e67a769fea17dd306cc061e18b4a"),
            u("1befd04cac47e808ebcb4ba9b6bdb3647b1b91fabef8b054debe9178c491e26c"),
            u("2c5398dc13bdc099c85174c67998b14ac0ac816b0b032224a4a4384eb832ba76"),
            u("2a2804219d3d918b1b41964f7d0583f8bbe1be79c2711acb76762f643e5af0ca"),
            u("282405a4cc79d4b4c148933d3a8c042d4875559ebbd14c879d1f444e622c86da"),
            u("1fa121fcffea66eaea48c63ecb456f66bab5e7a154196a6d5c4f2c87a8ead5bb"),
            u("0aa3b69f9fadb3c021b3d51713ca65c6e21ce14f5a3b16a5d89a795610bb75a7"),
            u("14ffb81dfc59d3b6e52e1648050733a53bae1d6026f1c9af1353a07264d54b0f"),
            u("26168c2b52fbb541dbe18e8eba8dd5c18cc1af91aeee5f509539e7339f70a4ae"),
            u("1b90f50e46bf5384ab14e7053ea86d5103db6ab004cfceb093e08a1d615ea8dd"),
            u("300f93ff3672538ad6d8710e7d3059c54c737629de136a4d1828b75f285207b9"),
            u("2b8124628d15379bad511b06ff875aaf32659177e5259a7d1ae9591968338d9f"),
            u("0c5e608824fbfc6f606e87d5e9bfa50ce5d6ace82e4d2506aef0620368ea3110"),
            u("2c47880a70e59be93ddda00085e5d270094cfd73e1ed9fd1afe14479b3d5a1eb"),
            u("2bce0773e35299c4ca7520cfdaed75ea65bc6ab6ec84f5cd30c3a119652e4805"),
            u("2751e08e0e472653cc254149846317f10ca5542f59741731f165c114cb968f7b"),
            u("0221013ddedcccca4f3392139e7d187b3a4ea0395fe850698851a7d25940921c"),
            u("2038470de5b96af4d0466f17419505ec4f4eda770e57a82b720a2945d54c319a"),
            u("1cf426dc8bee1be885fb7609ce65e5dff5251d13927107dca1da61a46629fbc1"),
            u("0b039f2d33bcab1701c9d87966f687c68235c80eb48d3abb835ae20576f364d8"),
            u("2c47880a70e59be93ddda00085e5d270094cfd73e1ed9fd1afe14479b3d5a1eb"),
            u("0c5e608824fbfc6f606e87d5e9bfa50ce5d6ace82e4d2506aef0620368ea3110"),
        ];

        let query_paths = vec![
            u("1417af592c5c5bf346902e5fb4bf6563d4fb3df74df428f7d5a055ef29d53530"),
            u("020ffa5c24166879374c2fb1320cbb31e07bec811892c529df221d8456007cb2"),
            u("162378934d8540f58ef9e5d423f0e3be0932727f12b7079410cf1c4759dd297c"),
            u("17d51ce4ec39bb2b8472aae57a63e0c08f0a277094425de658d4416023d4603c"),
            u("02369ea2710dd075b4a82dc9a291a1f1a545819a8d985fd0d890bd9e68992b0a"),
            u("1a4829627ad084661419d367486ae65236c7519d77174a665518591b1ef60a89"),
            u("1d7c1f95b249c40a6c80d48fd8c7f9f70e60ebabecc974ad65f1dbb87e0c9408"),
            u("08f4b1c5304deafcf797bc7372a7944209901100f2b61829f44a69e51cc21e7a"),
            u("17f0e2f12e4245824be94a2cfc4ff45e58cf554a53329592e4464a0a94c1c03f"),
            u("22088cf77c01752b1e91f8e3baaf4314ba7493737acbf3c6e6129bf373f610be"),
            u("141476ad3a7faffc9f8e15a2cc23e3bd7d4836ce75ceef43f46ae349a0d837d8"),
            u("130a923edf8c75d1d1f17509558c7a92592420562353e02f5d788eb4a9122bb8"),
            u("01e4f9d5e56b09a123e9025d4d2ac7b4b328042d2bc366ffbd64b244327c4a2e"),
            u("02908aed1976ff6bff42999cf7e42283ae24816def60f53838f9c810c687315e"),
            u("09d24f0b08c7539b3b88ef3df835bc33ce2f105a9ed646b9afe484ee5935e69a"),
            u("03e04534a67b50650d06784d9bfdb522d8a51e6405d8fe44903afa885178fc57"),
            u("2a842522baca97cc0e8cb7f755d0b4b0c5a221551aa2eac78f0ea31bdd85a62e"),
            u("113506143eb523eb39a81a573d355f77c6d9e67ac1c8c655914f0c2115483a62"),
            u("1c60690bce1e352eed34cf889ebb0d9af6d6cc7a849b556cb910944b5f64b743"),
            u("050c83c1eb9b32ba25b6faee7fd3c2704f58e85f3697c63360a29a250e0cd6cb"),
            u("148e87e9ba6ee8dba2f8e22d57390c1daf85e9efd96024c61fa8b90020983f75"),
            u("06637a947e6d367083b725994b75bfd8cab908318bd8a335727fbde579bd904b"),
            u("0b588a2574d36e43e1188f53db71f6ea460e7cc14f77b0632765edba103ed4af"),
            u("23bf49ea1632eeb794eb799b18157447b64b2e3f4abe5f9f2ea6f588fd453b12"),
            u("042de7bf27bdc26ba08e0c5c2c44f415f2d039da24905cdbde4a04e9a46bce52"),
            u("235475f5c06d6f1ea10ec28292e7d81dffe8424c2fbcbebeb3d3d7c7da6973e3"),
            u("2b404e068e0704783e93c971c5d15281e75489ba36b6a012f73bfc29c9ec8c1a"),
            u("1ac60467252d8e5f6292e143d8eef976e9afc08f803a39cfde26046ecc1ed386"),
            u("083d2d3dcd54680ef27400f82865c3ec13d13480a6fd3e699d58d0b4b965e9d0"),
            u("1808eb36a935d55101148872c089fcf876d5d16943ac61a5775d7d86b278e4cf"),
            u("0aef46ab89217f8d911e8c7a028368caa83bc372b45c32474b47e8e12ac37999"),
            u("02908aed1976ff6bff42999cf7e42283ae24816def60f53838f9c810c687315e"),
            u("09d24f0b08c7539b3b88ef3df835bc33ce2f105a9ed646b9afe484ee5935e69a"),
            u("2d06f5eda263de2935389fce160a550a6175b63bed4d3948b033e6a4ceefd07e"),
            u("19677d468b7f8c7e330785184f121ed5bc3c3e2e80b3959bd6a9761dcd6108a9"),
            u("113506143eb523eb39a81a573d355f77c6d9e67ac1c8c655914f0c2115483a62"),
            u("07d8e3b067d6f71eff78da021a66584169a6ee2bb494aec038920834e3a55da1"),
            u("2b5506ca50109ed6b223a1c5f5fa31c84d67d0adf913ae259ef6079884082342"),
            u("130765b0af6aad4765bb80a5dfcaf9f8c67e367dc0c87f01f3c47139abd7b242"),
            u("152afa086cd01f7c2c2f385d7ce5e7aa2c06728c3308baa6a3ec728c4015df2a"),
            u("0b588a2574d36e43e1188f53db71f6ea460e7cc14f77b0632765edba103ed4af"),
            u("23bf49ea1632eeb794eb799b18157447b64b2e3f4abe5f9f2ea6f588fd453b12"),
            u("294281ed897fd8770602e760fac1c1094291e6938fb70593d47ef79e2341c327"),
            u("0b69007657861c46899e83c4b628fadd931366fe07a666e4ae0bc69f3575f3e8"),
            u("00c583857a9ada85b3fadac9ec8154377c27a90d20b7c7f1a4e152e7ddb86364"),
            u("1cd9c0e8cc6aa9ab65f69cbc2c8f9d8e111703eccf6ecc014e03eec7605a0d3c"),
            u("083d2d3dcd54680ef27400f82865c3ec13d13480a6fd3e699d58d0b4b965e9d0"),
            u("26d04c020998e181d9cd31c25c4d353b803d9f2e73fc0d09e8ac2c8619093b62"),
            u("2b63a2eaa4da18982fb4864309554455a7476a1efb4c06f1362e1be432074584"),
            u("111e4d77a245afdc9ce9596bf40c81aa1521e726f48021132823a7edcdeb1fe0"),
            u("119ff1badb33d49dce92f7e201990a07b21d1b4bd16101e76da3afdbadcbe7ac"),
            u("03e04534a67b50650d06784d9bfdb522d8a51e6405d8fe44903afa885178fc57"),
            u("2a842522baca97cc0e8cb7f755d0b4b0c5a221551aa2eac78f0ea31bdd85a62e"),
            u("113506143eb523eb39a81a573d355f77c6d9e67ac1c8c655914f0c2115483a62"),
            u("07817a49269c70dc53b928b888390fc8756b3bbd8de1db6c90102104a2556c4c"),
            u("1d34900505592019e6a1a2ef130f90da90047b5cfd288f702ebaf0bc812ecdc5"),
            u("1c91d9f1017ef2ae0d78807b85a2571e027eddb288ec2e916efbc2c99c238341"),
            u("1aacef60890faa6c86a81af5293ea14d5e380c33a132e64e9a900039574e5851"),
            u("1f10040674f6be75802867d189856b0beae13dcbf9f21b35b4a6494dc5fd5db5"),
            u("1a4829627ad084661419d367486ae65236c7519d77174a665518591b1ef60a89"),
            u("0df68c060a5debf0f0fc797e6ebce692f14c4dda4f4a5dd0e0dfb02af344474b"),
            u("1f824d458a0983062bc1ba53b19da6dd045d4e3b590a009959022af5a726fd1c"),
            u("236a1f729d883890ef990751404628cd0e17911ad4f92d280d587f0e5307cc95"),
            u("1ac60467252d8e5f6292e143d8eef976e9afc08f803a39cfde26046ecc1ed386"),
            u("083d2d3dcd54680ef27400f82865c3ec13d13480a6fd3e699d58d0b4b965e9d0"),
            u("20d5b0aa97442abae1dafef29d7d292b00c1fa4fe67d4a540ac3518992d66fcf"),
            u("163cd3993257e412b3b88a60ac32915a94baa76cb276d348c394e5291bed6af4"),
            u("16a39de63e62427260735eed8b67130f27e4fcee9220629726421c5ea3c81a6e"),
            u("09d24f0b08c7539b3b88ef3df835bc33ce2f105a9ed646b9afe484ee5935e69a"),
            u("2c70f838ee3c6ca5712db1765d477316fecc2c19e29c6715faf6160e92c4c015"),
            u("2ac89b9f1be38d5d109688063faa294e46ec0359e098699f307931a310f3f6b9"),
            u("2fb21e640d9e11e85512805731e60fcd507c332830309c8e0a3ad881aff2c657"),
        ];

        let query_metadata = vec![
            U256::from(4u64), U256::from(4u64), U256::from(4u64),
            U256::from(0x35u64), U256::from(0x06u64), U256::from(0x0du64), U256::from(0x21u64),
        ];

        // Valid Sharpe proof should verify
        assert!(
            verify_sharpe_stark(&public_inputs, &commitments, &ood_values, &fri_final_poly,
                &query_values, &query_paths, &query_metadata),
            "Valid Sharpe STARK proof should verify"
        );

        // Tampered sharpe_sq_scaled should fail
        let bad_inputs = vec![
            U256::from(0x0fu64),
            U256::from(0x0bb8u64),
            U256::from(99999u64),  // wrong sharpe_sq_scaled
            u("19dcd5ea3705cc53d3063136623f6d5b1585ef6e74614338b52e74d7e138f6c0"),
        ];
        assert!(
            !verify_sharpe_stark(&bad_inputs, &commitments, &ood_values, &fri_final_poly,
                &query_values, &query_paths, &query_metadata),
            "Tampered Sharpe proof should fail"
        );
    }
}
