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
pub mod channel;
pub mod domain;
pub mod fri;
pub mod proof;

use alloy_primitives::U256;

use crate::field::Fp;
use crate::poseidon::field::BN254Field;
use crate::poseidon::PoseidonHasher;

use self::air::{evaluate_transition_ood, evaluate_boundary_quotients, transition_zerofier_at};
use self::channel::Channel;
use self::domain::domain_generator;
use self::fri::verify_fri;
use self::proof::{parse_stark_proof, StarkProof};

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
        seed = PoseidonHasher::hash_two(seed, public_inputs[i]);
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
            seed1 = PoseidonHasher::hash_two(seed1, pub_inputs[i]);
        }

        let mut seed2 = pub_inputs[0];
        for i in 1..pub_inputs.len() {
            seed2 = PoseidonHasher::hash_two(seed2, pub_inputs[i]);
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

    /// Integration test: verify a real STARK proof generated by the prover.
    /// Proof: cargo run --release -- --fib-n 8 --num-queries 4
    #[test]
    fn test_verify_stark_proof_fib8() {
        use alloc::vec;

        let public_inputs = vec![
            U256::from(1u64), U256::from(1u64), U256::from(0x22u64), // fib(8) = 34
        ];

        let commitments = vec![
            u("261b681f4439a653c81fc2fa5b63802ac6dee9616d644309a13fd9b75f3b2e44"),
            u("0e7be5a2386963ac0e133f9a1a1e05bd730e6f5fdc41ee2f60c224d1db576c24"),
            u("0e7be5a2386963ac0e133f9a1a1e05bd730e6f5fdc41ee2f60c224d1db576c24"),
            u("274b6e03bff0a929b0b4c5353f9f844865e3391d6b12702010ba6e1b50a531f1"),
            u("055de90be8118c36cf08a3f66789f790315509d5112ed92f3d2e10a9489fb72e"),
        ];

        let ood_values = vec![
            u("10e8a9ddbf80db3ed21da149f87a49228cabf2d41ab5a72d6b3570dee0e50961"),
            u("1f8c73278cd4cdebd68f664b123c93df14451569d8dd956b73f7a08718555af9"),
            u("1f3240c532d8dfcd66c60d9a8a8824145a7f3c929a3eeb33e1c038b44e0e9b09"),
            u("11160d03fb3cbd987c764a174e9a6234cbbacbc6e28df5b2f3429caee6f52a45"),
            u("1af1a348ebe2f89ba86f7765269c96c38d28a4d3b35546dd0a6fc8566e2c7158"),
        ];

        let fri_final_poly = vec![
            u("2a3125adb62b5d6a48d352c766fb8b03e101f345dd98a4dea8071602d39edc74"),
            u("0fa46008613215d911da90e79bcfeeae58ac5aa2a0ea1e1f9e722555da7d3743"),
            u("0fa46008613215d911da90e79bcfeeae58ac5aa2a0ea1e1f9e722555da7d3743"),
            u("0fa46008613215d911da90e79bcfeeae58ac5aa2a0ea1e1f9e722555da7d3743"),
        ];

        let query_values = vec![
            u("0f8ba815ba2f8e57368551a288d9eeeda1259b82bafc4f936fceb49bf49afccf"),
            u("09108a5706312ce4434bdc922dddb14a1650e4430e1a54d665a3b8cbd80111c3"),
            u("2f5e8d6fc5663df7e8d4e9c5c54d07fbd619a4dc163c7f8210502026220b9bb5"),
            u("26847a1d7d6449367bca00795334bcaa9d21837aa5816ffbfe46ccad234f7b38"),
            u("2846791de33956d0ea9b0f2ce7a27e0bfa5ba693eb29bb2b67a0696248b706da"),
            u("156da832d6bbf0caf569ad409e3333e1edc5762e09ac3fef0ff0cb9305956a7e"),
            u("1ae75aa37e6f7a4356d35b2898a64de795048e4aacaa5a5d5d6ed0bbadee8afd"),
            u("1650eed6b4ea4969d19daa6e41ee6adc1354012f2098019e523436e4038d0957"),
            u("094508b863458766bf0d6e1d212f6bd60725c682273b4024e3434687a7aa67f6"),
            u("280489470a8f94610153b6b751793b250ecc98fc45b51baa94f131a12d651ede"),
            u("1a1bad1965f43f9943da923a6a0a66bef8bcfb3a593c20854dbe5877c6669de1"),
            u("2841fee1c855bfa8e3d30467d7b30114f3c2dc9cd89feccb751e413cb032233f"),
            u("0a93893dd820e9cc82a1b82ce0c9f0b8b89a319e433745bba30b3f82fa66a1cb"),
            u("24ebde49ae50db94b93124f717d1f5016d354341f3eccd02449ca9a576a3ae96"),
            u("2a2bedc7be3848da4dc6d19499a4395991f37df5808640df5d5fbdc4ba0e09e0"),
            u("2a662e086d91b0c8bf00d7701d6d10da476572107cc133b6817331fe269beb88"),
            u("156da832d6bbf0caf569ad409e3333e1edc5762e09ac3fef0ff0cb9305956a7e"),
            u("2846791de33956d0ea9b0f2ce7a27e0bfa5ba693eb29bb2b67a0696248b706da"),
            u("0000000000000000000000000000000000000000000000000000000000000000"),
            u("27cd820312d7dd0af5a2fcc1db592030eec48281b02b39e4ed70f7f5af5e49c5"),
            u("0c89f5fc468351e437d4acc11a513f50581607844b41c30718e71639e3dcc4b3"),
            u("2950852ced2ac9af0dd03e6ce27a2a03c3faae132152dde747165b06a95b80f6"),
            u("2841fee1c855bfa8e3d30467d7b30114f3c2dc9cd89feccb751e413cb032233f"),
            u("1a1bad1965f43f9943da923a6a0a66bef8bcfb3a593c20854dbe5877c6669de1"),
        ];

        let query_paths = vec![
            u("1193eddc77416c4ca3433895a72b1cc15d19577ecb57e171e6bfdde6cb4abcbb"),
            u("09e4f27d61937fba9ff0481f1b69e590dc2cc4431f7ae4cdd5c8072c2d99222e"),
            u("1be8f6edfde5ee90166d7101f1e491257cf90357af0daad83e6a0ea54b38b9ac"),
            u("1ac072913597fa4a0a53495bafbb069e4ab0221cebea453b4a938595232ea70d"),
            u("06f2ded13a1d1e37a509f3a3703f54c17814e28bdc88e1b9708568029c0b06ef"),
            u("2a1181e3bd3aef1f680ee91a07efdebbfe8e4b352c1b1e17043a0dcf3ae5b5d9"),
            u("033a25832438c4c876bb3b7042cc49dbc824e273b1dd91574f6e740f42447a02"),
            u("0af05e45cec4d36376d5b1a688b25bdeda55b5eacaa585178622a9698c6b8aa7"),
            u("16b926b37e46f9e52b21fcaafcd589d83b39077d51a3bbe8cfebbe34afb46c8b"),
            u("0841d8c31ad8622a363925f863747700399e749e11770157029e14ff08957089"),
            u("088cd3c6a761a19a79d58f46ee52295d4db70155d810399538369211cf86e48a"),
            u("1abb137bec09d940fc0de51476f053bc3db0d9ded72a6c60a159e06baa8102fe"),
            u("1c181531d1ca1c080221d6c845fa962889a92cdf5260f86c24615bf5f86a5245"),
            u("27cceedb1e9c451b3116555003bdf124cf967a2998f81361eb0648c8a0babf52"),
            u("1d30d7a41f16f00d792cbf58bf5a7f3c7ff0b04971d374704a09793da050202f"),
            u("1e316a8843d7f2f197b1e28e4ba2ec581f37579aa41c37303ccb8e8432b53f26"),
            u("05a4d8ae3ab8382b0b318a3575d68440d9e0bd2349a407c49049ba8a0940bc1b"),
            u("13f8d4f5cd8572088b0ead26a8ec7b4ea892714151c1d58381209adb8e45230d"),
            u("148d740bb99168e2c933768d5f179ae96ed8a9c519b51cff6013e9b8d7d53023"),
            u("0af05e45cec4d36376d5b1a688b25bdeda55b5eacaa585178622a9698c6b8aa7"),
            u("16b926b37e46f9e52b21fcaafcd589d83b39077d51a3bbe8cfebbe34afb46c8b"),
            u("0c130227037d6fbbefab509ef12562b38790a9be39b6a0d894854abee4f53a15"),
            u("0aba57256e70cc6f720ae88558f3ae70633c1822c0c322b72440511850f459d4"),
            u("1abb137bec09d940fc0de51476f053bc3db0d9ded72a6c60a159e06baa8102fe"),
            u("032407692f7c659aa453e5bb7daf65cde21f0af42093d1a6d665a5910d372ecd"),
            u("129037d3123d1fea2e5556fb459cda14aa51c45dd32c52cec53c8e0805c1bc35"),
            u("1f6e9e2c2f568276f20b021e494787a9a094f6f940d4b1b3a495b94fe70b77c1"),
            u("1e4196c60e80f5945d10c4dfd576887b08b4c9802dfb197bc7365134d7bc8341"),
            u("05a4d8ae3ab8382b0b318a3575d68440d9e0bd2349a407c49049ba8a0940bc1b"),
            u("1c87b434f1befc5c891a87e4a68c0f552a64d04af4c2f5d6c31ae62082294256"),
            u("17e7169d5dd864716953985dd9a700f4e42109062f258aa2d99e06542188390f"),
            u("1b3562f981812ce943978903c78dc7727f6225a6422f346a7886d214cac8bfb1"),
            u("18ad37f59a66e305efbdb1c0bb1413188559f92033bb3587620e5b2b9a87216e"),
            u("050dfa1abdeb4547f17b50bea0dfe290864ebfdb69a5893231112a6255b700ce"),
            u("207df7883a5dde4863ca732ebd49c44b74038d4e28ac9673145c0a62cae6bab9"),
            u("04eb76675b4aa42a4f07dfb09066de5da48b603f035b32e569b566dca8fcc640"),
            u("095f3405ff9ffd77eb5682d161307ffc5ae2a2359dd13bcb93bdb6e59f538ec3"),
            u("14e95af3c8ebd7fec1bf3e65b31f413b7cb05eec5dfa14e40785429e175c6afb"),
            u("2614fc45ce29068025e7c8bf6b51985ff86af56d1748a4df7fba4e99e70ce7f7"),
            u("1ac072913597fa4a0a53495bafbb069e4ab0221cebea453b4a938595232ea70d"),
            u("06f2ded13a1d1e37a509f3a3703f54c17814e28bdc88e1b9708568029c0b06ef"),
            u("1f482a5101c780c082923b60c89c1ea0c12d2680675ca9ba55a9d7941019ecc2"),
            u("293a2db91a2771e277e3b07c3b087e101d76800070f8a059c5712c0cf7f3b5fa"),
            u("0e4f2b4d65920d7c5a21563d2d8e19bbb6b4d157bed9fe4663c3add0237417d0"),
            u("16b926b37e46f9e52b21fcaafcd589d83b39077d51a3bbe8cfebbe34afb46c8b"),
            u("013cd0b6d54637b638092618132ef6dd385c8abb4165e9b09f29f4a279573742"),
            u("1d3b8933c2785758b43bb18b0bcb2cb04c26f254c65f2794ef95a3892580d076"),
            u("04eb76675b4aa42a4f07dfb09066de5da48b603f035b32e569b566dca8fcc640"),
        ];

        let query_metadata = vec![
            U256::from(4u64), U256::from(3u64), U256::from(3u64),
            U256::from(27u64), U256::from(8u64), U256::from(7u64), U256::from(28u64),
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
}
