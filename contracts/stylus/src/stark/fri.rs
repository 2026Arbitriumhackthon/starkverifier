//! FRI (Fast Reed-Solomon Interactive Oracle Proof) Verifier
//!
//! Implements the verification side of the FRI protocol for proving
//! that a committed function is close to a polynomial of bounded degree.
//!
//! Protocol overview:
//! 1. Prover commits Merkle roots for each FRI layer
//! 2. Verifier draws folding challenges from Fiat-Shamir channel
//! 3. For each query, verifier checks:
//!    a. Merkle paths are valid
//!    b. Folding is consistent between layers
//! 4. Final layer is checked against a low-degree polynomial

use alloy_primitives::U256;

use crate::poseidon::field::BN254Field;
use crate::merkle::MerkleVerifier;
use super::channel::Channel;
use super::domain;

/// Precomputed inverse of 2 in BN254 scalar field: (p+1)/2.
/// This avoids expensive modular inversion in every FRI fold.
const INV_TWO: U256 = U256::from_limbs([
    0xa1f0fac9f8000001,
    0x9419f4243cdcb848,
    0xdc2822db40c0ac2e,
    0x183227397098d014,
]);

/// Parameters for the FRI protocol
pub struct FriParams {
    /// Log2 of the initial domain size (LDE domain)
    pub log_domain_size: u32,
    /// Number of FRI folding layers
    pub num_layers: usize,
    /// Number of query repetitions
    pub num_queries: usize,
    /// Blowup factor (typically 4)
    pub blowup_factor: u32,
}

impl FriParams {
    /// Create standard FRI parameters.
    pub fn new(log_trace_len: u32, num_layers: usize, num_queries: usize, blowup_factor: u32) -> Self {
        let log_blowup = match blowup_factor {
            2 => 1,
            4 => 2,
            8 => 3,
            16 => 4,
            _ => 2, // default to 4x blowup
        };
        FriParams {
            log_domain_size: log_trace_len + log_blowup,
            num_layers,
            num_queries,
            blowup_factor,
        }
    }
}

/// Perform FRI folding at a single point.
///
/// Given f(x) and f(-x), compute the folded value:
///   f_folded = (f(x) + f(-x)) / 2 + alpha * (f(x) - f(-x)) / (2 * x)
///
/// This combines the even and odd parts of the polynomial with the random challenge alpha.
///
/// # Arguments
/// * `fx` - f(x) evaluation at the query point
/// * `f_neg_x` - f(-x) evaluation at the symmetric point
/// * `alpha` - Folding challenge from Fiat-Shamir
/// * `x` - The domain point (x value)
pub fn fri_fold(fx: U256, f_neg_x: U256, alpha: U256, x: U256) -> U256 {
    // Even part: (f(x) + f(-x)) * inv(2)
    let sum = BN254Field::add(fx, f_neg_x);
    let even = BN254Field::mul(sum, INV_TWO);

    // Odd part: (f(x) - f(-x)) * inv(2) / x  (= (f(x) - f(-x)) / (2*x))
    let diff = BN254Field::sub(fx, f_neg_x);
    let half_diff = BN254Field::mul(diff, INV_TWO);
    let odd = BN254Field::div(half_diff, x);

    // Result: even + alpha * odd
    let alpha_odd = BN254Field::mul(alpha, odd);
    BN254Field::add(even, alpha_odd)
}

/// Evaluate a polynomial given its coefficients at point x.
///
/// Computes: sum(coeffs[i] * x^i) using Horner's method.
///
/// # Arguments
/// * `coeffs` - Polynomial coefficients [a_0, a_1, ..., a_n]
/// * `x` - Evaluation point
pub fn evaluate_polynomial(coeffs: &[U256], x: U256) -> U256 {
    if coeffs.is_empty() {
        return U256::ZERO;
    }
    // Horner's method: start from highest degree
    let mut result = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = BN254Field::mul(result, x);
        result = BN254Field::add(result, coeffs[i]);
    }
    result
}

/// Verify FRI proof.
///
/// This is the main FRI verification function. It checks:
/// 1. Each layer's folding is consistent
/// 2. Merkle paths are valid for each query
/// 3. Final polynomial evaluates correctly
///
/// # Arguments
/// * `channel` - Fiat-Shamir channel (already seeded with prior commitments)
/// * `layer_commitments` - Merkle roots for each FRI layer
/// * `query_values` - For each query, for each layer: [f(x), f(-x)] values
/// * `query_auth_paths` - Merkle authentication paths (flattened)
/// * `query_indices` - Initial query indices in the LDE domain
/// * `final_poly_coeffs` - Coefficients of the final low-degree polynomial
/// * `params` - FRI parameters
///
/// # Returns
/// `true` if the FRI proof is valid
pub fn verify_fri(
    channel: &mut Channel,
    layer_commitments: &[U256],
    query_values: &[U256],       // Flattened: [q0_l0_fx, q0_l0_fnx, q0_l1_fx, q0_l1_fnx, ...]
    query_auth_paths: &[U256],   // Flattened Merkle paths
    query_indices: &[usize],
    final_poly_coeffs: &[U256],
    params: &FriParams,
) -> bool {
    let num_layers = params.num_layers;
    let num_queries = params.num_queries;

    // Step 1: Draw folding challenges (one per layer)
    // Commit each layer root and draw alpha
    let mut alphas = [U256::ZERO; 32]; // Max 32 layers
    for i in 0..num_layers {
        channel.commit(layer_commitments[i]);
        alphas[i] = channel.draw_felt();
    }

    // Commit final polynomial coefficients
    for coeff in final_poly_coeffs {
        channel.commit(*coeff);
    }

    // Step 2: Derive query indices independently from Fiat-Shamir channel
    let lde_domain_size = 1usize << params.log_domain_size;
    let mut derived_indices = [0usize; 64]; // Max 64 queries
    let n = channel.draw_queries_into(&mut derived_indices, num_queries, lde_domain_size);
    if n != num_queries {
        return false;
    }
    for i in 0..num_queries {
        if derived_indices[i] != query_indices[i] {
            return false;
        }
    }

    // Pre-compute path elements per query:
    // Layer L has tree depth = log_domain_size - L
    // Total path elements per query = sum(log_domain_size - L) for L in 0..num_layers
    let mut path_elements_per_query = 0usize;
    for layer in 0..num_layers {
        path_elements_per_query += (params.log_domain_size - layer as u32) as usize;
    }

    // Pre-compute domain generators for each layer + final domain
    // This avoids repeated exponentiation inside the query loop
    let mut layer_generators = [U256::ZERO; 32]; // Max 32 layers
    for layer in 0..num_layers {
        let layer_log_domain = params.log_domain_size - layer as u32;
        layer_generators[layer] = domain::domain_generator(layer_log_domain);
    }
    let final_log_domain = params.log_domain_size - num_layers as u32;
    let final_gen = domain::domain_generator(final_log_domain);

    // Step 3: For each query, verify Merkle paths + folding consistency
    let values_per_query = num_layers * 2; // [f(x), f(-x)] per layer

    for q in 0..num_queries {
        let mut query_idx = query_indices[q];
        let value_offset = q * values_per_query;
        let query_path_start = q * path_elements_per_query;
        let mut path_cursor = query_path_start;

        let mut last_folded = U256::ZERO;

        for layer in 0..num_layers {
            let layer_log_domain = params.log_domain_size - layer as u32;
            let layer_domain_size: u64 = 1u64 << layer_log_domain;
            let half_domain = (layer_domain_size / 2) as usize;
            let depth = layer_log_domain as usize;

            // Get f(x) and f(-x) for this query at this layer
            let pair_offset = value_offset + layer * 2;
            let fx = query_values[pair_offset];
            let f_neg_x = query_values[pair_offset + 1];

            // --- Merkle path verification for f(x) ---
            // Leaf = fx (raw evaluation, matching prover's commit_column)
            let path_slice = &query_auth_paths[path_cursor..path_cursor + depth];

            // Derive path indices from query_idx bit decomposition
            // Bit k of query_idx determines left/right at level k
            let mut indices_buf = [false; 32]; // Max depth 32
            for k in 0..depth {
                indices_buf[k] = ((query_idx >> k) & 1) == 1;
            }

            if !MerkleVerifier::verify(
                layer_commitments[layer],
                fx,
                path_slice,
                &indices_buf[..depth],
            ) {
                return false;
            }

            path_cursor += depth;

            // --- Cross-layer folding consistency ---
            // Compute the domain point x using precomputed generator
            let x = domain::evaluate_at(layer_generators[layer], query_idx as u64);
            let folded = fri_fold(fx, f_neg_x, alphas[layer], x);

            if layer < num_layers - 1 {
                // Folded value must equal f(x) of the next layer
                let next_fx = query_values[value_offset + (layer + 1) * 2];
                if folded != next_fx {
                    return false;
                }
            } else {
                last_folded = folded;
            }

            // Next layer: query_idx halves
            query_idx = query_idx % half_domain;
        }

        // Verify final polynomial evaluation matches last folded value
        let final_x = domain::evaluate_at(final_gen, query_idx as u64);
        let expected = evaluate_polynomial(final_poly_coeffs, final_x);

        if last_folded != expected {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inv_two_constant() {
        // INV_TWO * 2 should equal 1 (mod p)
        let two = U256::from(2u64);
        let result = BN254Field::mul(INV_TWO, two);
        assert_eq!(result, U256::from(1u64), "INV_TWO * 2 != 1");
    }

    #[test]
    fn test_fri_fold_even_function() {
        // For an even function: f(x) = f(-x)
        // Folded should be f(x) regardless of alpha
        let fx = U256::from(42u64);
        let f_neg_x = U256::from(42u64);
        let alpha = U256::from(7u64);
        let x = U256::from(3u64);

        let folded = fri_fold(fx, f_neg_x, alpha, x);
        // even = (42+42)/2 = 42, odd = (42-42)/(2*3) = 0
        // folded = 42 + 7*0 = 42
        assert_eq!(folded, U256::from(42u64));
    }

    #[test]
    fn test_fri_fold_linear() {
        // f(x) = a*x + b, so f(x) = a*x + b, f(-x) = -a*x + b
        // even = b, odd = a
        // folded = b + alpha * a
        let a = U256::from(5u64);
        let b = U256::from(10u64);
        let x = U256::from(3u64);
        let alpha = U256::from(2u64);

        // f(x) = 5*3 + 10 = 25
        let fx = BN254Field::add(BN254Field::mul(a, x), b);
        // f(-x) = -5*3 + 10 = -5 (mod p)
        let neg_x = BN254Field::neg(x);
        let f_neg_x = BN254Field::add(BN254Field::mul(a, neg_x), b);

        let folded = fri_fold(fx, f_neg_x, alpha, x);

        // Expected: b + alpha * a = 10 + 2*5 = 20
        let expected = BN254Field::add(b, BN254Field::mul(alpha, a));
        assert_eq!(folded, expected);
    }

    #[test]
    fn test_evaluate_polynomial() {
        // p(x) = 3 + 2x + x^2
        let coeffs = [U256::from(3u64), U256::from(2u64), U256::from(1u64)];

        // p(0) = 3
        assert_eq!(evaluate_polynomial(&coeffs, U256::ZERO), U256::from(3u64));

        // p(1) = 3 + 2 + 1 = 6
        assert_eq!(
            evaluate_polynomial(&coeffs, U256::from(1u64)),
            U256::from(6u64)
        );

        // p(2) = 3 + 4 + 4 = 11
        assert_eq!(
            evaluate_polynomial(&coeffs, U256::from(2u64)),
            U256::from(11u64)
        );

        // p(10) = 3 + 20 + 100 = 123
        assert_eq!(
            evaluate_polynomial(&coeffs, U256::from(10u64)),
            U256::from(123u64)
        );
    }

    #[test]
    fn test_evaluate_polynomial_empty() {
        assert_eq!(evaluate_polynomial(&[], U256::from(5u64)), U256::ZERO);
    }

    #[test]
    fn test_evaluate_polynomial_constant() {
        let coeffs = [U256::from(7u64)];
        assert_eq!(
            evaluate_polynomial(&coeffs, U256::from(999u64)),
            U256::from(7u64)
        );
    }
}
