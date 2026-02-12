//! FRI (Fast Reed-Solomon Interactive Oracle Proof) Verifier

use crate::field::Fp;
use crate::field::BN254Field;
use crate::merkle::MerkleVerifier;
use super::channel::Channel;
use super::domain;

/// Precomputed inverse of 2 in BN254 scalar field (Montgomery form).
const INV_TWO: Fp = Fp::from_raw([
    0x783c14d81ffffffe,
    0xaf982f6f0c8d1edd,
    0x8f5f7492fcfd4f45,
    0x1f37631a3d9cbfac,
]);

/// Parameters for the FRI protocol
pub struct FriParams {
    pub log_domain_size: u32,
    pub num_layers: usize,
    pub num_queries: usize,
    pub blowup_factor: u32,
}

impl FriParams {
    pub fn new(log_trace_len: u32, num_layers: usize, num_queries: usize, blowup_factor: u32) -> Self {
        let log_blowup = match blowup_factor {
            2 => 1,
            4 => 2,
            8 => 3,
            16 => 4,
            _ => 2,
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
pub fn fri_fold(fx: Fp, f_neg_x: Fp, alpha: Fp, x: Fp) -> Fp {
    let sum = BN254Field::add(fx, f_neg_x);
    let even = BN254Field::mul(sum, INV_TWO);

    let diff = BN254Field::sub(fx, f_neg_x);
    let half_diff = BN254Field::mul(diff, INV_TWO);
    let odd = BN254Field::div(half_diff, x);

    let alpha_odd = BN254Field::mul(alpha, odd);
    BN254Field::add(even, alpha_odd)
}

/// Evaluate a polynomial given its coefficients at point x (Horner's method).
pub fn evaluate_polynomial(coeffs: &[Fp], x: Fp) -> Fp {
    if coeffs.is_empty() {
        return Fp::ZERO;
    }
    let mut result = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = BN254Field::mul(result, x);
        result = BN254Field::add(result, coeffs[i]);
    }
    result
}

/// Verify FRI proof.
pub fn verify_fri(
    channel: &mut Channel,
    layer_commitments: &[Fp],
    query_values: &[Fp],
    query_auth_paths: &[Fp],
    query_indices: &[usize],
    final_poly_coeffs: &[Fp],
    params: &FriParams,
) -> bool {
    let num_layers = params.num_layers;
    let num_queries = params.num_queries;

    let mut alphas = [Fp::ZERO; 32];
    for i in 0..num_layers {
        channel.commit(layer_commitments[i]);
        alphas[i] = channel.draw_felt();
    }

    for coeff in final_poly_coeffs {
        channel.commit(*coeff);
    }

    let lde_domain_size = 1usize << params.log_domain_size;
    let mut derived_indices = [0usize; 64];
    let n = channel.draw_queries_into(&mut derived_indices, num_queries, lde_domain_size);
    if n != num_queries {
        return false;
    }
    for i in 0..num_queries {
        if derived_indices[i] != query_indices[i] {
            return false;
        }
    }

    let mut path_elements_per_query = 0usize;
    for layer in 0..num_layers {
        path_elements_per_query += (params.log_domain_size - layer as u32) as usize;
    }

    let mut layer_generators = [Fp::ZERO; 32];
    for layer in 0..num_layers {
        let layer_log_domain = params.log_domain_size - layer as u32;
        layer_generators[layer] = domain::domain_generator(layer_log_domain);
    }
    let final_log_domain = params.log_domain_size - num_layers as u32;
    let final_gen = domain::domain_generator(final_log_domain);

    let values_per_query = num_layers * 2;

    for q in 0..num_queries {
        let mut query_idx = query_indices[q];
        let value_offset = q * values_per_query;
        let query_path_start = q * path_elements_per_query;
        let mut path_cursor = query_path_start;

        let mut last_folded = Fp::ZERO;

        for layer in 0..num_layers {
            let layer_log_domain = params.log_domain_size - layer as u32;
            let layer_domain_size: u64 = 1u64 << layer_log_domain;
            let half_domain = (layer_domain_size / 2) as usize;
            let depth = layer_log_domain as usize;

            let pair_offset = value_offset + layer * 2;
            let fx = query_values[pair_offset];
            let f_neg_x = query_values[pair_offset + 1];

            let path_slice = &query_auth_paths[path_cursor..path_cursor + depth];

            let mut indices_buf = [false; 32];
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

            let x = domain::evaluate_at(layer_generators[layer], query_idx as u64);
            let folded = fri_fold(fx, f_neg_x, alphas[layer], x);

            if layer < num_layers - 1 {
                let next_fx = query_values[value_offset + (layer + 1) * 2];
                if folded != next_fx {
                    return false;
                }
            } else {
                last_folded = folded;
            }

            query_idx = query_idx % half_domain;
        }

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
    use alloy_primitives::U256;

    #[test]
    fn test_inv_two_constant() {
        let two = Fp::from_u256(U256::from(2u64));
        let result = BN254Field::mul(INV_TWO, two);
        assert_eq!(result, Fp::ONE, "INV_TWO * 2 != 1");
    }

    #[test]
    fn test_fri_fold_even_function() {
        let fx = Fp::from_u256(U256::from(42u64));
        let f_neg_x = Fp::from_u256(U256::from(42u64));
        let alpha = Fp::from_u256(U256::from(7u64));
        let x = Fp::from_u256(U256::from(3u64));

        let folded = fri_fold(fx, f_neg_x, alpha, x);
        assert_eq!(folded, Fp::from_u256(U256::from(42u64)));
    }

    #[test]
    fn test_fri_fold_linear() {
        let a = Fp::from_u256(U256::from(5u64));
        let b = Fp::from_u256(U256::from(10u64));
        let x = Fp::from_u256(U256::from(3u64));
        let alpha = Fp::from_u256(U256::from(2u64));

        let fx = BN254Field::add(BN254Field::mul(a, x), b);
        let neg_x = BN254Field::neg(x);
        let f_neg_x = BN254Field::add(BN254Field::mul(a, neg_x), b);

        let folded = fri_fold(fx, f_neg_x, alpha, x);

        let expected = BN254Field::add(b, BN254Field::mul(alpha, a));
        assert_eq!(folded, expected);
    }

    #[test]
    fn test_evaluate_polynomial() {
        let coeffs = [
            Fp::from_u256(U256::from(3u64)),
            Fp::from_u256(U256::from(2u64)),
            Fp::from_u256(U256::from(1u64)),
        ];

        assert_eq!(evaluate_polynomial(&coeffs, Fp::ZERO), Fp::from_u256(U256::from(3u64)));

        assert_eq!(
            evaluate_polynomial(&coeffs, Fp::from_u256(U256::from(1u64))),
            Fp::from_u256(U256::from(6u64))
        );

        assert_eq!(
            evaluate_polynomial(&coeffs, Fp::from_u256(U256::from(2u64))),
            Fp::from_u256(U256::from(11u64))
        );

        assert_eq!(
            evaluate_polynomial(&coeffs, Fp::from_u256(U256::from(10u64))),
            Fp::from_u256(U256::from(123u64))
        );
    }

    #[test]
    fn test_evaluate_polynomial_empty() {
        assert_eq!(evaluate_polynomial(&[], Fp::from_u256(U256::from(5u64))), Fp::ZERO);
    }

    #[test]
    fn test_evaluate_polynomial_constant() {
        let coeffs = [Fp::from_u256(U256::from(7u64))];
        assert_eq!(
            evaluate_polynomial(&coeffs, Fp::from_u256(U256::from(999u64))),
            Fp::from_u256(U256::from(7u64))
        );
    }
}
