//! Poseidon Hash Implementation for BN254 Field
//!
//! Implements Poseidon hash function with:
//! - Field: BN254 (alt_bn128) prime field
//! - Width: t=3 (2 inputs + 1 capacity element)
//! - S-box: x^5
//! - Rounds: 8 full rounds + 57 partial rounds

use crate::field::Fp;

pub mod constants;
pub mod field;

use constants::{MDS_MATRIX, ROUND_CONSTANTS};
use field::BN254Field;

/// Poseidon hasher for BN254 field
pub struct PoseidonHasher;

impl PoseidonHasher {
    /// State width (t=3 for 2-input hash)
    const T: usize = 3;
    /// Number of full rounds
    const FULL_ROUNDS: usize = 8;
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize = 57;

    /// Hash two field elements using Poseidon
    #[inline]
    pub fn hash_two(a: Fp, b: Fp) -> Fp {
        // Initialize state: [0, a, b]
        let mut state = [Fp::ZERO, a, b];

        let half_full = Self::FULL_ROUNDS / 2;
        let mut round_ctr = 0;

        // First half of full rounds
        for _ in 0..half_full {
            Self::full_round(&mut state, round_ctr);
            round_ctr += Self::T;
        }

        // Partial rounds
        for _ in 0..Self::PARTIAL_ROUNDS {
            Self::partial_round(&mut state, round_ctr);
            round_ctr += Self::T;
        }

        // Second half of full rounds
        for _ in 0..half_full {
            Self::full_round(&mut state, round_ctr);
            round_ctr += Self::T;
        }

        // Return first state element as hash output
        state[0]
    }

    /// Full round: apply round constants, S-box to all elements, then MDS
    #[inline(always)]
    fn full_round(state: &mut [Fp; 3], round_ctr: usize) {
        for i in 0..Self::T {
            state[i] = BN254Field::add(state[i], ROUND_CONSTANTS[round_ctr + i]);
        }
        for i in 0..Self::T {
            state[i] = Self::sbox(state[i]);
        }
        Self::mds_multiply(state);
    }

    /// Partial round: apply round constants, S-box only to first element, then MDS
    #[inline(always)]
    fn partial_round(state: &mut [Fp; 3], round_ctr: usize) {
        for i in 0..Self::T {
            state[i] = BN254Field::add(state[i], ROUND_CONSTANTS[round_ctr + i]);
        }
        state[0] = Self::sbox(state[0]);
        Self::mds_multiply(state);
    }

    /// S-box: compute x^5 in the field
    #[inline(always)]
    fn sbox(x: Fp) -> Fp {
        let x2 = BN254Field::mul(x, x);
        let x4 = BN254Field::mul(x2, x2);
        BN254Field::mul(x4, x)
    }

    /// MDS matrix multiplication
    #[inline(always)]
    fn mds_multiply(state: &mut [Fp; 3]) {
        let mut result = [Fp::ZERO; 3];
        for i in 0..3 {
            for j in 0..3 {
                let term = BN254Field::mul(MDS_MATRIX[i][j], state[j]);
                result[i] = BN254Field::add(result[i], term);
            }
        }
        *state = result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_hash_deterministic() {
        let a = Fp::from_u256(U256::from(1u64));
        let b = Fp::from_u256(U256::from(2u64));

        let hash1 = PoseidonHasher::hash_two(a, b);
        let hash2 = PoseidonHasher::hash_two(a, b);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let hash1 = PoseidonHasher::hash_two(
            Fp::from_u256(U256::from(1u64)),
            Fp::from_u256(U256::from(2u64)),
        );
        let hash2 = PoseidonHasher::hash_two(
            Fp::from_u256(U256::from(2u64)),
            Fp::from_u256(U256::from(1u64)),
        );
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_zero() {
        let hash = PoseidonHasher::hash_two(Fp::ZERO, Fp::ZERO);
        assert_ne!(hash, Fp::ZERO);
    }

    #[test]
    fn test_poseidon_circomlib_compatibility() {
        // Test vector from circomlib/poseidon-rs
        // poseidon([1, 2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        let a = Fp::from_u256(U256::from(1u64));
        let b = Fp::from_u256(U256::from(2u64));
        let expected = U256::from_str_radix(
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
            16,
        )
        .unwrap();

        let hash = PoseidonHasher::hash_two(a, b);
        assert_eq!(
            hash.to_u256(),
            expected,
            "Poseidon hash does not match circomlib test vector"
        );
    }
}
