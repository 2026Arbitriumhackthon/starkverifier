//! Poseidon Hash for the prover
//!
//! This is a std-compatible copy of the Poseidon hash used by the on-chain verifier.
//! Both use identical constants and algorithm to ensure proof compatibility.

use alloy_primitives::U256;
use crate::field::BN254Field;

mod constants;
use constants::{ROUND_CONSTANTS, MDS_MATRIX};

pub struct PoseidonHasher;

impl PoseidonHasher {
    const T: usize = 3;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 57;

    pub fn hash_two(a: U256, b: U256) -> U256 {
        let mut state = [U256::ZERO, a, b];
        let half_full = Self::FULL_ROUNDS / 2;
        let mut round_ctr = 0;

        for _ in 0..half_full {
            Self::full_round(&mut state, round_ctr);
            round_ctr += Self::T;
        }
        for _ in 0..Self::PARTIAL_ROUNDS {
            Self::partial_round(&mut state, round_ctr);
            round_ctr += Self::T;
        }
        for _ in 0..half_full {
            Self::full_round(&mut state, round_ctr);
            round_ctr += Self::T;
        }

        state[0]
    }

    /// Hash a single element: poseidon(a, 0)
    pub fn hash_one(a: U256) -> U256 {
        Self::hash_two(a, U256::ZERO)
    }

    fn full_round(state: &mut [U256; 3], round_ctr: usize) {
        for i in 0..Self::T {
            state[i] = BN254Field::add(state[i], ROUND_CONSTANTS[round_ctr + i]);
        }
        for i in 0..Self::T {
            state[i] = Self::sbox(state[i]);
        }
        Self::mds_multiply(state);
    }

    fn partial_round(state: &mut [U256; 3], round_ctr: usize) {
        for i in 0..Self::T {
            state[i] = BN254Field::add(state[i], ROUND_CONSTANTS[round_ctr + i]);
        }
        state[0] = Self::sbox(state[0]);
        Self::mds_multiply(state);
    }

    fn sbox(x: U256) -> U256 {
        let x2 = BN254Field::mul(x, x);
        let x4 = BN254Field::mul(x2, x2);
        BN254Field::mul(x4, x)
    }

    fn mds_multiply(state: &mut [U256; 3]) {
        let mut result = [U256::ZERO; 3];
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

    #[test]
    fn test_poseidon_circomlib_compatibility() {
        let expected = U256::from_str_radix(
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
            16,
        ).unwrap();
        let hash = PoseidonHasher::hash_two(U256::from(1u64), U256::from(2u64));
        assert_eq!(hash, expected, "Poseidon hash does not match circomlib");
    }
}
