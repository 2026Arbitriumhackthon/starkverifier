//! STARK Stylus Verifier - Full STARK Verifier for Arbitrum Stylus
//!
//! Implements Poseidon hash, Merkle verification, and STARK proof verification.

#![cfg_attr(not(feature = "export-abi"), no_std, no_main)]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use stylus_sdk::{alloy_primitives::U256, prelude::*};

pub mod field;
pub mod merkle;
pub mod poseidon;
pub mod stark;

use field::Fp;
use poseidon::PoseidonHasher;

sol_storage! {
    #[entrypoint]
    pub struct StarkVerifier {
    }
}

#[public]
impl StarkVerifier {
    /// Compute Poseidon hash of two U256 inputs
    pub fn poseidon_hash(&self, a: U256, b: U256) -> U256 {
        PoseidonHasher::hash_two(Fp::from_u256(a), Fp::from_u256(b)).to_u256()
    }

    /// Verify a full STARK proof of Fibonacci computation.
    pub fn verify_stark_proof(
        &self,
        public_inputs: Vec<U256>,
        commitments: Vec<U256>,
        ood_values: Vec<U256>,
        fri_final_poly: Vec<U256>,
        query_values: Vec<U256>,
        query_paths: Vec<U256>,
        query_metadata: Vec<U256>,
    ) -> bool {
        stark::verify_stark(
            &public_inputs,
            &commitments,
            &ood_values,
            &fri_final_poly,
            &query_values,
            &query_paths,
            &query_metadata,
        )
    }
}
