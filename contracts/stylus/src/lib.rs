//! STARK Stylus Verifier - Full STARK Verifier for Arbitrum Stylus
//!
//! Implements Merkle verification and STARK proof verification.
//! Uses Keccak256 (native Stylus precompile) for Merkle commitments and Fiat-Shamir.

#![cfg_attr(not(feature = "export-abi"), no_std, no_main)]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use stylus_sdk::{alloy_primitives::U256, prelude::*};

pub mod field;
pub mod merkle;
pub mod mpt;
pub mod stark;

use field::Fp;

/// Keccak-based hash of two field elements.
///
/// Encoding: each Fp is converted to its canonical (non-Montgomery) U256 value,
/// then serialized as 32-byte **big-endian**. The two 32-byte chunks are concatenated
/// into a 64-byte buffer and hashed with keccak256. The 32-byte output is interpreted
/// as a big-endian U256 and converted to Fp (which applies mod BN254_PRIME via
/// Montgomery conversion).
///
/// This must produce identical output on both the on-chain verifier and off-chain prover.
#[inline]
pub fn keccak_hash_two(a: Fp, b: Fp) -> Fp {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&a.to_be_bytes());
    buf[32..].copy_from_slice(&b.to_be_bytes());
    let hash = stylus_sdk::crypto::keccak(&buf);
    Fp::from_u256(U256::from_be_bytes(hash.0))
}

sol_storage! {
    #[entrypoint]
    pub struct StarkVerifier {
    }
}

#[public]
impl StarkVerifier {
    /// Verify a full STARK proof of Sharpe ratio verification.
    pub fn verify_sharpe_proof(
        &self,
        public_inputs: Vec<U256>,
        commitments: Vec<U256>,
        ood_values: Vec<U256>,
        fri_final_poly: Vec<U256>,
        query_values: Vec<U256>,
        query_paths: Vec<U256>,
        query_metadata: Vec<U256>,
    ) -> bool {
        stark::verify_sharpe_stark(
            &public_inputs,
            &commitments,
            &ood_values,
            &fri_final_poly,
            &query_values,
            &query_paths,
            &query_metadata,
        )
    }

    /// Verify a STARK proof with commitment binding (Phase A — no large calldata).
    ///
    /// On-chain verification:
    ///   1. Compute aggregate commitment from receipt hashes (keccak hash chain)
    ///   2. Verify STARK proof (Sharpe ratio arithmetic)
    ///   3. Cross-check: pi[3] == merkle_root of constant commitment column
    ///
    /// Receipt hashes are keccak256(receiptRlp) for each trade's transaction,
    /// computed client-side. Total calldata: ~3KB (STARK) + N×32B (hashes).
    /// No receipt RLP or MPT proof nodes are sent on-chain.
    pub fn verify_sharpe_with_commitment(
        &self,
        public_inputs: Vec<U256>,
        commitments: Vec<U256>,
        ood_values: Vec<U256>,
        fri_final_poly: Vec<U256>,
        query_values: Vec<U256>,
        query_paths: Vec<U256>,
        query_metadata: Vec<U256>,
        receipt_hashes: Vec<U256>,
    ) -> bool {
        // Step 1: Compute aggregate commitment from receipt hashes
        if receipt_hashes.is_empty() {
            return false;
        }
        let fps: Vec<Fp> = receipt_hashes.iter().map(|h| Fp::from_u256(*h)).collect();
        let expected_commitment = mpt::compute_commitment_from_hashes(&fps);

        if expected_commitment == Fp::ZERO {
            return false;
        }

        // Step 2: Verify STARK proof
        let stark_valid = stark::verify_sharpe_stark(
            &public_inputs,
            &commitments,
            &ood_values,
            &fri_final_poly,
            &query_values,
            &query_paths,
            &query_metadata,
        );

        if !stark_valid {
            return false;
        }

        // Step 3: Cross-check — pi[3] == merkle_root of constant commitment column
        if public_inputs.len() < 4 || query_metadata.len() < 3 {
            return false;
        }

        let pi3 = Fp::from_u256(public_inputs[3]);
        let log_trace_len = query_metadata[2].as_limbs()[0] as u32;

        let expected_merkle_root = mpt::compute_constant_merkle_root(
            expected_commitment,
            log_trace_len,
        );

        pi3 == expected_merkle_root
    }

    /// Verify a STARK proof with receipt-based data provenance.
    ///
    /// Performs:
    /// 1. MPT proof verification (receipt ∈ receiptsRoot) → extracts receipt RLP from leaf
    /// 2. Dataset commitment computation from MPT-verified receipt (no separate receipt_rlp needed)
    /// 3. Full STARK proof verification
    /// 4. Cross-check: pi[3] == merkle_root of constant commitment column
    ///
    /// The receipt RLP is NOT passed separately — it is extracted directly from the
    /// MPT proof leaf, eliminating data redundancy and reducing calldata size.
    pub fn verify_sharpe_proof_with_receipt(
        &self,
        // STARK proof params (same as verify_sharpe_proof)
        public_inputs: Vec<U256>,
        commitments: Vec<U256>,
        ood_values: Vec<U256>,
        fri_final_poly: Vec<U256>,
        query_values: Vec<U256>,
        query_paths: Vec<U256>,
        query_metadata: Vec<U256>,
        // Receipt proof params (no receipt_rlp — extracted from MPT leaf)
        block_hash: U256,
        receipts_root: Vec<U256>,
        receipt_proof_nodes: Vec<U256>,
        receipt_proof_nodes_len: U256,
        receipt_key: Vec<U256>,
        receipt_key_len: U256,
    ) -> bool {
        // Step 1: Decode parameters
        if receipts_root.is_empty() {
            return false;
        }
        let receipts_root_bytes: [u8; 32] = receipts_root[0].to_be_bytes();

        let nodes_len = receipt_proof_nodes_len.as_limbs()[0] as usize;
        let key_len = receipt_key_len.as_limbs()[0] as usize;
        let key_bytes = mpt::decode_u256_words(&receipt_key, key_len);

        // Step 2: Decode and verify MPT proof — receipt ∈ receiptsRoot
        let proof_nodes = match mpt::decode_proof_nodes(&receipt_proof_nodes, nodes_len) {
            Some(nodes) => nodes,
            None => return false,
        };

        let verified_value = mpt::verify_mpt_proof(
            &receipts_root_bytes,
            &key_bytes,
            &proof_nodes,
        );

        // Extract receipt RLP directly from the MPT leaf — no separate parameter needed
        let receipt_rlp_bytes = match verified_value {
            None => return false,
            Some(leaf) => leaf,
        };

        // Step 3: Compute expected dataset_commitment from MPT-verified receipt
        let expected_commitment = mpt::compute_dataset_commitment_onchain(
            block_hash,
            &receipts_root_bytes,
            &receipt_rlp_bytes,
        );

        if expected_commitment == Fp::ZERO {
            return false;
        }

        // Step 4: Verify STARK proof
        let stark_valid = stark::verify_sharpe_stark(
            &public_inputs,
            &commitments,
            &ood_values,
            &fri_final_poly,
            &query_values,
            &query_paths,
            &query_metadata,
        );

        if !stark_valid {
            return false;
        }

        // Step 5: Cross-check — pi[3] == merkle_root of constant commitment column
        if public_inputs.len() < 4 || query_metadata.is_empty() {
            return false;
        }

        let pi3 = Fp::from_u256(public_inputs[3]);

        // Extract log_trace_len from query_metadata[2]
        // query_metadata layout: [num_queries, num_fri_layers, log_trace_len, ...]
        if query_metadata.len() < 3 {
            return false;
        }
        let log_trace_len = query_metadata[2].as_limbs()[0] as u32;

        // Compute expected merkle root: for a column where every leaf = expected_commitment,
        // the merkle root is deterministic and can be computed in O(log n) hashes.
        let expected_merkle_root = mpt::compute_constant_merkle_root(
            expected_commitment,
            log_trace_len,
        );

        if pi3 != expected_merkle_root {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BN254_PRIME;

    // =====================================================================
    // Cross-validation test vectors for keccak_hash_two
    //
    // These MUST match the prover's keccak_hash_two output exactly.
    // Encoding: big-endian 32-byte per Fp, concat, keccak256, mod BN254.
    // =====================================================================

    /// Test vector 1: keccak_hash_two(0, 0)
    #[test]
    fn test_keccak_vector_zero_zero() {
        let h = keccak_hash_two(Fp::ZERO, Fp::ZERO);
        // keccak256(0x00..00 || 0x00..00) = keccak256([0u8; 64])
        let expected_hash = stylus_sdk::crypto::keccak(&[0u8; 64]);
        let expected = Fp::from_u256(U256::from_be_bytes(expected_hash.0));
        assert_eq!(h, expected);
        assert_ne!(h, Fp::ZERO, "Hash of zeros must be nonzero");

        // Record the actual value for cross-validation with prover
        // Expected hex (from keccak256([0;64]) mod BN254):
        let h_u256 = h.to_u256();
        assert!(h_u256 < BN254_PRIME);
    }

    /// Test vector 2: keccak_hash_two(1, 2)
    #[test]
    fn test_keccak_vector_one_two() {
        let a = Fp::from_u256(U256::from(1u64));
        let b = Fp::from_u256(U256::from(2u64));
        let h = keccak_hash_two(a, b);

        // Manually construct the 64-byte preimage
        let mut buf = [0u8; 64];
        buf[31] = 1; // 1 in big-endian 32 bytes
        buf[63] = 2; // 2 in big-endian 32 bytes
        let expected_hash = stylus_sdk::crypto::keccak(&buf);
        let expected = Fp::from_u256(U256::from_be_bytes(expected_hash.0));
        assert_eq!(h, expected);
        assert!(h.to_u256() < BN254_PRIME);
    }

    /// Test vector 3: keccak_hash_two(BN254_PRIME - 1, 42)
    /// Tests with a large field element near the prime boundary.
    #[test]
    fn test_keccak_vector_large_value() {
        let p_minus_1 = BN254_PRIME - U256::from(1u64);
        let a = Fp::from_u256(p_minus_1);
        let b = Fp::from_u256(U256::from(42u64));
        let h = keccak_hash_two(a, b);

        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&p_minus_1.to_be_bytes::<32>());
        buf[63] = 42;
        let expected_hash = stylus_sdk::crypto::keccak(&buf);
        let expected = Fp::from_u256(U256::from_be_bytes(expected_hash.0));
        assert_eq!(h, expected);
        assert!(h.to_u256() < BN254_PRIME);
    }

    /// Determinism: same inputs always produce same output.
    #[test]
    fn test_keccak_deterministic() {
        let a = Fp::from_u256(U256::from(1u64));
        let b = Fp::from_u256(U256::from(2u64));
        assert_eq!(keccak_hash_two(a, b), keccak_hash_two(a, b));
    }

    /// Input order sensitivity: hash(a,b) != hash(b,a).
    #[test]
    fn test_keccak_order_sensitive() {
        let a = Fp::from_u256(U256::from(1u64));
        let b = Fp::from_u256(U256::from(2u64));
        assert_ne!(keccak_hash_two(a, b), keccak_hash_two(b, a));
    }

    /// Cross-validation: print actual hash values for comparison with prover.
    /// Run with: cargo test -- test_keccak_cross_validate --nocapture
    #[test]
    fn test_keccak_cross_validate_values() {
        let h0 = keccak_hash_two(Fp::ZERO, Fp::ZERO);
        let h1 = keccak_hash_two(
            Fp::from_u256(U256::from(1u64)),
            Fp::from_u256(U256::from(2u64)),
        );
        let p_minus_1 = BN254_PRIME - U256::from(1u64);
        let h2 = keccak_hash_two(
            Fp::from_u256(p_minus_1),
            Fp::from_u256(U256::from(42u64)),
        );

        assert!(h0.to_u256() < BN254_PRIME);
        assert!(h1.to_u256() < BN254_PRIME);
        assert!(h2.to_u256() < BN254_PRIME);
    }

    /// Field range: 100 consecutive hashes all produce values < BN254_PRIME.
    #[test]
    fn test_keccak_output_in_field() {
        let mut a = Fp::from_u256(U256::from(0u64));
        for i in 0..100u64 {
            let b = Fp::from_u256(U256::from(i));
            let h = keccak_hash_two(a, b);
            assert!(h.to_u256() < BN254_PRIME, "Output at i={} out of field", i);
            a = h;
        }
    }
}
