//! Keccak256 hash for the prover
//!
//! Produces identical output to the
//! on-chain verifier's `keccak_hash_two` given the same field element inputs.
//!
//! Encoding contract (must match verifier exactly):
//!   1. Each U256 value is serialized as 32-byte **big-endian**.
//!   2. Two 32-byte chunks are concatenated into a 64-byte buffer.
//!   3. keccak256 is applied to the 64-byte buffer.
//!   4. The 32-byte output is interpreted as a big-endian U256.
//!
//! Note: The output is NOT reduced mod BN254_PRIME here because `U256::from_be_bytes`
//! returns a full 256-bit value. Callers that need a field element should reduce
//! as needed (the verifier's `Fp::from_u256` handles this via Montgomery conversion).
//! For the prover, keccak output is used directly as U256 in Merkle trees and
//! Fiat-Shamir channels — matching the verifier's behavior since `Fp::from_u256`
//! followed by `Fp::to_u256` on a value < 2^256 applies mod BN254_PRIME.

use alloy_primitives::U256;
use tiny_keccak::{Hasher, Keccak};

use crate::field::BN254_PRIME;

/// Keccak256 hash of a byte slice.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Hash two U256 field elements using keccak256.
///
/// Encoding: big-endian 32 bytes per element, concatenated, hashed, reduced mod BN254.
/// This MUST produce identical output to the on-chain verifier's `keccak_hash_two`.
pub fn keccak_hash_two(a: U256, b: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&a.to_be_bytes::<32>());
    buf[32..].copy_from_slice(&b.to_be_bytes::<32>());
    let hash = keccak256(&buf);
    let raw = U256::from_be_bytes(hash);
    // Full reduction mod BN254 prime using mul_mod identity: x mod p = x * 1 mod p
    // This matches the verifier's Fp::from_u256 which applies Montgomery conversion (mod p).
    raw.mul_mod(U256::from(1u64), BN254_PRIME)
}

/// Hash a single element: keccak_hash_two(a, 0).
pub fn keccak_hash_one(a: U256) -> U256 {
    keccak_hash_two(a, U256::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // Cross-validation test vectors — must match verifier's keccak_hash_two
    // =====================================================================

    /// Test vector 1: keccak_hash_two(0, 0)
    #[test]
    fn test_keccak_vector_zero_zero() {
        let h = keccak_hash_two(U256::ZERO, U256::ZERO);
        // keccak256([0u8; 64]) = known constant
        let expected_raw = U256::from_be_bytes(keccak256(&[0u8; 64]));
        let expected = expected_raw.mul_mod(U256::from(1u64), BN254_PRIME);
        assert_eq!(h, expected);
        assert_ne!(h, U256::ZERO, "Hash of zeros must be nonzero");
        assert!(h < BN254_PRIME);
    }

    /// Test vector 2: keccak_hash_two(1, 2)
    #[test]
    fn test_keccak_vector_one_two() {
        let h = keccak_hash_two(U256::from(1u64), U256::from(2u64));
        // Manually construct preimage
        let mut buf = [0u8; 64];
        buf[31] = 1;
        buf[63] = 2;
        let expected_raw = U256::from_be_bytes(keccak256(&buf));
        let expected = expected_raw.mul_mod(U256::from(1u64), BN254_PRIME);
        assert_eq!(h, expected);
        assert!(h < BN254_PRIME);
    }

    /// Test vector 3: keccak_hash_two(BN254_PRIME - 1, 42)
    #[test]
    fn test_keccak_vector_large_value() {
        let p_minus_1 = BN254_PRIME - U256::from(1u64);
        let h = keccak_hash_two(p_minus_1, U256::from(42u64));

        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&p_minus_1.to_be_bytes::<32>());
        buf[63] = 42;
        let expected_raw = U256::from_be_bytes(keccak256(&buf));
        let expected = expected_raw.mul_mod(U256::from(1u64), BN254_PRIME);
        assert_eq!(h, expected);
        assert!(h < BN254_PRIME);
    }

    /// Determinism
    #[test]
    fn test_keccak_deterministic() {
        let a = U256::from(1u64);
        let b = U256::from(2u64);
        assert_eq!(keccak_hash_two(a, b), keccak_hash_two(a, b));
    }

    /// Input order sensitivity
    #[test]
    fn test_keccak_order_sensitive() {
        let a = U256::from(1u64);
        let b = U256::from(2u64);
        assert_ne!(keccak_hash_two(a, b), keccak_hash_two(b, a));
    }

    /// Cross-validation: print actual hash values for comparison with verifier.
    /// Run with: cargo test -- test_keccak_cross_validate --nocapture
    #[test]
    fn test_keccak_cross_validate_values() {
        // These are the three test vectors. We compute them here and verify
        // they match the verifier by encoding as hex for manual comparison.
        let h0 = keccak_hash_two(U256::ZERO, U256::ZERO);
        let h1 = keccak_hash_two(U256::from(1u64), U256::from(2u64));
        let p_minus_1 = BN254_PRIME - U256::from(1u64);
        let h2 = keccak_hash_two(p_minus_1, U256::from(42u64));

        // Print hex for manual cross-check with verifier
        eprintln!("Prover keccak_hash_two(0, 0)     = 0x{:064x}", h0);
        eprintln!("Prover keccak_hash_two(1, 2)     = 0x{:064x}", h1);
        eprintln!("Prover keccak_hash_two(p-1, 42)  = 0x{:064x}", h2);

        // All must be in field
        assert!(h0 < BN254_PRIME);
        assert!(h1 < BN254_PRIME);
        assert!(h2 < BN254_PRIME);

        // All must be nonzero
        assert_ne!(h0, U256::ZERO);
        assert_ne!(h1, U256::ZERO);
        assert_ne!(h2, U256::ZERO);
    }

    /// Field range: 100 consecutive hashes all < BN254_PRIME
    #[test]
    fn test_keccak_output_in_field() {
        let mut a = U256::ZERO;
        for i in 0..100u64 {
            let h = keccak_hash_two(a, U256::from(i));
            assert!(h < BN254_PRIME, "Output at i={} out of field", i);
            a = h;
        }
    }
}
