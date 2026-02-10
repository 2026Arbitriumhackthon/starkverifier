//! Evaluation Domain for FRI Protocol
//!
//! Provides roots of unity for the BN254 scalar field.
//! BN254 scalar field order: p - 1 = 2^28 × 3^2 × 13 × 29 × ...
//! This gives us a multiplicative subgroup of order 2^28.

use alloy_primitives::U256;

use crate::poseidon::field::BN254Field;
#[cfg(test)]
use crate::poseidon::field::BN254_PRIME;

/// Generator of the 2^28 multiplicative subgroup of BN254 scalar field.
/// This is a primitive 2^28-th root of unity: g^(2^28) = 1.
///
/// Computed as: MULTIPLICATIVE_GENERATOR^((p-1) / 2^28)
/// where MULTIPLICATIVE_GENERATOR = 5 (a generator of the full multiplicative group).
///
/// Verification: g^(2^28) ≡ 1 (mod p) and g^(2^27) ≢ 1 (mod p)
pub const GENERATOR_2_28: U256 = U256::from_limbs([
    0x9bd61b6e725b19f0,
    0x402d111e41112ed4,
    0x00e0a7eb8ef62abc,
    0x2a3c09f0a58a7e85,
]);

/// TWO_ADICITY: The largest k such that 2^k divides (p-1).
/// For BN254 scalar field, this is 28.
pub const TWO_ADICITY: u32 = 28;

/// Get the generator of a 2^k-sized domain.
///
/// Returns a 2^k-th primitive root of unity by computing:
///   g_k = GENERATOR_2_28 ^ (2^(28-k))
///
/// # Arguments
/// * `log_size` - k, where the domain size is 2^k. Must be <= 28.
///
/// # Returns
/// A 2^k-th primitive root of unity
pub fn domain_generator(log_size: u32) -> U256 {
    assert!(log_size <= TWO_ADICITY, "log_size exceeds two-adicity");
    let exp_power = TWO_ADICITY - log_size;
    let exp = U256::from(1u64) << exp_power;
    BN254Field::pow(GENERATOR_2_28, exp)
}

/// Evaluate g^index for a given generator g.
///
/// # Arguments
/// * `gen` - A domain generator (root of unity)
/// * `index` - The index within the domain
pub fn evaluate_at(gen: U256, index: u64) -> U256 {
    BN254Field::pow(gen, U256::from(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_2_28_is_root_of_unity() {
        // g^(2^28) should equal 1
        let mut val = GENERATOR_2_28;
        for _ in 0..28 {
            val = BN254Field::mul(val, val);
        }
        assert_eq!(val, U256::from(1u64), "g^(2^28) != 1");
    }

    #[test]
    fn test_generator_2_28_is_primitive() {
        // g^(2^27) should NOT equal 1 (primitive root)
        let mut val = GENERATOR_2_28;
        for _ in 0..27 {
            val = BN254Field::mul(val, val);
        }
        assert_ne!(val, U256::from(1u64), "g^(2^27) == 1, not primitive");
    }

    #[test]
    fn test_domain_generator_k() {
        // For k=4, g_4^16 = 1
        let g4 = domain_generator(4);
        let result = BN254Field::pow(g4, U256::from(16u64));
        assert_eq!(result, U256::from(1u64), "g_4^16 != 1");

        // g_4^8 != 1 (primitive)
        let half = BN254Field::pow(g4, U256::from(8u64));
        assert_ne!(half, U256::from(1u64), "g_4^8 == 1, not primitive");
    }

    #[test]
    fn test_domain_generator_6() {
        // 2^6 = 64 size domain
        let g6 = domain_generator(6);
        let result = BN254Field::pow(g6, U256::from(64u64));
        assert_eq!(result, U256::from(1u64), "g_6^64 != 1");
    }

    #[test]
    fn test_domain_generator_1() {
        // 2^1 = 2, so g^2 = 1 → g = p-1 (only -1 has order 2)
        let g1 = domain_generator(1);
        let result = BN254Field::pow(g1, U256::from(2u64));
        assert_eq!(result, U256::from(1u64));
        assert_eq!(g1, BN254_PRIME - U256::from(1u64));
    }

    #[test]
    fn test_evaluate_at() {
        let g = domain_generator(4);
        // g^0 = 1
        assert_eq!(evaluate_at(g, 0), U256::from(1u64));
        // g^1 = g
        assert_eq!(evaluate_at(g, 1), g);
    }

    #[test]
    fn test_domain_element() {
        let g = domain_generator(4);
        assert_eq!(evaluate_at(g, 3), BN254Field::pow(g, U256::from(3u64)));
    }
}
