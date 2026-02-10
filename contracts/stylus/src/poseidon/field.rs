//! BN254 Field Arithmetic — re-export shim
//!
//! Delegates to the Montgomery-form `Fp` implementation in `crate::field`.
//! Maintains the `BN254Field` API for compatibility with existing call sites.

pub use crate::field::Fp;
use alloy_primitives::U256;

/// BN254 field prime as U256 (used at ABI boundaries)
pub const BN254_PRIME: U256 = U256::from_limbs([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

/// BN254 field arithmetic operations (thin wrapper over Fp)
pub struct BN254Field;

impl BN254Field {
    #[inline(always)]
    pub fn add(a: Fp, b: Fp) -> Fp { Fp::add(a, b) }

    #[inline(always)]
    pub fn sub(a: Fp, b: Fp) -> Fp { Fp::sub(a, b) }

    #[inline(always)]
    pub fn mul(a: Fp, b: Fp) -> Fp { Fp::mul(a, b) }

    #[inline(always)]
    pub fn neg(a: Fp) -> Fp { Fp::neg(a) }

    #[inline]
    pub fn pow(base: Fp, exp: U256) -> Fp { Fp::pow(base, exp) }

    #[inline]
    pub fn inv(a: Fp) -> Fp { Fp::inv(a) }

    #[inline]
    pub fn div(a: Fp, b: Fp) -> Fp { Fp::div(a, b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_no_overflow() {
        let a = Fp::from_u256(U256::from(100u64));
        let b = Fp::from_u256(U256::from(200u64));
        let result = BN254Field::add(a, b);
        assert_eq!(result.to_u256(), U256::from(300u64));
    }

    #[test]
    fn test_add_with_reduction() {
        let a = Fp::from_u256(BN254_PRIME - U256::from(1u64));
        let b = Fp::from_u256(U256::from(2u64));
        let result = BN254Field::add(a, b);
        assert_eq!(result.to_u256(), U256::from(1u64));
    }

    #[test]
    fn test_sub() {
        let a = Fp::from_u256(U256::from(200u64));
        let b = Fp::from_u256(U256::from(100u64));
        let result = BN254Field::sub(a, b);
        assert_eq!(result.to_u256(), U256::from(100u64));
    }

    #[test]
    fn test_sub_underflow() {
        let a = Fp::from_u256(U256::from(100u64));
        let b = Fp::from_u256(U256::from(200u64));
        let result = BN254Field::sub(a, b);
        let expected = BN254_PRIME - U256::from(100u64);
        assert_eq!(result.to_u256(), expected);
    }

    #[test]
    fn test_mul() {
        let a = Fp::from_u256(U256::from(7u64));
        let b = Fp::from_u256(U256::from(8u64));
        let result = BN254Field::mul(a, b);
        assert_eq!(result.to_u256(), U256::from(56u64));
    }

    #[test]
    fn test_mul_large() {
        let a = Fp::from_u256(BN254_PRIME - U256::from(1u64));
        let b = Fp::from_u256(U256::from(2u64));
        let result = BN254Field::mul(a, b);
        let expected = BN254_PRIME - U256::from(2u64);
        assert_eq!(result.to_u256(), expected);
    }

    #[test]
    fn test_pow_basic() {
        let result = BN254Field::pow(Fp::from_u256(U256::from(2u64)), U256::from(10u64));
        assert_eq!(result.to_u256(), U256::from(1024u64));
    }

    #[test]
    fn test_pow_zero_exp() {
        let result = BN254Field::pow(Fp::from_u256(U256::from(42u64)), U256::ZERO);
        assert_eq!(result.to_u256(), U256::from(1u64));
    }

    #[test]
    fn test_pow_one_exp() {
        let result = BN254Field::pow(Fp::from_u256(U256::from(42u64)), U256::from(1u64));
        assert_eq!(result.to_u256(), U256::from(42u64));
    }

    #[test]
    fn test_pow_fermat() {
        let a = Fp::from_u256(U256::from(7u64));
        let exp = BN254_PRIME - U256::from(1u64);
        let result = BN254Field::pow(a, exp);
        assert_eq!(result.to_u256(), U256::from(1u64));
    }

    #[test]
    fn test_inv_basic() {
        let a = Fp::from_u256(U256::from(7u64));
        let a_inv = BN254Field::inv(a);
        let product = BN254Field::mul(a, a_inv);
        assert_eq!(product, Fp::ONE);
    }

    #[test]
    fn test_inv_large() {
        let a = Fp::from_u256(U256::from(123456789u64));
        let a_inv = BN254Field::inv(a);
        let product = BN254Field::mul(a, a_inv);
        assert_eq!(product, Fp::ONE);
    }

    #[test]
    fn test_inv_zero() {
        assert_eq!(BN254Field::inv(Fp::ZERO), Fp::ZERO);
    }

    #[test]
    fn test_div_basic() {
        let result = BN254Field::div(
            Fp::from_u256(U256::from(10u64)),
            Fp::from_u256(U256::from(2u64)),
        );
        assert_eq!(result.to_u256(), U256::from(5u64));
    }

    #[test]
    fn test_div_roundtrip() {
        let a = Fp::from_u256(U256::from(42u64));
        let b = Fp::from_u256(U256::from(13u64));
        let product = BN254Field::mul(a, b);
        let result = BN254Field::div(product, b);
        assert_eq!(result, a);
    }

    #[test]
    fn test_neg() {
        let a = Fp::from_u256(U256::from(5u64));
        let neg_a = BN254Field::neg(a);
        let sum = BN254Field::add(a, neg_a);
        assert_eq!(sum, Fp::ZERO);
    }

    #[test]
    fn test_neg_zero() {
        assert_eq!(BN254Field::neg(Fp::ZERO), Fp::ZERO);
    }
}
