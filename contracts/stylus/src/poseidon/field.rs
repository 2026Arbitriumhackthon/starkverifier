//! BN254 (alt_bn128) Field Arithmetic
//!
//! Implements modular arithmetic operations for the BN254 prime field.
//! Prime: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

use alloy_primitives::U256;

/// BN254 field prime
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub const BN254_PRIME: U256 = U256::from_limbs([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

/// BN254 field arithmetic operations
pub struct BN254Field;

impl BN254Field {
    /// Modular addition: (a + b) mod p
    #[inline(always)]
    pub fn add(a: U256, b: U256) -> U256 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow || sum >= BN254_PRIME {
            sum.wrapping_sub(BN254_PRIME)
        } else {
            sum
        }
    }

    /// Modular subtraction: (a - b) mod p
    #[inline(always)]
    pub fn sub(a: U256, b: U256) -> U256 {
        if a >= b {
            a.wrapping_sub(b)
        } else {
            BN254_PRIME.wrapping_sub(b.wrapping_sub(a))
        }
    }

    /// Modular multiplication: (a * b) mod p
    /// Uses mulmod for efficient modular multiplication
    #[inline(always)]
    pub fn mul(a: U256, b: U256) -> U256 {
        a.mul_mod(b, BN254_PRIME)
    }

    /// Check if value is in field (less than prime)
    #[inline(always)]
    pub fn is_valid(a: U256) -> bool {
        a < BN254_PRIME
    }

    /// Reduce value to field if necessary
    #[inline(always)]
    pub fn reduce(a: U256) -> U256 {
        if a >= BN254_PRIME {
            a.wrapping_sub(BN254_PRIME)
        } else {
            a
        }
    }

    /// Modular exponentiation: base^exp mod p
    /// Uses square-and-multiply algorithm
    #[inline]
    pub fn pow(base: U256, exp: U256) -> U256 {
        if exp == U256::ZERO {
            return U256::from(1u64);
        }
        let mut result = U256::from(1u64);
        let mut b = base;
        let mut e = exp;
        while e > U256::ZERO {
            if e & U256::from(1u64) == U256::from(1u64) {
                result = Self::mul(result, b);
            }
            b = Self::mul(b, b);
            e >>= 1;
        }
        result
    }

    /// Modular inverse: a^(p-2) mod p (Fermat's little theorem)
    /// Returns 0 for input 0 (undefined but safe)
    #[inline]
    pub fn inv(a: U256) -> U256 {
        if a == U256::ZERO {
            return U256::ZERO;
        }
        // p - 2
        let exp = BN254_PRIME.wrapping_sub(U256::from(2u64));
        Self::pow(a, exp)
    }

    /// Modular division: a / b = a * b^(-1) mod p
    #[inline]
    pub fn div(a: U256, b: U256) -> U256 {
        Self::mul(a, Self::inv(b))
    }

    /// Negate: -a mod p = p - a
    #[inline(always)]
    pub fn neg(a: U256) -> U256 {
        if a == U256::ZERO {
            U256::ZERO
        } else {
            BN254_PRIME.wrapping_sub(a)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_no_overflow() {
        let a = U256::from(100u64);
        let b = U256::from(200u64);
        let result = BN254Field::add(a, b);
        assert_eq!(result, U256::from(300u64));
    }

    #[test]
    fn test_add_with_reduction() {
        let a = BN254_PRIME - U256::from(1u64);
        let b = U256::from(2u64);
        let result = BN254Field::add(a, b);
        assert_eq!(result, U256::from(1u64));
    }

    #[test]
    fn test_sub() {
        let a = U256::from(200u64);
        let b = U256::from(100u64);
        let result = BN254Field::sub(a, b);
        assert_eq!(result, U256::from(100u64));
    }

    #[test]
    fn test_sub_underflow() {
        let a = U256::from(100u64);
        let b = U256::from(200u64);
        let result = BN254Field::sub(a, b);
        // Should wrap around: p - 100
        let expected = BN254_PRIME - U256::from(100u64);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_mul() {
        let a = U256::from(7u64);
        let b = U256::from(8u64);
        let result = BN254Field::mul(a, b);
        assert_eq!(result, U256::from(56u64));
    }

    #[test]
    fn test_mul_large() {
        // Test that multiplication properly reduces mod p
        let a = BN254_PRIME - U256::from(1u64);
        let b = U256::from(2u64);
        let result = BN254Field::mul(a, b);
        // (p-1) * 2 = 2p - 2 ≡ -2 ≡ p - 2 (mod p)
        let expected = BN254_PRIME - U256::from(2u64);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pow_basic() {
        // 2^10 = 1024
        let result = BN254Field::pow(U256::from(2u64), U256::from(10u64));
        assert_eq!(result, U256::from(1024u64));
    }

    #[test]
    fn test_pow_zero_exp() {
        let result = BN254Field::pow(U256::from(42u64), U256::ZERO);
        assert_eq!(result, U256::from(1u64));
    }

    #[test]
    fn test_pow_one_exp() {
        let result = BN254Field::pow(U256::from(42u64), U256::from(1u64));
        assert_eq!(result, U256::from(42u64));
    }

    #[test]
    fn test_pow_fermat() {
        // a^(p-1) = 1 for any a != 0 (Fermat's little theorem)
        let a = U256::from(7u64);
        let exp = BN254_PRIME - U256::from(1u64);
        let result = BN254Field::pow(a, exp);
        assert_eq!(result, U256::from(1u64));
    }

    #[test]
    fn test_inv_basic() {
        // a * inv(a) == 1
        let a = U256::from(7u64);
        let a_inv = BN254Field::inv(a);
        let product = BN254Field::mul(a, a_inv);
        assert_eq!(product, U256::from(1u64));
    }

    #[test]
    fn test_inv_large() {
        // Test with a larger value
        let a = U256::from(123456789u64);
        let a_inv = BN254Field::inv(a);
        let product = BN254Field::mul(a, a_inv);
        assert_eq!(product, U256::from(1u64));
    }

    #[test]
    fn test_inv_zero() {
        // inv(0) should return 0 (our convention)
        assert_eq!(BN254Field::inv(U256::ZERO), U256::ZERO);
    }

    #[test]
    fn test_div_basic() {
        // 10 / 2 = 5
        let result = BN254Field::div(U256::from(10u64), U256::from(2u64));
        assert_eq!(result, U256::from(5u64));
    }

    #[test]
    fn test_div_roundtrip() {
        // (a * b) / b == a
        let a = U256::from(42u64);
        let b = U256::from(13u64);
        let product = BN254Field::mul(a, b);
        let result = BN254Field::div(product, b);
        assert_eq!(result, a);
    }

    #[test]
    fn test_neg() {
        let a = U256::from(5u64);
        let neg_a = BN254Field::neg(a);
        // a + (-a) should be 0
        let sum = BN254Field::add(a, neg_a);
        assert_eq!(sum, U256::ZERO);
    }

    #[test]
    fn test_neg_zero() {
        assert_eq!(BN254Field::neg(U256::ZERO), U256::ZERO);
    }
}
