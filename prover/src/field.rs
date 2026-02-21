//! BN254 Field Arithmetic (shared with on-chain verifier)
//!
//! Exact same implementation as contracts/stylus/src/field.rs
//! to ensure prover and verifier are compatible.

use alloy_primitives::U256;

/// BN254 field prime
pub const BN254_PRIME: U256 = U256::from_limbs([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

pub struct BN254Field;

impl BN254Field {
    #[inline(always)]
    pub fn add(a: U256, b: U256) -> U256 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow || sum >= BN254_PRIME {
            sum.wrapping_sub(BN254_PRIME)
        } else {
            sum
        }
    }

    #[inline(always)]
    pub fn sub(a: U256, b: U256) -> U256 {
        if a >= b {
            a.wrapping_sub(b)
        } else {
            BN254_PRIME.wrapping_sub(b.wrapping_sub(a))
        }
    }

    #[inline(always)]
    pub fn mul(a: U256, b: U256) -> U256 {
        a.mul_mod(b, BN254_PRIME)
    }

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

    #[inline]
    pub fn inv(a: U256) -> U256 {
        if a == U256::ZERO {
            return U256::ZERO;
        }
        let exp = BN254_PRIME.wrapping_sub(U256::from(2u64));
        Self::pow(a, exp)
    }

    #[inline]
    pub fn div(a: U256, b: U256) -> U256 {
        Self::mul(a, Self::inv(b))
    }

    #[inline(always)]
    pub fn neg(a: U256) -> U256 {
        if a == U256::ZERO {
            U256::ZERO
        } else {
            BN254_PRIME.wrapping_sub(a)
        }
    }

    #[inline(always)]
    pub fn reduce(a: U256) -> U256 {
        if a >= BN254_PRIME {
            a.wrapping_sub(BN254_PRIME)
        } else {
            a
        }
    }
}
