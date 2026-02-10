//! Montgomery-form BN254 scalar field arithmetic
//!
//! Provides `Fp` type using Montgomery representation for efficient
//! modular multiplication without division.
//!
//! Montgomery form: a value `v` is stored as `v * R mod p` where R = 2^256.
//! Multiplication becomes `mont_mul(a_mont, b_mont) = a*b*R mod p` (one mul + shift).

use alloy_primitives::U256;

/// BN254 scalar field modulus (little-endian limbs)
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// -p^{-1} mod 2^64  (for Montgomery reduction)
const INV: u64 = 0xc2e1f593efffffff;

/// R^2 mod p  (for converting standard → Montgomery form)
const R2: [u64; 4] = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

/// Montgomery-form field element over BN254 scalar field.
/// Internally stores `a * R mod p` where R = 2^256.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Fp(pub [u64; 4]);

impl Fp {
    /// Additive identity (0 in Montgomery form = 0)
    pub const ZERO: Fp = Fp([0, 0, 0, 0]);

    /// Multiplicative identity (1 in Montgomery form = R mod p)
    pub const ONE: Fp = Fp([
        0xac96341c4ffffffb,
        0x36fc76959f60cd29,
        0x666ea36f7879462e,
        0x0e0a77c19a07df2f,
    ]);

    /// Create Fp from pre-computed Montgomery-form limbs (no conversion).
    #[inline(always)]
    pub const fn from_raw(limbs: [u64; 4]) -> Self {
        Fp(limbs)
    }

    /// Convert a standard U256 value into Montgomery form.
    #[inline]
    pub fn from_u256(val: U256) -> Fp {
        let limbs = val.as_limbs();
        let v = [limbs[0], limbs[1], limbs[2], limbs[3]];
        mont_mul(&v, &R2)
    }

    /// Convert from Montgomery form back to a standard U256.
    #[inline]
    pub fn to_u256(self) -> U256 {
        let one = [1u64, 0, 0, 0];
        let r = mont_mul(&self.0, &one);
        U256::from_limbs(r.0)
    }

    /// Modular addition: (a + b) mod p
    #[inline(always)]
    pub fn add(a: Fp, b: Fp) -> Fp {
        let (d0, carry) = adc(a.0[0], b.0[0], 0);
        let (d1, carry) = adc(a.0[1], b.0[1], carry);
        let (d2, carry) = adc(a.0[2], b.0[2], carry);
        let (d3, _) = adc(a.0[3], b.0[3], carry);

        // Conditionally subtract MODULUS
        let (sub0, borrow) = sbb(d0, MODULUS[0], 0);
        let (sub1, borrow) = sbb(d1, MODULUS[1], borrow);
        let (sub2, borrow) = sbb(d2, MODULUS[2], borrow);
        let (sub3, borrow) = sbb(d3, MODULUS[3], borrow);

        // borrow=0: sum >= p, use subtracted; borrow=1: sum < p, use original
        let mask = 0u64.wrapping_sub(borrow);
        Fp([
            (d0 & mask) | (sub0 & !mask),
            (d1 & mask) | (sub1 & !mask),
            (d2 & mask) | (sub2 & !mask),
            (d3 & mask) | (sub3 & !mask),
        ])
    }

    /// Modular subtraction: (a - b) mod p
    #[inline(always)]
    pub fn sub(a: Fp, b: Fp) -> Fp {
        let (d0, borrow) = sbb(a.0[0], b.0[0], 0);
        let (d1, borrow) = sbb(a.0[1], b.0[1], borrow);
        let (d2, borrow) = sbb(a.0[2], b.0[2], borrow);
        let (d3, borrow) = sbb(a.0[3], b.0[3], borrow);

        // If borrow, add MODULUS back
        let mask = 0u64.wrapping_sub(borrow);
        let (d0, carry) = adc(d0, MODULUS[0] & mask, 0);
        let (d1, carry) = adc(d1, MODULUS[1] & mask, carry);
        let (d2, carry) = adc(d2, MODULUS[2] & mask, carry);
        let (d3, _) = adc(d3, MODULUS[3] & mask, carry);

        Fp([d0, d1, d2, d3])
    }

    /// Modular negation: -a mod p
    #[inline(always)]
    pub fn neg(a: Fp) -> Fp {
        if a.0[0] | a.0[1] | a.0[2] | a.0[3] == 0 {
            return Fp::ZERO;
        }
        let (d0, borrow) = sbb(MODULUS[0], a.0[0], 0);
        let (d1, borrow) = sbb(MODULUS[1], a.0[1], borrow);
        let (d2, borrow) = sbb(MODULUS[2], a.0[2], borrow);
        let (d3, _) = sbb(MODULUS[3], a.0[3], borrow);
        Fp([d0, d1, d2, d3])
    }

    /// Modular multiplication: (a * b) mod p  via Montgomery
    #[inline(always)]
    pub fn mul(a: Fp, b: Fp) -> Fp {
        mont_mul(&a.0, &b.0)
    }

    /// Modular exponentiation: base^exp mod p  (square-and-multiply)
    #[inline]
    pub fn pow(base: Fp, exp: U256) -> Fp {
        if exp == U256::ZERO {
            return Fp::ONE;
        }
        let mut result = Fp::ONE;
        let mut b = base;
        let mut e = exp;
        while e > U256::ZERO {
            if e & U256::from(1u64) == U256::from(1u64) {
                result = Fp::mul(result, b);
            }
            b = Fp::mul(b, b);
            e >>= 1;
        }
        result
    }

    /// Modular inverse: a^(p-2) mod p  (Fermat's little theorem)
    #[inline]
    pub fn inv(a: Fp) -> Fp {
        if a == Fp::ZERO {
            return Fp::ZERO;
        }
        let exp = U256::from_limbs([
            0x43e1f593efffffff, // MODULUS[0] - 2
            0x2833e84879b97091,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]);
        Fp::pow(a, exp)
    }

    /// Modular division: a / b = a * b^(-1) mod p
    #[inline]
    pub fn div(a: Fp, b: Fp) -> Fp {
        Fp::mul(a, Fp::inv(b))
    }

    /// Check if value is zero
    #[inline(always)]
    pub fn is_zero(self) -> bool {
        self.0[0] | self.0[1] | self.0[2] | self.0[3] == 0
    }
}

impl core::fmt::Debug for Fp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fp({:#x})", self.to_u256())
    }
}

// ============================================================
// Limb arithmetic helpers
// ============================================================

/// Multiply-accumulate: (a + b*c + d) returning (lo, hi)
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let res = (a as u128) + (b as u128) * (c as u128) + (d as u128);
    (res as u64, (res >> 64) as u64)
}

/// Add with carry: (a + b + carry) returning (sum, carry_out)
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let res = (a as u128) + (b as u128) + (carry as u128);
    (res as u64, (res >> 64) as u64)
}

/// Subtract with borrow: (a - b - borrow) returning (diff, borrow_out)
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let res = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (res as u64, (res >> 127) as u64)
}

// ============================================================
// Montgomery multiplication (SOS method)
// ============================================================

/// Montgomery multiplication: compute a*b*R^{-1} mod p
///
/// Uses Separated Operand Scanning: full 512-bit product then reduction.
#[inline]
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> Fp {
    // Step 1: 512-bit product  t = a * b
    let (t0, carry) = mac(0, a[0], b[0], 0);
    let (t1, carry) = mac(0, a[1], b[0], carry);
    let (t2, carry) = mac(0, a[2], b[0], carry);
    let (t3, t4) = mac(0, a[3], b[0], carry);

    let (t1, carry) = mac(t1, a[0], b[1], 0);
    let (t2, carry) = mac(t2, a[1], b[1], carry);
    let (t3, carry) = mac(t3, a[2], b[1], carry);
    let (t4, t5) = mac(t4, a[3], b[1], carry);

    let (t2, carry) = mac(t2, a[0], b[2], 0);
    let (t3, carry) = mac(t3, a[1], b[2], carry);
    let (t4, carry) = mac(t4, a[2], b[2], carry);
    let (t5, t6) = mac(t5, a[3], b[2], carry);

    let (t3, carry) = mac(t3, a[0], b[3], 0);
    let (t4, carry) = mac(t4, a[1], b[3], carry);
    let (t5, carry) = mac(t5, a[2], b[3], carry);
    let (t6, t7) = mac(t6, a[3], b[3], carry);

    // Step 2: Montgomery reduction
    montgomery_reduce(t0, t1, t2, t3, t4, t5, t6, t7)
}

/// Montgomery reduction of a 512-bit value [t0..t7].
/// Returns (t * R^{-1}) mod p.
#[inline]
fn montgomery_reduce(
    t0: u64, t1: u64, t2: u64, t3: u64,
    t4: u64, t5: u64, t6: u64, t7: u64,
) -> Fp {
    // Round 0
    let k = t0.wrapping_mul(INV);
    let (_, carry) = mac(t0, k, MODULUS[0], 0);
    let (r1, carry) = mac(t1, k, MODULUS[1], carry);
    let (r2, carry) = mac(t2, k, MODULUS[2], carry);
    let (r3, carry) = mac(t3, k, MODULUS[3], carry);
    let (r4, carry2) = adc(t4, carry, 0);

    // Round 1
    let k = r1.wrapping_mul(INV);
    let (_, carry) = mac(r1, k, MODULUS[0], 0);
    let (r2, carry) = mac(r2, k, MODULUS[1], carry);
    let (r3, carry) = mac(r3, k, MODULUS[2], carry);
    let (r4, carry) = mac(r4, k, MODULUS[3], carry);
    let (r5, carry2) = adc(t5, carry2, carry);

    // Round 2
    let k = r2.wrapping_mul(INV);
    let (_, carry) = mac(r2, k, MODULUS[0], 0);
    let (r3, carry) = mac(r3, k, MODULUS[1], carry);
    let (r4, carry) = mac(r4, k, MODULUS[2], carry);
    let (r5, carry) = mac(r5, k, MODULUS[3], carry);
    let (r6, carry2) = adc(t6, carry2, carry);

    // Round 3
    let k = r3.wrapping_mul(INV);
    let (_, carry) = mac(r3, k, MODULUS[0], 0);
    let (r4, carry) = mac(r4, k, MODULUS[1], carry);
    let (r5, carry) = mac(r5, k, MODULUS[2], carry);
    let (r6, carry) = mac(r6, k, MODULUS[3], carry);
    let (r7, _) = adc(t7, carry2, carry);

    // Final conditional subtraction
    let (d0, borrow) = sbb(r4, MODULUS[0], 0);
    let (d1, borrow) = sbb(r5, MODULUS[1], borrow);
    let (d2, borrow) = sbb(r6, MODULUS[2], borrow);
    let (d3, borrow) = sbb(r7, MODULUS[3], borrow);

    let mask = 0u64.wrapping_sub(borrow);
    Fp([
        (r4 & mask) | (d0 & !mask),
        (r5 & mask) | (d1 & !mask),
        (r6 & mask) | (d2 & !mask),
        (r7 & mask) | (d3 & !mask),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_u256() {
        let val = U256::from(42u64);
        let fp = Fp::from_u256(val);
        assert_eq!(fp.to_u256(), val);
    }

    #[test]
    fn test_roundtrip_large() {
        let val = U256::from(123456789u64);
        let fp = Fp::from_u256(val);
        assert_eq!(fp.to_u256(), val);
    }

    #[test]
    fn test_one() {
        let one = Fp::from_u256(U256::from(1u64));
        assert_eq!(one, Fp::ONE);
        assert_eq!(one.to_u256(), U256::from(1u64));
    }

    #[test]
    fn test_zero() {
        let zero = Fp::from_u256(U256::ZERO);
        assert_eq!(zero, Fp::ZERO);
        assert_eq!(zero.to_u256(), U256::ZERO);
    }

    #[test]
    fn test_add_basic() {
        let a = Fp::from_u256(U256::from(100u64));
        let b = Fp::from_u256(U256::from(200u64));
        let c = Fp::add(a, b);
        assert_eq!(c.to_u256(), U256::from(300u64));
    }

    #[test]
    fn test_add_with_reduction() {
        let p_minus_1 = U256::from_limbs(MODULUS).wrapping_sub(U256::from(1u64));
        let a = Fp::from_u256(p_minus_1);
        let b = Fp::from_u256(U256::from(2u64));
        let c = Fp::add(a, b);
        assert_eq!(c.to_u256(), U256::from(1u64));
    }

    #[test]
    fn test_sub() {
        let a = Fp::from_u256(U256::from(200u64));
        let b = Fp::from_u256(U256::from(100u64));
        let c = Fp::sub(a, b);
        assert_eq!(c.to_u256(), U256::from(100u64));
    }

    #[test]
    fn test_sub_underflow() {
        let a = Fp::from_u256(U256::from(100u64));
        let b = Fp::from_u256(U256::from(200u64));
        let c = Fp::sub(a, b);
        let expected = U256::from_limbs(MODULUS).wrapping_sub(U256::from(100u64));
        assert_eq!(c.to_u256(), expected);
    }

    #[test]
    fn test_mul_small() {
        let a = Fp::from_u256(U256::from(7u64));
        let b = Fp::from_u256(U256::from(8u64));
        let c = Fp::mul(a, b);
        assert_eq!(c.to_u256(), U256::from(56u64));
    }

    #[test]
    fn test_mul_large() {
        let p_minus_1 = U256::from_limbs(MODULUS).wrapping_sub(U256::from(1u64));
        let a = Fp::from_u256(p_minus_1);
        let b = Fp::from_u256(U256::from(2u64));
        let c = Fp::mul(a, b);
        let expected = U256::from_limbs(MODULUS).wrapping_sub(U256::from(2u64));
        assert_eq!(c.to_u256(), expected);
    }

    #[test]
    fn test_mul_one() {
        let a = Fp::from_u256(U256::from(42u64));
        let c = Fp::mul(a, Fp::ONE);
        assert_eq!(c, a);
    }

    #[test]
    fn test_mul_zero() {
        let a = Fp::from_u256(U256::from(42u64));
        let c = Fp::mul(a, Fp::ZERO);
        assert_eq!(c, Fp::ZERO);
    }

    #[test]
    fn test_pow_basic() {
        let base = Fp::from_u256(U256::from(2u64));
        let result = Fp::pow(base, U256::from(10u64));
        assert_eq!(result.to_u256(), U256::from(1024u64));
    }

    #[test]
    fn test_pow_fermat() {
        let a = Fp::from_u256(U256::from(7u64));
        let p_minus_1 = U256::from_limbs(MODULUS).wrapping_sub(U256::from(1u64));
        let result = Fp::pow(a, p_minus_1);
        assert_eq!(result, Fp::ONE);
    }

    #[test]
    fn test_inv_basic() {
        let a = Fp::from_u256(U256::from(7u64));
        let a_inv = Fp::inv(a);
        let product = Fp::mul(a, a_inv);
        assert_eq!(product, Fp::ONE);
    }

    #[test]
    fn test_inv_large() {
        let a = Fp::from_u256(U256::from(123456789u64));
        let a_inv = Fp::inv(a);
        let product = Fp::mul(a, a_inv);
        assert_eq!(product, Fp::ONE);
    }

    #[test]
    fn test_div_basic() {
        let a = Fp::from_u256(U256::from(10u64));
        let b = Fp::from_u256(U256::from(2u64));
        let c = Fp::div(a, b);
        assert_eq!(c.to_u256(), U256::from(5u64));
    }

    #[test]
    fn test_div_roundtrip() {
        let a = Fp::from_u256(U256::from(42u64));
        let b = Fp::from_u256(U256::from(13u64));
        let product = Fp::mul(a, b);
        let result = Fp::div(product, b);
        assert_eq!(result, a);
    }

    #[test]
    fn test_neg() {
        let a = Fp::from_u256(U256::from(5u64));
        let neg_a = Fp::neg(a);
        let sum = Fp::add(a, neg_a);
        assert_eq!(sum, Fp::ZERO);
    }

    #[test]
    fn test_neg_zero() {
        assert_eq!(Fp::neg(Fp::ZERO), Fp::ZERO);
    }

    #[test]
    fn test_commutativity() {
        let a = Fp::from_u256(U256::from(123u64));
        let b = Fp::from_u256(U256::from(456u64));
        assert_eq!(Fp::mul(a, b), Fp::mul(b, a));
        assert_eq!(Fp::add(a, b), Fp::add(b, a));
    }

    #[test]
    fn test_associativity() {
        let a = Fp::from_u256(U256::from(11u64));
        let b = Fp::from_u256(U256::from(22u64));
        let c = Fp::from_u256(U256::from(33u64));
        assert_eq!(
            Fp::mul(Fp::mul(a, b), c),
            Fp::mul(a, Fp::mul(b, c))
        );
    }

    #[test]
    fn test_distributivity() {
        let a = Fp::from_u256(U256::from(5u64));
        let b = Fp::from_u256(U256::from(7u64));
        let c = Fp::from_u256(U256::from(11u64));
        // a * (b + c) = a*b + a*c
        let lhs = Fp::mul(a, Fp::add(b, c));
        let rhs = Fp::add(Fp::mul(a, b), Fp::mul(a, c));
        assert_eq!(lhs, rhs);
    }
}
