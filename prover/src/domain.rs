//! Evaluation Domain (prover side)
//!
//! Same roots of unity as the on-chain verifier.

use alloy_primitives::U256;
use crate::field::BN254Field;

/// Generator of the 2^28 multiplicative subgroup of BN254 scalar field.
/// g = 5^((p-1)/2^28) mod p
pub const GENERATOR_2_28: U256 = U256::from_limbs([
    0x9bd61b6e725b19f0,
    0x402d111e41112ed4,
    0x00e0a7eb8ef62abc,
    0x2a3c09f0a58a7e85,
]);

pub const TWO_ADICITY: u32 = 28;

/// Get generator for a 2^k-sized domain.
pub fn domain_generator(log_size: u32) -> U256 {
    assert!(log_size <= TWO_ADICITY, "log_size exceeds two-adicity");
    let exp_power = TWO_ADICITY - log_size;
    let exp = U256::from(1u64) << exp_power;
    BN254Field::pow(GENERATOR_2_28, exp)
}

/// Evaluate g^index.
pub fn evaluate_at(gen: U256, index: u64) -> U256 {
    BN254Field::pow(gen, U256::from(index))
}

/// Get all domain elements for a domain of size 2^log_size.
pub fn get_domain(log_size: u32) -> Vec<U256> {
    let size = 1usize << log_size;
    let gen = domain_generator(log_size);
    let mut domain = Vec::with_capacity(size);
    let mut current = U256::from(1u64);
    for _ in 0..size {
        domain.push(current);
        current = BN254Field::mul(current, gen);
    }
    domain
}

/// Bit-reversal permutation (in-place).
fn bit_reverse_permutation(a: &mut [U256], log_n: u32) {
    let n = a.len();
    for i in 0..n {
        let j = (i as u32).reverse_bits() >> (32 - log_n);
        if i < j as usize {
            a.swap(i, j as usize);
        }
    }
}

/// Radix-2 Cooley-Tukey FFT (iterative, in-place).
///
/// Transforms polynomial coefficients to evaluations on the domain
/// {1, ω, ω², ..., ω^{n-1}} where ω = domain_generator(log_size).
pub fn fft(coeffs: &mut [U256], log_size: u32) {
    let n = coeffs.len();
    assert_eq!(n, 1 << log_size);
    if n == 1 {
        return;
    }

    bit_reverse_permutation(coeffs, log_size);

    for s in 0..log_size {
        let m = 1usize << (s + 1);
        let half_m = m / 2;
        let w_m = domain_generator(s + 1);

        let mut k = 0;
        while k < n {
            let mut w = U256::from(1u64);
            for j in 0..half_m {
                let u = coeffs[k + j];
                let t = BN254Field::mul(w, coeffs[k + j + half_m]);
                coeffs[k + j] = BN254Field::add(u, t);
                coeffs[k + j + half_m] = BN254Field::sub(u, t);
                w = BN254Field::mul(w, w_m);
            }
            k += m;
        }
    }
}

/// Inverse FFT: evaluations on domain → polynomial coefficients (in-place).
///
/// Given evaluations [f(1), f(ω), f(ω²), ..., f(ω^{n-1})], computes
/// coefficients [c_0, c_1, ..., c_{n-1}] such that
/// f(x) = c_0 + c_1*x + ... + c_{n-1}*x^{n-1}.
pub fn ifft(evals: &mut [U256], log_size: u32) {
    let n = evals.len();
    assert_eq!(n, 1 << log_size);
    if n == 1 {
        return;
    }

    bit_reverse_permutation(evals, log_size);

    for s in 0..log_size {
        let m = 1usize << (s + 1);
        let half_m = m / 2;
        // Use inverse generator for IFFT
        let w_m = BN254Field::inv(domain_generator(s + 1));

        let mut k = 0;
        while k < n {
            let mut w = U256::from(1u64);
            for j in 0..half_m {
                let u = evals[k + j];
                let t = BN254Field::mul(w, evals[k + j + half_m]);
                evals[k + j] = BN254Field::add(u, t);
                evals[k + j + half_m] = BN254Field::sub(u, t);
                w = BN254Field::mul(w, w_m);
            }
            k += m;
        }
    }

    // Multiply by 1/n
    let n_inv = BN254Field::inv(U256::from(n as u64));
    for val in evals.iter_mut() {
        *val = BN254Field::mul(*val, n_inv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_ifft_roundtrip() {
        let original = vec![
            U256::from(42u64),
            U256::from(7u64),
            U256::from(1337u64),
            U256::from(0u64),
        ];
        let mut data = original.clone();
        fft(&mut data, 2);
        // After FFT, data should differ from original (not identity)
        assert_ne!(data, original);
        ifft(&mut data, 2);
        assert_eq!(data, original);
    }

    #[test]
    fn test_fft_ifft_roundtrip_large() {
        let n = 16;
        let original: Vec<U256> = (0..n).map(|i| U256::from(i as u64 * 31 + 5)).collect();
        let mut data = original.clone();
        fft(&mut data, 4);
        ifft(&mut data, 4);
        assert_eq!(data, original);
    }

    #[test]
    fn test_ifft_fft_roundtrip() {
        // Also test the reverse direction: ifft then fft
        let original = vec![
            U256::from(100u64),
            U256::from(200u64),
            U256::from(300u64),
            U256::from(400u64),
        ];
        let mut data = original.clone();
        ifft(&mut data, 2);
        fft(&mut data, 2);
        assert_eq!(data, original);
    }
}

/// Get coset domain: offset * g^i for each i.
pub fn get_coset_domain(log_size: u32, offset: U256) -> Vec<U256> {
    let size = 1usize << log_size;
    let gen = domain_generator(log_size);
    let mut domain = Vec::with_capacity(size);
    let mut current = offset;
    for _ in 0..size {
        domain.push(current);
        current = BN254Field::mul(current, gen);
    }
    domain
}
