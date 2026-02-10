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

/// Convert evaluations on a domain to polynomial coefficients (inverse NTT).
///
/// Given evaluations [f(1), f(ω), f(ω²), ..., f(ω^{n-1})] on a domain with
/// generator ω of order n, computes coefficients [c_0, c_1, ..., c_{n-1}]
/// such that f(x) = c_0 + c_1*x + c_2*x² + ... + c_{n-1}*x^{n-1}.
///
/// Uses the formula: c_k = (1/n) * Σ_{j=0}^{n-1} e_j * ω^{-jk}
pub fn inverse_ntt(evals: &[U256], log_domain_size: u32) -> Vec<U256> {
    let n = evals.len();
    assert_eq!(n, 1 << log_domain_size);
    let gen = domain_generator(log_domain_size);
    let gen_inv = BN254Field::inv(gen);
    let n_inv = BN254Field::inv(U256::from(n as u64));

    let mut coeffs = Vec::with_capacity(n);
    for k in 0..n {
        let mut c_k = U256::ZERO;
        for j in 0..n {
            let exp = ((j as u64) * (k as u64)) % (n as u64);
            let omega_inv_jk = BN254Field::pow(gen_inv, U256::from(exp));
            c_k = BN254Field::add(c_k, BN254Field::mul(evals[j], omega_inv_jk));
        }
        coeffs.push(BN254Field::mul(c_k, n_inv));
    }
    coeffs
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
