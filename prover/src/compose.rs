//! Composition Polynomial
//!
//! Combines AIR constraint quotients into a single composition polynomial.
//! The composition polynomial is a low-degree polynomial that encodes
//! all STARK constraints into one.

use alloy_primitives::U256;
use crate::field::BN254Field;
use crate::poseidon::PoseidonHasher;

/// Evaluate the composition polynomial at given LDE domain points.
///
/// For each point x in the LDE domain:
///   C(x) = alpha_t0 * TQ0(x) + alpha_t1 * TQ1(x) + alpha_b0 * BQ0(x) + alpha_b1 * BQ1(x) + alpha_b2 * BQ2(x)
///
/// Where:
///   TQ_i(x) = transition_constraint_i(x) / Z_T(x)
///   BQ_i(x) = (trace_col(x) - boundary_value) / (x - boundary_point)
///
/// # Arguments
/// * `trace_lde_a` - LDE evaluations of trace column a
/// * `trace_lde_b` - LDE evaluations of trace column b
/// * `lde_domain` - LDE domain points
/// * `trace_gen` - Generator of the trace domain
/// * `trace_len` - Length of the trace
/// * `public_inputs` - [first_a, first_b, claimed_result]
/// * `alphas` - Random combination coefficients [alpha_t0, alpha_t1, alpha_b0, alpha_b1, alpha_b2]
pub fn evaluate_composition_on_lde(
    trace_lde_a: &[U256],
    trace_lde_b: &[U256],
    lde_domain: &[U256],
    trace_gen: U256,
    trace_len: u64,
    public_inputs: &[U256; 3],
    alphas: &[U256; 5],
) -> Vec<U256> {
    let lde_size = lde_domain.len();
    let blowup = (lde_size as u64) / trace_len;
    let mut composition = vec![U256::ZERO; lde_size];

    let trace_domain_first = U256::from(1u64); // g^0
    let trace_domain_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));

    for i in 0..lde_size {
        let x = lde_domain[i];
        let a_x = trace_lde_a[i];
        let b_x = trace_lde_b[i];

        // "Next" values: trace evaluated at x * trace_gen
        // In the LDE, index i maps to index (i + blowup) mod lde_size
        let next_i = (i + blowup as usize) % lde_size;
        let a_next = trace_lde_a[next_i];
        let b_next = trace_lde_b[next_i];

        // Transition constraints
        let tc0 = BN254Field::sub(a_next, b_x);      // a_next - b = 0
        let tc1 = BN254Field::sub(b_next, BN254Field::add(a_x, b_x)); // b_next - (a + b) = 0

        // Transition zerofier: (x^N - 1) / (x - g^(N-1))
        let x_n = BN254Field::pow(x, U256::from(trace_len));
        let zerofier_num = BN254Field::sub(x_n, U256::from(1u64));
        let zerofier_den = BN254Field::sub(x, trace_domain_last);

        // Skip if we're exactly at a trace domain point where zerofier_den is 0
        if zerofier_den == U256::ZERO {
            // At trace domain points the constraints should be 0 / 0
            // Set composition to 0 (will be interpolated over)
            composition[i] = U256::ZERO;
            continue;
        }

        let zerofier = BN254Field::div(zerofier_num, zerofier_den);

        let tq0 = BN254Field::div(tc0, zerofier);
        let tq1 = BN254Field::div(tc1, zerofier);

        // Boundary constraints
        let den_first = BN254Field::sub(x, trace_domain_first);
        let den_last = BN254Field::sub(x, trace_domain_last);

        let bq0 = if den_first != U256::ZERO {
            BN254Field::div(BN254Field::sub(a_x, public_inputs[0]), den_first)
        } else {
            U256::ZERO
        };

        let bq1 = if den_first != U256::ZERO {
            BN254Field::div(BN254Field::sub(b_x, public_inputs[1]), den_first)
        } else {
            U256::ZERO
        };

        let bq2 = if den_last != U256::ZERO {
            BN254Field::div(BN254Field::sub(b_x, public_inputs[2]), den_last)
        } else {
            U256::ZERO
        };

        // Combine with random coefficients
        let mut comp = BN254Field::mul(alphas[0], tq0);
        comp = BN254Field::add(comp, BN254Field::mul(alphas[1], tq1));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[2], bq0));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[3], bq1));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[4], bq2));

        composition[i] = comp;
    }

    composition
}
