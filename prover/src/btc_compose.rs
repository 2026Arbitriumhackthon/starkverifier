//! BTC Lock Composition Polynomial
//!
//! Combines BTC Lock AIR constraint quotients into a single composition polynomial.
//! 8 transition constraints + 4 boundary constraints = 12 alphas.

use alloy_primitives::U256;
use crate::field::BN254Field;

/// Evaluate the BTC Lock composition polynomial at LDE domain points.
///
/// # Arguments
/// * `trace_lde` - [lock_amount, amount_inv, timelock_delta, delta_inv, script_type] LDE columns
/// * `lde_domain` - LDE domain points
/// * `trace_gen` - Generator of the trace domain
/// * `trace_len` - Length of the trace (8)
/// * `public_inputs` - [lock_amount, timelock_height, current_height, script_type]
/// * `alphas` - 12 random combination coefficients
pub fn evaluate_btc_composition_on_lde(
    trace_lde: &[&[U256]; 5],
    lde_domain: &[U256],
    trace_gen: U256,
    trace_len: u64,
    public_inputs: &[U256; 4],
    alphas: &[U256; 12],
) -> Vec<U256> {
    let lde_size = lde_domain.len();
    let blowup = (lde_size as u64) / trace_len;
    let mut composition = vec![U256::ZERO; lde_size];

    let trace_domain_first = U256::from(1u64); // g^0
    let trace_domain_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));
    let one = U256::from(1u64);
    let two = U256::from(2u64);

    // Expected delta: timelock_height - current_height
    let expected_delta = BN254Field::sub(public_inputs[1], public_inputs[2]);

    for i in 0..lde_size {
        let x = lde_domain[i];

        let c0 = trace_lde[0][i]; // lock_amount
        let c1 = trace_lde[1][i]; // amount_inv
        let c2 = trace_lde[2][i]; // timelock_delta
        let c3 = trace_lde[3][i]; // delta_inv
        let c4 = trace_lde[4][i]; // script_type

        let next_i = (i + blowup as usize) % lde_size;
        let c0_next = trace_lde[0][next_i];
        let c1_next = trace_lde[1][next_i];
        let c2_next = trace_lde[2][next_i];
        let c3_next = trace_lde[3][next_i];
        let c4_next = trace_lde[4][next_i];

        // TC0-TC4: Immutability
        let tc0 = BN254Field::sub(c0_next, c0);
        let tc1 = BN254Field::sub(c1_next, c1);
        let tc2 = BN254Field::sub(c2_next, c2);
        let tc3 = BN254Field::sub(c3_next, c3);
        let tc4 = BN254Field::sub(c4_next, c4);

        // TC5: lock_amount * amount_inv - 1 = 0
        let tc5 = BN254Field::sub(BN254Field::mul(c0, c1), one);

        // TC6: timelock_delta * delta_inv - 1 = 0
        let tc6 = BN254Field::sub(BN254Field::mul(c2, c3), one);

        // TC7: (script_type - 1) * (script_type - 2) = 0
        let tc7 = BN254Field::mul(BN254Field::sub(c4, one), BN254Field::sub(c4, two));

        // Transition zerofier: (x^N - 1) / (x - g^(N-1))
        let x_n = BN254Field::pow(x, U256::from(trace_len));
        let zerofier_num = BN254Field::sub(x_n, one);
        let zerofier_den = BN254Field::sub(x, trace_domain_last);

        if zerofier_den == U256::ZERO {
            composition[i] = U256::ZERO;
            continue;
        }

        let zerofier = BN254Field::div(zerofier_num, zerofier_den);

        let tq0 = BN254Field::div(tc0, zerofier);
        let tq1 = BN254Field::div(tc1, zerofier);
        let tq2 = BN254Field::div(tc2, zerofier);
        let tq3 = BN254Field::div(tc3, zerofier);
        let tq4 = BN254Field::div(tc4, zerofier);
        let tq5 = BN254Field::div(tc5, zerofier);
        let tq6 = BN254Field::div(tc6, zerofier);
        let tq7 = BN254Field::div(tc7, zerofier);

        // Boundary constraints
        let den_first = BN254Field::sub(x, trace_domain_first);
        let den_last = BN254Field::sub(x, trace_domain_last);

        // BC0: lock_amount[0] = public_inputs[0]
        let bq0 = if den_first != U256::ZERO {
            BN254Field::div(BN254Field::sub(c0, public_inputs[0]), den_first)
        } else {
            U256::ZERO
        };

        // BC1: timelock_delta[0] = expected_delta
        let bq1 = if den_first != U256::ZERO {
            BN254Field::div(BN254Field::sub(c2, expected_delta), den_first)
        } else {
            U256::ZERO
        };

        // BC2: script_type[0] = public_inputs[3]
        let bq2 = if den_first != U256::ZERO {
            BN254Field::div(BN254Field::sub(c4, public_inputs[3]), den_first)
        } else {
            U256::ZERO
        };

        // BC3: lock_amount[N-1] = public_inputs[0] (end consistency)
        let bq3 = if den_last != U256::ZERO {
            BN254Field::div(BN254Field::sub(c0, public_inputs[0]), den_last)
        } else {
            U256::ZERO
        };

        // Combine with random coefficients (8 TC + 4 BC = 12 alphas)
        let mut comp = BN254Field::mul(alphas[0], tq0);
        comp = BN254Field::add(comp, BN254Field::mul(alphas[1], tq1));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[2], tq2));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[3], tq3));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[4], tq4));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[5], tq5));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[6], tq6));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[7], tq7));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[8], bq0));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[9], bq1));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[10], bq2));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[11], bq3));

        composition[i] = comp;
    }

    composition
}
