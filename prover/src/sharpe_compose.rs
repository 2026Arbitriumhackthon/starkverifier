//! Sharpe Ratio Composition Polynomial
//!
//! Combines Sharpe AIR constraint quotients into a single composition polynomial.
//! 5 transition constraints + 4 boundary constraints = 9 alphas.
//!
//! Trace columns: [return, return_sq, cum_ret, cum_sq, trade_count, dataset_commitment]
//!
//! Transition constraints (applied to consecutive rows):
//!   TC0: cum_ret_next = cum_ret + ret_next
//!   TC1: ret_sq = ret * ret
//!   TC2: cum_sq_next = cum_sq + ret_sq_next
//!   TC3: trade_count_next = trade_count (immutability)
//!   TC4: dataset_commitment_next = dataset_commitment (immutability)
//!
//! Boundary constraints:
//!   BC0: cum_ret[0] = ret[0]                                    (at first row)
//!   BC1: cum_sq[0] = ret_sq[0]                                  (at first row)
//!   BC2: cum_ret[N-1] = total_return                            (at last row)
//!   BC3: cum_ret^2 * SCALE = sharpe_sq * (n * cum_sq - cum_ret^2)  (at last row)

use alloy_primitives::U256;
use crate::field::BN254Field;
use crate::mock_data::SHARPE_SCALE;

/// Evaluate the Sharpe composition polynomial at LDE domain points.
///
/// # Arguments
/// * `trace_lde` - [return, return_sq, cum_ret, cum_sq, trade_count, dataset_commit] LDE columns
/// * `lde_domain` - LDE domain points
/// * `trace_gen` - Generator of the trace domain
/// * `trace_len` - Padded trace length (power of 2)
/// * `public_inputs` - [trade_count, total_return, sharpe_sq_scaled, merkle_root]
/// * `alphas` - 9 random combination coefficients
pub fn evaluate_sharpe_composition_on_lde(
    trace_lde: &[&[U256]; 6],
    lde_domain: &[U256],
    trace_gen: U256,
    trace_len: u64,
    public_inputs: &[U256; 4],
    alphas: &[U256; 9],
) -> Vec<U256> {
    let lde_size = lde_domain.len();
    let blowup = (lde_size as u64) / trace_len;
    let mut composition = vec![U256::ZERO; lde_size];

    let trace_domain_first = U256::from(1u64); // g^0
    let trace_domain_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));
    let one = U256::from(1u64);
    let scale = U256::from(SHARPE_SCALE);

    for i in 0..lde_size {
        let x = lde_domain[i];

        // Current row values
        let c0 = trace_lde[0][i]; // return
        let c1 = trace_lde[1][i]; // return_sq
        let c2 = trace_lde[2][i]; // cum_ret
        let c3 = trace_lde[3][i]; // cum_sq
        let c4 = trace_lde[4][i]; // trade_count
        let c5 = trace_lde[5][i]; // dataset_commitment

        // Next row values
        let next_i = (i + blowup as usize) % lde_size;
        let c0_next = trace_lde[0][next_i]; // return_next
        let c1_next = trace_lde[1][next_i]; // return_sq_next
        let c2_next = trace_lde[2][next_i]; // cum_ret_next
        let c3_next = trace_lde[3][next_i]; // cum_sq_next
        let c4_next = trace_lde[4][next_i]; // trade_count_next
        let c5_next = trace_lde[5][next_i]; // dataset_commitment_next

        // TC0: cum_ret_next - cum_ret - ret_next = 0
        let tc0 = BN254Field::sub(c2_next, BN254Field::add(c2, c0_next));

        // TC1: ret_sq - ret * ret = 0
        let tc1 = BN254Field::sub(c1, BN254Field::mul(c0, c0));

        // TC2: cum_sq_next - cum_sq - ret_sq_next = 0
        let tc2 = BN254Field::sub(c3_next, BN254Field::add(c3, c1_next));

        // TC3: trade_count_next - trade_count = 0 (immutability)
        let tc3 = BN254Field::sub(c4_next, c4);

        // TC4: dataset_commitment_next - dataset_commitment = 0 (immutability)
        let tc4 = BN254Field::sub(c5_next, c5);

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

        // Boundary constraints
        let den_first = BN254Field::sub(x, trace_domain_first);
        let den_last = BN254Field::sub(x, trace_domain_last);

        // BC0: (cum_ret - ret) / (x - g^0) at first row
        let bq0 = if den_first != U256::ZERO {
            BN254Field::div(BN254Field::sub(c2, c0), den_first)
        } else {
            U256::ZERO
        };

        // BC1: (cum_sq - ret_sq) / (x - g^0) at first row
        let bq1 = if den_first != U256::ZERO {
            BN254Field::div(BN254Field::sub(c3, c1), den_first)
        } else {
            U256::ZERO
        };

        // BC2: (cum_ret - total_return) / (x - g^(N-1)) at last row
        let bq2 = if den_last != U256::ZERO {
            BN254Field::div(BN254Field::sub(c2, public_inputs[1]), den_last)
        } else {
            U256::ZERO
        };

        // BC3: (cum_ret^2 * SCALE - sharpe_sq * (n * cum_sq - cum_ret^2)) / (x - g^(N-1))
        let cum_ret_sq = BN254Field::mul(c2, c2);
        let bc3_lhs = BN254Field::mul(cum_ret_sq, scale);
        let n_cum_sq = BN254Field::mul(public_inputs[0], c3);
        let denom_inner = BN254Field::sub(n_cum_sq, cum_ret_sq);
        let bc3_rhs = BN254Field::mul(public_inputs[2], denom_inner);
        let bc3_num = BN254Field::sub(bc3_lhs, bc3_rhs);
        let bq3 = if den_last != U256::ZERO {
            BN254Field::div(bc3_num, den_last)
        } else {
            U256::ZERO
        };

        // Combine with random coefficients (5 TC + 4 BC = 9 alphas)
        let mut comp = BN254Field::mul(alphas[0], tq0);
        comp = BN254Field::add(comp, BN254Field::mul(alphas[1], tq1));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[2], tq2));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[3], tq3));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[4], tq4));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[5], bq0));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[6], bq1));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[7], bq2));
        comp = BN254Field::add(comp, BN254Field::mul(alphas[8], bq3));

        composition[i] = comp;
    }

    composition
}
