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
use crate::domain::domain_generator;
use crate::mock_data::SHARPE_SCALE;

/// Evaluate the Sharpe composition polynomial at LDE domain points.
///
/// Uses batch inversion (Montgomery's trick) to eliminate per-point
/// modular inversions: ~98K inversions → 1 inversion + ~300K muls.
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
    let one = U256::from(1u64);
    let scale = U256::from(SHARPE_SCALE);
    let trace_domain_last = BN254Field::pow(trace_gen, U256::from(trace_len - 1));

    // Precompute x^N using cyclic property.
    // x_i = ω^i, so x_i^N = (ω^N)^i with period = blowup.
    // ω^N = domain_generator(log_blowup).
    let log_blowup = blowup.trailing_zeros();
    let omega_n = domain_generator(log_blowup);
    let mut x_n_cycle = Vec::with_capacity(blowup as usize);
    let mut cur = one;
    for _ in 0..blowup {
        x_n_cycle.push(cur);
        cur = BN254Field::mul(cur, omega_n);
    }

    // Phase 1: Collect all denominators for batch inversion.
    // Per point i: [zerofier_num, den_first, den_last]
    let mut denoms = vec![U256::ZERO; lde_size * 3];
    for i in 0..lde_size {
        let x = lde_domain[i];
        let x_n = x_n_cycle[i % blowup as usize];
        denoms[3 * i] = BN254Field::sub(x_n, one);              // x^N - 1
        denoms[3 * i + 1] = BN254Field::sub(x, one);            // x - 1
        denoms[3 * i + 2] = BN254Field::sub(x, trace_domain_last); // x - g^(N-1)
    }

    // Phase 2: Batch invert (1 inversion + ~3n multiplications)
    BN254Field::batch_invert(&mut denoms);

    // Phase 3: Evaluate constraints using multiplications only
    let mut composition = vec![U256::ZERO; lde_size];

    for i in 0..lde_size {
        let x = lde_domain[i];
        let inv_zerofier_num = denoms[3 * i];
        let inv_den_first = denoms[3 * i + 1];
        let inv_den_last = denoms[3 * i + 2];
        let den_last = BN254Field::sub(x, trace_domain_last);

        // Current row
        let c0 = trace_lde[0][i];
        let c1 = trace_lde[1][i];
        let c2 = trace_lde[2][i];
        let c3 = trace_lde[3][i];
        let c4 = trace_lde[4][i];
        let c5 = trace_lde[5][i];

        // Next row
        let next_i = (i + blowup as usize) % lde_size;
        let c0_next = trace_lde[0][next_i];
        let c1_next = trace_lde[1][next_i];
        let c2_next = trace_lde[2][next_i];
        let c3_next = trace_lde[3][next_i];
        let c4_next = trace_lde[4][next_i];
        let c5_next = trace_lde[5][next_i];

        // Transition constraints
        let tc0 = BN254Field::sub(c2_next, BN254Field::add(c2, c0_next));
        let tc1 = BN254Field::sub(c1, BN254Field::mul(c0, c0));
        let tc2 = BN254Field::sub(c3_next, BN254Field::add(c3, c1_next));
        let tc3 = BN254Field::sub(c4_next, c4);
        let tc4 = BN254Field::sub(c5_next, c5);

        // tq_i = tc_i / zerofier = tc_i * den_last * inv(zerofier_num)
        let tq_factor = BN254Field::mul(den_last, inv_zerofier_num);
        let tq0 = BN254Field::mul(tc0, tq_factor);
        let tq1 = BN254Field::mul(tc1, tq_factor);
        let tq2 = BN254Field::mul(tc2, tq_factor);
        let tq3 = BN254Field::mul(tc3, tq_factor);
        let tq4 = BN254Field::mul(tc4, tq_factor);

        // Boundary constraints: bc / den = bc * inv(den)
        let bq0 = BN254Field::mul(BN254Field::sub(c2, c0), inv_den_first);
        let bq1 = BN254Field::mul(BN254Field::sub(c3, c1), inv_den_first);
        let bq2 = BN254Field::mul(BN254Field::sub(c2, public_inputs[1]), inv_den_last);

        let cum_ret_sq = BN254Field::mul(c2, c2);
        let bc3_lhs = BN254Field::mul(cum_ret_sq, scale);
        let n_cum_sq = BN254Field::mul(public_inputs[0], c3);
        let denom_inner = BN254Field::sub(n_cum_sq, cum_ret_sq);
        let bc3_rhs = BN254Field::mul(public_inputs[2], denom_inner);
        let bc3_num = BN254Field::sub(bc3_lhs, bc3_rhs);
        let bq3 = BN254Field::mul(bc3_num, inv_den_last);

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
