//! Sharpe Ratio AIR (Algebraic Intermediate Representation)
//!
//! Defines the constraint system for Sharpe ratio verification.
//! The trace has 6 columns:
//!   [return, return_sq, cum_ret, cum_sq, trade_count, dataset_commitment]
//!
//! Transition constraints (5):
//!   TC0: cum_ret_next = cum_ret + ret_next
//!   TC1: ret_sq = ret * ret
//!   TC2: cum_sq_next = cum_sq + ret_sq_next
//!   TC3: trade_count_next = trade_count (immutability)
//!   TC4: 0 (dataset_commitment placeholder)
//!
//! Boundary constraints (4):
//!   BC0: cum_ret[0] = ret[0]                                          (at first row)
//!   BC1: cum_sq[0] = ret_sq[0]                                        (at first row)
//!   BC2: cum_ret[N-1] = total_return                                  (at last row)
//!   BC3: cum_ret^2 * SCALE - sharpe_sq * (n * cum_sq - cum_ret^2) = 0 (at last row)

use crate::field::Fp;
use crate::field::BN254Field;
use alloy_primitives::U256;

/// Number of columns in the Sharpe trace
pub const NUM_COLUMNS: usize = 6;

/// Number of transition constraints
pub const NUM_TRANSITION_CONSTRAINTS: usize = 5;

/// Number of boundary constraints
pub const NUM_BOUNDARY_CONSTRAINTS: usize = 4;

/// Total number of alphas needed (transition + boundary)
pub const NUM_ALPHAS: usize = NUM_TRANSITION_CONSTRAINTS + NUM_BOUNDARY_CONSTRAINTS;

/// SHARPE_SCALE = 10000 in Montgomery form
fn sharpe_scale_fp() -> Fp {
    Fp::from_u256(U256::from(10000u64))
}

/// Compute the transition constraint zerofier at OOD point z.
/// Z_T(z) = (z^n - 1) / (z - g^{n-1})
pub fn transition_zerofier_at(z: Fp, trace_len: u64, trace_generator: Fp) -> Fp {
    let z_n = BN254Field::pow(z, U256::from(trace_len));
    let numerator = BN254Field::sub(z_n, Fp::ONE);

    let g_last = BN254Field::pow(trace_generator, U256::from(trace_len - 1));
    let denominator = BN254Field::sub(z, g_last);

    BN254Field::div(numerator, denominator)
}

/// Evaluate transition constraints at a given point.
///
/// current/next: [return, return_sq, cum_ret, cum_sq, trade_count, dataset_commitment]
pub fn evaluate_transition(current: [Fp; 6], next: [Fp; 6]) -> [Fp; 5] {
    // TC0: cum_ret_next - cum_ret - ret_next = 0
    let tc0 = BN254Field::sub(next[2], BN254Field::add(current[2], next[0]));

    // TC1: ret_sq - ret * ret = 0
    let tc1 = BN254Field::sub(current[1], BN254Field::mul(current[0], current[0]));

    // TC2: cum_sq_next - cum_sq - ret_sq_next = 0
    let tc2 = BN254Field::sub(next[3], BN254Field::add(current[3], next[1]));

    // TC3: trade_count_next - trade_count = 0 (immutability)
    let tc3 = BN254Field::sub(next[4], current[4]);

    // TC4: 0 (placeholder for dataset_commitment)
    let tc4 = Fp::ZERO;

    [tc0, tc1, tc2, tc3, tc4]
}

/// Evaluate transition constraints at an out-of-domain (OOD) point.
pub fn evaluate_transition_ood(trace_at_z: [Fp; 6], trace_at_zg: [Fp; 6]) -> [Fp; 5] {
    evaluate_transition(trace_at_z, trace_at_zg)
}

/// Compute the boundary constraint quotient evaluations at OOD point z.
///
/// public_inputs: [trade_count, total_return, sharpe_sq_scaled, merkle_root]
pub fn evaluate_boundary_quotients(
    trace_at_z: [Fp; 6],
    z: Fp,
    trace_domain_first: Fp,
    trace_domain_last: Fp,
    public_inputs: [Fp; 4],
) -> [Fp; 4] {
    let den_first = BN254Field::sub(z, trace_domain_first);
    let den_last = BN254Field::sub(z, trace_domain_last);
    let scale = sharpe_scale_fp();

    // BC0: (cum_ret - ret) / (z - g^0) at first row
    let num0 = BN254Field::sub(trace_at_z[2], trace_at_z[0]);
    let bq0 = BN254Field::div(num0, den_first);

    // BC1: (cum_sq - ret_sq) / (z - g^0) at first row
    let num1 = BN254Field::sub(trace_at_z[3], trace_at_z[1]);
    let bq1 = BN254Field::div(num1, den_first);

    // BC2: (cum_ret - total_return) / (z - g^(N-1)) at last row
    let num2 = BN254Field::sub(trace_at_z[2], public_inputs[1]);
    let bq2 = BN254Field::div(num2, den_last);

    // BC3: (cum_ret^2 * SCALE - sharpe_sq * (n * cum_sq - cum_ret^2)) / (z - g^(N-1))
    let cum_ret = trace_at_z[2];
    let cum_sq = trace_at_z[3];
    let cum_ret_sq = BN254Field::mul(cum_ret, cum_ret);
    let lhs = BN254Field::mul(cum_ret_sq, scale);
    let n_cum_sq = BN254Field::mul(public_inputs[0], cum_sq);
    let denom_inner = BN254Field::sub(n_cum_sq, cum_ret_sq);
    let rhs = BN254Field::mul(public_inputs[2], denom_inner);
    let num3 = BN254Field::sub(lhs, rhs);
    let bq3 = BN254Field::div(num3, den_last);

    [bq0, bq1, bq2, bq3]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_sharpe_pair() -> ([Fp; 6], [Fp; 6]) {
        // Row i: return=100, return_sq=10000, cum_ret=100, cum_sq=10000, n=2, commit=0
        let ret = Fp::from_u256(U256::from(100u64));
        let ret_sq = Fp::from_u256(U256::from(10000u64));
        let cum_ret = Fp::from_u256(U256::from(100u64));
        let cum_sq = Fp::from_u256(U256::from(10000u64));
        let n = Fp::from_u256(U256::from(2u64));
        let current = [ret, ret_sq, cum_ret, cum_sq, n, Fp::ZERO];

        // Row i+1: return=200, return_sq=40000, cum_ret=300, cum_sq=50000, n=2, commit=0
        let ret_next = Fp::from_u256(U256::from(200u64));
        let ret_sq_next = Fp::from_u256(U256::from(40000u64));
        let cum_ret_next = Fp::from_u256(U256::from(300u64));
        let cum_sq_next = Fp::from_u256(U256::from(50000u64));
        let next = [ret_next, ret_sq_next, cum_ret_next, cum_sq_next, n, Fp::ZERO];

        (current, next)
    }

    #[test]
    fn test_sharpe_transition_valid() {
        let (current, next) = make_valid_sharpe_pair();
        let constraints = evaluate_transition(current, next);

        for (i, c) in constraints.iter().enumerate() {
            assert_eq!(*c, Fp::ZERO, "TC{} should be zero for valid trace", i);
        }
    }

    #[test]
    fn test_sharpe_transition_tc0_violated() {
        let (current, mut next) = make_valid_sharpe_pair();
        // Change cum_ret_next to wrong value
        next[2] = Fp::from_u256(U256::from(999u64));
        let constraints = evaluate_transition(current, next);
        assert_ne!(constraints[0], Fp::ZERO, "TC0 should be nonzero");
    }

    #[test]
    fn test_sharpe_transition_tc1_violated() {
        let (mut current, next) = make_valid_sharpe_pair();
        // Set ret_sq to wrong value (not ret^2)
        current[1] = Fp::from_u256(U256::from(9999u64));
        let constraints = evaluate_transition(current, next);
        assert_ne!(constraints[1], Fp::ZERO, "TC1 should be nonzero");
    }

    #[test]
    fn test_sharpe_transition_tc3_violated() {
        let (current, mut next) = make_valid_sharpe_pair();
        // Change trade_count in next row
        next[4] = Fp::from_u256(U256::from(999u64));
        let constraints = evaluate_transition(current, next);
        assert_ne!(constraints[3], Fp::ZERO, "TC3 should be nonzero");
    }

    #[test]
    fn test_sharpe_transition_tc4_always_zero() {
        let (current, next) = make_valid_sharpe_pair();
        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[4], Fp::ZERO, "TC4 placeholder should always be zero");
    }

    #[test]
    fn test_sharpe_boundary_bc0_valid() {
        // At row 0: cum_ret[0] = ret[0]
        let ret = Fp::from_u256(U256::from(100u64));
        let ret_sq = Fp::from_u256(U256::from(10000u64));
        let cum_ret = ret; // BC0: cum_ret = ret at first row
        let cum_sq = ret_sq; // BC1: cum_sq = ret_sq at first row
        let n = Fp::from_u256(U256::from(15u64));
        let trace_at_z = [ret, ret_sq, cum_ret, cum_sq, n, Fp::ZERO];

        let z = Fp::from_u256(U256::from(12345u64));
        let first = Fp::ONE;
        let last = Fp::from_u256(U256::from(99u64));
        let total_return = cum_ret; // single row
        let sharpe_sq = Fp::ZERO; // not testing BC3 here

        let pi = [n, total_return, sharpe_sq, Fp::ZERO];
        let bqs = evaluate_boundary_quotients(trace_at_z, z, first, last, pi);

        // BC0 and BC1 numerators are zero since cum_ret=ret and cum_sq=ret_sq
        assert_eq!(bqs[0], Fp::ZERO, "BC0 should be zero");
        assert_eq!(bqs[1], Fp::ZERO, "BC1 should be zero");
    }

    #[test]
    fn test_sharpe_padding_transition() {
        // Padding row: return=0, return_sq=0, cumulative values carry forward
        let n = Fp::from_u256(U256::from(15u64));
        let cum_ret = Fp::from_u256(U256::from(3000u64));
        let cum_sq = Fp::from_u256(U256::from(700000u64));

        let current = [Fp::ZERO, Fp::ZERO, cum_ret, cum_sq, n, Fp::ZERO];
        let next = [Fp::ZERO, Fp::ZERO, cum_ret, cum_sq, n, Fp::ZERO];

        let constraints = evaluate_transition(current, next);
        for (i, c) in constraints.iter().enumerate() {
            assert_eq!(*c, Fp::ZERO, "TC{} should be zero for padding rows", i);
        }
    }
}
