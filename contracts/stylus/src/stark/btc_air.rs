//! BTC Lock AIR (Algebraic Intermediate Representation)
//!
//! Defines the constraint system for BTC lock verification.
//! The trace has 5 columns: [lock_amount, amount_inv, timelock_delta, delta_inv, script_type]
//!
//! Transition constraints (8):
//!   TC0-TC4: Immutability (each column stays constant row-to-row)
//!   TC5: lock_amount * amount_inv - 1 = 0 (proves amount != 0)
//!   TC6: timelock_delta * delta_inv - 1 = 0 (proves delta != 0)
//!   TC7: (script_type - 1) * (script_type - 2) = 0 (proves script in {1, 2})
//!
//! Boundary constraints (4):
//!   BC0: lock_amount[0] = public_inputs[0]
//!   BC1: timelock_delta[0] = public_inputs[1] - public_inputs[2]
//!   BC2: script_type[0] = public_inputs[3]
//!   BC3: lock_amount[N-1] = public_inputs[0]

use crate::field::Fp;
use crate::field::BN254Field;

/// Number of columns in the BTC lock trace
pub const NUM_COLUMNS: usize = 5;

/// Number of transition constraints
pub const NUM_TRANSITION_CONSTRAINTS: usize = 8;

/// Number of boundary constraints
pub const NUM_BOUNDARY_CONSTRAINTS: usize = 4;

/// Total number of alphas needed (transition + boundary)
pub const NUM_ALPHAS: usize = NUM_TRANSITION_CONSTRAINTS + NUM_BOUNDARY_CONSTRAINTS;

/// Evaluate transition constraints at a given point.
///
/// current/next: [lock_amount, amount_inv, timelock_delta, delta_inv, script_type]
pub fn evaluate_transition(current: [Fp; 5], next: [Fp; 5]) -> [Fp; 8] {
    // TC0-TC4: Immutability constraints
    let tc0 = BN254Field::sub(next[0], current[0]);
    let tc1 = BN254Field::sub(next[1], current[1]);
    let tc2 = BN254Field::sub(next[2], current[2]);
    let tc3 = BN254Field::sub(next[3], current[3]);
    let tc4 = BN254Field::sub(next[4], current[4]);

    // TC5: lock_amount * amount_inv - 1 = 0
    let tc5 = BN254Field::sub(BN254Field::mul(current[0], current[1]), Fp::ONE);

    // TC6: timelock_delta * delta_inv - 1 = 0
    let tc6 = BN254Field::sub(BN254Field::mul(current[2], current[3]), Fp::ONE);

    // TC7: (script_type - 1) * (script_type - 2) = 0
    let st_minus_1 = BN254Field::sub(current[4], Fp::ONE);
    let two = BN254Field::add(Fp::ONE, Fp::ONE);
    let st_minus_2 = BN254Field::sub(current[4], two);
    let tc7 = BN254Field::mul(st_minus_1, st_minus_2);

    [tc0, tc1, tc2, tc3, tc4, tc5, tc6, tc7]
}

/// Evaluate transition constraints at an out-of-domain (OOD) point.
pub fn evaluate_transition_ood(trace_at_z: [Fp; 5], trace_at_zg: [Fp; 5]) -> [Fp; 8] {
    evaluate_transition(trace_at_z, trace_at_zg)
}

/// Compute the boundary constraint quotient evaluations at OOD point z.
///
/// public_inputs: [lock_amount, timelock_height, current_height, script_type]
pub fn evaluate_boundary_quotients(
    trace_at_z: [Fp; 5],
    z: Fp,
    trace_domain_first: Fp,
    trace_domain_last: Fp,
    public_inputs: [Fp; 4],
) -> [Fp; 4] {
    let den_first = BN254Field::sub(z, trace_domain_first);
    let den_last = BN254Field::sub(z, trace_domain_last);

    // BC0: lock_amount[0] = public_inputs[0]
    let num0 = BN254Field::sub(trace_at_z[0], public_inputs[0]);
    let bq0 = BN254Field::div(num0, den_first);

    // BC1: timelock_delta[0] = public_inputs[1] - public_inputs[2]
    let expected_delta = BN254Field::sub(public_inputs[1], public_inputs[2]);
    let num1 = BN254Field::sub(trace_at_z[2], expected_delta);
    let bq1 = BN254Field::div(num1, den_first);

    // BC2: script_type[0] = public_inputs[3]
    let num2 = BN254Field::sub(trace_at_z[4], public_inputs[3]);
    let bq2 = BN254Field::div(num2, den_first);

    // BC3: lock_amount[N-1] = public_inputs[0] (end consistency)
    let num3 = BN254Field::sub(trace_at_z[0], public_inputs[0]);
    let bq3 = BN254Field::div(num3, den_last);

    [bq0, bq1, bq2, bq3]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn make_valid_trace_row() -> [Fp; 5] {
        let lock_amount = Fp::from_u256(U256::from(100000u64));
        let amount_inv = BN254Field::inv(lock_amount);
        let timelock_delta = Fp::from_u256(U256::from(50000u64));
        let delta_inv = BN254Field::inv(timelock_delta);
        let script_type = Fp::from_u256(U256::from(2u64)); // P2WSH
        [lock_amount, amount_inv, timelock_delta, delta_inv, script_type]
    }

    #[test]
    fn test_btc_lock_transition_valid() {
        let row = make_valid_trace_row();
        // All rows are identical in a valid BTC lock trace
        let constraints = evaluate_transition(row, row);

        for (i, c) in constraints.iter().enumerate() {
            assert_eq!(*c, Fp::ZERO, "TC{} should be zero for valid trace", i);
        }
    }

    #[test]
    fn test_btc_lock_transition_immutability_violated() {
        let row = make_valid_trace_row();
        let mut next = row;
        // Change lock_amount in next row
        next[0] = Fp::from_u256(U256::from(999u64));

        let constraints = evaluate_transition(row, next);
        assert_ne!(constraints[0], Fp::ZERO, "TC0 should be nonzero when lock_amount changes");
        // TC1-TC4 should still be zero since those columns didn't change
        assert_eq!(constraints[1], Fp::ZERO);
        assert_eq!(constraints[2], Fp::ZERO);
        assert_eq!(constraints[3], Fp::ZERO);
        assert_eq!(constraints[4], Fp::ZERO);
    }

    #[test]
    fn test_btc_lock_transition_zero_amount() {
        let mut row = make_valid_trace_row();
        // Set lock_amount to 0 and amount_inv to 0 (can't have valid inverse)
        row[0] = Fp::ZERO;
        row[1] = Fp::ZERO;

        let constraints = evaluate_transition(row, row);
        // TC5: 0 * 0 - 1 = -1 != 0
        assert_ne!(constraints[5], Fp::ZERO, "TC5 should be nonzero when amount is zero");
    }

    #[test]
    fn test_btc_lock_transition_invalid_script_type() {
        let mut row = make_valid_trace_row();
        // script_type = 3 (invalid, should be 1 or 2)
        row[4] = Fp::from_u256(U256::from(3u64));

        let constraints = evaluate_transition(row, row);
        // TC7: (3 - 1) * (3 - 2) = 2 * 1 = 2 != 0
        assert_ne!(constraints[7], Fp::ZERO, "TC7 should be nonzero for script_type=3");
    }

    #[test]
    fn test_btc_lock_transition_script_type_p2sh() {
        let mut row = make_valid_trace_row();
        row[4] = Fp::from_u256(U256::from(1u64)); // P2SH
        // Recalculate: row is otherwise valid, just change script_type
        let constraints = evaluate_transition(row, row);
        // TC7: (1 - 1) * (1 - 2) = 0 * (-1) = 0
        assert_eq!(constraints[7], Fp::ZERO, "TC7 should be zero for script_type=1");
    }

    #[test]
    fn test_btc_lock_transition_script_type_p2wsh() {
        let row = make_valid_trace_row(); // script_type = 2
        let constraints = evaluate_transition(row, row);
        // TC7: (2 - 1) * (2 - 2) = 1 * 0 = 0
        assert_eq!(constraints[7], Fp::ZERO, "TC7 should be zero for script_type=2");
    }

    #[test]
    fn test_btc_lock_boundary_valid() {
        let lock_amount = Fp::from_u256(U256::from(100000u64));
        let timelock_height = Fp::from_u256(U256::from(900000u64));
        let current_height = Fp::from_u256(U256::from(850000u64));
        let script_type = Fp::from_u256(U256::from(2u64));

        let expected_delta = BN254Field::sub(timelock_height, current_height);
        let amount_inv = BN254Field::inv(lock_amount);
        let delta_inv = BN254Field::inv(expected_delta);

        let trace_at_z = [lock_amount, amount_inv, expected_delta, delta_inv, script_type];

        // Test at a non-domain point (not trace_domain_first or last)
        let z = Fp::from_u256(U256::from(12345u64));
        let trace_domain_first = Fp::ONE;
        let trace_domain_last = Fp::from_u256(U256::from(99u64));

        let public_inputs = [lock_amount, timelock_height, current_height, script_type];
        let bqs = evaluate_boundary_quotients(
            trace_at_z, z, trace_domain_first, trace_domain_last, public_inputs,
        );

        // At the actual trace evaluation points (not the domain), the boundary numerators
        // should be zero, making all quotients zero.
        assert_eq!(bqs[0], Fp::ZERO, "BC0 should be zero for matching lock_amount");
        assert_eq!(bqs[1], Fp::ZERO, "BC1 should be zero for matching delta");
        assert_eq!(bqs[2], Fp::ZERO, "BC2 should be zero for matching script_type");
        assert_eq!(bqs[3], Fp::ZERO, "BC3 should be zero for matching lock_amount at end");
    }

    #[test]
    fn test_btc_lock_full_trace() {
        let row = make_valid_trace_row();
        // Simulate 8-row constant trace
        for _ in 0..7 {
            let constraints = evaluate_transition(row, row);
            for (i, c) in constraints.iter().enumerate() {
                assert_eq!(*c, Fp::ZERO, "TC{} should be zero in full trace", i);
            }
        }
    }
}
