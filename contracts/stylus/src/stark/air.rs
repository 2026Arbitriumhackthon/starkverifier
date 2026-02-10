//! Fibonacci AIR (Algebraic Intermediate Representation)
//!
//! Defines the constraint system for a Fibonacci sequence computation.
//! The trace has 2 columns [a, b] where each row satisfies:
//!   a_next = b
//!   b_next = a + b
//!
//! Boundary constraints:
//!   a[0] = 1, b[0] = 1 (initial values)
//!   b[N-1] = claimed_result (public output)

use alloy_primitives::U256;

use crate::poseidon::field::BN254Field;

/// Number of columns in the Fibonacci trace
pub const NUM_COLUMNS: usize = 2;

/// Number of transition constraints
pub const NUM_TRANSITION_CONSTRAINTS: usize = 2;

/// Evaluate transition constraints at a given point.
///
/// For Fibonacci:
///   constraint[0] = a_next - b_current
///   constraint[1] = b_next - (a_current + b_current)
///
/// Both should evaluate to 0 for valid trace rows.
///
/// # Arguments
/// * `current` - [a, b] values at current row
/// * `next` - [a, b] values at next row
///
/// # Returns
/// Array of constraint evaluations (should all be 0 for valid transitions)
pub fn evaluate_transition(current: [U256; 2], next: [U256; 2]) -> [U256; 2] {
    let a_curr = current[0];
    let b_curr = current[1];
    let a_next = next[0];
    let b_next = next[1];

    // Constraint 0: a_next - b_curr = 0
    let c0 = BN254Field::sub(a_next, b_curr);

    // Constraint 1: b_next - (a_curr + b_curr) = 0
    let sum = BN254Field::add(a_curr, b_curr);
    let c1 = BN254Field::sub(b_next, sum);

    [c0, c1]
}

/// Evaluate transition constraints at an out-of-domain (OOD) point.
///
/// Given evaluations of trace columns at z and z*g (where g is the trace domain generator),
/// computes the transition constraint values.
///
/// # Arguments
/// * `trace_at_z` - [a(z), b(z)] - trace evaluations at OOD point z
/// * `trace_at_zg` - [a(z*g), b(z*g)] - trace evaluations at z * generator
///
/// # Returns
/// Constraint evaluations at the OOD point
pub fn evaluate_transition_ood(trace_at_z: [U256; 2], trace_at_zg: [U256; 2]) -> [U256; 2] {
    evaluate_transition(trace_at_z, trace_at_zg)
}

/// Compute the boundary constraint quotient evaluations at OOD point z.
///
/// Boundary constraints for Fibonacci:
///   1. a(trace_domain[0]) = public_inputs[0]  (first_a)
///   2. b(trace_domain[0]) = public_inputs[1]  (first_b)
///   3. b(trace_domain[N-1]) = public_inputs[2] (claimed_result)
///
/// The boundary constraint quotient is:
///   (trace_col(z) - boundary_value) / (z - boundary_point)
///
/// # Arguments
/// * `trace_at_z` - [a(z), b(z)] at OOD point
/// * `z` - The OOD evaluation point
/// * `trace_domain_first` - First element of trace domain (should be 1 = g^0)
/// * `trace_domain_last` - Last element of trace domain (g^(N-1))
/// * `public_inputs` - [first_a, first_b, claimed_result]
///
/// # Returns
/// Array of 3 boundary quotient evaluations
pub fn evaluate_boundary_quotients(
    trace_at_z: [U256; 2],
    z: U256,
    trace_domain_first: U256,
    trace_domain_last: U256,
    public_inputs: [U256; 3],
) -> [U256; 3] {
    let first_a = public_inputs[0];
    let first_b = public_inputs[1];
    let claimed_result = public_inputs[2];

    // Boundary 0: (a(z) - first_a) / (z - trace_domain[0])
    let num0 = BN254Field::sub(trace_at_z[0], first_a);
    let den0 = BN254Field::sub(z, trace_domain_first);
    let bq0 = BN254Field::div(num0, den0);

    // Boundary 1: (b(z) - first_b) / (z - trace_domain[0])
    let num1 = BN254Field::sub(trace_at_z[1], first_b);
    let bq1 = BN254Field::div(num1, den0);

    // Boundary 2: (b(z) - claimed_result) / (z - trace_domain[N-1])
    let num2 = BN254Field::sub(trace_at_z[1], claimed_result);
    let den2 = BN254Field::sub(z, trace_domain_last);
    let bq2 = BN254Field::div(num2, den2);

    [bq0, bq1, bq2]
}

/// Compute the transition constraint divisor polynomial evaluated at z.
///
/// The transition constraints hold at all trace domain points EXCEPT the last,
/// so the divisor (zerofier) is:
///   Z_T(x) = (x^N - 1) / (x - g^(N-1))
///
/// Evaluated at z:
///   Z_T(z) = (z^N - 1) / (z - g^(N-1))
///
/// # Arguments
/// * `z` - OOD evaluation point
/// * `trace_len` - N = number of rows in trace
/// * `trace_generator` - g = generator of trace domain
pub fn transition_zerofier_at(z: U256, trace_len: u64, trace_generator: U256) -> U256 {
    // z^N - 1
    let z_n = BN254Field::pow(z, U256::from(trace_len));
    let numerator = BN254Field::sub(z_n, U256::from(1u64));

    // z - g^(N-1)
    let g_last = BN254Field::pow(trace_generator, U256::from(trace_len - 1));
    let denominator = BN254Field::sub(z, g_last);

    BN254Field::div(numerator, denominator)
}

/// Compute the transition constraint quotient at OOD point.
///
/// For each constraint c_i:
///   quotient_i = c_i(z) / Z_T(z)
///
/// # Arguments
/// * `constraint_evals` - Transition constraint evaluations at z
/// * `zerofier_eval` - Z_T(z)
///
/// # Returns
/// Transition quotient evaluations
pub fn transition_quotients(
    constraint_evals: [U256; 2],
    zerofier_eval: U256,
) -> [U256; 2] {
    [
        BN254Field::div(constraint_evals[0], zerofier_eval),
        BN254Field::div(constraint_evals[1], zerofier_eval),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_transition_valid() {
        // Fibonacci: 1, 1, 2, 3, 5, 8, ...
        // Row 0: [1, 1], Row 1: [1, 2]
        let current = [U256::from(1u64), U256::from(1u64)];
        let next = [U256::from(1u64), U256::from(2u64)];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], U256::ZERO, "a_next should equal b_curr");
        assert_eq!(constraints[1], U256::ZERO, "b_next should equal a_curr + b_curr");
    }

    #[test]
    fn test_fibonacci_transition_row2() {
        // Row 1: [1, 2], Row 2: [2, 3]
        let current = [U256::from(1u64), U256::from(2u64)];
        let next = [U256::from(2u64), U256::from(3u64)];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], U256::ZERO);
        assert_eq!(constraints[1], U256::ZERO);
    }

    #[test]
    fn test_fibonacci_transition_invalid() {
        // Invalid: [1, 1] -> [1, 3] (b_next should be 2, not 3)
        let current = [U256::from(1u64), U256::from(1u64)];
        let next = [U256::from(1u64), U256::from(3u64)];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], U256::ZERO); // a_next = b_curr is still valid
        assert_ne!(constraints[1], U256::ZERO); // b_next != a + b
    }

    #[test]
    fn test_fibonacci_sequence() {
        // Verify full Fibonacci sequence: 1,1,2,3,5,8,13,21
        let trace: [[U256; 2]; 8] = [
            [U256::from(1u64), U256::from(1u64)],
            [U256::from(1u64), U256::from(2u64)],
            [U256::from(2u64), U256::from(3u64)],
            [U256::from(3u64), U256::from(5u64)],
            [U256::from(5u64), U256::from(8u64)],
            [U256::from(8u64), U256::from(13u64)],
            [U256::from(13u64), U256::from(21u64)],
            [U256::from(21u64), U256::from(34u64)],
        ];

        for i in 0..7 {
            let constraints = evaluate_transition(trace[i], trace[i + 1]);
            assert_eq!(constraints[0], U256::ZERO, "Failed at row {}", i);
            assert_eq!(constraints[1], U256::ZERO, "Failed at row {}", i);
        }
    }

    #[test]
    fn test_transition_in_field() {
        // Test with field arithmetic (large values wrapping around)
        let a = BN254Field::sub(U256::ZERO, U256::from(1u64)); // p-1
        let b = U256::from(2u64);
        let current = [a, b];

        // next: a_next = b = 2, b_next = a + b = (p-1) + 2 = 1
        let next = [b, U256::from(1u64)];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], U256::ZERO);
        assert_eq!(constraints[1], U256::ZERO);
    }
}
