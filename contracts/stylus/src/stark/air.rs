//! Fibonacci AIR (Algebraic Intermediate Representation)
//!
//! Defines the constraint system for a Fibonacci sequence computation.
//! The trace has 2 columns [a, b] where each row satisfies:
//!   a_next = b
//!   b_next = a + b

use alloy_primitives::U256;

use crate::field::Fp;
use crate::field::BN254Field;

/// Number of columns in the Fibonacci trace
pub const NUM_COLUMNS: usize = 2;

/// Number of transition constraints
pub const NUM_TRANSITION_CONSTRAINTS: usize = 2;

/// Evaluate transition constraints at a given point.
pub fn evaluate_transition(current: [Fp; 2], next: [Fp; 2]) -> [Fp; 2] {
    let a_curr = current[0];
    let b_curr = current[1];
    let a_next = next[0];
    let b_next = next[1];

    let c0 = BN254Field::sub(a_next, b_curr);
    let sum = BN254Field::add(a_curr, b_curr);
    let c1 = BN254Field::sub(b_next, sum);

    [c0, c1]
}

/// Evaluate transition constraints at an out-of-domain (OOD) point.
pub fn evaluate_transition_ood(trace_at_z: [Fp; 2], trace_at_zg: [Fp; 2]) -> [Fp; 2] {
    evaluate_transition(trace_at_z, trace_at_zg)
}

/// Compute the boundary constraint quotient evaluations at OOD point z.
pub fn evaluate_boundary_quotients(
    trace_at_z: [Fp; 2],
    z: Fp,
    trace_domain_first: Fp,
    trace_domain_last: Fp,
    public_inputs: [Fp; 3],
) -> [Fp; 3] {
    let first_a = public_inputs[0];
    let first_b = public_inputs[1];
    let claimed_result = public_inputs[2];

    let num0 = BN254Field::sub(trace_at_z[0], first_a);
    let den0 = BN254Field::sub(z, trace_domain_first);
    let bq0 = BN254Field::div(num0, den0);

    let num1 = BN254Field::sub(trace_at_z[1], first_b);
    let bq1 = BN254Field::div(num1, den0);

    let num2 = BN254Field::sub(trace_at_z[1], claimed_result);
    let den2 = BN254Field::sub(z, trace_domain_last);
    let bq2 = BN254Field::div(num2, den2);

    [bq0, bq1, bq2]
}

/// Compute the transition constraint divisor polynomial evaluated at z.
pub fn transition_zerofier_at(z: Fp, trace_len: u64, trace_generator: Fp) -> Fp {
    let z_n = BN254Field::pow(z, U256::from(trace_len));
    let numerator = BN254Field::sub(z_n, Fp::ONE);

    let g_last = BN254Field::pow(trace_generator, U256::from(trace_len - 1));
    let denominator = BN254Field::sub(z, g_last);

    BN254Field::div(numerator, denominator)
}

/// Compute the transition constraint quotient at OOD point.
pub fn transition_quotients(
    constraint_evals: [Fp; 2],
    zerofier_eval: Fp,
) -> [Fp; 2] {
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
        let current = [Fp::from_u256(U256::from(1u64)), Fp::from_u256(U256::from(1u64))];
        let next = [Fp::from_u256(U256::from(1u64)), Fp::from_u256(U256::from(2u64))];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], Fp::ZERO, "a_next should equal b_curr");
        assert_eq!(constraints[1], Fp::ZERO, "b_next should equal a_curr + b_curr");
    }

    #[test]
    fn test_fibonacci_transition_row2() {
        let current = [Fp::from_u256(U256::from(1u64)), Fp::from_u256(U256::from(2u64))];
        let next = [Fp::from_u256(U256::from(2u64)), Fp::from_u256(U256::from(3u64))];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], Fp::ZERO);
        assert_eq!(constraints[1], Fp::ZERO);
    }

    #[test]
    fn test_fibonacci_transition_invalid() {
        let current = [Fp::from_u256(U256::from(1u64)), Fp::from_u256(U256::from(1u64))];
        let next = [Fp::from_u256(U256::from(1u64)), Fp::from_u256(U256::from(3u64))];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], Fp::ZERO);
        assert_ne!(constraints[1], Fp::ZERO);
    }

    #[test]
    fn test_fibonacci_sequence() {
        let trace: [[Fp; 2]; 8] = [
            [Fp::from_u256(U256::from(1u64)), Fp::from_u256(U256::from(1u64))],
            [Fp::from_u256(U256::from(1u64)), Fp::from_u256(U256::from(2u64))],
            [Fp::from_u256(U256::from(2u64)), Fp::from_u256(U256::from(3u64))],
            [Fp::from_u256(U256::from(3u64)), Fp::from_u256(U256::from(5u64))],
            [Fp::from_u256(U256::from(5u64)), Fp::from_u256(U256::from(8u64))],
            [Fp::from_u256(U256::from(8u64)), Fp::from_u256(U256::from(13u64))],
            [Fp::from_u256(U256::from(13u64)), Fp::from_u256(U256::from(21u64))],
            [Fp::from_u256(U256::from(21u64)), Fp::from_u256(U256::from(34u64))],
        ];

        for i in 0..7 {
            let constraints = evaluate_transition(trace[i], trace[i + 1]);
            assert_eq!(constraints[0], Fp::ZERO, "Failed at row {}", i);
            assert_eq!(constraints[1], Fp::ZERO, "Failed at row {}", i);
        }
    }

    #[test]
    fn test_transition_in_field() {
        let a = BN254Field::sub(Fp::ZERO, Fp::from_u256(U256::from(1u64)));
        let b = Fp::from_u256(U256::from(2u64));
        let current = [a, b];
        let next = [b, Fp::from_u256(U256::from(1u64))];

        let constraints = evaluate_transition(current, next);
        assert_eq!(constraints[0], Fp::ZERO);
        assert_eq!(constraints[1], Fp::ZERO);
    }
}
