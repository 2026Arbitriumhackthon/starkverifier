//! Fibonacci Trace Generation
//!
//! Generates the execution trace for a Fibonacci computation.
//! The trace has 2 columns [a, b] where:
//!   a[0] = 1, b[0] = 1
//!   a[i+1] = b[i]
//!   b[i+1] = a[i] + b[i]

use alloy_primitives::U256;
use crate::field::BN254Field;

/// A 2-column execution trace for Fibonacci computation.
pub struct FibonacciTrace {
    /// Column a values
    pub col_a: Vec<U256>,
    /// Column b values
    pub col_b: Vec<U256>,
    /// Number of rows (must be power of 2)
    pub len: usize,
}

impl FibonacciTrace {
    /// Generate a Fibonacci trace of length `n` (padded to next power of 2).
    ///
    /// # Arguments
    /// * `n` - Minimum number of Fibonacci steps (will be padded to power of 2)
    ///
    /// # Returns
    /// Trace with the Fibonacci sequence and public inputs
    pub fn generate(n: usize) -> Self {
        // Pad to next power of 2
        let trace_len = n.next_power_of_two();

        let mut col_a = Vec::with_capacity(trace_len);
        let mut col_b = Vec::with_capacity(trace_len);

        // Initial values
        col_a.push(U256::from(1u64));
        col_b.push(U256::from(1u64));

        // Generate Fibonacci sequence
        for i in 1..trace_len {
            let prev_a = col_a[i - 1];
            let prev_b = col_b[i - 1];
            // a[i] = b[i-1]
            col_a.push(prev_b);
            // b[i] = a[i-1] + b[i-1]
            col_b.push(BN254Field::add(prev_a, prev_b));
        }

        FibonacciTrace {
            col_a,
            col_b,
            len: trace_len,
        }
    }

    /// Get the public inputs for verification.
    ///
    /// Returns [first_a, first_b, claimed_result] where:
    ///   first_a = a[0] = 1
    ///   first_b = b[0] = 1
    ///   claimed_result = b[N-1]
    pub fn public_inputs(&self) -> [U256; 3] {
        [
            self.col_a[0],
            self.col_b[0],
            self.col_b[self.len - 1],
        ]
    }

    /// Get trace values at a specific row.
    pub fn row(&self, i: usize) -> [U256; 2] {
        [self.col_a[i], self.col_b[i]]
    }

    /// Get log2 of trace length.
    pub fn log_len(&self) -> u32 {
        (self.len as f64).log2() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_trace_basic() {
        let trace = FibonacciTrace::generate(8);
        assert_eq!(trace.len, 8);

        // Verify: 1, 1, 2, 3, 5, 8, 13, 21
        assert_eq!(trace.col_a[0], U256::from(1u64));
        assert_eq!(trace.col_b[0], U256::from(1u64));
        assert_eq!(trace.col_a[1], U256::from(1u64));
        assert_eq!(trace.col_b[1], U256::from(2u64));
        assert_eq!(trace.col_a[2], U256::from(2u64));
        assert_eq!(trace.col_b[2], U256::from(3u64));
        assert_eq!(trace.col_b[7], U256::from(34u64));
    }

    #[test]
    fn test_fibonacci_trace_padding() {
        // 5 rows -> padded to 8
        let trace = FibonacciTrace::generate(5);
        assert_eq!(trace.len, 8);
    }

    #[test]
    fn test_public_inputs() {
        let trace = FibonacciTrace::generate(8);
        let pi = trace.public_inputs();
        assert_eq!(pi[0], U256::from(1u64)); // first_a
        assert_eq!(pi[1], U256::from(1u64)); // first_b
        assert_eq!(pi[2], U256::from(34u64)); // b[7] = fib(9) = 34
    }
}
