//! BTC Lock Trace Generation
//!
//! Generates the execution trace for BTC lock verification.
//! The trace has 5 columns:
//!   [lock_amount, amount_inv, timelock_delta, delta_inv, script_type]
//! All rows are identical (constant trace padded to 8 rows).

use alloy_primitives::U256;
use crate::field::BN254Field;

/// A 5-column execution trace for BTC lock verification.
pub struct BtcLockTrace {
    pub col_lock_amount: Vec<U256>,
    pub col_amount_inv: Vec<U256>,
    pub col_timelock_delta: Vec<U256>,
    pub col_delta_inv: Vec<U256>,
    pub col_script_type: Vec<U256>,
    pub len: usize,
}

impl BtcLockTrace {
    /// Generate a BTC lock trace with 8 rows (constant).
    ///
    /// # Arguments
    /// * `lock_amount` - BTC lock amount (satoshis)
    /// * `timelock_height` - Block height when lock expires
    /// * `current_height` - Current block height
    /// * `script_type` - 1 for P2SH, 2 for P2WSH
    pub fn generate(
        lock_amount: u64,
        timelock_height: u64,
        current_height: u64,
        script_type: u64,
    ) -> Self {
        let trace_len = 8usize; // Fixed 8 rows (2^3)

        let amt = U256::from(lock_amount);
        let amt_inv = BN254Field::inv(amt);
        let delta = BN254Field::sub(
            U256::from(timelock_height),
            U256::from(current_height),
        );
        let delta_inv = BN254Field::inv(delta);
        let st = U256::from(script_type);

        BtcLockTrace {
            col_lock_amount: vec![amt; trace_len],
            col_amount_inv: vec![amt_inv; trace_len],
            col_timelock_delta: vec![delta; trace_len],
            col_delta_inv: vec![delta_inv; trace_len],
            col_script_type: vec![st; trace_len],
            len: trace_len,
        }
    }

    /// Get the public inputs for verification.
    ///
    /// Returns [lock_amount, timelock_height, current_height, script_type]
    pub fn public_inputs(&self, timelock_height: u64, current_height: u64) -> [U256; 4] {
        [
            self.col_lock_amount[0],
            U256::from(timelock_height),
            U256::from(current_height),
            self.col_script_type[0],
        ]
    }

    /// Get log2 of trace length (always 3 for 8 rows).
    pub fn log_len(&self) -> u32 {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btc_lock_trace_basic() {
        let trace = BtcLockTrace::generate(100000, 900000, 850000, 2);
        assert_eq!(trace.len, 8);
        assert_eq!(trace.log_len(), 3);

        // All rows should be identical
        for i in 1..8 {
            assert_eq!(trace.col_lock_amount[i], trace.col_lock_amount[0]);
            assert_eq!(trace.col_amount_inv[i], trace.col_amount_inv[0]);
            assert_eq!(trace.col_timelock_delta[i], trace.col_timelock_delta[0]);
            assert_eq!(trace.col_delta_inv[i], trace.col_delta_inv[0]);
            assert_eq!(trace.col_script_type[i], trace.col_script_type[0]);
        }
    }

    #[test]
    fn test_btc_lock_trace_inverses() {
        let trace = BtcLockTrace::generate(100000, 900000, 850000, 2);

        // amount * amount_inv = 1
        let product = BN254Field::mul(trace.col_lock_amount[0], trace.col_amount_inv[0]);
        assert_eq!(product, U256::from(1u64));

        // delta * delta_inv = 1
        let product = BN254Field::mul(trace.col_timelock_delta[0], trace.col_delta_inv[0]);
        assert_eq!(product, U256::from(1u64));
    }

    #[test]
    fn test_btc_lock_trace_delta() {
        let trace = BtcLockTrace::generate(100000, 900000, 850000, 2);
        // delta = timelock_height - current_height = 50000
        assert_eq!(trace.col_timelock_delta[0], U256::from(50000u64));
    }

    #[test]
    fn test_btc_lock_public_inputs() {
        let trace = BtcLockTrace::generate(100000, 900000, 850000, 2);
        let pi = trace.public_inputs(900000, 850000);

        assert_eq!(pi[0], U256::from(100000u64));
        assert_eq!(pi[1], U256::from(900000u64));
        assert_eq!(pi[2], U256::from(850000u64));
        assert_eq!(pi[3], U256::from(2u64));
    }
}
