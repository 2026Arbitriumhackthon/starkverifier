//! Sharpe Ratio Trace Generation
//!
//! Generates the execution trace for Sharpe ratio verification.
//! The trace has 6 columns:
//!   [return, return_sq, cumulative_return, cumulative_sq, trade_count, dataset_commitment]
//!
//! Actual trade rows are followed by zero-padded rows to the next power of 2.
//! Padding rows: return=0, return_sq=0, cumulative values carry forward,
//! trade_count=N(actual), dataset_commitment=0.

use alloy_primitives::U256;
use crate::field::BN254Field;
use crate::mock_data::{GmxTradeRecord, basis_points_to_field, SHARPE_SCALE};
use crate::commit::MerkleTree;

/// Number of trace columns.
pub const NUM_COLUMNS: usize = 6;

/// A 6-column execution trace for Sharpe ratio verification.
pub struct SharpeTrace {
    pub col_return: Vec<U256>,             // Col 0: return_i
    pub col_return_sq: Vec<U256>,          // Col 1: return_i^2
    pub col_cumulative_return: Vec<U256>,  // Col 2: sum of returns up to row i
    pub col_cumulative_sq: Vec<U256>,      // Col 3: sum of return_sq up to row i
    pub col_trade_count: Vec<U256>,        // Col 4: constant N (actual trade count)
    pub col_dataset_commitment: Vec<U256>, // Col 5: dataset commitment (constant per trace)
    pub len: usize,                        // Padded power-of-2 length
    pub actual_trade_count: usize,         // Actual number of trades
}

impl SharpeTrace {
    /// Generate a Sharpe trace from trade records.
    ///
    /// The trace is padded to the next power of 2.
    /// Padding rows have return=0, return_sq=0, and cumulative values carry forward.
    pub fn generate(trades: &[GmxTradeRecord], dataset_commitment: Option<U256>) -> Self {
        let actual_count = trades.len();
        assert!(actual_count >= 2, "need at least 2 trades");

        // Pad to next power of 2
        let trace_len = actual_count.next_power_of_two();

        let n_field = U256::from(actual_count as u64);
        let commitment_val = dataset_commitment.unwrap_or(U256::ZERO);

        let mut col_return = Vec::with_capacity(trace_len);
        let mut col_return_sq = Vec::with_capacity(trace_len);
        let mut col_cumulative_return = Vec::with_capacity(trace_len);
        let mut col_cumulative_sq = Vec::with_capacity(trace_len);
        let mut col_trade_count = Vec::with_capacity(trace_len);
        let mut col_dataset_commitment = Vec::with_capacity(trace_len);

        let mut cum_ret = U256::ZERO;
        let mut cum_sq = U256::ZERO;

        // Fill actual trade rows
        for trade in trades {
            let ret_field = basis_points_to_field(trade.return_bps);
            let ret_sq = BN254Field::mul(ret_field, ret_field);

            cum_ret = BN254Field::add(cum_ret, ret_field);
            cum_sq = BN254Field::add(cum_sq, ret_sq);

            col_return.push(ret_field);
            col_return_sq.push(ret_sq);
            col_cumulative_return.push(cum_ret);
            col_cumulative_sq.push(cum_sq);
            col_trade_count.push(n_field);
            col_dataset_commitment.push(commitment_val);
        }

        // Fill padding rows (zero return, cumulative values preserved)
        for _ in actual_count..trace_len {
            col_return.push(U256::ZERO);
            col_return_sq.push(U256::ZERO);
            col_cumulative_return.push(cum_ret); // carry forward
            col_cumulative_sq.push(cum_sq);      // carry forward
            col_trade_count.push(n_field);
            col_dataset_commitment.push(commitment_val);
        }

        SharpeTrace {
            col_return,
            col_return_sq,
            col_cumulative_return,
            col_cumulative_sq,
            col_trade_count,
            col_dataset_commitment,
            len: trace_len,
            actual_trade_count: actual_count,
        }
    }

    /// Get the public inputs for verification.
    ///
    /// Returns [trade_count, total_return, sharpe_sq_scaled, merkle_root]
    pub fn public_inputs(&self, claimed_sharpe_sq_scaled: U256) -> [U256; 4] {
        let trade_count = U256::from(self.actual_trade_count as u64);
        let total_return = self.col_cumulative_return[self.actual_trade_count - 1];

        // Merkle root of dataset_commitment column
        let merkle_root = MerkleTree::build(&self.col_dataset_commitment).root();

        [trade_count, total_return, claimed_sharpe_sq_scaled, merkle_root]
    }

    /// Get log2 of padded trace length.
    pub fn log_len(&self) -> u32 {
        (self.len as f64).log2() as u32
    }

    /// Compute the expected sharpe_sq_scaled from the trace data.
    /// Uses field division: cum_ret^2 * SCALE / (N * cum_sq - cum_ret^2)
    pub fn compute_sharpe_sq_scaled(&self) -> U256 {
        let cum_ret = self.col_cumulative_return[self.actual_trade_count - 1];
        let cum_sq = self.col_cumulative_sq[self.actual_trade_count - 1];
        let n = U256::from(self.actual_trade_count as u64);
        let scale = U256::from(SHARPE_SCALE);

        let cum_ret_sq = BN254Field::mul(cum_ret, cum_ret);
        let numerator = BN254Field::mul(cum_ret_sq, scale);
        let n_cum_sq = BN254Field::mul(n, cum_sq);
        let denominator = BN254Field::sub(n_cum_sq, cum_ret_sq);

        BN254Field::div(numerator, denominator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_data::{bot_a_aggressive_eth, bot_b_safe_hedger};

    #[test]
    fn test_bot_a_trace_generation() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);

        assert_eq!(trace.actual_trade_count, 15);
        assert_eq!(trace.len, 16); // 15 padded to 16
        assert_eq!(trace.log_len(), 4);

        // All columns should have len elements
        assert_eq!(trace.col_return.len(), 16);
        assert_eq!(trace.col_return_sq.len(), 16);
        assert_eq!(trace.col_cumulative_return.len(), 16);
        assert_eq!(trace.col_cumulative_sq.len(), 16);
        assert_eq!(trace.col_trade_count.len(), 16);
        assert_eq!(trace.col_dataset_commitment.len(), 16);
    }

    #[test]
    fn test_bot_b_trace_generation() {
        let bot = bot_b_safe_hedger();
        let trace = SharpeTrace::generate(&bot.trades, None);

        assert_eq!(trace.actual_trade_count, 23);
        assert_eq!(trace.len, 32); // 23 padded to 32
        assert_eq!(trace.log_len(), 5);
    }

    #[test]
    fn test_padding_rows() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);

        // Padding row (index 15) should have zero return
        assert_eq!(trace.col_return[15], U256::ZERO);
        assert_eq!(trace.col_return_sq[15], U256::ZERO);

        // Cumulative values should be preserved from last actual row
        assert_eq!(
            trace.col_cumulative_return[15],
            trace.col_cumulative_return[14]
        );
        assert_eq!(
            trace.col_cumulative_sq[15],
            trace.col_cumulative_sq[14]
        );

        // Trade count should be constant
        assert_eq!(trace.col_trade_count[15], trace.col_trade_count[0]);
    }

    #[test]
    fn test_cumulative_return_consistency() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);

        // Verify cumulative return is actually cumulative
        for i in 1..trace.actual_trade_count {
            let expected = BN254Field::add(
                trace.col_cumulative_return[i - 1],
                trace.col_return[i],
            );
            assert_eq!(
                trace.col_cumulative_return[i], expected,
                "Cumulative return mismatch at row {}", i
            );
        }
    }

    #[test]
    fn test_cumulative_sq_consistency() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);

        for i in 1..trace.actual_trade_count {
            let expected = BN254Field::add(
                trace.col_cumulative_sq[i - 1],
                trace.col_return_sq[i],
            );
            assert_eq!(
                trace.col_cumulative_sq[i], expected,
                "Cumulative sq mismatch at row {}", i
            );
        }
    }

    #[test]
    fn test_return_sq_is_square() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);

        for i in 0..trace.len {
            let expected = BN254Field::mul(trace.col_return[i], trace.col_return[i]);
            assert_eq!(
                trace.col_return_sq[i], expected,
                "return_sq mismatch at row {}", i
            );
        }
    }

    #[test]
    fn test_first_row_boundary() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);

        // BC0: cum_ret[0] = return[0]
        assert_eq!(trace.col_cumulative_return[0], trace.col_return[0]);

        // BC1: cum_sq[0] = return_sq[0]
        assert_eq!(trace.col_cumulative_sq[0], trace.col_return_sq[0]);
    }

    #[test]
    fn test_trade_count_constant() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);

        let expected = U256::from(15u64);
        for i in 0..trace.len {
            assert_eq!(trace.col_trade_count[i], expected);
        }
    }

    #[test]
    fn test_sharpe_sq_scaled_bot_a() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);
        let computed = trace.compute_sharpe_sq_scaled();
        assert_eq!(computed, U256::from(bot.expected_sharpe_sq_scaled));
    }

    #[test]
    fn test_sharpe_sq_scaled_bot_b() {
        let bot = bot_b_safe_hedger();
        let trace = SharpeTrace::generate(&bot.trades, None);
        let computed = trace.compute_sharpe_sq_scaled();
        assert_eq!(computed, U256::from(bot.expected_sharpe_sq_scaled));
    }

    #[test]
    fn test_public_inputs() {
        let bot = bot_a_aggressive_eth();
        let trace = SharpeTrace::generate(&bot.trades, None);
        let claimed = U256::from(bot.expected_sharpe_sq_scaled);
        let pi = trace.public_inputs(claimed);

        assert_eq!(pi[0], U256::from(15u64)); // trade_count
        assert_eq!(pi[2], claimed); // sharpe_sq_scaled
        // pi[1] = total_return, pi[3] = merkle_root (computed)
    }
}
