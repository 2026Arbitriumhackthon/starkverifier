//! Mock GMX Trade Data for Sharpe Ratio Proof
//!
//! Provides hardcoded trade data for testing the Sharpe AIR.
//! Two mock bots with different trading profiles:
//!   - Bot A: Aggressive ETH trader (15 trades, Sharpe ~ 2.45)
//!   - Bot B: Conservative hedger (23 trades, Sharpe ~ 1.37)
//!
//! Return values are chosen so that sharpe_sq_scaled is an exact integer
//! (no field-division rounding needed for the public input).

use alloy_primitives::U256;
use crate::field::BN254Field;
use crate::keccak::keccak_hash_two;

/// Scale factor for Sharpe^2 to avoid field division in the public input.
/// claimed_sharpe_sq_scaled = Sharpe^2 * SHARPE_SCALE
pub const SHARPE_SCALE: u64 = 10000;

/// A single GMX trade record with realistic fields.
pub struct GmxTradeRecord {
    pub size_in_usd: U256,
    pub size_in_tokens: U256,
    pub collateral_amount: U256,
    pub is_long: bool,
    pub entry_price: U256,
    pub exit_price: U256,
    pub realized_pnl: U256,
    pub borrowing_fee: U256,
    pub funding_fee: U256,
    pub duration_seconds: u64,
    /// Signed return in basis points. Negative for losing trades.
    pub return_bps: i64,
}

impl GmxTradeRecord {
    /// Create a minimal GmxTradeRecord with only return_bps set.
    /// Used by WASM interface when only return values are provided.
    pub fn from_return_bps(bps: i64) -> Self {
        GmxTradeRecord {
            size_in_usd: U256::ZERO,
            size_in_tokens: U256::ZERO,
            collateral_amount: U256::ZERO,
            is_long: true,
            entry_price: U256::ZERO,
            exit_price: U256::ZERO,
            realized_pnl: U256::ZERO,
            borrowing_fee: U256::ZERO,
            funding_fee: U256::ZERO,
            duration_seconds: 0,
            return_bps: bps,
        }
    }
}

/// A mock trading bot with hardcoded trades.
pub struct MockBot {
    pub name: &'static str,
    pub trades: Vec<GmxTradeRecord>,
    /// Pre-computed sharpe_sq_scaled = Sharpe^2 * SHARPE_SCALE (exact integer).
    pub expected_sharpe_sq_scaled: u64,
}

/// Convert signed basis points to a BN254 field element.
/// Negative values become BN254_PRIME - |bp| (modular negation).
pub fn basis_points_to_field(bp: i64) -> U256 {
    if bp >= 0 {
        U256::from(bp as u64)
    } else {
        BN254Field::neg(U256::from((-bp) as u64))
    }
}

/// Compute a chained keccak hash of trade fields for dataset commitment.
/// Hash chain: keccak(keccak(keccak(size_in_usd, entry_price), exit_price), realized_pnl)
pub fn trade_leaf_hash(trade: &GmxTradeRecord) -> U256 {
    let h1 = keccak_hash_two(trade.size_in_usd, trade.entry_price);
    let h2 = keccak_hash_two(h1, trade.exit_price);
    let h3 = keccak_hash_two(h2, trade.realized_pnl);
    keccak_hash_two(h3, U256::from(trade.duration_seconds))
}

fn make_trade(
    size_usd: u64,
    size_tokens: u64,
    collateral: u64,
    is_long: bool,
    entry: u64,
    exit: u64,
    pnl_abs: u64,
    borrow_fee: u64,
    fund_fee: u64,
    duration: u64,
    return_bps: i64,
) -> GmxTradeRecord {
    GmxTradeRecord {
        size_in_usd: U256::from(size_usd),
        size_in_tokens: U256::from(size_tokens),
        collateral_amount: U256::from(collateral),
        is_long,
        entry_price: U256::from(entry),
        exit_price: U256::from(exit),
        realized_pnl: U256::from(pnl_abs),
        borrowing_fee: U256::from(borrow_fee),
        funding_fee: U256::from(fund_fee),
        duration_seconds: duration,
        return_bps,
    }
}

/// Bot A: Aggressive ETH trader. 15 trades with pattern [100, 200, 300] x 5.
///
/// cum_ret = 3000, cum_sq = 700000, N = 15
/// sharpe_sq_scaled = 3000^2 * 10000 / (15 * 700000 - 3000^2) = 60000
/// Sharpe = sqrt(6) ~ 2.449
pub fn bot_a_aggressive_eth() -> MockBot {
    let pattern = [100i64, 200, 300];

    let trades: Vec<GmxTradeRecord> = (0..15)
        .map(|i| {
            let bp = pattern[i % 3];
            make_trade(
                50000 + i as u64 * 2000,   // size_in_usd: $50k-$78k
                25 + i as u64,              // size_in_tokens
                10000 + i as u64 * 500,     // collateral
                i % 2 == 0,                 // alternating long/short
                2000_00 + i as u64 * 50,    // entry_price ($2000+)
                2000_00 + i as u64 * 50 + bp as u64 * 20, // exit_price
                bp as u64 * 50,             // realized_pnl
                15 + i as u64 * 2,          // borrowing_fee
                8 + i as u64,               // funding_fee
                3600 + i as u64 * 900,      // duration: 1h to 4.75h
                bp,
            )
        })
        .collect();

    MockBot {
        name: "bot_a_aggressive_eth",
        trades,
        expected_sharpe_sq_scaled: 60000,
    }
}

/// Bot B: Conservative hedger. 23 trades: 15 trades of 200bp, 8 breakeven trades (0bp).
///
/// cum_ret = 3000, cum_sq = 600000, N = 23
/// denom = 23 * 600000 - 3000^2 = 13800000 - 9000000 = 4800000
/// sharpe_sq_scaled = 9000000 * 10000 / 4800000 = 18750
/// Sharpe = sqrt(1.875) ~ 1.369
pub fn bot_b_safe_hedger() -> MockBot {
    let mut trades = Vec::with_capacity(23);

    // 15 profitable hedging trades (200bp each)
    for i in 0..15 {
        trades.push(make_trade(
            20000 + i as u64 * 300,     // size_in_usd: $20k-$24.2k
            10 + i as u64,              // size_in_tokens
            5000 + i as u64 * 100,      // collateral
            i % 3 != 0,                 // mostly long
            1800_00 + i as u64 * 20,    // entry_price
            1800_00 + i as u64 * 20 + 400, // exit_price (+200bp)
            200 * 10,                   // realized_pnl
            10 + i as u64,              // borrowing_fee
            5 + i as u64,               // funding_fee
            7200 + i as u64 * 600,      // duration: 2h to 4.4h
            200,
        ));
    }

    // 8 breakeven hedging trades (0bp each)
    for i in 0..8 {
        trades.push(make_trade(
            15000 + i as u64 * 200,     // size_in_usd: $15k-$16.4k
            8 + i as u64,               // size_in_tokens
            4000 + i as u64 * 80,       // collateral
            i % 2 == 0,                 // alternating
            1800_00 + i as u64 * 15,    // entry_price
            1800_00 + i as u64 * 15,    // exit_price (same = breakeven)
            0,                          // realized_pnl
            8 + i as u64,               // borrowing_fee
            4 + i as u64,               // funding_fee
            5400 + i as u64 * 450,      // duration: 1.5h to 3h
            0,
        ));
    }

    MockBot {
        name: "bot_b_safe_hedger",
        trades,
        expected_sharpe_sq_scaled: 18750,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BN254_PRIME;

    #[test]
    fn test_basis_points_to_field_positive() {
        let val = basis_points_to_field(100);
        assert_eq!(val, U256::from(100u64));
    }

    #[test]
    fn test_basis_points_to_field_negative() {
        let val = basis_points_to_field(-100);
        let expected = BN254_PRIME - U256::from(100u64);
        assert_eq!(val, expected);
    }

    #[test]
    fn test_basis_points_to_field_zero() {
        let val = basis_points_to_field(0);
        assert_eq!(val, U256::ZERO);
    }

    #[test]
    fn test_negative_square_is_positive() {
        // (-x)^2 = x^2 in the field
        let pos = basis_points_to_field(100);
        let neg = basis_points_to_field(-100);
        let pos_sq = BN254Field::mul(pos, pos);
        let neg_sq = BN254Field::mul(neg, neg);
        assert_eq!(pos_sq, neg_sq);
    }

    #[test]
    fn test_bot_a_trade_count() {
        let bot = bot_a_aggressive_eth();
        assert_eq!(bot.trades.len(), 15);
        assert_eq!(bot.name, "bot_a_aggressive_eth");
    }

    #[test]
    fn test_bot_b_trade_count() {
        let bot = bot_b_safe_hedger();
        assert_eq!(bot.trades.len(), 23);
        assert_eq!(bot.name, "bot_b_safe_hedger");
    }

    #[test]
    fn test_bot_a_sharpe_equation() {
        let bot = bot_a_aggressive_eth();
        let n = bot.trades.len() as u64;

        let mut cum_ret = U256::ZERO;
        let mut cum_sq = U256::ZERO;
        for trade in &bot.trades {
            let ret_field = basis_points_to_field(trade.return_bps);
            let ret_sq = BN254Field::mul(ret_field, ret_field);
            cum_ret = BN254Field::add(cum_ret, ret_field);
            cum_sq = BN254Field::add(cum_sq, ret_sq);
        }

        // Verify: cum_ret^2 * SCALE = claimed * (N * cum_sq - cum_ret^2)
        let cum_ret_sq = BN254Field::mul(cum_ret, cum_ret);
        let scale = U256::from(SHARPE_SCALE);
        let lhs = BN254Field::mul(cum_ret_sq, scale);

        let claimed = U256::from(bot.expected_sharpe_sq_scaled);
        let n_cum_sq = BN254Field::mul(U256::from(n), cum_sq);
        let denom = BN254Field::sub(n_cum_sq, cum_ret_sq);
        let rhs = BN254Field::mul(claimed, denom);

        assert_eq!(lhs, rhs, "Sharpe equation must hold exactly in the field");
    }

    #[test]
    fn test_bot_b_sharpe_equation() {
        let bot = bot_b_safe_hedger();
        let n = bot.trades.len() as u64;

        let mut cum_ret = U256::ZERO;
        let mut cum_sq = U256::ZERO;
        for trade in &bot.trades {
            let ret_field = basis_points_to_field(trade.return_bps);
            let ret_sq = BN254Field::mul(ret_field, ret_field);
            cum_ret = BN254Field::add(cum_ret, ret_field);
            cum_sq = BN254Field::add(cum_sq, ret_sq);
        }

        let cum_ret_sq = BN254Field::mul(cum_ret, cum_ret);
        let scale = U256::from(SHARPE_SCALE);
        let lhs = BN254Field::mul(cum_ret_sq, scale);

        let claimed = U256::from(bot.expected_sharpe_sq_scaled);
        let n_cum_sq = BN254Field::mul(U256::from(n), cum_sq);
        let denom = BN254Field::sub(n_cum_sq, cum_ret_sq);
        let rhs = BN254Field::mul(claimed, denom);

        assert_eq!(lhs, rhs, "Sharpe equation must hold exactly in the field");
    }

    #[test]
    fn test_trade_leaf_hash_deterministic() {
        let bot = bot_a_aggressive_eth();
        let h1 = trade_leaf_hash(&bot.trades[0]);
        let h2 = trade_leaf_hash(&bot.trades[0]);
        assert_eq!(h1, h2);
        assert_ne!(h1, U256::ZERO);
    }

    #[test]
    fn test_trade_leaf_hash_different_trades() {
        let bot = bot_a_aggressive_eth();
        let h0 = trade_leaf_hash(&bot.trades[0]);
        let h1 = trade_leaf_hash(&bot.trades[1]);
        assert_ne!(h0, h1);
    }
}
