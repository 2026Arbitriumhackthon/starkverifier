//! STARK Prover CLI
//!
//! Generates STARK proofs for Sharpe ratio verification.
//!
//! Usage:
//!   cargo run --features cli -- --bot a
//!   cargo run --features cli -- --bot b --num-queries 20
//!   cargo run --features cli -- --wallet 0x... --num-queries 4

#[cfg(feature = "cli")]
use clap::Parser;

use stark_prover::proof;

/// STARK Prover CLI
#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
#[command(name = "stark-prover")]
#[command(about = "Generate STARK proofs for Sharpe ratio verification")]
struct Args {
    /// Number of FRI queries (more = more secure, ~4 bits per query)
    #[arg(long, default_value_t = 20)]
    num_queries: usize,

    /// Bot id: a or b (mock data mode)
    #[arg(long, default_value = "a")]
    bot: String,

    /// Wallet address to fetch real GMX trades from (overrides --bot)
    #[arg(long)]
    wallet: Option<String>,

    /// Arbitrum RPC URL for fetching trades
    #[arg(long)]
    rpc_url: Option<String>,

    /// Start block for trade fetching (default: latest - 10M)
    #[arg(long)]
    from_block: Option<u64>,

    /// End block for trade fetching (default: latest)
    #[arg(long)]
    to_block: Option<u64>,

    /// Output format: json or hex
    #[arg(long, default_value = "json")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[cfg(feature = "cli")]
fn progress_cb(verbose: bool) -> Box<dyn Fn(stark_prover::ProveProgress)> {
    if verbose {
        Box::new(|p: stark_prover::ProveProgress| {
            println!("[{}] {} ({}%)", p.stage, p.detail, p.percent);
        })
    } else {
        Box::new(|p: stark_prover::ProveProgress| {
            if p.percent == 0 || p.percent == 100 || p.stage == "fri" {
                println!("[{}] {}", p.stage, p.detail);
            }
        })
    }
}

#[cfg(feature = "cli")]
fn output_proof(serialized: &stark_prover::proof::SerializedProof, format: &str) {
    println!();
    println!("{}", serialized.summary());
    println!();

    match format {
        "json" => println!("{}", serialized.to_json()),
        "hex" => println!("{}", proof::encode_calldata_hex(serialized)),
        _ => eprintln!("Unknown format: {}", format),
    }
}

#[cfg(feature = "cli")]
#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(wallet) = &args.wallet {
        // Real wallet mode: fetch GMX trades via RPC
        run_wallet_mode(&args, wallet).await;
    } else {
        // Mock bot mode
        run_mock_mode(&args);
    }
}

#[cfg(feature = "cli")]
async fn run_wallet_mode(args: &Args, wallet: &str) {
    use stark_prover::gmx_fetcher;
    use stark_prover::mock_data::GmxTradeRecord;
    use stark_prover::sharpe_trace::SharpeTrace;

    println!("=== STARK Prover — Live Wallet Mode ===");
    println!("Wallet: {}", wallet);
    println!("FRI queries: {}", args.num_queries);
    println!();

    // Fetch trades from Arbitrum RPC
    println!("[fetch] Fetching GMX PositionDecrease events...");
    let result = gmx_fetcher::fetch_gmx_trades(
        wallet,
        args.rpc_url.as_deref(),
        args.from_block,
        args.to_block,
    )
    .await;

    let result = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to fetch trades: {}", e);
            return;
        }
    };

    println!(
        "[fetch] Found {} trades (blocks {} — {})",
        result.trades.len(),
        result.from_block,
        result.to_block
    );

    if result.trades.len() < 2 {
        eprintln!("Need at least 2 trades for Sharpe ratio proof. Found: {}", result.trades.len());
        return;
    }

    // Print trade summary
    for (i, trade) in result.trades.iter().enumerate() {
        println!(
            "  Trade {}: return_bps={:+}, is_long={}, tx={}",
            i + 1,
            trade.return_bps,
            trade.is_long,
            &trade.tx_hash[..10]
        );
    }

    let returns_bps: Vec<i64> = gmx_fetcher::trades_to_returns_bps(&result.trades);
    println!();
    println!("Total return: {:+} bps", result.total_return_bps);

    // Convert to GmxTradeRecord for the prover
    let trades: Vec<GmxTradeRecord> = returns_bps
        .iter()
        .map(|&bp| GmxTradeRecord {
            size_in_usd: alloy_primitives::U256::ZERO,
            size_in_tokens: alloy_primitives::U256::ZERO,
            collateral_amount: alloy_primitives::U256::ZERO,
            is_long: true,
            entry_price: alloy_primitives::U256::ZERO,
            exit_price: alloy_primitives::U256::ZERO,
            realized_pnl: alloy_primitives::U256::ZERO,
            borrowing_fee: alloy_primitives::U256::ZERO,
            funding_fee: alloy_primitives::U256::ZERO,
            duration_seconds: 0,
            return_bps: bp,
        })
        .collect();

    // Compute claimed Sharpe via field arithmetic
    let trace = SharpeTrace::generate(&trades);
    let claimed = trace.compute_sharpe_sq_scaled();
    println!("Claimed Sharpe^2 * SCALE: {}", claimed);
    println!();

    // Generate proof
    let serialized = stark_prover::prove_sharpe_with_progress(
        &trades,
        claimed,
        args.num_queries,
        progress_cb(args.verbose),
    );

    output_proof(&serialized, &args.format);
}

#[cfg(feature = "cli")]
fn run_mock_mode(args: &Args) {
    let bot = match args.bot.as_str() {
        "a" => stark_prover::mock_data::bot_a_aggressive_eth(),
        "b" => stark_prover::mock_data::bot_b_safe_hedger(),
        _ => {
            eprintln!("Unknown bot: {}. Use 'a' or 'b'.", args.bot);
            return;
        }
    };

    println!("=== STARK Prover for Sharpe Ratio ===");
    println!("Bot: {} ({} trades)", bot.name, bot.trades.len());
    println!("Expected Sharpe^2 * SCALE: {}", bot.expected_sharpe_sq_scaled);
    println!("FRI queries: {}", args.num_queries);
    println!("Blowup factor: 4");
    println!();

    let claimed = alloy_primitives::U256::from(bot.expected_sharpe_sq_scaled);
    let serialized = stark_prover::prove_sharpe_with_progress(
        &bot.trades,
        claimed,
        args.num_queries,
        progress_cb(args.verbose),
    );

    output_proof(&serialized, &args.format);
}

#[cfg(not(feature = "cli"))]
fn main() {
    eprintln!("CLI feature not enabled. Build with: cargo run --features cli");
}
