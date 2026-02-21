//! STARK Prover CLI
//!
//! Generates STARK proofs for Sharpe ratio verification.
//!
//! Usage:
//!   cargo run --features cli -- --bot a
//!   cargo run --features cli -- --bot b --num-queries 20
//!   cargo run --features cli -- --wallet 0x... --tx-hash 0x... --num-queries 4

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

    /// Transaction hash for receipt proof (used with --wallet)
    #[arg(long)]
    tx_hash: Option<String>,

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
fn make_progress_cb(verbose: bool) -> Box<dyn Fn(stark_prover::ProveProgress)> {
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

    if args.wallet.is_some() {
        run_wallet_mode(&args).await;
    } else {
        run_bot_mode(&args);
    }
}

#[cfg(not(feature = "cli"))]
fn main() {
    eprintln!("CLI feature not enabled. Build with: cargo run --features cli");
}

#[cfg(feature = "cli")]
fn run_bot_mode(args: &Args) {
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
        None,
        make_progress_cb(args.verbose),
    );

    println!();
    println!("{}", serialized.summary());
    println!();

    output_proof(&serialized, &args.format);
}

#[cfg(feature = "cli")]
async fn run_wallet_mode(args: &Args) {
    use stark_prover::gmx_fetcher;
    use stark_prover::mock_data::GmxTradeRecord;
    use stark_prover::sharpe_trace::SharpeTrace;

    let wallet = args.wallet.as_deref().unwrap();
    let rpc_url = args.rpc_url.as_deref().unwrap_or(gmx_fetcher::DEFAULT_ARBITRUM_RPC);

    println!("=== STARK Prover — Live Wallet Mode ===");
    println!("Wallet: {}", wallet);
    println!("RPC: {}", rpc_url);
    println!("FRI queries: {}", args.num_queries);
    println!();

    // Step 1: Fetch trades from Arbitrum RPC
    println!("[fetch] Fetching GMX PositionDecrease events...");
    let result = gmx_fetcher::fetch_gmx_trades(
        wallet,
        Some(rpc_url),
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

    // Step 2: Fetch receipt proof if tx_hash is provided
    let dataset_commitment = if let Some(ref tx_hash) = args.tx_hash {
        println!("\n[receipt] Fetching receipt proof for tx: {}", tx_hash);

        let client = reqwest::Client::new();
        match gmx_fetcher::fetch_receipt_proof(&client, rpc_url, tx_hash).await {
            Ok(proof_data) => {
                let commitment = gmx_fetcher::commitment_from_proof(&proof_data);
                println!("[receipt] Block: #{}", proof_data.block_number);
                println!("[receipt] Block hash: 0x{:064x}", proof_data.block_hash);
                println!("[receipt] Receipts root: 0x{}", hex::encode(proof_data.receipts_root));
                println!("[receipt] Dataset commitment: 0x{:064x}", commitment);
                Some(commitment)
            }
            Err(e) => {
                eprintln!("[receipt] Warning: Failed to fetch receipt proof: {}", e);
                eprintln!("[receipt] Continuing without receipt binding...");
                None
            }
        }
    } else {
        println!("\n[receipt] No --tx-hash provided, skipping receipt proof");
        None
    };

    // Step 3: Generate proof
    let trades: Vec<GmxTradeRecord> = returns_bps
        .iter()
        .map(|&bp| GmxTradeRecord::from_return_bps(bp))
        .collect();

    // Compute claimed Sharpe via field arithmetic
    let trace = SharpeTrace::generate(&trades, dataset_commitment);
    let claimed = trace.compute_sharpe_sq_scaled();
    println!("Claimed Sharpe^2 * SCALE: {}", claimed);
    println!();

    // Generate proof
    let serialized = stark_prover::prove_sharpe_with_progress(
        &trades,
        claimed,
        args.num_queries,
        dataset_commitment,
        make_progress_cb(args.verbose),
    );

    println!();
    println!("{}", serialized.summary());
    if dataset_commitment.is_some() {
        println!("Receipt proof: BOUND (dataset_commitment in pi[3])");
    } else {
        println!("Receipt proof: NOT BOUND (no tx-hash provided)");
    }
    println!();

    output_proof(&serialized, &args.format);
}
