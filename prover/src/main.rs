//! STARK Prover CLI
//!
//! Generates STARK proofs for Sharpe ratio verification.
//!
//! Usage:
//!   cargo run --features cli -- --bot a
//!   cargo run --features cli -- --bot b --num-queries 20
//!   cargo run --features cli --release -- --wallet 0x<address> --tx-hash 0x<hash> --num-queries 4

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

    /// Bot id: a or b (sharpe mode, used when --wallet is not set)
    #[arg(long, default_value = "a")]
    bot: String,

    /// Wallet address for live data mode (e.g., 0x1234...)
    #[arg(long)]
    wallet: Option<String>,

    /// Transaction hash for receipt proof (used with --wallet)
    #[arg(long)]
    tx_hash: Option<String>,

    /// Arbitrum RPC URL
    #[arg(long, default_value = "https://arb1.arbitrum.io/rpc")]
    rpc_url: String,

    /// Output format: json or hex
    #[arg(long, default_value = "json")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    #[cfg(feature = "cli")]
    {
        let args = Args::parse();

        if args.wallet.is_some() {
            run_wallet_mode(args);
        } else {
            run_bot_mode(args);
        }
    }

    #[cfg(not(feature = "cli"))]
    {
        eprintln!("CLI feature not enabled. Build with: cargo run --features cli");
    }
}

#[cfg(feature = "cli")]
fn run_bot_mode(args: Args) {
    let progress_cb = make_progress_cb(args.verbose);

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
        progress_cb,
    );

    println!();
    println!("{}", serialized.summary());
    println!();

    output_proof(&serialized, &args.format);
}

#[cfg(feature = "cli")]
fn run_wallet_mode(args: Args) {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    rt.block_on(async {
        let wallet = args.wallet.as_deref().unwrap();
        println!("=== STARK Prover — Live Wallet Mode ===");
        println!("Wallet: {}", wallet);
        println!("RPC: {}", args.rpc_url);

        // Step 1: Fetch receipt proof if tx_hash is provided
        let dataset_commitment = if let Some(ref tx_hash) = args.tx_hash {
            println!("\n[receipt] Fetching receipt proof for tx: {}", tx_hash);

            let client = reqwest::Client::new();
            match stark_prover::gmx_fetcher::fetch_receipt_proof(&client, &args.rpc_url, tx_hash).await {
                Ok(proof_data) => {
                    let commitment = stark_prover::gmx_fetcher::commitment_from_proof(&proof_data);
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

        // Step 2: Use mock trades for now (will be replaced with real GMX data)
        let bot = stark_prover::mock_data::bot_a_aggressive_eth();
        println!("\n[trace] Using {} trades", bot.trades.len());

        let progress_cb = make_progress_cb(args.verbose);
        let claimed = alloy_primitives::U256::from(bot.expected_sharpe_sq_scaled);

        let serialized = stark_prover::prove_sharpe_with_progress(
            &bot.trades,
            claimed,
            args.num_queries,
            dataset_commitment,
            progress_cb,
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
    });
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
        "json" => {
            println!("{}", serialized.to_json());
        }
        "hex" => {
            println!("{}", proof::encode_calldata_hex(serialized));
        }
        _ => {
            eprintln!("Unknown format: {}", format);
        }
    }
}
