//! STARK Prover CLI
//!
//! Generates STARK proofs for Fibonacci computation or BTC Lock verification.
//!
//! Usage:
//!   cargo run --features cli -- --fib-n 64
//!   cargo run --features cli -- --mode btclock --lock-amount 100000 \
//!     --timelock-height 900000 --current-height 850000 --script-type 2

#[cfg(feature = "cli")]
use clap::Parser;

use stark_prover::proof;

/// STARK Prover CLI
#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
#[command(name = "stark-prover")]
#[command(about = "Generate STARK proofs for Fibonacci, BTC Lock, or Sharpe verification")]
struct Args {
    /// Proof mode: fibonacci, btclock, or sharpe
    #[arg(long, default_value = "fibonacci")]
    mode: String,

    /// Number of Fibonacci steps (fibonacci mode only)
    #[arg(long, default_value_t = 64)]
    fib_n: usize,

    /// Number of FRI queries (more = more secure, ~4 bits per query)
    #[arg(long, default_value_t = 20)]
    num_queries: usize,

    /// BTC lock amount in satoshis (btclock mode)
    #[arg(long, default_value_t = 100000)]
    lock_amount: u64,

    /// Timelock expiry block height (btclock mode)
    #[arg(long, default_value_t = 900000)]
    timelock_height: u64,

    /// Current block height (btclock mode)
    #[arg(long, default_value_t = 850000)]
    current_height: u64,

    /// Script type: 1=P2SH, 2=P2WSH (btclock mode)
    #[arg(long, default_value_t = 2)]
    script_type: u64,

    /// Bot id: a or b (sharpe mode)
    #[arg(long, default_value = "a")]
    bot: String,

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

        let progress_cb = |verbose: bool| -> Box<dyn Fn(stark_prover::ProveProgress)> {
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
        };

        let serialized = match args.mode.as_str() {
            "fibonacci" => {
                println!("=== STARK Prover for Fibonacci ===");
                println!("Fibonacci steps: {}", args.fib_n);
                println!("FRI queries: {}", args.num_queries);
                println!("Blowup factor: 4");
                println!();

                stark_prover::prove_fibonacci_with_progress(
                    args.fib_n,
                    args.num_queries,
                    progress_cb(args.verbose),
                )
            }
            "btclock" => {
                println!("=== STARK Prover for BTC Lock ===");
                println!("Lock amount: {} sat", args.lock_amount);
                println!("Timelock height: {}", args.timelock_height);
                println!("Current height: {}", args.current_height);
                println!("Script type: {} ({})", args.script_type,
                    if args.script_type == 1 { "P2SH" } else { "P2WSH" });
                println!("FRI queries: {}", args.num_queries);
                println!("Blowup factor: 4");
                println!();

                stark_prover::prove_btc_lock_with_progress(
                    args.lock_amount,
                    args.timelock_height,
                    args.current_height,
                    args.script_type,
                    args.num_queries,
                    progress_cb(args.verbose),
                )
            }
            "sharpe" => {
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
                stark_prover::prove_sharpe_with_progress(
                    &bot.trades,
                    claimed,
                    args.num_queries,
                    progress_cb(args.verbose),
                )
            }
            _ => {
                eprintln!("Unknown mode: {}. Use 'fibonacci', 'btclock', or 'sharpe'.", args.mode);
                return;
            }
        };

        println!();
        println!("{}", serialized.summary());
        println!();

        match args.format.as_str() {
            "json" => {
                println!("{}", serialized.to_json());
            }
            "hex" => {
                println!("{}", proof::encode_calldata_hex(&serialized));
            }
            _ => {
                eprintln!("Unknown format: {}", args.format);
            }
        }
    }

    #[cfg(not(feature = "cli"))]
    {
        eprintln!("CLI feature not enabled. Build with: cargo run --features cli");
    }
}
