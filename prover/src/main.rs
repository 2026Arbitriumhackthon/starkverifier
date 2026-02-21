//! STARK Prover CLI
//!
//! Generates STARK proofs for Sharpe ratio verification.
//!
//! Usage:
//!   cargo run --features cli -- --bot a
//!   cargo run --features cli -- --bot b --num-queries 20

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
