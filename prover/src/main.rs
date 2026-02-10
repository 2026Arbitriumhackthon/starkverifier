//! STARK Prover CLI
//!
//! Generates STARK proofs for Fibonacci computation.
//! The generated proof can be submitted to the on-chain verifier.
//!
//! Usage:
//!   cargo run -- --fib-n 64
//!   cargo run -- --fib-n 64 --num-queries 20

#[cfg(feature = "cli")]
use clap::Parser;

use stark_prover::proof;

/// STARK Prover for Fibonacci computation
#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
#[command(name = "stark-prover")]
#[command(about = "Generate STARK proofs for Fibonacci computation")]
struct Args {
    /// Number of Fibonacci steps (will be padded to power of 2)
    #[arg(long, default_value_t = 64)]
    fib_n: usize,

    /// Number of FRI queries (more = more secure, ~4 bits per query)
    #[arg(long, default_value_t = 20)]
    num_queries: usize,

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

        println!("=== STARK Prover for Fibonacci ===");
        println!("Fibonacci steps: {}", args.fib_n);
        println!("FRI queries: {}", args.num_queries);
        println!("Blowup factor: 4");
        println!();

        let serialized = if args.verbose {
            stark_prover::prove_fibonacci_with_progress(
                args.fib_n,
                args.num_queries,
                |p| {
                    println!("[{}] {} ({}%)", p.stage, p.detail, p.percent);
                },
            )
        } else {
            stark_prover::prove_fibonacci_with_progress(
                args.fib_n,
                args.num_queries,
                |p| {
                    if p.percent == 0 || p.percent == 100 || p.stage == "fri" {
                        println!("[{}] {}", p.stage, p.detail);
                    }
                },
            )
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
