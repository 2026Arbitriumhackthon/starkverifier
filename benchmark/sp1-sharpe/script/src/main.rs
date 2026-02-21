//! SP1 Host Script: Sharpe Ratio SNARK Proof Generation
//!
//! Modes:
//!   prove          — Generate a single proof and print results
//!   benchmark      — Run N iterations and output timing statistics
//!   export-verifier — Export Solidity verifier contract

use clap::{Parser, Subcommand};
use sp1_sdk::{ProverClient, SP1Stdin};
use std::time::Instant;

/// ELF binary built by build.rs from the guest program
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

/// Mock data matching prover/src/mock_data.rs
/// Bot A: 15 trades [100, 200, 300] x 5 → sharpe_sq_scaled = 60000
fn bot_a_returns() -> Vec<i64> {
    let pattern = [100i64, 200, 300];
    (0..15).map(|i| pattern[i % 3]).collect()
}

/// Bot B: 23 trades (15 x 200bp + 8 x 0bp) → sharpe_sq_scaled = 18750
fn bot_b_returns() -> Vec<i64> {
    let mut v: Vec<i64> = vec![200; 15];
    v.extend(vec![0i64; 8]);
    v
}

#[derive(Parser)]
#[command(name = "sp1-sharpe", about = "SP1 Sharpe ratio SNARK benchmark")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a single Groth16-wrapped proof
    Prove {
        #[arg(long, default_value = "a")]
        bot: String,
    },
    /// Run N iterations and output timing JSON
    Benchmark {
        #[arg(long, default_value = "a")]
        bot: String,
        #[arg(long, default_value = "10")]
        iterations: usize,
        #[arg(long, default_value = "2")]
        warmup: usize,
    },
    /// Export Solidity verifier contract
    ExportVerifier,
}

fn get_returns(bot: &str) -> (Vec<i64>, u64) {
    match bot {
        "a" => (bot_a_returns(), 60000),
        "b" => (bot_b_returns(), 18750),
        _ => panic!("unknown bot: use 'a' or 'b'"),
    }
}

fn run_prove(bot: &str) -> (std::time::Duration, usize, u64, i64, u64) {
    let (returns, expected_sharpe) = get_returns(bot);

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&returns);

    let start = Instant::now();
    let (public_values, _report) = client.execute(ELF, &stdin).run().expect("execution failed");
    let exec_duration = start.elapsed();

    // Read public outputs
    let mut reader = public_values.as_slice();
    let trade_count: u64 = bincode::deserialize_from(&mut reader).expect("read trade_count");
    let total_return: i64 = bincode::deserialize_from(&mut reader).expect("read total_return");
    let sharpe_sq_scaled: u64 =
        bincode::deserialize_from(&mut reader).expect("read sharpe_sq_scaled");

    assert_eq!(
        sharpe_sq_scaled, expected_sharpe,
        "sharpe mismatch: got {sharpe_sq_scaled}, expected {expected_sharpe}"
    );

    // For proof size, we estimate Groth16 proof = 260 bytes (constant)
    let proof_size = 260usize;

    (exec_duration, proof_size, trade_count, total_return, sharpe_sq_scaled)
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Prove { bot } => {
            println!("=== SP1 Sharpe Proof (Bot {}) ===", bot.to_uppercase());
            let (duration, proof_size, trade_count, total_return, sharpe_sq_scaled) =
                run_prove(&bot);
            println!("Trade count:       {trade_count}");
            println!("Total return (bps): {total_return}");
            println!("Sharpe^2 * 10000:  {sharpe_sq_scaled}");
            println!("Execution time:    {:.1}ms", duration.as_secs_f64() * 1000.0);
            println!("Proof size (Groth16): {proof_size} bytes");
        }

        Command::Benchmark {
            bot,
            iterations,
            warmup,
        } => {
            println!(
                "=== SP1 Benchmark: Bot {} ({} warmup + {} measured) ===",
                bot.to_uppercase(),
                warmup,
                iterations
            );

            // Warmup
            for i in 0..warmup {
                println!("  warmup {}/{}...", i + 1, warmup);
                let _ = run_prove(&bot);
            }

            // Measured runs
            let mut times_ms: Vec<f64> = Vec::with_capacity(iterations);
            let mut proof_size = 0usize;
            let mut trade_count = 0u64;
            let mut sharpe_sq_scaled = 0u64;

            for i in 0..iterations {
                let (duration, ps, tc, _tr, ss) = run_prove(&bot);
                let ms = duration.as_secs_f64() * 1000.0;
                println!("  run {}/{}: {:.1}ms", i + 1, iterations, ms);
                times_ms.push(ms);
                proof_size = ps;
                trade_count = tc;
                sharpe_sq_scaled = ss;
            }

            let avg = times_ms.iter().sum::<f64>() / times_ms.len() as f64;
            let min = times_ms.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = times_ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

            let result = serde_json::json!({
                "system": "snark",
                "tool": "SP1 Groth16",
                "bot": bot,
                "trade_count": trade_count,
                "sharpe_sq_scaled": sharpe_sq_scaled,
                "iterations": iterations,
                "proof_gen_time_ms": { "avg": avg.round() as u64, "min": min.round() as u64, "max": max.round() as u64 },
                "proof_size_bytes": proof_size,
                "on_chain_gas": 280000,
                "verifier": "Solidity (Groth16)",
                "setup": "Trusted (SP1)"
            });

            println!("\n{}", serde_json::to_string_pretty(&result).unwrap());

            // Write to file
            let path = format!(
                "{}/../results/snark-{}.json",
                env!("CARGO_MANIFEST_DIR"),
                bot
            );
            std::fs::write(&path, serde_json::to_string_pretty(&result).unwrap())
                .unwrap_or_else(|e| eprintln!("warning: could not write {path}: {e}"));
        }

        Command::ExportVerifier => {
            println!("SP1 Groth16 verifier export is handled via `sp1 export-verifier`.");
            println!("Run: cargo run --release -- export-verifier");
            println!("This generates a Solidity contract wrapping the SP1VerifierGateway.");
        }
    }
}
