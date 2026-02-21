//! STARK Benchmark: Sharpe Ratio Proof Generation Timing
//!
//! Wraps the existing prover crate to measure wall-clock proof generation time
//! and proof size. Outputs JSON compatible with the benchmark results format.

use alloy_primitives::U256;
use clap::Parser;
use stark_prover::mock_data::{bot_a_aggressive_eth, bot_b_safe_hedger};
use stark_prover::prove_sharpe;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "stark-bench", about = "STARK Sharpe ratio proof benchmark")]
struct Cli {
    /// Bot to benchmark: "a" or "b"
    #[arg(long, default_value = "a")]
    bot: String,

    /// Number of FRI queries
    #[arg(long, default_value = "4")]
    num_queries: usize,

    /// Total iterations (measured, excluding warmup)
    #[arg(long, default_value = "10")]
    iterations: usize,

    /// Warmup iterations (excluded from results)
    #[arg(long, default_value = "2")]
    warmup: usize,
}

fn main() {
    let cli = Cli::parse();

    let bot = match cli.bot.as_str() {
        "a" => bot_a_aggressive_eth(),
        "b" => bot_b_safe_hedger(),
        _ => panic!("unknown bot: use 'a' or 'b'"),
    };

    let claimed = U256::from(bot.expected_sharpe_sq_scaled);

    println!(
        "=== STARK Benchmark: {} ({} warmup + {} measured, {} queries) ===",
        bot.name, cli.warmup, cli.iterations, cli.num_queries
    );

    // Warmup
    for i in 0..cli.warmup {
        println!("  warmup {}/{}...", i + 1, cli.warmup);
        let _ = prove_sharpe(&bot.trades, claimed, cli.num_queries, None);
    }

    // Measured runs
    let mut times_ms: Vec<f64> = Vec::with_capacity(cli.iterations);
    let mut proof_size = 0usize;

    for i in 0..cli.iterations {
        let start = Instant::now();
        let proof = prove_sharpe(&bot.trades, claimed, cli.num_queries, None);
        let ms = start.elapsed().as_secs_f64() * 1000.0;

        println!("  run {}/{}: {:.1}ms", i + 1, cli.iterations, ms);
        times_ms.push(ms);
        proof_size = proof.calldata_size();
    }

    let avg = times_ms.iter().sum::<f64>() / times_ms.len() as f64;
    let min = times_ms.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = times_ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    // On-chain gas from CLAUDE.md: Bot A ~1.25M, Bot B ~1.45M
    let on_chain_gas: u64 = match cli.bot.as_str() {
        "a" => 1_250_000,
        "b" => 1_450_000,
        _ => 1_250_000,
    };

    let result = serde_json::json!({
        "system": "stark",
        "tool": "Custom STARK (Keccak256)",
        "bot": cli.bot,
        "trade_count": bot.trades.len(),
        "sharpe_sq_scaled": bot.expected_sharpe_sq_scaled,
        "num_queries": cli.num_queries,
        "iterations": cli.iterations,
        "proof_gen_time_ms": {
            "avg": avg.round() as u64,
            "min": min.round() as u64,
            "max": max.round() as u64
        },
        "proof_size_bytes": proof_size,
        "on_chain_gas": on_chain_gas,
        "verifier": "Stylus (WASM)",
        "setup": "Transparent"
    });

    println!("\n{}", serde_json::to_string_pretty(&result).unwrap());

    // Write to file
    let path = format!("{}/../../benchmark/results/stark-{}.json", env!("CARGO_MANIFEST_DIR"), cli.bot);
    std::fs::write(&path, serde_json::to_string_pretty(&result).unwrap())
        .unwrap_or_else(|e| eprintln!("warning: could not write {path}: {e}"));
}
