//! SP1 Guest Program: Sharpe Ratio Computation
//!
//! Computes the same Sharpe ratio as the STARK prover, but inside a RISC-V zkVM.
//! SP1 automatically converts this native Rust into a Groth16-wrapped SNARK proof.
//!
//! Input (private): returns_bps: Vec<i64>
//! Output (public): (trade_count: u64, total_return: i64, sharpe_sq_scaled: u64)

#![no_main]
sp1_zkvm::entrypoint!(main);

const SHARPE_SCALE: i128 = 10000;

pub fn main() {
    // Read private input from the host
    let returns_bps: Vec<i64> = sp1_zkvm::io::read();

    let n = returns_bps.len() as i128;
    assert!(n > 1, "need at least 2 trades");

    // Accumulate cumulative return and cumulative squared return
    let mut cum_ret: i128 = 0;
    let mut cum_sq: i128 = 0;

    for &r in &returns_bps {
        let r128 = r as i128;
        cum_ret += r128;
        cum_sq += r128 * r128;
    }

    // Sharpe^2 equation (integer):
    //   sharpe_sq_scaled = cum_ret^2 * SCALE / (N * cum_sq - cum_ret^2)
    let cum_ret_sq = cum_ret * cum_ret;
    let denom = n * cum_sq - cum_ret_sq;
    assert!(denom > 0, "degenerate: zero variance");

    let sharpe_sq_scaled = (cum_ret_sq * SHARPE_SCALE) / denom;

    let total_return = cum_ret as i64;
    let trade_count = returns_bps.len() as u64;
    let sharpe_out = sharpe_sq_scaled as u64;

    // Commit public outputs
    sp1_zkvm::io::commit(&trade_count);
    sp1_zkvm::io::commit(&total_return);
    sp1_zkvm::io::commit(&sharpe_out);
}
