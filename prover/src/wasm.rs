//! WASM bindings for the STARK prover.
//!
//! Provides a JavaScript-friendly API via wasm-bindgen.
//! Build with: `wasm-pack build --target web --features wasm --no-default-features`

use wasm_bindgen::prelude::*;

/// WASM-accessible STARK prover.
#[wasm_bindgen]
pub struct StarkProverWasm;

#[wasm_bindgen]
impl StarkProverWasm {
    #[wasm_bindgen(constructor)]
    pub fn new() -> StarkProverWasm {
        StarkProverWasm
    }

    /// Generate a STARK proof for Fibonacci computation.
    ///
    /// Returns a JSON string containing the serialized proof.
    #[wasm_bindgen(js_name = "generateProof")]
    pub fn generate_proof(&self, fib_n: u32, num_queries: u32) -> String {
        let proof = crate::prove_fibonacci(fib_n as usize, num_queries as usize);
        proof.to_json()
    }

    /// Generate a proof with progress updates via a JS callback.
    ///
    /// The callback receives (stage: string, detail: string, percent: number).
    #[wasm_bindgen(js_name = "generateProofWithProgress")]
    pub fn generate_proof_with_progress(
        &self,
        fib_n: u32,
        num_queries: u32,
        callback: &js_sys::Function,
    ) -> String {
        let proof = crate::prove_fibonacci_with_progress(
            fib_n as usize,
            num_queries as usize,
            |progress| {
                let this = JsValue::null();
                let stage = JsValue::from_str(progress.stage);
                let detail = JsValue::from_str(progress.detail);
                let percent = JsValue::from_f64(progress.percent as f64);
                let _ = callback.call3(&this, &stage, &detail, &percent);
            },
        );
        proof.to_json()
    }

    /// Generate a BTC Lock STARK proof.
    ///
    /// Returns a JSON string containing the serialized proof.
    #[wasm_bindgen(js_name = "generateBtcLockProof")]
    pub fn generate_btc_lock_proof(
        &self,
        lock_amount: u32,
        timelock_height: u32,
        current_height: u32,
        script_type: u32,
        num_queries: u32,
    ) -> String {
        let proof = crate::prove_btc_lock(
            lock_amount as u64,
            timelock_height as u64,
            current_height as u64,
            script_type as u64,
            num_queries as usize,
        );
        proof.to_json()
    }

    /// Generate a BTC Lock proof with progress updates via a JS callback.
    #[wasm_bindgen(js_name = "generateBtcLockProofWithProgress")]
    pub fn generate_btc_lock_proof_with_progress(
        &self,
        lock_amount: u32,
        timelock_height: u32,
        current_height: u32,
        script_type: u32,
        num_queries: u32,
        callback: &js_sys::Function,
    ) -> String {
        let proof = crate::prove_btc_lock_with_progress(
            lock_amount as u64,
            timelock_height as u64,
            current_height as u64,
            script_type as u64,
            num_queries as usize,
            |progress| {
                let this = JsValue::null();
                let stage = JsValue::from_str(progress.stage);
                let detail = JsValue::from_str(progress.detail);
                let percent = JsValue::from_f64(progress.percent as f64);
                let _ = callback.call3(&this, &stage, &detail, &percent);
            },
        );
        proof.to_json()
    }

    /// Generate a Sharpe ratio STARK proof.
    ///
    /// bot_id: "a" for aggressive ETH bot, "b" for safe hedger.
    /// Returns a JSON string containing the serialized proof.
    #[wasm_bindgen(js_name = "generateSharpeProof")]
    pub fn generate_sharpe_proof(&self, bot_id: &str, num_queries: u32) -> String {
        let bot = match bot_id {
            "a" => crate::mock_data::bot_a_aggressive_eth(),
            "b" => crate::mock_data::bot_b_safe_hedger(),
            _ => return "{}".to_string(),
        };
        let claimed = alloy_primitives::U256::from(bot.expected_sharpe_sq_scaled);
        let proof = crate::prove_sharpe(&bot.trades, claimed, num_queries as usize);
        proof.to_json()
    }

    /// Generate a Sharpe proof with progress updates via a JS callback.
    #[wasm_bindgen(js_name = "generateSharpeProofWithProgress")]
    pub fn generate_sharpe_proof_with_progress(
        &self,
        bot_id: &str,
        num_queries: u32,
        callback: &js_sys::Function,
    ) -> String {
        let bot = match bot_id {
            "a" => crate::mock_data::bot_a_aggressive_eth(),
            "b" => crate::mock_data::bot_b_safe_hedger(),
            _ => return "{}".to_string(),
        };
        let claimed = alloy_primitives::U256::from(bot.expected_sharpe_sq_scaled);
        let proof = crate::prove_sharpe_with_progress(
            &bot.trades,
            claimed,
            num_queries as usize,
            |progress| {
                let this = JsValue::null();
                let stage = JsValue::from_str(progress.stage);
                let detail = JsValue::from_str(progress.detail);
                let percent = JsValue::from_f64(progress.percent as f64);
                let _ = callback.call3(&this, &stage, &detail, &percent);
            },
        );
        proof.to_json()
    }
}
