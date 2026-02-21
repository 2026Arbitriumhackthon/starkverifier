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
        let proof = crate::prove_sharpe(&bot.trades, claimed, num_queries as usize, None);
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
            None,
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

    /// Generate a Sharpe proof from return_bps array with a dataset commitment.
    ///
    /// returns_bps: array of trade returns in basis points
    /// dataset_commitment_hex: "0x..." hex string of the dataset commitment (or empty for no commitment)
    /// num_queries: number of FRI queries
    /// callback: JS function(stage, detail, percent) for progress updates
    #[wasm_bindgen(js_name = "generateSharpeProofWithCommitment")]
    pub fn generate_sharpe_proof_with_commitment(
        &self,
        returns_bps: &[i32],
        dataset_commitment_hex: &str,
        num_queries: u32,
        callback: &js_sys::Function,
    ) -> String {
        // Parse dataset commitment
        let commitment = if dataset_commitment_hex.is_empty() || dataset_commitment_hex == "0x" || dataset_commitment_hex == "0x0" {
            None
        } else {
            let hex_str = dataset_commitment_hex.trim_start_matches("0x");
            match alloy_primitives::U256::from_str_radix(hex_str, 16) {
                Ok(v) => Some(v),
                Err(_) => None,
            }
        };

        // Convert returns_bps to GmxTradeRecord (only return_bps matters for Sharpe)
        let trades: Vec<crate::mock_data::GmxTradeRecord> = returns_bps
            .iter()
            .map(|&bps| crate::mock_data::GmxTradeRecord::from_return_bps(bps as i64))
            .collect();

        if trades.len() < 2 {
            return "{}".to_string();
        }

        // Compute claimed sharpe_sq_scaled from trace
        let trace = crate::sharpe_trace::SharpeTrace::generate(&trades, commitment);
        let claimed = trace.compute_sharpe_sq_scaled();

        let proof = crate::prove_sharpe_with_progress(
            &trades,
            claimed,
            num_queries as usize,
            commitment,
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

    /// Generate a Sharpe proof from return_bps array (no commitment).
    ///
    /// returns_bps: array of trade returns in basis points
    /// num_queries: number of FRI queries
    /// callback: JS function(stage, detail, percent) for progress updates
    #[wasm_bindgen(js_name = "generateSharpeProofFromReturns")]
    pub fn generate_sharpe_proof_from_returns(
        &self,
        returns_bps: &[i32],
        num_queries: u32,
        callback: &js_sys::Function,
    ) -> String {
        self.generate_sharpe_proof_with_commitment(returns_bps, "", num_queries, callback)
    }
}
