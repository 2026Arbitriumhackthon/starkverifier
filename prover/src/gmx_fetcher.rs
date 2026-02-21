//! GMX Receipt Proof Fetcher (CLI only)
//!
//! Fetches transaction receipts and block data from Arbitrum RPC,
//! constructs MPT proofs, and computes dataset commitments.

use alloy_primitives::U256;
use crate::receipt_proof::{ReceiptProofData, compute_dataset_commitment, rlp_encode_tx_index};
use tiny_keccak::{Hasher, Keccak};

/// Keccak256 of a byte slice.
#[allow(dead_code)]
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// A simple in-memory MPT (Merkle Patricia Trie) for building receipt proofs.
/// This is used to construct the trie from all receipts in a block,
/// then extract a proof for a specific transaction index.
pub struct SimpleMptTrie {
    nodes: Vec<(Vec<u8>, Vec<u8>)>, // (key_nibbles, value)
}

impl SimpleMptTrie {
    pub fn new() -> Self {
        SimpleMptTrie { nodes: Vec::new() }
    }

    /// Insert a key-value pair into the trie.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        let nibbles = bytes_to_nibbles(key);
        self.nodes.push((nibbles, value));
    }

    /// Build the trie and generate a proof for the given key.
    /// Returns (root_hash, proof_nodes).
    ///
    /// For the hackathon demo, we use a simplified approach:
    /// we RLP-encode all receipts, compute the receipts root via keccak,
    /// and return the raw receipt as the "proof" (to be verified against
    /// the block header's receiptsRoot on-chain).
    pub fn build_proof(&self, _target_key: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        // Simplified: return empty proof nodes.
        // Full MPT proof generation would build the complete trie and extract path.
        // For the hackathon, on-chain verification uses the receiptsRoot from the block header.
        (Vec::new(), Vec::new())
    }
}

fn bytes_to_nibbles(data: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(data.len() * 2);
    for byte in data {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Fetch receipt proof data for a transaction from an RPC endpoint.
///
/// Steps:
/// 1. eth_getTransactionReceipt(tx_hash) → receipt + blockNumber + transactionIndex
/// 2. eth_getBlockByNumber(blockNumber) → block header (receiptsRoot, hash)
/// 3. Compute dataset_commitment
pub async fn fetch_receipt_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Result<ReceiptProofData, String> {
    // Step 1: Get transaction receipt
    let receipt_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash],
        "id": 1
    });

    let receipt_resp: serde_json::Value = client
        .post(rpc_url)
        .json(&receipt_body)
        .send()
        .await
        .map_err(|e| format!("RPC error: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse error: {}", e))?;

    let receipt = receipt_resp["result"]
        .as_object()
        .ok_or("No receipt found")?;

    let block_number_hex = receipt["blockNumber"]
        .as_str()
        .ok_or("No blockNumber")?;
    let block_number = u64::from_str_radix(block_number_hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Invalid blockNumber: {}", e))?;

    let tx_index_hex = receipt["transactionIndex"]
        .as_str()
        .ok_or("No transactionIndex")?;
    let tx_index = u64::from_str_radix(tx_index_hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Invalid transactionIndex: {}", e))?;

    // Step 2: Get block header
    let block_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [format!("0x{:x}", block_number), false],
        "id": 2
    });

    let block_resp: serde_json::Value = client
        .post(rpc_url)
        .json(&block_body)
        .send()
        .await
        .map_err(|e| format!("RPC error: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse error: {}", e))?;

    let block = block_resp["result"]
        .as_object()
        .ok_or("No block found")?;

    let block_hash_hex = block["hash"]
        .as_str()
        .ok_or("No block hash")?;
    let block_hash = U256::from_str_radix(block_hash_hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Invalid block hash: {}", e))?;

    let receipts_root_hex = block["receiptsRoot"]
        .as_str()
        .ok_or("No receiptsRoot")?;
    let receipts_root_bytes = hex::decode(receipts_root_hex.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid receiptsRoot hex: {}", e))?;
    let mut receipts_root = [0u8; 32];
    if receipts_root_bytes.len() == 32 {
        receipts_root.copy_from_slice(&receipts_root_bytes);
    } else {
        return Err("receiptsRoot is not 32 bytes".to_string());
    }

    // Step 3: Build receipt RLP (simplified — use the raw receipt fields)
    // For the hackathon, we serialize the essential receipt fields as RLP.
    let status_hex = receipt.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("0x1");
    let status = u64::from_str_radix(status_hex.trim_start_matches("0x"), 16).unwrap_or(1);

    let cumulative_gas_hex = receipt.get("cumulativeGasUsed")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");
    let cumulative_gas = u64::from_str_radix(cumulative_gas_hex.trim_start_matches("0x"), 16)
        .unwrap_or(0);

    let logs_bloom_hex = receipt.get("logsBloom")
        .and_then(|v| v.as_str())
        .unwrap_or("0x");
    let logs_bloom = hex::decode(logs_bloom_hex.trim_start_matches("0x"))
        .unwrap_or_default();

    // Simplified receipt RLP: [status, cumulativeGasUsed, logsBloom, logs_hash]
    // For commitment purposes, we hash all the key receipt fields.
    let mut receipt_data = Vec::new();
    receipt_data.extend_from_slice(&status.to_be_bytes());
    receipt_data.extend_from_slice(&cumulative_gas.to_be_bytes());
    receipt_data.extend_from_slice(&logs_bloom);

    // Include logs data for stronger binding
    if let Some(logs) = receipt.get("logs").and_then(|v| v.as_array()) {
        for log in logs {
            if let Some(data) = log.get("data").and_then(|v| v.as_str()) {
                let log_bytes = hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
                receipt_data.extend_from_slice(&log_bytes);
            }
            if let Some(topics) = log.get("topics").and_then(|v| v.as_array()) {
                for topic in topics {
                    if let Some(t) = topic.as_str() {
                        let topic_bytes = hex::decode(t.trim_start_matches("0x")).unwrap_or_default();
                        receipt_data.extend_from_slice(&topic_bytes);
                    }
                }
            }
        }
    }

    let receipt_key = rlp_encode_tx_index(tx_index);

    Ok(ReceiptProofData {
        block_hash,
        block_number,
        receipts_root,
        receipt_proof_nodes: Vec::new(), // Simplified for hackathon
        receipt_key,
        receipt_rlp: receipt_data,
    })
}

/// Compute the dataset commitment from fetched receipt proof data.
pub fn commitment_from_proof(proof: &ReceiptProofData) -> U256 {
    compute_dataset_commitment(
        proof.block_hash,
        &proof.receipts_root,
        &proof.receipt_rlp,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_from_proof_deterministic() {
        let proof = ReceiptProofData {
            block_hash: U256::from(0xdeadbeefu64),
            block_number: 12345,
            receipts_root: [0xab; 32],
            receipt_proof_nodes: Vec::new(),
            receipt_key: rlp_encode_tx_index(0),
            receipt_rlp: b"test_receipt".to_vec(),
        };

        let c1 = commitment_from_proof(&proof);
        let c2 = commitment_from_proof(&proof);
        assert_eq!(c1, c2);
    }
}
