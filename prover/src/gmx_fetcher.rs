//! GMX v2 Trade Data Fetcher
//!
//! Fetches PositionDecrease events from GMX v2 EventEmitter on Arbitrum
//! via `eth_getLogs` JSON-RPC calls. Parses ABI-encoded EventLogData
//! to extract trade details and compute return_bps for STARK proving.
//!
//! GMX v2 EventEmitter: 0xC8ee91A54287DB53897056e12D9819156D3822Fb (Arbitrum One)

use alloy_primitives::U256;
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

/// GMX v2 EventEmitter contract address on Arbitrum One.
pub const GMX_EVENT_EMITTER: &str = "0xC8ee91A54287DB53897056e12D9819156D3822Fb";

/// Default Arbitrum One public RPC endpoint.
pub const DEFAULT_ARBITRUM_RPC: &str = "https://arb1.arbitrum.io/rpc";

/// Block chunk size for getLogs queries (Arbitrum RPC limits).
const BLOCK_CHUNK: u64 = 100_000;

/// Approximately 30 days of Arbitrum blocks (~250ms block time).
const DEFAULT_LOOKBACK_BLOCKS: u64 = 10_000_000;

// ── ABI Types ──────────────────────────────────────────────

// GMX v2 EventEmitter uses EventLog1 / EventLog2 wrappers.
// We define the sol! types for ABI decoding of the EventLogData struct.
sol! {
    // Individual key-value structs
    struct AddressKeyValue {
        string key;
        address value;
    }

    struct UintKeyValue {
        string key;
        uint256 value;
    }

    struct IntKeyValue {
        string key;
        int256 value;
    }

    struct BoolKeyValue {
        string key;
        bool value;
    }

    struct Bytes32KeyValue {
        string key;
        bytes32 value;
    }

    struct BytesKeyValue {
        string key;
        bytes value;
    }

    struct StringKeyValue {
        string key;
        string value;
    }

    // Array variants
    struct AddressArrayKeyValue {
        string key;
        address[] value;
    }

    struct UintArrayKeyValue {
        string key;
        uint256[] value;
    }

    struct IntArrayKeyValue {
        string key;
        int256[] value;
    }

    struct BoolArrayKeyValue {
        string key;
        bool[] value;
    }

    struct Bytes32ArrayKeyValue {
        string key;
        bytes32[] value;
    }

    struct BytesArrayKeyValue {
        string key;
        bytes[] value;
    }

    struct StringArrayKeyValue {
        string key;
        string[] value;
    }

    // Item containers (items + arrayItems)
    struct AddressItems {
        AddressKeyValue[] items;
        AddressArrayKeyValue[] arrayItems;
    }

    struct UintItems {
        UintKeyValue[] items;
        UintArrayKeyValue[] arrayItems;
    }

    struct IntItems {
        IntKeyValue[] items;
        IntArrayKeyValue[] arrayItems;
    }

    struct BoolItems {
        BoolKeyValue[] items;
        BoolArrayKeyValue[] arrayItems;
    }

    struct Bytes32Items {
        Bytes32KeyValue[] items;
        Bytes32ArrayKeyValue[] arrayItems;
    }

    struct BytesItems {
        BytesKeyValue[] items;
        BytesArrayKeyValue[] arrayItems;
    }

    struct StringItems {
        StringKeyValue[] items;
        StringArrayKeyValue[] arrayItems;
    }

    // Top-level EventLogData
    struct EventLogData {
        AddressItems addressItems;
        UintItems uintItems;
        IntItems intItems;
        BoolItems boolItems;
        Bytes32Items bytes32Items;
        BytesItems bytesItems;
        StringItems stringItems;
    }
}

// ── Result Types ───────────────────────────────────────────

/// A parsed GMX trade result from a PositionDecrease event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxFetchedTrade {
    pub tx_hash: String,
    pub block_number: u64,
    pub size_delta_usd: String,
    pub base_pnl_usd: String,
    pub is_long: bool,
    pub return_bps: i64,
}

/// Result of fetching GMX trades.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxFetchResult {
    pub wallet: String,
    pub trades: Vec<GmxFetchedTrade>,
    pub total_return_bps: i64,
    pub from_block: u64,
    pub to_block: u64,
}

// ── JSON-RPC Types ─────────────────────────────────────────

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: &'static str,
    params: serde_json::Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: serde_json::Value,
}

#[derive(Deserialize)]
struct LogEntry {
    #[serde(rename = "blockNumber")]
    block_number: String,
    data: String,
    #[allow(dead_code)]
    topics: Vec<String>,
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
}

// ── Core Functions ─────────────────────────────────────────

/// Compute keccak256 hash of a string (for event selectors and topic matching).
fn keccak256_str(input: &str) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(input.as_bytes());
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Fetch the current block number from the RPC.
async fn get_block_number(client: &reqwest::Client, rpc_url: &str) -> Result<u64, String> {
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method: "eth_blockNumber",
        params: serde_json::json!([]),
        id: 1,
    };

    let resp: JsonRpcResponse = client
        .post(rpc_url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("RPC request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {e}"))?;

    let hex_str = resp.result.as_str().ok_or("Invalid block number response")?;
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Failed to parse block number: {e}"))
}

/// Fetch logs for a specific block range.
async fn get_logs(
    client: &reqwest::Client,
    rpc_url: &str,
    address: &str,
    topics: &[Option<String>],
    from_block: u64,
    to_block: u64,
) -> Result<Vec<LogEntry>, String> {
    let topics_json: Vec<serde_json::Value> = topics
        .iter()
        .map(|t| match t {
            Some(v) => serde_json::json!(v),
            None => serde_json::Value::Null,
        })
        .collect();

    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method: "eth_getLogs",
        params: serde_json::json!([{
            "address": address,
            "topics": topics_json,
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
        }]),
        id: 1,
    };

    let resp: JsonRpcResponse = client
        .post(rpc_url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("eth_getLogs failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse getLogs response: {e}"))?;

    serde_json::from_value(resp.result)
        .map_err(|e| format!("Failed to parse log entries: {e}"))
}

/// Decode ABI-encoded EventLogData from raw log data hex string.
/// Extracts sizeDeltaUsd, basePnlUsd, and isLong from the nested key-value structure.
fn decode_event_log_data(data_hex: &str) -> Option<(U256, i128, bool)> {
    let data_hex = data_hex.trim_start_matches("0x");
    let data = hex::decode(data_hex).ok()?;

    use alloy_sol_types::SolType;
    let decoded = <EventLogData as SolType>::abi_decode(&data, false).ok()?;

    // Extract from uintItems.items: sizeDeltaUsd
    let mut size_delta_usd = U256::ZERO;
    for item in &decoded.uintItems.items {
        if item.key == "sizeDeltaUsd" {
            size_delta_usd = item.value;
        }
    }

    // Extract from intItems.items: basePnlUsd
    let mut base_pnl_usd: i128 = 0;
    for item in &decoded.intItems.items {
        if item.key == "basePnlUsd" {
            // alloy int256 → i128 (safe for GMX USD values)
            base_pnl_usd = i256_to_i128(item.value);
        }
    }

    // Extract from boolItems.items: isLong
    let mut is_long = false;
    for item in &decoded.boolItems.items {
        if item.key == "isLong" {
            is_long = item.value;
        }
    }

    Some((size_delta_usd, base_pnl_usd, is_long))
}

/// Convert a signed 256-bit integer (two's complement in alloy_primitives::I256 form)
/// to i128. Safe for GMX USD values which are well within i128 range.
fn i256_to_i128(value: alloy_primitives::I256) -> i128 {
    // I256 has as_i128() but may panic for huge values; GMX values fit easily
    let (sign, abs) = value.into_sign_and_abs();
    let abs_u128 = abs.as_limbs()[0] as u128 | ((abs.as_limbs()[1] as u128) << 64);
    match sign {
        alloy_primitives::Sign::Positive => abs_u128 as i128,
        alloy_primitives::Sign::Negative => -(abs_u128 as i128),
    }
}

/// Compute return_bps from basePnlUsd and sizeDeltaUsd.
/// return_bps = (basePnlUsd * 10000) / sizeDeltaUsd
fn compute_return_bps(base_pnl_usd: i128, size_delta_usd: U256) -> i64 {
    if size_delta_usd.is_zero() {
        return 0;
    }

    // Convert size_delta_usd to i128 (safe for typical position sizes)
    let size_i128 = size_delta_usd.as_limbs()[0] as i128
        | ((size_delta_usd.as_limbs()[1] as i128) << 64);

    if size_i128 == 0 {
        return 0;
    }

    let bps = (base_pnl_usd * 10000) / size_i128;
    bps as i64
}

/// Fetch GMX PositionDecrease trades for a wallet address.
///
/// Uses Arbitrum One RPC to query EventEmitter logs with topic filters:
/// - topic0: EventLog1 or EventLog2 function selector
/// - topic1: keccak256("PositionDecrease")
/// - topic2: wallet address (zero-padded to 32 bytes)
pub async fn fetch_gmx_trades(
    wallet: &str,
    rpc_url: Option<&str>,
    from_block: Option<u64>,
    to_block: Option<u64>,
) -> Result<GmxFetchResult, String> {
    let rpc_url = rpc_url.unwrap_or(DEFAULT_ARBITRUM_RPC);
    let client = reqwest::Client::new();

    // Get current block number for defaults
    let current_block = get_block_number(&client, rpc_url).await?;
    let to_block = to_block.unwrap_or(current_block);
    let from_block = from_block.unwrap_or(to_block.saturating_sub(DEFAULT_LOOKBACK_BLOCKS));

    // Event topic hashes
    // EventLog1(address msgSender, string eventName, string eventNameHash, EventLogData eventData)
    let event_log1_selector = format!("0x{}", hex::encode(keccak256_str(
        "EventLog1(address,string,string,(((string,address)[],(string,address[])[]),((string,uint256)[],(string,uint256[])[]),((string,int256)[],(string,int256[])[]),((string,bool)[],(string,bool[])[]),((string,bytes32)[],(string,bytes32[])[]),((string,bytes)[],(string,bytes[])[]),((string,string)[],(string,string[])[])))"
    )));
    let event_log2_selector = format!("0x{}", hex::encode(keccak256_str(
        "EventLog2(address,string,string,(((string,address)[],(string,address[])[]),((string,uint256)[],(string,uint256[])[]),((string,int256)[],(string,int256[])[]),((string,bool)[],(string,bool[])[]),((string,bytes32)[],(string,bytes32[])[]),((string,bytes)[],(string,bytes[])[]),((string,string)[],(string,string[])[])))"
    )));

    let position_decrease_hash = format!("0x{}", hex::encode(keccak256_str("PositionDecrease")));

    // Normalize wallet address to zero-padded 32-byte topic
    let wallet_clean = wallet.trim_start_matches("0x").to_lowercase();
    let wallet_topic = format!("0x000000000000000000000000{}", wallet_clean);

    let mut all_trades = Vec::new();

    // Fetch in chunks
    let mut current_from = from_block;
    while current_from <= to_block {
        let current_to = std::cmp::min(current_from + BLOCK_CHUNK - 1, to_block);

        // Try EventLog1: topic0=EventLog1, topic1=PositionDecrease (no account filter in topic)
        // EventLog1 has: topic0=selector, topic1=eventNameHash, data=(msgSender, eventName, eventData)
        // For EventLog1, the account is in the data, not topics. We fetch all PositionDecrease and filter.
        let logs1 = get_logs(
            &client,
            rpc_url,
            GMX_EVENT_EMITTER,
            &[
                Some(event_log1_selector.clone()),
                Some(position_decrease_hash.clone()),
            ],
            current_from,
            current_to,
        )
        .await
        .unwrap_or_default();

        // EventLog2: topic0=selector, topic1=eventNameHash, topic2=account
        let logs2 = get_logs(
            &client,
            rpc_url,
            GMX_EVENT_EMITTER,
            &[
                Some(event_log2_selector.clone()),
                Some(position_decrease_hash.clone()),
                Some(wallet_topic.clone()),
            ],
            current_from,
            current_to,
        )
        .await
        .unwrap_or_default();

        // Process EventLog1 logs (filter by account in data)
        for log in &logs1 {
            // EventLog1 data starts with: msgSender (address, padded) + offsets...
            // Check if wallet address appears at the start of data (first 32 bytes = msgSender padded)
            let data_lower = log.data.to_lowercase();
            if !data_lower.contains(&wallet_clean) {
                continue;
            }

            if let Some(trade) = parse_log_entry(log) {
                all_trades.push(trade);
            }
        }

        // Process EventLog2 logs (already filtered by topic2=account)
        for log in &logs2 {
            if let Some(trade) = parse_log_entry(log) {
                all_trades.push(trade);
            }
        }

        current_from = current_to + 1;

        // Brief delay to avoid rate limiting
        if current_from <= to_block {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // Sort by block number
    all_trades.sort_by_key(|t| t.block_number);

    let total_return_bps: i64 = all_trades.iter().map(|t| t.return_bps).sum();

    Ok(GmxFetchResult {
        wallet: wallet.to_string(),
        trades: all_trades,
        total_return_bps,
        from_block,
        to_block,
    })
}

/// Parse a single log entry into a GmxFetchedTrade.
fn parse_log_entry(log: &LogEntry) -> Option<GmxFetchedTrade> {
    let block_number = u64::from_str_radix(
        log.block_number.trim_start_matches("0x"),
        16,
    )
    .ok()?;

    // The EventLog1/EventLog2 data contains:
    // - For EventLog1: msgSender (address padded to 32 bytes), then dynamic offsets for eventName, eventNameHash, eventData
    // - For EventLog2: same structure
    // The EventLogData is the last dynamic parameter.

    // We need to find the EventLogData within the data.
    // The data layout for EventLog1:
    // offset 0: offset to msgSender (or inline) — actually: address msgSender, string eventName, string eventNameHash, EventLogData eventData
    // ABI encoding for (address, string, string, tuple): address is inline, strings and tuple are dynamic.

    // Skip the first 32 bytes (msgSender padded) and parse dynamic offsets
    let data_hex = log.data.trim_start_matches("0x");
    let data = hex::decode(data_hex).ok()?;

    // The ABI encoding: (address, string, string, EventLogData)
    // address: 32 bytes (padded)
    // offset to string1: 32 bytes
    // offset to string2: 32 bytes
    // offset to EventLogData: 32 bytes
    // Then the dynamic data follows.

    if data.len() < 128 {
        return None;
    }

    // Read the offset to EventLogData (4th parameter, bytes 96..128)
    let event_data_offset = U256::from_be_slice(&data[96..128]);
    let offset = event_data_offset.as_limbs()[0] as usize;

    if offset >= data.len() {
        return None;
    }

    let event_data_bytes = &data[offset..];
    let (size_delta_usd, base_pnl_usd, is_long) =
        decode_event_log_data(&format!("0x{}", hex::encode(event_data_bytes)))?;

    if size_delta_usd.is_zero() {
        return None; // Skip zero-size events
    }

    let return_bps = compute_return_bps(base_pnl_usd, size_delta_usd);

    Some(GmxFetchedTrade {
        tx_hash: log.transaction_hash.clone(),
        block_number,
        size_delta_usd: format!("{}", size_delta_usd),
        base_pnl_usd: format!("{}", base_pnl_usd),
        is_long,
        return_bps,
    })
}

/// Convert fetched trades to return_bps vector for STARK proving.
pub fn trades_to_returns_bps(trades: &[GmxFetchedTrade]) -> Vec<i64> {
    trades.iter().map(|t| t.return_bps).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_return_bps() {
        // +500 PnL on 10000 size = 500 bps (precision-agnostic: ratio is the same)
        let pnl: i128 = 500;
        let size = U256::from(10_000u64);
        let bps = compute_return_bps(pnl, size);
        assert_eq!(bps, 500);
    }

    #[test]
    fn test_compute_return_bps_negative() {
        // -200 PnL on 10000 size = -200 bps
        let pnl: i128 = -200;
        let size = U256::from(10_000u64);
        let bps = compute_return_bps(pnl, size);
        assert_eq!(bps, -200);
    }

    #[test]
    fn test_compute_return_bps_zero_size() {
        let bps = compute_return_bps(100, U256::ZERO);
        assert_eq!(bps, 0);
    }

    #[test]
    fn test_keccak256_str() {
        // Known keccak256 of "PositionDecrease"
        let hash = keccak256_str("PositionDecrease");
        let hash_hex = hex::encode(hash);
        // Just verify it's a valid 32-byte hash
        assert_eq!(hash_hex.len(), 64);
    }

    #[test]
    fn test_i256_to_i128_positive() {
        let val = alloy_primitives::I256::try_from(12345i64).unwrap();
        assert_eq!(i256_to_i128(val), 12345i128);
    }

    #[test]
    fn test_i256_to_i128_negative() {
        let val = alloy_primitives::I256::try_from(-9999i64).unwrap();
        assert_eq!(i256_to_i128(val), -9999i128);
    }

    #[test]
    fn test_trades_to_returns_bps() {
        let trades = vec![
            GmxFetchedTrade {
                tx_hash: "0x1".into(),
                block_number: 100,
                size_delta_usd: "1000".into(),
                base_pnl_usd: "50".into(),
                is_long: true,
                return_bps: 500,
            },
            GmxFetchedTrade {
                tx_hash: "0x2".into(),
                block_number: 200,
                size_delta_usd: "2000".into(),
                base_pnl_usd: "-100".into(),
                is_long: false,
                return_bps: -200,
            },
        ];
        let bps = trades_to_returns_bps(&trades);
        assert_eq!(bps, vec![500, -200]);
    }
}
