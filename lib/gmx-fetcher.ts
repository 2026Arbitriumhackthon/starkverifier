/**
 * GMX v2 Trade Data Fetcher
 *
 * Fetches PositionDecrease events from GMX v2 EventEmitter on Arbitrum One
 * via thirdweb's eth_getLogs RPC calls. Decodes ABI-encoded EventLogData
 * to extract trade details and compute return_bps for STARK proving.
 */

import { getRpcClient, eth_getLogs, eth_blockNumber } from "thirdweb/rpc";
import { keccak256 } from "thirdweb/utils";
import { client } from "./client";
import { arbitrumOne } from "./chains";

/** GMX v2 EventEmitter on Arbitrum One */
const GMX_EVENT_EMITTER = "0xC8ee91A54287DB53897056e12D9819156D3822Fb";

/** Block chunk size for getLogs queries (Arbitrum RPC limits) */
const BLOCK_CHUNK = BigInt(100_000);

/** ~30 days of Arbitrum blocks (~250ms block time) */
const DEFAULT_LOOKBACK_BLOCKS = BigInt(10_000_000);

// Pre-computed event topic hashes
// EventLog1(address,string,string,(((...))) — complex nested EventLogData)
// We compute the topic0 at runtime since the full signature is long.
const EVENT_LOG1_TOPIC = keccak256(
  new TextEncoder().encode(
    "EventLog1(address,string,string,(((string,address)[],(string,address[])[]),((string,uint256)[],(string,uint256[])[]),((string,int256)[],(string,int256[])[]),((string,bool)[],(string,bool[])[]),((string,bytes32)[],(string,bytes32[])[]),((string,bytes)[],(string,bytes[])[]),((string,string)[],(string,string[])[])))"
  )
);

const EVENT_LOG2_TOPIC = keccak256(
  new TextEncoder().encode(
    "EventLog2(address,string,string,(((string,address)[],(string,address[])[]),((string,uint256)[],(string,uint256[])[]),((string,int256)[],(string,int256[])[]),((string,bool)[],(string,bool[])[]),((string,bytes32)[],(string,bytes32[])[]),((string,bytes)[],(string,bytes[])[]),((string,string)[],(string,string[])[])))"
  )
);

const POSITION_DECREASE_TOPIC = keccak256(
  new TextEncoder().encode("PositionDecrease")
);

export interface GmxTradeResult {
  txHash: string;
  blockNumber: bigint;
  sizeDeltaUsd: bigint;
  basePnlUsd: bigint;
  isLong: boolean;
  returnBps: number;
}

export interface GmxFetchProgress {
  phase: "starting" | "fetching" | "decoding" | "done";
  detail: string;
  blocksProcessed: number;
  totalBlocks: number;
  tradesFound: number;
}

/**
 * Fetch GMX PositionDecrease trades for a wallet address.
 */
export async function fetchGmxTrades(
  walletAddress: string,
  onProgress?: (progress: GmxFetchProgress) => void
): Promise<GmxTradeResult[]> {
  const rpc = getRpcClient({ client, chain: arbitrumOne });

  onProgress?.({
    phase: "starting",
    detail: "Getting current block number...",
    blocksProcessed: 0,
    totalBlocks: 0,
    tradesFound: 0,
  });

  const currentBlock = await eth_blockNumber(rpc);
  const fromBlock = currentBlock - DEFAULT_LOOKBACK_BLOCKS;
  const totalBlocks = Number(currentBlock - fromBlock);

  // Normalize wallet address for topic matching
  const walletClean = walletAddress.toLowerCase().replace("0x", "");
  const walletTopic = `0x000000000000000000000000${walletClean}` as `0x${string}`;

  const trades: GmxTradeResult[] = [];
  let currentFrom = fromBlock;

  while (currentFrom <= currentBlock) {
    const currentTo =
      currentFrom + BLOCK_CHUNK - BigInt(1) > currentBlock
        ? currentBlock
        : currentFrom + BLOCK_CHUNK - BigInt(1);

    const blocksProcessed = Number(currentFrom - fromBlock);
    onProgress?.({
      phase: "fetching",
      detail: `Scanning blocks ${currentFrom}—${currentTo}...`,
      blocksProcessed,
      totalBlocks,
      tradesFound: trades.length,
    });

    // Fetch EventLog2 logs (has account in topic2)
    try {
      const logs = await eth_getLogs(rpc, {
        address: GMX_EVENT_EMITTER,
        fromBlock: currentFrom,
        toBlock: currentTo,
        topics: [
          EVENT_LOG2_TOPIC as `0x${string}`,
          POSITION_DECREASE_TOPIC as `0x${string}`,
          walletTopic,
        ],
      });

      for (const log of logs) {
        const trade = decodeEventLog(log);
        if (trade) {
          trades.push(trade);
        }
      }
    } catch {
      // Rate limit or other error — continue with next chunk
    }

    // Also try EventLog1 (account in data, not topic)
    try {
      const logs1 = await eth_getLogs(rpc, {
        address: GMX_EVENT_EMITTER,
        fromBlock: currentFrom,
        toBlock: currentTo,
        topics: [
          EVENT_LOG1_TOPIC as `0x${string}`,
          POSITION_DECREASE_TOPIC as `0x${string}`,
        ],
      });

      for (const log of logs1) {
        // Filter by wallet in data (first 32 bytes = msgSender padded)
        if (log.data.toLowerCase().includes(walletClean)) {
          const trade = decodeEventLog(log);
          if (trade) {
            // Avoid duplicates from EventLog2
            if (!trades.some((t) => t.txHash === trade.txHash)) {
              trades.push(trade);
            }
          }
        }
      }
    } catch {
      // Continue with next chunk
    }

    currentFrom = currentTo + BigInt(1);

    // Brief delay to avoid rate limiting
    if (currentFrom <= currentBlock) {
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  // Sort by block number
  trades.sort((a, b) => Number(a.blockNumber - b.blockNumber));

  onProgress?.({
    phase: "done",
    detail: `Found ${trades.length} trades`,
    blocksProcessed: totalBlocks,
    totalBlocks,
    tradesFound: trades.length,
  });

  return trades;
}

/**
 * Decode EventLog1/EventLog2 log entry into trade data.
 * Extracts sizeDeltaUsd, basePnlUsd, isLong from ABI-encoded EventLogData.
 */
function decodeEventLog(log: {
  data: `0x${string}`;
  blockNumber: bigint | null;
  transactionHash: `0x${string}` | null;
}): GmxTradeResult | null {
  try {
    const data = hexToBytes(log.data);

    // ABI layout: (address msgSender, string eventName, string eventNameHash, EventLogData)
    // address: 32 bytes padded
    // offset to string1: 32 bytes
    // offset to string2: 32 bytes
    // offset to EventLogData: 32 bytes
    if (data.length < 128) return null;

    // Read offset to EventLogData (4th param, bytes 96..128)
    const eventDataOffset = bytesToBigInt(data.slice(96, 128));
    const offset = Number(eventDataOffset);
    if (offset >= data.length) return null;

    const eventData = data.slice(offset);
    const parsed = parseEventLogData(eventData);
    if (!parsed) return null;

    const { sizeDeltaUsd, basePnlUsd, isLong } = parsed;

    if (sizeDeltaUsd === BigInt(0)) return null;

    const returnBps = Number((basePnlUsd * BigInt(10000)) / sizeDeltaUsd);

    return {
      txHash: log.transactionHash ?? "0x",
      blockNumber: log.blockNumber ?? BigInt(0),
      sizeDeltaUsd,
      basePnlUsd,
      isLong,
      returnBps,
    };
  } catch {
    return null;
  }
}

/**
 * Parse ABI-encoded EventLogData to extract key fields.
 * The EventLogData has 7 nested item structs, each with items[] and arrayItems[].
 * We need: uintItems.items["sizeDeltaUsd"], intItems.items["basePnlUsd"], boolItems.items["isLong"].
 */
function parseEventLogData(
  data: Uint8Array
): { sizeDeltaUsd: bigint; basePnlUsd: bigint; isLong: boolean } | null {
  try {
    // EventLogData is a tuple of 7 dynamic components:
    // (AddressItems, UintItems, IntItems, BoolItems, Bytes32Items, BytesItems, StringItems)
    // First 7 * 32 bytes = offsets to each component
    if (data.length < 7 * 32) return null;

    const offsets: number[] = [];
    for (let i = 0; i < 7; i++) {
      offsets.push(Number(bytesToBigInt(data.slice(i * 32, (i + 1) * 32))));
    }

    let sizeDeltaUsd = BigInt(0);
    let basePnlUsd = BigInt(0);
    let isLong = false;

    // Parse UintItems (index 1) for sizeDeltaUsd
    const uintOffset = offsets[1];
    if (uintOffset !== undefined && uintOffset < data.length) {
      const uintData = data.slice(uintOffset);
      const uintItems = parseKeyValueItems(uintData, "uint256");
      for (const item of uintItems) {
        if (item.key === "sizeDeltaUsd") {
          sizeDeltaUsd = item.value as bigint;
        }
      }
    }

    // Parse IntItems (index 2) for basePnlUsd
    const intOffset = offsets[2];
    if (intOffset !== undefined && intOffset < data.length) {
      const intData = data.slice(intOffset);
      const intItems = parseKeyValueItems(intData, "int256");
      for (const item of intItems) {
        if (item.key === "basePnlUsd") {
          basePnlUsd = item.value as bigint;
        }
      }
    }

    // Parse BoolItems (index 3) for isLong
    const boolOffset = offsets[3];
    if (boolOffset !== undefined && boolOffset < data.length) {
      const boolData = data.slice(boolOffset);
      const boolItems = parseKeyValueItems(boolData, "bool");
      for (const item of boolItems) {
        if (item.key === "isLong") {
          isLong = item.value as boolean;
        }
      }
    }

    return { sizeDeltaUsd, basePnlUsd, isLong };
  } catch {
    return null;
  }
}

/**
 * Parse ABI-encoded key-value items from a *Items struct.
 * Each *Items struct has: (KeyValue[] items, ArrayKeyValue[] arrayItems)
 * We only need the items[] array, not arrayItems[].
 */
function parseKeyValueItems(
  data: Uint8Array,
  valueType: "uint256" | "int256" | "bool"
): Array<{ key: string; value: bigint | boolean }> {
  const results: Array<{ key: string; value: bigint | boolean }> = [];

  try {
    // First 2 * 32 bytes = offsets to items[] and arrayItems[]
    if (data.length < 64) return results;

    const itemsOffset = Number(bytesToBigInt(data.slice(0, 32)));
    if (itemsOffset >= data.length) return results;

    const itemsData = data.slice(itemsOffset);

    // items[] is a dynamic array: first 32 bytes = length
    if (itemsData.length < 32) return results;
    const length = Number(bytesToBigInt(itemsData.slice(0, 32)));

    // Then length * 32 bytes of offsets to each KeyValue struct
    const kvOffsets: number[] = [];
    for (let i = 0; i < length && (i + 1) * 32 + 32 <= itemsData.length; i++) {
      kvOffsets.push(
        Number(bytesToBigInt(itemsData.slice((i + 1) * 32, (i + 2) * 32)))
      );
    }

    for (const kvOffset of kvOffsets) {
      if (kvOffset >= itemsData.length) continue;

      const kvData = itemsData.slice(kvOffset);
      // KeyValue: (string key, <type> value)
      // For fixed types (uint256, int256, bool): offset-to-key (32 bytes), value (32 bytes)
      // For the key string: offset (32 bytes), then at that offset: length + data
      if (kvData.length < 64) continue;

      const keyOffset = Number(bytesToBigInt(kvData.slice(0, 32)));
      const rawValue = kvData.slice(32, 64);

      // Parse the key string
      if (keyOffset >= kvData.length) continue;
      const keyData = kvData.slice(keyOffset);
      if (keyData.length < 32) continue;
      const keyLength = Number(bytesToBigInt(keyData.slice(0, 32)));
      if (keyData.length < 32 + keyLength) continue;
      const key = new TextDecoder().decode(keyData.slice(32, 32 + keyLength));

      // Parse the value
      let value: bigint | boolean;
      if (valueType === "bool") {
        value = bytesToBigInt(rawValue) !== BigInt(0);
      } else if (valueType === "int256") {
        // Signed 256-bit: check high bit
        const unsigned = bytesToBigInt(rawValue);
        const maxPositive = BigInt(
          "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        if (unsigned > maxPositive) {
          // Two's complement: negative
          value = unsigned - (BigInt(1) << BigInt(256));
        } else {
          value = unsigned;
        }
      } else {
        value = bytesToBigInt(rawValue);
      }

      results.push({ key, value });
    }
  } catch {
    // Parsing error, return what we have
  }

  return results;
}

/** Convert fetched trades to Int32Array of return_bps for WASM prover. */
export function tradesToReturnBps(trades: GmxTradeResult[]): Int32Array {
  const arr = new Int32Array(trades.length);
  for (let i = 0; i < trades.length; i++) {
    arr[i] = trades[i]!.returnBps;
  }
  return arr;
}

// ── Utility functions ──────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = "0x";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}
