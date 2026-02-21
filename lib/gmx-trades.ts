/**
 * GMX V2 Trade Fetcher for Arbitrum
 *
 * Queries GMX V2's EventEmitter contract for PositionDecrease events
 * to extract a wallet's trading history for Sharpe ratio computation.
 *
 * GMX V2 EventEmitter topic structure:
 *   EventLog1: topics = [sig, keccak256(eventName), topic1]
 *   EventLog2: topics = [sig, keccak256(eventName), topic1, topic2]
 *
 * For PositionDecrease (EventLog1):
 *   topics[0] = EventLog1 signature hash
 *   topics[1] = keccak256("PositionDecrease")
 *   topics[2] = Cast.toBytes32(account) = padded wallet address
 *
 * Flow: wallet address -> eth_getLogs(EventEmitter, topics[2]=wallet) -> parse events -> return_bps[]
 */

/* ── GMX V2 Contract Addresses ────────────────────── */

const GMX_EVENT_EMITTER: Record<string, string> = {
  "arbitrum-one": "0xC8ee91A54287DB53897056e12D9819156D3822Fb",
};

/**
 * keccak256("PositionDecrease") — indexed eventNameHash for topic filtering.
 * Pre-computed from on-chain data.
 */
const POSITION_DECREASE_HASH =
  "0x07d51b51b408d7c62dcc47cc558da5ce6a6e0fd129a427ebce150f52b0e5171a";

/* ── Types ─────────────────────────────────────────── */

export interface TradeEvent {
  txHash: string;
  blockNumber: number;
  eventName: string;
  returnBps: number;
  sizeDeltaUsd: bigint;
  basePnlUsd: bigint;
}

export interface WalletTradeResult {
  trades: TradeEvent[];
  returnsBps: number[];
  txHashes: string[];
  tradeCount: number;
  totalReturnBps: number;
  /** Total trades found on-chain (before maxTrades limit) */
  totalEventsFound: number;
  fromBlock: number;
  toBlock: number;
}

/* ── Helpers ───────────────────────────────────────── */

async function rpcCall(
  url: string,
  method: string,
  params: unknown[]
): Promise<Record<string, unknown> | unknown[] | string | null> {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: Date.now() }),
  });
  const data = (await resp.json()) as {
    result?: Record<string, unknown> | unknown[] | string | null;
    error?: { message: string };
  };
  if (data.error) throw new Error(`RPC error: ${data.error.message}`);
  return data.result ?? null;
}

function stringToHex(str: string): string {
  let hex = "";
  for (let i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToString(hex: string): string {
  let str = "";
  for (let i = 0; i < hex.length; i += 2) {
    const code = parseInt(hex.slice(i, i + 2), 16);
    if (code === 0) break;
    str += String.fromCharCode(code);
  }
  return str;
}

/**
 * Decode the eventName from GMX EventLog1/EventLog2 data field.
 *
 * ABI layout: abi.encode(address msgSender, string eventName, string eventNameHash, EventLogData)
 * Word 0: msgSender (padded address)
 * Word 1: offset to eventName string
 * Word 2: offset to eventNameHash string
 * Word 3: offset to eventData
 * At eventName offset: [length][string bytes padded]
 */
function decodeEventName(dataHex: string): string {
  if (dataHex.length < 256) return "";
  // Word 1 = offset to eventName (in bytes)
  const eventNameOffset = parseInt(dataHex.slice(64, 128), 16) * 2; // convert to hex chars
  if (eventNameOffset + 128 > dataHex.length) return "";
  const eventNameLen = parseInt(
    dataHex.slice(eventNameOffset, eventNameOffset + 64),
    16
  );
  if (eventNameLen === 0 || eventNameLen > 100) return "";
  const eventNameHex = dataHex.slice(
    eventNameOffset + 64,
    eventNameOffset + 64 + eventNameLen * 2
  );
  return hexToString(eventNameHex);
}

/**
 * Search for a key-value pair in ABI-encoded GMX event data.
 *
 * In ABI encoding of tuple(string key, int256/uint256 value):
 *   offset 0x00: pointer to key string (e.g., 0x40)
 *   offset 0x20: value (int256 or uint256)
 *   offset 0x40: key string length
 *   offset 0x60: key string bytes
 *
 * So the value is always 128 hex chars (2 words) before the key string data.
 */
function findKeyValueInData(dataHex: string, keyName: string): bigint | null {
  const keyHex = stringToHex(keyName);
  let searchFrom = 0;

  while (searchFrom < dataHex.length) {
    const idx = dataHex.indexOf(keyHex, searchFrom);
    if (idx < 0 || idx < 128) break;

    // Verify: the word before the key should be the string length
    const lengthWord = dataHex.slice(idx - 64, idx);
    const strLen = parseInt(lengthWord, 16);

    if (strLen === keyName.length) {
      // Value is 2 words before the length word
      const valueStart = idx - 128;
      const valueHex = dataHex.slice(valueStart, valueStart + 64);
      if (valueHex.length === 64) {
        return BigInt("0x" + valueHex);
      }
    }

    searchFrom = idx + keyHex.length;
  }

  return null;
}

function decodeInt256(value: bigint): bigint {
  const MAX_INT256 = (BigInt(1) << BigInt(255)) - BigInt(1);
  if (value > MAX_INT256) {
    return value - (BigInt(1) << BigInt(256));
  }
  return value;
}

/* ── Main Fetcher ──────────────────────────────────── */

/**
 * Fetch GMX V2 PositionDecrease events for a wallet address.
 *
 * Queries the GMX EventEmitter contract using eth_getLogs with the wallet
 * address as topic1. Parses the event data to extract basePnlUsd and
 * sizeDeltaUsd, then computes return_bps for each closed position.
 *
 * @param rpcUrl - Arbitrum RPC URL
 * @param walletAddress - Trader wallet address (0x...)
 * @param networkId - Network identifier ("arbitrum-one")
 * @param maxTrades - Maximum number of recent trades to use for Sharpe (default 200)
 * @param blocksBack - Number of blocks to search back (default ~90 days, Arbitrum ~0.25s/block)
 */
export async function fetchWalletTrades(
  rpcUrl: string,
  walletAddress: string,
  networkId: string,
  maxTrades: number = 200,
  blocksBack: number = 31_000_000,
): Promise<WalletTradeResult> {
  const emitterAddress = GMX_EVENT_EMITTER[networkId];
  if (!emitterAddress) {
    throw new Error(
      `GMX V2 is not available on ${networkId}. Please select Arbitrum One.`
    );
  }

  // Get latest block number
  const latestHex = (await rpcCall(rpcUrl, "eth_blockNumber", [])) as string;
  const latestBlock = parseInt(latestHex, 16);
  const fromBlock = Math.max(0, latestBlock - blocksBack);

  // Pad wallet address to bytes32 for topic filter
  const paddedWallet =
    "0x" + walletAddress.slice(2).toLowerCase().padStart(64, "0");

  // Query EventEmitter for PositionDecrease events where account = wallet.
  //
  // GMX V2 EventLog1 topic layout:
  //   topics[0] = EventLog1 signature (null to match any event type)
  //   topics[1] = keccak256("PositionDecrease") — filter by event name
  //   topics[2] = Cast.toBytes32(account) — filter by wallet address
  const logs = (await rpcCall(rpcUrl, "eth_getLogs", [
    {
      address: emitterAddress,
      topics: [null, POSITION_DECREASE_HASH, paddedWallet],
      fromBlock: "0x" + fromBlock.toString(16),
      toBlock: "latest",
    },
  ])) as Array<Record<string, string>> | null;

  if (!logs || logs.length === 0) {
    const daysBack = Math.round(blocksBack / 345600); // ~345600 blocks/day on Arbitrum (~0.25s/block)
    throw new Error(
      `No PositionDecrease events found for ${walletAddress.slice(0, 10)}... in the last ~${daysBack} days. ` +
        `Make sure the wallet has closed positions on GMX V2 on Arbitrum One.`
    );
  }

  // Parse each event log — all should be PositionDecrease (pre-filtered by topics)
  const trades: TradeEvent[] = [];

  for (const log of logs) {
    try {
      const dataHex = (log.data as string).slice(2); // remove 0x prefix

      // Extract basePnlUsd (int256) and sizeDeltaUsd (uint256) from event data
      const basePnlRaw = findKeyValueInData(dataHex, "basePnlUsd");
      const sizeDeltaRaw = findKeyValueInData(dataHex, "sizeDeltaUsd");

      if (
        basePnlRaw !== null &&
        sizeDeltaRaw !== null &&
        sizeDeltaRaw > BigInt(0)
      ) {
        const basePnl = decodeInt256(basePnlRaw);
        // return_bps = basePnlUsd * 10000 / sizeDeltaUsd
        const returnBps = Number((basePnl * BigInt(10000)) / sizeDeltaRaw);

        trades.push({
          txHash: log.transactionHash as string,
          blockNumber: parseInt(log.blockNumber as string, 16),
          eventName: "PositionDecrease",
          returnBps,
          sizeDeltaUsd: sizeDeltaRaw,
          basePnlUsd: basePnl,
        });
      }
    } catch {
      // Skip unparseable events
      continue;
    }
  }

  if (trades.length < 2) {
    throw new Error(
      `Found ${trades.length} parseable PositionDecrease event(s) for ${walletAddress.slice(0, 10)}... ` +
        `Need at least 2 trades to compute Sharpe ratio. ` +
        `(Total events from EventEmitter: ${logs.length})`
    );
  }

  // Use only the most recent N trades to keep proof generation fast.
  // STARK trace length = next power of 2 above trade count, so limiting trades
  // keeps the proof small and fast in the browser WASM prover.
  const totalParsed = trades.length;
  const recentTrades = trades.slice(-maxTrades);

  const returnsBps = recentTrades.map((t) => t.returnBps);
  const totalReturnBps = returnsBps.reduce((sum, r) => sum + r, 0);
  const uniqueTxHashes = [...new Set(recentTrades.map((t) => t.txHash))];

  return {
    trades: recentTrades,
    returnsBps,
    txHashes: uniqueTxHashes,
    tradeCount: recentTrades.length,
    totalReturnBps,
    totalEventsFound: totalParsed,
    fromBlock,
    toBlock: latestBlock,
  };
}
