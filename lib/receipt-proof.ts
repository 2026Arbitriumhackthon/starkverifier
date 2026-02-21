/**
 * Receipt Proof Fetcher
 *
 * Fetches Ethereum transaction receipts and block headers,
 * then computes a dataset_commitment that binds the receipt data
 * to the STARK proof for data provenance verification.
 *
 * dataset_commitment = keccak(blockHash, keccak(receiptsRoot, receiptHash)) mod BN254
 */

const BN254_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

export interface ReceiptProofData {
  blockHash: string;
  blockNumber: number;
  receiptsRoot: string;
  txIndex: number;
  receiptData: Uint8Array;
  datasetCommitment: string;
}

/**
 * Keccak256 hash using the Web Crypto API fallback.
 * Since we need keccak (not SHA), we use a minimal JS implementation.
 */
async function keccak256(data: Uint8Array): Promise<Uint8Array> {
  // Minimal Keccak-256 implementation for browser use
  return keccakHash(data);
}

/**
 * Fetch receipt proof data for a transaction and compute dataset_commitment.
 */
export async function fetchReceiptProof(
  rpcUrl: string,
  txHash: string
): Promise<ReceiptProofData> {
  // Step 1: Get transaction receipt
  const receiptResp = await rpcCall(rpcUrl, "eth_getTransactionReceipt", [
    txHash,
  ]);
  if (!receiptResp) {
    throw new Error(`No receipt found for tx: ${txHash}`);
  }

  const blockNumber = parseInt(receiptResp.blockNumber as string, 16);
  const txIndex = parseInt(receiptResp.transactionIndex as string, 16);

  // Step 2: Get block header
  const blockResp = await rpcCall(rpcUrl, "eth_getBlockByNumber", [
    receiptResp.blockNumber,
    false,
  ]);
  if (!blockResp) {
    throw new Error(`No block found for number: ${blockNumber}`);
  }

  const blockHash = blockResp.hash as string;
  const receiptsRoot = blockResp.receiptsRoot as string;

  // Step 3: Build receipt data for hashing
  const receiptData = buildReceiptData(receiptResp);

  // Step 4: Compute dataset_commitment
  const receiptHash = await keccak256(receiptData);

  // inner = keccak256(receiptsRoot || receiptHash)
  const receiptsRootBytes = hexToBytes(receiptsRoot);
  const innerInput = new Uint8Array(64);
  innerInput.set(padTo32(receiptsRootBytes), 0);
  innerInput.set(receiptHash, 32);
  const inner = await keccak256(innerInput);

  // outer = keccak256(blockHash || inner)
  const blockHashBytes = hexToBytes(blockHash);
  const outerInput = new Uint8Array(64);
  outerInput.set(padTo32(blockHashBytes), 0);
  outerInput.set(inner, 32);
  const outer = await keccak256(outerInput);

  // Reduce mod BN254 prime
  const raw = bytesToBigInt(outer);
  const commitmentBigInt = raw % BN254_PRIME;
  const commitmentHex = "0x" + commitmentBigInt.toString(16).padStart(64, "0");

  return {
    blockHash,
    blockNumber,
    receiptsRoot,
    txIndex,
    receiptData,
    datasetCommitment: commitmentHex,
  };
}

function buildReceiptData(
  receipt: Record<string, unknown>
): Uint8Array {
  const parts: Uint8Array[] = [];

  // Status (8 bytes big-endian)
  const statusHex = (receipt.status as string) || "0x1";
  const status = BigInt(statusHex);
  parts.push(bigIntToBytes(status, 8));

  // Cumulative gas used (8 bytes big-endian)
  const gasHex = (receipt.cumulativeGasUsed as string) || "0x0";
  const gas = BigInt(gasHex);
  parts.push(bigIntToBytes(gas, 8));

  // Logs bloom
  const logsBloomHex = (receipt.logsBloom as string) || "0x";
  if (logsBloomHex.length > 2) {
    parts.push(hexToBytes(logsBloomHex));
  }

  // Logs data and topics
  const logs = (receipt.logs as Array<Record<string, unknown>>) || [];
  for (const log of logs) {
    const data = (log.data as string) || "0x";
    if (data.length > 2) {
      parts.push(hexToBytes(data));
    }
    const topics = (log.topics as string[]) || [];
    for (const topic of topics) {
      if (topic.length > 2) {
        parts.push(hexToBytes(topic));
      }
    }
  }

  // Concatenate all parts
  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = clean.length % 2 === 0 ? clean : "0" + clean;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function padTo32(bytes: Uint8Array): Uint8Array {
  if (bytes.length >= 32) return bytes.slice(0, 32);
  const padded = new Uint8Array(32);
  padded.set(bytes, 32 - bytes.length);
  return padded;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & BigInt(0xff));
    v = v >> BigInt(8);
  }
  return bytes;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = BigInt(0);
  for (const byte of bytes) {
    result = (result << BigInt(8)) | BigInt(byte);
  }
  return result;
}

async function rpcCall(
  url: string,
  method: string,
  params: unknown[]
): Promise<Record<string, unknown> | null> {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method,
      params,
      id: 1,
    }),
  });

  const data = (await resp.json()) as { result: Record<string, unknown> | null };
  return data.result;
}

// ────────────────────────────────────────────────────────
// Minimal Keccak-256 implementation (no external dependencies)
// Based on the Keccak specification (FIPS 202 / SHA-3)
// ────────────────────────────────────────────────────────

const KECCAK_ROUNDS = 24;
const RC = [
  BigInt("0x0000000000000001"), BigInt("0x0000000000008082"),
  BigInt("0x800000000000808A"), BigInt("0x8000000080008000"),
  BigInt("0x000000000000808B"), BigInt("0x0000000080000001"),
  BigInt("0x8000000080008081"), BigInt("0x8000000000008009"),
  BigInt("0x000000000000008A"), BigInt("0x0000000000000088"),
  BigInt("0x0000000080008009"), BigInt("0x000000008000000A"),
  BigInt("0x000000008000808B"), BigInt("0x800000000000008B"),
  BigInt("0x8000000000008089"), BigInt("0x8000000000008003"),
  BigInt("0x8000000000008002"), BigInt("0x8000000000000080"),
  BigInt("0x000000000000800A"), BigInt("0x800000008000000A"),
  BigInt("0x8000000080008081"), BigInt("0x8000000000008080"),
  BigInt("0x0000000080000001"), BigInt("0x8000000080008008"),
];

const ROTATIONS = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

const MASK64 = BigInt("0xFFFFFFFFFFFFFFFF");

function rot64(x: bigint, n: number): bigint {
  n = n % 64;
  if (n === 0) return x;
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

function keccakF1600(state: bigint[]): void {
  for (let round = 0; round < KECCAK_ROUNDS; round++) {
    // Theta
    const c = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    const d = new Array(5);
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rot64(c[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + y * 5] = (state[x + y * 5] ^ d[x]) & MASK64;
      }
    }

    // Rho and Pi
    const b = new Array(25).fill(BigInt(0));
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + ((2 * x + 3 * y) % 5) * 5] = rot64(state[x + y * 5], ROTATIONS[y][x]);
      }
    }

    // Chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const notB = (b[(x + 1) % 5 + y * 5] ^ MASK64) & MASK64;
        state[x + y * 5] = (b[x + y * 5] ^ (notB & b[(x + 2) % 5 + y * 5])) & MASK64;
      }
    }

    // Iota
    state[0] = (state[0] ^ RC[round]) & MASK64;
  }
}

function keccakHash(data: Uint8Array): Uint8Array {
  const rate = 136; // 1088 bits for Keccak-256
  const outputLen = 32;

  // Padding (Keccak padding: 0x01...0x80)
  const padLen = rate - (data.length % rate);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded[data.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  // Initialize state
  const state = new Array(25).fill(BigInt(0));

  // Absorb
  for (let i = 0; i < padded.length; i += rate) {
    for (let j = 0; j < rate / 8; j++) {
      let lane = BigInt(0);
      for (let k = 0; k < 8; k++) {
        lane |= BigInt(padded[i + j * 8 + k]) << BigInt(k * 8);
      }
      state[j] = (state[j] ^ lane) & MASK64;
    }
    keccakF1600(state);
  }

  // Squeeze
  const output = new Uint8Array(outputLen);
  for (let j = 0; j < outputLen / 8; j++) {
    const lane = state[j];
    for (let k = 0; k < 8; k++) {
      output[j * 8 + k] = Number((lane >> BigInt(k * 8)) & BigInt(0xff));
    }
  }

  return output;
}
