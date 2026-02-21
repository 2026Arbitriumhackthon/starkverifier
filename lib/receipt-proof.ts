/**
 * Receipt Proof Fetcher
 *
 * Fetches Ethereum transaction receipts and block headers,
 * builds an MPT (Merkle Patricia Trie) proof for inclusion,
 * and computes a dataset_commitment that binds the receipt data
 * to the STARK proof for data provenance verification.
 *
 * dataset_commitment = keccak(blockHash, keccak(receiptsRoot, receiptHash)) mod BN254
 */

import { rlpEncodeReceipt } from "./rlp";
import {
  buildReceiptTrieAndProve,
  buildReceiptTrieFromRawBytes,
  verifyMptProof,
} from "./receipt-trie";
import { keccak_256 } from "@noble/hashes/sha3.js";

const BN254_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

export interface ReceiptProofData {
  blockHash: string;
  blockNumber: number;
  receiptsRoot: string;
  txIndex: number;
  receiptRlp: Uint8Array;
  receiptProofNodes: Uint8Array[];
  receiptKey: Uint8Array;
  datasetCommitment: string;
}

/**
 * Keccak256 hash using @noble/hashes (same algorithm as Stylus precompile).
 */
async function keccak256(data: Uint8Array): Promise<Uint8Array> {
  return keccak_256(data);
}

/**
 * Fetch receipt proof data for a transaction, including MPT proof nodes.
 *
 * 1. Fetches the target transaction receipt and block header
 * 2. Fetches all receipts in the block (eth_getBlockReceipts)
 * 3. Builds a receipt trie and generates an MPT proof
 * 4. Verifies the proof client-side (sanity check)
 * 5. Computes dataset_commitment
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

  // Step 3: Build receipt trie and generate MPT proof.
  // Try debug_getRawReceipts first (exact bytes from the node → guaranteed correct root).
  // Fall back to eth_getBlockReceipts + re-encoding if debug method is unavailable.
  let trieProof;

  const rawReceiptsHex = await fetchRawReceipts(rpcUrl, receiptResp.blockNumber as string);

  if (rawReceiptsHex) {
    console.log(`[ReceiptProof] Using debug_getRawReceipts (${rawReceiptsHex.length} receipts)`);
    const rawReceipts = rawReceiptsHex.map((hex: string) => hexToBytes(hex));
    trieProof = buildReceiptTrieFromRawBytes(rawReceipts, txIndex);
  } else {
    console.log("[ReceiptProof] debug_getRawReceipts unavailable, falling back to re-encoding");
    const blockReceipts = await rpcCallArray(rpcUrl, "eth_getBlockReceipts", [
      receiptResp.blockNumber,
    ]);
    if (!blockReceipts || blockReceipts.length === 0) {
      throw new Error(`Failed to fetch block receipts for block ${blockNumber}`);
    }
    const formattedReceipts = blockReceipts.map(formatReceiptForRlp);
    trieProof = buildReceiptTrieAndProve(formattedReceipts, txIndex);
  }

  // Step 5: Client-side sanity check — verify our MPT proof against receiptsRoot
  const expectedRoot = hexToBytes(receiptsRoot);
  const verifiedValue = verifyMptProof(
    expectedRoot,
    trieProof.key,
    trieProof.proofNodes,
  );

  // If client-side verification fails, the trie root may not match on-chain receiptsRoot.
  // Log a warning but don't hard-fail: the on-chain verifier is the final authority.
  if (verifiedValue === null) {
    console.warn(
      "Client-side MPT proof verification returned null. " +
      "Computed root may differ from on-chain receiptsRoot. " +
      `Computed: 0x${bytesToHex(trieProof.root)}, Expected: ${receiptsRoot}`
    );
  }

  // Step 6: RLP-encode the target receipt (standard format)
  const receiptRlp = trieProof.value;

  // Step 7: Compute dataset_commitment
  const receiptHash = await keccak256(receiptRlp);

  const receiptsRootBytes = hexToBytes(receiptsRoot);
  const innerInput = new Uint8Array(64);
  innerInput.set(padTo32(receiptsRootBytes), 0);
  innerInput.set(receiptHash, 32);
  const inner = await keccak256(innerInput);

  const blockHashBytes = hexToBytes(blockHash);
  const outerInput = new Uint8Array(64);
  outerInput.set(padTo32(blockHashBytes), 0);
  outerInput.set(inner, 32);
  const outer = await keccak256(outerInput);

  const raw = bytesToBigInt(outer);
  const commitmentBigInt = raw % BN254_PRIME;
  const commitmentHex = "0x" + commitmentBigInt.toString(16).padStart(64, "0");

  return {
    blockHash,
    blockNumber,
    receiptsRoot,
    txIndex,
    receiptRlp,
    receiptProofNodes: trieProof.proofNodes,
    receiptKey: trieProof.key,
    datasetCommitment: commitmentHex,
  };
}

/**
 * Format a raw RPC receipt into the shape expected by rlpEncodeReceipt.
 */
function formatReceiptForRlp(receipt: Record<string, unknown>): {
  status: string;
  type?: string;
  cumulativeGasUsed: string;
  logsBloom: string;
  logs: Array<{ address: string; topics: string[]; data: string }>;
} {
  return {
    status: (receipt.status as string) || "0x1",
    type: receipt.type as string | undefined,
    cumulativeGasUsed: (receipt.cumulativeGasUsed as string) || "0x0",
    logsBloom: (receipt.logsBloom as string) || "0x",
    logs: ((receipt.logs as Array<Record<string, unknown>>) || []).map((log) => ({
      address: (log.address as string) || "0x",
      topics: (log.topics as string[]) || [],
      data: (log.data as string) || "0x",
    })),
  };
}

/**
 * Encode U256 words for on-chain submission.
 * Packs arbitrary bytes into 32-byte aligned U256 words.
 */
export function encodeToU256Words(data: Uint8Array): bigint[] {
  const words: bigint[] = [];
  for (let i = 0; i < data.length; i += 32) {
    const chunk = data.slice(i, Math.min(i + 32, data.length));
    // Pad to 32 bytes (right-pad with zeros)
    const padded = new Uint8Array(32);
    padded.set(chunk, 0);
    words.push(bytesToBigInt(padded));
  }
  return words;
}

/**
 * Encode MPT proof nodes for on-chain submission.
 *
 * Format: [num_nodes, len_0, len_1, ..., len_{n-1}, packed_data_words...]
 *
 * - num_nodes: number of proof nodes
 * - len_i: byte length of i-th node
 * - packed_data_words: all node bytes concatenated and packed into 32-byte U256 words
 */
export function encodeProofNodes(
  nodes: Uint8Array[]
): { words: bigint[]; totalLen: number } {
  // Header: [num_nodes, len_0, len_1, ...]
  const headerWords: bigint[] = [BigInt(nodes.length)];
  let totalDataLen = 0;
  for (const node of nodes) {
    headerWords.push(BigInt(node.length));
    totalDataLen += node.length;
  }

  // Body: concatenate all node bytes
  const allData = new Uint8Array(totalDataLen);
  let offset = 0;
  for (const node of nodes) {
    allData.set(node, offset);
    offset += node.length;
  }

  // Pack into 32-byte words
  const dataWords = encodeToU256Words(allData);

  return {
    words: [...headerWords, ...dataWords],
    totalLen: totalDataLen,
  };
}

// ── Utility functions ────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = clean.length % 2 === 0 ? clean : "0" + clean;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function padTo32(bytes: Uint8Array): Uint8Array {
  if (bytes.length >= 32) return bytes.slice(0, 32);
  const padded = new Uint8Array(32);
  padded.set(bytes, 32 - bytes.length);
  return padded;
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

/**
 * Try to fetch raw receipt bytes via debug_getRawReceipts.
 * Returns null if the RPC doesn't support this method.
 */
async function fetchRawReceipts(
  url: string,
  blockNumber: string,
): Promise<string[] | null> {
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "debug_getRawReceipts",
        params: [blockNumber],
        id: 1,
      }),
    });

    const data = (await resp.json()) as {
      result?: string[] | null;
      error?: { code: number; message: string };
    };

    if (data.error || !data.result) {
      return null;
    }

    return data.result;
  } catch {
    return null;
  }
}

async function rpcCallArray(
  url: string,
  method: string,
  params: unknown[]
): Promise<Array<Record<string, unknown>> | null> {
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

  const data = (await resp.json()) as {
    result: Array<Record<string, unknown>> | null;
  };
  return data.result;
}

