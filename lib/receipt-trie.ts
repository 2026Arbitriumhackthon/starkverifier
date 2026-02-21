/**
 * Merkle Patricia Trie — Receipt Trie Builder & Proof Generator
 *
 * Builds an Ethereum receipt trie from a block's receipts and generates
 * MPT inclusion proofs for individual receipts.
 *
 * Trie key: RLP(txIndex)
 * Trie value: RLP-encoded receipt (with type prefix for typed transactions)
 *
 * Uses the same Keccak256 implementation from receipt-proof.ts.
 */

import { rlpEncode, rlpEncodeTxIndex, rlpEncodeReceipt, type RLPInput } from "./rlp";
import { keccak_256 } from "@noble/hashes/sha3.js";

function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

// Runtime keccak verification — log once to confirm noble is loaded
let _keccakVerified = false;
function verifyKeccakOnce() {
  if (_keccakVerified) return;
  _keccakVerified = true;
  const testHash = keccak256(new Uint8Array(0));
  const hex = Array.from(testHash).map(b => b.toString(16).padStart(2, "0")).join("");
  const ok = hex.startsWith("c5d24601");
  console.log(`[ReceiptTrie] keccak256 verification: ${ok ? "CORRECT" : "WRONG"} (noble/hashes) hash=${hex.slice(0, 16)}...`);
}

// ── MPT Node Types ───────────────────────────────────────

function bytesToNibbles(data: Uint8Array): number[] {
  const nibbles: number[] = [];
  for (const byte of data) {
    nibbles.push(byte >> 4);
    nibbles.push(byte & 0x0f);
  }
  return nibbles;
}

/**
 * Encode nibbles with hex prefix (HP encoding) for MPT leaf/extension nodes.
 * - Leaf, even length: prefix nibble = 0x20
 * - Leaf, odd length:  prefix nibble = 0x3 + first nibble
 * - Extension, even:   prefix nibble = 0x00
 * - Extension, odd:    prefix nibble = 0x1 + first nibble
 */
function encodeHPPrefix(nibbles: number[], isLeaf: boolean): Uint8Array {
  const flag = isLeaf ? 2 : 0;
  const isOdd = nibbles.length % 2 === 1;

  if (isOdd) {
    const bytes = new Uint8Array(Math.ceil((nibbles.length + 1) / 2));
    bytes[0] = ((flag + 1) << 4) | nibbles[0];
    for (let i = 1; i < nibbles.length; i += 2) {
      bytes[(i + 1) / 2] = (nibbles[i] << 4) | (nibbles[i + 1] ?? 0);
    }
    return bytes;
  }

  const bytes = new Uint8Array(1 + nibbles.length / 2);
  bytes[0] = flag << 4;
  for (let i = 0; i < nibbles.length; i += 2) {
    bytes[1 + i / 2] = (nibbles[i] << 4) | nibbles[i + 1];
  }
  return bytes;
}

// ── Trie Node Structures ─────────────────────────────────

interface TrieNode {
  type: "branch" | "leaf" | "extension";
}

interface BranchNode extends TrieNode {
  type: "branch";
  children: (TrieNodeRef | null)[];
  value: Uint8Array | null;
}

interface LeafNode extends TrieNode {
  type: "leaf";
  nibbles: number[];
  value: Uint8Array;
}

interface ExtensionNode extends TrieNode {
  type: "extension";
  nibbles: number[];
  child: TrieNodeRef;
}

type TrieNodeRef = BranchNode | LeafNode | ExtensionNode;

function rlpEncodeNode(node: TrieNodeRef): Uint8Array {
  if (node.type === "leaf") {
    const encoded = encodeHPPrefix(node.nibbles, true);
    return rlpEncode([encoded, node.value]);
  }

  if (node.type === "extension") {
    const encoded = encodeHPPrefix(node.nibbles, false);
    const childRlp = rlpEncodeNode(node.child);
    const childRef = childRlp.length >= 32 ? keccak256(childRlp) : childRlp;
    return rlpEncode([encoded, childRef]);
  }

  // Branch node
  const items: RLPInput = [];
  for (let i = 0; i < 16; i++) {
    const child = node.children[i];
    if (child === null) {
      items.push(new Uint8Array(0));
    } else {
      const childRlp = rlpEncodeNode(child);
      if (childRlp.length >= 32) {
        items.push(keccak256(childRlp));
      } else {
        items.push(childRlp);
      }
    }
  }
  items.push(node.value ?? new Uint8Array(0));
  return rlpEncode(items);
}

// ── MPT Builder ──────────────────────────────────────────

function commonPrefixLength(a: number[], b: number[], aStart: number, bStart: number): number {
  let len = 0;
  while (aStart + len < a.length && bStart + len < b.length && a[aStart + len] === b[bStart + len]) {
    len++;
  }
  return len;
}

function insertIntoNode(
  node: TrieNodeRef | null,
  key: number[],
  keyOffset: number,
  value: Uint8Array,
): TrieNodeRef {
  if (node === null) {
    return { type: "leaf", nibbles: key.slice(keyOffset), value };
  }

  if (node.type === "leaf") {
    const existingKey = node.nibbles;
    const commonLen = commonPrefixLength(existingKey, key, 0, keyOffset);

    if (commonLen === existingKey.length && keyOffset + commonLen === key.length) {
      // Replace value
      return { type: "leaf", nibbles: existingKey, value };
    }

    // Split into branch
    const branch: BranchNode = {
      type: "branch",
      children: new Array(16).fill(null),
      value: null,
    };

    if (commonLen === existingKey.length) {
      branch.value = node.value;
    } else {
      const oldNibble = existingKey[commonLen];
      branch.children[oldNibble] = {
        type: "leaf",
        nibbles: existingKey.slice(commonLen + 1),
        value: node.value,
      };
    }

    if (keyOffset + commonLen === key.length) {
      branch.value = value;
    } else {
      const newNibble = key[keyOffset + commonLen];
      branch.children[newNibble] = {
        type: "leaf",
        nibbles: key.slice(keyOffset + commonLen + 1),
        value,
      };
    }

    if (commonLen > 0) {
      return {
        type: "extension",
        nibbles: existingKey.slice(0, commonLen),
        child: branch,
      };
    }

    return branch;
  }

  if (node.type === "extension") {
    const extNibbles = node.nibbles;
    const commonLen = commonPrefixLength(extNibbles, key, 0, keyOffset);

    if (commonLen === extNibbles.length) {
      // Full match — recurse into child
      const newChild = insertIntoNode(node.child, key, keyOffset + commonLen, value);
      return { type: "extension", nibbles: extNibbles, child: newChild };
    }

    // Partial match — split the extension
    const branch: BranchNode = {
      type: "branch",
      children: new Array(16).fill(null),
      value: null,
    };

    // Remaining extension after common prefix
    const extNibble = extNibbles[commonLen];
    if (commonLen + 1 < extNibbles.length) {
      branch.children[extNibble] = {
        type: "extension",
        nibbles: extNibbles.slice(commonLen + 1),
        child: node.child,
      };
    } else {
      branch.children[extNibble] = node.child;
    }

    // New key
    if (keyOffset + commonLen === key.length) {
      branch.value = value;
    } else {
      const newNibble = key[keyOffset + commonLen];
      branch.children[newNibble] = {
        type: "leaf",
        nibbles: key.slice(keyOffset + commonLen + 1),
        value,
      };
    }

    if (commonLen > 0) {
      return {
        type: "extension",
        nibbles: extNibbles.slice(0, commonLen),
        child: branch,
      };
    }

    return branch;
  }

  // Branch node
  if (keyOffset >= key.length) {
    return { ...node, value };
  }

  const nibble = key[keyOffset];
  const newChildren = [...node.children];
  newChildren[nibble] = insertIntoNode(node.children[nibble], key, keyOffset + 1, value);
  return { type: "branch", children: newChildren, value: node.value };
}

/**
 * Collect MPT proof nodes for a given key from root to leaf.
 */
function collectProof(
  node: TrieNodeRef | null,
  key: number[],
  keyOffset: number,
): Uint8Array[] {
  if (node === null) return [];

  const nodeRlp = rlpEncodeNode(node);
  const proof = [nodeRlp];

  if (node.type === "leaf") {
    return proof;
  }

  if (node.type === "extension") {
    const extLen = node.nibbles.length;
    // Verify prefix matches
    for (let i = 0; i < extLen; i++) {
      if (keyOffset + i >= key.length || key[keyOffset + i] !== node.nibbles[i]) {
        return proof;
      }
    }
    return [...proof, ...collectProof(node.child, key, keyOffset + extLen)];
  }

  // Branch node
  if (keyOffset >= key.length) {
    return proof;
  }

  const nibble = key[keyOffset];
  const child = node.children[nibble];
  if (child === null) return proof;

  return [...proof, ...collectProof(child, key, keyOffset + 1)];
}

// ── Public API ───────────────────────────────────────────

export interface ReceiptTrieProof {
  /** RLP-encoded proof nodes from root to leaf */
  proofNodes: Uint8Array[];
  /** The trie root hash */
  root: Uint8Array;
  /** RLP-encoded key (transaction index) */
  key: Uint8Array;
  /** The receipt value at the leaf */
  value: Uint8Array;
}

/**
 * Build a receipt trie from raw pre-encoded receipt bytes and generate a proof.
 *
 * This is the preferred method — when raw receipt bytes come from `debug_getRawReceipts`,
 * they are exactly what go-ethereum used to build the trie, so the root hash will match.
 *
 * @param rawReceipts - Array of pre-encoded receipt bytes (from debug_getRawReceipts)
 * @param targetTxIndex - Transaction index to prove
 * @returns MPT proof data
 */
export function buildReceiptTrieFromRawBytes(
  rawReceipts: Uint8Array[],
  targetTxIndex: number,
): ReceiptTrieProof {
  verifyKeccakOnce();
  let root: TrieNodeRef | null = null;

  for (let i = 0; i < rawReceipts.length; i++) {
    const key = rlpEncodeTxIndex(i);
    const keyNibbles = bytesToNibbles(key);
    root = insertIntoNode(root, keyNibbles, 0, rawReceipts[i]);
  }

  if (root === null) {
    throw new Error("Empty trie — no receipts");
  }

  const rootRlp = rlpEncodeNode(root);
  const rootHash = keccak256(rootRlp);

  const targetKey = rlpEncodeTxIndex(targetTxIndex);
  const targetKeyNibbles = bytesToNibbles(targetKey);
  const proofNodes = collectProof(root, targetKeyNibbles, 0);

  return {
    proofNodes,
    root: rootHash,
    key: targetKey,
    value: rawReceipts[targetTxIndex],
  };
}

/**
 * Build a receipt trie and generate a proof for a specific transaction index.
 * Fallback method: encodes receipts from RPC JSON objects.
 *
 * @param receipts - Array of raw RPC receipt objects for the entire block
 * @param targetTxIndex - Transaction index to prove
 * @returns MPT proof data
 */
export function buildReceiptTrieAndProve(
  receipts: Array<{
    status: string;
    type?: string;
    cumulativeGasUsed: string;
    logsBloom: string;
    logs: Array<{
      address: string;
      topics: string[];
      data: string;
    }>;
  }>,
  targetTxIndex: number,
): ReceiptTrieProof {
  verifyKeccakOnce();
  // Build trie
  let root: TrieNodeRef | null = null;

  const encodedReceipts: Uint8Array[] = [];

  for (let i = 0; i < receipts.length; i++) {
    const key = rlpEncodeTxIndex(i);
    const keyNibbles = bytesToNibbles(key);
    const receiptRlp = rlpEncodeReceipt(receipts[i]);
    encodedReceipts.push(receiptRlp);
    root = insertIntoNode(root, keyNibbles, 0, receiptRlp);
  }

  if (root === null) {
    throw new Error("Empty trie — no receipts");
  }

  // Compute root hash
  const rootRlp = rlpEncodeNode(root);
  const rootHash = keccak256(rootRlp);

  // Generate proof for target tx index
  const targetKey = rlpEncodeTxIndex(targetTxIndex);
  const targetKeyNibbles = bytesToNibbles(targetKey);
  const proofNodes = collectProof(root, targetKeyNibbles, 0);

  return {
    proofNodes,
    root: rootHash,
    key: targetKey,
    value: encodedReceipts[targetTxIndex],
  };
}

/**
 * Verify an MPT proof client-side (sanity check before submitting on-chain).
 *
 * @param root - Expected trie root hash (32 bytes)
 * @param key - RLP-encoded transaction index
 * @param proofNodes - RLP-encoded proof nodes
 * @returns The verified leaf value, or null if proof is invalid
 */
export function verifyMptProof(
  root: Uint8Array,
  key: Uint8Array,
  proofNodes: Uint8Array[],
): Uint8Array | null {
  if (proofNodes.length === 0) return null;

  const keyNibbles = bytesToNibbles(key);
  let keyOffset = 0;
  let expectedHash = root;

  for (const nodeRlp of proofNodes) {
    // Verify node hash
    if (nodeRlp.length >= 32) {
      const nodeHash = keccak256(nodeRlp);
      if (!arraysEqual(nodeHash, expectedHash)) {
        return null;
      }
    }

    // Decode RLP list
    const items = rlpDecodeList(nodeRlp);
    if (items === null) return null;

    if (items.length === 17) {
      // Branch node
      if (keyOffset >= keyNibbles.length) {
        return items[16];
      }
      const nibble = keyNibbles[keyOffset];
      if (nibble >= 16) return null;
      keyOffset++;

      const child = items[nibble];
      if (child.length === 0) return null;
      if (child.length === 32) {
        expectedHash = child;
      } else {
        expectedHash = new Uint8Array(32);
      }
    } else if (items.length === 2) {
      // Leaf or extension node
      const decoded = decodeHPPrefix(items[0]);
      if (decoded === null) return null;
      const [prefixNibbles, isLeaf] = decoded;

      for (const nibble of prefixNibbles) {
        if (keyOffset >= keyNibbles.length || keyNibbles[keyOffset] !== nibble) {
          return null;
        }
        keyOffset++;
      }

      if (isLeaf) {
        if (keyOffset === keyNibbles.length) {
          return items[1];
        }
        return null;
      }

      // Extension
      const child = items[1];
      if (child.length === 32) {
        expectedHash = child;
      } else {
        expectedHash = new Uint8Array(32);
      }
    } else {
      return null;
    }
  }

  return null;
}

// ── Internal verification helpers ────────────────────────

function rlpDecodeList(data: Uint8Array): Uint8Array[] | null {
  if (data.length === 0) return null;

  const result = decodeRlpListInternal(data, 0);
  if (result === null) return null;
  return result[0];
}

function decodeRlpListInternal(data: Uint8Array, offset: number): [Uint8Array[], number] | null {
  if (offset >= data.length) return null;
  const prefix = data[offset];

  let payloadStart: number;
  let payloadEnd: number;

  if (prefix <= 0xf7 && prefix >= 0xc0) {
    const len = prefix - 0xc0;
    payloadStart = offset + 1;
    payloadEnd = payloadStart + len;
  } else if (prefix > 0xf7) {
    const lenOfLen = prefix - 0xf7;
    let len = 0;
    for (let i = 0; i < lenOfLen; i++) {
      len = (len << 8) | data[offset + 1 + i];
    }
    payloadStart = offset + 1 + lenOfLen;
    payloadEnd = payloadStart + len;
  } else {
    return null;
  }

  if (payloadEnd > data.length) return null;

  const items: Uint8Array[] = [];
  let pos = payloadStart;

  while (pos < payloadEnd) {
    const [item, consumed] = decodeRlpItemRaw(data, pos);
    items.push(item);
    pos += consumed;
  }

  return [items, payloadEnd - offset];
}

function decodeRlpItemRaw(data: Uint8Array, offset: number): [Uint8Array, number] {
  const prefix = data[offset];

  if (prefix <= 0x7f) {
    return [new Uint8Array([prefix]), 1];
  }

  if (prefix <= 0xb7) {
    const len = prefix - 0x80;
    return [data.slice(offset + 1, offset + 1 + len), 1 + len];
  }

  if (prefix <= 0xbf) {
    const lenOfLen = prefix - 0xb7;
    let len = 0;
    for (let i = 0; i < lenOfLen; i++) {
      len = (len << 8) | data[offset + 1 + i];
    }
    const start = offset + 1 + lenOfLen;
    return [data.slice(start, start + len), 1 + lenOfLen + len];
  }

  if (prefix <= 0xf7) {
    const len = prefix - 0xc0;
    return [data.slice(offset, offset + 1 + len), 1 + len];
  }

  const lenOfLen = prefix - 0xf7;
  let len = 0;
  for (let i = 0; i < lenOfLen; i++) {
    len = (len << 8) | data[offset + 1 + i];
  }
  return [data.slice(offset, offset + 1 + lenOfLen + len), 1 + lenOfLen + len];
}

function decodeHPPrefix(encoded: Uint8Array): [number[], boolean] | null {
  if (encoded.length === 0) return null;
  const firstNibble = encoded[0] >> 4;
  const isLeaf = firstNibble >= 2;
  const isOdd = (firstNibble & 1) === 1;

  const nibbles: number[] = [];
  if (isOdd) {
    nibbles.push(encoded[0] & 0x0f);
  }
  for (let i = 1; i < encoded.length; i++) {
    nibbles.push(encoded[i] >> 4);
    nibbles.push(encoded[i] & 0x0f);
  }

  return [nibbles, isLeaf];
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
