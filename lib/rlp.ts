/**
 * RLP (Recursive Length Prefix) Encoding/Decoding
 *
 * Implements the Ethereum RLP serialization standard per the Yellow Paper.
 * Used for encoding transaction receipts and MPT trie keys.
 *
 * Encoding rules:
 * - Single byte [0x00, 0x7f]: itself
 * - String 0-55 bytes: 0x80 + len, then data
 * - String >55 bytes: 0xb7 + len_of_len, then length, then data
 * - List 0-55 bytes payload: 0xc0 + len, then payload
 * - List >55 bytes payload: 0xf7 + len_of_len, then length, then payload
 */

export type RLPInput = Uint8Array | RLPInput[];

/**
 * RLP-encode a value (byte string or nested list).
 */
export function rlpEncode(input: RLPInput): Uint8Array {
  if (input instanceof Uint8Array) {
    return encodeBytes(input);
  }
  // List
  const encodedItems = input.map((item) => rlpEncode(item));
  const payload = concatBytes(encodedItems);
  return concatBytes([encodeLength(payload.length, 0xc0), payload]);
}

/**
 * RLP-decode a byte string into its components.
 * Returns the decoded RLPInput and the number of bytes consumed.
 */
export function rlpDecode(data: Uint8Array): RLPInput {
  const [result] = decodeItem(data, 0);
  return result;
}

/**
 * RLP-encode a transaction index as a trie key.
 * Matches the Rust prover's rlp_encode_tx_index().
 */
export function rlpEncodeTxIndex(index: number): Uint8Array {
  if (index === 0) {
    return new Uint8Array([0x80]); // RLP encoding of empty string (zero)
  }
  const bytes = bigIntToMinBytes(BigInt(index));
  if (bytes.length === 1 && bytes[0] <= 0x7f) {
    return bytes;
  }
  const result = new Uint8Array(1 + bytes.length);
  result[0] = 0x80 + bytes.length;
  result.set(bytes, 1);
  return result;
}

/**
 * RLP-encode an Ethereum transaction receipt (Type 2 / EIP-1559).
 *
 * Produces: 0x02 || rlp([status, cumulativeGasUsed, logsBloom, logs])
 * where logs = [rlp([address, topics[], data]), ...]
 */
export function rlpEncodeReceipt(receipt: {
  status: string;
  type?: string;
  cumulativeGasUsed: string;
  logsBloom: string;
  logs: Array<{
    address: string;
    topics: string[];
    data: string;
  }>;
}): Uint8Array {
  // Status: 0 → empty bytes (RLP encodes as 0x80), 1 → [0x01]
  // go-ethereum: statusEncoding() returns []byte{} for 0, []byte{0x01} for 1
  const statusInt = parseInt(receipt.status, 16);
  const status = statusInt === 0 ? new Uint8Array(0) : bigIntToMinBytes(BigInt(statusInt));
  const cumulativeGas = bigIntToMinBytes(BigInt(receipt.cumulativeGasUsed));
  const logsBloom = hexToBytes(receipt.logsBloom);

  const encodedLogs: RLPInput = receipt.logs.map((log) => [
    hexToBytes(log.address),
    log.topics.map((t) => hexToBytes(t)),
    hexToBytes(log.data),
  ]);

  const receiptBody = rlpEncode([status, cumulativeGas, logsBloom, encodedLogs]);

  // Determine receipt type
  const txType = receipt.type ? parseInt(receipt.type, 16) : 2;

  if (txType === 0) {
    // Legacy receipt: just RLP
    return receiptBody;
  }

  // Typed receipt: type_byte || rlp(...)
  const result = new Uint8Array(1 + receiptBody.length);
  result[0] = txType;
  result.set(receiptBody, 1);
  return result;
}

// ── Internal helpers ──────────────────────────────────────

function encodeBytes(data: Uint8Array): Uint8Array {
  if (data.length === 1 && data[0] <= 0x7f) {
    return data;
  }
  return concatBytes([encodeLength(data.length, 0x80), data]);
}

function encodeLength(len: number, offset: number): Uint8Array {
  if (len <= 55) {
    return new Uint8Array([offset + len]);
  }
  const lenBytes = bigIntToMinBytes(BigInt(len));
  const result = new Uint8Array(1 + lenBytes.length);
  result[0] = offset + 55 + lenBytes.length;
  result.set(lenBytes, 1);
  return result;
}

function decodeItem(data: Uint8Array, offset: number): [RLPInput, number] {
  if (offset >= data.length) {
    throw new Error("RLP: unexpected end of data");
  }

  const prefix = data[offset];

  if (prefix <= 0x7f) {
    // Single byte
    return [new Uint8Array([prefix]), offset + 1];
  }

  if (prefix <= 0xb7) {
    // Short string (0-55 bytes)
    const len = prefix - 0x80;
    const end = offset + 1 + len;
    if (end > data.length) throw new Error("RLP: string exceeds data");
    return [data.slice(offset + 1, end), end];
  }

  if (prefix <= 0xbf) {
    // Long string
    const lenOfLen = prefix - 0xb7;
    let len = 0;
    for (let i = 0; i < lenOfLen; i++) {
      len = (len << 8) | data[offset + 1 + i];
    }
    const start = offset + 1 + lenOfLen;
    const end = start + len;
    if (end > data.length) throw new Error("RLP: long string exceeds data");
    return [data.slice(start, end), end];
  }

  if (prefix <= 0xf7) {
    // Short list (0-55 bytes payload)
    const len = prefix - 0xc0;
    const payloadEnd = offset + 1 + len;
    const items: RLPInput[] = [];
    let pos = offset + 1;
    while (pos < payloadEnd) {
      const [item, newPos] = decodeItem(data, pos);
      items.push(item);
      pos = newPos;
    }
    return [items, payloadEnd];
  }

  // Long list
  const lenOfLen = prefix - 0xf7;
  let len = 0;
  for (let i = 0; i < lenOfLen; i++) {
    len = (len << 8) | data[offset + 1 + i];
  }
  const payloadStart = offset + 1 + lenOfLen;
  const payloadEnd = payloadStart + len;
  const items: RLPInput[] = [];
  let pos = payloadStart;
  while (pos < payloadEnd) {
    const [item, newPos] = decodeItem(data, pos);
    items.push(item);
    pos = newPos;
  }
  return [items, payloadEnd];
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length === 0) return new Uint8Array(0);
  const padded = clean.length % 2 === 0 ? clean : "0" + clean;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bigIntToMinBytes(value: bigint): Uint8Array {
  if (value === BigInt(0)) return new Uint8Array(0);
  const hex = value.toString(16);
  const padded = hex.length % 2 === 0 ? hex : "0" + hex;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function concatBytes(arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
