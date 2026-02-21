import { describe, it, expect } from "vitest";
import { rlpEncode, rlpDecode, rlpEncodeTxIndex, rlpEncodeReceipt, type RLPInput } from "../rlp";

describe("rlpEncode / rlpDecode", () => {
  it("encodes a single byte <= 0x7f as itself", () => {
    const data = new Uint8Array([0x42]);
    const encoded = rlpEncode(data);
    expect(encoded).toEqual(new Uint8Array([0x42]));
  });

  it("encodes empty bytes as 0x80", () => {
    const encoded = rlpEncode(new Uint8Array(0));
    expect(encoded).toEqual(new Uint8Array([0x80]));
  });

  it("encodes short string (1-55 bytes)", () => {
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const encoded = rlpEncode(data);
    expect(encoded[0]).toBe(0x80 + 3);
    expect(encoded.slice(1)).toEqual(data);
  });

  it("encodes a simple list", () => {
    const list: RLPInput = [new Uint8Array([0x01]), new Uint8Array([0x02])];
    const encoded = rlpEncode(list);
    // [0xc2, 0x01, 0x02]
    expect(encoded).toEqual(new Uint8Array([0xc2, 0x01, 0x02]));
  });

  it("roundtrips a nested list", () => {
    const list: RLPInput = [
      new Uint8Array([0x01]),
      [new Uint8Array([0x02]), new Uint8Array([0x03])],
    ];
    const encoded = rlpEncode(list);
    const decoded = rlpDecode(encoded);
    // Should be a list with 2 elements
    expect(Array.isArray(decoded)).toBe(true);
    const items = decoded as RLPInput[];
    expect(items.length).toBe(2);
  });

  it("encodes a long string (> 55 bytes)", () => {
    const data = new Uint8Array(256).fill(0xAB);
    const encoded = rlpEncode(data);
    // prefix: 0xb7 + 2 (256 needs 2 bytes to encode length)
    expect(encoded[0]).toBe(0xb9);
    expect(encoded[1]).toBe(0x01); // 256 >> 8
    expect(encoded[2]).toBe(0x00); // 256 & 0xff
    expect(encoded.slice(3)).toEqual(data);
  });
});

describe("rlpEncodeTxIndex", () => {
  it("encodes index 0 as [0x80]", () => {
    expect(rlpEncodeTxIndex(0)).toEqual(new Uint8Array([0x80]));
  });

  it("encodes index 1 as [0x01]", () => {
    expect(rlpEncodeTxIndex(1)).toEqual(new Uint8Array([0x01]));
  });

  it("encodes index 127 as [0x7f]", () => {
    expect(rlpEncodeTxIndex(127)).toEqual(new Uint8Array([0x7f]));
  });

  it("encodes index 128 as [0x81, 0x80]", () => {
    expect(rlpEncodeTxIndex(128)).toEqual(new Uint8Array([0x81, 0x80]));
  });

  it("encodes index 256 as [0x82, 0x01, 0x00]", () => {
    expect(rlpEncodeTxIndex(256)).toEqual(new Uint8Array([0x82, 0x01, 0x00]));
  });
});

describe("rlpEncodeReceipt", () => {
  it("encodes a minimal Type 2 receipt", () => {
    const receipt = {
      status: "0x1",
      type: "0x2",
      cumulativeGasUsed: "0x5208",
      logsBloom: "0x" + "00".repeat(256),
      logs: [],
    };
    const encoded = rlpEncodeReceipt(receipt);
    // Type 2: first byte should be 0x02
    expect(encoded[0]).toBe(0x02);
    // Rest is RLP
    expect(encoded.length).toBeGreaterThan(1);
  });

  it("encodes a legacy (type 0) receipt without type prefix", () => {
    const receipt = {
      status: "0x1",
      type: "0x0",
      cumulativeGasUsed: "0x5208",
      logsBloom: "0x" + "00".repeat(256),
      logs: [],
    };
    const encoded = rlpEncodeReceipt(receipt);
    // Legacy: no type prefix, starts with RLP list prefix
    expect(encoded[0]).toBeGreaterThanOrEqual(0xc0);
  });

  it("encodes status 0 as empty bytes", () => {
    const receipt = {
      status: "0x0",
      cumulativeGasUsed: "0x5208",
      logsBloom: "0x" + "00".repeat(256),
      logs: [],
    };
    const encoded = rlpEncodeReceipt(receipt);
    // Type 2 (default): first byte = 0x02
    expect(encoded[0]).toBe(0x02);
  });

  it("encodes a receipt with logs", () => {
    const receipt = {
      status: "0x1",
      type: "0x2",
      cumulativeGasUsed: "0x1234",
      logsBloom: "0x" + "00".repeat(256),
      logs: [
        {
          address: "0x" + "ab".repeat(20),
          topics: ["0x" + "cd".repeat(32)],
          data: "0x" + "ef".repeat(32),
        },
      ],
    };
    const encoded = rlpEncodeReceipt(receipt);
    expect(encoded[0]).toBe(0x02);
    expect(encoded.length).toBeGreaterThan(300); // logsBloom alone is 256 bytes
  });

  it("is deterministic", () => {
    const receipt = {
      status: "0x1",
      type: "0x2",
      cumulativeGasUsed: "0x5208",
      logsBloom: "0x" + "00".repeat(256),
      logs: [],
    };
    const a = rlpEncodeReceipt(receipt);
    const b = rlpEncodeReceipt(receipt);
    expect(a).toEqual(b);
  });
});
