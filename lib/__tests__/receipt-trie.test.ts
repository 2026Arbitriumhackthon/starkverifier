import { describe, it, expect } from "vitest";
import {
  buildReceiptTrieAndProve,
  buildReceiptTrieFromRawBytes,
  verifyMptProof,
} from "../receipt-trie";
import { rlpEncodeReceipt } from "../rlp";

function makeReceipt(gasUsed: string, status = "0x1", type = "0x2") {
  return {
    status,
    type,
    cumulativeGasUsed: gasUsed,
    logsBloom: "0x" + "00".repeat(256),
    logs: [] as Array<{ address: string; topics: string[]; data: string }>,
  };
}

describe("buildReceiptTrieAndProve", () => {
  it("builds a trie and produces a valid proof for a single receipt", () => {
    const receipts = [makeReceipt("0x5208")];
    const proof = buildReceiptTrieAndProve(receipts, 0);

    expect(proof.root.length).toBe(32);
    expect(proof.proofNodes.length).toBeGreaterThan(0);
    expect(proof.value.length).toBeGreaterThan(0);

    // Verify client-side
    const verified = verifyMptProof(proof.root, proof.key, proof.proofNodes);
    expect(verified).not.toBeNull();
    expect(verified).toEqual(proof.value);
  });

  it("builds a trie with multiple receipts and proves each", () => {
    const receipts = [
      makeReceipt("0x5208"),
      makeReceipt("0xa410"),
      makeReceipt("0xf618"),
    ];

    for (let i = 0; i < receipts.length; i++) {
      const proof = buildReceiptTrieAndProve(receipts, i);
      const verified = verifyMptProof(proof.root, proof.key, proof.proofNodes);
      expect(verified).not.toBeNull();
      expect(verified).toEqual(proof.value);
    }
  });

  it("produces the same root regardless of which tx is proven", () => {
    const receipts = [
      makeReceipt("0x5208"),
      makeReceipt("0xa410"),
    ];
    const proof0 = buildReceiptTrieAndProve(receipts, 0);
    const proof1 = buildReceiptTrieAndProve(receipts, 1);
    expect(proof0.root).toEqual(proof1.root);
  });

  it("produces deterministic results", () => {
    const receipts = [makeReceipt("0x5208"), makeReceipt("0xa410")];
    const a = buildReceiptTrieAndProve(receipts, 0);
    const b = buildReceiptTrieAndProve(receipts, 0);
    expect(a.root).toEqual(b.root);
    expect(a.value).toEqual(b.value);
  });
});

describe("buildReceiptTrieFromRawBytes", () => {
  it("builds from raw bytes and verifies proof", () => {
    const receipts = [makeReceipt("0x5208"), makeReceipt("0xa410")];
    const rawReceipts = receipts.map((r) => rlpEncodeReceipt(r));

    const proof = buildReceiptTrieFromRawBytes(rawReceipts, 0);
    const verified = verifyMptProof(proof.root, proof.key, proof.proofNodes);
    expect(verified).not.toBeNull();
    expect(verified).toEqual(rawReceipts[0]);
  });

  it("matches buildReceiptTrieAndProve root", () => {
    const receipts = [makeReceipt("0x5208"), makeReceipt("0xa410")];
    const rawReceipts = receipts.map((r) => rlpEncodeReceipt(r));

    const fromRaw = buildReceiptTrieFromRawBytes(rawReceipts, 0);
    const fromJson = buildReceiptTrieAndProve(receipts, 0);
    expect(fromRaw.root).toEqual(fromJson.root);
  });
});

describe("verifyMptProof", () => {
  it("returns null for empty proof nodes", () => {
    expect(verifyMptProof(new Uint8Array(32), new Uint8Array(1), [])).toBeNull();
  });

  it("returns null for tampered root", () => {
    const receipts = [makeReceipt("0x5208")];
    const proof = buildReceiptTrieAndProve(receipts, 0);

    const badRoot = new Uint8Array(32).fill(0xff);
    expect(verifyMptProof(badRoot, proof.key, proof.proofNodes)).toBeNull();
  });
});
