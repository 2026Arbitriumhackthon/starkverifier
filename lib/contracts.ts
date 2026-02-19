import { getContract } from "thirdweb";
import { client } from "./client";
import { arbitrumSepolia } from "./chains";

/**
 * Contract addresses on Arbitrum Sepolia
 */

// STARK Verifier v4 (Keccak + BTC Lock + Sharpe ratio, Stylus)
export const STARK_VERIFIER_V4_ADDRESS =
  "0x4709cc3862280597855a6986b13f1f1ccb309ff9" as const;

// STARK Verifier v1 (Poseidon, legacy)
export const STARK_VERIFIER_ADDRESS =
  "0x572318f371e654d8f3b18209b9b6ae766326ef46" as const;

// Poseidon/Merkle benchmark contract (old, poseidon+merkle only)
export const STYLUS_VERIFIER_ADDRESS =
  "0x327c65e04215bd5575d60b00ba250ed5dd25a4fc" as const;

export const SOLIDITY_VERIFIER_ADDRESS =
  "0x96326E368b6f2fdA258452ac42B1aC013238f5Ce" as const;

/**
 * Verifier contract ABI (Poseidon/Merkle benchmark)
 * Shared interface for both Stylus and Solidity implementations
 */
export const VERIFIER_ABI = [
  {
    type: "function",
    name: "poseidonHash",
    inputs: [
      { name: "a", type: "uint256" },
      { name: "b", type: "uint256" },
    ],
    outputs: [{ name: "hash", type: "uint256" }],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "batchPoseidon",
    inputs: [
      { name: "inputsA", type: "uint256[]" },
      { name: "inputsB", type: "uint256[]" },
    ],
    outputs: [{ name: "hashes", type: "uint256[]" }],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "verifyMerklePath",
    inputs: [
      { name: "root", type: "uint256" },
      { name: "leaf", type: "uint256" },
      { name: "path", type: "uint256[]" },
      { name: "indices", type: "bool[]" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getLastResult",
    inputs: [],
    outputs: [
      { name: "root", type: "uint256" },
      { name: "result", type: "bool" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getVerificationCount",
    inputs: [],
    outputs: [{ name: "count", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "benchmarkHash",
    inputs: [
      { name: "iterations", type: "uint32" },
      { name: "seedA", type: "uint256" },
      { name: "seedB", type: "uint256" },
    ],
    outputs: [{ name: "result", type: "uint256" }],
    stateMutability: "pure",
  },
  {
    type: "event",
    name: "MerkleVerified",
    inputs: [
      { name: "root", type: "uint256", indexed: true },
      { name: "leaf", type: "uint256", indexed: false },
      { name: "result", type: "bool", indexed: false },
    ],
  },
] as const;

/**
 * STARK Verifier ABI (full STARK proof verification)
 */
export const STARK_VERIFIER_ABI = [
  {
    type: "function",
    name: "verifyStarkProof",
    inputs: [
      { name: "publicInputs", type: "uint256[]" },
      { name: "commitments", type: "uint256[]" },
      { name: "oodValues", type: "uint256[]" },
      { name: "friFinalPoly", type: "uint256[]" },
      { name: "queryValues", type: "uint256[]" },
      { name: "queryPaths", type: "uint256[]" },
      { name: "queryMetadata", type: "uint256[]" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "verifyBtcLockProof",
    inputs: [
      { name: "publicInputs", type: "uint256[]" },
      { name: "commitments", type: "uint256[]" },
      { name: "oodValues", type: "uint256[]" },
      { name: "friFinalPoly", type: "uint256[]" },
      { name: "queryValues", type: "uint256[]" },
      { name: "queryPaths", type: "uint256[]" },
      { name: "queryMetadata", type: "uint256[]" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "verifySharpeProof",
    inputs: [
      { name: "publicInputs", type: "uint256[]" },
      { name: "commitments", type: "uint256[]" },
      { name: "oodValues", type: "uint256[]" },
      { name: "friFinalPoly", type: "uint256[]" },
      { name: "queryValues", type: "uint256[]" },
      { name: "queryPaths", type: "uint256[]" },
      { name: "queryMetadata", type: "uint256[]" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
    stateMutability: "nonpayable",
  },
] as const;

/**
 * TypeScript type for a serialized STARK proof (from prover WASM)
 */
export interface StarkProofJSON {
  publicInputs: string[];
  commitments: string[];
  oodValues: string[];
  friFinalPoly: string[];
  queryValues: string[];
  queryPaths: string[];
  queryMetadata: string[];
}

/**
 * Get Stylus verifier contract instance (Poseidon/Merkle benchmark)
 */
export const getStylusContract = () =>
  getContract({
    client,
    chain: arbitrumSepolia,
    address: STYLUS_VERIFIER_ADDRESS,
    abi: VERIFIER_ABI,
  });

/**
 * Get Solidity verifier contract instance
 */
export const getSolidityContract = () =>
  getContract({
    client,
    chain: arbitrumSepolia,
    address: SOLIDITY_VERIFIER_ADDRESS,
    abi: VERIFIER_ABI,
  });

/**
 * Get STARK verifier contract instance
 */
export const getStarkVerifierContract = () =>
  getContract({
    client,
    chain: arbitrumSepolia,
    address: STARK_VERIFIER_V4_ADDRESS,
    abi: STARK_VERIFIER_ABI,
  });

/**
 * Contract type for verification
 */
export type VerifierType = "stylus" | "solidity";

/**
 * Verification result interface
 */
export interface VerificationResult {
  type: VerifierType;
  success: boolean;
  gasUsed: bigint;
  txHash: string;
  timestamp: number;
  error?: string;
}

/**
 * Benchmark data point interface
 */
export interface BenchmarkData {
  depth: number;
  stylusGas: number;
  solidityGas: number;
  savings: string;
}

/**
 * Expected benchmark results based on OpenZeppelin research
 */
export const EXPECTED_BENCHMARKS: BenchmarkData[] = [
  { depth: 8, stylusGas: 13000, solidityGas: 240000, savings: "18x" },
  { depth: 16, stylusGas: 26000, solidityGas: 480000, savings: "18x" },
  { depth: 32, stylusGas: 52000, solidityGas: 960000, savings: "18x" },
];

/**
 * Generate test Merkle proof data for a given depth
 */
export function generateTestProof(depth: number): {
  root: bigint;
  leaf: bigint;
  path: bigint[];
  indices: boolean[];
} {
  // Generate deterministic test data
  const leaf = BigInt("0x1234567890abcdef1234567890abcdef");
  const path: bigint[] = [];
  const indices: boolean[] = [];

  for (let i = 0; i < depth; i++) {
    // Generate pseudo-random sibling values
    path.push(BigInt(`0x${(i + 1).toString(16).padStart(64, "0")}`));
    indices.push(i % 2 === 0);
  }

  // In production, this would be the actual computed root
  const root = BigInt("0x9876543210fedcba9876543210fedcba");

  return { root, leaf, path, indices };
}
