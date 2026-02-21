import { getContract } from "thirdweb";
import { client } from "./client";
import { arbitrumSepolia } from "./chains";

/**
 * Contract addresses on Arbitrum Sepolia
 */

// STARK Verifier v4 (Keccak + Sharpe ratio, Stylus)
export const STARK_VERIFIER_V4_ADDRESS =
  "0x4709cc3862280597855a6986b13f1f1ccb309ff9" as const;

// EvaluationRegistry (Phase 2 — agent evaluation on-chain records)
export const EVALUATION_REGISTRY_ADDRESS =
  "0x0000000000000000000000000000000000000000" as const;

/**
 * STARK Verifier ABI (Sharpe ratio proof verification)
 */
export const STARK_VERIFIER_ABI = [
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
  {
    type: "function",
    name: "verifySharpeProofWithReceipt",
    inputs: [
      { name: "publicInputs", type: "uint256[]" },
      { name: "commitments", type: "uint256[]" },
      { name: "oodValues", type: "uint256[]" },
      { name: "friFinalPoly", type: "uint256[]" },
      { name: "queryValues", type: "uint256[]" },
      { name: "queryPaths", type: "uint256[]" },
      { name: "queryMetadata", type: "uint256[]" },
      { name: "blockHash", type: "uint256" },
      { name: "receiptsRoot", type: "uint256[]" },
      { name: "receiptRlp", type: "uint256[]" },
      { name: "receiptRlpLen", type: "uint256" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
    stateMutability: "nonpayable",
  },
] as const;

/**
 * EvaluationRegistry ABI
 */
export const EVALUATION_REGISTRY_ABI = [
  {
    type: "function",
    name: "submitEvaluation",
    inputs: [
      { name: "agentId", type: "address" },
      { name: "publicInputs", type: "uint256[]" },
      { name: "commitments", type: "uint256[]" },
      { name: "oodValues", type: "uint256[]" },
      { name: "friFinalPoly", type: "uint256[]" },
      { name: "queryValues", type: "uint256[]" },
      { name: "queryPaths", type: "uint256[]" },
      { name: "queryMetadata", type: "uint256[]" },
    ],
    outputs: [{ name: "evaluationId", type: "uint256" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getTopAgents",
    inputs: [{ name: "limit", type: "uint256" }],
    outputs: [
      { name: "agents", type: "address[]" },
      { name: "scores", type: "uint256[]" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getAgentEvaluations",
    inputs: [{ name: "agentId", type: "address" }],
    outputs: [
      {
        name: "records",
        type: "tuple[]",
        components: [
          { name: "agentId", type: "address" },
          { name: "datasetCommitment", type: "bytes32" },
          { name: "tradeCount", type: "uint256" },
          { name: "sharpeSqBps", type: "uint256" },
          { name: "totalReturnBps", type: "uint256" },
          { name: "proofHash", type: "bytes32" },
          { name: "blockNumber", type: "uint256" },
          { name: "evaluator", type: "address" },
          { name: "timestamp", type: "uint256" },
          { name: "verified", type: "bool" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getEvaluation",
    inputs: [{ name: "evaluationId", type: "uint256" }],
    outputs: [
      {
        name: "record",
        type: "tuple",
        components: [
          { name: "agentId", type: "address" },
          { name: "datasetCommitment", type: "bytes32" },
          { name: "tradeCount", type: "uint256" },
          { name: "sharpeSqBps", type: "uint256" },
          { name: "totalReturnBps", type: "uint256" },
          { name: "proofHash", type: "bytes32" },
          { name: "blockNumber", type: "uint256" },
          { name: "evaluator", type: "address" },
          { name: "timestamp", type: "uint256" },
          { name: "verified", type: "bool" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getEvaluationCount",
    inputs: [],
    outputs: [{ name: "count", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getBestScore",
    inputs: [{ name: "agentId", type: "address" }],
    outputs: [{ name: "score", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "EvaluationSubmitted",
    inputs: [
      { name: "evaluationId", type: "uint256", indexed: true },
      { name: "agentId", type: "address", indexed: true },
      { name: "evaluator", type: "address", indexed: true },
      { name: "sharpeSqBps", type: "uint256", indexed: false },
      { name: "verified", type: "bool", indexed: false },
    ],
  },
  {
    type: "event",
    name: "BestScoreUpdated",
    inputs: [
      { name: "agentId", type: "address", indexed: true },
      { name: "newBestSharpeSqBps", type: "uint256", indexed: false },
      { name: "evaluationId", type: "uint256", indexed: false },
    ],
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
 * Get EvaluationRegistry contract instance
 */
export const getEvaluationRegistryContract = () =>
  getContract({
    client,
    chain: arbitrumSepolia,
    address: EVALUATION_REGISTRY_ADDRESS,
    abi: EVALUATION_REGISTRY_ABI,
  });

