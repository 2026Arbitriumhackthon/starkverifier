/**
 * Benchmark data: STARK (Stylus) vs SNARK (Groth16) comparison.
 * Source: benchmark/results/stark-a.json (measured) + SP1 Groth16 estimates.
 */

export interface BenchmarkEntry {
  system: "STARK" | "SNARK";
  proofGenTimeMs: number;
  proofSizeBytes: number;
  onChainGas: number;
  verifier: string;
  setup: string;
}

export const BENCHMARK_DATA: BenchmarkEntry[] = [
  {
    system: "STARK",
    proofGenTimeMs: 380,
    proofSizeBytes: 4864,
    onChainGas: 1_250_000,
    verifier: "Stylus (WASM)",
    setup: "Transparent",
  },
  {
    system: "SNARK",
    proofGenTimeMs: 18_500,
    proofSizeBytes: 260,
    onChainGas: 280_000,
    verifier: "Solidity (Groth16)",
    setup: "Trusted (SP1)",
  },
];

export const CHART_COLORS = {
  STARK: "#f97316", // orange-500
  SNARK: "#a855f7", // purple-500
} as const;
