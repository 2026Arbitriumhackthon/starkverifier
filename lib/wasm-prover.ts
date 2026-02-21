/**
 * WASM singleton loader + Sharpe proof generation wrapper.
 */

import type { StarkProofJSON } from "./contracts";
import type { ProofProgress } from "./bot-data";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let loadPromise: Promise<any> | null = null;

/**
 * Dynamically import and initialize the WASM prover module.
 * Uses promise caching to prevent race conditions on concurrent calls.
 */
export async function loadWasmProver() {
  if (!loadPromise) {
    loadPromise = (async () => {
      const mod = await import("@/prover/pkg/stark_prover");
      const wasmUrl = new URL("@/prover/pkg/stark_prover_bg.wasm", import.meta.url);
      await mod.default(wasmUrl);
      return mod;
    })();
  }
  return loadPromise;
}

/**
 * Generate a Sharpe ratio STARK proof using the WASM prover.
 *
 * @param botId - "a" or "b"
 * @param numQueries - number of FRI queries (default 4)
 * @param onProgress - optional callback for proof generation progress
 * @returns Parsed StarkProofJSON ready for on-chain verification
 */
export async function generateSharpeProof(
  botId: "a" | "b",
  numQueries: number,
  onProgress?: (progress: ProofProgress) => void
): Promise<StarkProofJSON> {
  const mod = await loadWasmProver();
  const prover = new mod.StarkProverWasm();

  let jsonStr: string;
  try {
    if (onProgress) {
      jsonStr = prover.generateSharpeProofWithProgress(
        botId,
        numQueries,
        (stage: string, detail: string, percent: number) => {
          onProgress({ stage, detail, percent });
        }
      );
    } else {
      jsonStr = prover.generateSharpeProof(botId, numQueries);
    }
  } finally {
    prover.free();
  }

  return JSON.parse(jsonStr) as StarkProofJSON;
}

/**
 * Generate a Sharpe ratio STARK proof from raw return_bps values.
 *
 * @param returnsBps - Int32Array of signed basis-point returns per trade
 * @param numQueries - number of FRI queries
 * @param onProgress - optional callback for proof generation progress
 * @returns Parsed StarkProofJSON ready for on-chain verification
 */
export async function generateSharpeProofFromReturns(
  returnsBps: Int32Array,
  numQueries: number,
  onProgress?: (progress: ProofProgress) => void
): Promise<StarkProofJSON> {
  const mod = await loadWasmProver();
  const prover = new mod.StarkProverWasm();

  let jsonStr: string;
  try {
    if (onProgress) {
      jsonStr = prover.generateSharpeProofFromReturnsWithProgress(
        returnsBps,
        numQueries,
        (stage: string, detail: string, percent: number) => {
          onProgress({ stage, detail, percent });
        }
      );
    } else {
      jsonStr = prover.generateSharpeProofFromReturns(returnsBps, numQueries);
    }
  } finally {
    prover.free();
  }

  const result = JSON.parse(jsonStr);
  if (result.error) {
    throw new Error(result.error);
  }
  return result as StarkProofJSON;
}
