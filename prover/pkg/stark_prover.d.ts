/* tslint:disable */
/* eslint-disable */

/**
 * WASM-accessible STARK prover.
 */
export class StarkProverWasm {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Generate a Sharpe ratio STARK proof.
     *
     * bot_id: "a" for aggressive ETH bot, "b" for safe hedger.
     * Returns a JSON string containing the serialized proof.
     */
    generateSharpeProof(bot_id: string, num_queries: number): string;
    /**
     * Generate a Sharpe proof from return_bps array (no commitment).
     *
     * returns_bps: array of trade returns in basis points
     * num_queries: number of FRI queries
     * callback: JS function(stage, detail, percent) for progress updates
     */
    generateSharpeProofFromReturns(returns_bps: Int32Array, num_queries: number, callback: Function): string;
    /**
     * Generate a Sharpe proof from return_bps array with a dataset commitment.
     *
     * returns_bps: array of trade returns in basis points
     * dataset_commitment_hex: "0x..." hex string of the dataset commitment (or empty for no commitment)
     * num_queries: number of FRI queries
     * callback: JS function(stage, detail, percent) for progress updates
     */
    generateSharpeProofWithCommitment(returns_bps: Int32Array, dataset_commitment_hex: string, num_queries: number, callback: Function): string;
    /**
     * Generate a Sharpe proof with progress updates via a JS callback.
     */
    generateSharpeProofWithProgress(bot_id: string, num_queries: number, callback: Function): string;
    constructor();
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_starkproverwasm_free: (a: number, b: number) => void;
    readonly starkproverwasm_generateSharpeProof: (a: number, b: number, c: number, d: number) => [number, number];
    readonly starkproverwasm_generateSharpeProofFromReturns: (a: number, b: number, c: number, d: number, e: any) => [number, number];
    readonly starkproverwasm_generateSharpeProofWithCommitment: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => [number, number];
    readonly starkproverwasm_generateSharpeProofWithProgress: (a: number, b: number, c: number, d: number, e: any) => [number, number];
    readonly starkproverwasm_new: () => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
