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
export default function __wbg_init (module_or_path: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
