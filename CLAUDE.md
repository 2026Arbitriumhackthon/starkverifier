# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

STARK Stylus Verifier — the first on-chain STARK verifier on Arbitrum Stylus. Includes a full STARK pipeline: off-chain prover (Rust, WASM-compatible), on-chain verifier (Stylus Rust/WASM), and a Next.js frontend with proof generation and on-chain verification. Uses Keccak256 (native Stylus precompile) for FRI Merkle commitments and Fiat-Shamir channel. STARK verification costs ~1.04M gas (fib-8, 4 queries).

## Common Commands

### Frontend (Next.js 16 / pnpm)
```bash
pnpm install          # Install dependencies
pnpm dev              # Dev server on localhost:3000
pnpm build            # Production build
pnpm lint             # ESLint (next/core-web-vitals + typescript)
```

### Stylus Contract (Rust)
```bash
cd contracts/stylus
cargo test --features export-abi      # Run all 68 unit tests
cargo test merkle                     # Run only merkle tests
cargo test stark                      # Run only stark tests
cargo stylus check                    # Validate WASM contract
cargo build --release --target wasm32-unknown-unknown  # Build WASM
```

### Solidity Contract (Foundry)
```bash
cd contracts/solidity
forge build                         # Compile
forge test -vvv                     # Run tests with verbosity
forge test --gas-report             # Gas usage report
forge fmt                           # Format (line_length=100, tab_width=4)
```

### Prover (Off-chain)
```bash
cd prover
cargo test                          # Run prover tests (15 tests)
cargo run --release -- --fib-n 8 --num-queries 4   # Generate proof
cargo run --release -- --fib-n 64 --num-queries 20  # Full proof
wasm-pack build --target web --features wasm --no-default-features  # WASM build
```

## Architecture

The codebase has four parts:

**`contracts/stylus/`** — Rust no_std on-chain STARK verifier targeting `wasm32-unknown-unknown` via Stylus SDK 0.9. Uses Keccak256 (native precompile) for Merkle verification (`src/merkle.rs`) and Fiat-Shamir channel. Full STARK verification (`src/stark/`) with AIR constraints, FRI protocol. Entry point: `src/lib.rs` with `#[entrypoint]` macro on `StarkVerifier`. On-chain functions: `verifyStarkProof(7 × uint256[]) → bool` (Fibonacci), `verifyBtcLockProof(7 × uint256[]) → bool` (BTC Lock), `verifySharpeProof(7 × uint256[]) → bool` (Sharpe ratio). BTC Lock AIR: 5 columns, 8 transition constraints, 4 boundary constraints, 12 alphas. Sharpe AIR: 6 columns, transition + boundary constraints for Sharpe^2 computation.

**`prover/`** — Off-chain STARK prover (Rust). Structured as lib + bin: `src/lib.rs` exposes `prove_fibonacci()` / `prove_btc_lock()` / `prove_sharpe()` with progress variants. CLI via `src/main.rs` (feature `cli`, `--mode fibonacci|btclock|sharpe`). WASM wrapper via `src/wasm.rs` (feature `wasm`). Generates proofs for Fibonacci computation, BTC Lock verification, and Sharpe ratio verification.

**`contracts/solidity/`** — Foundry project with Solidity Poseidon/Merkle contracts for gas comparison. `src/Poseidon.sol` is a ~24K line unrolled Poseidon using `addmod`/`mulmod`.

**`app/` + `components/` + `lib/`** — Next.js 16 App Router frontend. `StarkPipeline.tsx` is the main STARK proof generation/verification UI. `VerifyPanel.tsx` handles Poseidon/Merkle benchmarks. Uses thirdweb v5, Recharts, shadcn/ui.

## Deployed Contracts (Arbitrum Sepolia)

| Contract | Address | Purpose |
|----------|---------|---------|
| STARK Verifier v4 (Keccak + BTC Lock + Sharpe, Stylus) | `0x4709cc3862280597855a6986b13f1f1ccb309ff9` | Fibonacci + BTC Lock + Sharpe ratio STARK verification |
| STARK Verifier v3 (Keccak + BTC Lock, Stylus) | `0xbbc1a7c1df3f63052960ec38e2e578cf3bf28934` | Fibonacci + BTC Lock STARK verification |
| STARK Verifier v2 (Keccak, Stylus) | `0xefcc033b0743565fb444307e35bf7b104220da00` | Fibonacci-only STARK verification (~1.04M gas) |
| STARK Verifier v1 (Poseidon, Stylus) | `0x572318f371e654d8f3b18209b9b6ae766326ef46` | Legacy v1 (~31.9M gas) |
| Poseidon Benchmark (Stylus) | `0x327c65e04215bd5575d60b00ba250ed5dd25a4fc` | Poseidon/Merkle gas benchmark |
| Poseidon Benchmark (Solidity) | `0x96326E368b6f2fdA258452ac42B1aC013238f5Ce` | Solidity comparison baseline |

## STARK Proof Interface

```
verifyStarkProof(
    publicInputs: uint256[],    // [first_a, first_b, claimed_result]
    commitments: uint256[],     // [trace_root, comp_root, fri_roots...]
    oodValues: uint256[],       // [a(z), b(z), a(zg), b(zg), comp(z)]
    friFinalPoly: uint256[],    // Final polynomial coefficients
    queryValues: uint256[],     // Flattened query data
    queryPaths: uint256[],      // Flattened Merkle paths
    queryMetadata: uint256[],   // [num_queries, num_fri_layers, log_trace_len, indices...]
) → bool
```

### BTC Lock Proof Interface

```
verifyBtcLockProof(
    publicInputs: uint256[],    // [lock_amount, timelock_height, current_height, script_type]
    commitments: uint256[],     // [trace_root, comp_root, fri_roots...]
    oodValues: uint256[],       // [5 trace(z), 5 trace(zg), comp(z)] = 11 values
    friFinalPoly: uint256[],    // Final polynomial coefficients
    queryValues: uint256[],     // Flattened query data
    queryPaths: uint256[],      // Flattened Merkle paths
    queryMetadata: uint256[],   // [num_queries, num_fri_layers, log_trace_len, indices...]
) → bool
```

### Sharpe Ratio Proof Interface

```
verifySharpeProof(
    publicInputs: uint256[],    // [num_trades, scale, sharpe_sq_scaled, trace_hash]
    commitments: uint256[],     // [trace_root, comp_root, fri_roots...]
    oodValues: uint256[],       // [6 trace(z), 6 trace(zg), comp(z)] = 13 values
    friFinalPoly: uint256[],    // Final polynomial coefficients
    queryValues: uint256[],     // Flattened query data
    queryPaths: uint256[],      // Flattened Merkle paths
    queryMetadata: uint256[],   // [num_queries, num_fri_layers, log_trace_len, indices...]
) → bool
```

## Key Technical Details

- **Hash function**: Keccak256 (native Stylus precompile) for FRI Merkle + Fiat-Shamir
- **BN254 prime**: `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- **Chain**: Arbitrum Sepolia (421614)
- **Gas**: STARK verification (fib-8, 4 queries): ~1.04M gas (v2 Keccak), ~31.9M gas (v1 Poseidon)
- **Gas**: Sharpe ratio verification (4 queries): ~1.25M gas (Bot A, 15 trades), ~1.45M gas (Bot B, 23 trades)
- TypeScript path alias: `@/*` maps to project root
- Solidity compiler: 0.8.24 with via_ir and Cancun EVM target
- Rust release profile: LTO, stripped, panic=abort, opt-level=z, codegen-units=1
- WASM size: 19.2KB (v4 w/ Sharpe), 16.6KB (v3 w/ BTC Lock), 13.9KB (v2 Fib-only), ~23.6KB (v1 Poseidon)
- Stylus SDK ABI naming: snake_case Rust → camelCase Solidity

## Environment Variables

```
NEXT_PUBLIC_THIRDWEB_CLIENT_ID   # Required for frontend
PRIVATE_KEY                       # For contract deployment
ARBITRUM_SEPOLIA_RPC_URL          # Optional RPC override
ARBISCAN_API_KEY                  # Optional for verification
```

## Github Rules

Do not write "🤖 Generated with [Claude Code](https://claude.com/claude-code)".
Make github issues when you start working.
When you done github issue, comment the result and close the issue.