# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ProofScore — On-chain STARK-verified trading agent evaluation on Arbitrum Stylus. Full STARK pipeline: off-chain prover (Rust, WASM-compatible), on-chain verifier (Stylus Rust/WASM), EvaluationRegistry (Solidity), and a Next.js frontend. Uses Keccak256 (native Stylus precompile) for FRI Merkle commitments and Fiat-Shamir channel. Verifies Sharpe ratio proofs for trading agent performance evaluation.

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
cargo test --features export-abi      # Run all 79 unit tests
cargo test merkle                     # Run only merkle tests
cargo test stark                      # Run only stark tests
cargo stylus check                    # Validate WASM contract
cargo build --release --target wasm32-unknown-unknown  # Build WASM
```

### Solidity Contract (Foundry)
```bash
cd contracts/solidity
forge build                         # Compile EvaluationRegistry
forge test -vvv                     # Run tests with verbosity
```

### Prover (Off-chain)
```bash
cd prover
cargo test                          # Run prover tests (33 tests)
cargo run --features cli --release -- --bot a --num-queries 4   # Generate Sharpe proof (Bot A)
cargo run --features cli --release -- --bot b --num-queries 20  # Full proof (Bot B)
wasm-pack build --target web --features wasm --no-default-features  # WASM build
```

## Architecture

The codebase has four parts:

**`contracts/stylus/`** — Rust no_std on-chain STARK verifier targeting `wasm32-unknown-unknown` via Stylus SDK 0.9. Uses Keccak256 (native precompile) for Merkle verification (`src/merkle.rs`) and Fiat-Shamir channel. Full STARK verification (`src/stark/`) with Sharpe AIR constraints, FRI protocol. Entry point: `src/lib.rs` with `#[entrypoint]` macro on `StarkVerifier`. On-chain function: `verifySharpeProof(7 × uint256[]) → bool`. Sharpe AIR: 6 columns, 5 transition constraints, 4 boundary constraints, 9 alphas.

**`prover/`** — Off-chain STARK prover (Rust). Structured as lib + bin: `src/lib.rs` exposes `prove_sharpe()` with progress variant. CLI via `src/main.rs` (feature `cli`, `--bot a|b`). WASM wrapper via `src/wasm.rs` (feature `wasm`). Generates Sharpe ratio STARK proofs.

**`contracts/solidity/`** — Foundry project with EvaluationRegistry contract for on-chain agent evaluation records. Stores verified Sharpe scores per agent.

**`app/` + `components/` + `lib/`** — Next.js 16 App Router frontend. Uses thirdweb v5, shadcn/ui. Dashboard for agent evaluation (in progress).

## Deployed Contracts (Arbitrum Sepolia)

| Contract | Address | Purpose |
|----------|---------|---------|
| STARK Verifier v6 (Keccak + Sharpe + Phase A commitment, Stylus) | `0x365344c7057eee248c986e4170e143f0449d943e` | Sharpe ratio STARK + multi-receipt commitment binding |
| EvaluationRegistry (Solidity) | TBD | On-chain agent evaluation records |

## Sharpe Ratio Proof Interface

```
verifySharpeProof(
    publicInputs: uint256[],    // [trade_count, total_return, sharpe_sq_scaled, merkle_root]
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
- **Gas**: Sharpe ratio verification (4 queries): ~1.25M gas (Bot A, 15 trades), ~1.45M gas (Bot B, 23 trades)
- TypeScript path alias: `@/*` maps to project root
- Rust release profile: LTO, stripped, panic=abort, opt-level=z, codegen-units=1
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
Do not write "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>".
Make github issues when you start working.
When you done github issue, comment the result and close the issue.
