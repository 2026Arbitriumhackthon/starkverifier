# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

STARK Stylus Verifier — demonstrates ~2.1x gas savings for cryptographic proof verification on Arbitrum Stylus (Rust/WASM) vs Solidity/EVM. The project implements identical Poseidon hash and Merkle proof verification contracts in both Rust (Stylus) and Solidity, with a Next.js frontend for side-by-side benchmarking on Arbitrum Sepolia.

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
cargo test                          # Run all unit tests
cargo test merkle                   # Run only merkle tests
cargo test poseidon                 # Run only poseidon tests
cargo stylus check                  # Validate WASM contract
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

## Architecture

The codebase has three independent parts:

**`contracts/stylus/`** — Rust no_std contract targeting `wasm32-unknown-unknown` via Stylus SDK 0.9. The Poseidon implementation (`src/poseidon/`) uses BN254 field arithmetic with t=3 (2 inputs + capacity), 65 rounds (8 full + 57 partial), and 195 round constants verified against iden3/circomlib. Merkle verification is in `src/merkle.rs`. Entry point is `src/lib.rs` with the `#[entrypoint]` macro on `StarkVerifier`.

**`contracts/solidity/`** — Foundry project with a mirror Solidity contract. `src/Poseidon.sol` is a ~24K line unrolled Poseidon implementation using `addmod`/`mulmod` opcodes. `src/StarkVerifier.sol` wraps it with the same interface. Tests in `test/Poseidon.t.sol` verify circomlib compatibility.

**`app/` + `components/` + `lib/`** — Next.js 16 App Router frontend using thirdweb v5 for wallet/contract interaction, Recharts for visualization, and shadcn/ui (New York style) for components. `lib/gas-context.tsx` is a React Context storing gas measurements from both contracts. `lib/contracts.ts` has ABIs and deployed addresses. `lib/gas-utils.ts` extracts Arbitrum L1/L2 gas breakdown.

Both contracts expose identical interfaces: `poseidonHash`, `batchPoseidon`, `verifyMerklePath`, `getLastResult`, `getVerificationCount`, `benchmarkHash`.

## Key Technical Details

- **Poseidon test vector**: `poseidon([1, 2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a` (must match circomlib)
- **BN254 prime**: `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- **Stylus contract**: `0x327c65e04215bd5575d60b00ba250ed5dd25a4fc` (Arbitrum Sepolia)
- **Solidity contract**: `0x96326E368b6f2fdA258452ac42B1aC013238f5Ce` (Arbitrum Sepolia)
- **Chain**: Arbitrum Sepolia (421614)
- TypeScript path alias: `@/*` maps to project root
- Solidity compiler: 0.8.24 with via_ir and Cancun EVM target
- Rust release profile: LTO, stripped, panic=abort, opt-level=s, codegen-units=1

## Environment Variables

```
NEXT_PUBLIC_THIRDWEB_CLIENT_ID   # Required for frontend
PRIVATE_KEY                       # For contract deployment
ARBITRUM_SEPOLIA_RPC_URL          # Optional RPC override
ARBISCAN_API_KEY                  # Optional for verification
```
