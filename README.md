# ProofScore — On-Chain Agent Evaluation with STARK Proofs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Arbitrum](https://img.shields.io/badge/Arbitrum-Stylus-blue.svg)](https://arbitrum.io/)
[![Rust](https://img.shields.io/badge/Rust-WASM-orange.svg)](https://www.rust-lang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16-black.svg)](https://nextjs.org/)

> **STARK-verified trading agent evaluation on Arbitrum Stylus — Sharpe ratio proofs with zero-knowledge guarantees**

Built for **Arbitrum Buildathon 2026** | Evolved from APAC Mini Hackathon 1st place

---

## Overview

ProofScore uses STARK proofs to verify trading agent performance (Sharpe ratio) on-chain. Agents submit their trade data off-chain, generate a STARK proof of their Sharpe ratio computation, and the proof is verified on Arbitrum Stylus. Results are recorded in the EvaluationRegistry smart contract for transparent, trustless agent ranking.

### Key Features

- **STARK-Verified Sharpe Ratio** — Zero-knowledge proof of trading performance metrics
- **On-Chain Agent Evaluation** — EvaluationRegistry records verified scores per agent
- **Arbitrum Stylus (Rust/WASM)** — Native Keccak256 precompile for efficient FRI Merkle verification
- **No Trusted Setup** — Hash-based STARK security, post-quantum ready
- **Off-Chain Prover** — Rust CLI/WASM prover generates Sharpe proofs
- **~1.25M Gas** — Sharpe ratio verification (Bot A, 15 trades, 4 queries)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Off-Chain Prover (Rust CLI / WASM)             │
│                                                                  │
│  1. Build Sharpe trace (6 columns: ret, ret², cum_ret, etc.)     │
│  2. Evaluate trace on LDE domain (4x blowup)                    │
│  3. Commit via Keccak256 Merkle trees                            │
│  4. Fiat-Shamir: draw OOD point z, 9 composition alphas         │
│  5. Compute composition polynomial on LDE                        │
│  6. Run FRI protocol (fold + commit each layer)                  │
│  7. Serialize proof → ABI-encoded calldata                       │
│                                                                  │
│  cargo run --features cli --release -- --bot a --num-queries 4   │
└───────────────────────────────┬─────────────────────────────────┘
                                │ STARK Proof (calldata)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Arbitrum Sepolia (L2)                          │
│                      Chain ID: 421614                            │
├────────────────────────────┬────────────────────────────────────┤
│     STARK Verifier         │     EvaluationRegistry             │
│     (Rust → WASM)          │     (Solidity)                     │
│                            │                                     │
│  verifySharpeProof()       │  submitEvaluation()                │
│  - Fiat-Shamir channel     │  getTopAgents()                    │
│  - Sharpe AIR constraints  │  getAgentEvaluations()             │
│  - Composition polynomial  │                                     │
│  - FRI low-degree test     │                                     │
│                            │                                     │
│  0x4709cc38...             │  TBD                               │
└────────────────────────────┴────────────────────────────────────┘
```

### Sharpe Ratio AIR Constraints

6 trace columns: `[return, return_sq, cum_ret, cum_sq, trade_count, dataset_commitment]`

**Transition Constraints (5):**
- TC0: `cum_ret_next = cum_ret + ret_next`
- TC1: `ret_sq = ret * ret`
- TC2: `cum_sq_next = cum_sq + ret_sq_next`
- TC3: `trade_count` immutability
- TC4: placeholder (dataset commitment)

**Boundary Constraints (4):**
- BC0: `cum_ret[0] = ret[0]` (first row)
- BC1: `cum_sq[0] = ret_sq[0]` (first row)
- BC2: `cum_ret[N-1] = total_return` (last row)
- BC3: `cum_ret² × SCALE - sharpe_sq × (n × cum_sq - cum_ret²) = 0` (last row)

---

## Quick Start

### Prerequisites

- **Node.js** 18+ / **pnpm**
- **Rust** + cargo (for Stylus / prover)
- **Foundry** (for Solidity EvaluationRegistry)

### Installation

```bash
git clone https://github.com/hoddukzoa12/starkverifier.git
cd starkverifier
pnpm install
cp .env.example .env.local
pnpm dev
```

### Generate a Proof

```bash
cd prover
cargo run --features cli --release -- --bot a --num-queries 4
```

### Run Tests

```bash
# Stylus verifier (66 tests)
cd contracts/stylus && cargo test --features export-abi

# Prover (33 tests)
cd prover && cargo test

# Solidity (EvaluationRegistry)
cd contracts/solidity && forge test -vvv
```

---

## Project Structure

```
starkverifier/
├── contracts/
│   ├── stylus/                  # On-chain STARK Verifier (Rust → WASM)
│   │   └── src/
│   │       ├── lib.rs          # Entry point (verifySharpeProof)
│   │       ├── field.rs        # BN254 field arithmetic (Montgomery)
│   │       ├── merkle.rs       # Keccak256 Merkle tree verification
│   │       └── stark/
│   │           ├── mod.rs      # Full Sharpe verifier orchestration
│   │           ├── sharpe_air.rs # Sharpe AIR constraints + zerofier
│   │           ├── channel.rs  # Fiat-Shamir (Keccak-based)
│   │           ├── domain.rs   # Evaluation domains (roots of unity)
│   │           ├── fri.rs      # FRI low-degree verifier
│   │           └── proof.rs    # Proof deserialization
│   │
│   └── solidity/                # EvaluationRegistry (Solidity)
│       └── src/
│           └── EvaluationRegistry.sol
│
├── prover/                      # Off-chain STARK Prover (Rust)
│   └── src/
│       ├── main.rs             # CLI: --bot a|b --num-queries N
│       ├── lib.rs              # prove_sharpe() + shared utilities
│       ├── sharpe_trace.rs     # Sharpe ratio trace generation
│       ├── sharpe_compose.rs   # Composition polynomial on LDE
│       ├── mock_data.rs        # Bot A / Bot B trade datasets
│       ├── commit.rs           # Keccak Merkle tree construction
│       ├── fri.rs              # FRI prover (fold + commit layers)
│       ├── channel.rs          # Fiat-Shamir (matches on-chain)
│       ├── domain.rs           # Evaluation domains
│       ├── proof.rs            # Proof serialization (JSON / ABI)
│       ├── field.rs            # BN254 field arithmetic
│       ├── keccak.rs           # Keccak hash (matches on-chain)
│       └── wasm.rs             # WASM bindings (wasm-bindgen)
│
├── app/                         # Next.js 16 Frontend
├── components/                  # React components (shadcn/ui)
├── lib/                         # Contracts, chains, client
└── package.json
```

---

## Deployed Contracts (Arbitrum Sepolia)

| Contract | Address | Purpose |
|----------|---------|---------|
| **STARK Verifier v4** | [`0x4709cc3862280597855a6986b13f1f1ccb309ff9`](https://sepolia.arbiscan.io/address/0x4709cc3862280597855a6986b13f1f1ccb309ff9) | Sharpe ratio STARK verification |
| EvaluationRegistry | TBD | On-chain agent evaluation records |

---

## Proof Interface

```solidity
interface IStarkVerifier {
    function verifySharpeProof(
        uint256[] calldata publicInputs,    // [trade_count, total_return, sharpe_sq_scaled, merkle_root]
        uint256[] calldata commitments,      // [trace_root, comp_root, fri_roots...]
        uint256[] calldata oodValues,        // [6 trace(z), 6 trace(zg), comp(z)] = 13 values
        uint256[] calldata friFinalPoly,     // Final polynomial coefficients
        uint256[] calldata queryValues,      // FRI query evaluations (flattened)
        uint256[] calldata queryPaths,       // Merkle auth paths (flattened)
        uint256[] calldata queryMetadata     // [num_queries, num_fri_layers, log_trace_len, indices...]
    ) external returns (bool);
}
```

---

## Gas Benchmarks

| Bot | Trades | Queries | Gas Used |
|-----|--------|---------|----------|
| Bot A (Aggressive ETH) | 15 | 4 | ~1.25M |
| Bot B (Safe Hedger) | 23 | 4 | ~1.45M |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| On-chain verifier | Rust → WASM (Arbitrum Stylus SDK 0.9) |
| On-chain registry | Solidity 0.8.24 (Foundry) |
| Off-chain prover | Rust (CLI + WASM) |
| Hash function | Keccak256 (native Stylus precompile) |
| Field | BN254 scalar field |
| Frontend | Next.js 16, thirdweb v5, shadcn/ui |

---

## Environment Variables

```env
NEXT_PUBLIC_THIRDWEB_CLIENT_ID   # Required for frontend
PRIVATE_KEY                       # For contract deployment
ARBITRUM_SEPOLIA_RPC_URL          # Optional RPC override
ARBISCAN_API_KEY                  # Optional for verification
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built for <strong>Arbitrum Buildathon 2026</strong>
</p>
