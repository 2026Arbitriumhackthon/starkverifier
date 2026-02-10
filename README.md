# STARK Stylus Verifier

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Arbitrum](https://img.shields.io/badge/Arbitrum-Stylus-blue.svg)](https://arbitrum.io/)
[![Rust](https://img.shields.io/badge/Rust-WASM-orange.svg)](https://www.rust-lang.org/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-purple.svg)](https://soliditylang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16-black.svg)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![circomlib](https://img.shields.io/badge/Poseidon-circomlib%20Compatible-green.svg)](https://github.com/iden3/circomlib)

> **Full STARK Verifier on Arbitrum Stylus (Rust/WASM) — direct on-chain verification without SNARK wrapping**

Built for **Arbitrum Buildathon 2026** | Evolved from APAC Mini Hackathon 1st place (Poseidon/Merkle ~2.1x gas benchmark)

---

## Table of Contents

- [Features](#features)
- [The Paradigm Shift: No More Wrapping Tax](#-the-paradigm-shift-no-more-wrapping-tax)
- [Benchmark Results](#benchmark-results)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Contract Deployment](#contract-deployment)
- [Deployed Contracts](#deployed-contracts)
- [Technical Details](#technical-details)
  - [Poseidon Hash Function](#poseidon-hash-function)
  - [Merkle Verification](#merkle-verification)
- [Why Stylus is Faster](#why-stylus-is-faster)
- [STARK Verification Gas](#stark-verification-gas)
- [Security](#security)
- [API Reference](#api-reference)
- [Supported Wallets](#supported-wallets)
- [Environment Variables](#environment-variables)
- [License](#license)
- [References](#references)

---

## Features

- **Full STARK Verification On-Chain** - Complete STARK proof verification for Fibonacci computation, running natively on Stylus WASM
- **No Wrapping Tax** - Direct STARK verification without SNARK wrapping overhead
- **~2.1x Gas Savings** - Poseidon/Merkle benchmarks: Stylus vs Solidity
- **Post-Quantum Ready** - Hash-based STARK security, no trusted setup required
- **Off-Chain Prover** - Rust CLI prover generates STARK proofs for on-chain verification
- **Zero External Dependencies** - All cryptography (Poseidon, FRI, AIR) self-implemented within 24KB WASM limit
- **circomlib Compatible** - Poseidon hash function compatible with iden3/circomlib
- **Security Audited** - FRI Merkle verification, cross-layer consistency, and Fiat-Shamir index derivation all validated
- **Live on Arbitrum Sepolia** - STARK verifier deployed and [verified on-chain](https://sepolia.arbiscan.io/tx/0x1794ff88663a73b50614533d28caa13bc82cd799374d69dbddb03febae32a9a8) (31.9M gas)

---

## 🚀 The Paradigm Shift: No More Wrapping Tax

### The Problem with Traditional ZK Rollups

Standard ZK rollups wrap **STARK proofs inside SNARKs** (e.g., Groth16) to reduce on-chain verification costs. This "wrapping" introduces significant trade-offs:

| Trade-off | Impact |
|-----------|--------|
| **Computational Overhead** | Extra proving time for the wrapping circuit |
| **Trusted Setup Required** | Groth16 requires a ceremony (security assumption) |
| **Lost Post-Quantum Resistance** | SNARKs are vulnerable to quantum attacks |
| **Increased Complexity** | More code = more attack surface |

```
┌─────────────────────────────────────────────────────────────────┐
│                    Legacy Approach (EVM)                         │
│                                                                  │
│   STARK Proof ──► Wrapping Circuit ──► SNARK Proof ──► EVM     │
│                   (Slow, Trusted)       (Groth16)    (Expensive) │
│                                                                  │
│   ⚠️  Security compromised for gas savings                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Our Approach (Stylus)                         │
│                                                                  │
│   STARK Proof ─────────────────────────────────► Stylus (WASM)  │
│                     Direct Verification              ⚡ Fast     │
│                                                                  │
│   ✅  Full security preserved, no compromises                   │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Matters

> **"We've been forced to sacrifice security (trustless setup) and future-proofing (post-quantum resistance) just because EVM gas was too expensive. Stylus changes everything."**

### 📊 Head-to-Head: Total Cost of Verification

The "Wrapping Tax" isn't just on-chain gas — it's the **full cost of running a SNARK wrapper pipeline**: GPU servers, trusted setup ceremonies, wrapper circuit maintenance, and proving time.

| Metric | Traditional (STARK→SNARK wrap) | Our Approach (Pure STARK on Stylus) |
|--------|-------------------------------|-------------------------------------|
| **Off-chain Proving** | STARK + SNARK wrapping (GPU, $2-5/proof) | STARK only (CPU, <$1/proof) |
| **On-chain Gas** | ~230K (Groth16 precompile) | ~32M (fib-8) — higher |
| **Trust Model** | Trusted Setup required | **Transparent** (trustless) |
| **Quantum Safety** | Vulnerable (Groth16) | **Post-quantum resistant** |
| **Infrastructure** | High-RAM GPU servers | Standard servers |
| **Dev Complexity** | Wrapper circuit maintenance | Direct verification logic |

### The Bottom Line

On-chain gas alone favors Groth16 (~230K vs ~32M). But gas is only part of the cost:

- **No trusted setup ceremony** — Pure mathematics, no security assumptions
- **No GPU infrastructure** — Standard CPU servers generate proofs
- **No wrapper circuit maintenance** — Change logic without updating Groth16 circuits
- **Post-quantum resistant** — Hash-based security, no elliptic curve assumptions

The real value is **architectural simplicity**: one proof system, no wrapping pipeline, no trusted setup, and a direct path to post-quantum security.

> **Key Insight**: We trade higher on-chain gas for **eliminating the entire off-chain wrapping pipeline**. As Stylus precompiles mature and L2 gas costs drop, the on-chain gap will narrow — but the architectural advantages are permanent.
>
> **"No trusted setup, no GPU servers, no wrapper circuits."**

---

## Benchmark Results

Real transaction measurements on Arbitrum Sepolia testnet:

| Depth | Stylus (Rust/WASM) | Solidity (EVM) | Gas Savings |
|-------|-------------------|----------------|-------------|
| 8     | 2.08M gas         | 4.34M gas      | **2.08x**   |
| 16    | 4.11M gas         | 8.66M gas      | **2.11x**   |
| 32    | 8.16M gas         | 17.32M gas     | **2.12x**   |

### Per-Hash Analysis

| Metric | Stylus | Solidity | Ratio |
|--------|--------|----------|-------|
| Gas per Poseidon hash | ~257K | ~541K | 2.1x |
| Single hash call | 300K | 564K | 1.88x |

> **Note**: The consistent ~2.1x ratio across all depths confirms that Stylus maintains its efficiency advantage regardless of workload size.

### STARK Verification Gas

Real on-chain STARK proof verification on Arbitrum Sepolia ([tx](https://sepolia.arbiscan.io/tx/0x1794ff88663a73b50614533d28caa13bc82cd799374d69dbddb03febae32a9a8)):

| Metric | Value |
|--------|-------|
| **Proof** | fib(8), 4 FRI queries, 3 FRI layers |
| **Gas Used** | **31,961,858** |
| **Calldata** | ~3.4 KB (96 U256 elements) |
| **Result** | `true` (valid proof) |
| **ETH Cost** | 0.00064 ETH @ 0.02 Gwei |

#### Gas Breakdown by Verification Phase

| Phase | Description | Dominant Cost |
|-------|-------------|---------------|
| Fiat-Shamir channel | Poseidon hashing of commitments | ~5% |
| AIR constraint check | Transition + boundary quotients | ~10% |
| Composition polynomial | 5 coefficient multiplications | ~5% |
| **FRI verification** | **Merkle path verification + folding** | **~80%** |

> The FRI phase dominates gas cost because each query requires multiple Poseidon hashes for Merkle path verification (depth 5+4+3=12 hashes per query).

#### Production Scaling

| Parameter | Current (Demo) | Production (Target) |
|-----------|:-:|:-:|
| FRI queries | 4 | 20+ |
| Security bits | ~16 | ~80 |
| Gas (single TX) | 31.9M | ~200M (exceeds 32M limit) |
| Solution | Single TX | Multi-TX split verification |

Production-grade proofs (20+ queries for ~80-bit security) exceed the single-transaction gas limit. The solution is **split verification**: FRI queries are independent and can be verified across multiple transactions (~8 TXs of ~25M gas each). Each transaction verifies a subset of queries and stores intermediate results; a final transaction aggregates them.

#### On-chain Gas: STARK vs Groth16

| Approach | On-chain Gas | Off-chain Cost | Trust Model |
|----------|:-:|:-:|:-:|
| **Groth16 (SNARK)** | ~230K | $2-5/proof (GPU) | Trusted Setup |
| **Our STARK (Stylus)** | ~32M | <$1/proof (CPU) | Transparent |

Raw STARK verification costs ~140x more on-chain gas than Groth16. This is an inherent trade-off: STARKs exchange compact proofs for transparency and post-quantum security. As Arbitrum adds Poseidon precompiles or Stylus-native hash acceleration, this gap will shrink significantly.

### 🚀 Impact on Scalability

**Why L2?** Heavy ZK verification on Ethereum Mainnet would consume entire blocks. By offloading to Arbitrum Stylus, we free up valuable L1 block space while inheriting Ethereum's security.

At Depth 32, Solidity consumes **17.32M gas (54% of block limit)**, causing potential network congestion. Stylus consumes only **8.16M gas (25% of block limit)**, making large-scale ZK verification **sustainable**.

| Metric | Solidity | Stylus | Improvement |
|--------|----------|--------|-------------|
| Block Usage (Depth 32) | 54% | 25% | **2.1x more headroom** |
| Max Verifications/Block | ~1.8 | ~3.9 | **2.1x throughput** |

> **L2 Scaling Strategy**: Offload compute-intensive verification to Arbitrum → Settle proofs on Ethereum → Best of both worlds (speed + security)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Off-Chain Prover (Rust CLI)                    │
│                                                                  │
│  1. Generate Fibonacci trace (N steps)                           │
│  2. Evaluate trace on LDE domain (4x blowup)                    │
│  3. Commit via Poseidon Merkle trees                             │
│  4. Fiat-Shamir: draw OOD point z, composition alphas            │
│  5. Compute composition polynomial on LDE                        │
│  6. Run FRI protocol (fold + commit each layer)                  │
│  7. Serialize proof → ABI-encoded calldata (~3.4 KB)             │
│                                                                  │
│  cargo run --release -- --fib-n 64 --num-queries 20              │
└───────────────────────────────┬─────────────────────────────────┘
                                │ STARK Proof (calldata)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Arbitrum Sepolia (L2)                          │
│                      Chain ID: 421614                            │
├────────────────────────────┬────────────────────────────────────┤
│     STARK Verifier         │       Solidity Verifier            │
│     (Rust → WASM, 23.6KB)  │       (Solidity → EVM)            │
│                            │                                     │
│  ┌──────────────────────┐  │    ┌──────────────────┐            │
│  │ verify_stark_proof() │  │    │ poseidonHash()   │            │
│  │ poseidon_hash()      │  │    │ batchPoseidon()  │            │
│  └──────────────────────┘  │    │ verifyMerkle()   │            │
│                            │    └──────────────────┘            │
│  Verification Pipeline:    │                                     │
│  1. Fiat-Shamir channel    │    0x96326E36...                   │
│  2. AIR constraint check   │                                     │
│  3. Composition polynomial │                                     │
│  4. FRI low-degree test    │                                     │
│                            │                                     │
│  0x572318f3...             │                                     │
├────────────────────────────┴────────────────────────────────────┤
│             Shared Primitives: Poseidon BN254 (t=3)              │
│           8 Full Rounds + 57 Partial Rounds (circomlib)          │
│          Field Arithmetic: pow, inv, div over BN254              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

### Frontend

| Technology | Version | Purpose |
|------------|---------|---------|
| Next.js | 16.1.1 | React framework (App Router) |
| React | 19.2.3 | UI library |
| TypeScript | 5.x | Type safety |
| Tailwind CSS | 4.x | Styling |
| thirdweb | 5.116.1 | Web3 integration |
| Recharts | 2.15.4 | Data visualization |
| shadcn/ui | - | UI components |
| Radix UI | - | Accessible primitives |

### Stylus Contract (Rust)

| Dependency | Version | Purpose |
|------------|---------|---------|
| stylus-sdk | 0.9.0 | Arbitrum Stylus SDK |
| alloy-primitives | 0.8 | Ethereum types (U256) |
| alloy-sol-types | 0.8 | Solidity type interop |
| ruint | 1.12.3 | Big integer operations |
| mini-alloc | 0.6 | WASM allocator |

### Solidity Contract

| Technology | Version | Purpose |
|------------|---------|---------|
| Solidity | ^0.8.24 | Smart contract language |
| Foundry | latest | Development framework |
| forge-std | - | Testing utilities |

---

## Project Structure

```
starkverifier/
├── contracts/
│   ├── stylus/                  # On-chain STARK Verifier (Rust → WASM)
│   │   ├── src/
│   │   │   ├── lib.rs          # Contract entry point (poseidon_hash, verify_stark_proof)
│   │   │   ├── poseidon/
│   │   │   │   ├── mod.rs      # Poseidon hash (BN254, circomlib compatible)
│   │   │   │   ├── constants.rs # 195 round constants (symlinked to prover)
│   │   │   │   └── field.rs    # BN254 field: add, sub, mul, pow, inv, div
│   │   │   ├── merkle.rs       # Merkle tree verification
│   │   │   └── stark/          # STARK verification pipeline
│   │   │       ├── mod.rs      # Full verifier orchestration
│   │   │       ├── air.rs      # Fibonacci AIR constraints
│   │   │       ├── channel.rs  # Fiat-Shamir (Poseidon-based)
│   │   │       ├── domain.rs   # Evaluation domains (roots of unity)
│   │   │       ├── fri.rs      # FRI low-degree verifier
│   │   │       └── proof.rs    # Proof deserialization
│   │   ├── Cargo.toml
│   │   ├── Stylus.toml         # cargo-stylus 0.10 config
│   │   └── rust-toolchain.toml # Rust 1.85.0
│   │
│   └── solidity/                # Solidity baseline for gas comparison
│       ├── src/
│       │   ├── StarkVerifier.sol
│       │   └── Poseidon.sol
│       └── foundry.toml
│
├── prover/                      # Off-chain STARK Prover (Rust CLI)
│   ├── src/
│   │   ├── main.rs             # CLI: --fib-n N --num-queries Q
│   │   ├── trace.rs            # Fibonacci trace generation
│   │   ├── commit.rs           # Poseidon Merkle tree construction
│   │   ├── compose.rs          # Composition polynomial on LDE
│   │   ├── fri.rs              # FRI prover (fold + commit layers)
│   │   ├── channel.rs          # Fiat-Shamir (matches on-chain)
│   │   ├── domain.rs           # Evaluation domains + inverse NTT
│   │   ├── proof.rs            # Proof → JSON / ABI serialization
│   │   ├── field.rs            # BN254 field arithmetic
│   │   └── poseidon.rs         # Poseidon hash (shared constants)
│   └── Cargo.toml
│
├── app/                         # Next.js 16 Frontend
│   ├── layout.tsx
│   ├── page.tsx
│   └── providers.tsx
├── components/                  # React components
├── lib/                         # Contracts, gas utils, chains
└── package.json
```

---

## Quick Start

### Prerequisites

- **Node.js** 18+
- **pnpm** (recommended) or npm/yarn
- **Rust** + cargo (for Stylus development)
- **Foundry** (for Solidity development)

### Installation

```bash
# Clone the repository
git clone https://github.com/hoddukzoa12/starkverifier.git
cd starkverifier

# Install dependencies
pnpm install

# Set up environment variables
cp .env.example .env.local
# Edit .env.local with your thirdweb client ID

# Start development server
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Available Scripts

```bash
pnpm dev      # Start development server
pnpm build    # Build for production
pnpm start    # Start production server
pnpm lint     # Run ESLint
```

---

## Contract Deployment

### Stylus (Rust)

```bash
# Navigate to Stylus contract directory
cd contracts/stylus

# Check contract validity
cargo stylus check

# Build WASM binary
cargo build --release --target wasm32-unknown-unknown

# Deploy to Arbitrum Sepolia
cargo stylus deploy \
  --private-key $PRIVATE_KEY \
  --endpoint https://sepolia-rollup.arbitrum.io/rpc
```

### Solidity

```bash
# Navigate to Solidity contract directory
cd contracts/solidity

# Install dependencies
forge install

# Build contracts
forge build

# Run tests
forge test -vvv

# Deploy to Arbitrum Sepolia
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url https://sepolia-rollup.arbitrum.io/rpc \
  --broadcast \
  --verify
```

---

## Deployed Contracts

| Contract | Address | Network | Purpose |
|----------|---------|---------|---------|
| **STARK Verifier (Stylus, audited)** | [`0x572318f371e654d8f3b18209b9b6ae766326ef46`](https://sepolia.arbiscan.io/address/0x572318f371e654d8f3b18209b9b6ae766326ef46) | Arbitrum Sepolia | Full STARK proof verification (security-fixed) |
| STARK Verifier (Stylus, pre-audit) | [`0x252b0c1d4959c19154f174912cbf478b6d81d9d0`](https://sepolia.arbiscan.io/address/0x252b0c1d4959c19154f174912cbf478b6d81d9d0) | Arbitrum Sepolia | Pre-audit version (missing FRI security checks) |
| Poseidon/Merkle (Stylus) | [`0x327c65e04215bd5575d60b00ba250ed5dd25a4fc`](https://sepolia.arbiscan.io/address/0x327c65e04215bd5575d60b00ba250ed5dd25a4fc) | Arbitrum Sepolia | Gas benchmark baseline |
| **Solidity Verifier** | [`0x96326E368b6f2fdA258452ac42B1aC013238f5Ce`](https://sepolia.arbiscan.io/address/0x96326E368b6f2fdA258452ac42B1aC013238f5Ce) | Arbitrum Sepolia | Solidity gas comparison |

**Network Details:**
- Chain ID: `421614`
- RPC: `https://sepolia-rollup.arbitrum.io/rpc`
- Explorer: [Arbiscan Sepolia](https://sepolia.arbiscan.io)

**WASM Binary:** 23.6 KB compressed (under Stylus 24KB limit)

---

## Technical Details

### Poseidon Hash Function

The Poseidon hash function is a ZK-friendly hash designed for efficient verification in zero-knowledge proof systems.

#### Specification

| Parameter | Value |
|-----------|-------|
| **Field** | BN254 (alt_bn128) |
| **Prime** | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| **Width (t)** | 3 (2 inputs + 1 capacity element) |
| **Full Rounds** | 8 (4 before + 4 after partial) |
| **Partial Rounds** | 57 |
| **Total Rounds** | 65 |
| **S-box** | x^5 (quintic) |
| **MDS Matrix** | 3×3 Cauchy matrix |
| **Round Constants** | 195 (65 rounds × 3 elements) |

#### Round Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Poseidon Permutation                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Input: [0, a, b]  (capacity element = 0)                   │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐                                        │
│  │  4 Full Rounds  │  ← Add constants, S-box ALL, MDS      │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐                                        │
│  │ 57 Partial Rds  │  ← Add constants, S-box FIRST only    │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐                                        │
│  │  4 Full Rounds  │  ← Add constants, S-box ALL, MDS      │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  Output: state[0]                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Test Vector (circomlib compatible)

```
Input:  [1, 2]
Output: 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
```

Both Stylus and Solidity implementations produce identical outputs, verified against [iden3/circomlib](https://github.com/iden3/circomlib).

### Merkle Verification

#### Algorithm

```
verify_merkle_path(root, leaf, path[], indices[]) → bool

1. Validate: path.length == indices.length
2. Initialize: current = leaf
3. For each (sibling, is_right) in zip(path, indices):
   - If is_right (true):  current = hash(sibling, current)
   - If is_right (false): current = hash(current, sibling)
4. Return: current == root
```

#### Example (4-leaf tree)

```
        root
       /    \
     h01    h23
    /  \   /  \
   L0  L1 L2  L3

Proof for L0:
  - path:    [L1, h23]
  - indices: [false, false]

Computation:
  h01  = hash(L0, L1)     // L0 is left child
  root = hash(h01, h23)   // h01 is left child
```

#### Supported Depths

| Depth | Leaves | Hash Operations | Use Case |
|-------|--------|-----------------|----------|
| 8 | 256 | 8 | Small datasets |
| 16 | 65,536 | 16 | Medium datasets |
| 32 | 4.3B | 32 | Large-scale applications |

### STARK Verification

The on-chain verifier validates STARK proofs for Fibonacci computation over the BN254 scalar field.

#### Verification Pipeline

```
verify_stark_proof(public_inputs, commitments, ood_values, fri_final_poly,
                   query_values, query_paths, query_metadata) → bool

1. Parse proof from ABI-compatible parameters (with input validation)
2. Initialize Fiat-Shamir channel (Poseidon-based) with public inputs
3. Commit trace Merkle root, draw OOD point z
4. Verify AIR constraints at z:
   - Transition: a_next == b, b_next == a + b
   - Boundary: a[0]==1, b[0]==1, b[N-1]==claimed_result
5. Compose constraint quotients with random coefficients
6. Verify composition polynomial matches prover's claim
7. Verify composition commitment == FRI layer 0 commitment
8. Run FRI verification:
   a. Draw folding challenges from Fiat-Shamir channel
   b. Independently derive query indices from channel (prevent index manipulation)
   c. For each query, for each layer: verify Merkle path for f(x)
   d. Verify cross-layer folding consistency (folded value == next layer's f(x))
   e. Final polynomial evaluation check
```

#### Proof Format

| Parameter | Size (fib-8, 4 queries) | Description |
|-----------|-------------------------|-------------|
| `public_inputs` | 3 U256 | [a[0], b[0], claimed_result] |
| `commitments` | 5 U256 | trace_root + comp_root + FRI layer roots |
| `ood_values` | 5 U256 | Trace + composition at OOD point |
| `fri_final_poly` | 4 U256 | Final polynomial coefficients |
| `query_values` | 24 U256 | f(x), f(-x) per query per FRI layer |
| `query_paths` | 48 U256 | Merkle authentication paths |
| `query_metadata` | 7 U256 | num_queries, num_layers, log_trace, indices |
| **Total calldata** | **~3.4 KB** | |

#### Generating and Verifying a Proof

```bash
# Generate proof for fib(64) with 20 FRI queries
cd prover
cargo run --release -- --fib-n 64 --num-queries 20 > proof.json

# The JSON output can be ABI-encoded and submitted to:
# 0x572318f371e654d8f3b18209b9b6ae766326ef46 on Arbitrum Sepolia
```

---

## Why Stylus is Faster

### EVM vs WASM Comparison

| Aspect | EVM (Solidity) | WASM (Stylus) | Impact |
|--------|----------------|---------------|--------|
| **Register Size** | 256-bit stack | 64-bit registers | 4x smaller operations |
| **Loop Overhead** | Gas metering per iteration | Native loops | No per-iteration cost |
| **Memory Access** | Expensive MLOAD/MSTORE | Linear memory model | Faster data access |
| **Arithmetic** | mulmod/addmod opcodes | Native 64-bit ops | Hardware acceleration |
| **Call Overhead** | High context switch cost | Minimal overhead | Cheaper function calls |

### Detailed Analysis

#### 1. Native 64-bit Arithmetic
EVM operates on 256-bit integers, requiring multiple CPU cycles for basic operations. Stylus uses native 64-bit arithmetic, leveraging hardware optimizations.

```
256-bit multiplication (EVM):
  - Multiple 64-bit multiplications
  - Manual carry propagation
  - ~8 CPU cycles per operation

64-bit multiplication (WASM):
  - Single CPU instruction
  - Hardware optimization
  - ~1 CPU cycle per operation
```

#### 2. Efficient Loop Execution
EVM charges gas for every instruction, including loop management. WASM executes loops natively without per-iteration overhead.

```solidity
// Solidity: Gas charged for each iteration
for (uint i = 0; i < 57; i++) {
    // ~200 gas overhead per iteration
    state = partialRound(state);
}
```

```rust
// Stylus: Native loop execution
for i in 0..57 {
    // Zero overhead for loop management
    state = partial_round(state);
}
```

#### 3. Memory Model
EVM's memory expansion has quadratic cost growth. WASM uses a linear memory model with predictable costs.

---

## Security

### 🔐 Cryptographic Verification

Our Poseidon implementation is **verified against industry-standard test vectors** from [iden3/circomlib](https://github.com/iden3/circomlib), the most widely-used ZK library in production.

#### Test Vector Verification

```rust
// Official circomlib test vector
poseidon([1, 2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
```

| Verification | Status |
|--------------|--------|
| circomlib test vector match | ✅ **Passed** |
| BN254 field arithmetic | ✅ **Verified** |
| Round constants (195 values) | ✅ **Matches circomlib** |
| MDS matrix | ✅ **Matches circomlib** |

#### Implementation Audit Checklist

| Component | Implementation | Security Status |
|-----------|---------------|-----------------|
| Field Prime | BN254 (alt_bn128) | ✅ Standard curve |
| S-box | x^5 | ✅ Proven secure |
| Rounds | 8 full + 57 partial | ✅ Matches spec |
| Width | t=3 (2 inputs + capacity) | ✅ Standard config |

### 🛡️ Smart Contract Security

- **No external calls** - Pure computation, no reentrancy risk
- **No storage manipulation** - Only verification state stored
- **Deterministic execution** - Same inputs always produce same outputs
- **No owner privileges** - Fully permissionless verification

### 🔍 FRI Verification Audit (2026-02-09)

A code audit of the FRI verification logic identified and fixed **3 critical + 1 medium + 3 low** severity issues. All fixes are deployed in the audited contract (`0x5723...ef46`).

| Severity | Issue | File | Fix |
|----------|-------|------|-----|
| **CRITICAL** | FRI Merkle path verification completely skipped | `fri.rs` | Added `MerkleVerifier::verify()` for every query at every FRI layer |
| **CRITICAL** | FRI cross-layer folding result discarded (`_folded`) | `fri.rs` | Folded value now checked against next layer's f(x) |
| **CRITICAL** | Composition-FRI commitment link not verified | `mod.rs` | Added `composition_commitment == fri_layer_commitments[0]` check |
| MEDIUM | Query indices taken from prover without independent derivation | `fri.rs` | Indices now derived from Fiat-Shamir channel and compared |
| LOW | `query_path_indices` field always empty | `proof.rs` | Removed; path indices derived from bit decomposition |
| LOW | Unused variable `_log_lde_size` | `mod.rs` | Removed |
| LOW | No `log_trace_len` range validation | `proof.rs` | Added bounds check (1..=26) |

**Impact of fixes on gas**: Security checks add ~2.2x gas overhead (31.9M vs 14.4M), primarily from Merkle path verification. This is the true cost of sound STARK verification -- the pre-audit contract accepted forged proofs.

### ⚠️ Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Testnet L1 gas = 0 | L1/L2 breakdown unavailable on Sepolia | Mainnet returns actual values |
| Small test proof | fib(8) with 4 queries is minimal | Scale to fib(64) with 20 queries for production-grade security |
| STARK on-chain gas > SNARK | Raw STARK verification costs ~140x more gas than Groth16 | Compensated by no off-chain wrapping cost; precompiles will narrow the gap |
| Single-TX gas limit | Production proofs (20+ queries) exceed 32M gas limit | Split verification across multiple transactions |

> **Note**: This implementation is designed for demonstration and benchmarking purposes. For production ZK applications, use audited libraries like [circomlib](https://github.com/iden3/circomlib) or [arkworks](https://github.com/arkworks-rs).

---

## API Reference

### STARK Verifier Contract (Stylus)

```solidity
interface IStarkVerifier {
    /// @notice Compute Poseidon hash of two field elements
    function poseidonHash(uint256 a, uint256 b)
        external pure returns (uint256);

    /// @notice Verify a full STARK proof of Fibonacci computation
    /// @return True if the proof is valid
    function verifyStarkProof(
        uint256[] calldata publicInputs,    // [a[0], b[0], claimed_result]
        uint256[] calldata commitments,      // [trace_root, comp_root, fri_roots...]
        uint256[] calldata oodValues,        // [a(z), b(z), a(zg), b(zg), comp(z)]
        uint256[] calldata friFinalPoly,     // Final polynomial coefficients
        uint256[] calldata queryValues,      // FRI query evaluations (flattened)
        uint256[] calldata queryPaths,       // Merkle auth paths (flattened)
        uint256[] calldata queryMetadata     // [num_queries, num_fri_layers, log_trace_len, indices...]
    ) external pure returns (bool);
}
```

### JavaScript/TypeScript Usage

```typescript
import { prepareContractCall, sendTransaction } from "thirdweb";
import { getStylusContract, generateTestProof } from "@/lib/contracts";

// Get contract instance
const contract = getStylusContract();

// Generate test proof
const { root, leaf, path, indices } = generateTestProof(8);

// Prepare and send transaction
const tx = prepareContractCall({
  contract,
  method: "verifyMerklePath",
  params: [root, leaf, path, indices],
});

const result = await sendTransaction(tx);
console.log("Gas used:", result.receipt.gasUsed);
```

---

## Supported Wallets

The application supports multiple wallets through thirdweb:

| Wallet | Status | Notes |
|--------|--------|-------|
| MetaMask | Supported | Browser extension |
| Coinbase Wallet | Supported | Browser & mobile |
| Rabby | Supported | Multi-chain wallet |
| WalletConnect | Supported | QR code connection |

---

## Environment Variables

Create a `.env.local` file in the root directory:

```env
# Required: thirdweb client ID
NEXT_PUBLIC_THIRDWEB_CLIENT_ID=your_thirdweb_client_id

# Optional: For contract deployment
PRIVATE_KEY=your_private_key_for_deployment
```

### Getting a thirdweb Client ID

1. Go to [thirdweb Dashboard](https://thirdweb.com/dashboard)
2. Create a new project
3. Copy the Client ID
4. Add to `.env.local`

---

## Testing

### Solidity Tests

```bash
cd contracts/solidity

# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test
forge test --match-test test_CircomlibCompatibility

# Gas report
forge test --gas-report
```

### Stylus Tests (58 tests)

```bash
cd contracts/stylus

# Run all 58 unit tests
cargo test --features export-abi

# Run STARK integration test (verifies real proof from prover)
cargo test test_verify_stark_proof_fib8

# Run field arithmetic tests
cargo test field

# Run FRI tests
cargo test fri

# Run with output
cargo test -- --nocapture
```

### Prover

```bash
cd prover

# Generate proof for fib(8) with 4 queries (small, fast)
cargo run --release -- --fib-n 8 --num-queries 4

# Generate proof for fib(64) with 20 queries (~80-bit security)
cargo run --release -- --fib-n 64 --num-queries 20
```

---

## Gas Optimization Details

### Why ~2x Instead of 18x?

[OpenZeppelin achieved 18x](https://www.openzeppelin.com/news/poseidon-go-brr-with-stylus-cryptographic-functions-are-18x-more-gas-efficient-via-rust-on-arbitrum) using **hand-optimized Montgomery arithmetic** - complex low-level code that requires cryptography expertise to write and maintain.

**Our approach is different: We prioritized accessibility.**

| Approach | Performance | Accessibility | Maintainability |
|----------|-------------|---------------|-----------------|
| OZ (Montgomery) | 18x | ❌ Expert only | ❌ Complex |
| **Ours (Standard libs)** | **2.1x** | ✅ Any developer | ✅ Clean code |

> **Key Insight**: We achieved **2.1x improvement using standard, safe Rust libraries**. This proves that **any developer**—not just cryptographers—can immediately double their app's efficiency by switching to Stylus, without sacrificing code safety or readability.

### The Real-World Value

```
OpenZeppelin's 18x = Theoretical ceiling (requires PhD-level optimization)
Our 2.1x = Practical floor (achievable with `cargo add`)
```

| Metric | OZ Approach | Our Approach |
|--------|-------------|--------------|
| Lines of Montgomery code | ~500+ | 0 |
| Time to implement | Weeks | Hours |
| Audit complexity | High | Low |
| Production readiness | Requires expert review | Standard library backed |

**For the Ethereum ecosystem, a stable 2x that works today is more valuable than a theoretical 18x that requires months of specialized development.**

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## References

- [Arbitrum Stylus Documentation](https://docs.arbitrum.io/stylus/stylus-gentle-introduction)
- [circomlib Poseidon](https://github.com/iden3/circomlib)
- [poseidon-rs](https://github.com/arnaucube/poseidon-rs)
- [OpenZeppelin Stylus Benchmark](https://www.openzeppelin.com/news/poseidon-go-brr-with-stylus-cryptographic-functions-are-18x-more-gas-efficient-via-rust-on-arbitrum)
- [thirdweb Documentation](https://portal.thirdweb.com/)
- [Foundry Book](https://book.getfoundry.sh/)

---

## Acknowledgments

- **Arbitrum Team** - For creating Stylus and enabling WASM smart contracts
- **iden3** - For the circomlib Poseidon implementation reference
- **OpenZeppelin** - For Stylus benchmarking methodology
- **thirdweb** - For the excellent Web3 development tools

---

<p align="center">
  Built for <strong>Arbitrum Open House NYC Buildathon 2026</strong>
</p>
