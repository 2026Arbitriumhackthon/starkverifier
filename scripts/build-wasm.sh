#!/usr/bin/env bash
set -euo pipefail

# Build the STARK prover as a WASM package for frontend usage.
# Requires: rustup target add wasm32-unknown-unknown
#           cargo install wasm-bindgen-cli

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROVER_DIR="$SCRIPT_DIR/../prover"
PKG_DIR="$PROVER_DIR/pkg"

echo "Building WASM prover..."
cd "$PROVER_DIR"

# Step 1: Compile to WASM
cargo build --lib --release --target wasm32-unknown-unknown --features wasm --no-default-features

# Step 2: Generate JS bindings with wasm-bindgen
WASM_FILE="$PROVER_DIR/target/wasm32-unknown-unknown/release/stark_prover.wasm"
mkdir -p "$PKG_DIR"
wasm-bindgen "$WASM_FILE" --out-dir "$PKG_DIR" --target web --omit-default-module-path

echo "WASM build complete: prover/pkg/"
