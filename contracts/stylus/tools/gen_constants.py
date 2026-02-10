#!/usr/bin/env python3
"""Generate Montgomery form constants for BN254 scalar field.

Reads the existing constants.rs and outputs Montgomery form values
for use in the optimized Fp implementation.
"""

import re
import sys

# BN254 scalar field prime
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Montgomery constant: R = 2^256 mod p
R = pow(2, 256, p)

# R^2 mod p (used for converting to Montgomery form)
R2 = pow(R, 2, p)

# -p^{-1} mod 2^64
def compute_inv(p_val):
    """Compute -p^{-1} mod 2^64 using Hensel's lifting."""
    W = 1 << 64
    p0 = p_val % W
    # Start with inverse mod 2
    inv = 1
    for i in range(6):  # 6 iterations: 2^(2^6) = 2^64
        inv = (inv * (2 - p0 * inv)) % W
    # Verify: p0 * inv ≡ 1 (mod 2^64)
    assert (p0 * inv) % W == 1, f"inv computation failed"
    # We want -p^{-1} mod 2^64
    return (W - inv) % W

INV = compute_inv(p)

def limbs_to_int(limbs):
    """Convert [u64; 4] little-endian limbs to Python int."""
    return limbs[0] + (limbs[1] << 64) + (limbs[2] << 128) + (limbs[3] << 192)

def int_to_limbs(n):
    """Convert Python int to [u64; 4] little-endian limbs."""
    mask = (1 << 64) - 1
    return [n & mask, (n >> 64) & mask, (n >> 128) & mask, (n >> 192) & mask]

def to_mont(val):
    """Convert value to Montgomery form: val * R mod p."""
    return (val * R) % p

def format_fp(limbs):
    """Format limbs as Fp::from_raw([...])."""
    return f"Fp::from_raw([0x{limbs[0]:016x}, 0x{limbs[1]:016x}, 0x{limbs[2]:016x}, 0x{limbs[3]:016x}])"

def format_u64_limbs(limbs):
    """Format limbs as [u64; 4] array."""
    return f"[0x{limbs[0]:016x}, 0x{limbs[1]:016x}, 0x{limbs[2]:016x}, 0x{limbs[3]:016x}]"

def verify_inv(p_val, inv_val):
    """Verify that p[0] * INV ≡ -1 (mod 2^64)."""
    p0 = p_val % (1 << 64)
    product = (p0 * inv_val) % (1 << 64)
    expected = (1 << 64) - 1  # -1 mod 2^64
    assert product == expected, f"INV verification failed: {product:#x} != {expected:#x}"

# Verify INV
verify_inv(p, INV)

# --- Print Montgomery parameters ---
print("=" * 60)
print("Montgomery Parameters for BN254 Fr")
print("=" * 60)

R_limbs = int_to_limbs(R)
R2_limbs = int_to_limbs(R2)

print(f"\n// MODULUS (p)")
print(f"const MODULUS: [u64; 4] = {format_u64_limbs(int_to_limbs(p))};")
print(f"\n// INV = -p^{{-1}} mod 2^64")
print(f"const INV: u64 = 0x{INV:016x};")
print(f"\n// R^2 mod p (for converting to Montgomery form)")
print(f"const R2: [u64; 4] = {format_u64_limbs(R2_limbs)};")
print(f"\n// Fp::ONE = R mod p (1 in Montgomery form)")
print(f"pub const ONE: Fp = Fp({format_u64_limbs(R_limbs)});")

# --- Verify with test vector ---
# Verify: 1 in Montgomery form should be R mod p
one_mont = to_mont(1)
assert one_mont == R, f"1 in Montgomery != R: {one_mont} != {R}"

# Verify: 2 in Montgomery form
two_mont = to_mont(2)
two_limbs = int_to_limbs(two_mont)
print(f"\n// 2 in Montgomery form (for verification)")
print(f"// {format_fp(two_limbs)}")

# --- Parse and convert round constants ---
constants_path = sys.argv[1] if len(sys.argv) > 1 else "src/poseidon/constants.rs"
with open(constants_path) as f:
    content = f.read()

pattern = r'U256::from_limbs\(\[(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+)\]\)'
matches = re.findall(pattern, content)

print(f"\nFound {len(matches)} U256::from_limbs entries in {constants_path}")
assert len(matches) >= 195 + 9, f"Expected at least 204 entries, found {len(matches)}"

# --- Round constants ---
print("\n" + "=" * 60)
print("Round Constants in Montgomery Form")
print("=" * 60)
print(f"\npub const ROUND_CONSTANTS: [Fp; 195] = [")

round_names = {
    0: "Round 0 (Full)", 3: "Round 1 (Full)", 6: "Round 2 (Full)", 9: "Round 3 (Full)",
    12: "Partial rounds (rounds 4-60, 57 rounds)",
}
full_round_2_start = None

for i in range(195):
    limbs = [int(x, 16) for x in matches[i]]
    val = limbs_to_int(limbs)
    mont_val = to_mont(val)
    mont_limbs = int_to_limbs(mont_val)

    if i in round_names:
        print(f"    // {round_names[i]}")

    # Detect the second half of full rounds
    if i == 183:
        print(f"    // Round 61-64 (Full - second half)")

    print(f"    {format_fp(mont_limbs)},")

print("];")

# --- MDS matrix ---
print("\n" + "=" * 60)
print("MDS Matrix in Montgomery Form")
print("=" * 60)
print(f"\npub const MDS_MATRIX: [[Fp; 3]; 3] = [")

for row in range(3):
    print("    [")
    for col in range(3):
        idx = 195 + row * 3 + col
        limbs = [int(x, 16) for x in matches[idx]]
        val = limbs_to_int(limbs)
        mont_val = to_mont(val)
        mont_limbs = int_to_limbs(mont_val)
        comma = "," if col < 2 else ""
        print(f"        {format_fp(mont_limbs)}{comma}")
    end = "," if row < 2 else ""
    print(f"    ]{end}")

print("];")

# --- Domain generator ---
print("\n" + "=" * 60)
print("Other Constants in Montgomery Form")
print("=" * 60)

# GENERATOR_2_28
gen_limbs = [0x9bd61b6e725b19f0, 0x402d111e41112ed4, 0x00e0a7eb8ef62abc, 0x2a3c09f0a58a7e85]
gen_val = limbs_to_int(gen_limbs)
gen_mont = to_mont(gen_val)
gen_mont_limbs = int_to_limbs(gen_mont)
print(f"\n// GENERATOR_2_28 in Montgomery form")
print(f"pub const GENERATOR_2_28: Fp = {format_fp(gen_mont_limbs)};")

# INV_TWO = (p+1)/2
inv_two_limbs = [0xa1f0fac9f8000001, 0x9419f4243cdcb848, 0xdc2822db40c0ac2e, 0x183227397098d014]
inv_two_val = limbs_to_int(inv_two_limbs)
# Verify: 2 * inv_two_val mod p == 1
assert (2 * inv_two_val) % p == 1, "INV_TWO verification failed"
inv_two_mont = to_mont(inv_two_val)
inv_two_mont_limbs = int_to_limbs(inv_two_mont)
print(f"\n// INV_TWO = (p+1)/2 in Montgomery form")
print(f"const INV_TWO: Fp = {format_fp(inv_two_mont_limbs)};")

# Verify Montgomery arithmetic
# mont(a) * mont(b) should, when reduced, give mont(a*b)
# But the actual check is: to_mont(a) * to_mont(b) in Montgomery mul = to_mont(a*b)
print("\n" + "=" * 60)
print("Verification")
print("=" * 60)

# poseidon([1, 2]) test - the hash should still match after all conversions
# We can't easily verify Poseidon here, but we can verify the basic arithmetic

# Verify: R * R * R^{-1} mod p = R (i.e., mont_mul(R, R) should give R^2 * R^{-1} = R)
# Actually, if we have a in Montgomery form (a*R mod p) and b in Montgomery form (b*R mod p),
# then mont_mul(a_mont, b_mont) = a_mont * b_mont * R^{-1} mod p = a*R * b*R * R^{-1} = a*b*R mod p
# which is the Montgomery form of a*b. Correct.

# Verify ONE*ONE = ONE (R * R * R^{-1} = R)
print(f"\nVerification: R * R * R^{{-1}} mod p = R")
product = (R * R * pow(R, p - 2, p)) % p
assert product == R, f"Failed: {product} != {R}"
print("PASSED")

# Verify round-trip: to_mont(42) -> from_mont -> 42
val42 = 42
mont42 = to_mont(val42)
# from_mont: mont42 * R^{-1} mod p = 42 * R * R^{-1} = 42
from42 = (mont42 * pow(R, p - 2, p)) % p
assert from42 == val42, f"Round-trip failed: {from42} != {val42}"
print(f"Round-trip for 42: PASSED")

print("\nAll verifications passed!")
