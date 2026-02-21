//! MPT (Merkle Patricia Trie) Proof Verification
//!
//! Verifies Ethereum receipt MPT proofs on-chain using native Keccak precompile.
//! Used to verify that a transaction receipt exists in a block's receiptsRoot.

use alloc::vec;
use alloc::vec::Vec;
use alloy_primitives::U256;
use crate::field::Fp;

/// Keccak256 hash using the Stylus native precompile.
#[inline]
fn keccak256(data: &[u8]) -> [u8; 32] {
    stylus_sdk::crypto::keccak(data).0
}

/// Verify an MPT proof: verify that a key maps to a value under the given root.
///
/// Returns `Some(leaf_value)` if the proof is valid, `None` otherwise.
///
/// # Arguments
/// * `root` - Expected Merkle Patricia Trie root (32 bytes)
/// * `key` - Key to look up (RLP-encoded transaction index)
/// * `proof_nodes` - Sequence of RLP-encoded trie nodes from root to leaf
pub fn verify_mpt_proof(
    root: &[u8; 32],
    key: &[u8],
    proof_nodes: &[Vec<u8>],
) -> Option<Vec<u8>> {
    if proof_nodes.is_empty() {
        return None;
    }

    let key_nibbles = bytes_to_nibbles(key);
    let mut key_offset = 0;
    let mut expected_hash = *root;

    for node_rlp in proof_nodes {
        // Verify the node hash matches expected
        if node_rlp.len() >= 32 {
            let node_hash = keccak256(node_rlp);
            if node_hash != expected_hash {
                return None;
            }
        }

        let items = rlp_decode_list(node_rlp)?;

        match items.len() {
            17 => {
                // Branch node: 16 children + value
                if key_offset >= key_nibbles.len() {
                    return Some(items[16].clone());
                }
                let nibble = key_nibbles[key_offset] as usize;
                if nibble >= 16 {
                    return None;
                }
                key_offset += 1;

                let child = &items[nibble];
                if child.is_empty() {
                    return None;
                }
                if child.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(child);
                    expected_hash = hash;
                } else {
                    expected_hash = [0u8; 32];
                }
            }
            2 => {
                // Extension or Leaf node
                let (prefix_nibbles, is_leaf) = decode_hp_prefix(&items[0])?;

                for nibble in &prefix_nibbles {
                    if key_offset >= key_nibbles.len() || key_nibbles[key_offset] != *nibble {
                        return None;
                    }
                    key_offset += 1;
                }

                if is_leaf {
                    if key_offset == key_nibbles.len() {
                        return Some(items[1].clone());
                    }
                    return None;
                }

                // Extension node
                let child = &items[1];
                if child.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(child);
                    expected_hash = hash;
                } else {
                    expected_hash = [0u8; 32];
                }
            }
            _ => return None,
        }
    }

    None
}

/// Compute dataset_commitment = keccak(blockHash, keccak(receiptsRoot, receiptHash))
///
/// This must produce identical output to the prover's compute_dataset_commitment.
pub fn compute_dataset_commitment_onchain(
    block_hash: U256,
    receipts_root: &[u8; 32],
    receipt_rlp: &[u8],
) -> Fp {
    // receiptHash = keccak256(receipt_rlp)
    let receipt_hash = keccak256(receipt_rlp);

    // inner = keccak256(receiptsRoot || receiptHash)
    let mut inner_buf = [0u8; 64];
    inner_buf[..32].copy_from_slice(receipts_root);
    inner_buf[32..].copy_from_slice(&receipt_hash);
    let inner = keccak256(&inner_buf);

    // outer = keccak256(blockHash || inner)
    let mut outer_buf = [0u8; 64];
    outer_buf[..32].copy_from_slice(&block_hash.to_be_bytes::<32>());
    outer_buf[32..].copy_from_slice(&inner);
    let raw = U256::from_be_bytes(keccak256(&outer_buf));

    Fp::from_u256(raw)
}

/// Convert bytes to nibbles (half-bytes).
fn bytes_to_nibbles(data: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(data.len() * 2);
    for byte in data {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Decode hex prefix encoding used in MPT leaf/extension nodes.
fn decode_hp_prefix(encoded: &[u8]) -> Option<(Vec<u8>, bool)> {
    if encoded.is_empty() {
        return None;
    }
    let first_nibble = encoded[0] >> 4;
    let is_leaf = first_nibble >= 2;
    let is_odd = first_nibble & 1 == 1;

    let mut nibbles = Vec::new();
    if is_odd {
        nibbles.push(encoded[0] & 0x0f);
    }
    for byte in &encoded[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }

    Some((nibbles, is_leaf))
}

/// Decode an RLP list into its items (raw bytes).
fn rlp_decode_list(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.is_empty() {
        return None;
    }

    let (payload, _) = decode_rlp_length(data)?;
    let mut items = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let (item, consumed) = decode_rlp_item(&payload[offset..])?;
        items.push(item);
        offset += consumed;
    }

    Some(items)
}

fn decode_rlp_length(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.is_empty() {
        return None;
    }
    let prefix = data[0];

    if prefix <= 0x7f {
        Some((&data[0..1], 1))
    } else if prefix <= 0xb7 {
        let len = (prefix - 0x80) as usize;
        if data.len() < 1 + len { return None; }
        Some((&data[1..1 + len], 1 + len))
    } else if prefix <= 0xbf {
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len { return None; }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len { return None; }
        Some((&data[1 + len_of_len..1 + len_of_len + len], 1 + len_of_len + len))
    } else if prefix <= 0xf7 {
        let len = (prefix - 0xc0) as usize;
        if data.len() < 1 + len { return None; }
        Some((&data[1..1 + len], 1 + len))
    } else {
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len { return None; }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len { return None; }
        Some((&data[1 + len_of_len..1 + len_of_len + len], 1 + len_of_len + len))
    }
}

fn decode_rlp_item(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    if data.is_empty() {
        return None;
    }
    let prefix = data[0];

    if prefix <= 0x7f {
        Some((vec![prefix], 1))
    } else if prefix <= 0xb7 {
        let len = (prefix - 0x80) as usize;
        if data.len() < 1 + len { return None; }
        Some((data[1..1 + len].to_vec(), 1 + len))
    } else if prefix <= 0xbf {
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len { return None; }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len { return None; }
        Some((data[1 + len_of_len..1 + len_of_len + len].to_vec(), 1 + len_of_len + len))
    } else if prefix <= 0xf7 {
        let len = (prefix - 0xc0) as usize;
        if data.len() < 1 + len { return None; }
        Some((data[..1 + len].to_vec(), 1 + len))
    } else {
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len { return None; }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len { return None; }
        Some((data[..1 + len_of_len + len].to_vec(), 1 + len_of_len + len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_nibbles() {
        assert_eq!(bytes_to_nibbles(&[0xab, 0xcd]), vec![0xa, 0xb, 0xc, 0xd]);
    }

    #[test]
    fn test_decode_hp_prefix_leaf() {
        let (nibbles, is_leaf) = decode_hp_prefix(&[0x20, 0xab]).unwrap();
        assert!(is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb]);
    }

    #[test]
    fn test_decode_hp_prefix_extension() {
        let (nibbles, is_leaf) = decode_hp_prefix(&[0x00, 0xab]).unwrap();
        assert!(!is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb]);
    }

    #[test]
    fn test_rlp_decode_simple_list() {
        let data = vec![0xc2, 0x01, 0x02];
        let items = rlp_decode_list(&data).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], vec![0x01]);
        assert_eq!(items[1], vec![0x02]);
    }

    #[test]
    fn test_compute_dataset_commitment_onchain_deterministic() {
        let block_hash = U256::from(0x1234u64);
        let receipts_root = [0xabu8; 32];
        let receipt_rlp = b"test_data";

        let c1 = compute_dataset_commitment_onchain(block_hash, &receipts_root, receipt_rlp);
        let c2 = compute_dataset_commitment_onchain(block_hash, &receipts_root, receipt_rlp);
        assert_eq!(c1, c2);
    }
}
