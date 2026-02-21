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

/// Decode flattened U256 words back to Vec<Vec<u8>> proof nodes.
///
/// Format: [num_nodes, len_0, len_1, ..., len_{n-1}, packed_data_words...]
/// The packed data words contain all node bytes concatenated, padded to 32-byte words.
pub fn decode_proof_nodes(words: &[U256], total_len: usize) -> Option<Vec<Vec<u8>>> {
    if words.is_empty() {
        return None;
    }

    let num_nodes = words[0].as_limbs()[0] as usize;
    if num_nodes == 0 || words.len() < 1 + num_nodes {
        return None;
    }

    // Read node lengths from header
    let mut node_lengths = Vec::with_capacity(num_nodes);
    for i in 0..num_nodes {
        node_lengths.push(words[1 + i].as_limbs()[0] as usize);
    }

    // Verify total length consistency
    let computed_total: usize = node_lengths.iter().sum();
    if computed_total != total_len {
        return None;
    }

    // Decode packed data from remaining words
    let data_words = &words[1 + num_nodes..];
    let mut all_data = Vec::with_capacity(total_len);
    for word in data_words {
        let word_bytes = word.to_be_bytes::<32>();
        all_data.extend_from_slice(&word_bytes);
    }
    all_data.truncate(total_len);

    // Split data into individual nodes by their lengths
    let mut nodes = Vec::with_capacity(num_nodes);
    let mut offset = 0;
    for len in &node_lengths {
        if offset + len > all_data.len() {
            return None;
        }
        nodes.push(all_data[offset..offset + len].to_vec());
        offset += len;
    }

    Some(nodes)
}

/// Compute merkle root for a column where all leaves have the same value.
///
/// Uses O(log n) keccak hashes (constant-leaf tree optimization).
/// For a tree of size 2^log_size, if every leaf = v, then:
///   level 0: leaf = v
///   level 1: hash(v, v)
///   level 2: hash(hash(v,v), hash(v,v))
///   ...
pub fn compute_constant_merkle_root(leaf_value: Fp, log_size: u32) -> Fp {
    let mut current = leaf_value;
    for _ in 0..log_size {
        current = crate::keccak_hash_two(current, current);
    }
    current
}

/// Decode U256 words to a flat byte array, truncating to actual_len.
pub fn decode_u256_words(words: &[U256], actual_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(actual_len);
    for word in words {
        let word_bytes = word.to_be_bytes::<32>();
        result.extend_from_slice(&word_bytes);
    }
    result.truncate(actual_len);
    result
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

    #[test]
    fn test_decode_proof_nodes_basic() {
        // Create a simple proof with 2 nodes: [0x01, 0x02] and [0x03, 0x04, 0x05]
        let node1 = vec![0x01u8, 0x02];
        let node2 = vec![0x03u8, 0x04, 0x05];
        let total_len = node1.len() + node2.len(); // 5

        // Header: [num_nodes=2, len_0=2, len_1=3]
        let mut words = vec![
            U256::from(2u64),  // num_nodes
            U256::from(2u64),  // len_0
            U256::from(3u64),  // len_1
        ];

        // Pack data into U256 word (all 5 bytes fit in one word)
        let mut data_buf = [0u8; 32];
        data_buf[0] = 0x01; data_buf[1] = 0x02;
        data_buf[2] = 0x03; data_buf[3] = 0x04; data_buf[4] = 0x05;
        words.push(U256::from_be_bytes(data_buf));

        let result = decode_proof_nodes(&words, total_len).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], vec![0x01, 0x02]);
        assert_eq!(result[1], vec![0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_decode_proof_nodes_empty() {
        assert!(decode_proof_nodes(&[], 0).is_none());
    }

    #[test]
    fn test_decode_proof_nodes_length_mismatch() {
        let words = vec![
            U256::from(1u64),  // num_nodes
            U256::from(5u64),  // len_0 = 5
        ];
        // total_len doesn't match
        assert!(decode_proof_nodes(&words, 3).is_none());
    }

    #[test]
    fn test_compute_constant_merkle_root_log0() {
        // log_size=0 → single leaf, root = leaf
        let leaf = Fp::from_u256(U256::from(42u64));
        let root = compute_constant_merkle_root(leaf, 0);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_compute_constant_merkle_root_log1() {
        // log_size=1 → 2 leaves, root = hash(leaf, leaf)
        let leaf = Fp::from_u256(U256::from(42u64));
        let root = compute_constant_merkle_root(leaf, 1);
        let expected = crate::keccak_hash_two(leaf, leaf);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_compute_constant_merkle_root_log2() {
        // log_size=2 → 4 leaves, root = hash(hash(leaf,leaf), hash(leaf,leaf))
        let leaf = Fp::from_u256(U256::from(42u64));
        let root = compute_constant_merkle_root(leaf, 2);
        let l1 = crate::keccak_hash_two(leaf, leaf);
        let expected = crate::keccak_hash_two(l1, l1);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_decode_u256_words() {
        let mut word_bytes = [0u8; 32];
        word_bytes[0] = 0xAB;
        word_bytes[1] = 0xCD;
        word_bytes[2] = 0xEF;
        let words = vec![U256::from_be_bytes(word_bytes)];
        let result = decode_u256_words(&words, 3);
        assert_eq!(result, vec![0xAB, 0xCD, 0xEF]);
    }
}
