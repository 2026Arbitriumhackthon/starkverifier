//! Receipt Proof Module
//!
//! Provides MPT (Merkle Patricia Trie) proof verification for Ethereum transaction receipts,
//! and computes `dataset_commitment` values that bind receipt data provenance to STARK proofs.
//!
//! The dataset_commitment is computed as:
//!   `keccak(blockHash, keccak(receiptsRoot, receiptHash))`
//!
//! where receiptHash = keccak256(receipt_rlp).

use alloy_primitives::U256;
use tiny_keccak::{Hasher, Keccak};

use crate::field::BN254_PRIME;

/// Receipt proof data for a single transaction.
pub struct ReceiptProofData {
    /// Block hash containing the transaction
    pub block_hash: U256,
    /// Block number
    pub block_number: u64,
    /// receiptsRoot from the block header
    pub receipts_root: [u8; 32],
    /// MPT proof nodes (RLP-encoded)
    pub receipt_proof_nodes: Vec<Vec<u8>>,
    /// RLP-encoded key (transaction index in the trie)
    pub receipt_key: Vec<u8>,
    /// Full RLP-encoded receipt
    pub receipt_rlp: Vec<u8>,
}

/// Keccak256 of a byte slice.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Compute dataset_commitment = keccak(blockHash, keccak(receiptsRoot, receiptHash)) mod BN254.
///
/// This binds the receipt data to a specific block, proving data provenance.
pub fn compute_dataset_commitment(
    block_hash: U256,
    receipts_root: &[u8; 32],
    receipt_rlp: &[u8],
) -> U256 {
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

    // Reduce mod BN254 to get a valid field element
    raw.mul_mod(U256::from(1u64), BN254_PRIME)
}

/// Verify a receipt MPT proof against the receipts_root.
///
/// Traverses the trie from root to leaf using the provided proof nodes,
/// verifying keccak hashes at each step.
///
/// Returns `Some(leaf_value)` if the proof is valid, `None` otherwise.
pub fn verify_receipt_proof(proof: &ReceiptProofData) -> Option<Vec<u8>> {
    if proof.receipt_proof_nodes.is_empty() {
        return None;
    }

    let key_nibbles = bytes_to_nibbles(&proof.receipt_key);
    let mut key_offset = 0;
    let mut expected_hash = proof.receipts_root;

    for node_rlp in &proof.receipt_proof_nodes {
        // Verify the node hash matches expected
        let node_hash = keccak256(node_rlp);
        // For the root node and intermediate nodes, hash must match.
        // Short nodes (< 32 bytes) may be embedded inline.
        if node_rlp.len() >= 32 && node_hash != expected_hash {
            return None;
        }

        let items = rlp_decode_list(node_rlp)?;

        match items.len() {
            17 => {
                // Branch node: 16 children + value
                if key_offset >= key_nibbles.len() {
                    // We're at the end of the key, return the value
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
                    expected_hash.copy_from_slice(child);
                } else {
                    // Embedded node (< 32 bytes) — skip hash check for next iteration
                    expected_hash = [0u8; 32];
                }
            }
            2 => {
                // Extension or Leaf node
                let (prefix_nibbles, is_leaf) = decode_hp_prefix(&items[0])?;

                // Verify key path matches
                for nibble in &prefix_nibbles {
                    if key_offset >= key_nibbles.len() || key_nibbles[key_offset] != *nibble {
                        return None;
                    }
                    key_offset += 1;
                }

                if is_leaf {
                    // Leaf node — return the value
                    if key_offset == key_nibbles.len() {
                        return Some(items[1].clone());
                    }
                    return None;
                }

                // Extension node — follow the child
                let child = &items[1];
                if child.len() == 32 {
                    expected_hash.copy_from_slice(child);
                } else {
                    expected_hash = [0u8; 32];
                }
            }
            _ => return None,
        }
    }

    None
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
/// Returns (nibbles, is_leaf).
fn decode_hp_prefix(encoded: &[u8]) -> Option<(Vec<u8>, bool)> {
    if encoded.is_empty() {
        return None;
    }
    let first_nibble = encoded[0] >> 4;
    let is_leaf = first_nibble >= 2;
    let is_odd = first_nibble & 1 == 1;

    let mut nibbles = Vec::new();
    if is_odd {
        // Odd: first byte's low nibble is part of the path
        nibbles.push(encoded[0] & 0x0f);
    }
    // Remaining bytes
    for byte in &encoded[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }

    Some((nibbles, is_leaf))
}

/// Decode an RLP list into its items (raw bytes).
/// Returns None if the data is not a valid RLP list.
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

/// Decode the length prefix of an RLP item.
/// Returns (payload_slice, total_consumed).
fn decode_rlp_length(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.is_empty() {
        return None;
    }

    let prefix = data[0];

    if prefix <= 0x7f {
        // Single byte
        Some((&data[0..1], 1))
    } else if prefix <= 0xb7 {
        // Short string (0-55 bytes)
        let len = (prefix - 0x80) as usize;
        if data.len() < 1 + len {
            return None;
        }
        Some((&data[1..1 + len], 1 + len))
    } else if prefix <= 0xbf {
        // Long string
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return None;
        }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len {
            return None;
        }
        Some((&data[1 + len_of_len..1 + len_of_len + len], 1 + len_of_len + len))
    } else if prefix <= 0xf7 {
        // Short list (0-55 bytes payload)
        let len = (prefix - 0xc0) as usize;
        if data.len() < 1 + len {
            return None;
        }
        Some((&data[1..1 + len], 1 + len))
    } else {
        // Long list
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return None;
        }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len {
            return None;
        }
        Some((&data[1 + len_of_len..1 + len_of_len + len], 1 + len_of_len + len))
    }
}

/// Decode a single RLP item from data, returning (decoded_bytes, bytes_consumed).
fn decode_rlp_item(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    if data.is_empty() {
        return None;
    }

    let prefix = data[0];

    if prefix <= 0x7f {
        // Single byte
        Some((vec![prefix], 1))
    } else if prefix <= 0xb7 {
        // Short string (0-55 bytes)
        let len = (prefix - 0x80) as usize;
        if data.len() < 1 + len {
            return None;
        }
        Some((data[1..1 + len].to_vec(), 1 + len))
    } else if prefix <= 0xbf {
        // Long string
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return None;
        }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len {
            return None;
        }
        Some((data[1 + len_of_len..1 + len_of_len + len].to_vec(), 1 + len_of_len + len))
    } else if prefix <= 0xf7 {
        // Short list — return the whole encoded list as raw bytes
        let len = (prefix - 0xc0) as usize;
        if data.len() < 1 + len {
            return None;
        }
        Some((data[..1 + len].to_vec(), 1 + len))
    } else {
        // Long list — return the whole encoded list as raw bytes
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return None;
        }
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | (data[1 + i] as usize);
        }
        if data.len() < 1 + len_of_len + len {
            return None;
        }
        Some((data[..1 + len_of_len + len].to_vec(), 1 + len_of_len + len))
    }
}

/// RLP-encode an integer as a key for receipt trie lookup.
/// Transaction indices in the receipt trie are RLP-encoded as integers.
pub fn rlp_encode_tx_index(index: u64) -> Vec<u8> {
    if index == 0 {
        return vec![0x80]; // RLP encoding of empty string (zero)
    }
    let bytes = {
        let mut buf = index.to_be_bytes().to_vec();
        while buf.first() == Some(&0) {
            buf.remove(0);
        }
        buf
    };
    if bytes.len() == 1 && bytes[0] <= 0x7f {
        bytes
    } else {
        let mut encoded = vec![0x80 + bytes.len() as u8];
        encoded.extend_from_slice(&bytes);
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_dataset_commitment_deterministic() {
        let block_hash = U256::from(0x1234u64);
        let receipts_root = [0xabu8; 32];
        let receipt_rlp = b"some_receipt_data";

        let c1 = compute_dataset_commitment(block_hash, &receipts_root, receipt_rlp);
        let c2 = compute_dataset_commitment(block_hash, &receipts_root, receipt_rlp);
        assert_eq!(c1, c2);
        assert!(c1 < BN254_PRIME);
    }

    #[test]
    fn test_compute_dataset_commitment_different_inputs() {
        let block_hash_1 = U256::from(0x1234u64);
        let block_hash_2 = U256::from(0x5678u64);
        let receipts_root = [0xabu8; 32];
        let receipt_rlp = b"some_receipt_data";

        let c1 = compute_dataset_commitment(block_hash_1, &receipts_root, receipt_rlp);
        let c2 = compute_dataset_commitment(block_hash_2, &receipts_root, receipt_rlp);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_rlp_encode_tx_index() {
        assert_eq!(rlp_encode_tx_index(0), vec![0x80]);
        assert_eq!(rlp_encode_tx_index(1), vec![0x01]);
        assert_eq!(rlp_encode_tx_index(127), vec![0x7f]);
        assert_eq!(rlp_encode_tx_index(128), vec![0x81, 0x80]);
    }

    #[test]
    fn test_bytes_to_nibbles() {
        assert_eq!(bytes_to_nibbles(&[0xab, 0xcd]), vec![0xa, 0xb, 0xc, 0xd]);
        assert_eq!(bytes_to_nibbles(&[0x01]), vec![0x0, 0x1]);
    }

    #[test]
    fn test_decode_hp_prefix_leaf_even() {
        // 0x20 prefix = leaf, even length
        let (nibbles, is_leaf) = decode_hp_prefix(&[0x20, 0xab]).unwrap();
        assert!(is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb]);
    }

    #[test]
    fn test_decode_hp_prefix_leaf_odd() {
        // 0x3a prefix = leaf, odd length, first nibble = a
        let (nibbles, is_leaf) = decode_hp_prefix(&[0x3a, 0xbc]).unwrap();
        assert!(is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb, 0xc]);
    }

    #[test]
    fn test_decode_hp_prefix_extension_even() {
        // 0x00 prefix = extension, even length
        let (nibbles, is_leaf) = decode_hp_prefix(&[0x00, 0xab]).unwrap();
        assert!(!is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb]);
    }

    #[test]
    fn test_rlp_decode_list_simple() {
        // RLP: [0x01, 0x02] → list prefix 0xc2, items 0x01, 0x02
        let data = vec![0xc2, 0x01, 0x02];
        let items = rlp_decode_list(&data).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], vec![0x01]);
        assert_eq!(items[1], vec![0x02]);
    }

    #[test]
    fn test_rlp_decode_list_empty_string() {
        // RLP: [""] → list prefix 0xc1, empty string 0x80
        let data = vec![0xc1, 0x80];
        let items = rlp_decode_list(&data).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], Vec::<u8>::new());
    }
}
