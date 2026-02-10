//! Merkle Path Verification
//!
//! Implements Merkle tree path verification using Poseidon hash.
//! Supports verification of membership proofs for trees of any depth.

use crate::field::Fp;

use crate::poseidon::PoseidonHasher;

/// Merkle path verifier using Poseidon hash
pub struct MerkleVerifier;

impl MerkleVerifier {
    /// Verify a Merkle proof
    ///
    /// Computes the root by hashing the leaf up the tree using the provided
    /// sibling hashes and position indicators.
    ///
    /// # Arguments
    /// * `root` - Expected Merkle root
    /// * `leaf` - Leaf value to verify
    /// * `path` - Array of sibling hashes along the path from leaf to root
    /// * `indices` - Position indicators for each level (false=left, true=right)
    ///
    /// # Returns
    /// `true` if the computed root matches the expected root
    #[inline]
    pub fn verify(root: Fp, leaf: Fp, path: &[Fp], indices: &[bool]) -> bool {
        // Path and indices must have same length
        if path.len() != indices.len() {
            return false;
        }

        // Empty path means leaf should equal root
        if path.is_empty() {
            return leaf == root;
        }

        let mut current = leaf;

        // Walk up the tree
        for (sibling, is_right) in path.iter().zip(indices.iter()) {
            current = if *is_right {
                PoseidonHasher::hash_two(*sibling, current)
            } else {
                PoseidonHasher::hash_two(current, *sibling)
            };
        }

        current == root
    }

    /// Compute Merkle root from leaves (test helper)
    #[cfg(test)]
    pub fn compute_root(leaves: &[Fp]) -> Fp {
        if leaves.is_empty() {
            return Fp::ZERO;
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level: alloc::vec::Vec<Fp> = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = alloc::vec::Vec::new();

            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                next_level.push(PoseidonHasher::hash_two(left, right));
            }

            current_level = next_level;
        }

        current_level[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::U256;

    #[test]
    fn test_empty_path() {
        let leaf = Fp::from_u256(U256::from(42u64));
        assert!(MerkleVerifier::verify(leaf, leaf, &[], &[]));
        assert!(!MerkleVerifier::verify(Fp::from_u256(U256::from(1u64)), leaf, &[], &[]));
    }

    #[test]
    fn test_simple_two_leaf_tree() {
        let leaf0 = Fp::from_u256(U256::from(100u64));
        let leaf1 = Fp::from_u256(U256::from(200u64));

        let root = PoseidonHasher::hash_two(leaf0, leaf1);

        assert!(MerkleVerifier::verify(root, leaf0, &[leaf1], &[false]));
        assert!(MerkleVerifier::verify(root, leaf1, &[leaf0], &[true]));
    }

    #[test]
    fn test_four_leaf_tree() {
        let leaves = [
            Fp::from_u256(U256::from(1u64)),
            Fp::from_u256(U256::from(2u64)),
            Fp::from_u256(U256::from(3u64)),
            Fp::from_u256(U256::from(4u64)),
        ];

        let h01 = PoseidonHasher::hash_two(leaves[0], leaves[1]);
        let h23 = PoseidonHasher::hash_two(leaves[2], leaves[3]);
        let root = PoseidonHasher::hash_two(h01, h23);

        assert!(MerkleVerifier::verify(
            root, leaves[0], &[leaves[1], h23], &[false, false]
        ));
        assert!(MerkleVerifier::verify(
            root, leaves[3], &[leaves[2], h01], &[true, true]
        ));
    }

    #[test]
    fn test_invalid_proof() {
        let leaf0 = Fp::from_u256(U256::from(100u64));
        let leaf1 = Fp::from_u256(U256::from(200u64));
        let root = PoseidonHasher::hash_two(leaf0, leaf1);

        assert!(!MerkleVerifier::verify(
            root, leaf0, &[Fp::from_u256(U256::from(999u64))], &[false]
        ));
        assert!(!MerkleVerifier::verify(root, leaf0, &[leaf1], &[true]));
    }

    #[test]
    fn test_path_indices_length_mismatch() {
        let root = Fp::from_u256(U256::from(1u64));
        let leaf = Fp::from_u256(U256::from(2u64));

        assert!(!MerkleVerifier::verify(
            root, leaf,
            &[Fp::from_u256(U256::from(3u64)), Fp::from_u256(U256::from(4u64))],
            &[false]
        ));
    }

    #[test]
    fn test_depth_8_tree() {
        let leaves: alloc::vec::Vec<Fp> = (0..256u64)
            .map(|i| Fp::from_u256(U256::from(i)))
            .collect();
        let root = MerkleVerifier::compute_root(&leaves);

        let mut path = vec![];
        let mut indices = vec![];
        let mut current_level: alloc::vec::Vec<Fp> = leaves.clone();
        let mut target_index = 0usize;

        while current_level.len() > 1 {
            let sibling_index = if target_index % 2 == 0 {
                target_index + 1
            } else {
                target_index - 1
            };

            if sibling_index < current_level.len() {
                path.push(current_level[sibling_index]);
            } else {
                path.push(current_level[target_index]);
            }
            indices.push(target_index % 2 == 1);

            let mut next_level = vec![];
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                next_level.push(PoseidonHasher::hash_two(left, right));
            }

            target_index /= 2;
            current_level = next_level;
        }

        assert!(MerkleVerifier::verify(root, leaves[0], &path, &indices));
    }
}
