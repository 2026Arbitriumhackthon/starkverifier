//! Keccak256 Merkle Tree Commitment
//!
//! Builds Merkle trees using Keccak256 hash and generates authentication paths
//! for the STARK prover.

use alloy_primitives::U256;
use crate::keccak::keccak_hash_two;

/// A Keccak256 Merkle tree for committing to polynomial evaluations.
pub struct MerkleTree {
    /// All tree nodes, stored level by level from leaves to root.
    /// nodes[0..n] = leaves, nodes[n..n+n/2] = level 1, etc.
    nodes: Vec<U256>,
    /// Number of leaves (must be power of 2)
    num_leaves: usize,
    /// Depth of the tree
    depth: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf values.
    ///
    /// # Arguments
    /// * `leaves` - Leaf values (length must be power of 2)
    pub fn build(leaves: &[U256]) -> Self {
        let n = leaves.len();
        assert!(n.is_power_of_two(), "Number of leaves must be power of 2");
        let depth = (n as f64).log2() as usize;

        // Total nodes = 2*n - 1 (all levels)
        let mut nodes = Vec::with_capacity(2 * n);

        // Copy leaves
        nodes.extend_from_slice(leaves);

        // Build each level
        let mut level_start = 0;
        let mut level_size = n;

        while level_size > 1 {
            let next_size = level_size / 2;
            for i in 0..next_size {
                let left = nodes[level_start + 2 * i];
                let right = nodes[level_start + 2 * i + 1];
                nodes.push(keccak_hash_two(left, right));
            }
            level_start += level_size;
            level_size = next_size;
        }

        MerkleTree {
            nodes,
            num_leaves: n,
            depth,
        }
    }

    /// Get the Merkle root.
    pub fn root(&self) -> U256 {
        *self.nodes.last().unwrap()
    }

    /// Generate an authentication path for a leaf at the given index.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf (0-based)
    ///
    /// # Returns
    /// (path, indices) where:
    ///   - path: sibling hashes from leaf to root
    ///   - indices: position indicators (false=left, true=right)
    pub fn auth_path(&self, leaf_index: usize) -> (Vec<U256>, Vec<bool>) {
        assert!(leaf_index < self.num_leaves);

        let mut path = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);

        let mut idx = leaf_index;
        let mut level_start = 0;
        let mut level_size = self.num_leaves;

        for _ in 0..self.depth {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            path.push(self.nodes[level_start + sibling_idx]);
            indices.push(idx % 2 == 1); // true if current is right child

            level_start += level_size;
            level_size /= 2;
            idx /= 2;
        }

        (path, indices)
    }

    /// Get the leaf value at a given index.
    pub fn leaf(&self, index: usize) -> U256 {
        self.nodes[index]
    }

    /// Get number of leaves.
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Get tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// Build a Merkle tree from multiple columns of trace evaluations.
/// Each leaf is the chain-hash of all columns: keccak(keccak(...keccak(c0, c1), c2)..., cN).
pub fn commit_trace_multi(cols: &[&[U256]]) -> MerkleTree {
    assert!(!cols.is_empty());
    let n = cols[0].len();
    for c in cols {
        assert_eq!(c.len(), n);
    }

    let leaves: Vec<U256> = (0..n)
        .map(|i| {
            let mut h = keccak_hash_two(cols[0][i], cols[1][i]);
            for col in &cols[2..] {
                h = keccak_hash_two(h, col[i]);
            }
            h
        })
        .collect();
    MerkleTree::build(&leaves)
}

/// Build a Merkle tree from a single column of evaluations.
pub fn commit_column(values: &[U256]) -> MerkleTree {
    MerkleTree::build(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_two_leaves() {
        let leaves = vec![U256::from(1u64), U256::from(2u64)];
        let tree = MerkleTree::build(&leaves);

        assert_eq!(tree.num_leaves(), 2);
        assert_eq!(tree.depth(), 1);

        let expected_root = keccak_hash_two(U256::from(1u64), U256::from(2u64));
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_merkle_tree_auth_path() {
        let leaves = vec![
            U256::from(1u64),
            U256::from(2u64),
            U256::from(3u64),
            U256::from(4u64),
        ];
        let tree = MerkleTree::build(&leaves);

        // Get auth path for leaf 0
        let (path, indices) = tree.auth_path(0);
        assert_eq!(path.len(), 2);
        assert_eq!(indices.len(), 2);

        // Verify: manually compute
        let h01 = keccak_hash_two(U256::from(1u64), U256::from(2u64));
        let h23 = keccak_hash_two(U256::from(3u64), U256::from(4u64));
        let root = keccak_hash_two(h01, h23);

        assert_eq!(tree.root(), root);
        assert_eq!(path[0], U256::from(2u64)); // sibling of leaf 0 is leaf 1
        assert_eq!(path[1], h23); // sibling of h01 is h23
        assert!(!indices[0]); // leaf 0 is left child
        assert!(!indices[1]); // h01 is left child
    }

    #[test]
    fn test_merkle_tree_auth_path_right_child() {
        let leaves = vec![
            U256::from(10u64),
            U256::from(20u64),
            U256::from(30u64),
            U256::from(40u64),
        ];
        let tree = MerkleTree::build(&leaves);

        // Auth path for leaf 3 (rightmost)
        let (path, indices) = tree.auth_path(3);
        assert_eq!(path[0], U256::from(30u64)); // sibling is leaf 2
        assert!(indices[0]); // leaf 3 is right child

        let h01 = keccak_hash_two(U256::from(10u64), U256::from(20u64));
        assert_eq!(path[1], h01); // sibling of h23 is h01
        assert!(indices[1]); // h23 is right child
    }

}
