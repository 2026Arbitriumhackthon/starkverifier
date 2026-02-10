//! FRI Prover
//!
//! Implements the prover side of the FRI protocol:
//! 1. Commit to polynomial evaluations via Merkle trees
//! 2. Fold polynomial with random challenges
//! 3. Generate query proofs with Merkle authentication paths

use alloy_primitives::U256;
use crate::field::BN254Field;
use crate::channel::Channel;
use crate::commit::MerkleTree;
use crate::domain;

/// Data for a single FRI layer produced by the prover.
pub struct FriLayer {
    /// Merkle tree commitment for this layer
    pub tree: MerkleTree,
    /// Evaluations at this layer (the polynomial values)
    pub evaluations: Vec<U256>,
    /// Log2 of the domain size for this layer
    pub log_domain_size: u32,
}

/// Result of FRI commitment phase.
pub struct FriCommitment {
    /// FRI layers (one per folding step)
    pub layers: Vec<FriLayer>,
    /// Final low-degree polynomial coefficients
    pub final_poly: Vec<U256>,
    /// Folding challenges (alphas) drawn from channel
    pub alphas: Vec<U256>,
}

/// Perform FRI commitment (folding + Merkle commitments).
///
/// Starting from evaluations on the LDE domain, repeatedly fold
/// the polynomial using random challenges and commit to each layer.
///
/// # Arguments
/// * `evaluations` - Initial polynomial evaluations on LDE domain
/// * `channel` - Fiat-Shamir channel for drawing challenges
/// * `log_domain_size` - Log2 of the initial domain size
/// * `num_layers` - Number of folding layers
pub fn fri_commit(
    evaluations: &[U256],
    channel: &mut Channel,
    log_domain_size: u32,
    num_layers: usize,
) -> FriCommitment {
    let mut layers = Vec::with_capacity(num_layers);
    let mut alphas = Vec::with_capacity(num_layers);
    let mut current_evals = evaluations.to_vec();
    let mut current_log_domain = log_domain_size;

    for _layer in 0..num_layers {
        // Commit to current evaluations
        let tree = MerkleTree::build(&current_evals);
        let root = tree.root();

        // Send commitment to channel
        channel.commit(root);

        // Draw folding challenge
        let alpha = channel.draw_felt();
        alphas.push(alpha);

        // Fold the polynomial
        let current_size = current_evals.len();
        let half = current_size / 2;
        let gen = domain::domain_generator(current_log_domain);

        let mut next_evals = Vec::with_capacity(half);
        for i in 0..half {
            let fx = current_evals[i];
            let f_neg_x = current_evals[i + half];
            let x = domain::evaluate_at(gen, i as u64);

            // Fold: (f(x) + f(-x))/2 + alpha * (f(x) - f(-x))/(2x)
            let two = U256::from(2u64);
            let sum = BN254Field::add(fx, f_neg_x);
            let even = BN254Field::div(sum, two);
            let diff = BN254Field::sub(fx, f_neg_x);
            let two_x = BN254Field::mul(two, x);
            let odd = BN254Field::div(diff, two_x);
            let folded = BN254Field::add(even, BN254Field::mul(alpha, odd));

            next_evals.push(folded);
        }

        layers.push(FriLayer {
            tree,
            evaluations: current_evals,
            log_domain_size: current_log_domain,
        });

        current_evals = next_evals;
        current_log_domain -= 1;
    }

    // Convert final evaluations to polynomial coefficients via inverse NTT
    let final_poly = domain::inverse_ntt(&current_evals, current_log_domain);

    // Commit final polynomial to channel
    for coeff in &final_poly {
        channel.commit(*coeff);
    }

    FriCommitment {
        layers,
        final_poly,
        alphas,
    }
}

/// Generate FRI query proofs.
///
/// For each query index, produces the values and authentication paths
/// at each FRI layer.
///
/// # Arguments
/// * `commitment` - FRI commitment data
/// * `query_indices` - Indices in the initial LDE domain
///
/// # Returns
/// (query_values, query_paths, query_path_indices) all flattened
pub fn fri_query_proofs(
    commitment: &FriCommitment,
    query_indices: &[usize],
) -> (Vec<U256>, Vec<U256>, Vec<bool>) {
    let mut all_values = Vec::new();
    let mut all_paths = Vec::new();
    let mut all_indices = Vec::new();

    for &initial_idx in query_indices {
        let mut idx = initial_idx;

        for layer in &commitment.layers {
            let layer_size = layer.evaluations.len();
            let half = layer_size / 2;

            // Value at index
            let fx = layer.evaluations[idx % layer_size];
            // Symmetric value
            let sym_idx = (idx + half) % layer_size;
            let f_neg_x = layer.evaluations[sym_idx];

            all_values.push(fx);
            all_values.push(f_neg_x);

            // Merkle authentication path for fx
            let (path, path_indices) = layer.tree.auth_path(idx % layer_size);
            all_paths.extend_from_slice(&path);
            all_indices.extend_from_slice(&path_indices);

            // Update index for next layer (halved domain)
            idx = idx % half;
        }
    }

    (all_values, all_paths, all_indices)
}
