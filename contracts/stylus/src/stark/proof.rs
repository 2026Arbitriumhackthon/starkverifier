//! STARK Proof Deserialization
//!
//! Defines the proof structure and parsing logic for STARK proofs
//! received as calldata (flattened Vec<U256> parameters).
//!
//! The proof format is designed for ABI compatibility with Solidity,
//! using multiple Vec<U256> parameters to avoid complex encoding.

use alloy_primitives::U256;
use alloc::vec::Vec;

/// Parsed STARK proof structure.
///
/// Contains all data needed to verify a STARK proof for Fibonacci computation.
pub struct StarkProof {
    // --- Commitments ---
    /// Merkle root of the execution trace polynomial evaluation
    pub trace_commitment: U256,
    /// Merkle root of the composition polynomial evaluation
    pub composition_commitment: U256,
    /// Merkle roots of FRI layer commitments
    pub fri_layer_commitments: Vec<U256>,

    // --- OOD (Out-of-Domain) Evaluations ---
    /// Trace column evaluations at OOD point z: [a(z), b(z)]
    pub trace_ood_evals: [U256; 2],
    /// Trace column evaluations at z*g: [a(z*g), b(z*g)]
    pub trace_ood_evals_next: [U256; 2],
    /// Composition polynomial evaluation at z
    pub composition_ood_eval: U256,

    // --- FRI Final Polynomial ---
    /// Coefficients of the final low-degree polynomial after FRI folding
    pub fri_final_poly: Vec<U256>,

    // --- Query Data ---
    /// Query indices in the LDE domain
    pub query_indices: Vec<usize>,
    /// Number of FRI layers
    pub num_fri_layers: usize,
    /// Log2 of trace length
    pub log_trace_len: u32,

    // --- Query Proof Data (per query, per layer) ---
    /// Query values: for each query, for each FRI layer: [f(x), f(-x)]
    pub query_values: Vec<U256>,
    /// Merkle authentication paths (flattened)
    pub query_paths: Vec<U256>,
}

/// Parse a STARK proof from ABI-compatible parameters.
///
/// # Parameter Layout
///
/// ## `commitments`: [trace_root, comp_root, fri_root_0, fri_root_1, ...]
///   - Index 0: Trace polynomial Merkle commitment
///   - Index 1: Composition polynomial Merkle commitment
///   - Index 2+: FRI layer commitments
///
/// ## `ood_values`: [a(z), b(z), a(z*g), b(z*g), comp(z)]
///   - Indices 0-1: Trace at OOD point z
///   - Indices 2-3: Trace at z * trace_generator
///   - Index 4: Composition polynomial at z
///
/// ## `fri_final_poly`: [coeff_0, coeff_1, ..., coeff_d]
///   - Coefficients of the final low-degree polynomial
///
/// ## `query_values`: Flattened query evaluation data
///   - For each query q in [0, num_queries):
///     For each FRI layer l in [0, num_layers):
///       [f(x_q_l), f(-x_q_l)]
///
/// ## `query_paths`: Flattened Merkle authentication paths
///   - For each query, for each layer: path elements
///
/// ## `query_metadata`: [num_queries, num_fri_layers, log2_trace_len, idx_0, idx_1, ...]
///   - Index 0: Number of queries
///   - Index 1: Number of FRI layers
///   - Index 2: Log2 of trace length
///   - Index 3+: Query indices
///
pub fn parse_stark_proof(
    commitments: &[U256],
    ood_values: &[U256],
    fri_final_poly: &[U256],
    query_values: &[U256],
    query_paths: &[U256],
    query_metadata: &[U256],
) -> Option<StarkProof> {
    // Parse metadata
    if query_metadata.len() < 3 {
        return None;
    }

    let num_queries = query_metadata[0].as_limbs()[0] as usize;
    let num_fri_layers = query_metadata[1].as_limbs()[0] as usize;
    let log_trace_len = query_metadata[2].as_limbs()[0] as u32;

    // Validate log_trace_len range: BN254 TWO_ADICITY=28, blowup=4 (log=2)
    // So log_trace_len + 2 <= 28, i.e. log_trace_len <= 26
    if log_trace_len == 0 || log_trace_len > 26 {
        return None;
    }

    // Validate num_fri_layers: must be positive and at most log_domain_size
    if num_fri_layers == 0 || num_fri_layers as u32 > log_trace_len + 2 {
        return None;
    }

    // Validate metadata has enough entries for query indices
    if query_metadata.len() < 3 + num_queries {
        return None;
    }

    // Parse query indices
    let query_indices: Vec<usize> = (0..num_queries)
        .map(|i| query_metadata[3 + i].as_limbs()[0] as usize)
        .collect();

    // Parse commitments
    if commitments.len() < 2 + num_fri_layers {
        return None;
    }

    let trace_commitment = commitments[0];
    let composition_commitment = commitments[1];
    let fri_layer_commitments: Vec<U256> = commitments[2..2 + num_fri_layers].to_vec();

    // Parse OOD values
    if ood_values.len() < 5 {
        return None;
    }

    let trace_ood_evals = [ood_values[0], ood_values[1]];
    let trace_ood_evals_next = [ood_values[2], ood_values[3]];
    let composition_ood_eval = ood_values[4];

    Some(StarkProof {
        trace_commitment,
        composition_commitment,
        fri_layer_commitments,
        trace_ood_evals,
        trace_ood_evals_next,
        composition_ood_eval,
        fri_final_poly: fri_final_poly.to_vec(),
        query_indices,
        num_fri_layers,
        log_trace_len,
        query_values: query_values.to_vec(),
        query_paths: query_paths.to_vec(),
    })
}

/// Compute the expected number of query values.
/// Each query has num_layers FRI rounds, each with 2 values (f(x), f(-x)).
pub fn expected_query_values_len(num_queries: usize, num_fri_layers: usize) -> usize {
    num_queries * num_fri_layers * 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_parse_proof_basic() {
        let commitments = vec![
            U256::from(1u64), // trace root
            U256::from(2u64), // composition root
            U256::from(3u64), // FRI layer 0
            U256::from(4u64), // FRI layer 1
        ];

        let ood_values = vec![
            U256::from(10u64), // a(z)
            U256::from(11u64), // b(z)
            U256::from(12u64), // a(z*g)
            U256::from(13u64), // b(z*g)
            U256::from(14u64), // comp(z)
        ];

        let fri_final = vec![U256::from(100u64), U256::from(101u64)];

        let query_values = vec![
            U256::from(20u64), U256::from(21u64), // q0, layer0
            U256::from(22u64), U256::from(23u64), // q0, layer1
        ];

        let query_paths = vec![];

        let query_metadata = vec![
            U256::from(1u64), // num_queries = 1
            U256::from(2u64), // num_fri_layers = 2
            U256::from(6u64), // log_trace_len = 6
            U256::from(5u64), // query index 0 = 5
        ];

        let proof = parse_stark_proof(
            &commitments,
            &ood_values,
            &fri_final,
            &query_values,
            &query_paths,
            &query_metadata,
        );

        assert!(proof.is_some());
        let proof = proof.unwrap();

        assert_eq!(proof.trace_commitment, U256::from(1u64));
        assert_eq!(proof.composition_commitment, U256::from(2u64));
        assert_eq!(proof.fri_layer_commitments.len(), 2);
        assert_eq!(proof.trace_ood_evals[0], U256::from(10u64));
        assert_eq!(proof.trace_ood_evals[1], U256::from(11u64));
        assert_eq!(proof.composition_ood_eval, U256::from(14u64));
        assert_eq!(proof.query_indices.len(), 1);
        assert_eq!(proof.query_indices[0], 5);
        assert_eq!(proof.log_trace_len, 6);
        assert_eq!(proof.num_fri_layers, 2);
    }

    #[test]
    fn test_parse_proof_insufficient_metadata() {
        let commitments = vec![U256::from(1u64), U256::from(2u64)];
        let ood_values = vec![U256::ZERO; 5];
        let result = parse_stark_proof(
            &commitments,
            &ood_values,
            &[],
            &[],
            &[],
            &[U256::from(1u64)], // Only 1 element, need at least 3
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_expected_query_values_len() {
        // 20 queries, 4 FRI layers -> 20 * 4 * 2 = 160
        assert_eq!(expected_query_values_len(20, 4), 160);
    }
}
