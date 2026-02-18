//! STARK Proof Deserialization
//!
//! Defines the proof structure and parsing logic for STARK proofs
//! received as calldata (flattened Vec<U256> parameters).

use alloy_primitives::U256;
use alloc::vec::Vec;

use crate::field::Fp;

/// Parsed STARK proof structure.
pub struct StarkProof {
    pub trace_commitment: Fp,
    pub composition_commitment: Fp,
    pub fri_layer_commitments: Vec<Fp>,

    pub trace_ood_evals: [Fp; 2],
    pub trace_ood_evals_next: [Fp; 2],
    pub composition_ood_eval: Fp,

    pub fri_final_poly: Vec<Fp>,

    pub query_indices: Vec<usize>,
    pub num_fri_layers: usize,
    pub log_trace_len: u32,

    pub query_values: Vec<Fp>,
    pub query_paths: Vec<Fp>,
}

/// Parse a STARK proof from ABI-compatible parameters.
/// Converts U256 calldata to Montgomery-form Fp at parse time.
pub fn parse_stark_proof(
    commitments: &[U256],
    ood_values: &[U256],
    fri_final_poly: &[U256],
    query_values: &[U256],
    query_paths: &[U256],
    query_metadata: &[U256],
) -> Option<StarkProof> {
    if query_metadata.len() < 3 {
        return None;
    }

    let num_queries = query_metadata[0].as_limbs()[0] as usize;
    let num_fri_layers = query_metadata[1].as_limbs()[0] as usize;
    let log_trace_len = query_metadata[2].as_limbs()[0] as u32;

    if log_trace_len == 0 || log_trace_len > 26 {
        return None;
    }

    if num_fri_layers == 0 || num_fri_layers as u32 > log_trace_len + 2 {
        return None;
    }

    // FRI verifier uses fixed-size arrays: alphas[32] and derived_indices[64]
    if num_queries == 0 || num_queries > 64 {
        return None;
    }

    if query_metadata.len() < 3 + num_queries {
        return None;
    }

    let query_indices: Vec<usize> = (0..num_queries)
        .map(|i| query_metadata[3 + i].as_limbs()[0] as usize)
        .collect();

    if commitments.len() < 2 + num_fri_layers {
        return None;
    }

    let trace_commitment = Fp::from_u256(commitments[0]);
    let composition_commitment = Fp::from_u256(commitments[1]);
    let fri_layer_commitments: Vec<Fp> = commitments[2..2 + num_fri_layers]
        .iter()
        .map(|v| Fp::from_u256(*v))
        .collect();

    if ood_values.len() < 5 {
        return None;
    }

    let trace_ood_evals = [Fp::from_u256(ood_values[0]), Fp::from_u256(ood_values[1])];
    let trace_ood_evals_next = [Fp::from_u256(ood_values[2]), Fp::from_u256(ood_values[3])];
    let composition_ood_eval = Fp::from_u256(ood_values[4]);

    Some(StarkProof {
        trace_commitment,
        composition_commitment,
        fri_layer_commitments,
        trace_ood_evals,
        trace_ood_evals_next,
        composition_ood_eval,
        fri_final_poly: fri_final_poly.iter().map(|v| Fp::from_u256(*v)).collect(),
        query_indices,
        num_fri_layers,
        log_trace_len,
        query_values: query_values.iter().map(|v| Fp::from_u256(*v)).collect(),
        query_paths: query_paths.iter().map(|v| Fp::from_u256(*v)).collect(),
    })
}

/// Compute the expected number of query values.
pub fn expected_query_values_len(num_queries: usize, num_fri_layers: usize) -> usize {
    num_queries * num_fri_layers * 2
}

/// Parsed BTC Lock STARK proof structure.
pub struct BtcLockStarkProof {
    pub trace_commitment: Fp,
    pub composition_commitment: Fp,
    pub fri_layer_commitments: Vec<Fp>,

    pub trace_ood_evals: [Fp; 5],
    pub trace_ood_evals_next: [Fp; 5],
    pub composition_ood_eval: Fp,

    pub fri_final_poly: Vec<Fp>,

    pub query_indices: Vec<usize>,
    pub num_fri_layers: usize,
    pub log_trace_len: u32,

    pub query_values: Vec<Fp>,
    pub query_paths: Vec<Fp>,
}

/// Parse a BTC Lock STARK proof from ABI-compatible parameters.
/// Expects 11 OOD values: 5 trace at z + 5 trace at zg + 1 composition at z.
pub fn parse_btc_lock_proof(
    commitments: &[U256],
    ood_values: &[U256],
    fri_final_poly: &[U256],
    query_values: &[U256],
    query_paths: &[U256],
    query_metadata: &[U256],
) -> Option<BtcLockStarkProof> {
    if query_metadata.len() < 3 {
        return None;
    }

    let num_queries = query_metadata[0].as_limbs()[0] as usize;
    let num_fri_layers = query_metadata[1].as_limbs()[0] as usize;
    let log_trace_len = query_metadata[2].as_limbs()[0] as u32;

    if log_trace_len == 0 || log_trace_len > 26 {
        return None;
    }

    if num_fri_layers == 0 || num_fri_layers as u32 > log_trace_len + 2 {
        return None;
    }

    if query_metadata.len() < 3 + num_queries {
        return None;
    }

    let query_indices: Vec<usize> = (0..num_queries)
        .map(|i| query_metadata[3 + i].as_limbs()[0] as usize)
        .collect();

    if commitments.len() < 2 + num_fri_layers {
        return None;
    }

    let trace_commitment = Fp::from_u256(commitments[0]);
    let composition_commitment = Fp::from_u256(commitments[1]);
    let fri_layer_commitments: Vec<Fp> = commitments[2..2 + num_fri_layers]
        .iter()
        .map(|v| Fp::from_u256(*v))
        .collect();

    // BTC Lock: 5 + 5 + 1 = 11 OOD values
    if ood_values.len() < 11 {
        return None;
    }

    let trace_ood_evals = [
        Fp::from_u256(ood_values[0]),
        Fp::from_u256(ood_values[1]),
        Fp::from_u256(ood_values[2]),
        Fp::from_u256(ood_values[3]),
        Fp::from_u256(ood_values[4]),
    ];
    let trace_ood_evals_next = [
        Fp::from_u256(ood_values[5]),
        Fp::from_u256(ood_values[6]),
        Fp::from_u256(ood_values[7]),
        Fp::from_u256(ood_values[8]),
        Fp::from_u256(ood_values[9]),
    ];
    let composition_ood_eval = Fp::from_u256(ood_values[10]);

    // C2 fix: validate query_values length
    // Each query needs num_fri_layers * 2 values (fx, f_neg_x per layer)
    let expected_qv = num_queries * num_fri_layers * 2;
    if query_values.len() < expected_qv {
        return None;
    }

    // C2 fix: validate query_paths length
    // Each query needs sum of (log_domain_size - layer) path elements across all FRI layers
    // log_domain_size = log_trace_len + 2 (BLOWUP_FACTOR = 4)
    let log_domain_size = log_trace_len as usize + 2;
    let mut path_elements_per_query = 0usize;
    for layer in 0..num_fri_layers {
        path_elements_per_query += log_domain_size - layer;
    }
    let expected_qp = num_queries * path_elements_per_query;
    if query_paths.len() < expected_qp {
        return None;
    }

    Some(BtcLockStarkProof {
        trace_commitment,
        composition_commitment,
        fri_layer_commitments,
        trace_ood_evals,
        trace_ood_evals_next,
        composition_ood_eval,
        fri_final_poly: fri_final_poly.iter().map(|v| Fp::from_u256(*v)).collect(),
        query_indices,
        num_fri_layers,
        log_trace_len,
        query_values: query_values.iter().map(|v| Fp::from_u256(*v)).collect(),
        query_paths: query_paths.iter().map(|v| Fp::from_u256(*v)).collect(),
    })
}

/// Parsed Sharpe STARK proof structure.
pub struct SharpeStarkProof {
    pub trace_commitment: Fp,
    pub composition_commitment: Fp,
    pub fri_layer_commitments: Vec<Fp>,

    pub trace_ood_evals: [Fp; 6],
    pub trace_ood_evals_next: [Fp; 6],
    pub composition_ood_eval: Fp,

    pub fri_final_poly: Vec<Fp>,

    pub query_indices: Vec<usize>,
    pub num_fri_layers: usize,
    pub log_trace_len: u32,

    pub query_values: Vec<Fp>,
    pub query_paths: Vec<Fp>,
}

/// Parse a Sharpe STARK proof from ABI-compatible parameters.
/// Expects 13 OOD values: 6 trace at z + 6 trace at zg + 1 composition at z.
pub fn parse_sharpe_proof(
    commitments: &[U256],
    ood_values: &[U256],
    fri_final_poly: &[U256],
    query_values: &[U256],
    query_paths: &[U256],
    query_metadata: &[U256],
) -> Option<SharpeStarkProof> {
    if query_metadata.len() < 3 {
        return None;
    }

    let num_queries = query_metadata[0].as_limbs()[0] as usize;
    let num_fri_layers = query_metadata[1].as_limbs()[0] as usize;
    let log_trace_len = query_metadata[2].as_limbs()[0] as u32;

    if log_trace_len == 0 || log_trace_len > 26 {
        return None;
    }

    if num_fri_layers == 0 || num_fri_layers as u32 > log_trace_len + 2 {
        return None;
    }

    if num_queries == 0 || num_queries > 64 {
        return None;
    }

    if query_metadata.len() < 3 + num_queries {
        return None;
    }

    let query_indices: Vec<usize> = (0..num_queries)
        .map(|i| query_metadata[3 + i].as_limbs()[0] as usize)
        .collect();

    if commitments.len() < 2 + num_fri_layers {
        return None;
    }

    let trace_commitment = Fp::from_u256(commitments[0]);
    let composition_commitment = Fp::from_u256(commitments[1]);
    let fri_layer_commitments: Vec<Fp> = commitments[2..2 + num_fri_layers]
        .iter()
        .map(|v| Fp::from_u256(*v))
        .collect();

    // Sharpe: 6 + 6 + 1 = 13 OOD values
    if ood_values.len() < 13 {
        return None;
    }

    let trace_ood_evals = [
        Fp::from_u256(ood_values[0]),
        Fp::from_u256(ood_values[1]),
        Fp::from_u256(ood_values[2]),
        Fp::from_u256(ood_values[3]),
        Fp::from_u256(ood_values[4]),
        Fp::from_u256(ood_values[5]),
    ];
    let trace_ood_evals_next = [
        Fp::from_u256(ood_values[6]),
        Fp::from_u256(ood_values[7]),
        Fp::from_u256(ood_values[8]),
        Fp::from_u256(ood_values[9]),
        Fp::from_u256(ood_values[10]),
        Fp::from_u256(ood_values[11]),
    ];
    let composition_ood_eval = Fp::from_u256(ood_values[12]);

    // Validate query_values length
    let expected_qv = num_queries * num_fri_layers * 2;
    if query_values.len() < expected_qv {
        return None;
    }

    // Validate query_paths length
    let log_domain_size = log_trace_len as usize + 2;
    let mut path_elements_per_query = 0usize;
    for layer in 0..num_fri_layers {
        path_elements_per_query += log_domain_size - layer;
    }
    let expected_qp = num_queries * path_elements_per_query;
    if query_paths.len() < expected_qp {
        return None;
    }

    Some(SharpeStarkProof {
        trace_commitment,
        composition_commitment,
        fri_layer_commitments,
        trace_ood_evals,
        trace_ood_evals_next,
        composition_ood_eval,
        fri_final_poly: fri_final_poly.iter().map(|v| Fp::from_u256(*v)).collect(),
        query_indices,
        num_fri_layers,
        log_trace_len,
        query_values: query_values.iter().map(|v| Fp::from_u256(*v)).collect(),
        query_paths: query_paths.iter().map(|v| Fp::from_u256(*v)).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_parse_proof_basic() {
        let commitments = vec![
            U256::from(1u64),
            U256::from(2u64),
            U256::from(3u64),
            U256::from(4u64),
        ];

        let ood_values = vec![
            U256::from(10u64),
            U256::from(11u64),
            U256::from(12u64),
            U256::from(13u64),
            U256::from(14u64),
        ];

        let fri_final = vec![U256::from(100u64), U256::from(101u64)];

        let query_values = vec![
            U256::from(20u64), U256::from(21u64),
            U256::from(22u64), U256::from(23u64),
        ];

        let query_paths = vec![];

        let query_metadata = vec![
            U256::from(1u64),
            U256::from(2u64),
            U256::from(6u64),
            U256::from(5u64),
        ];

        let proof = parse_stark_proof(
            &commitments, &ood_values, &fri_final,
            &query_values, &query_paths, &query_metadata,
        );

        assert!(proof.is_some());
        let proof = proof.unwrap();

        assert_eq!(proof.trace_commitment, Fp::from_u256(U256::from(1u64)));
        assert_eq!(proof.composition_commitment, Fp::from_u256(U256::from(2u64)));
        assert_eq!(proof.fri_layer_commitments.len(), 2);
        assert_eq!(proof.trace_ood_evals[0], Fp::from_u256(U256::from(10u64)));
        assert_eq!(proof.trace_ood_evals[1], Fp::from_u256(U256::from(11u64)));
        assert_eq!(proof.composition_ood_eval, Fp::from_u256(U256::from(14u64)));
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
            &commitments, &ood_values, &[], &[], &[],
            &[U256::from(1u64)],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_expected_query_values_len() {
        assert_eq!(expected_query_values_len(20, 4), 160);
    }

    #[test]
    fn test_parse_btc_lock_proof_basic() {
        let commitments = vec![
            U256::from(1u64),
            U256::from(2u64),
            U256::from(3u64),
            U256::from(4u64),
        ];

        // 11 OOD values: 5 trace at z + 5 trace at zg + 1 composition
        let ood_values = vec![
            U256::from(10u64), U256::from(11u64), U256::from(12u64),
            U256::from(13u64), U256::from(14u64),
            U256::from(15u64), U256::from(16u64), U256::from(17u64),
            U256::from(18u64), U256::from(19u64),
            U256::from(20u64),
        ];

        let fri_final = vec![U256::from(100u64), U256::from(101u64)];
        // 1 query * 2 layers * 2 = 4 values
        let query_values = vec![U256::from(30u64); 4];
        // 1 query * ((8-0) + (8-1)) = 15 path elements (log_domain_size = 6+2 = 8)
        let query_paths = vec![U256::from(40u64); 15];
        let query_metadata = vec![
            U256::from(1u64), U256::from(2u64), U256::from(6u64),
            U256::from(5u64),
        ];

        let proof = parse_btc_lock_proof(
            &commitments, &ood_values, &fri_final,
            &query_values, &query_paths, &query_metadata,
        );

        assert!(proof.is_some());
        let proof = proof.unwrap();

        assert_eq!(proof.trace_ood_evals[0], Fp::from_u256(U256::from(10u64)));
        assert_eq!(proof.trace_ood_evals[4], Fp::from_u256(U256::from(14u64)));
        assert_eq!(proof.trace_ood_evals_next[0], Fp::from_u256(U256::from(15u64)));
        assert_eq!(proof.trace_ood_evals_next[4], Fp::from_u256(U256::from(19u64)));
        assert_eq!(proof.composition_ood_eval, Fp::from_u256(U256::from(20u64)));
        assert_eq!(proof.log_trace_len, 6);
    }

    #[test]
    fn test_parse_btc_lock_proof_insufficient_ood() {
        let commitments = vec![U256::from(1u64), U256::from(2u64), U256::from(3u64)];
        // Only 5 OOD values (need 11)
        let ood_values = vec![U256::ZERO; 5];
        let result = parse_btc_lock_proof(
            &commitments, &ood_values, &[], &[], &[],
            &[U256::from(1u64), U256::from(1u64), U256::from(3u64), U256::from(0u64)],
        );
        assert!(result.is_none());
    }
}
