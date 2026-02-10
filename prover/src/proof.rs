//! Proof Serialization
//!
//! Serializes STARK proof data into the flattened Vec<U256> format
//! expected by the on-chain verifier's `verify_stark_proof` function.

use alloy_primitives::U256;

/// Serialized proof ready for on-chain submission.
pub struct SerializedProof {
    pub public_inputs: Vec<U256>,
    pub commitments: Vec<U256>,
    pub ood_values: Vec<U256>,
    pub fri_final_poly: Vec<U256>,
    pub query_values: Vec<U256>,
    pub query_paths: Vec<U256>,
    pub query_metadata: Vec<U256>,
}

impl SerializedProof {
    /// Create a new serialized proof.
    ///
    /// # Arguments
    /// * `public_inputs` - [first_a, first_b, claimed_result]
    /// * `trace_commitment` - Merkle root of trace evaluations
    /// * `composition_commitment` - Merkle root of composition evaluations
    /// * `fri_layer_roots` - Merkle roots for each FRI layer
    /// * `trace_ood_evals` - [a(z), b(z)] at OOD point
    /// * `trace_ood_evals_next` - [a(zg), b(zg)] at OOD point * generator
    /// * `composition_ood_eval` - C(z) composition at OOD point
    /// * `fri_final_poly` - Final low-degree polynomial coefficients
    /// * `query_indices` - Query indices in LDE domain
    /// * `query_values` - Flattened query values
    /// * `query_paths` - Flattened Merkle auth paths
    /// * `num_fri_layers` - Number of FRI layers
    /// * `log_trace_len` - Log2 of trace length
    pub fn new(
        public_inputs: [U256; 3],
        trace_commitment: U256,
        composition_commitment: U256,
        fri_layer_roots: &[U256],
        trace_ood_evals: [U256; 2],
        trace_ood_evals_next: [U256; 2],
        composition_ood_eval: U256,
        fri_final_poly: &[U256],
        query_indices: &[usize],
        query_values: &[U256],
        query_paths: &[U256],
        num_fri_layers: usize,
        log_trace_len: u32,
    ) -> Self {
        // commitments: [trace_root, comp_root, fri_roots...]
        let mut commitments = Vec::with_capacity(2 + fri_layer_roots.len());
        commitments.push(trace_commitment);
        commitments.push(composition_commitment);
        commitments.extend_from_slice(fri_layer_roots);

        // ood_values: [a(z), b(z), a(zg), b(zg), comp(z)]
        let ood_values = vec![
            trace_ood_evals[0],
            trace_ood_evals[1],
            trace_ood_evals_next[0],
            trace_ood_evals_next[1],
            composition_ood_eval,
        ];

        // query_metadata: [num_queries, num_fri_layers, log_trace_len, idx_0, idx_1, ...]
        let num_queries = query_indices.len();
        let mut query_metadata = Vec::with_capacity(3 + num_queries);
        query_metadata.push(U256::from(num_queries as u64));
        query_metadata.push(U256::from(num_fri_layers as u64));
        query_metadata.push(U256::from(log_trace_len as u64));
        for &idx in query_indices {
            query_metadata.push(U256::from(idx as u64));
        }

        SerializedProof {
            public_inputs: public_inputs.to_vec(),
            commitments,
            ood_values,
            fri_final_poly: fri_final_poly.to_vec(),
            query_values: query_values.to_vec(),
            query_paths: query_paths.to_vec(),
            query_metadata,
        }
    }

    /// Serialize to JSON for easy transport.
    pub fn to_json(&self) -> String {
        let fmt_vec = |v: &[U256]| -> String {
            let parts: Vec<String> = v.iter().map(|x| format!("\"0x{:064x}\"", x)).collect();
            format!("[{}]", parts.join(","))
        };

        format!(
            "{{\n  \"publicInputs\": {},\n  \"commitments\": {},\n  \"oodValues\": {},\n  \"friFinalPoly\": {},\n  \"queryValues\": {},\n  \"queryPaths\": {},\n  \"queryMetadata\": {}\n}}",
            fmt_vec(&self.public_inputs),
            fmt_vec(&self.commitments),
            fmt_vec(&self.ood_values),
            fmt_vec(&self.fri_final_poly),
            fmt_vec(&self.query_values),
            fmt_vec(&self.query_paths),
            fmt_vec(&self.query_metadata),
        )
    }

    /// Total calldata size estimate in bytes.
    pub fn calldata_size(&self) -> usize {
        let total_words = self.public_inputs.len()
            + self.commitments.len()
            + self.ood_values.len()
            + self.fri_final_poly.len()
            + self.query_values.len()
            + self.query_paths.len()
            + self.query_metadata.len();
        // Each U256 = 32 bytes, plus ABI overhead (~7 * 64 bytes for array pointers/lengths)
        total_words * 32 + 7 * 64
    }

    /// Print a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "STARK Proof Summary:\n\
             - Public inputs: {} elements\n\
             - Commitments: {} (trace + comp + {} FRI layers)\n\
             - OOD values: {} elements\n\
             - FRI final poly: {} coefficients\n\
             - Query values: {} elements\n\
             - Query paths: {} elements\n\
             - Query metadata: {} elements\n\
             - Estimated calldata: {} bytes ({:.1} KB)",
            self.public_inputs.len(),
            self.commitments.len(),
            self.commitments.len() - 2,
            self.ood_values.len(),
            self.fri_final_poly.len(),
            self.query_values.len(),
            self.query_paths.len(),
            self.query_metadata.len(),
            self.calldata_size(),
            self.calldata_size() as f64 / 1024.0,
        )
    }
}

/// Convert proof data to hex-encoded calldata for direct contract call.
pub fn encode_calldata_hex(proof: &SerializedProof) -> String {
    // Simple hex encoding of all U256 values
    let mut hex = String::new();
    for v in &proof.public_inputs {
        hex.push_str(&format!("{:064x}", v));
    }
    hex
}
