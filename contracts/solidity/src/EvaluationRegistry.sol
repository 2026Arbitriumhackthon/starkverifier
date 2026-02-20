// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Interface for the Stylus STARK verifier contract
interface IStylusVerifier {
    /// @notice Verify a Sharpe ratio STARK proof
    /// @param publicInputs Public inputs [num_trades, scale, sharpe_sq_scaled, trace_hash]
    /// @param commitments Merkle commitments [trace_root, comp_root, fri_roots...]
    /// @param oodValues Out-of-domain evaluation values
    /// @param friFinalPoly Final FRI polynomial coefficients
    /// @param queryValues Flattened query data
    /// @param queryPaths Flattened Merkle paths
    /// @param queryMetadata Query metadata [num_queries, num_fri_layers, ...]
    /// @return valid Whether the proof is valid
    function verifySharpeProof(
        uint256[] calldata publicInputs,
        uint256[] calldata commitments,
        uint256[] calldata oodValues,
        uint256[] calldata friFinalPoly,
        uint256[] calldata queryValues,
        uint256[] calldata queryPaths,
        uint256[] calldata queryMetadata
    ) external returns (bool valid);
}

/// @title EvaluationRegistry - On-chain agent evaluation record registry
/// @notice Stores agent evaluation results with STARK proof verification via Stylus verifier
/// @dev Phase 2 contract: submit + verify in 1 tx, tracks best scores and rankings
contract EvaluationRegistry {
    /// @notice Evaluation record for a single agent submission
    struct EvaluationRecord {
        address agentId;
        bytes32 datasetCommitment;
        uint256 tradeCount;
        uint256 sharpeSqBps;
        uint256 totalReturnBps;
        bytes32 proofHash;
        uint256 blockNumber;
        address evaluator;
        uint256 timestamp;
        bool verified;
    }

    /// @notice Emitted when an evaluation is submitted
    /// @param evaluationId The unique evaluation ID
    /// @param agentId The agent address
    /// @param evaluator The address that submitted the evaluation
    /// @param sharpeSqBps The Sharpe^2 score in basis points
    /// @param verified Whether the STARK proof was verified
    event EvaluationSubmitted(
        uint256 indexed evaluationId,
        address indexed agentId,
        address indexed evaluator,
        uint256 sharpeSqBps,
        bool verified
    );

    /// @notice Emitted when an agent's best score is updated
    /// @param agentId The agent address
    /// @param newBestSharpeSqBps The new best Sharpe^2 score
    /// @param evaluationId The evaluation ID that set the new best
    event BestScoreUpdated(
        address indexed agentId,
        uint256 newBestSharpeSqBps,
        uint256 evaluationId
    );

    /// @notice The Stylus verifier contract used for STARK proof verification
    IStylusVerifier public immutable stylusVerifier;

    /// @dev Next evaluation ID counter (starts at 1)
    uint256 private _nextEvaluationId = 1;

    /// @dev Mapping from evaluation ID to record
    mapping(uint256 => EvaluationRecord) private _evaluations;

    /// @dev Mapping from agent address to list of evaluation IDs
    mapping(address => uint256[]) private _agentEvaluationIds;

    /// @dev Mapping from agent address to best Sharpe^2 score (bps)
    mapping(address => uint256) private _bestSharpeSqBps;

    /// @dev Array of agent addresses that have at least one verified evaluation
    address[] private _rankedAgents;

    /// @dev Whether an agent has been added to the ranked agents list
    mapping(address => bool) private _hasEvaluation;

    /// @dev Whether a proof hash has already been submitted (duplicate prevention)
    mapping(bytes32 => bool) private _proofSubmitted;

    /// @param _stylusVerifier Address of the deployed Stylus STARK verifier
    constructor(address _stylusVerifier) {
        stylusVerifier = IStylusVerifier(_stylusVerifier);
    }

    /// @notice Submit an evaluation with STARK proof for verification
    /// @dev Calls Stylus verifier via try/catch; records verified=false on failure
    /// @param agentId The agent address being evaluated
    /// @param publicInputs Public inputs [num_trades, scale, sharpe_sq_scaled, trace_hash]
    /// @param commitments Merkle commitments
    /// @param oodValues Out-of-domain values
    /// @param friFinalPoly Final FRI polynomial
    /// @param queryValues Query values
    /// @param queryPaths Query Merkle paths
    /// @param queryMetadata Query metadata
    /// @return evaluationId The assigned evaluation ID
    function submitEvaluation(
        address agentId,
        uint256[] calldata publicInputs,
        uint256[] calldata commitments,
        uint256[] calldata oodValues,
        uint256[] calldata friFinalPoly,
        uint256[] calldata queryValues,
        uint256[] calldata queryPaths,
        uint256[] calldata queryMetadata
    ) external returns (uint256 evaluationId) {
        require(agentId != address(0), "Agent address cannot be zero");
        require(publicInputs.length == 4, "Public inputs must have 4 elements");

        // Compute proof hash for duplicate prevention
        bytes32 proofHash = keccak256(
            abi.encode(
                publicInputs,
                commitments,
                oodValues,
                friFinalPoly,
                queryValues,
                queryPaths,
                queryMetadata
            )
        );
        require(!_proofSubmitted[proofHash], "Proof already submitted");
        _proofSubmitted[proofHash] = true;

        // Attempt verification via Stylus verifier
        bool verified;
        try
            stylusVerifier.verifySharpeProof(
                publicInputs,
                commitments,
                oodValues,
                friFinalPoly,
                queryValues,
                queryPaths,
                queryMetadata
            )
        returns (bool result) {
            verified = result;
        } catch {
            verified = false;
        }

        // Parse public inputs
        uint256 tradeCount = publicInputs[0];
        uint256 totalReturnBps = publicInputs[1];
        uint256 sharpeSqBps = publicInputs[2];
        bytes32 datasetCommitment = bytes32(publicInputs[3]);

        // Store evaluation record
        evaluationId = _nextEvaluationId++;
        _evaluations[evaluationId] = EvaluationRecord({
            agentId: agentId,
            datasetCommitment: datasetCommitment,
            tradeCount: tradeCount,
            sharpeSqBps: sharpeSqBps,
            totalReturnBps: totalReturnBps,
            proofHash: proofHash,
            blockNumber: block.number,
            evaluator: msg.sender,
            timestamp: block.timestamp,
            verified: verified
        });
        _agentEvaluationIds[agentId].push(evaluationId);

        // Update ranking only for verified evaluations
        if (verified) {
            _updateRanking(agentId, sharpeSqBps, evaluationId);
        }

        emit EvaluationSubmitted(evaluationId, agentId, msg.sender, sharpeSqBps, verified);
    }

    /// @notice Get the top-ranked agents by best Sharpe^2 score
    /// @param limit Maximum number of agents to return
    /// @return agents Array of agent addresses (descending by score)
    /// @return scores Array of corresponding best scores
    function getTopAgents(
        uint256 limit
    ) external view returns (address[] memory agents, uint256[] memory scores) {
        uint256 total = _rankedAgents.length;
        uint256 count = limit < total ? limit : total;

        // Copy to memory for sorting
        address[] memory allAgents = new address[](total);
        uint256[] memory allScores = new uint256[](total);
        for (uint256 i = 0; i < total; i++) {
            allAgents[i] = _rankedAgents[i];
            allScores[i] = _bestSharpeSqBps[_rankedAgents[i]];
        }

        // Selection sort: find top `count` in descending order
        for (uint256 i = 0; i < count; i++) {
            uint256 maxIdx = i;
            for (uint256 j = i + 1; j < total; j++) {
                if (allScores[j] > allScores[maxIdx]) {
                    maxIdx = j;
                }
            }
            if (maxIdx != i) {
                // Swap scores
                (allScores[i], allScores[maxIdx]) = (allScores[maxIdx], allScores[i]);
                // Swap agents
                (allAgents[i], allAgents[maxIdx]) = (allAgents[maxIdx], allAgents[i]);
            }
        }

        // Build result arrays
        agents = new address[](count);
        scores = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            agents[i] = allAgents[i];
            scores[i] = allScores[i];
        }
    }

    /// @notice Get all evaluations for a specific agent
    /// @param agentId The agent address
    /// @return records Array of evaluation records
    function getAgentEvaluations(
        address agentId
    ) external view returns (EvaluationRecord[] memory records) {
        uint256[] storage ids = _agentEvaluationIds[agentId];
        records = new EvaluationRecord[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            records[i] = _evaluations[ids[i]];
        }
    }

    /// @notice Get a single evaluation by ID
    /// @param evaluationId The evaluation ID
    /// @return record The evaluation record
    function getEvaluation(
        uint256 evaluationId
    ) external view returns (EvaluationRecord memory record) {
        return _evaluations[evaluationId];
    }

    /// @notice Get the total number of evaluations submitted
    /// @return count The evaluation count
    function getEvaluationCount() external view returns (uint256 count) {
        return _nextEvaluationId - 1;
    }

    /// @notice Get the best Sharpe^2 score for an agent
    /// @param agentId The agent address
    /// @return score The best score in basis points
    function getBestScore(address agentId) external view returns (uint256 score) {
        return _bestSharpeSqBps[agentId];
    }

    /// @dev Update the ranking when a verified evaluation has a new best score
    /// @param agentId The agent address
    /// @param sharpeSqBps The new score
    /// @param evaluationId The evaluation that produced this score
    function _updateRanking(address agentId, uint256 sharpeSqBps, uint256 evaluationId) private {
        if (!_hasEvaluation[agentId]) {
            _hasEvaluation[agentId] = true;
            _rankedAgents.push(agentId);
        }

        if (sharpeSqBps > _bestSharpeSqBps[agentId]) {
            _bestSharpeSqBps[agentId] = sharpeSqBps;
            emit BestScoreUpdated(agentId, sharpeSqBps, evaluationId);
        }
    }
}
