// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Interface for SP1's on-chain verifier gateway
/// @dev SP1 v4 uses a shared gateway contract for Groth16/PLONK verification
interface ISP1Verifier {
    /// @notice Verify a SP1 proof
    /// @param programVKey The verification key for the SP1 program
    /// @param publicValues The ABI-encoded public outputs from the program
    /// @param proofBytes The Groth16-wrapped proof bytes
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title SP1SharpeVerifier — SNARK-based Sharpe ratio verifier (for benchmark comparison)
/// @notice Wraps SP1's auto-generated Groth16 verifier to verify Sharpe ratio computations
/// @dev Used in the STARK vs SNARK benchmark to compare gas costs and proof sizes
contract SP1SharpeVerifier {
    /// @notice The SP1 verifier gateway contract
    ISP1Verifier public immutable sp1Verifier;

    /// @notice The SP1 program verification key (set at deployment)
    bytes32 public immutable programVKey;

    /// @notice Emitted when a Sharpe proof is successfully verified
    event SharpeProofVerified(
        uint64 indexed tradeCount,
        int64 totalReturn,
        uint64 sharpeSqScaled
    );

    /// @param _sp1Verifier Address of the SP1VerifierGateway contract
    /// @param _programVKey Verification key of the compiled SP1 Sharpe program
    constructor(address _sp1Verifier, bytes32 _programVKey) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        programVKey = _programVKey;
    }

    /// @notice Verify a SP1 Groth16 proof of Sharpe ratio computation
    /// @param publicValues ABI-encoded (uint64 tradeCount, int64 totalReturn, uint64 sharpeSqScaled)
    /// @param proofBytes The Groth16-wrapped proof from SP1
    /// @return tradeCount Number of trades
    /// @return totalReturn Sum of return basis points
    /// @return sharpeSqScaled Sharpe^2 * 10000
    function verifySharpeProof(
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view returns (uint64 tradeCount, int64 totalReturn, uint64 sharpeSqScaled) {
        // Verify the proof via SP1 gateway (reverts on failure)
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);

        // Decode public outputs
        (tradeCount, totalReturn, sharpeSqScaled) = abi.decode(
            publicValues,
            (uint64, int64, uint64)
        );
    }

    /// @notice Verify and store result (non-view version for gas measurement)
    /// @param publicValues ABI-encoded public outputs
    /// @param proofBytes The Groth16 proof
    function verifyAndEmit(
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external returns (uint64 tradeCount, int64 totalReturn, uint64 sharpeSqScaled) {
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);

        (tradeCount, totalReturn, sharpeSqScaled) = abi.decode(
            publicValues,
            (uint64, int64, uint64)
        );

        emit SharpeProofVerified(tradeCount, totalReturn, sharpeSqScaled);
    }
}
