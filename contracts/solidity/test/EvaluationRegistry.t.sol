// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/EvaluationRegistry.sol";

/// @notice Mock Stylus verifier that returns a configurable result
contract MockStylusVerifier is IStylusVerifier {
    bool public shouldVerify;

    constructor(bool _shouldVerify) {
        shouldVerify = _shouldVerify;
    }

    function verifySharpeProof(
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        return shouldVerify;
    }
}

/// @notice Mock Stylus verifier that always reverts
contract RevertingVerifier is IStylusVerifier {
    function verifySharpeProof(
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        uint256[] calldata
    ) external pure override returns (bool) {
        revert("Verifier error");
    }
}

contract EvaluationRegistryTest is Test {
    EvaluationRegistry public registry;
    EvaluationRegistry public unverifiedRegistry;
    EvaluationRegistry public revertingRegistry;

    MockStylusVerifier public verifier;
    MockStylusVerifier public falseVerifier;
    RevertingVerifier public revertVerifier;

    address constant AGENT_A = address(0xA);
    address constant AGENT_B = address(0xB);
    address constant AGENT_C = address(0xC);
    address constant AGENT_D = address(0xD);
    address constant AGENT_E = address(0xE);

    function setUp() public {
        verifier = new MockStylusVerifier(true);
        falseVerifier = new MockStylusVerifier(false);
        revertVerifier = new RevertingVerifier();

        registry = new EvaluationRegistry(address(verifier));
        unverifiedRegistry = new EvaluationRegistry(address(falseVerifier));
        revertingRegistry = new EvaluationRegistry(address(revertVerifier));
    }

    /// @dev Helper to build dummy proof arrays with a unique seed
    function _makeProof(
        uint256 tradeCount,
        uint256 totalReturn,
        uint256 sharpeSq,
        uint256 merkleRoot,
        uint256 seed
    )
        internal
        pure
        returns (
            uint256[] memory publicInputs,
            uint256[] memory commitments,
            uint256[] memory oodValues,
            uint256[] memory friFinalPoly,
            uint256[] memory queryValues,
            uint256[] memory queryPaths,
            uint256[] memory queryMetadata
        )
    {
        publicInputs = new uint256[](4);
        publicInputs[0] = tradeCount;
        publicInputs[1] = totalReturn;
        publicInputs[2] = sharpeSq;
        publicInputs[3] = merkleRoot;

        commitments = new uint256[](2);
        commitments[0] = seed;
        commitments[1] = seed + 1;

        oodValues = new uint256[](1);
        oodValues[0] = seed + 2;

        friFinalPoly = new uint256[](1);
        friFinalPoly[0] = seed + 3;

        queryValues = new uint256[](1);
        queryValues[0] = seed + 4;

        queryPaths = new uint256[](1);
        queryPaths[0] = seed + 5;

        queryMetadata = new uint256[](1);
        queryMetadata[0] = seed + 6;
    }

    /// @notice Test: verified submission stores all fields correctly and emits event
    function test_submitEvaluation_verified() public {
        (
            uint256[] memory pi,
            uint256[] memory cm,
            uint256[] memory ood,
            uint256[] memory fri,
            uint256[] memory qv,
            uint256[] memory qp,
            uint256[] memory qm
        ) = _makeProof(15, 500, 2500, 0xABCD, 100);

        vm.expectEmit(true, true, true, true);
        emit EvaluationRegistry.EvaluationSubmitted(1, AGENT_A, address(this), 2500, true);

        uint256 id = registry.submitEvaluation(AGENT_A, pi, cm, ood, fri, qv, qp, qm);
        assertEq(id, 1, "First evaluation should have ID 1");

        EvaluationRegistry.EvaluationRecord memory rec = registry.getEvaluation(1);
        assertEq(rec.agentId, AGENT_A);
        assertEq(rec.tradeCount, 15);
        assertEq(rec.sharpeSqBps, 2500);
        assertEq(rec.totalReturnBps, 500);
        assertEq(rec.evaluator, address(this));
        assertTrue(rec.verified);
        assertEq(rec.blockNumber, block.number);
        assertEq(rec.timestamp, block.timestamp);
        assertEq(rec.datasetCommitment, bytes32(uint256(0xABCD)));

        assertEq(registry.getEvaluationCount(), 1);
        assertEq(registry.getBestScore(AGENT_A), 2500);
    }

    /// @notice Test: unverified submission stores verified=false and does not update ranking
    function test_submitEvaluation_unverified() public {
        (
            uint256[] memory pi,
            uint256[] memory cm,
            uint256[] memory ood,
            uint256[] memory fri,
            uint256[] memory qv,
            uint256[] memory qp,
            uint256[] memory qm
        ) = _makeProof(10, 300, 1000, 0x1234, 200);

        uint256 id = unverifiedRegistry.submitEvaluation(AGENT_A, pi, cm, ood, fri, qv, qp, qm);
        assertEq(id, 1);

        EvaluationRegistry.EvaluationRecord memory rec = unverifiedRegistry.getEvaluation(1);
        assertFalse(rec.verified);

        // Ranking should not be updated for unverified
        (address[] memory agents, ) = unverifiedRegistry.getTopAgents(10);
        assertEq(agents.length, 0, "No agents should be ranked for unverified submissions");
        assertEq(unverifiedRegistry.getBestScore(AGENT_A), 0);
    }

    /// @notice Test: revert on zero agent address
    function test_revertOnZeroAgent() public {
        (
            uint256[] memory pi,
            uint256[] memory cm,
            uint256[] memory ood,
            uint256[] memory fri,
            uint256[] memory qv,
            uint256[] memory qp,
            uint256[] memory qm
        ) = _makeProof(5, 100, 500, 0xDEAD, 300);

        vm.expectRevert("Agent address cannot be zero");
        registry.submitEvaluation(address(0), pi, cm, ood, fri, qv, qp, qm);
    }

    /// @notice Test: revert on invalid public inputs length
    function test_revertOnInvalidPublicInputs() public {
        uint256[] memory pi = new uint256[](3); // wrong length
        uint256[] memory cm = new uint256[](1);
        uint256[] memory ood = new uint256[](1);
        uint256[] memory fri = new uint256[](1);
        uint256[] memory qv = new uint256[](1);
        uint256[] memory qp = new uint256[](1);
        uint256[] memory qm = new uint256[](1);

        vm.expectRevert("Public inputs must have 4 elements");
        registry.submitEvaluation(AGENT_A, pi, cm, ood, fri, qv, qp, qm);
    }

    /// @notice Test: revert on duplicate proof submission
    function test_revertOnDuplicateProof() public {
        (
            uint256[] memory pi,
            uint256[] memory cm,
            uint256[] memory ood,
            uint256[] memory fri,
            uint256[] memory qv,
            uint256[] memory qp,
            uint256[] memory qm
        ) = _makeProof(10, 200, 800, 0xBEEF, 400);

        registry.submitEvaluation(AGENT_A, pi, cm, ood, fri, qv, qp, qm);

        vm.expectRevert("Proof already submitted");
        registry.submitEvaluation(AGENT_A, pi, cm, ood, fri, qv, qp, qm);
    }

    /// @notice Test: multiple evaluations for same agent are tracked correctly
    function test_getAgentEvaluations_multiple() public {
        for (uint256 i = 0; i < 3; i++) {
            (
                uint256[] memory pi,
                uint256[] memory cm,
                uint256[] memory ood,
                uint256[] memory fri,
                uint256[] memory qv,
                uint256[] memory qp,
                uint256[] memory qm
            ) = _makeProof(10 + i, 100 + i, 500 + i * 100, 0xAAAA + i, 500 + i * 10);

            registry.submitEvaluation(AGENT_A, pi, cm, ood, fri, qv, qp, qm);
        }

        EvaluationRegistry.EvaluationRecord[] memory records =
            registry.getAgentEvaluations(AGENT_A);
        assertEq(records.length, 3, "Should have 3 evaluations");
        assertEq(records[0].tradeCount, 10);
        assertEq(records[1].tradeCount, 11);
        assertEq(records[2].tradeCount, 12);
    }

    /// @notice Test: getTopAgents returns correct descending ranking for 5 agents, top 3
    function test_getTopAgents_ranking() public {
        address[5] memory agents = [AGENT_A, AGENT_B, AGENT_C, AGENT_D, AGENT_E];
        uint256[5] memory scores = [uint256(300), 500, 100, 400, 200];

        for (uint256 i = 0; i < 5; i++) {
            (
                uint256[] memory pi,
                uint256[] memory cm,
                uint256[] memory ood,
                uint256[] memory fri,
                uint256[] memory qv,
                uint256[] memory qp,
                uint256[] memory qm
            ) = _makeProof(10, 100, scores[i], 0xF000 + i, 600 + i * 10);

            registry.submitEvaluation(agents[i], pi, cm, ood, fri, qv, qp, qm);
        }

        (address[] memory topAgents, uint256[] memory topScores) = registry.getTopAgents(3);

        assertEq(topAgents.length, 3, "Should return 3 agents");
        // Descending order: B(500), D(400), A(300)
        assertEq(topAgents[0], AGENT_B);
        assertEq(topScores[0], 500);
        assertEq(topAgents[1], AGENT_D);
        assertEq(topScores[1], 400);
        assertEq(topAgents[2], AGENT_A);
        assertEq(topScores[2], 300);
    }

    /// @notice Test: best score only updates when new score is higher
    function test_bestScoreUpdate() public {
        // First submission: score 200
        (
            uint256[] memory pi1,
            uint256[] memory cm1,
            uint256[] memory ood1,
            uint256[] memory fri1,
            uint256[] memory qv1,
            uint256[] memory qp1,
            uint256[] memory qm1
        ) = _makeProof(10, 100, 200, 0x1111, 700);
        registry.submitEvaluation(AGENT_A, pi1, cm1, ood1, fri1, qv1, qp1, qm1);
        assertEq(registry.getBestScore(AGENT_A), 200);

        // Second submission: lower score 100 — should NOT update
        (
            uint256[] memory pi2,
            uint256[] memory cm2,
            uint256[] memory ood2,
            uint256[] memory fri2,
            uint256[] memory qv2,
            uint256[] memory qp2,
            uint256[] memory qm2
        ) = _makeProof(10, 100, 100, 0x2222, 800);
        registry.submitEvaluation(AGENT_A, pi2, cm2, ood2, fri2, qv2, qp2, qm2);
        assertEq(registry.getBestScore(AGENT_A), 200, "Best score should not decrease");

        // Third submission: higher score 500 — should update
        (
            uint256[] memory pi3,
            uint256[] memory cm3,
            uint256[] memory ood3,
            uint256[] memory fri3,
            uint256[] memory qv3,
            uint256[] memory qp3,
            uint256[] memory qm3
        ) = _makeProof(10, 100, 500, 0x3333, 900);
        registry.submitEvaluation(AGENT_A, pi3, cm3, ood3, fri3, qv3, qp3, qm3);
        assertEq(registry.getBestScore(AGENT_A), 500, "Best score should update to higher value");
    }

    /// @notice Test: reverting verifier records unverified evaluation
    function test_verifierReverts_recordsUnverified() public {
        (
            uint256[] memory pi,
            uint256[] memory cm,
            uint256[] memory ood,
            uint256[] memory fri,
            uint256[] memory qv,
            uint256[] memory qp,
            uint256[] memory qm
        ) = _makeProof(20, 400, 3000, 0xCAFE, 1000);

        uint256 id =
            revertingRegistry.submitEvaluation(AGENT_A, pi, cm, ood, fri, qv, qp, qm);
        assertEq(id, 1);

        EvaluationRegistry.EvaluationRecord memory rec = revertingRegistry.getEvaluation(1);
        assertFalse(rec.verified, "Should be unverified when verifier reverts");
        assertEq(rec.sharpeSqBps, 3000);

        // Should not appear in ranking
        (address[] memory agents, ) = revertingRegistry.getTopAgents(10);
        assertEq(agents.length, 0);
    }
}
