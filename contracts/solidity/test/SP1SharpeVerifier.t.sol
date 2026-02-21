// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SP1SharpeVerifier.sol";

/// @notice Mock SP1 verifier that always succeeds
contract MockSP1Verifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure override {}
}

/// @notice Mock SP1 verifier that always reverts
contract RevertingSP1Verifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure override {
        revert("SP1: invalid proof");
    }
}

contract SP1SharpeVerifierTest is Test {
    SP1SharpeVerifier public verifier;
    SP1SharpeVerifier public revertingVerifier;

    MockSP1Verifier public mockSP1;
    RevertingSP1Verifier public revertSP1;

    bytes32 constant VKEY = bytes32(uint256(0xDEADBEEF));

    function setUp() public {
        mockSP1 = new MockSP1Verifier();
        revertSP1 = new RevertingSP1Verifier();
        verifier = new SP1SharpeVerifier(address(mockSP1), VKEY);
        revertingVerifier = new SP1SharpeVerifier(address(revertSP1), VKEY);
    }

    /// @notice Test: successful verification returns decoded public values
    function test_verifySharpeProof_success() public view {
        // Bot A: 15 trades, total_return = 3000, sharpe_sq_scaled = 60000
        bytes memory publicValues = abi.encode(uint64(15), int64(3000), uint64(60000));
        bytes memory proofBytes = hex"AABB"; // mock proof

        (uint64 tradeCount, int64 totalReturn, uint64 sharpeSqScaled) =
            verifier.verifySharpeProof(publicValues, proofBytes);

        assertEq(tradeCount, 15);
        assertEq(totalReturn, 3000);
        assertEq(sharpeSqScaled, 60000);
    }

    /// @notice Test: Bot B values decode correctly
    function test_verifySharpeProof_botB() public view {
        bytes memory publicValues = abi.encode(uint64(23), int64(3000), uint64(18750));
        bytes memory proofBytes = hex"CCDD";

        (uint64 tradeCount, int64 totalReturn, uint64 sharpeSqScaled) =
            verifier.verifySharpeProof(publicValues, proofBytes);

        assertEq(tradeCount, 23);
        assertEq(totalReturn, 3000);
        assertEq(sharpeSqScaled, 18750);
    }

    /// @notice Test: verifyAndEmit emits event with correct values
    function test_verifyAndEmit_emitsEvent() public {
        bytes memory publicValues = abi.encode(uint64(15), int64(3000), uint64(60000));
        bytes memory proofBytes = hex"EEFF";

        vm.expectEmit(true, false, false, true);
        emit SP1SharpeVerifier.SharpeProofVerified(15, 3000, 60000);

        verifier.verifyAndEmit(publicValues, proofBytes);
    }

    /// @notice Test: invalid proof causes revert
    function test_verifySharpeProof_reverts() public {
        bytes memory publicValues = abi.encode(uint64(15), int64(3000), uint64(60000));
        bytes memory proofBytes = hex"AABB";

        vm.expectRevert("SP1: invalid proof");
        revertingVerifier.verifySharpeProof(publicValues, proofBytes);
    }

    /// @notice Test: constructor stores immutables correctly
    function test_constructor() public view {
        assertEq(address(verifier.sp1Verifier()), address(mockSP1));
        assertEq(verifier.programVKey(), VKEY);
    }

    /// @notice Test: gas measurement for Groth16 verification path
    function test_gasEstimate() public {
        bytes memory publicValues = abi.encode(uint64(15), int64(3000), uint64(60000));
        bytes memory proofBytes = hex"AABB";

        uint256 gasBefore = gasleft();
        verifier.verifyAndEmit(publicValues, proofBytes);
        uint256 gasUsed = gasBefore - gasleft();

        // Mock verifier uses minimal gas; real Groth16 would use ~200-300K
        // This test verifies the wrapper overhead is small
        assertLt(gasUsed, 100000, "Wrapper overhead should be small");
    }
}
