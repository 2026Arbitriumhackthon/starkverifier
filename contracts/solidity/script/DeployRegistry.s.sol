// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {EvaluationRegistry} from "../src/EvaluationRegistry.sol";

contract DeployRegistryScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address stylusVerifier = vm.envAddress("STYLUS_VERIFIER_V4");

        console.log("========================================");
        console.log("  EvaluationRegistry - Deployment");
        console.log("========================================");
        console.log("");
        console.log("Deployer:", vm.addr(deployerPrivateKey));
        console.log("Chain ID:", block.chainid);
        console.log("Stylus Verifier:", stylusVerifier);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        EvaluationRegistry registry = new EvaluationRegistry(stylusVerifier);

        vm.stopBroadcast();

        console.log("========================================");
        console.log("  Deployment Successful!");
        console.log("========================================");
        console.log("EvaluationRegistry deployed at:", address(registry));
        console.log("");
        console.log("Update lib/contracts.ts with:");
        console.log("  EVALUATION_REGISTRY_ADDRESS =", address(registry));
    }
}
