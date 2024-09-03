// SPDX-License-Identifier: MIT
/*solhint-disable compiler-version */
pragma solidity ^0.8.20;

/// -----------------------------------------------------------------------
/// Imports
/// -----------------------------------------------------------------------

import {Script, console} from "forge-std/Script.sol";
import {Identity, IIdentity} from "@onchain-id/solidity/contracts/Identity.sol";
import {ClaimIssuer} from "@onchain-id/solidity/contracts/ClaimIssuer.sol";
import {DidKYC} from "../src/DidKYC.sol";
import {HelperConfig} from "../../../script/HelperConfig.s.sol";

contract DidKYCDeploy is Script {
    HelperConfig public config;

    ClaimIssuer public claimIssuer;

    DidKYC public didKYC;

    function run() public {
      config = new HelperConfig();
        (uint256 key) = config.activeNetworkConfig();

        vm.startBroadcast(vm.rememberKey(key));
        
        claimIssuer = new ClaimIssuer(vm.addr(key));
        
        didKYC = new DidKYC(vm.addr(key));

        // Autoriza para interagir com o contrato de did
        didKYC.authorizeAddress(address(claimIssuer)); 
        //didKYC.authorizeAddress(wallet1); //pode ser um cliente externo que queira validar o KYC
        
        vm.stopBroadcast();
        console.log("didKYC:", address(didKYC));
        console.log("claimIssuer:", address(claimIssuer));
    }
}
