// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IVotes} from "@openzeppelin/contracts/governance/utils/IVotes.sol";
import {CatallaxyVIN} from "../contracts/CatallaxyVIN.sol";
import {CatallaxyConsent} from "../contracts/CatallaxyConsent.sol";
import {CatallaxyToken} from "../contracts/CatallaxyToken.sol";
import {CatallaxyDAO} from "../contracts/CatallaxyDAO.sol";
import {FederatedRounds} from "../contracts/FederatedRounds.sol";

/// @notice Stage 1 deployment (Base / Arbitrum L2).
///
/// Ordering matters: the timelock is deployed first with an empty proposer set, the
/// governor is then granted PROPOSER/CANCELLER, and the deployer's admin role is
/// renounced last. Every registry is owned by the timelock from birth — there is no
/// window in which the deployer holds unilateral control over attestor admission.
///
/// Usage:
///   forge script script/Deploy.s.sol:Deploy --rpc-url base_sepolia --broadcast --verify
contract Deploy is Script {
    // Seconds, because CatallaxyToken runs a timestamp clock (`CLOCK_MODE()`).
    uint48 constant VOTING_DELAY = 1 days;
    uint32 constant VOTING_PERIOD = 7 days;
    uint256 constant PROPOSAL_THRESHOLD = 1_000e18;
    uint256 constant QUORUM_PCT = 4;
    uint256 constant TIMELOCK_DELAY = 2 days;

    uint256 constant MAX_SUPPLY = 100_000_000e18;
    uint256 constant TREASURY_MINT = 10_000_000e18;
    uint16 constant FEE_BPS = 100; // 1%

    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address genesisAttestor = vm.envAddress("GENESIS_ATTESTOR");

        vm.startBroadcast(pk);

        address[] memory none = new address[](0);
        TimelockController timelock = new TimelockController(TIMELOCK_DELAY, none, none, deployer);

        // Token and VIN registry are wired by the deployer, then handed over. Consent
        // and the round registry need no setup, so they are born timelock-owned.
        CatallaxyToken token = new CatallaxyToken(deployer, MAX_SUPPLY, TREASURY_MINT, address(timelock));

        CatallaxyDAO dao = new CatallaxyDAO(
            IVotes(address(token)), timelock, VOTING_DELAY, VOTING_PERIOD, PROPOSAL_THRESHOLD, QUORUM_PCT
        );

        CatallaxyVIN vinRegistry = new CatallaxyVIN(deployer);
        CatallaxyConsent consent =
            new CatallaxyConsent(address(vinRegistry), address(timelock), address(timelock), FEE_BPS);
        FederatedRounds rounds =
            new FederatedRounds(address(vinRegistry), address(consent), address(token), address(timelock));

        // Governor proposes and cancels; anyone may execute a matured operation, so
        // execution cannot be censored by a single keeper.
        timelock.grantRole(timelock.PROPOSER_ROLE(), address(dao));
        timelock.grantRole(timelock.CANCELLER_ROLE(), address(dao));
        timelock.grantRole(timelock.EXECUTOR_ROLE(), address(0));

        // The round registry is the only minter.
        token.grantRole(token.MINTER_ROLE(), address(rounds));

        // Seed one attestor so Stage 1 onboarding can begin; further attestors are a
        // governance decision.
        vinRegistry.setAttestor(genesisAttestor, true);

        // Hand everything to the timelock and drop the deployer's privileges. After
        // this block, no key controls the protocol outside a passed proposal.
        vinRegistry.transferOwnership(address(timelock));
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), address(timelock));
        token.renounceRole(token.DEFAULT_ADMIN_ROLE(), deployer);
        timelock.renounceRole(timelock.DEFAULT_ADMIN_ROLE(), deployer);

        vm.stopBroadcast();

        console2.log("timelock  ", address(timelock));
        console2.log("token     ", address(token));
        console2.log("dao       ", address(dao));
        console2.log("vin       ", address(vinRegistry));
        console2.log("consent   ", address(consent));
        console2.log("rounds    ", address(rounds));
    }
}
