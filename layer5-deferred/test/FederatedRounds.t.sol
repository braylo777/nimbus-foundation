// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {FederatedRounds} from "../contracts/FederatedRounds.sol";
import {Scopes} from "../contracts/lib/Scopes.sol";
import {MockVerifier, RejectingVerifier} from "./mocks/MockVerifier.sol";

contract FederatedRoundsTest is Base {
    MockVerifier verifier;

    uint256 tokenId;
    uint256 roundId;
    address edgeNode;

    bytes32 constant MODEL = keccak256("battery-degradation-v3");
    uint128 constant REWARD = 25e18;

    function setUp() public override {
        super.setUp();
        verifier = new MockVerifier();
        edgeNode = makeAddr("edge-node");

        tokenId = _registerAlice();
        vm.startPrank(alice);
        consent.setPolicy(tokenId, Scopes.BATTERY_HEALTH, 1 ether, 1, 365, true);
        consent.setPolicy(tokenId, Scopes.LOCATION_PRECISE, 50 ether, 1, 30, false);
        rounds.authoriseNode(tokenId, edgeNode);
        vm.stopPrank();

        roundId = rounds.createRound(
            Scopes.BATTERY_HEALTH,
            MODEL,
            address(verifier),
            REWARD,
            uint64(block.timestamp),
            uint64(block.timestamp + 7 days),
            100
        );
    }

    function _proof(uint256 round_, uint256 token_, bytes32 nullifier, bytes32 updateCommitment, bytes32 model)
        internal
        view
        returns (bytes memory)
    {
        uint256[] memory inputs = new uint256[](5);
        inputs[0] = uint256(nullifier);
        inputs[1] = uint256(updateCommitment);
        inputs[2] = round_;
        inputs[3] = uint256(model);
        inputs[4] = uint256(vinReg.commitmentOf(token_));
        return abi.encode(inputs);
    }

    // ------------------------------------------------------------------ happy path

    /// Reward goes to the vehicle owner even though the edge node submitted: a rented
    /// or compromised in-car key can waste the round slot but cannot divert payment.
    function test_acceptedUpdateRewardsOwnerNotSubmitter() public {
        bytes32 nullifier = keccak256("nullifier-r1-v1");
        bytes32 update = keccak256("delta-1");

        vm.prank(edgeNode);
        rounds.submitUpdate(roundId, tokenId, update, nullifier, _proof(roundId, tokenId, nullifier, update, MODEL));

        assertEq(token.balanceOf(alice), REWARD);
        assertEq(token.balanceOf(edgeNode), 0);
        assertTrue(rounds.nullifierUsed(roundId, nullifier));
        assertEq(rounds.roundOf(roundId).accepted, 1);
    }

    // ------------------------------------------------------------------- consent

    /// No raw telemetry leaves the car in federated mode, but participation is still
    /// the owner's call, per scope.
    function test_federatedRequiresOwnerOptIn() public {
        uint256 locationRound = rounds.createRound(
            Scopes.LOCATION_PRECISE,
            MODEL,
            address(verifier),
            REWARD,
            uint64(block.timestamp),
            uint64(block.timestamp + 7 days),
            100
        );
        bytes32 nullifier = keccak256("nullifier-loc");
        bytes32 update = keccak256("delta-loc");

        vm.prank(edgeNode);
        vm.expectRevert(FederatedRounds.FederatedNotPermitted.selector);
        rounds.submitUpdate(
            locationRound, tokenId, update, nullifier, _proof(locationRound, tokenId, nullifier, update, MODEL)
        );
    }

    function test_strangerCannotSubmitForYourVehicle() public {
        bytes32 nullifier = keccak256("nullifier-x");
        bytes32 update = keccak256("delta-x");

        vm.prank(insurer);
        vm.expectRevert(FederatedRounds.NotOwnerOrNode.selector);
        rounds.submitUpdate(roundId, tokenId, update, nullifier, _proof(roundId, tokenId, nullifier, update, MODEL));
    }

    function test_revokedNodeCanNoLongerSubmit() public {
        vm.prank(alice);
        rounds.authoriseNode(tokenId, address(0));

        bytes32 nullifier = keccak256("nullifier-revoked");
        bytes32 update = keccak256("delta-revoked");

        vm.prank(edgeNode);
        vm.expectRevert(FederatedRounds.NotOwnerOrNode.selector);
        rounds.submitUpdate(roundId, tokenId, update, nullifier, _proof(roundId, tokenId, nullifier, update, MODEL));
    }

    // ----------------------------------------------------------------- soundness

    /// One reward per vehicle per round, enforced without learning which vehicle it
    /// was: the nullifier is unlinkable to the token id.
    function test_nullifierBlocksDoubleClaimInRound() public {
        bytes32 nullifier = keccak256("nullifier-r1-v1");
        bytes32 update = keccak256("delta-1");
        bytes memory proof = _proof(roundId, tokenId, nullifier, update, MODEL);

        vm.startPrank(edgeNode);
        rounds.submitUpdate(roundId, tokenId, update, nullifier, proof);
        vm.expectRevert(FederatedRounds.NullifierAlreadyUsed.selector);
        rounds.submitUpdate(roundId, tokenId, update, nullifier, proof);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), REWARD, "exactly one reward");
    }

    /// Nullifiers are per-round, so ordinary repeat participation is unimpeded.
    function test_sameVehicleContributesToTheNextRound() public {
        bytes32 n1 = keccak256("nullifier-r1-v1");
        bytes32 update = keccak256("delta-1");
        vm.prank(edgeNode);
        rounds.submitUpdate(roundId, tokenId, update, n1, _proof(roundId, tokenId, n1, update, MODEL));

        uint256 round2 = rounds.createRound(
            Scopes.BATTERY_HEALTH,
            MODEL,
            address(verifier),
            REWARD,
            uint64(block.timestamp),
            uint64(block.timestamp + 7 days),
            100
        );
        bytes32 n2 = keccak256("nullifier-r2-v1");
        vm.prank(edgeNode);
        rounds.submitUpdate(round2, tokenId, update, n2, _proof(round2, tokenId, n2, update, MODEL));

        assertEq(token.balanceOf(alice), REWARD * 2);
    }

    /// The round id is a public signal supplied by the contract, so a proof produced
    /// for round 1 is worthless in round 2.
    function test_proofCannotBeReplayedIntoAnotherRound() public {
        uint256 round2 = rounds.createRound(
            Scopes.BATTERY_HEALTH,
            MODEL,
            address(verifier),
            REWARD,
            uint64(block.timestamp),
            uint64(block.timestamp + 7 days),
            100
        );
        bytes32 nullifier = keccak256("nullifier-r1-v1");
        bytes32 update = keccak256("delta-1");
        bytes memory proofForRound1 = _proof(roundId, tokenId, nullifier, update, MODEL);

        vm.prank(edgeNode);
        vm.expectRevert(FederatedRounds.InvalidProof.selector);
        rounds.submitUpdate(round2, tokenId, update, nullifier, proofForRound1);
    }

    /// Likewise the vehicle commitment: a proof about Alice's car cannot be presented
    /// as work done by a second, freshly registered vehicle.
    function test_proofCannotBeAttributedToAnotherVehicle() public {
        uint256 other = _register(researcher, "5YJ3E1EA7KF000002", bytes32("salt-2"));
        vm.startPrank(researcher);
        consent.setPolicy(other, Scopes.BATTERY_HEALTH, 1 ether, 1, 365, true);
        rounds.authoriseNode(other, researcher);
        vm.stopPrank();

        bytes32 nullifier = keccak256("nullifier-r1-v1");
        bytes32 update = keccak256("delta-1");
        bytes memory proofForAlice = _proof(roundId, tokenId, nullifier, update, MODEL);

        vm.prank(researcher);
        vm.expectRevert(FederatedRounds.InvalidProof.selector);
        rounds.submitUpdate(roundId, other, update, nullifier, proofForAlice);
    }

    function test_badProofRejected() public {
        RejectingVerifier bad = new RejectingVerifier();
        uint256 strictRound = rounds.createRound(
            Scopes.BATTERY_HEALTH,
            MODEL,
            address(bad),
            REWARD,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            10
        );

        vm.prank(edgeNode);
        vm.expectRevert(FederatedRounds.InvalidProof.selector);
        rounds.submitUpdate(strictRound, tokenId, keccak256("u"), keccak256("n"), hex"00");
    }

    // ------------------------------------------------------------- round windows

    function test_closedRoundRejectsSubmissions() public {
        vm.warp(block.timestamp + 8 days);
        bytes32 nullifier = keccak256("late");
        bytes32 update = keccak256("delta-late");

        vm.prank(edgeNode);
        vm.expectRevert(FederatedRounds.RoundNotOpen.selector);
        rounds.submitUpdate(roundId, tokenId, update, nullifier, _proof(roundId, tokenId, nullifier, update, MODEL));
    }

    function test_cancelledRoundRejectsSubmissions() public {
        rounds.cancelRound(roundId);
        bytes32 nullifier = keccak256("cancelled");
        bytes32 update = keccak256("delta-c");

        vm.prank(edgeNode);
        vm.expectRevert(FederatedRounds.RoundNotOpen.selector);
        rounds.submitUpdate(roundId, tokenId, update, nullifier, _proof(roundId, tokenId, nullifier, update, MODEL));
    }

    /// Emission per round is bounded at creation, so a round cannot mint without limit.
    function test_roundCapBoundsEmission() public {
        uint256 capped = rounds.createRound(
            Scopes.BATTERY_HEALTH,
            MODEL,
            address(verifier),
            REWARD,
            uint64(block.timestamp),
            uint64(block.timestamp + 7 days),
            1
        );

        bytes32 n1 = keccak256("cap-1");
        vm.prank(edgeNode);
        rounds.submitUpdate(capped, tokenId, keccak256("d1"), n1, _proof(capped, tokenId, n1, keccak256("d1"), MODEL));

        uint256 other = _register(researcher, "5YJ3E1EA7KF000003", bytes32("salt-3"));
        vm.startPrank(researcher);
        consent.setPolicy(other, Scopes.BATTERY_HEALTH, 1 ether, 1, 365, true);
        bytes32 n2 = keccak256("cap-2");
        vm.expectRevert(FederatedRounds.RoundFull.selector);
        rounds.submitUpdate(capped, other, keccak256("d2"), n2, _proof(capped, other, n2, keccak256("d2"), MODEL));
        vm.stopPrank();
    }

    function test_onlyGovernanceCreatesRounds() public {
        vm.prank(alice);
        vm.expectRevert();
        rounds.createRound(
            Scopes.BATTERY_HEALTH,
            MODEL,
            address(verifier),
            REWARD,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            1
        );
    }
}
