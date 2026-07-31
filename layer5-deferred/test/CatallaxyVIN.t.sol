// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {CatallaxyVIN} from "../contracts/CatallaxyVIN.sol";

contract CatallaxyVINTest is Base {
    function test_registersUnderAttestation() public {
        uint256 tokenId = _registerAlice();
        assertEq(tokenId, 1, "ids start at 1 so 0 means unregistered");
        assertEq(vinReg.ownerOf(tokenId), alice);
        assertTrue(vinReg.exists(tokenId));
        assertEq(vinReg.consentEpoch(tokenId), 0);
        assertEq(vinReg.epochChangedAt(tokenId), 0);
    }

    /// The core reason registration is attested: a VIN is readable through a
    /// windshield, so self-registration would let a passer-by mint the consent
    /// rights to a stranger's car.
    function test_unattestedRegistrationRejected() public {
        uint256 randomPk = 0xBADBEEF;
        bytes32 commitment = _commit("5YJ3E1EA7KF000002", bytes32("s"));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory sig = _sign(randomPk, commitment, insurer, bytes32(0), deadline);

        vm.expectRevert(CatallaxyVIN.UnknownAttestor.selector);
        vinReg.registerVehicle(commitment, insurer, bytes32(0), deadline, vm.addr(randomPk), sig);
    }

    /// An attestation naming Alice cannot be redirected to the insurer: the owner
    /// address is inside the signed struct.
    function test_attestationBoundToNamedOwner() public {
        bytes32 commitment = _commit("5YJ3E1EA7KF000003", bytes32("s"));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory sig = _sign(attestorPk, commitment, alice, bytes32(0), deadline);

        vm.expectRevert(CatallaxyVIN.BadAttestation.selector);
        vinReg.registerVehicle(commitment, insurer, bytes32(0), deadline, attestor, sig);
    }

    function test_commitmentCannotBeSquattedTwice() public {
        _registerAlice();
        bytes32 commitment = _commit("5YJ3E1EA7KF000001", bytes32("salt-1"));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory sig = _sign(attestorPk, commitment, insurer, bytes32(0), deadline);

        vm.expectRevert(CatallaxyVIN.CommitmentAlreadyRegistered.selector);
        vinReg.registerVehicle(commitment, insurer, bytes32(0), deadline, attestor, sig);
    }

    function test_expiredAttestationRejected() public {
        bytes32 commitment = _commit("5YJ3E1EA7KF000004", bytes32("s"));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory sig = _sign(attestorPk, commitment, alice, bytes32(0), deadline);

        vm.warp(block.timestamp + 2 hours);
        vm.expectRevert(CatallaxyVIN.AttestationExpired.selector);
        vinReg.registerVehicle(commitment, alice, bytes32(0), deadline, attestor, sig);
    }

    /// The salt is what keeps the index unlinkable to an onlooker who knows the VIN,
    /// while still letting a counterparty who has been shown (vin, salt) confirm it.
    function test_commitmentHidesVinUntilRevealed() public {
        uint256 tokenId = _registerAlice();
        assertTrue(vinReg.verifyCommitment(tokenId, "5YJ3E1EA7KF000001", bytes32("salt-1")));
        assertFalse(vinReg.verifyCommitment(tokenId, "5YJ3E1EA7KF000001", bytes32("wrong-salt")));
        assertFalse(vinReg.verifyCommitment(tokenId, "5YJ3E1EA7KF999999", bytes32("salt-1")));
    }

    function test_transferAdvancesConsentEpoch() public {
        uint256 tokenId = _registerAlice();

        vm.prank(alice);
        vinReg.transferFrom(alice, insurer, tokenId);

        assertEq(vinReg.consentEpoch(tokenId), 1, "sale must not carry consent grants across");
        assertEq(vinReg.epochChangedAt(tokenId), uint64(block.timestamp));
    }

    function test_ownerPanicRevokeAdvancesEpoch() public {
        uint256 tokenId = _registerAlice();

        vm.prank(alice);
        vinReg.advanceEpoch(tokenId);
        assertEq(vinReg.consentEpoch(tokenId), 1);

        vm.prank(insurer);
        vm.expectRevert(CatallaxyVIN.NotVehicleOwner.selector);
        vinReg.advanceEpoch(tokenId);
    }

    function test_onlyGovernanceSetsAttestors() public {
        vm.prank(alice);
        vm.expectRevert();
        vinReg.setAttestor(alice, true);
    }
}
