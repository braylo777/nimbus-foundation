// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CatallaxyVIN} from "../contracts/CatallaxyVIN.sol";
import {CatallaxyConsent} from "../contracts/CatallaxyConsent.sol";
import {CatallaxyToken} from "../contracts/CatallaxyToken.sol";
import {FederatedRounds} from "../contracts/FederatedRounds.sol";
import {Scopes} from "../contracts/lib/Scopes.sol";

abstract contract Base is Test {
    bytes32 internal constant ATTESTATION_TYPEHASH =
        keccak256("VehicleAttestation(bytes32 commitment,address owner,bytes32 evidenceRef,uint64 deadline)");

    CatallaxyVIN internal vinReg;
    CatallaxyConsent internal consent;
    CatallaxyToken internal token;
    FederatedRounds internal rounds;

    uint256 internal attestorPk = 0xA11CE;
    address internal attestor;

    address internal treasury;
    address internal alice;
    address internal insurer;
    address internal researcher;

    uint16 internal constant FEE_BPS = 100; // 1%

    function setUp() public virtual {
        attestor = vm.addr(attestorPk);
        treasury = makeAddr("treasury");
        alice = makeAddr("alice");
        insurer = makeAddr("insurer");
        researcher = makeAddr("researcher");

        vinReg = new CatallaxyVIN(address(this));
        vinReg.setAttestor(attestor, true);

        consent = new CatallaxyConsent(address(vinReg), address(this), treasury, FEE_BPS);
        token = new CatallaxyToken(address(this), 100_000_000e18, 0, address(0));
        rounds = new FederatedRounds(address(vinReg), address(consent), address(token), address(this));
        token.grantRole(token.MINTER_ROLE(), address(rounds));

        vm.deal(insurer, 100 ether);
        vm.deal(researcher, 100 ether);

        // Timestamps start at 1 in Foundry; move somewhere realistic so that
        // "epoch never advanced" (0) is unambiguously distinguishable.
        vm.warp(1_800_000_000);
    }

    // --------------------------------------------------------------- attestation

    function _commit(string memory vinNumber, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(vinNumber, salt));
    }

    function _sign(uint256 pk, bytes32 commitment, address owner, bytes32 evidenceRef, uint64 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(ATTESTATION_TYPEHASH, commitment, owner, evidenceRef, deadline));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", vinReg.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Registers a vehicle to `owner` and returns its token id.
    function _register(address owner, string memory vinNumber, bytes32 salt) internal returns (uint256) {
        bytes32 commitment = _commit(vinNumber, salt);
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory sig = _sign(attestorPk, commitment, owner, bytes32("oauth-receipt"), deadline);
        return vinReg.registerVehicle(commitment, owner, bytes32("oauth-receipt"), deadline, attestor, sig);
    }

    function _registerAlice() internal returns (uint256) {
        return _register(alice, "5YJ3E1EA7KF000001", bytes32("salt-1"));
    }

    function _scope() internal pure returns (bytes32) {
        return Scopes.BATTERY_HEALTH;
    }
}
