// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

/// @notice Stand-in for a snarkjs-generated verifier adapter.
/// @dev A "valid proof" here is `abi.encode(publicInputs)`. That is obviously not
///      sound cryptography, but it reproduces the property the real verifier has and
///      that the round registry depends on: a proof is valid only for the exact
///      public-signal vector it was produced against. That lets the tests prove the
///      binding logic (round id, model commitment, vehicle commitment) without a
///      trusted setup in CI.
contract MockVerifier is IProofVerifier {
    function verify(bytes calldata proof, uint256[] calldata publicInputs) external pure returns (bool) {
        return keccak256(proof) == keccak256(abi.encode(publicInputs));
    }

    /// @notice Helper: build the proof blob a caller would submit for these signals.
    function blobFor(uint256[] calldata publicInputs) external pure returns (bytes memory) {
        return abi.encode(publicInputs);
    }
}

/// @notice Always-reject verifier, for the "bad proof" path.
contract RejectingVerifier is IProofVerifier {
    function verify(bytes calldata, uint256[] calldata) external pure returns (bool) {
        return false;
    }
}

/// @notice Vehicle owner that rejects ETH, to prove payouts are pull-based.
contract RevertingReceiver {
    receive() external payable {
        revert("no ether here");
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
}
