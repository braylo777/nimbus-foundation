// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Adapter interface over a circuit-specific verifier.
/// @dev snarkjs emits `verifyProof(uint[2],uint[2][2],uint[2],uint[N])`. Wrap that
///      generated contract in a thin adapter implementing this interface so the
///      round registry stays agnostic to proof system and public-signal arity.
interface IProofVerifier {
    /// @param proof Opaque, ABI-encoded proof blob understood by the adapter.
    /// @param publicInputs Public signals, in the order documented by the circuit.
    function verify(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}
