// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice The subset of the vehicle index registry that downstream markets rely on.
interface ICatallaxyVIN {
    function ownerOf(uint256 tokenId) external view returns (address);

    function exists(uint256 tokenId) external view returns (bool);

    /// @notice Salted commitment to the VIN. Public index, never a credential.
    function commitmentOf(uint256 tokenId) external view returns (bytes32);

    /// @notice Monotonic counter invalidating every consent grant issued before it.
    ///         Advanced on transfer and by the owner's panic revoke.
    function consentEpoch(uint256 tokenId) external view returns (uint64);

    /// @notice Timestamp at which `consentEpoch` last advanced. 0 if never.
    function epochChangedAt(uint256 tokenId) external view returns (uint64);
}
