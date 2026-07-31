// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICatallaxyConsent {
    function hasAccess(uint256 tokenId, bytes32 scope, address subscriber) external view returns (bool);

    function accessExpiry(uint256 tokenId, bytes32 scope, address subscriber) external view returns (uint64);

    function allowsFederatedModel(uint256 tokenId, bytes32 scope) external view returns (bool);
}
