// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Votes} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title CatallaxyToken ($CATALLAXY)
/// @notice Governance and contribution unit. Minted to owners who contribute
///         verified federated-learning updates, and to the treasury by proposal.
/// @dev Supply is capped in code. An uncapped mint role held by governance means
///      a majority can dilute the owners who earned their stake by contributing —
///      which would make the token a claim on the majority's forbearance rather
///      than on the work done. `MINTER_ROLE` goes to the round registry; the DAO
///      timelock keeps the admin role and can rotate it.
contract CatallaxyToken is ERC20, ERC20Permit, ERC20Votes, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    uint256 public immutable maxSupply;

    error MaxSupplyExceeded();

    constructor(address admin, uint256 _maxSupply, uint256 initialTreasuryMint, address treasury)
        ERC20("Catallaxy", "CATALLAXY")
        ERC20Permit("Catallaxy")
    {
        maxSupply = _maxSupply;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        if (initialTreasuryMint != 0) {
            if (initialTreasuryMint > _maxSupply) revert MaxSupplyExceeded();
            _mint(treasury, initialTreasuryMint);
        }
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (totalSupply() + amount > maxSupply) revert MaxSupplyExceeded();
        _mint(to, amount);
    }

    // ------------------------------------------------------------------- clock

    /// @dev Timestamp clock, not block numbers. `GovernorVotes` inherits its clock
    ///      from the token, and L2 block times are neither uniform nor a promise —
    ///      Base and Arbitrum can and do change them, which would silently redefine
    ///      every voting period expressed in blocks. Seconds mean what they say.
    function clock() public view override returns (uint48) {
        return uint48(block.timestamp);
    }

    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() public pure override returns (string memory) {
        return "mode=timestamp";
    }

    // ------------------------------------------------------- required overrides

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Votes) {
        super._update(from, to, value);
    }

    function nonces(address owner) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }
}
