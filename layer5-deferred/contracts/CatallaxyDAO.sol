// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Governor} from "@openzeppelin/contracts/governance/Governor.sol";
import {GovernorSettings} from "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import {GovernorCountingSimple} from "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import {GovernorVotes} from "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import {GovernorVotesQuorumFraction} from
    "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import {GovernorTimelockControl} from "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IVotes} from "@openzeppelin/contracts/governance/utils/IVotes.sol";

/// @title CatallaxyDAO
/// @notice Monograph alignment: §6.10 (Polycentric Governance).
///
/// Deliberately narrow jurisdiction. This DAO governs the *commons*: scope schemas
/// and their SAE J2735/J1979 mappings, which attestors count as evidence of custody,
/// which ZK verifiers are trusted, the federated round calendar, and the fee within
/// its coded ceiling.
///
/// It has no jurisdiction over any individual vehicle. There is no function anywhere
/// in this suite by which a majority can price, grant, or revoke consent on a car it
/// does not own. Polycentricity is enforced by the absence of that function, not by
/// a norm against using it — the registry and the consent market simply expose no
/// governance hook on a vehicle's own policies.
///
/// Two additions over a bare Governor, both structural:
///
/// - A quorum floor (`GovernorVotesQuorumFraction`). Bare `Governor` has no quorum,
///   so a single voter passes a proposal in an empty room; for a registry that
///   admits attestors and verifiers, that is the whole attack.
/// - A timelock (`GovernorTimelockControl`). Every executed decision is visible for
///   the delay before it binds, which is what makes exit a real option: an owner who
///   dislikes a newly admitted attestor has time to advance their consent epoch and
///   leave before it takes effect.
contract CatallaxyDAO is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl
{
    /// @param _token $CATALLAXY, as an IVotes source.
    /// @param _timelock Executor that actually holds ownership of the registries.
    /// @param _votingDelay Blocks (or seconds, per the token's clock) before voting opens.
    /// @param _votingPeriod Duration of the vote.
    /// @param _proposalThreshold Voting units required to propose.
    /// @param _quorumFraction Percent of total supply that must vote for validity.
    constructor(
        IVotes _token,
        TimelockController _timelock,
        uint48 _votingDelay,
        uint32 _votingPeriod,
        uint256 _proposalThreshold,
        uint256 _quorumFraction
    )
        Governor("Catallaxy of Machines DAO")
        GovernorSettings(_votingDelay, _votingPeriod, _proposalThreshold)
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(_quorumFraction)
        GovernorTimelockControl(_timelock)
    {}

    // ------------------------------------------------------- required overrides

    function votingDelay() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.votingDelay();
    }

    function votingPeriod() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.votingPeriod();
    }

    function proposalThreshold() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.proposalThreshold();
    }

    function quorum(uint256 timepoint)
        public
        view
        override(Governor, GovernorVotesQuorumFraction)
        returns (uint256)
    {
        return super.quorum(timepoint);
    }

    function state(uint256 proposalId)
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (ProposalState)
    {
        return super.state(proposalId);
    }

    function proposalNeedsQueuing(uint256 proposalId)
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (bool)
    {
        return super.proposalNeedsQueuing(proposalId);
    }

    function _queueOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint48) {
        return super._queueOperations(proposalId, targets, values, calldatas, descriptionHash);
    }

    function _executeOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) {
        super._executeOperations(proposalId, targets, values, calldatas, descriptionHash);
    }

    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint256) {
        return super._cancel(targets, values, calldatas, descriptionHash);
    }

    function _executor() internal view override(Governor, GovernorTimelockControl) returns (address) {
        return super._executor();
    }
}
