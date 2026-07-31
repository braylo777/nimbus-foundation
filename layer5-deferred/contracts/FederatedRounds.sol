// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ICatallaxyVIN} from "./interfaces/ICatallaxyVIN.sol";
import {ICatallaxyConsent} from "./interfaces/ICatallaxyConsent.sol";
import {IProofVerifier} from "./interfaces/IProofVerifier.sol";

interface IMintableERC20 is IERC20 {
    function mint(address to, uint256 amount) external;
}

/// @title FederatedRounds — verified federated learning as Hayekian aggregation
/// @notice Monograph alignment: §6.6 (Federated Learning as Hayekian Aggregation).
///
/// Each round is an open call for model updates over one scope. A vehicle's edge
/// node trains locally, commits to its weight delta, and proves in zero knowledge
/// that the delta was computed by the stated procedure over data belonging to a
/// *registered* vehicle — without revealing the VIN, the location trace, or the
/// raw telemetry. Accepting the proof mints the contributor's reward. Only the
/// commitment lands on chain; the aggregator fetches deltas off-chain and can
/// verify each against its commitment.
///
/// The knowledge stays local; only what can be aggregated travels. That is the
/// whole point of the chapter, and it is also what makes the reward honest: the
/// protocol pays for a proof of useful work on real vehicle data, not for a
/// self-report.
///
/// Circuit public-signal order (enforced positionally below — a verifier adapter
/// must match it exactly):
///   [0] nullifier          = H(vehicleSecret, roundId)
///   [1] updateCommitment   = H(weightDelta)
///   [2] roundId
///   [3] modelCommitment    = H(globalWeights, trainingSpec) for this round
///   [4] vehicleCommitment  = the registry's commitment for the claimed tokenId
///
/// Signals [2]–[4] are supplied by this contract from trusted storage, never by the
/// submitter, so a valid proof cannot be replayed into a different round or
/// attributed to a different vehicle. [0] bounds each vehicle to one reward per
/// round while keeping which vehicle it was private: the nullifier is unlinkable
/// to the tokenId, so double-claim resistance costs no anonymity.
contract FederatedRounds is Ownable {
    ICatallaxyVIN public immutable vin;
    ICatallaxyConsent public immutable consent;
    IMintableERC20 public immutable rewardToken;

    struct Round {
        bytes32 scope; // which consent scope the training data falls under
        bytes32 modelCommitment; // global weights + training spec this round builds on
        address verifier; // IProofVerifier adapter for this round's circuit
        uint128 rewardPerUpdate; // $CATALLAXY minted per accepted update
        uint64 opensAt;
        uint64 closesAt;
        uint32 maxUpdates; // caps total emission for the round
        uint32 accepted;
        bool cancelled;
    }

    mapping(uint256 roundId => Round) private _rounds;
    /// @dev Per-round nullifier set. Scoped per round so a vehicle contributing to
    ///      every round is normal, while contributing twice to one round is not.
    mapping(uint256 roundId => mapping(bytes32 nullifier => bool)) public nullifierUsed;
    /// @notice Optional edge node authorised to submit on a vehicle's behalf, so the
    ///         owner's cold key never has to sit in the car.
    mapping(uint256 tokenId => address) public nodeOf;

    uint256 public nextRoundId;

    event RoundCreated(
        uint256 indexed roundId,
        bytes32 indexed scope,
        bytes32 modelCommitment,
        address verifier,
        uint256 rewardPerUpdate,
        uint64 opensAt,
        uint64 closesAt,
        uint32 maxUpdates
    );
    event RoundCancelled(uint256 indexed roundId);
    event NodeAuthorised(uint256 indexed tokenId, address indexed node);
    event UpdateAccepted(
        uint256 indexed roundId,
        bytes32 indexed nullifier,
        bytes32 updateCommitment,
        address indexed rewardedTo,
        uint256 reward
    );

    error UnknownRound();
    error RoundNotOpen();
    error RoundFull();
    error UnknownVehicle();
    error NotOwnerOrNode();
    error FederatedNotPermitted();
    error NullifierAlreadyUsed();
    error InvalidProof();
    error BadRoundWindow();
    error ZeroVerifier();

    constructor(address _vin, address _consent, address _rewardToken, address governance) Ownable(governance) {
        vin = ICatallaxyVIN(_vin);
        consent = ICatallaxyConsent(_consent);
        rewardToken = IMintableERC20(_rewardToken);
    }

    // -------------------------------------------------------------- round admin

    /// @dev Governance-gated: the DAO decides which circuits are trusted and what a
    ///      round pays. It cannot decide that a given vehicle participates — that
    ///      remains a per-vehicle policy flag set by the owner.
    function createRound(
        bytes32 scope,
        bytes32 modelCommitment,
        address verifier,
        uint128 rewardPerUpdate,
        uint64 opensAt,
        uint64 closesAt,
        uint32 maxUpdates
    ) external onlyOwner returns (uint256 roundId) {
        if (verifier == address(0)) revert ZeroVerifier();
        if (closesAt <= opensAt || maxUpdates == 0) revert BadRoundWindow();

        roundId = ++nextRoundId;
        _rounds[roundId] = Round({
            scope: scope,
            modelCommitment: modelCommitment,
            verifier: verifier,
            rewardPerUpdate: rewardPerUpdate,
            opensAt: opensAt,
            closesAt: closesAt,
            maxUpdates: maxUpdates,
            accepted: 0,
            cancelled: false
        });

        emit RoundCreated(
            roundId, scope, modelCommitment, verifier, rewardPerUpdate, opensAt, closesAt, maxUpdates
        );
    }

    function cancelRound(uint256 roundId) external onlyOwner {
        if (_rounds[roundId].verifier == address(0)) revert UnknownRound();
        _rounds[roundId].cancelled = true;
        emit RoundCancelled(roundId);
    }

    /// @notice Authorise (or clear, with `address(0)`) the in-vehicle node key.
    function authoriseNode(uint256 tokenId, address node) external {
        if (!vin.exists(tokenId)) revert UnknownVehicle();
        if (vin.ownerOf(tokenId) != msg.sender) revert NotOwnerOrNode();
        nodeOf[tokenId] = node;
        emit NodeAuthorised(tokenId, node);
    }

    // ------------------------------------------------------------- contribution

    /// @notice Submit a proven local model update and claim the round reward.
    /// @param roundId Round being contributed to.
    /// @param tokenId Vehicle index whose data was trained on.
    /// @param updateCommitment Commitment to the weight delta; the aggregator matches
    ///        the off-chain payload against this.
    /// @param nullifier H(vehicleSecret, roundId), proven inside the circuit.
    /// @param proof Proof blob for the round's verifier adapter.
    /// @dev Reward is minted to the vehicle *owner*, not to the submitting node.
    ///      A compromised or rented edge key can therefore burn the vehicle's
    ///      once-per-round slot but cannot divert the payment.
    function submitUpdate(
        uint256 roundId,
        uint256 tokenId,
        bytes32 updateCommitment,
        bytes32 nullifier,
        bytes calldata proof
    ) external {
        Round storage r = _rounds[roundId];
        if (r.verifier == address(0)) revert UnknownRound();
        if (r.cancelled || block.timestamp < r.opensAt || block.timestamp >= r.closesAt) revert RoundNotOpen();
        if (r.accepted >= r.maxUpdates) revert RoundFull();

        if (!vin.exists(tokenId)) revert UnknownVehicle();
        address owner = vin.ownerOf(tokenId);
        if (msg.sender != owner && msg.sender != nodeOf[tokenId]) revert NotOwnerOrNode();

        // Federated participation is consent, not a default. Even though no raw
        // telemetry leaves the vehicle, the owner must have opted this scope in.
        if (!consent.allowsFederatedModel(tokenId, r.scope)) revert FederatedNotPermitted();

        if (nullifierUsed[roundId][nullifier]) revert NullifierAlreadyUsed();

        uint256[] memory publicInputs = new uint256[](5);
        publicInputs[0] = uint256(nullifier);
        publicInputs[1] = uint256(updateCommitment);
        publicInputs[2] = roundId;
        publicInputs[3] = uint256(r.modelCommitment);
        publicInputs[4] = uint256(vin.commitmentOf(tokenId));
        if (!IProofVerifier(r.verifier).verify(proof, publicInputs)) revert InvalidProof();

        nullifierUsed[roundId][nullifier] = true;
        r.accepted += 1;

        uint256 reward = r.rewardPerUpdate;
        if (reward != 0) rewardToken.mint(owner, reward);

        emit UpdateAccepted(roundId, nullifier, updateCommitment, owner, reward);
    }

    function roundOf(uint256 roundId) external view returns (Round memory) {
        return _rounds[roundId];
    }
}
