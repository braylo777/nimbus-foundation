// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ICatallaxyVIN} from "./interfaces/ICatallaxyVIN.sol";

/// @title CatallaxyConsent — consent brokerage and price discovery
/// @notice Monograph alignment: §6.2, §6.4 (Consent Brokerage, Discovery of Prices).
///
/// An owner posts, per scope, the price at which they will consent to a stream.
/// A consumer buys a time-bounded grant. The posted prices *are* the price signal:
/// there is no clearing committee and no platform setting a take rate on the
/// owner's behalf beyond the DAO fee, which is capped in code.
///
/// Settlement is streamed, not paid up front. This is what makes revocation real:
/// if consent could be sold only as a lump sum, revoking mid-term would either rob
/// the buyer or trap the owner. Here the escrow accrues to the owner second by
/// second, and the unearned remainder is always refundable to the buyer. Consent
/// stays revocable at every instant without either side taking a loss on the
/// portion already delivered.
///
/// Funds are never pushed. Every payout lands in `credits` and is pulled by its
/// recipient, so a vehicle owner whose address is a contract that reverts on
/// receive cannot brick the subscription path for everyone else.
contract CatallaxyConsent is Ownable, ReentrancyGuard {
    uint256 private constant DAY = 1 days;
    uint16 private constant BPS = 10_000;
    /// @dev Hard ceiling on the DAO's cut. Governance cannot vote itself above 5%;
    ///      raising it requires redeploying and migrating, which owners can refuse.
    uint16 public constant MAX_FEE_BPS = 500;

    ICatallaxyVIN public immutable vin;

    struct DataPolicy {
        uint128 pricePerDay; // wei per day of access
        uint32 minDays;
        uint32 maxDays;
        bool allowFederatedModel; // permits ZK model updates without raw streaming
        bool active;
    }

    struct Grant {
        address payee; // vehicle owner at grant time, not at settlement time
        uint64 startedAt;
        uint64 expiresAt;
        uint64 revokedAt; // 0 while live
        uint64 epoch; // consent epoch this grant was issued under
        bool settled;
        uint128 escrow; // wei still held against this grant
        uint128 ratePerSecond;
    }

    mapping(uint256 tokenId => mapping(bytes32 scope => DataPolicy)) private _policies;
    mapping(uint256 tokenId => mapping(bytes32 scope => mapping(address subscriber => Grant))) private _grants;

    /// @notice Pull-payment balances: owners' revenue, buyers' refunds, DAO fees.
    mapping(address account => uint256) public credits;

    address public treasury;
    uint16 public feeBps;

    event PolicyUpdated(
        uint256 indexed tokenId,
        bytes32 indexed scope,
        uint256 pricePerDay,
        uint32 minDays,
        uint32 maxDays,
        bool allowFederatedModel,
        bool active
    );
    event AccessGranted(
        uint256 indexed tokenId,
        bytes32 indexed scope,
        address indexed subscriber,
        uint64 expiresAt,
        uint256 escrow,
        uint64 epoch
    );
    event AccessRevoked(uint256 indexed tokenId, bytes32 indexed scope, address indexed subscriber, uint64 at);
    event GrantSettled(
        uint256 indexed tokenId,
        bytes32 indexed scope,
        address indexed subscriber,
        uint256 earned,
        uint256 refunded,
        uint256 fee
    );
    event Withdrawn(address indexed account, uint256 amount);
    event FeeUpdated(uint16 feeBps, address treasury);

    error NotVehicleOwner();
    error UnknownVehicle();
    error PolicyInactive();
    error TermOutOfBounds();
    error InsufficientPayment();
    error GrantOutstanding();
    error NoSuchGrant();
    error NotSettleableYet();
    error PriceTooLowForStreaming();
    error FeeTooHigh();
    error NothingToWithdraw();
    error TransferFailed();

    constructor(address _vin, address governance, address _treasury, uint16 _feeBps) Ownable(governance) {
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh();
        vin = ICatallaxyVIN(_vin);
        treasury = _treasury;
        feeBps = _feeBps;
    }

    modifier onlyVehicleOwner(uint256 tokenId) {
        if (!vin.exists(tokenId)) revert UnknownVehicle();
        if (vin.ownerOf(tokenId) != msg.sender) revert NotVehicleOwner();
        _;
    }

    // ------------------------------------------------------------------ policies

    /// @notice Post terms for one scope of one vehicle.
    /// @dev `pricePerDay` must be at least 86_400 wei so the per-second rate is
    ///      non-zero and streaming settlement is exact; below that, integer
    ///      truncation would silently make the stream free. Zero is allowed and
    ///      means "consent freely given" — donating data to a research pool is a
    ///      legitimate price, and the monograph's argument is about the owner
    ///      choosing, not about the choice being paid.
    function setPolicy(
        uint256 tokenId,
        bytes32 scope,
        uint128 pricePerDay,
        uint32 minDays,
        uint32 maxDays,
        bool allowFederatedModel
    ) external onlyVehicleOwner(tokenId) {
        if (pricePerDay != 0 && pricePerDay < DAY) revert PriceTooLowForStreaming();
        if (minDays == 0 || maxDays < minDays) revert TermOutOfBounds();

        _policies[tokenId][scope] = DataPolicy({
            pricePerDay: pricePerDay,
            minDays: minDays,
            maxDays: maxDays,
            allowFederatedModel: allowFederatedModel,
            active: true
        });
        emit PolicyUpdated(tokenId, scope, pricePerDay, minDays, maxDays, allowFederatedModel, true);
    }

    /// @notice Stop selling a scope. Live grants are unaffected — use `revokeAccess`
    ///         or `CatallaxyVIN.advanceEpoch` to terminate those.
    function deactivatePolicy(uint256 tokenId, bytes32 scope) external onlyVehicleOwner(tokenId) {
        DataPolicy storage p = _policies[tokenId][scope];
        p.active = false;
        emit PolicyUpdated(tokenId, scope, p.pricePerDay, p.minDays, p.maxDays, p.allowFederatedModel, false);
    }

    // ------------------------------------------------------------- subscriptions

    /// @notice Buy a time-bounded grant over one scope of one vehicle.
    /// @dev The grant is scoped. A buyer of BATTERY_HEALTH gains nothing on
    ///      LOCATION_PRECISE, however cheap the former was.
    function subscribe(uint256 tokenId, bytes32 scope, uint32 daysRequested)
        external
        payable
        nonReentrant
        returns (uint64 expiresAt)
    {
        if (!vin.exists(tokenId)) revert UnknownVehicle();
        DataPolicy memory p = _policies[tokenId][scope];
        if (!p.active) revert PolicyInactive();
        if (daysRequested < p.minDays || daysRequested > p.maxDays) revert TermOutOfBounds();

        Grant storage existing = _grants[tokenId][scope][msg.sender];
        // One live grant per (vehicle, scope, buyer). A stale grant must be settled
        // first so its escrow is distributed before the slot is reused.
        if (existing.startedAt != 0 && !existing.settled) revert GrantOutstanding();

        uint256 duration = uint256(daysRequested) * DAY;
        uint256 quoted = uint256(p.pricePerDay) * daysRequested;
        if (msg.value < quoted) revert InsufficientPayment();

        // Charge exactly rate*duration; the truncated remainder and any overpayment
        // are credited straight back rather than being quietly retained.
        uint256 ratePerSecond = quoted / duration;
        uint256 cost = ratePerSecond * duration;
        if (msg.value > cost) credits[msg.sender] += msg.value - cost;

        expiresAt = uint64(block.timestamp + duration);
        _grants[tokenId][scope][msg.sender] = Grant({
            payee: vin.ownerOf(tokenId),
            startedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            revokedAt: 0,
            epoch: vin.consentEpoch(tokenId),
            settled: false,
            escrow: uint128(cost),
            ratePerSecond: uint128(ratePerSecond)
        });

        emit AccessGranted(tokenId, scope, msg.sender, expiresAt, cost, vin.consentEpoch(tokenId));
    }

    /// @notice Terminate a live grant now. Owner only, no notice period, no penalty.
    function revokeAccess(uint256 tokenId, bytes32 scope, address subscriber) external onlyVehicleOwner(tokenId) {
        Grant storage g = _grants[tokenId][scope][subscriber];
        if (g.startedAt == 0 || g.settled) revert NoSuchGrant();
        if (g.revokedAt == 0) {
            g.revokedAt = uint64(block.timestamp);
            emit AccessRevoked(tokenId, scope, subscriber, uint64(block.timestamp));
        }
        _settle(tokenId, scope, subscriber);
    }

    /// @notice Distribute a finished grant's escrow. Permissionless: either party,
    ///         or a keeper, can close the books once the term is over.
    function settle(uint256 tokenId, bytes32 scope, address subscriber) external {
        Grant storage g = _grants[tokenId][scope][subscriber];
        if (g.startedAt == 0 || g.settled) revert NoSuchGrant();
        _settle(tokenId, scope, subscriber);
    }

    /// @dev Earned time runs from `startedAt` to the earliest of: term expiry,
    ///      explicit revocation, and the epoch advance that invalidated the grant.
    ///      Using the recorded epoch-change timestamp — rather than "now" — is what
    ///      stops a seller from continuing to earn on a car they no longer own.
    ///      Revenue goes to `payee`, the owner *at grant time*, so a mid-term
    ///      transfer cannot redirect money the previous owner already earned.
    function _settle(uint256 tokenId, bytes32 scope, address subscriber) private {
        Grant storage g = _grants[tokenId][scope][subscriber];

        uint64 cutoff = g.expiresAt;
        if (g.revokedAt != 0 && g.revokedAt < cutoff) cutoff = g.revokedAt;
        if (vin.consentEpoch(tokenId) != g.epoch) {
            uint64 changedAt = vin.epochChangedAt(tokenId);
            if (changedAt != 0 && changedAt < cutoff) cutoff = changedAt;
        }
        if (block.timestamp < cutoff) revert NotSettleableYet();

        uint256 elapsed = cutoff > g.startedAt ? cutoff - g.startedAt : 0;
        uint256 earned = elapsed * g.ratePerSecond;
        uint256 escrow = g.escrow;
        if (earned > escrow) earned = escrow;
        uint256 refund = escrow - earned;

        uint256 fee = (earned * feeBps) / BPS;

        g.escrow = 0;
        g.settled = true;

        if (fee != 0) credits[treasury] += fee;
        if (earned - fee != 0) credits[g.payee] += earned - fee;
        if (refund != 0) credits[subscriber] += refund;

        emit GrantSettled(tokenId, scope, subscriber, earned - fee, refund, fee);
    }

    function withdraw() external nonReentrant returns (uint256 amount) {
        amount = credits[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credits[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(msg.sender, amount);
    }

    // -------------------------------------------------------------- governance

    function setFee(uint16 _feeBps, address _treasury) external onlyOwner {
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh();
        feeBps = _feeBps;
        treasury = _treasury;
        emit FeeUpdated(_feeBps, _treasury);
    }

    // -------------------------------------------------------------------- views

    /// @notice The single question the off-chain broker asks before relaying a byte.
    function hasAccess(uint256 tokenId, bytes32 scope, address subscriber) external view returns (bool) {
        Grant memory g = _grants[tokenId][scope][subscriber];
        if (g.startedAt == 0) return false;
        if (block.timestamp >= g.expiresAt) return false;
        if (g.revokedAt != 0 && block.timestamp >= g.revokedAt) return false;
        if (g.epoch != vin.consentEpoch(tokenId)) return false;
        return true;
    }

    /// @notice Unix time at which the broker must stop relaying, absent revocation.
    ///         Used to bound capability-token lifetime off-chain.
    function accessExpiry(uint256 tokenId, bytes32 scope, address subscriber) external view returns (uint64) {
        Grant memory g = _grants[tokenId][scope][subscriber];
        if (g.startedAt == 0 || g.epoch != vin.consentEpoch(tokenId)) return 0;
        if (g.revokedAt != 0 && g.revokedAt < g.expiresAt) return g.revokedAt;
        return g.expiresAt;
    }

    function allowsFederatedModel(uint256 tokenId, bytes32 scope) external view returns (bool) {
        DataPolicy memory p = _policies[tokenId][scope];
        return p.active && p.allowFederatedModel;
    }

    function policyOf(uint256 tokenId, bytes32 scope) external view returns (DataPolicy memory) {
        return _policies[tokenId][scope];
    }

    function grantOf(uint256 tokenId, bytes32 scope, address subscriber) external view returns (Grant memory) {
        return _grants[tokenId][scope][subscriber];
    }

    function quote(uint256 tokenId, bytes32 scope, uint32 daysRequested) external view returns (uint256) {
        return uint256(_policies[tokenId][scope].pricePerDay) * daysRequested;
    }
}
