// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title CatallaxyVIN — vehicle index registry
/// @notice Monograph alignment: §4.4, §4.6 (Identifier-not-Credential Doctrine).
///
/// Holding the token for a vehicle index proves ownership of that vehicle's
/// *data consent rights*. It proves nothing to the vehicle's gateway and grants
/// no remote control over it. The chain is a property-rights ledger, not a key.
///
/// Two deviations from the naive design, both load-bearing:
///
/// 1. Vehicles are registered under a *salted commitment*, not `keccak256(vin)`.
///    A VIN is a public identifier with ~10^8 realistic entropy for a known
///    make/model/year, so a bare hash is a rainbow-table lookup: anyone could
///    confirm a given VIN is registered and enumerate the fleet from the
///    windshield of a parking lot. `commitment = keccak256(abi.encode(vin, salt))`
///    with a 256-bit owner-held salt keeps the index unlinkable to onlookers
///    while still being provable to a counterparty on demand.
///
/// 2. Registration requires an EIP-712 attestation from an approved attestor.
///    Permissionless self-registration is unsound *because* the VIN is a public
///    identifier: the first party to read a VIN off a dashboard could mint the
///    consent rights to someone else's car and start selling their telemetry.
///    An attestor is whatever the DAO recognises as evidence of custody — an OEM
///    OAuth consent broker, a dongle provisioning service, a licensed inspector,
///    a title registry. The attestor asserts custody; it does not custody keys.
contract CatallaxyVIN is ERC721, EIP712, Ownable {
    // keccak256("VehicleAttestation(bytes32 commitment,address owner,bytes32 evidenceRef,uint64 deadline)")
    bytes32 private constant ATTESTATION_TYPEHASH =
        keccak256("VehicleAttestation(bytes32 commitment,address owner,bytes32 evidenceRef,uint64 deadline)");

    mapping(bytes32 commitment => uint256 tokenId) public commitmentToTokenId;
    mapping(uint256 tokenId => bytes32 commitment) private _commitmentOf;

    /// @notice Attestors the DAO recognises as evidence of vehicle custody.
    mapping(address attestor => bool) public isAttestor;

    /// @notice Consumed attestation digests. Prevents replay of a single attestation.
    mapping(bytes32 digest => bool) public attestationUsed;

    mapping(uint256 tokenId => uint64) public consentEpoch;
    mapping(uint256 tokenId => uint64) public epochChangedAt;

    uint256 public nextTokenId;

    event VehicleRegistered(
        uint256 indexed tokenId, bytes32 indexed commitment, address indexed owner, address attestor, bytes32 evidenceRef
    );
    event AttestorSet(address indexed attestor, bool allowed);
    event ConsentEpochAdvanced(uint256 indexed tokenId, uint64 epoch, uint64 at, bool byTransfer);

    error CommitmentAlreadyRegistered();
    error ZeroCommitment();
    error UnknownAttestor();
    error AttestationExpired();
    error AttestationAlreadyUsed();
    error BadAttestation();
    error NotVehicleOwner();

    constructor(address governance)
        ERC721("Catallaxy Vehicle Index", "C-VIN")
        EIP712("CatallaxyVIN", "1")
        Ownable(governance)
    {}

    // ------------------------------------------------------------------ registry

    /// @notice Register a vehicle index against a custody attestation.
    /// @param commitment keccak256(abi.encode(vin, salt)); salt stays with the owner.
    /// @param owner Account that will hold the consent rights.
    /// @param evidenceRef Opaque pointer to the off-chain evidence the attestor
    ///        relied on (content hash of an OAuth grant receipt, inspection report,
    ///        title record). Auditable after the fact without publishing the evidence.
    /// @param deadline Attestation expiry, seconds.
    /// @param attestor Approved attestor that signed.
    /// @param signature EOA (ECDSA) or ERC-1271 contract signature over the EIP-712 struct.
    /// @dev Callable by anyone holding a valid attestation, so a broker can sponsor
    ///      gas for an owner who holds no ETH. The signature, not the caller,
    ///      is the authority.
    function registerVehicle(
        bytes32 commitment,
        address owner,
        bytes32 evidenceRef,
        uint64 deadline,
        address attestor,
        bytes calldata signature
    ) external returns (uint256 tokenId) {
        if (commitment == bytes32(0)) revert ZeroCommitment();
        if (commitmentToTokenId[commitment] != 0) revert CommitmentAlreadyRegistered();
        if (!isAttestor[attestor]) revert UnknownAttestor();
        if (block.timestamp > deadline) revert AttestationExpired();

        bytes32 digest =
            _hashTypedDataV4(keccak256(abi.encode(ATTESTATION_TYPEHASH, commitment, owner, evidenceRef, deadline)));
        if (attestationUsed[digest]) revert AttestationAlreadyUsed();
        if (!SignatureChecker.isValidSignatureNow(attestor, digest, signature)) revert BadAttestation();
        attestationUsed[digest] = true;

        // Token ids start at 1 so that `commitmentToTokenId == 0` means "unregistered".
        tokenId = ++nextTokenId;
        commitmentToTokenId[commitment] = tokenId;
        _commitmentOf[tokenId] = commitment;

        _safeMint(owner, tokenId);
        emit VehicleRegistered(tokenId, commitment, owner, attestor, evidenceRef);
    }

    function setAttestor(address attestor, bool allowed) external onlyOwner {
        isAttestor[attestor] = allowed;
        emit AttestorSet(attestor, allowed);
    }

    // ------------------------------------------------------------------- epochs

    /// @notice Invalidate every consent grant on this vehicle, immediately.
    /// @dev The sovereignty backstop. Per-grant revocation lives in CatallaxyConsent
    ///      and settles escrow pro rata; this is the single-transaction panic switch
    ///      for an owner who does not want to enumerate counterparties first.
    ///      Escrow held against the invalidated grants is still settled fairly:
    ///      time already delivered pays out, the remainder refunds.
    function advanceEpoch(uint256 tokenId) external {
        if (_ownerOf(tokenId) != msg.sender) revert NotVehicleOwner();
        _advanceEpoch(tokenId, false);
    }

    function _advanceEpoch(uint256 tokenId, bool byTransfer) private {
        uint64 epoch = ++consentEpoch[tokenId];
        epochChangedAt[tokenId] = uint64(block.timestamp);
        emit ConsentEpochAdvanced(tokenId, epoch, uint64(block.timestamp), byTransfer);
    }

    /// @dev Transfer of the index must not carry the seller's consent grants with it.
    ///      Without this, buying a used car would silently hand you a live insurer
    ///      subscription you never agreed to, and selling one would keep paying the
    ///      seller for the buyer's driving. OZ v5 routes mint, burn and transfer
    ///      through `_update`; only the transfer/burn cases advance the epoch.
    function _update(address to, uint256 tokenId, address auth) internal override returns (address from) {
        from = super._update(to, tokenId, auth);
        if (from != address(0) && from != to) {
            _advanceEpoch(tokenId, true);
        }
    }

    // -------------------------------------------------------------------- views

    function commitmentOf(uint256 tokenId) external view returns (bytes32) {
        return _commitmentOf[tokenId];
    }

    function exists(uint256 tokenId) external view returns (bool) {
        return _ownerOf(tokenId) != address(0);
    }

    /// @notice Verify a claimed VIN against a registered index, off the critical path.
    /// @dev For a counterparty that has been shown `(vin, salt)` out of band and wants
    ///      on-chain confirmation that this index really is that vehicle.
    function verifyCommitment(uint256 tokenId, string calldata vin, bytes32 salt) external view returns (bool) {
        return _commitmentOf[tokenId] == keccak256(abi.encode(vin, salt)) && _commitmentOf[tokenId] != bytes32(0);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
