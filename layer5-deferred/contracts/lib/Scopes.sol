// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Scopes
/// @notice Canonical data-stream scope identifiers.
///
/// A scope is the unit of consent. Owners price and revoke per scope, never
/// "all vehicle data" — an owner who sells battery-degradation telemetry to a
/// warranty analyst has not thereby sold their trip history to an insurer.
///
/// Scope semantics are read-only telemetry projections. There is deliberately
/// no scope that maps to an actuation or command endpoint: the registry proves
/// consent rights over *data*, and confers no remote control over hardware
/// (Identifier-not-Credential Doctrine, §4.4/§4.6). A governance proposal that
/// adds an actuation scope is out of protocol scope and must be rejected at the
/// broker layer, which enforces its own read-only field allowlist.
library Scopes {
    /// @dev Speed, acceleration, heading. No absolute position.
    bytes32 internal constant KINEMATICS = keccak256("TELEMETRY_KINEMATICS_V1");

    /// @dev Coarse position, quantised off-chain to a geohash precision set by policy.
    bytes32 internal constant LOCATION_COARSE = keccak256("TELEMETRY_LOCATION_COARSE_V1");

    /// @dev Precise position trace. High re-identification risk; price accordingly.
    bytes32 internal constant LOCATION_PRECISE = keccak256("TELEMETRY_LOCATION_PRECISE_V1");

    /// @dev State of charge, pack temperature, charge cycles, degradation estimate.
    bytes32 internal constant BATTERY_HEALTH = keccak256("TELEMETRY_BATTERY_HEALTH_V1");

    /// @dev SAE J1979 diagnostic trouble codes and freeze frames.
    bytes32 internal constant DIAGNOSTICS = keccak256("TELEMETRY_DIAGNOSTICS_V1");

    /// @dev Odometer, engine hours, service intervals.
    bytes32 internal constant USAGE = keccak256("TELEMETRY_USAGE_V1");

    /// @dev Harsh-braking / cornering event counts, aggregated per window.
    bytes32 internal constant DRIVER_EVENTS = keccak256("TELEMETRY_DRIVER_EVENTS_V1");
}
