import { getAddress, type Address } from 'viem'

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`missing required env var ${name}`)
  return value
}

function optionalInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const parsed = Number.parseInt(raw, 10)
  if (Number.isNaN(parsed)) throw new Error(`env var ${name} must be an integer`)
  return parsed
}

export const config = {
  chainId: optionalInt('CHAIN_ID', 84532), // Base Sepolia
  rpcUrl: required('RPC_URL'),
  consentAddress: getAddress(required('CONSENT_ADDRESS')) as Address,
  vinAddress: getAddress(required('VIN_ADDRESS')) as Address,
  /** Optional. When set, in-vehicle node keys authorised there may push frames. */
  roundsAddress: process.env.ROUNDS_ADDRESS
    ? (getAddress(process.env.ROUNDS_ADDRESS) as Address)
    : undefined,

  port: optionalInt('PORT', 8787),

  /** HMAC secret for capability tokens. Rotating it invalidates every live session. */
  jwtSecret: required('BROKER_JWT_SECRET'),

  /**
   * Capability tokens are deliberately short-lived. Revocation on chain is instant;
   * a long-lived bearer token would reintroduce exactly the lag the consent epoch
   * exists to eliminate. 120s is the outer bound on how long a revoked subscriber
   * can still present a token — and the stream loop re-checks on chain anyway, so
   * in practice the cut is at the next poll.
   */
  capabilityTtlSeconds: optionalInt('CAPABILITY_TTL_SECONDS', 120),

  /** How often an open stream re-verifies consent against chain state. */
  accessRecheckSeconds: optionalInt('ACCESS_RECHECK_SECONDS', 15),

  /** Login challenge lifetime. */
  challengeTtlSeconds: optionalInt('CHALLENGE_TTL_SECONDS', 300),

  /** Upstream OEM/dongle adapter base URL. Credentials never leave this process. */
  upstreamBaseUrl: process.env.UPSTREAM_BASE_URL ?? '',
} as const

export type Config = typeof config
