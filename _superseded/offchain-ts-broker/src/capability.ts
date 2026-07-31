import { SignJWT, jwtVerify } from 'jose'
import type { Address } from 'viem'
import { config } from './config.js'

const secret = new TextEncoder().encode(config.jwtSecret)

export interface Capability {
  subscriber: Address
  tokenId: string
  scopeId: `0x${string}`
  /** Consent epoch the capability was minted under. */
  epoch: string
}

/**
 * Capability tokens carry no authority of their own. They are a cache of one
 * on-chain answer, stamped with the consent epoch it was true under, and they expire
 * within minutes. The stream handler re-derives authorisation from chain state
 * regardless; the token exists so that a subscriber does not have to re-sign a
 * challenge for every frame.
 *
 * Binding the epoch into the token means a revocation invalidates outstanding
 * tokens cryptographically rather than administratively: the epoch in the token no
 * longer matches the chain, so the token is dead even if the broker's revocation
 * bookkeeping fails or the process restarted with a cold cache.
 */
export async function issueCapability(
  cap: Capability,
  accessExpiresAt: number,
): Promise<{ token: string; expiresAt: number }> {
  const now = Math.floor(Date.now() / 1000)
  const ceiling = accessExpiresAt > 0 ? accessExpiresAt : now
  const expiresAt = Math.min(now + config.capabilityTtlSeconds, ceiling)
  if (expiresAt <= now) throw new Error('grant has already lapsed')

  const token = await new SignJWT({
    sub: cap.subscriber,
    tokenId: cap.tokenId,
    scope: cap.scopeId,
    epoch: cap.epoch,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now)
    .setExpirationTime(expiresAt)
    .setAudience('catallaxy-broker')
    .sign(secret)

  return { token, expiresAt }
}

export async function verifyCapability(token: string): Promise<Capability> {
  const { payload } = await jwtVerify(token, secret, { audience: 'catallaxy-broker' })
  const { sub, tokenId, scope, epoch } = payload as Record<string, unknown>
  if (
    typeof sub !== 'string' ||
    typeof tokenId !== 'string' ||
    typeof scope !== 'string' ||
    typeof epoch !== 'string'
  ) {
    throw new Error('malformed capability')
  }
  return {
    subscriber: sub as Address,
    tokenId,
    scopeId: scope as `0x${string}`,
    epoch,
  }
}
