import { createPublicClient, http, parseAbi, type Address, type PublicClient } from 'viem'
import { config } from './config.js'

export const consentAbi = parseAbi([
  'function hasAccess(uint256 tokenId, bytes32 scope, address subscriber) view returns (bool)',
  'function accessExpiry(uint256 tokenId, bytes32 scope, address subscriber) view returns (uint64)',
  'function allowsFederatedModel(uint256 tokenId, bytes32 scope) view returns (bool)',
  'function policyOf(uint256 tokenId, bytes32 scope) view returns (uint128 pricePerDay, uint32 minDays, uint32 maxDays, bool allowFederatedModel, bool active)',
  'function quote(uint256 tokenId, bytes32 scope, uint32 daysRequested) view returns (uint256)',
  'event AccessRevoked(uint256 indexed tokenId, bytes32 indexed scope, address indexed subscriber, uint64 at)',
])

export const vinAbi = parseAbi([
  'function ownerOf(uint256 tokenId) view returns (address)',
  'function consentEpoch(uint256 tokenId) view returns (uint64)',
  'event ConsentEpochAdvanced(uint256 indexed tokenId, uint64 epoch, uint64 at, bool byTransfer)',
])

export const client: PublicClient = createPublicClient({
  transport: http(config.rpcUrl),
})

export interface AccessDecision {
  allowed: boolean
  /** Unix seconds at which access lapses absent revocation; 0 if no grant. */
  expiresAt: number
}

/**
 * The broker's only authorisation question, asked of the chain rather than of a
 * database it controls. There is no local override, no "trusted partner" list, and
 * no cache that can outlive a revocation by more than one recheck interval.
 */
export async function checkAccess(
  tokenId: bigint,
  scopeId: `0x${string}`,
  subscriber: Address,
): Promise<AccessDecision> {
  const [allowed, expiry] = await Promise.all([
    client.readContract({
      address: config.consentAddress,
      abi: consentAbi,
      functionName: 'hasAccess',
      args: [tokenId, scopeId, subscriber],
    }),
    client.readContract({
      address: config.consentAddress,
      abi: consentAbi,
      functionName: 'accessExpiry',
      args: [tokenId, scopeId, subscriber],
    }),
  ])
  return { allowed: allowed as boolean, expiresAt: Number(expiry as bigint) }
}

export async function currentEpoch(tokenId: bigint): Promise<bigint> {
  return (await client.readContract({
    address: config.vinAddress,
    abi: vinAbi,
    functionName: 'consentEpoch',
    args: [tokenId],
  })) as bigint
}

/**
 * Push-side revocation. Polling alone would leave a revoked buyer streaming until
 * the next recheck; watching the two invalidation events lets the broker cut open
 * connections in the same block the owner acted. Polling stays as the backstop for
 * dropped subscriptions — an owner's revocation must not depend on the broker's
 * websocket staying up.
 */
export function watchRevocations(onInvalidate: (tokenId: bigint) => void): () => void {
  const unwatchEpoch = client.watchContractEvent({
    address: config.vinAddress,
    abi: vinAbi,
    eventName: 'ConsentEpochAdvanced',
    onLogs: (logs) => {
      for (const log of logs) {
        const tokenId = (log as { args?: { tokenId?: bigint } }).args?.tokenId
        if (tokenId !== undefined) onInvalidate(tokenId)
      }
    },
  })

  const unwatchRevoke = client.watchContractEvent({
    address: config.consentAddress,
    abi: consentAbi,
    eventName: 'AccessRevoked',
    onLogs: (logs) => {
      for (const log of logs) {
        const tokenId = (log as { args?: { tokenId?: bigint } }).args?.tokenId
        if (tokenId !== undefined) onInvalidate(tokenId)
      }
    },
  })

  return () => {
    unwatchEpoch()
    unwatchRevoke()
  }
}
