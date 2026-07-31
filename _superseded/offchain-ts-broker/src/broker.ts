import { randomBytes, createHash } from 'node:crypto'
import Fastify from 'fastify'
import { getAddress, parseAbi, verifyMessage, type Address } from 'viem'
import { config } from './config.js'
import { checkAccess, client, consentAbi, currentEpoch, vinAbi, watchRevocations } from './chain.js'
import { issueCapability, verifyCapability } from './capability.js'
import { project, scopeById, scopeByName, type ScopeSpec } from './scopes.js'
import { defaultSource, PushSource, type Frame, type TelemetrySource } from './source.js'

const roundsAbi = parseAbi(['function nodeOf(uint256 tokenId) view returns (address)'])

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? 'info' } })

const pushSource = new PushSource()
const pullSource: TelemetrySource = defaultSource()

/** Vehicles whose consent state changed and whose open streams must be re-checked now. */
const invalidated = new Set<string>()
const stopWatching = watchRevocations((tokenId) => {
  invalidated.add(tokenId.toString())
  app.log.info({ tokenId: tokenId.toString() }, 'consent invalidated; cutting streams')
})

// ---------------------------------------------------------------------- helpers

interface Challenge {
  nonce: string
  issuedAt: number
}
const challenges = new Map<string, Challenge>()

function challengeStatement(address: Address, nonce: string): string {
  return [
    'Catallaxy consent broker: prove control of the subscribing address.',
    '',
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    `Chain: ${config.chainId}`,
    `Consent registry: ${config.consentAddress}`,
    '',
    'Signing this authorises nothing on chain and moves no funds. It only lets the',
    'broker relay data you have already purchased consent for.',
  ].join('\n')
}

function parseTokenId(raw: string): bigint {
  if (!/^\d{1,78}$/.test(raw)) throw new Error('tokenId must be a decimal integer')
  return BigInt(raw)
}

function resolveScope(raw: string): { id: `0x${string}`; spec: ScopeSpec } {
  const byName = scopeByName(raw)
  if (byName) return { id: byName.id, spec: byName }
  const byId = scopeById(raw)
  if (byId) return { id: byId.spec.id, spec: byId.spec }
  throw new Error(`unknown scope ${raw}`)
}

// ------------------------------------------------------------------- public reads

app.get<{ Params: { tokenId: string; scope: string } }>(
  '/policies/:tokenId/:scope',
  async (req, reply) => {
    const tokenId = parseTokenId(req.params.tokenId)
    const { id } = resolveScope(req.params.scope)

    const policy = await client.readContract({
      address: config.consentAddress,
      abi: consentAbi,
      functionName: 'policyOf',
      args: [tokenId, id],
    })
    const [pricePerDay, minDays, maxDays, allowFederatedModel, active] = policy as readonly [
      bigint,
      number,
      number,
      boolean,
      boolean,
    ]

    // Prices are public by design: posted terms are the price signal. Nothing about
    // the vehicle or the owner is disclosed here — only what they are asking.
    return reply.send({
      tokenId: tokenId.toString(),
      scope: id,
      pricePerDayWei: pricePerDay.toString(),
      minDays,
      maxDays,
      allowFederatedModel,
      active,
    })
  },
)

// ------------------------------------------------------------------------- auth

app.post<{ Body: { address: string } }>('/auth/challenge', async (req, reply) => {
  const address = getAddress(req.body.address)
  const nonce = randomBytes(16).toString('hex')
  challenges.set(address, { nonce, issuedAt: Math.floor(Date.now() / 1000) })
  return reply.send({ nonce, statement: challengeStatement(address, nonce) })
})

app.post<{
  Body: { address: string; tokenId: string; scope: string; nonce: string; signature: `0x${string}` }
}>('/auth/session', async (req, reply) => {
  const address = getAddress(req.body.address)
  const tokenId = parseTokenId(req.body.tokenId)
  const { id: scopeId } = resolveScope(req.body.scope)

  const challenge = challenges.get(address)
  if (!challenge || challenge.nonce !== req.body.nonce) {
    return reply.code(401).send({ error: 'no matching challenge' })
  }
  if (Math.floor(Date.now() / 1000) - challenge.issuedAt > config.challengeTtlSeconds) {
    challenges.delete(address)
    return reply.code(401).send({ error: 'challenge expired' })
  }

  const valid = await verifyMessage({
    address,
    message: challengeStatement(address, challenge.nonce),
    signature: req.body.signature,
  })
  if (!valid) return reply.code(401).send({ error: 'bad signature' })
  challenges.delete(address)

  // Signature proves who you are. The chain decides what you may read.
  const decision = await checkAccess(tokenId, scopeId, address)
  if (!decision.allowed) {
    return reply.code(403).send({ error: 'no live consent grant for this vehicle and scope' })
  }

  const epoch = await currentEpoch(tokenId)
  const { token, expiresAt } = await issueCapability(
    { subscriber: address, tokenId: tokenId.toString(), scopeId, epoch: epoch.toString() },
    decision.expiresAt,
  )
  return reply.send({ capability: token, expiresAt, grantExpiresAt: decision.expiresAt })
})

// ----------------------------------------------------------------------- stream

app.get<{ Params: { tokenId: string; scope: string } }>(
  '/streams/:tokenId/:scope',
  async (req, reply) => {
    const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, '')
    if (!bearer) return reply.code(401).send({ error: 'missing capability' })

    let cap
    try {
      cap = await verifyCapability(bearer)
    } catch {
      return reply.code(401).send({ error: 'invalid or expired capability' })
    }

    const tokenId = parseTokenId(req.params.tokenId)
    const { id: scopeId, spec } = resolveScope(req.params.scope)
    // A capability is bound to one vehicle and one scope. Presenting a battery-health
    // capability on the location endpoint is not a mistake to tolerate.
    if (cap.tokenId !== tokenId.toString() || cap.scopeId.toLowerCase() !== scopeId.toLowerCase()) {
      return reply.code(403).send({ error: 'capability does not cover this stream' })
    }

    const epoch = await currentEpoch(tokenId)
    if (epoch.toString() !== cap.epoch) {
      return reply.code(403).send({ error: 'consent epoch advanced; re-authorise' })
    }

    reply.raw.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      connection: 'keep-alive',
    })

    let open = true
    let lastSent = 0
    let lastCheck = Math.floor(Date.now() / 1000)

    const close = (reason: string) => {
      if (!open) return
      open = false
      reply.raw.write(`event: end\ndata: ${JSON.stringify({ reason })}\n\n`)
      reply.raw.end()
    }

    req.raw.on('close', () => {
      open = false
    })

    while (open) {
      const now = Math.floor(Date.now() / 1000)

      // Re-derive authorisation from chain state, on an interval and immediately on
      // any invalidation event. The capability token is never the final word.
      const forced = invalidated.delete(tokenId.toString())
      if (forced || now - lastCheck >= config.accessRecheckSeconds) {
        lastCheck = now
        const [decision, liveEpoch] = await Promise.all([
          checkAccess(tokenId, scopeId, cap.subscriber),
          currentEpoch(tokenId),
        ])
        if (!decision.allowed) {
          close('consent withdrawn or lapsed')
          break
        }
        if (liveEpoch.toString() !== cap.epoch) {
          close('consent epoch advanced')
          break
        }
      }

      if (now - lastSent >= spec.minIntervalSeconds) {
        const raw: Frame | null =
          (await pushSource.read(tokenId)) ?? (await pullSource.read(tokenId))
        if (raw) {
          const payload = project(spec, raw)
          reply.raw.write(`data: ${JSON.stringify(payload)}\n\n`)
          lastSent = now
        }
      }

      await new Promise((resolve) => setTimeout(resolve, 500))
    }

    if (open) close('server shutdown')
  },
)

// ----------------------------------------------------------------------- ingest

/**
 * Dongle / on-board-unit push. Authenticated by the vehicle's own key, not by any
 * shared broker secret: only the registered owner or the node they authorised on
 * chain can write frames for a vehicle.
 */
app.post<{
  Body: { tokenId: string; frame: Frame; ts: number; signature: `0x${string}`; signer: string }
}>('/ingest', async (req, reply) => {
  const tokenId = parseTokenId(req.body.tokenId)
  const signer = getAddress(req.body.signer)
  const skew = Math.abs(Math.floor(Date.now() / 1000) - req.body.ts)
  if (skew > 120) return reply.code(400).send({ error: 'stale or future-dated frame' })

  const digest = createHash('sha256').update(JSON.stringify(req.body.frame)).digest('hex')
  const message = `catallaxy-ingest:${tokenId}:${req.body.ts}:${digest}`
  const valid = await verifyMessage({ address: signer, message, signature: req.body.signature })
  if (!valid) return reply.code(401).send({ error: 'bad frame signature' })

  const owner = (await client.readContract({
    address: config.vinAddress,
    abi: vinAbi,
    functionName: 'ownerOf',
    args: [tokenId],
  })) as Address

  let authorised = owner.toLowerCase() === signer.toLowerCase()
  if (!authorised && config.roundsAddress) {
    const node = (await client.readContract({
      address: config.roundsAddress,
      abi: roundsAbi,
      functionName: 'nodeOf',
      args: [tokenId],
    })) as Address
    authorised = node.toLowerCase() === signer.toLowerCase()
  }
  if (!authorised) return reply.code(403).send({ error: 'signer is not owner or authorised node' })

  pushSource.write(tokenId, { ...req.body.frame, ts: req.body.ts })
  return reply.send({ ok: true })
})

// ----------------------------------------------------------------------- lifecycle

app.get('/healthz', async () => ({ ok: true, chainId: config.chainId }))

const shutdown = async () => {
  stopWatching()
  await app.close()
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

app
  .listen({ port: config.port, host: '0.0.0.0' })
  .then(() => app.log.info(`consent broker listening on :${config.port}`))
  .catch((err) => {
    app.log.error(err)
    process.exit(1)
  })
