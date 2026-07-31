import { createHash } from 'node:crypto'
import { privateKeyToAccount } from 'viem/accounts'
import { keccak256, toHex } from 'viem'
import { MockSource, type Frame, type TelemetrySource } from './source.js'

/**
 * Vehicle twin — the in-vehicle or dongle-side agent.
 *
 * Runs on the owner's hardware, holds the node key, and does two things:
 *
 *  1. Signs and pushes telemetry frames to a consent broker. The frame is signed so
 *     the broker can prove provenance to buyers without the broker being trusted to
 *     assert it; the broker still projects the frame down per scope before relaying.
 *
 *  2. Trains locally and emits a commitment plus nullifier for a federated round.
 *     The weight delta itself never goes on chain, and the proof asserts the training
 *     was done as specified over data from a registered vehicle without naming which.
 *
 * The node key is a data-publishing key. It is not, and must not become, a key to
 * the vehicle: this process reads from the diagnostic bus and writes to a broker. It
 * has no command path, and the seed below is derived from a vehicle secret that never
 * leaves the device.
 */

const BROKER_URL = process.env.BROKER_URL ?? 'http://127.0.0.1:8787'
const NODE_PRIVATE_KEY = process.env.NODE_PRIVATE_KEY as `0x${string}` | undefined
const TOKEN_ID = BigInt(process.env.TOKEN_ID ?? '1')
const PUSH_INTERVAL_MS = Number.parseInt(process.env.PUSH_INTERVAL_MS ?? '5000', 10)
/** Never transmitted. Basis of the per-round nullifier and of the vehicle commitment. */
const VEHICLE_SECRET = process.env.VEHICLE_SECRET ?? 'dev-only-vehicle-secret'

if (!NODE_PRIVATE_KEY) throw new Error('missing NODE_PRIVATE_KEY')
const account = privateKeyToAccount(NODE_PRIVATE_KEY)

// ------------------------------------------------------------------ publishing

async function pushFrame(frame: Frame): Promise<void> {
  const ts = Math.floor(Date.now() / 1000)
  const digest = createHash('sha256').update(JSON.stringify(frame)).digest('hex')
  const message = `catallaxy-ingest:${TOKEN_ID}:${ts}:${digest}`
  const signature = await account.signMessage({ message })

  const res = await fetch(new URL('/ingest', BROKER_URL), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      tokenId: TOKEN_ID.toString(),
      frame,
      ts,
      signature,
      signer: account.address,
    }),
  })
  if (!res.ok) {
    console.error('ingest rejected', res.status, await res.text())
  }
}

// ------------------------------------------------- federated learning (local)

export interface LocalUpdate {
  /** keccak of the serialised weight delta. Goes on chain. */
  updateCommitment: `0x${string}`
  /** H(vehicleSecret, roundId). Unlinkable to the token id; one per round. */
  nullifier: `0x${string}`
  /** The delta itself. Handed to the aggregator over an authenticated channel. */
  weightDelta: number[]
}

/**
 * Placeholder for the local training step. A real implementation runs the round's
 * published training spec against the on-device log — battery degradation curves,
 * DTC co-occurrence, whatever the round is for — and returns the delta.
 *
 * Kept deliberately explicit rather than faked: the contract's guarantee is that a
 * *proof* was verified, so the honest thing for this stub to do is name what has to
 * exist and produce a well-formed but unproven update.
 */
export function trainLocally(roundId: bigint, samples: Frame[]): LocalUpdate {
  const weightDelta = [
    samples.length,
    samples.reduce((acc, f) => acc + Number(f.socPct ?? 0), 0) / Math.max(samples.length, 1),
    samples.reduce((acc, f) => acc + Number(f.packTempC ?? 0), 0) / Math.max(samples.length, 1),
  ]

  return {
    updateCommitment: keccak256(toHex(JSON.stringify(weightDelta))),
    nullifier: keccak256(toHex(`${VEHICLE_SECRET}:${roundId}`)),
    weightDelta,
  }
}

/**
 * The proof is produced by the round's circuit, whose public signals must be, in
 * order: [nullifier, updateCommitment, roundId, modelCommitment, vehicleCommitment].
 * FederatedRounds supplies the last three from trusted storage, so a proof cannot be
 * replayed into another round or attributed to another vehicle.
 *
 * Left unimplemented on purpose: wiring a real circuit here is Stage 2 work, and a
 * stub that returned a plausible-looking blob would be a lie the tests would not
 * catch. The mock verifier in test/mocks stands in until the circuit lands.
 */
export async function proveUpdate(_update: LocalUpdate): Promise<`0x${string}`> {
  throw new Error(
    'proveUpdate not implemented: requires the Stage 2 circuit and its proving key. ' +
      'See README, "Stage 2 — what is not built yet".',
  )
}

// ----------------------------------------------------------------------- runner

async function main(): Promise<void> {
  const source: TelemetrySource = new MockSource()
  console.log(`twin online — vehicle ${TOKEN_ID}, node ${account.address}, broker ${BROKER_URL}`)

  const window: Frame[] = []
  for (;;) {
    const frame = await source.read(TOKEN_ID)
    if (frame) {
      await pushFrame(frame)
      window.push(frame)
      if (window.length > 720) window.shift()
    }
    await new Promise((resolve) => setTimeout(resolve, PUSH_INTERVAL_MS))
  }
}

if (process.argv[1]?.endsWith('twin.ts') || process.argv[1]?.endsWith('twin.js')) {
  main().catch((err) => {
    console.error(err)
    process.exit(1)
  })
}
