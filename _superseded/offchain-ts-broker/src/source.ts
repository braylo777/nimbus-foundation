import { assertReadOnlyUpstream } from './scopes.js'
import { config } from './config.js'

export type Frame = Record<string, unknown> & { ts: number }

/**
 * Where the broker gets telemetry. Two shapes matter in Stage 1:
 *
 *  - `HttpOemSource` — the owner has granted the broker an OAuth scope on the OEM
 *    cloud. The broker holds the refresh token and pulls. This is the path that
 *    reaches the existing installed base without touching the vehicle gateway, and
 *    it is why the doctrine matters: the broker's OEM credential is a *credential*,
 *    held in one place, never derived from anything on chain, and never exposed to
 *    the buyer. The buyer's on-chain grant buys a projection of the response, not
 *    the credential that produced it.
 *
 *  - `PushSource` — an OBD-II dongle or on-board unit signs frames with its node key
 *    and pushes them. No OEM relationship at all.
 *
 * Neither shape gives the buyer a route to the vehicle. There is no source
 * implementation that issues commands, and `assertReadOnlyUpstream` fails closed on
 * any upstream path that looks like actuation.
 */
export interface TelemetrySource {
  /** Latest frame for a vehicle, or null if nothing fresh. */
  read(tokenId: bigint): Promise<Frame | null>
}

/** Broker-pull adapter over an OEM telemetry API. */
export class HttpOemSource implements TelemetrySource {
  constructor(
    private readonly baseUrl: string,
    /** Resolves a vehicle to the OEM-side id and a bearer token held only here. */
    private readonly credentials: (tokenId: bigint) => Promise<{ vehicleRef: string; bearer: string } | null>,
  ) {}

  async read(tokenId: bigint): Promise<Frame | null> {
    const cred = await this.credentials(tokenId)
    if (!cred) return null

    const path = `/vehicles/${encodeURIComponent(cred.vehicleRef)}/telemetry`
    assertReadOnlyUpstream(path)

    const res = await fetch(new URL(path, this.baseUrl), {
      headers: { authorization: `Bearer ${cred.bearer}`, accept: 'application/json' },
    })
    if (!res.ok) return null

    const body = (await res.json()) as Record<string, unknown>
    return { ...body, ts: Math.floor(Date.now() / 1000) }
  }
}

/** Dongle-push buffer. The twin writes; the broker reads and projects. */
export class PushSource implements TelemetrySource {
  private readonly latest = new Map<string, Frame>()

  write(tokenId: bigint, frame: Frame): void {
    this.latest.set(tokenId.toString(), frame)
  }

  async read(tokenId: bigint): Promise<Frame | null> {
    return this.latest.get(tokenId.toString()) ?? null
  }
}

/** Deterministic stand-in for local development. */
export class MockSource implements TelemetrySource {
  async read(tokenId: bigint): Promise<Frame | null> {
    const t = Math.floor(Date.now() / 1000)
    const wobble = Number(tokenId % 7n)
    return {
      ts: t,
      speedKph: 40 + ((t + wobble) % 25),
      accelMs2: ((t % 5) - 2) / 2,
      headingDeg: (t * 3 + wobble * 17) % 360,
      lat: 30.2672 + wobble / 1000,
      lon: -97.7431 - wobble / 1000,
      geohash: '9v6kpsrmn',
      socPct: 80 - ((t / 600) % 40),
      packTempC: 27 + (t % 4),
      cycleCount: 412 + wobble,
      sohPct: 94.1,
      chargeRateKw: 0,
      odometerKm: 41_233 + wobble * 11,
      engineHours: 1_204,
      serviceDueKm: 1_767,
      dtcs: [],
      milOn: false,
      harshBrakeCount: wobble % 3,
      harshCornerCount: 0,
      windowSeconds: 60,
      // Present in the raw frame and never relayed under any scope: the projection
      // allowlist drops it. Left here on purpose as a live test of that property.
      vin: 'REDACT-ME',
      driverPhone: '+1-555-0100',
    }
  }
}

export function defaultSource(): TelemetrySource {
  if (config.upstreamBaseUrl) {
    return new HttpOemSource(config.upstreamBaseUrl, async () => null)
  }
  return new MockSource()
}
