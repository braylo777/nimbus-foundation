import { keccak256, toHex } from 'viem'

/**
 * Scope definitions, mirrored from contracts/lib/Scopes.sol.
 *
 * A scope is not just an identifier — it is a *projection*. The broker may relay
 * only the fields listed here, whatever the upstream OEM API happens to return.
 * This is the enforcement point for the Identifier-not-Credential Doctrine on the
 * data path: an insurer who bought BATTERY_HEALTH gets state of charge, and gets
 * no GPS fix even though the same upstream payload contained one.
 *
 * Projections are allowlists, never denylists. A new field appearing in an OEM
 * response is withheld by default until governance adds it to a scope — the failure
 * mode of a schema change is "buyer sees less than they paid for", not "buyer
 * silently receives data nobody consented to".
 */

export type ScopeName =
  | 'KINEMATICS'
  | 'LOCATION_COARSE'
  | 'LOCATION_PRECISE'
  | 'BATTERY_HEALTH'
  | 'DIAGNOSTICS'
  | 'USAGE'
  | 'DRIVER_EVENTS'

export interface ScopeSpec {
  /** keccak256 of the on-chain scope label. */
  id: `0x${string}`
  /** Fields the broker is permitted to forward for this scope. */
  fields: readonly string[]
  /** Geohash precision to truncate any positional field to; undefined = strip position. */
  geohashPrecision?: number
  /** Minimum seconds between frames, to bound re-identification via sample rate. */
  minIntervalSeconds: number
}

const scopeId = (label: string) => keccak256(toHex(label))

export const SCOPES: Record<ScopeName, ScopeSpec> = {
  KINEMATICS: {
    id: scopeId('TELEMETRY_KINEMATICS_V1'),
    fields: ['ts', 'speedKph', 'accelMs2', 'headingDeg'],
    minIntervalSeconds: 1,
  },
  LOCATION_COARSE: {
    id: scopeId('TELEMETRY_LOCATION_COARSE_V1'),
    fields: ['ts', 'geohash'],
    geohashPrecision: 5, // ~4.9 km cell
    minIntervalSeconds: 60,
  },
  LOCATION_PRECISE: {
    id: scopeId('TELEMETRY_LOCATION_PRECISE_V1'),
    fields: ['ts', 'lat', 'lon', 'geohash'],
    geohashPrecision: 9,
    minIntervalSeconds: 1,
  },
  BATTERY_HEALTH: {
    id: scopeId('TELEMETRY_BATTERY_HEALTH_V1'),
    fields: ['ts', 'socPct', 'packTempC', 'cycleCount', 'sohPct', 'chargeRateKw'],
    minIntervalSeconds: 30,
  },
  DIAGNOSTICS: {
    id: scopeId('TELEMETRY_DIAGNOSTICS_V1'),
    fields: ['ts', 'dtcs', 'milOn', 'freezeFrame'],
    minIntervalSeconds: 30,
  },
  USAGE: {
    id: scopeId('TELEMETRY_USAGE_V1'),
    fields: ['ts', 'odometerKm', 'engineHours', 'serviceDueKm'],
    minIntervalSeconds: 300,
  },
  DRIVER_EVENTS: {
    id: scopeId('TELEMETRY_DRIVER_EVENTS_V1'),
    fields: ['ts', 'harshBrakeCount', 'harshCornerCount', 'windowSeconds'],
    minIntervalSeconds: 60,
  },
}

export const scopeByName = (name: string): ScopeSpec | undefined =>
  SCOPES[name as ScopeName]

export const scopeById = (id: string): { name: ScopeName; spec: ScopeSpec } | undefined => {
  const lower = id.toLowerCase()
  for (const [name, spec] of Object.entries(SCOPES) as [ScopeName, ScopeSpec][]) {
    if (spec.id.toLowerCase() === lower) return { name, spec }
  }
  return undefined
}

/**
 * Upstream paths the broker refuses to call under any scope, ever.
 *
 * The registry proves consent rights over data. It is not a key to the car, and
 * nothing in the DAO's governance surface can make it one — so the data path must
 * refuse actuation independently, rather than trusting that no scope was ever
 * mapped to a command endpoint. A governance proposal cannot widen this list; it is
 * code in the broker, and an operator who edits it is running a different program.
 */
export const FORBIDDEN_UPSTREAM = [
  /\/commands?\b/i,
  /\/actuat/i,
  /\/remote[-_/]?(start|stop|unlock|lock|climate|horn|trunk|window)/i,
  /\/doors?\b/i,
  /\/engine\/(start|stop)/i,
  /\/charge\/(start|stop)/i,
  /\/valet/i,
  /\/sentry/i,
  /\/firmware|\/ota\b/i,
  /\/keys?\b/i,
  /\/subscriptions?\/(add|remove)/i,
] as const

export function assertReadOnlyUpstream(path: string): void {
  for (const pattern of FORBIDDEN_UPSTREAM) {
    if (pattern.test(path)) {
      throw new Error(
        `refusing upstream call to ${path}: matches actuation pattern ${pattern}. ` +
          'The broker relays telemetry only; it never commands a vehicle.',
      )
    }
  }
}

/** Project a raw telemetry frame down to what this scope permits. */
export function project(spec: ScopeSpec, frame: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const field of spec.fields) {
    if (field in frame && frame[field] !== undefined) out[field] = frame[field]
  }
  if (spec.geohashPrecision === undefined) {
    delete out.lat
    delete out.lon
    delete out.geohash
  } else {
    if (typeof out.geohash === 'string') {
      out.geohash = out.geohash.slice(0, spec.geohashPrecision)
    }
    if (!spec.fields.includes('lat')) {
      delete out.lat
      delete out.lon
    }
  }
  return out
}
