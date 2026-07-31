/**
 * M0 — the VIN-yield study.
 *
 * Nimbus Foundation NF-WP-1 §11, §13 limitation 1, §14 M0, §15 recommendation 1.
 *
 * The load-bearing data assumption of the entire architecture is that a VIN yields the
 * fields Layers 3 and 4 are designed around. That assumption is UNTESTED (§13
 * limitation 1). This Worker tests it, empirically, against the only public source of
 * VIN-derived vehicle data — NHTSA's Product Information Catalog and Vehicle Listing
 * (vPIC), populated from manufacturer submissions under 49 C.F.R. Part 565.
 *
 * M0 gates everything downstream. It is deliberately the first build because it is the
 * cheapest action that can invalidate the most expensive work: if `trim` or `gvwr_class`
 * materialises for 40% of VINs, then a repair-parts grant scoped on trim is a promise
 * the protocol cannot keep, and that has to be known before the broker exists rather
 * than after a counterparty has integrated against it.
 *
 * What this Worker is NOT, and cannot become:
 *
 *  - It is not a VIN resolver in the §10.1 refusal-1 sense. vPIC returns build and
 *    specification data and nothing else: no owner, no address, no credential, no
 *    location. There is no code path here from a VIN to an authorisation, and the
 *    persistence layer is allowlist-projected (see `projectVpicResult`) so that a
 *    future change to NHTSA's response schema cannot quietly introduce one.
 *  - It is not a ledger. Everything lands in D1 — mutable, deletable, and purgeable by
 *    sample (§9.5, the 45-day Delete Act cadence). Nothing here is committed anywhere
 *    immutable, and the study store is expected to be erased once the report is written.
 *
 * Measurement doctrine. vPIC does not return nulls; it returns empty strings and the
 * literal string "Not Applicable". Collapsing those into one bucket would destroy the
 * only distinction the study exists to make, so values are classified into three states
 * (`VALUE_STATES`) and every rate is reported against a denominator that is stated
 * alongside it. A coverage number without its denominator is not a measurement.
 */

import { validateVin } from '../../broker/src/vin.js'
import { FIELDS, FIELD_CLASSES, NON_TRANSACTABLE, classOfField } from '../../broker/src/fields.js'

/* ------------------------------------------------------------------------- *
 * Constants
 * ------------------------------------------------------------------------- */

export const STUDY_VERSION = 'nf-m0-vin-yield/1'

/** vPIC is public, keyless, and unregistered (NF-WP-1 §11). No credential belongs here. */
const VPIC_BASE_DEFAULT = 'https://vpic.nhtsa.dot.gov/api/vehicles'

/** Documented vPIC ceiling for DecodeVinValuesBatch. Exceeding it truncates silently. */
export const VPIC_BATCH_LIMIT = 50

/**
 * NF-WP-1 §15 recommendation 1. A field the architecture assumes is VIN-derivable and
 * which materialises for fewer than 80% of decoded VINs is not a field a grant can be
 * scoped on — it is a field that needs a second source.
 */
export const COVERAGE_THRESHOLD = 0.8

/**
 * The re-scoping finding, as a fixed string. It is a constant rather than prose
 * assembled at render time so that it cannot be softened, hedged, or paraphrased into
 * something a reader could mistake for a pass.
 */
export const RESCOPE_STATEMENT =
  'Layers 3 and 4 need re-scoping around Layer-2 authenticated access before the broker is built.'

/**
 * The §3.3 honest ceiling, restated as the empirical claim this study either confirms
 * or refutes. Emitted verbatim into every report.
 */
export const CEILING_STATEMENT =
  'vPIC yields build and specification data — make, model, model year, body class, plant, ' +
  'engine configuration, fuel type. It does NOT yield location, kinematics, live diagnostic ' +
  'trouble codes, battery state, or service history. Every one of those requires Layer-2 ' +
  'authenticated access, not VIN decode.'

/**
 * A verdict drawn from a handful of VINs is worse than no verdict, because it will be
 * cited downstream as clearance. Below this decoded count the report refuses to rule.
 */
export const MIN_SAMPLE_FOR_VERDICT = 100

/** Per-request ceilings. A larger study is several runs sharing one `sample_id`. */
export const MAX_VINS_PER_REQUEST = 500
const MAX_SUBREQUEST_BUDGET = 40
const RUN_BUDGET_MS = 20_000

/** vPIC responses are deterministic for a given VIN, so the cache TTL is generous. */
const CACHE_TTL_S_DEFAULT = 45 * 24 * 60 * 60

const VPIC_TIMEOUT_MS_DEFAULT = 8_000
const VPIC_MAX_ATTEMPTS_DEFAULT = 3
const BACKOFF_BASE_MS = 400
const BACKOFF_CAP_MS = 6_000

/** json_each insert chunking. Keeps each bound JSON argument comfortably small. */
const INSERT_CHUNK_ROWS = 400

const MAX_REJECT_INPUT_CHARS = 64

/* ------------------------------------------------------------------------- *
 * Value states — the whole measurement lives here
 * ------------------------------------------------------------------------- */

export const VALUE_STATES = Object.freeze({
  /** A usable value was returned. Counts toward coverage. */
  PRESENT: 'present',
  /** Empty string or null: nothing was submitted under Part 565. A gap. */
  ABSENT_EMPTY: 'absent_empty',
  /** "Not Applicable" and friends: the manufacturer asserts the field does not apply. */
  ABSENT_NOT_APPLICABLE: 'absent_not_applicable',
  /** The probe key is not in the response object at all — the probe name may be wrong. */
  KEY_ABSENT: 'key_absent',
})

/**
 * Manufacturer-asserted inapplicability. A BEV with `DisplacementL = "Not Applicable"`
 * is not a data gap; it is a correct answer. Kept separate from ABSENT_EMPTY because
 * conflating them would let a report blame NHTSA for a fact about the vehicle — and
 * because the remedy differs: a gap may be fillable from a second source, an
 * inapplicability never is.
 */
const NOT_APPLICABLE_LITERALS = new Set([
  'not applicable',
  'notapplicable',
  'na',
  'n/a',
  'none',
])

const EMPTY_LITERALS = new Set([
  '',
  'null',
  'not available',
  'unknown',
  'undetermined',
  'not reported',
  'tbd',
  '-',
  '--',
])

/**
 * Classify one raw vPIC value.
 *
 * Deliberately does NOT treat '0' or '0.0' as missing. vPIC uses "0" as a real value —
 * `ErrorCode` "0" means a clean decode — and a displacement of "0" on a combustion
 * vehicle is a data *defect*, not an *absence*. Reclassifying a present-but-wrong value
 * as absent would report a data-quality problem as a coverage problem, which is the one
 * substitution that would make the study's conclusion wrong in the flattering
 * direction: it inflates the null rate, which makes the architecture look like it needs
 * a second source when what it actually needs is validation.
 *
 * @param {unknown} raw
 * @returns {{ state: string, value: string|null }}
 */
export function normalizeVpicValue(raw) {
  if (raw === undefined) return { state: VALUE_STATES.KEY_ABSENT, value: null }
  if (raw === null) return { state: VALUE_STATES.ABSENT_EMPTY, value: null }

  const asString = typeof raw === 'string' ? raw : String(raw)
  const trimmed = asString.trim()
  const probe = trimmed.replace(/\s+/g, ' ').toLowerCase()

  if (NOT_APPLICABLE_LITERALS.has(probe)) {
    return { state: VALUE_STATES.ABSENT_NOT_APPLICABLE, value: null }
  }
  if (EMPTY_LITERALS.has(probe)) {
    return { state: VALUE_STATES.ABSENT_EMPTY, value: null }
  }
  return { state: VALUE_STATES.PRESENT, value: trimmed }
}

/** True when the state counts as VIN-derived coverage. One place, so it cannot drift. */
export function isCovered(state) {
  return state === VALUE_STATES.PRESENT
}

/* ------------------------------------------------------------------------- *
 * The map from the NF-2 vocabulary to vPIC response keys
 * ------------------------------------------------------------------------- */

/**
 * Every field in `FIELD_CLASSES` gets an entry, and the entry says how M0 measures it.
 *
 *   keys    — vPIC response keys, in preference order. Empty means no vPIC key exists.
 *   probes  — keys a naive reading might mistake for the field. Measured, then reported
 *             as near-misses rather than coverage. This is the difference between a
 *             *specification* value and a *state* value, and it is where an honest
 *             study is most likely to be quietly dishonest: `BatteryKWh` is nameplate
 *             capacity from a Part 565 submission, not the measured usable capacity of
 *             a four-year-old pack, and counting it as `usable_capacity_kwh` coverage
 *             would manufacture a Layer-2 independence that does not exist.
 *   whyNot  — required for every field with no keys. This is the §3.3 honest ceiling
 *             made machine-readable: the reason, per field, that a VIN cannot supply it.
 *
 * Fields whose `FIELD_CLASSES` layer is 'layer2' or 'operator' are EXPECTED to have no
 * keys — but the study confirms that rather than assuming it. Confirmation is what the
 * probes are for: an empty `keys` list is a claim about vPIC's schema, and a probe that
 * hits is evidence the claim was wrong.
 */
export const VPIC_FIELD_MAP = Object.freeze({
  // ---- build_specification (expected layer 'vpic') --------------------------
  make: { keys: ['Make'] },
  model: { keys: ['Model'] },
  model_year: { keys: ['ModelYear'] },
  body_class: { keys: ['BodyClass'] },
  vehicle_type: { keys: ['VehicleType'] },
  drive_type: { keys: ['DriveType'] },
  engine_configuration: { keys: ['EngineConfiguration'] },
  engine_displacement_l: { keys: ['DisplacementL'] },
  fuel_type_primary: { keys: ['FuelTypePrimary'] },
  // vPIC expresses GVWR as a banded class string ("Class 2E: 6,001 - 7,000 lb"), with
  // GVWR_From/GVWR_To as the numeric band. All three are accepted: the field id asks
  // for a class, and refusing a value because it arrived in the range keys rather than
  // the class key would understate coverage for a reason that is about NHTSA's
  // serialisation rather than about the vehicle.
  gvwr_class: { keys: ['GVWR', 'GVWR_From', 'GVWR_To'] },
  plant_country: { keys: ['PlantCountry'] },
  plant_company_name: { keys: ['PlantCompanyName'] },
  // Series and Trim are the two build fields most likely to breach the §15 threshold,
  // and they are the two that matter most commercially: parts applicability for an
  // independent repairer turns on trim, not on body class. vPIC carries Series/Series2
  // and Trim/Trim2 because manufacturers submit the same concept under either.
  series: { keys: ['Series', 'Series2'] },
  trim: { keys: ['Trim', 'Trim2'] },

  // ---- diagnostics (expected layer 'layer2') -------------------------------
  dtc_codes: {
    keys: [],
    whyNot:
      'Diagnostic trouble codes are runtime state read over OBD-II or an OEM telematics ' +
      'API. Part 565 submissions describe the vehicle as built; they carry no runtime state.',
  },
  dtc_first_seen_at: {
    keys: [],
    whyNot: 'A timestamp of a runtime event. vPIC holds no per-vehicle event history.',
  },
  mil_status: {
    keys: [],
    whyNot: 'Malfunction indicator lamp state is runtime state, not a build attribute.',
  },
  freeze_frame: {
    keys: [],
    whyNot: 'A freeze frame is an ECU snapshot captured at fault time. Layer-2 only.',
  },
  readiness_monitors: {
    keys: [],
    whyNot: 'Monitor readiness is emissions-cycle state, read from the ECU.',
  },
  obd_protocol: {
    keys: [],
    whyNot:
      'Plausibly a build attribute, and genuinely absent from DecodeVinValues. Determining ' +
      'the OBD protocol requires interrogating the vehicle, which is a Layer-2 diagnostic ' +
      'interaction bounded by CFAA as narrowed by Van Buren and by DMCA §1201.',
  },

  // ---- battery_health (expected layer 'layer2') ----------------------------
  state_of_charge_pct: {
    keys: [],
    whyNot: 'Instantaneous pack charge. Runtime state; no VIN-derived analogue exists.',
  },
  state_of_health_pct: {
    keys: [],
    whyNot:
      'Degradation measured against nameplate. vPIC can supply the nameplate but never ' +
      'the measurement, so state of health is structurally Layer-2 even where vPIC is complete.',
  },
  pack_temperature_c: { keys: [], whyNot: 'Sensor reading. Runtime state.' },
  charge_cycle_count: {
    keys: [],
    whyNot: 'A cumulative counter held by the battery management system.',
  },
  charge_rate_kw: {
    keys: [],
    probes: ['ChargerPowerKW', 'ChargerLevel'],
    whyNot:
      'vPIC may carry the rated onboard charger power. Rated power is a build attribute; ' +
      'the delivered rate during a session is runtime state. The probe measures the former ' +
      'so the report can say plainly that it is not the latter.',
  },
  usable_capacity_kwh: {
    keys: [],
    probes: ['BatteryKWh', 'BatteryKWh_From', 'BatteryKWh_To'],
    whyNot:
      'BatteryKWh is nameplate capacity as submitted under Part 565. Usable capacity after ' +
      'degradation is a measurement only the pack can report. Treating the nameplate as the ' +
      'measurement would invent Layer-2 independence.',
  },

  // ---- motion_aggregate (expected layer 'layer2') --------------------------
  speed_mean_kph: {
    keys: [],
    whyNot: 'An observed aggregate over a driving window. No build attribute corresponds.',
  },
  speed_p95_kph: {
    keys: [],
    probes: ['TopSpeedMPH'],
    whyNot:
      'TopSpeedMPH, where present, is a rated maximum — a property of the vehicle, not of ' +
      'how it was driven. A 95th-percentile observed speed cannot be derived from it.',
  },
  harsh_brake_count: { keys: [], whyNot: 'An event count derived from consented telemetry.' },
  harsh_accel_count: { keys: [], whyNot: 'An event count derived from consented telemetry.' },
  harsh_corner_count: { keys: [], whyNot: 'An event count derived from consented telemetry.' },
  aggregation_window_s: {
    keys: [],
    whyNot:
      'Metadata describing a Layer-4 aggregation that has not happened yet at VIN-decode time.',
  },

  // ---- usage (expected layer 'layer2') -------------------------------------
  odometer_km: {
    keys: [],
    whyNot:
      'The single most-requested field in the repair and fleet use cases, and flatly ' +
      'unavailable from a VIN. Odometer comes from the cluster over Layer 2, from a title ' +
      'record, or from an operator disclosure. Any design that assumed VIN-derived odometer ' +
      'is wrong, and this is the finding most likely to force re-scoping.',
  },
  engine_hours: { keys: [], whyNot: 'A cumulative ECU counter.' },
  service_due_km: {
    keys: [],
    whyNot:
      'Derived from an OEM maintenance schedule applied to a live odometer. Needs both a ' +
      'Layer-2 reading and an OEM schedule.',
  },
  annual_mileage_estimate_km: {
    keys: [],
    whyNot: 'An estimate over observed usage. Requires a usage history, not a VIN.',
  },

  // ---- service_history (expected layer 'operator') -------------------------
  service_events: { keys: [], whyNot: 'Held by whoever performed the service.' },
  repair_order_summaries: { keys: [], whyNot: 'Held by the repairing operator.' },
  recall_completion_status: {
    keys: [],
    whyNot:
      'A trap worth naming: NHTSA does publish recall data, so "the NHTSA API" sounds like ' +
      'it covers this. It does not. DecodeVinValues returns no recall field at all; the ' +
      'Recalls endpoints are keyed by make/model/year and describe whether a CAMPAIGN exists, ' +
      'never whether THIS vehicle has been remedied. Per-vehicle completion is OEM-held — ' +
      'Layer 2 or an operator disclosure.',
  },
  last_service_at: { keys: [], whyNot: 'Held by the servicing operator.' },
})

/**
 * Fail closed on vocabulary drift. Adding a field to fields.js without deciding its M0
 * status must be a loud error at module load, not a field silently absent from the
 * study — a report that omits a field reads exactly like a report where the field
 * passed.
 */
{
  const unmapped = FIELDS.filter((f) => !Object.hasOwn(VPIC_FIELD_MAP, f))
  if (unmapped.length > 0) {
    throw new Error(
      `M0: fields in the NF-2 vocabulary with no measurement decision: ${unmapped.join(', ')}`,
    )
  }
  const stray = Object.keys(VPIC_FIELD_MAP).filter((f) => !FIELDS.includes(f))
  if (stray.length > 0) {
    throw new Error(`M0: measurement entries for fields outside the vocabulary: ${stray.join(', ')}`)
  }
  const missingWhyNot = FIELDS.filter(
    (f) => VPIC_FIELD_MAP[f].keys.length === 0 && !VPIC_FIELD_MAP[f].whyNot,
  )
  if (missingWhyNot.length > 0) {
    throw new Error(`M0: no-key fields lacking a whyNot rationale: ${missingWhyNot.join(', ')}`)
  }
}

/** Field ids M0 measures directly against a vPIC key. */
export const MEASURED_FIELDS = Object.freeze(
  FIELDS.filter((f) => VPIC_FIELD_MAP[f].keys.length > 0),
)

/** Field ids with no vPIC key — measured indirectly, via probes and the whyNot rationale. */
export const UNMEASURABLE_FIELDS = Object.freeze(
  FIELDS.filter((f) => VPIC_FIELD_MAP[f].keys.length === 0),
)

/** The declared layer for a field, straight from fields.js. Never restated here. */
export function expectedLayerOf(fieldId) {
  const cls = classOfField(fieldId)
  return cls ? FIELD_CLASSES[cls].layer : null
}

/** Probe entries as a flat list of [fieldId, probeKey] pairs. */
export const PROBE_PAIRS = Object.freeze(
  FIELDS.flatMap((f) => (VPIC_FIELD_MAP[f].probes ?? []).map((k) => Object.freeze([f, k]))),
)

/* ------------------------------------------------------------------------- *
 * Projection — an allowlist, mirroring the broker's Layer-3 doctrine
 * ------------------------------------------------------------------------- */

/**
 * The only vPIC keys that may be persisted. Everything vPIC returns outside this set is
 * discarded before it reaches D1.
 *
 * Allowlist rather than denylist for the same reason the broker projects rather than
 * filters: NHTSA adds keys, and the failure mode of an allowlist is "the study measures
 * less than it could", while the failure mode of a denylist is "the study silently
 * persisted a field nobody decided to persist". The first is a bug you notice.
 */
const ALLOWED_VPIC_KEYS = Object.freeze(
  new Set([
    'VIN',
    'ErrorCode',
    'ErrorText',
    ...MEASURED_FIELDS.flatMap((f) => VPIC_FIELD_MAP[f].keys),
    ...PROBE_PAIRS.map(([, k]) => k),
  ]),
)

/**
 * Tripwire patterns. These do not gate persistence — the allowlist already does that —
 * they detect the event worth knowing about: NHTSA's VIN-decode response acquiring a key
 * that looks like personal information or position. If that ever fires, refusal 1 and
 * refusal 2 both need a fresh look at whether vPIC may still be consumed at all.
 *
 * Seeded from `NON_TRANSACTABLE` so the two lists cannot diverge, plus token patterns
 * for shapes the vocabulary does not enumerate. Matching is on token boundaries, not
 * substrings: `PlantCompanyName` normalises to `plant_company_name`, and a naive
 * substring test for "name" would flag a plant as a person forever.
 */
const TRIPWIRE_TOKENS = Object.freeze(
  new Set([
    ...NON_TRANSACTABLE,
    'owner',
    'driver',
    'lessee',
    'registrant',
    'latitude',
    'longitude',
    'geohash',
    'gps',
    'coordinates',
    'biometric',
    'fingerprint',
    'voiceprint',
    'address',
    'phone',
    'email',
    'ssn',
  ]),
)

/** CamelCase vPIC key to snake_case, so tripwire tokens compare against fields.js ids. */
function snakeCase(key) {
  return String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase()
}

function tripwireHit(key) {
  const snake = snakeCase(key)
  if (TRIPWIRE_TOKENS.has(snake)) return true
  return snake.split('_').some((t) => TRIPWIRE_TOKENS.has(t))
}

/**
 * Reduce one raw vPIC result object to the allowlisted projection that may be persisted.
 *
 * `VehicleDescriptor` is deliberately not allowlisted even though it is harmless-looking:
 * it is the VIN with the vehicle-identifier section masked, i.e. a partial VIN, and the
 * study has no use for a second copy of an identifier it already stores.
 *
 * @param {Record<string, unknown>} result
 * @returns {{ vin: string|null, errorCode: string|null, errorText: string|null,
 *             values: Record<string, unknown>, tripwires: string[], droppedKeys: number }}
 */
export function projectVpicResult(result) {
  const values = {}
  const tripwires = []
  let droppedKeys = 0

  for (const [key, raw] of Object.entries(result ?? {})) {
    if (tripwireHit(key)) tripwires.push(key)
    if (ALLOWED_VPIC_KEYS.has(key)) {
      values[key] = raw
    } else {
      droppedKeys += 1
    }
  }

  const vinRaw = normalizeVpicValue(values.VIN)
  return {
    vin: vinRaw.state === VALUE_STATES.PRESENT ? vinRaw.value.toUpperCase() : null,
    errorCode: normalizeVpicValue(values.ErrorCode).value,
    errorText: normalizeVpicValue(values.ErrorText).value,
    values,
    tripwires,
    droppedKeys,
  }
}

/**
 * Classify every measured field and probe for one projected result.
 *
 * A field with several candidate keys resolves to the first key that is PRESENT. If none
 * is present, the reported state is that of the FIRST key — the primary — because the
 * primary is what the architecture nominally reads, and reporting "Not Applicable" from
 * a fallback key would attribute a manufacturer assertion to a key the manufacturer
 * never populated.
 *
 * @param {{ values: Record<string, unknown> }} projected
 * @returns {{ fields: Array<{fieldId: string, sourceKey: string|null, state: string}>,
 *             probes: Array<{fieldId: string, probeKey: string, state: string}> }}
 */
export function classifyResult(projected) {
  const values = projected.values ?? {}
  const fields = []

  for (const fieldId of MEASURED_FIELDS) {
    const keys = VPIC_FIELD_MAP[fieldId].keys
    let chosen = null
    for (const key of keys) {
      const { state } = normalizeVpicValue(values[key])
      if (state === VALUE_STATES.PRESENT) {
        chosen = { fieldId, sourceKey: key, state }
        break
      }
    }
    if (!chosen) {
      const primary = keys[0]
      chosen = { fieldId, sourceKey: primary, state: normalizeVpicValue(values[primary]).state }
    }
    fields.push(chosen)
  }

  const probes = PROBE_PAIRS.map(([fieldId, probeKey]) => ({
    fieldId,
    probeKey,
    state: normalizeVpicValue(values[probeKey]).state,
  }))

  return { fields, probes }
}

/* ------------------------------------------------------------------------- *
 * vPIC client — timeouts, bounded retry, and honest failure
 * ------------------------------------------------------------------------- */

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** Full-jitter exponential backoff. Jitter, not fixed delay, so parallel runs desynchronise. */
function backoffDelayMs(attempt) {
  const ceiling = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt)
  return Math.floor(Math.random() * ceiling)
}

/** `Retry-After` in seconds. HTTP-date form is ignored rather than guessed at. */
function retryAfterMs(response) {
  const header = response.headers.get('retry-after')
  if (!header) return null
  const seconds = Number(header.trim())
  if (!Number.isFinite(seconds) || seconds < 0) return null
  return Math.min(seconds * 1000, BACKOFF_CAP_MS)
}

/** 429 and 408 are transient by definition; 5xx is assumed transient; other 4xx is not. */
function isRetryableStatus(status) {
  return status === 429 || status === 408 || (status >= 500 && status <= 599)
}

/**
 * One vPIC call with a timeout and bounded retry.
 *
 * Returns a result object rather than throwing, because a failed batch must degrade the
 * run into partial mode with an accurate count — not abort it, and not vanish. The
 * distinction between "vPIC said this vehicle has no trim" and "we never heard back
 * about this vehicle" is the difference between a finding and a fabrication.
 *
 * @returns {Promise<{ ok: boolean, results: object[]|null, status: number|null,
 *                     error: string|null, attempts: number }>}
 */
async function vpicFetch(url, init, cfg) {
  let lastError = null
  let lastStatus = null

  for (let attempt = 0; attempt < cfg.maxAttempts; attempt += 1) {
    if (attempt > 0) await sleep(backoffDelayMs(attempt - 1))
    if (Date.now() > cfg.deadline) {
      return { ok: false, results: null, status: lastStatus, error: 'run deadline exceeded', attempts: attempt }
    }

    let response
    try {
      response = await fetch(url, {
        ...init,
        // AbortSignal.timeout is a web standard and is what bounds a slow vPIC. Without
        // it a single hung connection consumes the whole run budget.
        signal: AbortSignal.timeout(cfg.timeoutMs),
      })
    } catch (err) {
      lastError = err?.name === 'TimeoutError' ? `timeout after ${cfg.timeoutMs}ms` : String(err)
      continue
    }

    lastStatus = response.status

    if (!response.ok) {
      lastError = `vPIC HTTP ${response.status}`
      if (!isRetryableStatus(response.status)) {
        return { ok: false, results: null, status: response.status, error: lastError, attempts: attempt + 1 }
      }
      const wait = retryAfterMs(response)
      if (wait !== null) await sleep(wait)
      continue
    }

    let body
    try {
      body = await response.json()
    } catch (err) {
      // A 200 with unparseable content is a gateway or maintenance page, which is
      // transient in practice. Retry rather than record 50 undecoded VINs.
      lastError = `vPIC returned non-JSON: ${String(err)}`
      continue
    }

    if (!body || !Array.isArray(body.Results)) {
      lastError = 'vPIC response has no Results array'
      continue
    }

    return { ok: true, results: body.Results, status: response.status, error: null, attempts: attempt + 1 }
  }

  return { ok: false, results: null, status: lastStatus, error: lastError ?? 'unknown', attempts: cfg.maxAttempts }
}

/**
 * Decode up to VPIC_BATCH_LIMIT VINs in one call.
 *
 * URLSearchParams does the encoding. validateVin has already restricted the input to
 * [A-HJ-NPR-Z0-9], so nothing here can contain a delimiter — but the encoding stays,
 * because the charset guarantee lives in another module and a future relaxation of it
 * must not silently become an injection into a semicolon-delimited payload.
 */
async function decodeBatch(vins, cfg) {
  if (vins.length > VPIC_BATCH_LIMIT) {
    throw new Error(`batch of ${vins.length} exceeds the vPIC limit of ${VPIC_BATCH_LIMIT}`)
  }
  const body = new URLSearchParams({ format: 'json', data: vins.join(';') })
  return vpicFetch(`${cfg.base}/DecodeVinValuesBatch/`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      // Identifying the caller lets NHTSA rate-limit us deliberately rather than blindly.
      'user-agent': `${STUDY_VERSION} (Nimbus Foundation M0 VIN-yield study)`,
    },
    body: body.toString(),
  }, cfg)
}

/** Single-VIN decode. Used for cache top-ups of one or two VINs. */
async function decodeSingle(vin, cfg) {
  const url = `${cfg.base}/DecodeVinValues/${encodeURIComponent(vin)}?format=json`
  return vpicFetch(url, {
    method: 'GET',
    headers: { accept: 'application/json', 'user-agent': `${STUDY_VERSION}` },
    // vPIC is deterministic per VIN, so the edge cache is safe and reduces load on a
    // public service we do not pay for.
    cf: { cacheTtlByStatus: { '200-299': cfg.cacheTtlS, '400-599': 0 } },
  }, cfg)
}

/**
 * Match results to the VINs we asked about, by VIN and never by index.
 *
 * vPIC does not promise ordering, and a positional match would silently attribute one
 * vehicle's build data to another — a defect that produces plausible-looking coverage
 * numbers, which is the worst kind.
 *
 * A VIN absent from Results is `missing`: it must NOT be recorded as forty absent
 * fields. Doing so would let an outage masquerade as a coverage finding and drive a
 * re-scoping decision off a network error.
 */
export function matchResultsToVins(results, vins) {
  const byVin = new Map()
  const anomalies = []

  for (const raw of results) {
    const projected = projectVpicResult(raw)
    if (!projected.vin) {
      anomalies.push('result row with no VIN key')
      continue
    }
    if (byVin.has(projected.vin)) {
      anomalies.push(`duplicate result for ${projected.vin}`)
      continue
    }
    byVin.set(projected.vin, projected)
  }

  const matched = []
  const missing = []
  for (const vin of vins) {
    const hit = byVin.get(vin)
    if (hit) matched.push(hit)
    else missing.push(vin)
  }

  const requested = new Set(vins)
  for (const vin of byVin.keys()) {
    if (!requested.has(vin)) anomalies.push(`unrequested VIN in results: ${vin}`)
  }

  return { matched, missing, anomalies }
}

/** Split an array into fixed-size chunks. */
export function chunk(items, size) {
  const out = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

/* ------------------------------------------------------------------------- *
 * D1 schema
 * ------------------------------------------------------------------------- */

/**
 * The study store. D1, therefore mutable and deletable — which is the whole reason the
 * architecture puts identifiers here and hashes on a ledger (§9.5). A VIN in this store
 * is correct; a VIN in a commitment would not be.
 *
 * Two deliberate omissions:
 *
 *  - `m0_observation` records STATE ONLY, never the value. Coverage does not need the
 *    value, and a table of VIN-to-build-data would be a vehicle fingerprint the study
 *    has no reason to accumulate. The projected values live only in the cache table,
 *    which is what the purge path targets.
 *  - No field class or layer column. Those belong to fields.js, and duplicating them
 *    here would mean a vocabulary change needs a migration and could silently disagree
 *    with the source of truth. The table records measurements; fields.js records meaning.
 *
 * DDL lives in the Worker rather than a migrations directory because M0's assigned file
 * list is three files. `GET /schema.sql` emits it for `wrangler d1 execute --file=-`.
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS m0_run (
  run_id                   TEXT PRIMARY KEY,
  sample_id                TEXT NOT NULL,
  provenance               TEXT NOT NULL,
  study_version            TEXT NOT NULL,
  strict_check_digit       INTEGER NOT NULL,
  started_at               INTEGER NOT NULL,
  finished_at              INTEGER,
  vins_submitted           INTEGER NOT NULL DEFAULT 0,
  vins_duplicate           INTEGER NOT NULL DEFAULT 0,
  vins_syntax_invalid      INTEGER NOT NULL DEFAULT 0,
  vins_check_digit_invalid INTEGER NOT NULL DEFAULT 0,
  vins_eligible            INTEGER NOT NULL DEFAULT 0,
  vins_attempted           INTEGER NOT NULL DEFAULT 0,
  vins_decoded             INTEGER NOT NULL DEFAULT 0,
  vins_from_cache          INTEGER NOT NULL DEFAULT 0,
  vins_unreached           INTEGER NOT NULL DEFAULT 0,
  null_decodes             INTEGER NOT NULL DEFAULT 0,
  batches_total            INTEGER NOT NULL DEFAULT 0,
  batches_failed           INTEGER NOT NULL DEFAULT 0,
  truncated                INTEGER NOT NULL DEFAULT 0,
  truncation_reason        TEXT,
  error_code_histogram     TEXT,
  anomalies                TEXT,
  tripwires                TEXT
);

CREATE TABLE IF NOT EXISTS m0_observation (
  run_id     TEXT NOT NULL,
  vin        TEXT NOT NULL,
  field_id   TEXT NOT NULL,
  source_key TEXT,
  state      TEXT NOT NULL,
  PRIMARY KEY (run_id, vin, field_id)
);

CREATE INDEX IF NOT EXISTS m0_observation_run_field
  ON m0_observation (run_id, field_id, state);

CREATE TABLE IF NOT EXISTS m0_probe (
  run_id    TEXT NOT NULL,
  vin       TEXT NOT NULL,
  field_id  TEXT NOT NULL,
  probe_key TEXT NOT NULL,
  state     TEXT NOT NULL,
  PRIMARY KEY (run_id, vin, field_id, probe_key)
);

CREATE INDEX IF NOT EXISTS m0_probe_run_field
  ON m0_probe (run_id, field_id, probe_key, state);

CREATE TABLE IF NOT EXISTS m0_vin_reject (
  run_id             TEXT NOT NULL,
  vin_input          TEXT NOT NULL,
  reason             TEXT NOT NULL,
  syntax_valid       INTEGER,
  check_digit_valid  INTEGER,
  expected_check_digit TEXT,
  PRIMARY KEY (run_id, vin_input)
);

CREATE TABLE IF NOT EXISTS m0_unreached (
  run_id TEXT NOT NULL,
  vin    TEXT NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY (run_id, vin)
);

CREATE TABLE IF NOT EXISTS m0_vpic_cache (
  vin        TEXT PRIMARY KEY,
  fetched_at INTEGER NOT NULL,
  error_code TEXT,
  payload    TEXT NOT NULL
);
`

/**
 * Idempotent schema bootstrap, memoised per isolate.
 *
 * Not a substitute for `wrangler d1 execute` — an operator should apply the schema
 * deliberately — but a study Worker that 500s on a fresh database because nobody ran a
 * migration wastes exactly the time M0 exists to save.
 */
let schemaReady = null
function ensureSchema(env) {
  if (!schemaReady) {
    const statements = SCHEMA_SQL.split(';')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .map((s) => env.DB.prepare(s))
    schemaReady = env.DB.batch(statements).catch((err) => {
      schemaReady = null // let the next request retry rather than pinning the failure
      throw err
    })
  }
  return schemaReady
}

/**
 * Bulk insert via json_each.
 *
 * D1 caps bound parameters per statement, so a multi-row VALUES list would need one
 * statement per handful of rows — hundreds per run. Passing the rows as a single JSON
 * argument keeps it to two bound parameters regardless of row count, and stays fully
 * parameterised: no user input is ever concatenated into SQL.
 *
 * Depends on SQLite's JSON1 functions, which D1 provides.
 */
function jsonInsertStatements(env, sql, scalar, rows) {
  return chunk(rows, INSERT_CHUNK_ROWS).map((group) =>
    env.DB.prepare(sql).bind(scalar, JSON.stringify(group)),
  )
}

const OBSERVATION_INSERT = `
INSERT OR REPLACE INTO m0_observation (run_id, vin, field_id, source_key, state)
SELECT ?1,
       json_extract(j.value, '$.v'),
       json_extract(j.value, '$.f'),
       json_extract(j.value, '$.k'),
       json_extract(j.value, '$.s')
FROM json_each(?2) AS j
`

const PROBE_INSERT = `
INSERT OR REPLACE INTO m0_probe (run_id, vin, field_id, probe_key, state)
SELECT ?1,
       json_extract(j.value, '$.v'),
       json_extract(j.value, '$.f'),
       json_extract(j.value, '$.p'),
       json_extract(j.value, '$.s')
FROM json_each(?2) AS j
`

const REJECT_INSERT = `
INSERT OR REPLACE INTO m0_vin_reject
  (run_id, vin_input, reason, syntax_valid, check_digit_valid, expected_check_digit)
SELECT ?1,
       json_extract(j.value, '$.i'),
       json_extract(j.value, '$.r'),
       json_extract(j.value, '$.sv'),
       json_extract(j.value, '$.cv'),
       json_extract(j.value, '$.ec')
FROM json_each(?2) AS j
`

const UNREACHED_INSERT = `
INSERT OR REPLACE INTO m0_unreached (run_id, vin, reason)
SELECT ?1, json_extract(j.value, '$.v'), json_extract(j.value, '$.r')
FROM json_each(?2) AS j
`

const CACHE_UPSERT = `
INSERT INTO m0_vpic_cache (vin, fetched_at, error_code, payload)
SELECT json_extract(j.value, '$.v'),
       ?1,
       json_extract(j.value, '$.e'),
       json_extract(j.value, '$.p')
FROM json_each(?2) AS j
WHERE true
ON CONFLICT(vin) DO UPDATE SET
  fetched_at = excluded.fetched_at,
  error_code = excluded.error_code,
  payload    = excluded.payload
`

/* ------------------------------------------------------------------------- *
 * Input validation — before any network call
 * ------------------------------------------------------------------------- */

/**
 * Partition submitted VINs into eligible and rejected, entirely locally.
 *
 * Validation happens BEFORE any network call for two reasons. The obvious one is that
 * sending malformed VINs to a free public service we do not pay for is rude and wastes
 * the batch slots. The load-bearing one is that a check-digit failure is a finding about
 * the SAMPLE, not about vPIC, and mixing the two would let a sample sourced from bad OCR
 * present itself as a vPIC coverage problem.
 *
 * Check-digit-invalid VINs are REPORTED, never silently dropped. vin.js reports syntax
 * and check digit separately because 49 C.F.R. §565.15 mandates the check digit only for
 * the North American market, so structurally valid grey-market and some non-NA VINs fail
 * it. A study that discarded them without saying so would understate its own sample loss
 * and would quietly exclude a class of legally-registered vehicles from the yield
 * question — which is precisely the population most likely to have poor vPIC coverage,
 * so dropping them biases the result toward a pass.
 */
export function partitionVins(input, { strict = true } = {}) {
  const eligible = []
  const rejected = []
  const seen = new Set()
  let duplicates = 0
  let syntaxInvalid = 0
  let checkDigitInvalid = 0

  for (const raw of input) {
    const asString = typeof raw === 'string' ? raw : String(raw ?? '')
    const label = asString.slice(0, MAX_REJECT_INPUT_CHARS)
    const v = validateVin(asString, { strict: false })

    if (!v.syntaxValid) {
      syntaxInvalid += 1
      rejected.push({ i: label, r: v.reason, sv: 0, cv: null, ec: null })
      continue
    }
    if (seen.has(v.normalized)) {
      duplicates += 1
      continue
    }
    seen.add(v.normalized)

    if (!v.checkDigitValid) {
      checkDigitInvalid += 1
      // Recorded either way. In non-strict mode the VIN is still submitted, and the
      // report cross-tabulates coverage against check-digit validity — a decode that
      // succeeds on a check-digit-invalid VIN is itself informative.
      rejected.push({
        i: label,
        r: strict ? `excluded (strict): ${v.reason}` : `submitted despite: ${v.reason}`,
        sv: 1,
        cv: 0,
        ec: v.expectedCheckDigit,
      })
      if (strict) continue
    }
    eligible.push(v.normalized)
  }

  return { eligible, rejected, duplicates, syntaxInvalid, checkDigitInvalid }
}

/* ------------------------------------------------------------------------- *
 * The run
 * ------------------------------------------------------------------------- */

/**
 * Execute one study run: validate, decode (cache first), classify, persist.
 *
 * Partial-result mode is not an error path, it is a first-class outcome. Three counters
 * are kept strictly apart and all three are reported:
 *
 *   vins_eligible  — passed local validation
 *   vins_attempted — actually put on the wire or served from cache
 *   vins_decoded   — vPIC returned a result row for them
 *
 * Coverage denominators use `vins_decoded`. VINs we never heard back about are recorded
 * in `m0_unreached` and set `truncated`, so no rate is ever computed over a shortened
 * sample without the report saying so.
 *
 * `null_decodes` — a result row containing not one present measured field — ARE counted
 * in the denominator. A VIN vPIC accepts but cannot describe is a genuine coverage
 * failure, and excluding it would be denominator-shopping in the flattering direction.
 * It is counted separately as well so the reader can see how much of the shortfall is
 * "vPIC knows nothing about this vehicle" versus "vPIC knows this vehicle but not its trim".
 */
async function executeRun(env, cfg, { sampleId, provenance, vins, strict, refresh }) {
  const runId = crypto.randomUUID()
  const startedAt = Math.floor(Date.now() / 1000)

  const part = partitionVins(vins, { strict })

  await env.DB.prepare(
    `INSERT INTO m0_run (run_id, sample_id, provenance, study_version, strict_check_digit,
                         started_at, vins_submitted, vins_duplicate, vins_syntax_invalid,
                         vins_check_digit_invalid, vins_eligible)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
  )
    .bind(
      runId,
      sampleId,
      provenance,
      STUDY_VERSION,
      strict ? 1 : 0,
      startedAt,
      vins.length,
      part.duplicates,
      part.syntaxInvalid,
      part.checkDigitInvalid,
      part.eligible.length,
    )
    .run()

  const cached = refresh ? new Map() : await loadCache(env, part.eligible, cfg.cacheTtlS)

  const toFetch = part.eligible.filter((v) => !cached.has(v))
  const batches = chunk(toFetch, VPIC_BATCH_LIMIT)

  const projections = [...cached.values()]
  const unreached = []
  const anomalies = []
  const tripwires = new Set()
  const freshlyFetched = []
  let batchesFailed = 0
  let truncationReason = null
  // VINs never put on the wire at all, as distinct from VINs attempted and lost. Only
  // the latter tells you anything about vPIC; conflating them would attribute our own
  // budget ceiling to NHTSA.
  let neverAttempted = 0

  for (const [index, batch] of batches.entries()) {
    if (index >= MAX_SUBREQUEST_BUDGET) {
      truncationReason = `subrequest budget of ${MAX_SUBREQUEST_BUDGET} batches exhausted`
      const rest = batches.slice(index).flat()
      neverAttempted += rest.length
      for (const vin of rest) unreached.push({ v: vin, r: truncationReason })
      break
    }
    if (Date.now() > cfg.deadline) {
      truncationReason = `run wall-clock budget of ${RUN_BUDGET_MS}ms exhausted`
      const rest = batches.slice(index).flat()
      neverAttempted += rest.length
      for (const vin of rest) unreached.push({ v: vin, r: truncationReason })
      break
    }

    // A single leftover VIN goes through the single-VIN endpoint: it is edge-cacheable,
    // and there is no reason to POST an uncacheable batch of one.
    const call = batch.length === 1 ? await decodeSingle(batch[0], cfg) : await decodeBatch(batch, cfg)

    if (!call.ok) {
      batchesFailed += 1
      const reason = `vPIC unavailable after ${call.attempts} attempt(s): ${call.error}`
      for (const vin of batch) unreached.push({ v: vin, r: reason })
      continue
    }

    const { matched, missing, anomalies: batchAnomalies } = matchResultsToVins(call.results, batch)
    for (const a of batchAnomalies) anomalies.push(a)
    for (const vin of missing) unreached.push({ v: vin, r: 'vPIC returned no result row for this VIN' })
    for (const p of matched) {
      for (const t of p.tripwires) tripwires.add(t)
      projections.push(p)
      freshlyFetched.push(p)
    }
  }

  // Classify, then persist. Classification is pure and testable; persistence is bulk.
  const observationRows = []
  const probeRows = []
  const errorCodes = new Map()
  let nullDecodes = 0

  for (const projected of projections) {
    const { fields, probes } = classifyResult(projected)
    if (!fields.some((f) => isCovered(f.state))) nullDecodes += 1
    for (const f of fields) {
      observationRows.push({ v: projected.vin, f: f.fieldId, k: f.sourceKey, s: f.state })
    }
    for (const p of probes) {
      probeRows.push({ v: projected.vin, f: p.fieldId, p: p.probeKey, s: p.state })
    }
    for (const code of splitErrorCodes(projected.errorCode)) {
      errorCodes.set(code, (errorCodes.get(code) ?? 0) + 1)
    }
  }

  const statements = [
    ...jsonInsertStatements(env, OBSERVATION_INSERT, runId, observationRows),
    ...jsonInsertStatements(env, PROBE_INSERT, runId, probeRows),
    ...jsonInsertStatements(env, REJECT_INSERT, runId, part.rejected),
    ...jsonInsertStatements(env, UNREACHED_INSERT, runId, unreached),
  ]
  if (freshlyFetched.length > 0) {
    const cacheRows = freshlyFetched.map((p) => ({
      v: p.vin,
      e: p.errorCode,
      p: JSON.stringify(p.values),
    }))
    statements.push(
      ...jsonInsertStatements(env, CACHE_UPSERT, Math.floor(Date.now() / 1000), cacheRows),
    )
  }
  if (statements.length > 0) await env.DB.batch(statements)

  const truncated = unreached.length > 0
  if (truncated && !truncationReason) truncationReason = 'one or more vPIC calls did not return'

  await env.DB.prepare(
    `UPDATE m0_run SET finished_at = ?2, vins_attempted = ?3, vins_decoded = ?4,
       vins_from_cache = ?5, vins_unreached = ?6, null_decodes = ?7, batches_total = ?8,
       batches_failed = ?9, truncated = ?10, truncation_reason = ?11,
       error_code_histogram = ?12, anomalies = ?13, tripwires = ?14
     WHERE run_id = ?1`,
  )
    .bind(
      runId,
      Math.floor(Date.now() / 1000),
      part.eligible.length - neverAttempted,
      projections.length,
      cached.size,
      unreached.length,
      nullDecodes,
      batches.length,
      batchesFailed,
      truncated ? 1 : 0,
      truncationReason,
      JSON.stringify(Object.fromEntries(errorCodes)),
      JSON.stringify(anomalies.slice(0, 200)),
      JSON.stringify([...tripwires]),
    )
    .run()

  return { runId, sampleId }
}

/** vPIC returns ErrorCode as a comma-separated list when several apply. */
export function splitErrorCodes(errorCode) {
  if (typeof errorCode !== 'string' || errorCode.trim() === '') return []
  return errorCode
    .split(',')
    .map((c) => c.trim())
    .filter((c) => c.length > 0)
}

/**
 * Read fresh cache rows for the requested VINs.
 *
 * Chunked into IN-lists of bound placeholders — parameterised, never interpolated. A
 * stale row is treated as a miss rather than deleted: the refetch overwrites it, and a
 * delete-then-fetch would lose the old row if vPIC were down.
 */
async function loadCache(env, vins, ttlS) {
  const cutoff = Math.floor(Date.now() / 1000) - ttlS
  const found = new Map()

  for (const group of chunk(vins, 80)) {
    const placeholders = group.map((_, i) => `?${i + 2}`).join(', ')
    const { results } = await env.DB.prepare(
      `SELECT vin, error_code, payload FROM m0_vpic_cache
       WHERE fetched_at >= ?1 AND vin IN (${placeholders})`,
    )
      .bind(cutoff, ...group)
      .all()

    for (const row of results ?? []) {
      let values
      try {
        values = JSON.parse(row.payload)
      } catch {
        continue // a corrupt cache row is a miss, not a crash
      }
      found.set(row.vin, {
        vin: row.vin,
        errorCode: row.error_code,
        errorText: null,
        values,
        tripwires: [],
        droppedKeys: 0,
      })
    }
  }
  return found
}

/* ------------------------------------------------------------------------- *
 * Report
 * ------------------------------------------------------------------------- */

/**
 * Per-field verdicts from raw state counts.
 *
 * `denominator` travels with every rate, in every row. It is not a convenience — a
 * coverage figure detached from the count it was computed over is the single easiest way
 * for this study to mislead the decision it gates.
 *
 * @param {Map<string, Record<string, number>>} stateCounts field_id -> state -> n
 * @param {Map<string, Record<string, Record<string, number>>>} probeCounts
 * @param {number} denominator vins_decoded
 */
export function computeFieldReport(stateCounts, probeCounts, denominator) {
  const rows = []

  for (const fieldId of FIELDS) {
    const expectedLayer = expectedLayerOf(fieldId)
    const spec = VPIC_FIELD_MAP[fieldId]
    const measured = spec.keys.length > 0
    const counts = stateCounts.get(fieldId) ?? {}
    const present = counts[VALUE_STATES.PRESENT] ?? 0
    const empty = counts[VALUE_STATES.ABSENT_EMPTY] ?? 0
    const notApplicable = counts[VALUE_STATES.ABSENT_NOT_APPLICABLE] ?? 0
    const keyAbsent = counts[VALUE_STATES.KEY_ABSENT] ?? 0
    const observed = present + empty + notApplicable + keyAbsent

    const probes = Object.entries(probeCounts.get(fieldId) ?? {}).map(([probeKey, pc]) => ({
      probe_key: probeKey,
      present: pc[VALUE_STATES.PRESENT] ?? 0,
      absent_empty: pc[VALUE_STATES.ABSENT_EMPTY] ?? 0,
      absent_not_applicable: pc[VALUE_STATES.ABSENT_NOT_APPLICABLE] ?? 0,
      key_absent: pc[VALUE_STATES.KEY_ABSENT] ?? 0,
      present_rate: denominator > 0 ? (pc[VALUE_STATES.PRESENT] ?? 0) / denominator : null,
    }))

    const coverage = measured && denominator > 0 ? present / denominator : measured ? null : 0
    const probeHit = probes.some((p) => p.present > 0)

    rows.push({
      field_id: fieldId,
      field_class: classOfField(fieldId),
      expected_layer: expectedLayer,
      measured_against_vpic: measured,
      vpic_keys: spec.keys,
      denominator,
      observed,
      // An accounting mismatch means rows were lost. A rate over a denominator that does
      // not reconcile is not a measurement, so it is surfaced rather than smoothed.
      reconciles: !measured || observed === denominator,
      present,
      absent_empty: empty,
      absent_not_applicable: notApplicable,
      key_absent: keyAbsent,
      coverage_rate: coverage,
      null_rate: measured && denominator > 0 ? empty / denominator : null,
      not_applicable_rate: measured && denominator > 0 ? notApplicable / denominator : null,
      probes,
      probe_hit: probeHit,
      why_not_vin_derivable: spec.whyNot ?? null,
      verdict: fieldVerdict({ measured, coverage, expectedLayer, probeHit }),
      second_source_required: secondSourceRequired({ measured, coverage }),
    })
  }

  return rows
}

function fieldVerdict({ measured, coverage, expectedLayer, probeHit }) {
  if (!measured) {
    // Expected-not-derivable, confirmed by the absence of any vPIC key. A probe hit does
    // not overturn that — it means vPIC carries an adjacent SPECIFICATION value, which is
    // reported as a near-miss precisely so nobody reads it as the state value.
    return probeHit ? 'not_vin_derivable_specification_near_miss_present' : 'not_vin_derivable_confirmed'
  }
  if (coverage === null) return 'indeterminate_no_sample'
  if (coverage >= COVERAGE_THRESHOLD) return 'vin_derivable'
  if (coverage > 0) {
    return expectedLayer === 'vpic'
      ? 'vin_derivable_below_threshold_second_source_required'
      : 'partially_vin_derivable_unexpected'
  }
  return 'not_vin_derivable'
}

/**
 * A field needs a second source unless vPIC supplies it at or above the threshold. Below
 * the threshold the answer is the same whatever the declared layer: a grant cannot be
 * scoped on a field the broker can only sometimes populate.
 */
function secondSourceRequired({ measured, coverage }) {
  if (!measured) return true
  if (coverage === null) return null
  return coverage < COVERAGE_THRESHOLD
}

/**
 * Assemble the full report for a run or a whole sample.
 *
 * The verdict is withheld below MIN_SAMPLE_FOR_VERDICT. A pass drawn from twelve VINs
 * would be cited downstream as clearance for the broker build, and that is a worse
 * outcome than no answer.
 */
export function buildReport({ runs, fieldRows, denominator }) {
  const totals = runs.reduce(
    (acc, r) => ({
      vins_submitted: acc.vins_submitted + (r.vins_submitted ?? 0),
      vins_eligible: acc.vins_eligible + (r.vins_eligible ?? 0),
      vins_attempted: acc.vins_attempted + (r.vins_attempted ?? 0),
      vins_decoded: acc.vins_decoded + (r.vins_decoded ?? 0),
      vins_from_cache: acc.vins_from_cache + (r.vins_from_cache ?? 0),
      vins_unreached: acc.vins_unreached + (r.vins_unreached ?? 0),
      vins_syntax_invalid: acc.vins_syntax_invalid + (r.vins_syntax_invalid ?? 0),
      vins_check_digit_invalid: acc.vins_check_digit_invalid + (r.vins_check_digit_invalid ?? 0),
      vins_duplicate: acc.vins_duplicate + (r.vins_duplicate ?? 0),
      null_decodes: acc.null_decodes + (r.null_decodes ?? 0),
      batches_total: acc.batches_total + (r.batches_total ?? 0),
      batches_failed: acc.batches_failed + (r.batches_failed ?? 0),
    }),
    {
      vins_submitted: 0, vins_eligible: 0, vins_attempted: 0, vins_decoded: 0,
      vins_from_cache: 0, vins_unreached: 0, vins_syntax_invalid: 0,
      vins_check_digit_invalid: 0, vins_duplicate: 0, null_decodes: 0,
      batches_total: 0, batches_failed: 0,
    },
  )

  const truncated = runs.some((r) => r.truncated === 1 || r.truncated === true)
  const caveats = []

  if (truncated || totals.vins_unreached > 0) {
    const lost = totals.vins_unreached
    const pct = totals.vins_eligible > 0 ? ((lost / totals.vins_eligible) * 100).toFixed(1) : 'n/a'
    caveats.push(
      `PARTIAL SAMPLE. ${lost} of ${totals.vins_eligible} eligible VINs (${pct}%) were never ` +
      `decoded. Every coverage rate below is computed over the ${denominator} VINs vPIC actually ` +
      'returned, not over the sample as submitted. Reasons are recorded per VIN in m0_unreached.',
    )
  }
  if (totals.null_decodes > 0) {
    const pct = denominator > 0 ? ((totals.null_decodes / denominator) * 100).toFixed(1) : 'n/a'
    caveats.push(
      `${totals.null_decodes} decoded VINs (${pct}%) yielded no present measured field at all. ` +
      'They are counted in the denominator: a VIN vPIC accepts but cannot describe is a coverage ' +
      'failure, not a sample defect.',
    )
  }
  if (totals.vins_check_digit_invalid > 0) {
    caveats.push(
      `${totals.vins_check_digit_invalid} submitted VINs failed the ISO 3779 check digit. ` +
      'Reported, not silently dropped: 49 C.F.R. §565.15 mandates the check digit only for the ' +
      'North American market, so some legally-registered vehicles fail it, and excluding them ' +
      'without saying so would bias the yield question toward a pass.',
    )
  }
  const unreconciled = fieldRows.filter((r) => !r.reconciles).map((r) => r.field_id)
  if (unreconciled.length > 0) {
    caveats.push(
      `ACCOUNTING DEFECT: observation counts do not reconcile with the denominator for ` +
      `${unreconciled.join(', ')}. Treat those rows as unmeasured, not as low coverage.`,
    )
  }
  const tripwires = new Set()
  for (const r of runs) {
    for (const t of safeJsonArray(r.tripwires)) tripwires.add(t)
  }
  if (tripwires.size > 0) {
    caveats.push(
      `TRIPWIRE: vPIC returned response keys resembling personal information or position ` +
      `(${[...tripwires].join(', ')}). None were persisted — the projection is an allowlist — but ` +
      'refusals 1 and 2 (§10.1) need a fresh review of whether vPIC may still be consumed as-is.',
    )
  }

  // The negative-finding set. Two disjoint populations, kept disjoint on purpose.
  const assumedButAbsent = fieldRows.filter(
    (r) => r.expected_layer === 'vpic' && r.verdict !== 'vin_derivable' && r.measured_against_vpic,
  )
  const confirmedLayer2 = fieldRows.filter((r) => r.expected_layer !== 'vpic')
  const unexpectedlyDerivable = fieldRows.filter(
    (r) => r.expected_layer !== 'vpic' && r.coverage_rate > 0,
  )
  const nearMisses = fieldRows.filter((r) => !r.measured_against_vpic && r.probe_hit)

  const belowThreshold = assumedButAbsent.filter(
    (r) => r.coverage_rate !== null && r.coverage_rate < COVERAGE_THRESHOLD,
  )

  let verdict
  if (denominator < MIN_SAMPLE_FOR_VERDICT) {
    verdict = {
      determination: 'INDETERMINATE',
      threshold: COVERAGE_THRESHOLD,
      rescope_required: null,
      statement:
        `Only ${denominator} VINs were decoded; M0 declines to rule below ` +
        `${MIN_SAMPLE_FOR_VERDICT}. A pass drawn from a sample this small would be cited ` +
        'downstream as clearance for the broker build, which is worse than no answer. ' +
        'Run more VINs under the same sample_id and re-read the report.',
    }
  } else if (belowThreshold.length > 0) {
    verdict = {
      determination: 'THRESHOLD BREACH',
      threshold: COVERAGE_THRESHOLD,
      rescope_required: true,
      fields_below_threshold: belowThreshold.map((r) => ({
        field_id: r.field_id,
        coverage_rate: r.coverage_rate,
        denominator: r.denominator,
      })),
      statement:
        `NF-WP-1 §15 recommendation 1: the following architecturally-assumed VIN-derivable ` +
        `fields fall below ${Math.round(COVERAGE_THRESHOLD * 100)}% coverage over ${denominator} ` +
        `decoded VINs — ${belowThreshold
          .map((r) => `${r.field_id} (${(r.coverage_rate * 100).toFixed(1)}%)`)
          .join(', ')}. Each therefore requires a second source. ${RESCOPE_STATEMENT}`,
    }
  } else {
    verdict = {
      determination: 'THRESHOLD MET',
      threshold: COVERAGE_THRESHOLD,
      rescope_required: false,
      statement:
        `Every field the architecture assumes is VIN-derivable is at or above ` +
        `${Math.round(COVERAGE_THRESHOLD * 100)}% coverage over ${denominator} decoded VINs. ` +
        'Layers 3 and 4 may proceed as scoped for the build-specification class ONLY. ' +
        `The Layer-2 dependency is unchanged and empirically confirmed: ${CEILING_STATEMENT}`,
    }
  }

  return {
    study_version: STUDY_VERSION,
    generated_at: new Date().toISOString(),
    runs: runs.map((r) => ({
      run_id: r.run_id,
      sample_id: r.sample_id,
      provenance: r.provenance,
      started_at: r.started_at,
      finished_at: r.finished_at,
      strict_check_digit: r.strict_check_digit === 1,
      truncated: r.truncated === 1,
      truncation_reason: r.truncation_reason,
      error_code_histogram: safeJsonObject(r.error_code_histogram),
      anomalies: safeJsonArray(r.anomalies),
    })),
    sample: { ...totals, coverage_denominator: denominator, complete: !truncated && totals.vins_unreached === 0 },
    caveats,
    verdict,
    honest_ceiling: CEILING_STATEMENT,
    fields: fieldRows,
    negative_findings: {
      assumed_vin_available_but_absent: assumedButAbsent.map((r) => ({
        field_id: r.field_id,
        field_class: r.field_class,
        coverage_rate: r.coverage_rate,
        null_rate: r.null_rate,
        not_applicable_rate: r.not_applicable_rate,
        denominator: r.denominator,
        verdict: r.verdict,
      })),
      confirmed_second_source_required: confirmedLayer2.map((r) => ({
        field_id: r.field_id,
        field_class: r.field_class,
        expected_layer: r.expected_layer,
        why_not_vin_derivable: r.why_not_vin_derivable,
        verdict: r.verdict,
      })),
      specification_near_misses: nearMisses.map((r) => ({
        field_id: r.field_id,
        probes: r.probes.filter((p) => p.present > 0),
        why_not_vin_derivable: r.why_not_vin_derivable,
      })),
      unexpectedly_vin_derivable: unexpectedlyDerivable.map((r) => ({
        field_id: r.field_id,
        expected_layer: r.expected_layer,
        coverage_rate: r.coverage_rate,
        note:
          'fields.js declares this field non-VIN-derivable and M0 measured coverage above zero. ' +
          'Reconcile fields.js against this finding before relying on either.',
      })),
    },
  }
}

function safeJsonArray(text) {
  try {
    const parsed = JSON.parse(text ?? '[]')
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function safeJsonObject(text) {
  try {
    const parsed = JSON.parse(text ?? '{}')
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
  } catch {
    return {}
  }
}

/** Load runs plus their aggregated state counts, by run_id or by sample_id. */
async function loadReport(env, { runId, sampleId }) {
  const runQuery = runId
    ? env.DB.prepare('SELECT * FROM m0_run WHERE run_id = ?1').bind(runId)
    : sampleId
      ? env.DB.prepare('SELECT * FROM m0_run WHERE sample_id = ?1 ORDER BY started_at').bind(sampleId)
      : env.DB.prepare('SELECT * FROM m0_run ORDER BY started_at DESC LIMIT 1')

  const { results: runs } = await runQuery.all()
  if (!runs || runs.length === 0) return null

  const runIds = runs.map((r) => r.run_id)
  const placeholders = runIds.map((_, i) => `?${i + 1}`).join(', ')

  const [{ results: obs }, { results: probes }] = await Promise.all([
    env.DB.prepare(
      `SELECT field_id, state, COUNT(*) AS n FROM m0_observation
       WHERE run_id IN (${placeholders}) GROUP BY field_id, state`,
    ).bind(...runIds).all(),
    env.DB.prepare(
      `SELECT field_id, probe_key, state, COUNT(*) AS n FROM m0_probe
       WHERE run_id IN (${placeholders}) GROUP BY field_id, probe_key, state`,
    ).bind(...runIds).all(),
  ])

  const stateCounts = new Map()
  for (const row of obs ?? []) {
    if (!stateCounts.has(row.field_id)) stateCounts.set(row.field_id, {})
    stateCounts.get(row.field_id)[row.state] = row.n
  }
  const probeCounts = new Map()
  for (const row of probes ?? []) {
    if (!probeCounts.has(row.field_id)) probeCounts.set(row.field_id, {})
    const forField = probeCounts.get(row.field_id)
    if (!forField[row.probe_key]) forField[row.probe_key] = {}
    forField[row.probe_key][row.state] = row.n
  }

  const denominator = runs.reduce((n, r) => n + (r.vins_decoded ?? 0), 0)
  const fieldRows = computeFieldReport(stateCounts, probeCounts, denominator)
  return buildReport({ runs, fieldRows, denominator })
}

/* ------------------------------------------------------------------------- *
 * Markdown rendering
 * ------------------------------------------------------------------------- */

function pct(rate) {
  return rate === null || rate === undefined ? '—' : `${(rate * 100).toFixed(1)}%`
}

/**
 * Render the report in the shape of REPORT-TEMPLATE.md.
 *
 * The Worker renders it rather than leaving a human to transcribe numbers into the
 * template, because hand-transcription is where a threshold breach becomes a rounding
 * discussion. Every mandatory section is emitted unconditionally, with "none observed"
 * where a section is empty — an omitted section reads exactly like a passed test.
 */
export function renderMarkdown(report) {
  const L = []
  const v = report.verdict
  const s = report.sample

  L.push('# M0 — VIN-yield study result')
  L.push('')
  L.push(`- Study version: \`${report.study_version}\``)
  L.push(`- Generated: ${report.generated_at}`)
  L.push(`- Source: NHTSA vPIC \`DecodeVinValues\` / \`DecodeVinValuesBatch\` (public, keyless;`)
  L.push('  populated from manufacturer submissions under 49 C.F.R. Part 565)')
  L.push(`- Runs: ${report.runs.length}`)
  for (const r of report.runs) {
    L.push(`  - \`${r.run_id}\` · sample \`${r.sample_id}\` · strict check digit: ${r.strict_check_digit}`)
    L.push(`    - provenance: ${r.provenance}`)
    if (r.truncated) L.push(`    - TRUNCATED: ${r.truncation_reason}`)
  }
  L.push('')

  L.push(`## 1. Determination — ${v.determination}`)
  L.push('')
  L.push(`> ${v.statement}`)
  L.push('')
  L.push(`Threshold applied: ${Math.round(v.threshold * 100)}% (NF-WP-1 §15 recommendation 1).`)
  L.push(`Re-scoping required: **${v.rescope_required === null ? 'undetermined' : v.rescope_required}**`)
  L.push('')

  L.push('## 2. Sample integrity')
  L.push('')
  L.push('| Measure | Count |')
  L.push('| --- | --- |')
  L.push(`| VINs submitted | ${s.vins_submitted} |`)
  L.push(`| Duplicates collapsed | ${s.vins_duplicate} |`)
  L.push(`| Rejected — syntax (ISO 3779) | ${s.vins_syntax_invalid} |`)
  L.push(`| Flagged — check digit | ${s.vins_check_digit_invalid} |`)
  L.push(`| Eligible after local validation | ${s.vins_eligible} |`)
  L.push(`| Attempted against vPIC | ${s.vins_attempted} |`)
  L.push(`| Served from cache | ${s.vins_from_cache} |`)
  L.push(`| **Decoded (coverage denominator)** | **${s.coverage_denominator}** |`)
  L.push(`| Never decoded | ${s.vins_unreached} |`)
  L.push(`| Null decodes (row returned, no field present) | ${s.null_decodes} |`)
  L.push(`| Batches / failed | ${s.batches_total} / ${s.batches_failed} |`)
  L.push(`| Sample complete | ${s.complete} |`)
  L.push('')

  L.push('### Caveats')
  L.push('')
  if (report.caveats.length === 0) L.push('None observed.')
  else for (const c of report.caveats) L.push(`- ${c}`)
  L.push('')

  L.push('## 3. Per-field coverage')
  L.push('')
  L.push(`All rates are over ${s.coverage_denominator} decoded VINs.`)
  L.push('')
  L.push('| Field | Class | Expected layer | vPIC key(s) | Coverage | Null | Not applicable | Second source | Verdict |')
  L.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- |')
  for (const f of report.fields) {
    L.push(
      `| \`${f.field_id}\` | ${f.field_class} | ${f.expected_layer} | ` +
      `${f.vpic_keys.length > 0 ? f.vpic_keys.map((k) => `\`${k}\``).join(', ') : '_none_'} | ` +
      `${pct(f.coverage_rate)} | ${pct(f.null_rate)} | ${pct(f.not_applicable_rate)} | ` +
      `${f.second_source_required === null ? '—' : f.second_source_required} | ${f.verdict} |`,
    )
  }
  L.push('')

  const nf = report.negative_findings

  L.push('## 4. MANDATORY NEGATIVE FINDINGS — fields the architecture assumes are VIN-available but are not')
  L.push('')
  if (nf.assumed_vin_available_but_absent.length === 0) {
    L.push('None. Every field `fields.js` marks `layer: \'vpic\'` materialised at or above the threshold.')
  } else {
    L.push('`fields.js` marks each of these `layer: \'vpic\'`. vPIC did not deliver.')
    L.push('')
    L.push('| Field | Class | Coverage | Null rate | Not-applicable rate | Verdict |')
    L.push('| --- | --- | --- | --- | --- | --- |')
    for (const f of nf.assumed_vin_available_but_absent) {
      L.push(
        `| \`${f.field_id}\` | ${f.field_class} | ${pct(f.coverage_rate)} | ${pct(f.null_rate)} | ` +
        `${pct(f.not_applicable_rate)} | ${f.verdict} |`,
      )
    }
  }
  L.push('')

  L.push('## 5. Confirmed Layer-2 / operator dependencies')
  L.push('')
  L.push(report.honest_ceiling)
  L.push('')
  L.push('This is NF-WP-1 §3.3 restated as an empirical finding rather than a caveat.')
  L.push('')
  L.push('| Field | Class | Expected layer | Why a VIN cannot supply it |')
  L.push('| --- | --- | --- | --- |')
  for (const f of nf.confirmed_second_source_required) {
    L.push(`| \`${f.field_id}\` | ${f.field_class} | ${f.expected_layer} | ${f.why_not_vin_derivable} |`)
  }
  L.push('')

  L.push('## 6. Specification near-misses')
  L.push('')
  L.push(
    'vPIC keys that describe the vehicle as built and could be mistaken for the runtime state ' +
    'the field actually names. Counting any of these as coverage would manufacture a Layer-2 ' +
    'independence that does not exist.',
  )
  L.push('')
  if (nf.specification_near_misses.length === 0) {
    L.push('None observed in this sample.')
  } else {
    L.push('| Field | vPIC probe key | Present | Present rate | Why it is not the same field |')
    L.push('| --- | --- | --- | --- | --- |')
    for (const f of nf.specification_near_misses) {
      for (const p of f.probes) {
        L.push(
          `| \`${f.field_id}\` | \`${p.probe_key}\` | ${p.present} | ${pct(p.present_rate)} | ` +
          `${f.why_not_vin_derivable} |`,
        )
      }
    }
  }
  L.push('')

  L.push('## 7. Contradictions of `fields.js`')
  L.push('')
  if (nf.unexpectedly_vin_derivable.length === 0) {
    L.push('None. Every field declared non-VIN-derivable measured zero VIN-derived coverage.')
  } else {
    for (const f of nf.unexpectedly_vin_derivable) {
      L.push(`- \`${f.field_id}\` (declared \`${f.expected_layer}\`) measured ${pct(f.coverage_rate)}. ${f.note}`)
    }
  }
  L.push('')

  L.push('## 8. vPIC error codes')
  L.push('')
  const histogram = {}
  for (const r of report.runs) {
    for (const [code, n] of Object.entries(r.error_code_histogram ?? {})) {
      histogram[code] = (histogram[code] ?? 0) + n
    }
  }
  const codes = Object.entries(histogram).sort((a, b) => b[1] - a[1])
  if (codes.length === 0) L.push('No error codes returned.')
  else {
    L.push('| ErrorCode | Occurrences |')
    L.push('| --- | --- |')
    for (const [code, n] of codes) L.push(`| \`${code}\` | ${n} |`)
  }
  L.push('')

  L.push('## 9. What M0 does not establish')
  L.push('')
  L.push('- Nothing about data the OEM holds. M0 measures the public VIN decode only.')
  L.push('- Nothing about whether Layer-2 access is legally or commercially obtainable.')
  L.push('- Nothing about accuracy. A present value is counted as coverage even if it is wrong;')
  L.push('  vPIC reflects manufacturer submissions and M0 does not ground-truth them.')
  L.push('- Nothing about representativeness beyond the stated sample provenance.')
  L.push('')

  return L.join('\n')
}

/* ------------------------------------------------------------------------- *
 * HTTP surface
 * ------------------------------------------------------------------------- */

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, { status, headers: { 'content-type': contentType, 'cache-control': 'no-store' } })
}

function problem(status, detail) {
  return json({ error: detail, status }, status)
}

/**
 * Constant-time bearer check.
 *
 * Compares SHA-256 digests rather than the strings: digest comparison is fixed-length and
 * leaks neither the secret's length nor the position of the first differing byte.
 *
 * Fails CLOSED when the secret is unset. An unauthenticated `POST /decode` would be an
 * open proxy onto a free public service and an open writer into D1, so a missing secret
 * disables mutation entirely rather than defaulting to open.
 */
async function authorized(request, env) {
  const expected = env.M0_ADMIN_TOKEN
  if (typeof expected !== 'string' || expected.length === 0) return false

  const header = request.headers.get('authorization') ?? ''
  const match = /^Bearer\s+(.+)$/i.exec(header.trim())
  if (!match) return false

  const enc = new TextEncoder()
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(match[1])),
    crypto.subtle.digest('SHA-256', enc.encode(expected)),
  ])
  const av = new Uint8Array(a)
  const bv = new Uint8Array(b)
  let diff = 0
  for (let i = 0; i < av.length; i += 1) diff |= av[i] ^ bv[i]
  return diff === 0
}

function readConfig(env) {
  const positiveInt = (raw, fallback) => {
    const n = Number(raw)
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback
  }
  return {
    base: typeof env.VPIC_BASE === 'string' && env.VPIC_BASE ? env.VPIC_BASE.replace(/\/+$/, '') : VPIC_BASE_DEFAULT,
    timeoutMs: positiveInt(env.VPIC_TIMEOUT_MS, VPIC_TIMEOUT_MS_DEFAULT),
    maxAttempts: positiveInt(env.VPIC_MAX_ATTEMPTS, VPIC_MAX_ATTEMPTS_DEFAULT),
    cacheTtlS: positiveInt(env.CACHE_TTL_S, CACHE_TTL_S_DEFAULT),
    deadline: Date.now() + RUN_BUDGET_MS,
  }
}

/**
 * The vocabulary endpoint. Publishes exactly what the study measures and why, so the
 * assumption under test is auditable without reading the source — and so a reviewer can
 * check the map against fields.js before trusting any number the report produces.
 */
function vocabularyResponse() {
  return json({
    study_version: STUDY_VERSION,
    coverage_threshold: COVERAGE_THRESHOLD,
    min_sample_for_verdict: MIN_SAMPLE_FOR_VERDICT,
    vpic_batch_limit: VPIC_BATCH_LIMIT,
    honest_ceiling: CEILING_STATEMENT,
    value_states: VALUE_STATES,
    fields: FIELDS.map((f) => ({
      field_id: f,
      field_class: classOfField(f),
      expected_layer: expectedLayerOf(f),
      vpic_keys: VPIC_FIELD_MAP[f].keys,
      probes: VPIC_FIELD_MAP[f].probes ?? [],
      why_not_vin_derivable: VPIC_FIELD_MAP[f].whyNot ?? null,
    })),
  })
}

/** Validate the /decode body. Fails closed on anything unexpected. */
function parseDecodeBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, reason: 'body must be a JSON object' }
  }
  const allowed = new Set(['sample_id', 'provenance', 'vins', 'strict', 'refresh'])
  const unknown = Object.keys(body).filter((k) => !allowed.has(k))
  if (unknown.length > 0) return { ok: false, reason: `unknown field(s): ${unknown.join(', ')}` }

  const sampleId = body.sample_id
  if (typeof sampleId !== 'string' || sampleId.trim().length === 0 || sampleId.length > 128) {
    return { ok: false, reason: 'sample_id is required, non-empty, <= 128 chars' }
  }
  // Provenance is mandatory. A yield report whose sample origin is blank cannot be acted
  // on: the number would be uninterpretable and would still get cited.
  const provenance = body.provenance
  if (typeof provenance !== 'string' || provenance.trim().length < 16 || provenance.length > 2000) {
    return {
      ok: false,
      reason:
        'provenance is required (16-2000 chars): where these VINs came from and on what basis. ' +
        'A coverage rate over an unattributed sample is not a finding.',
    }
  }
  if (!Array.isArray(body.vins) || body.vins.length === 0) {
    return { ok: false, reason: 'vins must be a non-empty array' }
  }
  if (body.vins.length > MAX_VINS_PER_REQUEST) {
    return {
      ok: false,
      reason:
        `at most ${MAX_VINS_PER_REQUEST} VINs per request; a larger study is several runs ` +
        'sharing one sample_id, and GET /report aggregates by sample_id',
    }
  }
  if (body.strict !== undefined && typeof body.strict !== 'boolean') {
    return { ok: false, reason: 'strict must be a boolean' }
  }
  if (body.refresh !== undefined && typeof body.refresh !== 'boolean') {
    return { ok: false, reason: 'refresh must be a boolean' }
  }
  return {
    ok: true,
    value: {
      sampleId: sampleId.trim(),
      provenance: provenance.trim(),
      vins: body.vins,
      strict: body.strict !== false,
      refresh: body.refresh === true,
    },
  }
}

/**
 * Purge a whole sample.
 *
 * The study store holds VINs, so it needs an erasure path or it contradicts the §9.5
 * cadence it was written to respect. Cache rows are deleted BEFORE the observations that
 * identify which VINs belong to the sample — reverse that order and the cache rows become
 * unreachable orphans holding exactly the data the purge exists to remove.
 */
async function purgeSample(env, sampleId) {
  const statements = [
    env.DB.prepare(
      `DELETE FROM m0_vpic_cache WHERE vin IN (
         SELECT DISTINCT vin FROM m0_observation
         WHERE run_id IN (SELECT run_id FROM m0_run WHERE sample_id = ?1))`,
    ).bind(sampleId),
    env.DB.prepare(
      'DELETE FROM m0_observation WHERE run_id IN (SELECT run_id FROM m0_run WHERE sample_id = ?1)',
    ).bind(sampleId),
    env.DB.prepare(
      'DELETE FROM m0_probe WHERE run_id IN (SELECT run_id FROM m0_run WHERE sample_id = ?1)',
    ).bind(sampleId),
    env.DB.prepare(
      'DELETE FROM m0_vin_reject WHERE run_id IN (SELECT run_id FROM m0_run WHERE sample_id = ?1)',
    ).bind(sampleId),
    env.DB.prepare(
      'DELETE FROM m0_unreached WHERE run_id IN (SELECT run_id FROM m0_run WHERE sample_id = ?1)',
    ).bind(sampleId),
    env.DB.prepare('DELETE FROM m0_run WHERE sample_id = ?1').bind(sampleId),
  ]
  const results = await env.DB.batch(statements)
  return results.map((r) => r.meta?.changes ?? 0)
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const path = url.pathname.replace(/\/+$/, '') || '/'
    const method = request.method.toUpperCase()

    try {
      if (method === 'GET' && (path === '/' || path === '/health')) {
        return json({ study: STUDY_VERSION, ok: true, vpic_base: readConfig(env).base })
      }

      if (method === 'GET' && path === '/schema.sql') {
        return text(SCHEMA_SQL.trim(), 200, 'application/sql; charset=utf-8')
      }

      if (method === 'GET' && path === '/vocabulary') {
        return vocabularyResponse()
      }

      if (!env.DB) {
        return problem(500, 'D1 binding DB is not configured; see wrangler.toml')
      }

      if (method === 'POST' && path === '/decode') {
        if (!(await authorized(request, env))) return problem(401, 'bearer token required')

        let body
        try {
          body = await request.json()
        } catch {
          return problem(400, 'body must be valid JSON')
        }
        const parsed = parseDecodeBody(body)
        if (!parsed.ok) return problem(400, parsed.reason)

        await ensureSchema(env)
        const cfg = readConfig(env)
        const { runId, sampleId } = await executeRun(env, cfg, parsed.value)
        const report = await loadReport(env, { runId })
        return json({ run_id: runId, sample_id: sampleId, report })
      }

      if (method === 'GET' && path === '/report') {
        await ensureSchema(env)
        const runId = url.searchParams.get('run_id')
        const sampleId = url.searchParams.get('sample_id')
        const report = await loadReport(env, { runId, sampleId })
        if (!report) return problem(404, 'no matching run')
        return url.searchParams.get('format') === 'md'
          ? text(renderMarkdown(report), 200, 'text/markdown; charset=utf-8')
          : json(report)
      }

      if (method === 'DELETE' && path.startsWith('/sample/')) {
        if (!(await authorized(request, env))) return problem(401, 'bearer token required')
        const sampleId = decodeURIComponent(path.slice('/sample/'.length))
        if (!sampleId) return problem(400, 'sample id required')
        await ensureSchema(env)
        const changes = await purgeSample(env, sampleId)
        return json({ purged: sampleId, rows_deleted: changes })
      }

      return problem(404, `no route for ${method} ${path}`)
    } catch (err) {
      // Surface the failure rather than returning a plausible empty report. A study that
      // fails silently produces a document that reads like a clean pass.
      return problem(500, `M0 failure: ${err?.message ?? String(err)}`)
    }
  },
}
