/**
 * NF-2 closed field vocabulary and the non-transactable classes.
 *
 * Nimbus Foundation NF-WP-1 §8.2, §9.5, §12.2.
 *
 * This module is the single source of truth for what a Consent Grant can and cannot
 * cover. Two properties are structural, not advisory:
 *
 *  1. The data-field vocabulary is CLOSED. A grant naming a field that is not in
 *     `FIELDS` is invalid — there is no "other" or free-text field. An open
 *     vocabulary would let purpose limitation be defeated by naming, which is the
 *     usual way consent regimes fail in practice.
 *
 *  2. The forbidden classes have NO GRANT TYPE AT ALL. Precise geolocation,
 *     biometric identifiers, and in-cabin audio/video are not fields with a "deny"
 *     flag — they are absent from the vocabulary, and `NON_TRANSACTABLE` exists only
 *     so the conformance suite can assert their absence. A design constraint beats a
 *     policy statement: it cannot be waived by a pressured or unsophisticated owner,
 *     by a persuasive counterparty, or by an operator under commercial pressure,
 *     because there is no encoding for the waiver. This aligns with the CCPA's
 *     sensitive-personal-information category (Civ. Code § 1798.140(ae)).
 *
 * V1 conservatism, flagged deliberately: NF-2 forbids *precise* geolocation, and the
 * CCPA's definition turns on a ~1,850-foot radius. V1 admits no positional field at
 * any precision. A coarse-position class is defensible in principle — a geohash-5
 * cell is ~4.9 km, far outside the statutory radius — but it needs a documented
 * precision floor, a re-identification analysis (Sweeney; Narayanan-Shmatikov), and
 * CPPA-aligned counsel review before it earns a field id. Until then the honest
 * position is that we do not ship it. Non-positional motion data (speed, acceleration
 * events) is not geolocation and is admitted.
 */

/** DPPA permissible-use categories, 18 U.S.C. § 2721(b). A grant's purpose MUST cite one. */
export const DPPA_PURPOSES = Object.freeze({
  'dppa-2721b-2': Object.freeze({
    cite: '18 U.S.C. § 2721(b)(2)',
    label: 'Motor vehicle or driver safety, theft, emissions, recalls, performance monitoring, parts and dealers',
  }),
  'dppa-2721b-3': Object.freeze({
    cite: '18 U.S.C. § 2721(b)(3)',
    label: 'Legitimate business need to verify accuracy of information or prevent fraud',
  }),
  'dppa-2721b-5': Object.freeze({
    cite: '18 U.S.C. § 2721(b)(5)',
    label: 'Research activities and statistical reports, personal information not published or redisclosed',
  }),
  'dppa-2721b-6': Object.freeze({
    cite: '18 U.S.C. § 2721(b)(6)',
    label: 'Insurance: claims investigation, antifraud, rating, underwriting',
  }),
  'dppa-2721b-11': Object.freeze({
    cite: '18 U.S.C. § 2721(b)(11)',
    label: 'Express consent of the individual to whom the information pertains',
  }),
  'dppa-2721b-13': Object.freeze({
    cite: '18 U.S.C. § 2721(b)(13)',
    label: 'Use for which the requester has demonstrated written consent of the individual',
  }),
})

/**
 * Counterparty classes. A grant names the class it is issued to, and the broker
 * refuses to serve a requester outside it. Class, not identity, so that a grant does
 * not have to be reissued when an insurer changes corporate form — and so that the
 * owner's decision is about *kinds* of counterparty, which is the decision they are
 * actually equipped to make.
 *
 * `insurer` is admitted in the schema but is not the California entry wedge:
 * Proposition 103 and 10 C.C.R. § 2632.5 mandate rating-factor order and constrain
 * usage-based insurance more tightly than most states (NF-WP-1 §9.9). Lead with
 * fleet, repair, municipal, and research demand.
 */
export const COUNTERPARTY_CLASSES = Object.freeze([
  'repair-independent',
  'repair-franchised',
  'dealer-licensed-ca',
  'fleet-operator',
  'municipal-agency',
  'academic-research',
  'insurer',
  'oem-warranty',
])

/**
 * Field classes and their fields. `layer` records where the data actually comes
 * from, which is the honest ceiling of NF-WP-1 §3.3 made machine-readable:
 *
 *   'vpic'    — derivable from the VIN alone via NHTSA vPIC (49 C.F.R. Part 565).
 *   'layer2'  — requires OEM-authenticated access or a diagnostic interface. NOT
 *               VIN-derivable. M0 must confirm per field; anything assumed here and
 *               contradicted by M0 is a negative finding, not a rounding error.
 *   'operator'— supplied by a bonded participant (e.g. a dealer's service records).
 */
export const FIELD_CLASSES = Object.freeze({
  build_specification: Object.freeze({
    layer: 'vpic',
    label: 'Build and specification data',
    fields: Object.freeze([
      'make',
      'model',
      'model_year',
      'body_class',
      'vehicle_type',
      'drive_type',
      'engine_configuration',
      'engine_displacement_l',
      'fuel_type_primary',
      'gvwr_class',
      'plant_country',
      'plant_company_name',
      'series',
      'trim',
    ]),
  }),
  diagnostics: Object.freeze({
    layer: 'layer2',
    label: 'Diagnostic trouble codes and readiness',
    fields: Object.freeze([
      'dtc_codes',
      'dtc_first_seen_at',
      'mil_status',
      'freeze_frame',
      'readiness_monitors',
      'obd_protocol',
    ]),
  }),
  battery_health: Object.freeze({
    layer: 'layer2',
    label: 'Traction battery state and health',
    fields: Object.freeze([
      'state_of_charge_pct',
      'state_of_health_pct',
      'pack_temperature_c',
      'charge_cycle_count',
      'charge_rate_kw',
      'usable_capacity_kwh',
    ]),
  }),
  motion_aggregate: Object.freeze({
    layer: 'layer2',
    label: 'Non-positional motion aggregates',
    fields: Object.freeze([
      'speed_mean_kph',
      'speed_p95_kph',
      'harsh_brake_count',
      'harsh_accel_count',
      'harsh_corner_count',
      'aggregation_window_s',
    ]),
  }),
  usage: Object.freeze({
    layer: 'layer2',
    label: 'Cumulative usage',
    fields: Object.freeze([
      'odometer_km',
      'engine_hours',
      'service_due_km',
      'annual_mileage_estimate_km',
    ]),
  }),
  service_history: Object.freeze({
    layer: 'operator',
    label: 'Service and repair history',
    fields: Object.freeze([
      'service_events',
      'repair_order_summaries',
      'recall_completion_status',
      'last_service_at',
    ]),
  }),
})

/** Flat set of every grantable field id. */
export const FIELDS = Object.freeze(
  Object.values(FIELD_CLASSES).flatMap((c) => c.fields),
)

/**
 * Classes with no grant type, ever. Present here so NF-5 can assert their absence
 * from FIELDS; nothing in the protocol consumes this list to *permit* anything.
 *
 * `raw_vin` is included for a distinct reason: the VIN is the index, and it never
 * appears in a grant payload. NF-2 requires a salted, rotating pseudonym. The Delete
 * Act's broker disclosures expressly enumerate vehicle identification numbers as a
 * category of personal information collected (NF-WP-1 §9.5), so a VIN in a payload
 * is not merely untidy — it drags the payload into the regime.
 */
export const NON_TRANSACTABLE = Object.freeze([
  'precise_geolocation',
  'coarse_geolocation',
  'gps_trace',
  'latitude',
  'longitude',
  'geohash',
  'biometric_identifier',
  'driver_face_template',
  'fingerprint',
  'voiceprint',
  'in_cabin_audio',
  'in_cabin_video',
  'driver_monitoring_video',
  'raw_vin',
  'owner_name',
  'owner_address',
  'owner_phone',
  'owner_email',
])

const FIELD_SET = new Set(FIELDS)
const NON_TRANSACTABLE_SET = new Set(NON_TRANSACTABLE)

/** True if `field` is in the closed vocabulary. */
export function isGrantableField(field) {
  return FIELD_SET.has(field)
}

/** True if `field` names a forbidden class. Used by NF-5 and by defensive checks. */
export function isNonTransactable(field) {
  return NON_TRANSACTABLE_SET.has(field)
}

/**
 * Validate a requested field set. Returns `{ ok, rejected, reason }`.
 *
 * Fails closed: an unknown field is rejected, never ignored. Rejecting the whole
 * grant rather than silently narrowing it matters because a grant that quietly
 * covers less than the owner read is a consent defect, not a convenience.
 */
export function validateFieldSet(fields) {
  if (!Array.isArray(fields) || fields.length === 0) {
    return { ok: false, rejected: [], reason: 'field set must be a non-empty array' }
  }
  const seen = new Set()
  const rejected = []
  for (const f of fields) {
    if (typeof f !== 'string') {
      return { ok: false, rejected: [String(f)], reason: 'field ids must be strings' }
    }
    if (seen.has(f)) {
      return { ok: false, rejected: [f], reason: `duplicate field ${f}` }
    }
    seen.add(f)
    if (NON_TRANSACTABLE_SET.has(f)) {
      rejected.push(f)
      continue
    }
    if (!FIELD_SET.has(f)) rejected.push(f)
  }
  if (rejected.length > 0) {
    const forbidden = rejected.filter((f) => NON_TRANSACTABLE_SET.has(f))
    return {
      ok: false,
      rejected,
      reason:
        forbidden.length > 0
          ? `non-transactable field class has no grant type: ${forbidden.join(', ')}`
          : `field not in the NF-2 closed vocabulary: ${rejected.join(', ')}`,
    }
  }
  return { ok: true, rejected: [], reason: null }
}

/** The field class a field belongs to, or null. */
export function classOfField(field) {
  for (const [name, spec] of Object.entries(FIELD_CLASSES)) {
    if (spec.fields.includes(field)) return name
  }
  return null
}

/**
 * Which layer each requested field needs. A grant covering only `vpic` fields can be
 * served from the M0 cache; anything else needs Layer-2 authenticated access, and
 * saying so up front is what keeps the honest ceiling honest at request time rather
 * than at delivery time.
 */
export function layersRequired(fields) {
  const layers = new Set()
  for (const f of fields) {
    const cls = classOfField(f)
    if (cls) layers.add(FIELD_CLASSES[cls].layer)
  }
  return [...layers].sort()
}

export function isValidPurpose(purpose) {
  return Object.hasOwn(DPPA_PURPOSES, purpose)
}

export function isValidCounterpartyClass(cls) {
  return COUNTERPARTY_CLASSES.includes(cls)
}
