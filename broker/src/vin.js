/**
 * VIN syntax validation and pseudonymisation.
 *
 * Nimbus Foundation NF-WP-1 §1.4 (identifier-not-credential), §8.2, §14 (M0).
 *
 * Everything here is about the VIN as a *name*. Nothing in this module authorises
 * anything, and nothing in this module accepts a credential. That is the doctrine's
 * enforcement point at the syntax layer: the only outputs are "is this a well-formed
 * name" and "what is the rotating pseudonym for this name".
 *
 * The 2015 Miller-Valasek Jeep compromise and Curry et al.'s 2023 "Web Hackers vs.
 * the Auto Industry" both turned on a VIN being treated as a credential — an
 * access-control failure, not a property of the VIN (NF-WP-1 §3.4). A VIN is public:
 * it is visible through a windshield, printed on insurance documents, and enumerable.
 * Code that treats it as a secret is wrong twice over.
 */

/** ISO 3779 excludes I, O and Q to avoid confusion with 1 and 0. */
const VIN_CHARSET = /^[A-HJ-NPR-Z0-9]{17}$/

/** ISO 3779 / 49 C.F.R. Part 565 transliteration. */
const TRANSLITERATION = Object.freeze({
  A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8,
  J: 1, K: 2, L: 3, M: 4, N: 5, P: 7, R: 9,
  S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9,
})

/** Positional weights; index 8 is the check digit itself and carries weight 0. */
const WEIGHTS = Object.freeze([8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2])

const CHECK_DIGIT_INDEX = 8

/**
 * Validate VIN syntax and, separately, the check digit.
 *
 * The two are reported separately on purpose. The check digit is mandatory for
 * vehicles manufactured for the North American market (49 C.F.R. § 565.15) but is not
 * universally required by ISO 3779, so grey-market and some non-NA vehicles carry
 * structurally valid VINs that fail it. Collapsing the two results into one boolean
 * would silently exclude those vehicles, and a consent broker that cannot enrol a
 * legally-registered vehicle because of a validation shortcut has a defect, not a
 * policy. The caller decides how strict to be; `strict` defaults to requiring the
 * check digit because Sybil-VIN resistance (NF-WP-1 §12.4) depends on it.
 *
 * @param {string} vin
 * @param {{ strict?: boolean }} [opts]
 * @returns {{ valid: boolean, syntaxValid: boolean, checkDigitValid: boolean|null,
 *            normalized: string|null, expectedCheckDigit: string|null, reason: string|null }}
 */
export function validateVin(vin, opts = {}) {
  const strict = opts.strict !== false

  if (typeof vin !== 'string') {
    return fail('VIN must be a string')
  }
  const normalized = vin.trim().toUpperCase()

  if (normalized.length !== 17) {
    return fail(`VIN must be exactly 17 characters, got ${normalized.length}`)
  }
  if (!VIN_CHARSET.test(normalized)) {
    return fail('VIN contains characters outside the ISO 3779 set (I, O and Q are excluded)')
  }

  const expected = computeCheckDigit(normalized)
  const checkDigitValid = normalized[CHECK_DIGIT_INDEX] === expected

  return {
    valid: strict ? checkDigitValid : true,
    syntaxValid: true,
    checkDigitValid,
    normalized,
    expectedCheckDigit: expected,
    reason: checkDigitValid
      ? null
      : `check digit mismatch: position 9 is '${normalized[CHECK_DIGIT_INDEX]}', expected '${expected}'`,
  }

  function fail(reason) {
    return {
      valid: false,
      syntaxValid: false,
      checkDigitValid: null,
      normalized: null,
      expectedCheckDigit: null,
      reason,
    }
  }
}

/**
 * ISO 3779 check digit: weighted sum of transliterated characters, mod 11, with 10
 * rendered as 'X'.
 */
export function computeCheckDigit(vin) {
  let sum = 0
  for (let i = 0; i < 17; i += 1) {
    const ch = vin[i]
    const value = ch >= '0' && ch <= '9' ? Number(ch) : TRANSLITERATION[ch]
    if (value === undefined) return null
    sum += value * WEIGHTS[i]
  }
  const remainder = sum % 11
  return remainder === 10 ? 'X' : String(remainder)
}

/** The World Manufacturer Identifier: first three characters. */
export function wmi(vin) {
  const v = validateVin(vin, { strict: false })
  return v.syntaxValid ? v.normalized.slice(0, 3) : null
}

/**
 * Domain separator and version tag for the pseudonym construction.
 *
 * Exported because consumers (NF-2 grants record the construction so a verifier can
 * recompute the pseudonym) would otherwise hard-code a copy of this string. Two
 * copies of one security constant drift the moment the construction is versioned,
 * and the failure is silent: pseudonyms simply stop matching, which reads as a data
 * problem rather than a version skew.
 */
export const PSEUDONYM_DERIVATION = 'nf2-pseudonym:v1'

/** Minimum salt entropy, in decoded bytes. */
export const MIN_SALT_BYTES = 32

/**
 * Derive the rotating, salted pseudonym that appears in a grant payload in place of
 * the VIN (NF-2).
 *
 * Three properties matter, and each is a response to a specific failure mode:
 *
 *  - *Salted*, because a VIN has perhaps 10^8 realistic entropy once make, model and
 *    year are known. A bare hash is a rainbow-table lookup, so an unsalted pseudonym
 *    would let anyone holding a VIN confirm enrolment and enumerate a fleet from a
 *    parking lot.
 *  - *Rotating* by epoch, because a stable pseudonym is a permanent correlation
 *    handle: two counterparties holding grants over the same vehicle could join their
 *    datasets on it, reconstructing a profile neither was granted. Rotation bounds
 *    linkability to one epoch (Sweeney; Narayanan-Shmatikov re-identification work,
 *    NF-WP-1 §12.7).
 *  - *Per-audience*, because rotation alone still lets two simultaneous counterparties
 *    join within an epoch. Binding the pseudonym to the counterparty class makes the
 *    join fail even inside a single epoch.
 *
 * The salt is owner-held and never leaves the broker's mutable, deletable store — it
 * is not derivable from anything committed on-chain. Destroying the salt destroys the
 * linkage, which is what makes Delete Act erasure real rather than nominal
 * (NF-WP-1 §9.5).
 *
 * @param {string} vin
 * @param {string} salt owner-held secret, >= 32 bytes of entropy, hex or base64url
 * @param {number} epoch monotonic rotation counter
 * @param {string} audience counterparty class the pseudonym is issued to
 * @returns {Promise<string>} base64url pseudonym, 32 bytes
 */
export async function vehiclePseudonym(vin, salt, epoch, audience) {
  const v = validateVin(vin, { strict: false })
  if (!v.syntaxValid) throw new Error(`cannot pseudonymise malformed VIN: ${v.reason}`)
  // Measured in DECODED BYTES, not characters. A 32-character hex string is 16 bytes
  // of entropy, not 32 — half the advertised strength, and against an enumerable VIN
  // space (the whole reason the salt exists) that difference is the security margin.
  // Requiring base64url specifically keeps the measurement unambiguous; a caller
  // holding hex must convert rather than have its entropy silently mis-measured.
  if (typeof salt !== 'string' || !/^[A-Za-z0-9_-]+$/.test(salt)) {
    throw new Error('pseudonym salt must be a base64url string; use generatePseudonymSalt()')
  }
  // The charset test above is necessary but not sufficient: a base64url string whose length
  // is 1 mod 4 encodes no whole byte and `atob` throws a DOMException on it. Letting that
  // escape would be fail-closed but undiagnosable — the caller gets "Invalid character" from
  // a validation path that knows perfectly well what is wrong with its input.
  let saltBytes
  try {
    saltBytes = base64urlToBytes(salt)
  } catch {
    throw new Error(
      'pseudonym salt must be a base64url string; use generatePseudonymSalt() ' +
        `(the ${salt.length}-character value supplied is not a whole number of bytes)`,
    )
  }
  if (saltBytes.length < MIN_SALT_BYTES) {
    throw new Error(
      `pseudonym salt must decode to at least ${MIN_SALT_BYTES} bytes; ` +
        'a short salt is brute-forceable against the enumerable VIN space',
    )
  }
  // SAFE integer, not merely integer. The epoch is copied verbatim into a grant's
  // `vehicle_pseudonym.epoch`, which lands inside the signed JCS bytes, and past 2^53 - 1
  // distinct integers canonicalise identically — so an unsafe epoch is a value whose
  // signature would authenticate a different value (jcs.js `assertSafeInteger`, which names
  // pseudonym epochs explicitly). Rejecting here keeps `vehiclePseudonym` from minting a
  // pseudonym for an epoch no conformant grant could ever carry.
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new Error('pseudonym epoch must be a non-negative safe integer (<= 2^53 - 1)')
  }
  if (typeof audience !== 'string' || audience.length === 0) {
    throw new Error('pseudonym audience is required; an unbound pseudonym is a correlation handle')
  }

  // HMAC rather than a plain hash: the salt is a key, and using it as a key rather
  // than a prefix removes length-extension and multi-target concerns outright.
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(salt),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const message = new TextEncoder().encode(
    `${PSEUDONYM_DERIVATION}:${v.normalized}:${epoch}:${audience}`,
  )
  const mac = await crypto.subtle.sign('HMAC', key, message)
  return base64url(new Uint8Array(mac))
}

/** Fresh 32-byte salt, base64url. Store in D1, never on a ledger. */
export function generatePseudonymSalt() {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

export function base64url(bytes) {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64urlToBytes(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}
