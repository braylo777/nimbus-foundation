/**
 * NF-4 Revocation Semantics: how an owner takes authority back.
 *
 * Nimbus Foundation NF-WP-1 §8.4 (revocation propagation, cascade, staleness bound),
 * §9.5 (Delete Act cadence, mutable storage), §10.1 (the three refusals), §14 (stack).
 *
 * A Consent Grant is only a *revocable* capability if revocation is real, and revocation
 * is only real if three separate things hold at once:
 *
 *  1. AUTHORITY. Exactly one party can revoke — the owner, via the key named in the
 *     grant's `revocation_key_id`. Not the broker, not the Foundation, not the holder.
 *  2. REACH. Revoking a grant reaches every capability derived from it. Delegation makes
 *     a tree; a lever that only cuts the root of the tree while the leaves keep reading
 *     is theatre.
 *  3. TIMELINESS. A cached "allowed" decision is an authorisation that outlives the state
 *     it was derived from. Without an explicit bound on its age, a cache silently converts
 *     a revocable grant into an irrevocable one, and no amount of correctness in (1) and
 *     (2) survives that. §8.4 names the bound for exactly this reason.
 *
 * The three refusals, as structure rather than commentary:
 *
 *  - Refusal 1 (a VIN is never a credential). Nothing here accepts, stores or derives a
 *    VIN. Revocation targets are grant commitments and revocation-key thumbprints — both
 *    opaque 32-byte digests. The kill switch, which is conceptually "this vehicle", is
 *    realised as "everything under this owner-held revocation key", so a vehicle is
 *    revoked without ever being named.
 *  - Refusal 2 (no PI on an immutable ledger). The only artefact that crosses onto a
 *    ledger is `buildAnchor` output: a version tag, a root, an epoch and a publication
 *    time. `assertAnchorCarriesNoPayload` is the executable form of that promise. What is
 *    and is not derivable from the root is enumerated at `revocationStateRoot`.
 *  - Refusal 3 (the Foundation does not operate what it governs). `applyRevocation` has
 *    NO policy parameter. There is no allow-list, deny-list, approval hook, reason the
 *    operator may supply, or return path by which a structurally valid, correctly signed
 *    revocation is declined. That omission is the enforcement mechanism; see the note on
 *    "both directions" below.
 *
 * WHERE THE STATE LIVES. Entries are D1 rows — mutable and deletable, because a standing
 * 45-day Delete Act cadence and CCPA erasure cannot be reconciled with immutability
 * (§9.5). The sparse Merkle tree over those rows is a *derived index*: it is
 * order-independent, so it can always be recomputed from the rows, and it is never on the
 * authorisation path. Authorisation reads two indexed rows (see `isRevoked`); roots and
 * proofs are batch work. Sketch of the durable shape, prepared statements only:
 *
 *   CREATE TABLE nf4_revocation (
 *     leaf_key        TEXT PRIMARY KEY,   -- base64url, 32 bytes
 *     kind            TEXT NOT NULL,      -- 'grant' | 'vehicle'
 *     target          TEXT NOT NULL,      -- grant commitment | revocation_key_id
 *     effective_from  INTEGER,            -- vehicle scope only, else NULL
 *     revoked_at      INTEGER NOT NULL,
 *     cause           TEXT NOT NULL,
 *     cascaded_from   TEXT,
 *     record_digest   TEXT NOT NULL,
 *     grant_id        TEXT                -- operational only, NOT committed
 *   );
 *   CREATE INDEX nf4_revocation_vehicle ON nf4_revocation (target, effective_from);
 *
 * WHAT THIS MODULE DOES NOT DO. It does not un-revoke. There is no such function and
 * there must never be one: an operator who can remove an entry can resurrect authority
 * the owner withdrew, which is strictly worse than never having had revocation, because
 * the owner believes they are protected. Revocation is monotone. `assertRevocationMonotone`
 * makes that checkable across any state transition, including erasure.
 */

import {
  MAX_DELEGATION_DEPTH,
  MAX_PLAUSIBLE_TIME_S,
  MIN_PLAUSIBLE_TIME_S,
  deriveGrantCommitment,
  importPublicKeyBase64url,
  revocationKeyIdFromPublicKey,
} from './nf2-grant.js'
import { base64url, base64urlToBytes } from './vin.js'
import { assertSafeInteger, canonicalize, canonicalizeToBytes } from './jcs.js'

// ---------------------------------------------------------------------------------
// Versions and closed vocabularies
// ---------------------------------------------------------------------------------

/**
 * Every artefact this module produces is versioned, and the version is inside the bytes
 * that get signed or hashed. Revocation semantics are the part of the protocol most
 * likely to change, and "was this record written under the old or the new cascade rule"
 * has to be answerable from the record alone.
 */
export const NF4_RECORD_VERSION = 'nf4-revocation/1'
export const NF4_WITNESS_VERSION = 'nf4-witness/1'
export const NF4_PROOF_VERSION = 'nf4-proof/1'
export const NF4_DECISION_VERSION = 'nf4-decision/1'
export const NF4_ANCHOR_VERSION = 'nf4-anchor/1'
export const NF4_STATE_VERSION = 'nf4-state/1'

/**
 * The two revocation scopes.
 *
 * 'grant'   — one grant, identified by its NF-2 commitment. Cascades to descendants.
 * 'vehicle' — the kill switch: everything under one owner-held revocation key, issued at
 *             or before `effective_from`. See `revokeVehicle` for why the target is a key
 *             thumbprint and not a vehicle identifier of any kind.
 */
export const REVOCATION_SCOPES = Object.freeze(['grant', 'vehicle'])

/**
 * Reason codes are a CLOSED vocabulary, and that is a privacy control, not tidiness.
 *
 * A revocation witness is disclosed inside an inclusion proof, so anything an owner can
 * type into a reason field is a channel for personal information to escape D1 and reach a
 * third party — and its digest reaches the ledger. "Sold to <name>, moved to <address>"
 * is exactly what a free-text field collects from a person explaining themselves. There
 * is no free-text reason, so there is nothing to leak. Same argument as the closed field
 * vocabulary in fields.js: a design constraint cannot be waived under pressure.
 */
export const REVOCATION_REASONS = Object.freeze([
  'owner_withdrew',
  'vehicle_transferred',
  'revocation_key_rotated',
  'counterparty_breach',
  'purpose_complete',
  'unspecified',
])

/**
 * Closed key set for a revocation record. Every key present on every record, explicit
 * `null` where a scope does not use it — never omitted.
 *
 * Same reasoning as GRANT_KEYS in nf2-grant.js, and it bites harder here: absence and
 * explicit null canonicalise to different bytes, so a record that allowed both forms would
 * have two digests, and the accumulator is keyed by digest-derived values. One semantic
 * revocation must have exactly one commitment or the second form evades the entry.
 */
export const REVOCATION_KEYS = Object.freeze([
  'v',
  'scope',
  'target',
  'revocation_key',
  'issued_at',
  'effective_from',
  'reason',
  'signature',
])

/** Closed key set for the committed witness. Disclosed in proofs — keep it minimal. */
export const WITNESS_KEYS = Object.freeze([
  'v',
  'cause',
  'revoked_at',
  'cascaded_from',
  'record_digest',
])

/** Closed key set for a cached authorisation decision. */
export const DECISION_KEYS = Object.freeze([
  'v',
  'grant_commitment',
  'presenter_key',
  'decision',
  'cause',
  'derived_at',
  'state_root',
])

/**
 * Closed key set for the on-chain anchor. Four fields, none of them derived from a
 * payload. Notably ABSENT: any count, size, or per-vehicle field. An entry count would
 * publish the owner population's revocation volume, which is behavioural data about
 * people even though it names none of them.
 */
export const ANCHOR_KEYS = Object.freeze(['v', 'root', 'epoch', 'published_at'])

const REVOCATION_KEY_SET = new Set(REVOCATION_KEYS)
const WITNESS_KEY_SET = new Set(WITNESS_KEYS)
const DECISION_KEY_SET = new Set(DECISION_KEYS)
const ANCHOR_KEY_SET = new Set(ANCHOR_KEYS)
const REASON_SET = new Set(REVOCATION_REASONS)
const SCOPE_SET = new Set(REVOCATION_SCOPES)

const DIGEST_BYTES = 32
const ED25519_PUBLIC_KEY_BYTES = 32
const ED25519_SIGNATURE_BYTES = 64
const GRANT_ID_BYTES = 16

// ---------------------------------------------------------------------------------
// Domain separation
// ---------------------------------------------------------------------------------
/**
 * Every SHA-256 in this file is domain-separated. The system already hashes grants
 * (`nf2-grant-commitment:v1:`) and revocation public keys (`nf2-revocation-key-id:v1:`),
 * and a digest that could be produced by two different constructions is a digest that can
 * be replayed from one context into another — a grant commitment accepted as a leaf key,
 * a leaf hash accepted as an internal node. Distinct prefixes make each construction
 * unforgeable as any other.
 */
const RECORD_DIGEST_DOMAIN = 'nf4-record-digest:v1:'
const WITNESS_DIGEST_DOMAIN = 'nf4-witness-digest:v1:'
const LEAF_KEY_GRANT_DOMAIN = 'nf4-leaf-grant:v1:'
const LEAF_KEY_VEHICLE_DOMAIN = 'nf4-leaf-vehicle:v1:'
const SMT_LEAF_DOMAIN = 'nf4-smt-leaf:v1:'
const SMT_NODE_DOMAIN = 'nf4-smt-node:v1:'
const SMT_EMPTY_LEAF_DOMAIN = 'nf4-smt-empty:v1:'

/**
 * Sparse Merkle tree depth: 256 bits, the full SHA-256 output.
 *
 * Truncating the keyspace would shorten proofs and speed up insertion, and it is exactly
 * the wrong trade here. A leaf-key collision means two grants share a position, so one
 * grant's revocation proof would verify against the other — and with witness-bearing leaf
 * values, a collision breaks previously issued proofs rather than merely being untidy.
 * 256 bits makes the collision term negligible at any population size, and the cost is
 * paid in a batch job that is never on the authorisation path.
 */
export const SMT_DEPTH = 256

// ---------------------------------------------------------------------------------
// The staleness bound (§8.4)
// ---------------------------------------------------------------------------------

/**
 * Default maximum age of a cached "allowed" decision: 60 seconds.
 *
 * The bound is not a performance knob. It is the width of the window in which a revoked
 * grant is still honoured, so it is the number an owner is actually being promised when
 * the system says revocation is effective. Sixty seconds is defended on both sides:
 *
 *  - Short enough that "effective immediately" remains a truthful description to a person
 *    who just pressed revoke. A minute is inside the span of a single interaction; an hour
 *    is not, and a day would mean the revocation lever does nothing an owner can perceive.
 *  - Long enough to matter operationally. It bounds the revocation read to once per minute
 *    per active (grant, counterparty) pair rather than once per request, which is the
 *    difference that makes a caller willing to obey the bound instead of routing around
 *    it. A bound that is ignored protects nobody.
 *
 * Note what the bound is NOT doing: it is not the primary propagation mechanism. A cache
 * that can see the current state root is invalidated the instant the root changes
 * (`evaluateCachedDecision` requires the root to match), which is immediate. The age bound
 * is the backstop for a cache that cannot see the root — a partitioned edge, a stale
 * replica — and that is precisely the case where an unbounded cache is unbounded harm.
 */
export const DEFAULT_MAX_DECISION_AGE_S = 60

/**
 * Hard ceiling on any configured staleness bound: 300 seconds.
 *
 * The bound itself has to be bounded, or the first operator under load configures the
 * cache into a de-facto irrevocable grant and the revocable-capability design becomes a
 * claim in a document. `assertDecisionAgeBound` refuses anything above this, so the
 * ceiling cannot be waived by configuration — the same design-constraint-beats-policy move
 * the non-transactable field classes use (§8.2, §12.2).
 *
 * Five minutes is the largest window over which "your revocation has taken effect" is
 * still an honest statement, and it is far below the shortest useful grant lifetime, so
 * the cache bound never becomes the operative bound on a grant.
 */
export const MAX_PERMITTED_DECISION_AGE_S = 300

/**
 * Refuse an out-of-range staleness bound. Throws rather than clamping: a caller who asked
 * for a day and silently got five minutes has a different security posture than the one
 * they wrote down, and will discover the difference during an incident.
 */
export function assertDecisionAgeBound(maxAgeS) {
  assertSafeInteger(maxAgeS, 'maxAgeS')
  if (maxAgeS < 0) throw new Error('staleness bound cannot be negative')
  if (maxAgeS > MAX_PERMITTED_DECISION_AGE_S) {
    throw new Error(
      `staleness bound ${maxAgeS}s exceeds the hard ceiling of ${MAX_PERMITTED_DECISION_AGE_S}s. ` +
        'A cached authorisation older than the ceiling is an unrevokable grant; the ceiling ' +
        'is not configurable because that is the only thing that makes it a bound',
    )
  }
  return maxAgeS
}

// ---------------------------------------------------------------------------------
// Revocation records: construction, signing, verification
// ---------------------------------------------------------------------------------

/**
 * Build an unsigned revocation record.
 *
 * The record is SELF-AUTHENTICATING by design: it carries the raw revocation public key,
 * so any party can hash it, compare the thumbprint to the `revocation_key_id` inside the
 * grant, and verify the signature — with no out-of-band key lookup and no trust in the
 * broker. That is the opposite choice from the grant itself, where the signer's key is
 * deliberately absent to prevent cross-counterparty joins (nf2-grant.js schema note), and
 * the asymmetry is deliberate:
 *
 *  - A grant is *presented* by a counterparty to obtain access, so the verifying key can
 *    be resolved by a party already entitled to make the lookup.
 *  - A revocation must be verifiable by anyone the owner shows it to, including a party
 *    with no relationship to the broker, precisely because the broker is the party whose
 *    refusal it defends against. A revocation that needs the broker to interpret it gives
 *    the broker a veto.
 *
 * The linkage cost is real and bounded: `revocation_key_id` is already in every grant, so
 * two counterparties over the same vehicle can already join on it. Under the recommended
 * key management — one revocation keypair per (vehicle, counterparty class), matching the
 * pseudonym's audience granularity exactly — that join reveals nothing the shared
 * `vehicle_pseudonym` does not already reveal, because same-class counterparties share a
 * pseudonym too (vin.js binds the audience to the class, not to an identity). Under a
 * single per-vehicle revocation key it reveals strictly more: cross-class counterparties
 * become linkable. Use per-class keys; the kill switch is built to make that painless.
 *
 * @param {object} params
 * @param {'grant'|'vehicle'} params.scope
 * @param {string} params.target             grant commitment (grant scope) or the
 *                                           revocation-key thumbprint (vehicle scope)
 * @param {string} params.revocationPublicKey raw Ed25519 public key, base64url
 * @param {number} params.issuedAt           Unix seconds
 * @param {number|null} [params.effectiveFrom] vehicle scope only; null on grant scope
 * @param {string} params.reason             REVOCATION_REASONS member
 * @returns {object} unsigned record (`signature: null`)
 */
export function buildRevocation(params) {
  const p = requireParams(params, [
    'scope',
    'target',
    'revocationPublicKey',
    'issuedAt',
    'effectiveFrom',
    'reason',
  ])

  const issuedAt = assertSafeInteger(p.issuedAt, 'issuedAt')
  let effectiveFrom = p.effectiveFrom ?? null

  if (p.scope === 'grant') {
    if (effectiveFrom !== null) {
      throw new Error(
        'effectiveFrom is meaningless on a grant-scope revocation: the target is one ' +
          'specific grant, not a time window. Pass null',
      )
    }
  } else if (p.scope === 'vehicle') {
    effectiveFrom = assertSafeInteger(effectiveFrom ?? issuedAt, 'effectiveFrom')
    if (effectiveFrom > issuedAt) {
      // A future effective_from is a standing self-destruct: it would kill grants the
      // owner has not yet decided to issue, so a kill switch could never be followed by
      // re-consent under the same key. Retroactive is fine and sometimes necessary
      // (backdating to the moment a key was known compromised); prospective is not.
      throw new Error(
        `effectiveFrom ${effectiveFrom} is after issued_at ${issuedAt}: a kill switch cannot ` +
          'pre-revoke grants that do not exist yet, or the owner could never re-consent',
      )
    }
  } else {
    throw new Error(`unknown revocation scope "${String(p.scope)}"; one of ${REVOCATION_SCOPES.join(', ')}`)
  }

  const record = {
    v: NF4_RECORD_VERSION,
    scope: p.scope,
    target: p.target,
    revocation_key: p.revocationPublicKey,
    issued_at: issuedAt,
    effective_from: effectiveFrom,
    reason: p.reason,
    signature: null,
  }

  const reasons = recordShapeReasons(record)
  if (reasons.length > 0) {
    throw new Error(`refusing to build an invalid revocation record: ${reasons.join('; ')}`)
  }
  return record
}

/**
 * The exact bytes a revocation signature covers: the record with `signature` removed,
 * canonicalised per RFC 8785 and UTF-8 encoded.
 *
 * No external domain tag, for the same reason nf2-grant.js omits one: the type binding is
 * already inside the signed bytes as `v`, so these bytes cannot be reinterpreted as
 * another kind of object, and a version bump changes every signature. A second tag outside
 * the canonical bytes would be a second thing that has to agree with the first.
 */
export function revocationSigningInput(record) {
  const reasons = recordShapeReasons(record)
  if (reasons.length > 0) {
    throw new Error(`refusing to compute a signing input for an invalid record: ${reasons.join('; ')}`)
  }
  const unsigned = {}
  for (const key of REVOCATION_KEYS) {
    if (key === 'signature') continue
    unsigned[key] = record[key]
  }
  return canonicalizeToBytes(unsigned)
}

/**
 * Sign a revocation record with the owner-held revocation private key. Returns a NEW
 * object; the input is not mutated.
 *
 * The algorithm is taken from the CryptoKey rather than probed again, because nf2-grant.js
 * already owns the Ed25519 name resolution (`Ed25519` vs the legacy Workers
 * `NODE-ED25519`) and two copies of that decision would drift. See the report note: that
 * module should export its resolver.
 *
 * Before returning, the signature is verified against the record's own `revocation_key`.
 * That self-check is not paranoia about WebCrypto — it catches the two mistakes that
 * otherwise ship silently: signing with a key that is not the one named in the record
 * (producing a revocation nobody will honour, which the owner discovers only when they
 * need it), and signing with a non-Ed25519 key (producing bytes no verifier in this system
 * can ever check).
 */
export async function signRevocation(record, privateKey) {
  if (!isPlainObject(record)) throw new Error('record must be a plain object')
  if (record.signature !== null) {
    throw new Error('record is already signed; build a new record rather than re-signing this one')
  }
  if (!privateKey || privateKey.type !== 'private') {
    throw new Error('signRevocation requires an Ed25519 private CryptoKey')
  }
  const algName = privateKey.algorithm?.name
  if (typeof algName !== 'string') throw new Error('signing key has no algorithm name')

  const input = revocationSigningInput(record)
  const sig = await crypto.subtle.sign({ name: algName }, privateKey, input)
  const signature = base64url(new Uint8Array(sig))
  const signed = { ...record, signature }

  // `now: record.issued_at` neutralises the future-dated check on purpose. The self-check is
  // about key binding and algorithm, not wall-clock agreement: an owner signing offline, or
  // backdating `effective_from` to when a key was known compromised, is legitimate, and the
  // freshness judgement belongs to the party APPLYING the record — it has its own clock and
  // its own skew tolerance, and it is the one exposed to a replayed stale record.
  const check = await verifyRevocation(signed, { now: record.issued_at })
  if (!check.valid) {
    throw new Error(
      `refusing to return a revocation that does not verify against its own revocation_key ` +
        `(${check.reasons.join('; ')}). A revocation the owner cannot prove is not a revocation`,
    )
  }
  return signed
}

/**
 * Verify a revocation record. Structured verdict, all reasons collected, never throws — a
 * verifier that throws on malformed input hands any caller a denial of service, and here
 * that denial would be *against a revocation*, which is the worst direction to fail in.
 *
 * There is deliberately NO policy parameter. No operator allow-list, no forbidden-key
 * list, no approval callback. Refusal 3 is enforced at issuance: nf2-grant's `verifyGrant`
 * already rejects a grant whose `revocation_key_id` is operator-held, so a key that should
 * not hold revocation authority never gets into a grant in the first place. Adding a
 * second, apply-time list here would hand the broker a veto over the owner — it could
 * declare the owner's own key "forbidden" and every valid revocation would be refused by
 * the same code path that was supposed to prevent operator capture.
 *
 * @param {object} record
 * @param {object} [opts]
 * @param {number} [opts.now] Unix seconds, for the future-dated check
 * @param {number} [opts.clockSkewS=300]
 * @returns {Promise<{ valid: boolean, reasons: string[] }>}
 */
export async function verifyRevocation(record, opts = {}) {
  const reasons = []
  try {
    reasons.push(...recordShapeReasons(record))
    if (reasons.length > 0) return { valid: false, reasons }

    if (record.signature === null) {
      reasons.push('signature_missing: revocation record is unsigned')
      return { valid: false, reasons }
    }

    const now = opts.now ?? Math.floor(Date.now() / 1000)
    const skew = opts.clockSkewS ?? 300
    if (Number.isSafeInteger(now) && record.issued_at > now + skew) {
      reasons.push(`issued_in_future: issued_at ${record.issued_at} exceeds now ${now} + ${skew}s skew`)
    }

    // Vehicle scope is self-authorising: the target IS the thumbprint of the key that
    // signed it, so the record proves its own scope with no external input. Grant scope
    // cannot be checked here — the authorisation is a property of the *grant* (its
    // revocation_key_id), and that check lives in `applyRevocation`.
    let publicKey
    try {
      publicKey = await importPublicKeyBase64url(record.revocation_key)
    } catch (err) {
      reasons.push(`revocation_key_unusable: ${err?.message ?? String(err)}`)
      return { valid: false, reasons }
    }
    if (record.scope === 'vehicle') {
      const thumbprint = await revocationKeyIdFromPublicKey(base64urlToBytes(record.revocation_key))
      if (thumbprint !== record.target) {
        reasons.push(
          'vehicle_scope_target_mismatch: a vehicle-scope target must be the thumbprint of the ' +
            'signing revocation key, so the record proves its own scope without the broker',
        )
      }
    }

    let ok = false
    try {
      ok = await crypto.subtle.verify(
        { name: publicKey.algorithm.name },
        publicKey,
        base64urlToBytes(record.signature),
        revocationSigningInput(record),
      )
    } catch (err) {
      reasons.push(`signature_invalid: verification failed (${err?.message ?? String(err)})`)
      return { valid: false, reasons }
    }
    if (!ok) {
      reasons.push('signature_invalid: Ed25519 signature does not verify over the canonical record')
    }
  } catch (err) {
    reasons.push(`internal: verification aborted (${err?.message ?? String(err)})`)
  }
  return { valid: reasons.length === 0, reasons }
}

/**
 * Digest of a signed revocation record, domain-separated. Covers the signature, because
 * the signature is what binds the record to an issuer — same argument as
 * `deriveGrantCommitment` in nf2-grant.js.
 */
export async function revocationRecordDigest(record) {
  const reasons = recordShapeReasons(record)
  if (reasons.length > 0) {
    throw new Error(`refusing to digest an invalid record: ${reasons.join('; ')}`)
  }
  if (record.signature === null) {
    throw new Error('refusing to digest an unsigned record: the digest must bind the issuer')
  }
  return base64url(await sha256(encode(RECORD_DIGEST_DOMAIN + canonicalize(record))))
}

/** Shape, vocabulary and range checks. Pure and synchronous. */
function recordShapeReasons(record) {
  const reasons = []
  if (!isPlainObject(record)) return ['shape: revocation record must be a plain object']

  for (const key of Object.keys(record)) {
    if (!REVOCATION_KEY_SET.has(key)) {
      reasons.push(`unknown_field: "${key}" is not part of ${NF4_RECORD_VERSION}`)
    }
  }
  for (const key of REVOCATION_KEYS) {
    if (!Object.hasOwn(record, key)) {
      reasons.push(`missing_field: "${key}" (optional fields are present as null, never omitted)`)
    }
  }
  if (reasons.length > 0) return reasons

  if (record.v !== NF4_RECORD_VERSION) {
    reasons.push(`version_unsupported: "${String(record.v)}", expected "${NF4_RECORD_VERSION}"`)
  }
  if (!SCOPE_SET.has(record.scope)) {
    reasons.push(`scope_unknown: "${String(record.scope)}" (${REVOCATION_SCOPES.join(', ')})`)
  }
  if (!isBase64urlBytes(record.target, DIGEST_BYTES)) {
    reasons.push(`target_malformed: expected a ${DIGEST_BYTES}-byte digest, base64url`)
  }
  if (!isBase64urlBytes(record.revocation_key, ED25519_PUBLIC_KEY_BYTES)) {
    reasons.push(
      `revocation_key_malformed: expected a raw ${ED25519_PUBLIC_KEY_BYTES}-byte Ed25519 public key, base64url`,
    )
  }
  if (!REASON_SET.has(record.reason)) {
    reasons.push(
      `reason_unknown: "${String(record.reason)}" is not in the closed vocabulary ` +
        `(${REVOCATION_REASONS.join(', ')}); there is no free-text reason because a disclosed ` +
        'witness must not be able to carry personal information',
    )
  }
  if (!isPlausibleTime(record.issued_at)) {
    reasons.push(
      `issued_at_implausible: must be an integer number of Unix SECONDS in ` +
        `[${MIN_PLAUSIBLE_TIME_S}, ${MAX_PLAUSIBLE_TIME_S}] — a millisecond timestamp or a broken clock`,
    )
  }
  if (record.scope === 'grant') {
    if (record.effective_from !== null) {
      reasons.push('effective_from_invalid: must be null on a grant-scope revocation')
    }
  } else if (record.scope === 'vehicle') {
    if (!isPlausibleTime(record.effective_from)) {
      reasons.push('effective_from_implausible: vehicle scope requires Unix seconds in the plausible window')
    } else if (Number.isSafeInteger(record.issued_at) && record.effective_from > record.issued_at) {
      reasons.push(
        `effective_from_prospective: ${record.effective_from} > issued_at ${record.issued_at}; a ` +
          'kill switch cannot pre-revoke grants that do not exist yet',
      )
    }
  }
  if (record.signature !== null && !isBase64urlBytes(record.signature, ED25519_SIGNATURE_BYTES)) {
    reasons.push(`signature_malformed: expected a ${ED25519_SIGNATURE_BYTES}-byte Ed25519 signature, base64url`)
  }
  return reasons
}

// ---------------------------------------------------------------------------------
// Revocation state
// ---------------------------------------------------------------------------------

/**
 * A revocation state: the entry set plus the two indexes the authorisation path needs.
 *
 * `entries` is keyed by leaf key so insertion is idempotent by construction — the same
 * revocation applied twice writes the same key, and FIRST WINS. First-wins is not an
 * arbitrary tie-break: the witness carries `revoked_at`, so letting a later application
 * overwrite it would change the leaf value, change the root, and invalidate every
 * inclusion proof already issued against the old root. Revocation is monotone; so is the
 * record of it.
 *
 * `vehicleFloor` maps a revocation-key thumbprint to the latest `effective_from` seen for
 * it, so the kill-switch check is one lookup rather than a scan.
 */
export function createRevocationState() {
  return {
    v: NF4_STATE_VERSION,
    entries: new Map(),
    vehicleFloor: new Map(),
    root: null,
  }
}

/**
 * Rebuild a state from its durable rows. The cold-start path, and the reason it is here
 * rather than left to each caller.
 *
 * A state carries TWO indexes over one row set: `entries`, keyed by leaf key, and
 * `vehicleFloor`, the kill-switch index that `isRevoked` consults. The obvious rebuild —
 * read the rows, populate `entries` — silently leaves `vehicleFloor` empty, and the
 * consequence is not a missing feature but silent UNDER-revocation: every kill switch stops
 * being enforced, `isRevoked` answers "not revoked" for grants the owner killed, and nothing
 * anywhere reports it. Two indexes that a caller must remember to populate together will
 * eventually be populated apart, so the module populates them together and exports that.
 *
 * Fails closed on any row it cannot read, rather than loading a partial index: a revocation
 * state missing rows answers "not revoked" for exactly the grants whose rows were bad, which
 * is the worst possible direction for a read error to fail in. An operator seeing this throw
 * has an unreadable revocation table and must not serve until it is fixed.
 *
 * Accepts rows in either shape: the entry objects `revocationEntries` returns (witness
 * nested), or a flat D1 row with the witness spread across the `cause`, `revoked_at`,
 * `cascaded_from` and `record_digest` columns of the schema sketched at the top of this file.
 *
 * @param {Iterable<object>} rows
 * @returns {object} a state, equivalent to the one the rows were written from
 */
export function revocationStateFromRows(rows) {
  if (rows === null || typeof rows !== 'object' || typeof rows[Symbol.iterator] !== 'function') {
    throw new Error('revocationStateFromRows: rows must be iterable')
  }
  const state = createRevocationState()
  for (const row of rows) {
    if (!isPlainObject(row)) throw new Error('revocation row must be a plain object')
    if (!isBase64urlBytes(row.leaf_key, DIGEST_BYTES)) {
      throw new Error(`revocation row has a malformed leaf_key: ${String(row.leaf_key)}`)
    }
    if (row.kind !== 'grant' && row.kind !== 'vehicle') {
      throw new Error(`revocation row has an unknown kind "${String(row.kind)}"`)
    }
    if (!isBase64urlBytes(row.target, DIGEST_BYTES)) {
      throw new Error(`revocation row ${row.leaf_key} has a malformed target`)
    }

    const witness = isPlainObject(row.witness)
      ? row.witness
      : {
          v: NF4_WITNESS_VERSION,
          cause: row.cause,
          revoked_at: row.revoked_at,
          cascaded_from: row.cascaded_from ?? null,
          record_digest: row.record_digest,
        }
    const witnessReasons = witnessShapeReasons(witness)
    if (witnessReasons.length > 0) {
      throw new Error(`revocation row ${row.leaf_key} has an unusable witness: ${witnessReasons.join('; ')}`)
    }

    const effectiveFrom = row.effective_from ?? null
    if (row.kind === 'vehicle' && !isPlausibleTime(effectiveFrom)) {
      throw new Error(`vehicle revocation row ${row.leaf_key} has an implausible effective_from`)
    }
    if (row.kind === 'grant' && effectiveFrom !== null) {
      throw new Error(`grant revocation row ${row.leaf_key} carries an effective_from`)
    }

    state.entries.set(row.leaf_key, {
      leaf_key: row.leaf_key,
      kind: row.kind,
      target: row.target,
      effective_from: effectiveFrom,
      grant_id: row.grant_id ?? null,
      witness,
    })
    if (row.kind === 'vehicle') {
      const previousFloor = state.vehicleFloor.get(row.target)
      if (previousFloor === undefined || effectiveFrom > previousFloor) {
        state.vehicleFloor.set(row.target, effectiveFrom)
      }
    }
  }
  return state
}

/**
 * Entries in deterministic order (by leaf key). The tree is built from this, so the root
 * is a function of the SET and not of insertion order — which is what makes the tree a
 * derived index that can always be rebuilt from D1 rows in whatever order they come back.
 */
export function revocationEntries(state) {
  assertState(state)
  return [...state.entries.values()].sort((a, b) => (a.leaf_key < b.leaf_key ? -1 : a.leaf_key > b.leaf_key ? 1 : 0))
}

function assertState(state) {
  if (!isPlainObject(state) || state.v !== NF4_STATE_VERSION || !(state.entries instanceof Map)) {
    throw new Error('not an NF-4 revocation state; build one with createRevocationState()')
  }
  return state
}

// ---------------------------------------------------------------------------------
// Leaf keys
// ---------------------------------------------------------------------------------

/**
 * Leaf key for a grant-scope entry: H(domain || grant_commitment).
 *
 * Deriving the position from the commitment rather than storing an arbitrary index is what
 * makes the tree order-independent and the proof self-locating: a verifier who holds the
 * grant computes the commitment, computes the key, and knows exactly which position to
 * check. A verifier who does not hold the grant cannot compute the key at all, which is
 * the privacy property — see `revocationStateRoot`.
 */
export async function revocationLeafKeyForGrant(grantCommitment) {
  if (!isBase64urlBytes(grantCommitment, DIGEST_BYTES)) {
    throw new Error('grant commitment must be a 32-byte base64url digest from deriveGrantCommitment()')
  }
  return sha256(encode(LEAF_KEY_GRANT_DOMAIN + grantCommitment))
}

/**
 * Leaf key for a kill-switch entry: H(domain || revocation_key_id || ':' || effective_from).
 *
 * `effective_from` is inside the KEY, not just the value, so a kill switch at one instant
 * is a different leaf from a kill switch at another. Two consequences, both wanted: a
 * later kill switch cannot silently rewrite an earlier one's leaf (proofs stay valid), and
 * the pair (key, effective_from) is exactly what a third party needs to reconstruct the
 * position from a record they were handed.
 */
export async function revocationLeafKeyForVehicle(revocationKeyId, effectiveFrom) {
  if (!isBase64urlBytes(revocationKeyId, DIGEST_BYTES)) {
    throw new Error('revocation_key_id must be a 32-byte base64url thumbprint')
  }
  assertSafeInteger(effectiveFrom, 'effectiveFrom')
  return sha256(encode(`${LEAF_KEY_VEHICLE_DOMAIN}${revocationKeyId}:${effectiveFrom}`))
}

// ---------------------------------------------------------------------------------
// Applying a revocation
// ---------------------------------------------------------------------------------
/**
 * WHY BOTH DIRECTIONS OF BROKER POWERLESSNESS MATTER.
 *
 * The requirement is symmetric and the two halves defend against different adversaries.
 *
 * The broker must not be able to REVOKE on the owner's behalf. If it could, revocation
 * stops being a property of the owner's key and becomes a service the operator performs.
 * That is a kill switch pointed the wrong way: an operator under commercial pressure could
 * cut a disfavoured counterparty's access — an independent repair shop competing with a
 * franchised dealer is the concrete case (§9.9, and the reason `repair-independent` is a
 * first-class counterparty class) — and dress it as the owner's decision. It would also
 * make the operator a party to every consent relationship, which is exactly the
 * market-operator role Refusal 3 forbids the Foundation and which no broker in this
 * architecture is supposed to occupy either. Enforcement: `applyRevocation` accepts no
 * authority except a signature that verifies under the public key whose thumbprint the
 * GRANT names. There is no operator key, no privileged scope, and no code path that
 * inserts an entry without a verified record.
 *
 * The broker must not be able to REFUSE a valid revocation. This is the half that gets
 * left out, and it is the one an owner is harmed by. A revocation the operator can decline
 * is a revocation that exists at the operator's discretion, which is no revocation at all
 * — and the incentive to decline is real, because a revoked grant is a customer
 * relationship the broker was intermediating. Enforcement is by ABSENCE, which is the only
 * enforcement that works when the broker runs the code:
 *
 *   - `applyRevocation` has no policy parameter. Nothing to configure, no list to add the
 *     owner's key to, no callback, no reason code the operator may supply, no return path
 *     for "declined". A valid record either applies or the function is not being called.
 *   - The state transition is a pure function of (state, record, population). Any party
 *     given the same three inputs computes the same entries and the same root, so a broker
 *     that skipped a revocation produces a root that does not match the one anyone else
 *     computes. Refusal becomes detectable rather than deniable.
 *   - The record is self-authenticating (it carries the public key), so the owner can hand
 *     it to a counterparty, a regulator or a court and have it verified without the
 *     broker's cooperation or existence.
 *   - `isRevoked` treats a vehicle-scope record as decisive on its own terms — thumbprint
 *     match plus `issued_at <= effective_from` — so a broker that fails to enumerate the
 *     affected grants does not thereby keep them alive for anyone who has seen the record.
 *   - `assertRevocationMonotone` fails if an entry disappears, so refusal-by-deletion is
 *     caught by the same check that catches erasure doing it accidentally.
 *
 * What the broker CAN still do is withhold: not show a counterparty the record, not publish
 * the root. Cryptography cannot stop a party from staying silent. Three things bound the
 * damage, and it is worth being honest that they bound rather than eliminate it: the
 * anchored root is public and its cadence is fixed, so a root that never changes while the
 * owner holds a signed revocation is evidence; the owner holds a self-verifying receipt
 * they can publish themselves; and the staleness bound caps how long any cached decision
 * derived from withheld state can be honoured. That last one is why §8.4 makes the bound
 * part of the protocol rather than an implementation detail.
 */

/**
 * Apply a verified revocation record to a state. The single transition point — both named
 * entry points below are thin wrappers, so there is exactly one place where an entry can
 * come into existence.
 *
 * Returns a result object rather than throwing on an unauthorised record, because "this
 * record does not authorise this revocation" is data the caller must surface, not an
 * exception to swallow. It throws only on programmer error (a non-state, a non-array
 * population).
 *
 * Mutates and returns `state`: the entries are D1 rows and writing them is a mutation
 * anyway, and a copy-on-write tree would only create the possibility of two states
 * disagreeing about what has been revoked.
 *
 * @param {object} state
 * @param {object} record signed revocation record
 * @param {object} [opts]
 * @param {object} [opts.grant] the grant being revoked — REQUIRED for grant scope, because
 *        the authorisation to revoke it is a property of the grant, not of the record
 * @param {Iterable<object>} [opts.population] known grants, for cascade and kill-switch
 *        materialisation. Descendants outside the population are still denied at check
 *        time via `isRevoked`'s ancestor walk; the population only determines which
 *        entries get committed.
 * @param {number} [opts.now] Unix seconds, for record freshness checks
 * @returns {Promise<{ applied: boolean, reasons: string[], inserted: object[],
 *                     alreadyPresent: string[], warnings: string[], state: object }>}
 */
export async function applyRevocation(state, record, opts = {}) {
  assertState(state)
  const reasons = []
  const warnings = []
  const inserted = []
  const alreadyPresent = []

  const check = await verifyRevocation(record, { now: opts.now })
  if (!check.valid) {
    return { applied: false, reasons: check.reasons, inserted, alreadyPresent, warnings, state }
  }

  const recordDigest = await revocationRecordDigest(record)
  const revokedAt = record.issued_at
  const population = opts.population === undefined ? [] : [...opts.population]

  if (record.scope === 'grant') {
    const grant = opts.grant
    if (!isPlainObject(grant)) {
      // Fail closed. Without the grant we cannot check that this record's key is the key
      // the OWNER named, and skipping that check would let any revocation keypair in the
      // world revoke any grant — free griefing, and a denial-of-service against a
      // counterparty the owner chose.
      reasons.push(
        'authorisation_grant_unavailable: a grant-scope revocation must be checked against ' +
          'the grant it targets, because only the key named in that grant may revoke it',
      )
      return { applied: false, reasons, inserted, alreadyPresent, warnings, state }
    }

    let commitment
    try {
      commitment = await deriveGrantCommitment(grant)
    } catch (err) {
      reasons.push(`authorisation_grant_uncommittable: ${err?.message ?? String(err)}`)
      return { applied: false, reasons, inserted, alreadyPresent, warnings, state }
    }
    if (commitment !== record.target) {
      reasons.push(
        `target_mismatch: record targets ${record.target} but the supplied grant commits to ${commitment}`,
      )
      return { applied: false, reasons, inserted, alreadyPresent, warnings, state }
    }

    const thumbprint = await revocationKeyIdFromPublicKey(base64urlToBytes(record.revocation_key))
    if (thumbprint !== grant.revocation_key_id) {
      reasons.push(
        'not_owner_revocation_key: the signing key is not the key this grant names in ' +
          'revocation_key_id; only the owner-held revocation key may revoke a grant, and the ' +
          'broker holds no key that substitutes for it',
      )
      return { applied: false, reasons, inserted, alreadyPresent, warnings, state }
    }

    // The grant itself.
    await insertGrantEntry(state, {
      grant,
      commitment,
      cause: 'owner_revocation',
      cascadedFrom: null,
      revokedAt,
      recordDigest,
      inserted,
      alreadyPresent,
      warnings,
    })

    // ...and everything derived from it.
    const cascade = collectDescendants(grant.grant_id, population)
    warnings.push(...cascade.warnings)
    for (const descendant of cascade.descendants) {
      await insertGrantEntry(state, {
        grant: descendant,
        commitment: null,
        cause: 'cascade',
        cascadedFrom: grant.grant_id,
        revokedAt,
        recordDigest,
        inserted,
        alreadyPresent,
        warnings,
      })
    }
    return { applied: true, reasons, inserted, alreadyPresent, warnings, state }
  }

  // ------------------------------------------------------------------ vehicle scope
  const leafKeyBytes = await revocationLeafKeyForVehicle(record.target, record.effective_from)
  const leafKey = base64url(leafKeyBytes)
  const witness = makeWitness({
    cause: 'owner_revocation',
    revokedAt,
    cascadedFrom: null,
    recordDigest,
  })
  if (state.entries.has(leafKey)) {
    alreadyPresent.push(leafKey)
  } else {
    const entry = {
      leaf_key: leafKey,
      kind: 'vehicle',
      target: record.target,
      effective_from: record.effective_from,
      grant_id: null,
      witness,
    }
    state.entries.set(leafKey, entry)
    state.root = null
    inserted.push(entry)
  }
  const previousFloor = state.vehicleFloor.get(record.target)
  if (previousFloor === undefined || record.effective_from > previousFloor) {
    state.vehicleFloor.set(record.target, record.effective_from)
  }

  // Materialise a per-grant entry for every affected grant we can see, and cascade from
  // each. This is convenience and completeness, not correctness: the check-time decision
  // does not depend on it (see `isRevoked`), so a broker that under-enumerates cannot keep
  // a killed grant alive. What per-grant entries buy is a counterparty holding only its own
  // grant being able to obtain an inclusion proof without being handed the kill-switch
  // record — and without anyone having to disclose a different counterparty's grant.
  for (const g of population) {
    if (!isPlainObject(g)) continue
    if (g.revocation_key_id !== record.target) continue
    if (!Number.isSafeInteger(g.issued_at) || g.issued_at > record.effective_from) continue
    await insertGrantEntry(state, {
      grant: g,
      commitment: null,
      cause: 'cascade',
      cascadedFrom: null,
      revokedAt,
      recordDigest,
      inserted,
      alreadyPresent,
      warnings,
    })
  }
  return { applied: true, reasons, inserted, alreadyPresent, warnings, state }
}

/**
 * Revoke one grant. Cascades to every descendant sub-grant, transitively.
 *
 * @param {object} state
 * @param {object} record signed grant-scope revocation record
 * @param {object} grant the grant being revoked
 * @param {object} [opts] { population, now }
 */
export async function revokeGrant(state, record, grant, opts = {}) {
  if (!isPlainObject(record) || record.scope !== 'grant') {
    return {
      applied: false,
      reasons: ['scope_mismatch: revokeGrant requires a grant-scope record'],
      inserted: [],
      alreadyPresent: [],
      warnings: [],
      state,
    }
  }
  return applyRevocation(state, record, { ...opts, grant })
}

/**
 * The kill switch: revoke everything under one owner-held revocation key, issued at or
 * before `effective_from`.
 *
 * WHY THE TARGET IS A KEY AND NOT A VEHICLE. An owner exercising sovereignty should not
 * have to know, list, or think about who holds grants over their car — that is the whole
 * asymmetry the consent layer exists to correct, and a UI that says "select the
 * counterparties to revoke" has reproduced it. So the switch is scoped by the one thing
 * the owner definitionally already holds: their revocation key. No enumeration of
 * counterparties, no pseudonym lookup, no VIN, no round trip to the broker to ask who is
 * out there. The owner signs one record offline and every grant under that key is dead.
 *
 * Under the recommended key management — one revocation keypair per (vehicle, counterparty
 * class) — a vehicle-wide kill switch is one record per class the owner has issued under,
 * at most `COUNTERPARTY_CLASSES.length`. That is still not enumerating counterparties: the
 * owner's client enumerates its OWN keys, which it generated, over a closed vocabulary it
 * already ships. Loop `buildRevocation`/`signRevocation` over those keys and apply each.
 *
 * Note the fail-safe asymmetry if an owner instead reuses one key across two vehicles: the
 * switch over-revokes. Over-revocation costs access; under-revocation costs control. The
 * cheap error is the right one to be exposed to.
 *
 * @param {object} state
 * @param {object} record signed vehicle-scope revocation record
 * @param {object} [opts] { population, now }
 */
export async function revokeVehicle(state, record, opts = {}) {
  if (!isPlainObject(record) || record.scope !== 'vehicle') {
    return {
      applied: false,
      reasons: ['scope_mismatch: revokeVehicle requires a vehicle-scope record'],
      inserted: [],
      alreadyPresent: [],
      warnings: [],
      state,
    }
  }
  if (opts.grant !== undefined) throw new Error('revokeVehicle takes no single grant; it is scoped by key')
  return applyRevocation(state, record, opts)
}

/** Insert one grant-scope entry, idempotently. First write wins. */
async function insertGrantEntry(state, args) {
  let commitment = args.commitment
  if (commitment === null) {
    try {
      commitment = await deriveGrantCommitment(args.grant)
    } catch (err) {
      // A grant we cannot commit to is a grant that cannot be verified either, so it can
      // never be served — but say so loudly, because it means the population contains a
      // row that does not round-trip and the entry set is therefore incomplete.
      args.warnings.push(
        `population_grant_uncommittable: ${String(args.grant?.grant_id)} (${err?.message ?? String(err)})`,
      )
      return
    }
  }
  const leafKey = base64url(await revocationLeafKeyForGrant(commitment))
  if (state.entries.has(leafKey)) {
    args.alreadyPresent.push(leafKey)
    return
  }
  const entry = {
    leaf_key: leafKey,
    kind: 'grant',
    target: commitment,
    effective_from: null,
    grant_id: args.grant.grant_id,
    witness: makeWitness({
      cause: args.cause,
      revokedAt: args.revokedAt,
      cascadedFrom: args.cascadedFrom,
      recordDigest: args.recordDigest,
    }),
  }
  state.entries.set(leafKey, entry)
  state.root = null
  args.inserted.push(entry)
}

/**
 * The committed, disclosable part of an entry. Closed key set, always present, explicit
 * null — the leaf value is its digest, so absence-vs-null would give one semantic entry two
 * leaf values and therefore two roots.
 *
 * `cascaded_from` is a parent grant_id, disclosed to whoever verifies a cascaded entry.
 * That is not a new leak: a sub-grant already carries `parent_grant_id`, so its holder
 * already knows it, and a random 128-bit id tells a stranger nothing.
 */
function makeWitness({ cause, revokedAt, cascadedFrom, recordDigest }) {
  return {
    v: NF4_WITNESS_VERSION,
    cause,
    revoked_at: assertSafeInteger(revokedAt, 'revoked_at'),
    cascaded_from: cascadedFrom ?? null,
    record_digest: recordDigest,
  }
}

async function witnessValue(witness) {
  const reasons = witnessShapeReasons(witness)
  if (reasons.length > 0) throw new Error(`invalid witness: ${reasons.join('; ')}`)
  return sha256(encode(WITNESS_DIGEST_DOMAIN + canonicalize(witness)))
}

function witnessShapeReasons(witness) {
  const reasons = []
  if (!isPlainObject(witness)) return ['witness_malformed: must be a plain object']
  for (const key of Object.keys(witness)) {
    if (!WITNESS_KEY_SET.has(key)) reasons.push(`witness_malformed: unknown member "${key}"`)
  }
  for (const key of WITNESS_KEYS) {
    if (!Object.hasOwn(witness, key)) reasons.push(`witness_malformed: missing member "${key}"`)
  }
  if (reasons.length > 0) return reasons
  if (witness.v !== NF4_WITNESS_VERSION) reasons.push(`witness_version_unsupported: "${String(witness.v)}"`)
  if (witness.cause !== 'owner_revocation' && witness.cause !== 'cascade') {
    reasons.push(`witness_malformed: cause must be owner_revocation or cascade`)
  }
  if (!isPlausibleTime(witness.revoked_at)) reasons.push('witness_malformed: revoked_at implausible')
  if (witness.cascaded_from !== null && !isBase64urlBytes(witness.cascaded_from, GRANT_ID_BYTES)) {
    reasons.push('witness_malformed: cascaded_from must be null or a grant_id')
  }
  if (!isBase64urlBytes(witness.record_digest, DIGEST_BYTES)) {
    reasons.push('witness_malformed: record_digest must be a 32-byte base64url digest')
  }
  return reasons
}

/**
 * Collect every descendant of `rootGrantId` by walking `parent_grant_id` edges.
 *
 * Cycle-safe via a visited set, which also makes the walk terminate in O(population)
 * regardless of how corrupt the edges are — `parent_grant_id` comes out of D1 and a cycle
 * there would otherwise be an infinite loop in the revocation path, i.e. a way to make
 * revocation hang.
 *
 * The walk is NOT truncated at `MAX_DELEGATION_DEPTH`. A legitimate chain cannot be longer
 * than the root's declared `delegation_depth`, so an over-deep chain means the population
 * is malformed — and stopping there would leave live descendants holding authority derived
 * from a grant the owner just revoked. So: revoke everything reachable, and REPORT the
 * invariant violation. The declared depth is the bound on what should exist, not a licence
 * to stop revoking.
 */
function collectDescendants(rootGrantId, population) {
  const warnings = []
  const children = new Map()
  for (const g of population) {
    if (!isPlainObject(g)) continue
    const parent = g.parent_grant_id
    if (typeof parent !== 'string' || parent.length === 0) continue
    if (parent === g.grant_id) {
      warnings.push(`cascade_self_parent: grant ${g.grant_id} names itself as parent; edge ignored`)
      continue
    }
    if (!children.has(parent)) children.set(parent, [])
    children.get(parent).push(g)
  }

  const descendants = []
  const visited = new Set([rootGrantId])
  let queue = [rootGrantId]
  let hops = 0
  while (queue.length > 0) {
    const next = []
    for (const id of queue) {
      for (const child of children.get(id) ?? []) {
        if (typeof child.grant_id !== 'string') continue
        if (visited.has(child.grant_id)) {
          warnings.push(
            `cascade_cycle: grant ${child.grant_id} reached twice; the delegation graph is not a ` +
              'tree, which a valid population cannot be',
          )
          continue
        }
        visited.add(child.grant_id)
        descendants.push(child)
        next.push(child.grant_id)
      }
    }
    if (next.length > 0) hops += 1
    queue = next
  }
  if (hops > MAX_DELEGATION_DEPTH) {
    warnings.push(
      `cascade_depth_exceeds_declared_bound: walked ${hops} hops, MAX_DELEGATION_DEPTH is ` +
        `${MAX_DELEGATION_DEPTH}. Everything reached was revoked — truncating would leave live ` +
        'descendants — but the population violates the delegation invariant',
    )
  }
  return { descendants, hops, warnings }
}

// ---------------------------------------------------------------------------------
// The check-time predicate
// ---------------------------------------------------------------------------------

/**
 * Is this grant revoked? The one function the authorisation path calls.
 *
 * Three independent grounds, checked in order of cost, any one of which is decisive:
 *
 *  1. A grant-scope entry for this grant's own commitment.
 *  2. A kill switch under this grant's `revocation_key_id` with
 *     `effective_from >= grant.issued_at`. Evaluated directly from the state's floor index
 *     rather than from materialised per-grant entries, so a broker that failed to enumerate
 *     the affected grants cannot thereby keep one alive.
 *  3. Any ANCESTOR being revoked, when the caller supplies the chain. This makes the
 *     cascade correct even if the accumulator missed a descendant — a population read that
 *     raced with an insert, a row written by an older build. The walk is bounded by
 *     construction: a chain cannot be longer than MAX_DELEGATION_DEPTH + 1, so this is at
 *     most two extra checks, and `opts.ancestors` is rejected if it is longer.
 *
 * Ancestors are the caller's responsibility to supply because they are a D1 read the
 * caller is already doing to verify the chain (nf2-grant's `verifyGrant` needs the parent
 * anyway, and refuses to verify a delegated grant without it). Omitting them is permitted
 * for a root grant — where there are none — and is a latent hole for a delegated one, so
 * a delegated grant with no ancestors supplied is reported.
 *
 * @param {object} state
 * @param {object} grant
 * @param {object} [opts]
 * @param {object[]} [opts.ancestors] parent, grandparent, ... nearest first
 * @returns {Promise<{ revoked: boolean, cause: string|null, revoked_at: number|null,
 *                     entry: object|null, notes: string[] }>}
 */
export async function isRevoked(state, grant, opts = {}) {
  assertState(state)
  const notes = []
  if (!isPlainObject(grant)) throw new Error('isRevoked: grant must be a plain object')

  // (1) this grant, by commitment.
  const commitment = await deriveGrantCommitment(grant)
  const leafKey = base64url(await revocationLeafKeyForGrant(commitment))
  const entry = state.entries.get(leafKey)
  if (entry !== undefined) {
    return {
      revoked: true,
      cause: entry.witness.cause === 'cascade' ? 'cascaded' : 'revoked',
      revoked_at: entry.witness.revoked_at,
      entry,
      notes,
    }
  }

  // (2) kill switch.
  const floor = state.vehicleFloor.get(grant.revocation_key_id)
  if (floor !== undefined && Number.isSafeInteger(grant.issued_at) && floor >= grant.issued_at) {
    return { revoked: true, cause: 'vehicle_kill_switch', revoked_at: floor, entry: null, notes }
  }

  // (3) ancestry.
  const ancestors = opts.ancestors
  if (ancestors === undefined) {
    if (grant.parent_grant_id !== null && grant.parent_grant_id !== undefined) {
      notes.push(
        'ancestors_not_supplied: this is a delegated grant and its chain was not checked. The ' +
          'cascade entries should cover it, but supplying the chain is what makes that ' +
          'independent of the accumulator being complete',
      )
    }
  } else {
    if (!Array.isArray(ancestors)) throw new Error('opts.ancestors must be an array')
    if (ancestors.length > MAX_DELEGATION_DEPTH + 1) {
      throw new Error(
        `opts.ancestors has ${ancestors.length} entries; a valid chain cannot exceed ` +
          `MAX_DELEGATION_DEPTH + 1 = ${MAX_DELEGATION_DEPTH + 1}`,
      )
    }
    const seen = new Set([grant.grant_id])
    for (const ancestor of ancestors) {
      if (!isPlainObject(ancestor)) throw new Error('opts.ancestors entries must be plain objects')
      if (seen.has(ancestor.grant_id)) {
        // Fail closed: a cycle in the supplied chain means we cannot establish provenance,
        // and an unprovable chain must not be served.
        return {
          revoked: true,
          cause: 'ancestry_cyclic',
          revoked_at: null,
          entry: null,
          notes: [...notes, `ancestry_cyclic: ${String(ancestor.grant_id)} appears twice in the chain`],
        }
      }
      seen.add(ancestor.grant_id)
      const up = await isRevoked(state, ancestor, {})
      if (up.revoked) {
        return {
          revoked: true,
          cause: 'ancestor_revoked',
          revoked_at: up.revoked_at,
          entry: up.entry,
          notes,
        }
      }
    }
  }
  return { revoked: false, cause: null, revoked_at: null, entry: null, notes }
}

// ---------------------------------------------------------------------------------
// Cached decisions and the staleness bound (§8.4)
// ---------------------------------------------------------------------------------

/**
 * Build a well-formed cached authorisation decision. Correct-by-construction, so a caller
 * cannot invent a cache row that `evaluateCachedDecision` will misread.
 *
 * The decision is bound to the grant commitment AND to the key the presenter proved
 * possession of, because a decision cached against a grant alone would be replayable by a
 * different presenter — the grant is not a bearer token (nf2-grant.js) and neither is a
 * decision about it. It also records the state root it was derived against, which is what
 * makes immediate invalidation possible.
 */
export function deriveDecision(params) {
  const p = requireParams(params, [
    'grantCommitment',
    'presenterKey',
    'allowed',
    'cause',
    'derivedAt',
    'stateRoot',
  ])
  if (typeof p.allowed !== 'boolean') throw new Error('allowed must be a boolean')
  if (typeof p.cause !== 'string' || p.cause.length === 0) throw new Error('cause is required')
  const decision = {
    v: NF4_DECISION_VERSION,
    grant_commitment: p.grantCommitment,
    presenter_key: p.presenterKey,
    decision: p.allowed ? 'allow' : 'deny',
    cause: p.cause,
    derived_at: assertSafeInteger(p.derivedAt, 'derivedAt'),
    state_root: p.stateRoot ?? null,
  }
  const reasons = decisionShapeReasons(decision)
  if (reasons.length > 0) throw new Error(`refusing to build an invalid decision: ${reasons.join('; ')}`)
  return decision
}

/**
 * Enforce the staleness bound on a cached decision. THIS is what stops a revocation from
 * being outrun by a cache.
 *
 * The rules, and the asymmetry between them, which is the substance of §8.4:
 *
 *  - A cached ALLOW is honoured only if it is fresh on BOTH axes: age within the bound, and
 *    derived against the current state root when the caller can see one. Otherwise the
 *    result is 'unknown' — never 'allow', and never 'deny' either, because a stale allow is
 *    not evidence of anything. 'unknown' means re-derive from the revocation state; a
 *    caller that treats it as allow has reintroduced the failure this whole module exists
 *    to prevent.
 *  - A cached DENY whose cause is revocation is honoured FOREVER, at any age. That is not
 *    laxity, it is the monotonicity of revocation being spent usefully: there is no
 *    un-revoke, so this row can never become wrong. Caching it indefinitely also removes
 *    the incentive to raise the allow bound for performance, because the expensive case
 *    (a hot revoked grant hammering the store) is the one that caches best.
 *  - Any other DENY is 'unknown'. It may have been about a since-renewed grant, an expiry,
 *    or a transient read failure, and caching those permanently would deny access the owner
 *    has authorised.
 *  - A decision from the future ('derived_at' > now + skew) is 'unknown'. A clock that ran
 *    backwards, or a forged row, must not extend a cache's life.
 *
 * @param {object} cached decision row from `deriveDecision`
 * @param {object} [opts]
 * @param {number} [opts.now]
 * @param {number} [opts.maxAgeS=DEFAULT_MAX_DECISION_AGE_S]
 * @param {string|null} [opts.currentStateRoot] pass when known; omit only if unreachable
 * @param {string} [opts.presenterKey] key proved in THIS session
 * @param {string} [opts.grantCommitment] commitment of the grant presented in THIS session
 * @param {number} [opts.clockSkewS=5]
 * @returns {{ decision: 'allow'|'deny'|'unknown', reason: string, ageS: number|null,
 *             mustRederive: boolean }}
 */
export function evaluateCachedDecision(cached, opts = {}) {
  const maxAgeS = assertDecisionAgeBound(opts.maxAgeS ?? DEFAULT_MAX_DECISION_AGE_S)
  const now = opts.now ?? Math.floor(Date.now() / 1000)
  const skew = opts.clockSkewS ?? 5

  const shape = decisionShapeReasons(cached)
  if (shape.length > 0) return unknown(`cache_malformed: ${shape.join('; ')}`, null)

  const ageS = now - cached.derived_at

  if (opts.grantCommitment !== undefined && opts.grantCommitment !== cached.grant_commitment) {
    return unknown('cache_target_mismatch: cached decision is about a different grant', ageS)
  }
  if (opts.presenterKey !== undefined && opts.presenterKey !== cached.presenter_key) {
    return unknown(
      'cache_presenter_mismatch: cached decision was derived for a different presenter; a ' +
        'decision is not a bearer token any more than a grant is',
      ageS,
    )
  }

  if (cached.decision === 'deny') {
    if (cached.cause === 'revoked' || cached.cause === 'cascaded' || cached.cause === 'vehicle_kill_switch') {
      return {
        decision: 'deny',
        reason: `deny_monotone: ${cached.cause}; revocation cannot be undone, so this row can never become wrong`,
        ageS,
        mustRederive: false,
      }
    }
    return unknown(
      `deny_not_monotone: cause "${cached.cause}" may no longer hold; re-derive rather than ` +
        'denying access the owner may have re-authorised',
      ageS,
    )
  }

  if (ageS < -skew) {
    return unknown(`cache_future_dated: derived_at ${cached.derived_at} is ahead of now ${now}`, ageS)
  }
  if (ageS > maxAgeS) {
    return unknown(
      `stale_allow: cached decision is ${ageS}s old, bound is ${maxAgeS}s. A cached "allowed" ` +
        'past the bound is UNKNOWN and must be re-derived — treating it as allowed is what turns ' +
        'a revocable grant into an irrevocable one',
      ageS,
    )
  }
  if (opts.currentStateRoot !== undefined) {
    if (cached.state_root === null || cached.state_root !== opts.currentStateRoot) {
      return unknown(
        'state_root_moved: the revocation state changed since this decision was derived; a root ' +
          'change is the immediate invalidation signal and the age bound is only the backstop',
        ageS,
      )
    }
  }
  return { decision: 'allow', reason: 'fresh', ageS, mustRederive: false }

  function unknown(reason, age) {
    return { decision: 'unknown', reason, ageS: age, mustRederive: true }
  }
}

/**
 * The posture when the revocation state cannot be read at all: DENY.
 *
 * Stated as a function so it is testable and so no request path can "temporarily" default
 * the other way under load. An unreachable revocation store means every grant's status is
 * unknown, and unknown is not allowed. The cost of failing closed is an outage; the cost of
 * failing open is serving data the owner has withdrawn consent for, with no bound on how
 * long. Those are not comparable.
 */
export function decisionOnStateUnavailable(cause = 'revocation_state_unreachable') {
  return { decision: 'deny', reason: `fail_closed: ${cause}`, ageS: null, mustRederive: false }
}

function decisionShapeReasons(decision) {
  const reasons = []
  if (!isPlainObject(decision)) return ['must be a plain object']
  for (const key of Object.keys(decision)) {
    if (!DECISION_KEY_SET.has(key)) reasons.push(`unknown member "${key}"`)
  }
  for (const key of DECISION_KEYS) {
    if (!Object.hasOwn(decision, key)) reasons.push(`missing member "${key}"`)
  }
  if (reasons.length > 0) return reasons
  if (decision.v !== NF4_DECISION_VERSION) reasons.push(`version "${String(decision.v)}" unsupported`)
  if (!isBase64urlBytes(decision.grant_commitment, DIGEST_BYTES)) reasons.push('grant_commitment malformed')
  if (!isBase64urlBytes(decision.presenter_key, ED25519_PUBLIC_KEY_BYTES)) reasons.push('presenter_key malformed')
  if (decision.decision !== 'allow' && decision.decision !== 'deny') reasons.push('decision must be allow or deny')
  if (typeof decision.cause !== 'string' || decision.cause.length === 0) reasons.push('cause required')
  if (!Number.isSafeInteger(decision.derived_at)) reasons.push('derived_at must be Unix seconds')
  if (decision.state_root !== null && !isBase64urlBytes(decision.state_root, DIGEST_BYTES)) {
    reasons.push('state_root must be null or a 32-byte base64url root')
  }
  return reasons
}

// ---------------------------------------------------------------------------------
// The revocation-state commitment (Refusal 2)
// ---------------------------------------------------------------------------------
/**
 * A sparse Merkle tree over the revoked set, anchored on-chain as a single 32-byte root.
 *
 * Revocation is the ONE thing in this system that may be committed to an immutable ledger,
 * and the reason is that revocation must be REAL: an owner's withdrawal of consent is worth
 * exactly as much as a third party's ability to check it without asking the broker whose
 * interest runs the other way. Everything the root governs — the grants, the pseudonym
 * salts, the counterparty relationships — stays in mutable, deletable D1 (§9.5).
 *
 * WHY SPARSE MERKLE AND NOT A SORTED-LIST ROOT OR AN RSA-STYLE ACCUMULATOR:
 *  - Position is derived from the key, so the root is a function of the SET. No insertion
 *    order, no rebuild ambiguity, no way for two honest brokers to publish different roots
 *    over the same rows.
 *  - It yields NON-inclusion proofs for free, and non-inclusion is the security-critical
 *    direction: an authorisation decision needs "this grant is not revoked", proven against
 *    a fresh root. A list-of-revoked-hashes root proves inclusion only, so a verifier could
 *    never establish non-revocation without trusting the list to be complete.
 *  - It needs no trusted setup and no modular arithmetic — WebCrypto SHA-256 only, which is
 *    the whole cryptographic budget available under §14.
 *
 * WHAT IS DERIVABLE FROM THE ROOT — the question Refusal 2 turns on:
 *
 *  Not derivable by anyone: a VIN, an owner, a counterparty, a field set, a purpose, a
 *  pseudonym, a timestamp, or the existence of any particular vehicle. The root is a
 *  preimage-resistant digest over keys that are themselves digests of grant commitments,
 *  and a grant commitment is a digest over a payload whose only vehicle reference is an
 *  HMAC keyed by an owner-held salt that never leaves D1. Erasing the salt severs the
 *  linkage permanently, even for a party holding the root, the commitment, and a candidate
 *  VIN.
 *
 *  Not derivable: the number of revocations. An SMT root is fixed-size and
 *  indistinguishable from random regardless of population.
 *
 *  Derivable by a party who ALREADY HOLDS the grant: whether that grant is revoked, and
 *  when. That is the entire point — it is the counterparty's own grant, and the alternative
 *  is asking the broker to be honest. It is not an enumeration capability: without the
 *  grant object (signature included) the leaf key cannot be computed, and guessing it is a
 *  256-bit search.
 *
 *  Derivable by an OBSERVER of the anchor stream: that roots are being published. Nothing
 *  more, provided the cadence is fixed — which is why `buildAnchor` is documented to publish
 *  every epoch whether or not the root moved. A change-triggered anchor would publish the
 *  timing of owners' revocation decisions in aggregate, which is behavioural data about
 *  people even though it names none of them. And note the composition risk: if grant
 *  commitments are ALSO anchored individually, an observer can test any anchored commitment
 *  against any revocation root and learn the issuance-to-revocation interval for a grant it
 *  cannot otherwise identify. Batch grant-commitment anchoring for the same reason.
 *
 * COST. Root computation is O(n · 256) hashes and a proof is O(n · 256) as well, because
 * the tree is recomputed from the entry set rather than cached. That is a deliberate trade:
 * a node cache would be ~n·256 entries of memory and a second source of truth that can go
 * stale, and neither the root nor a proof is ever on the authorisation path —
 * authorisation is `isRevoked`, which is two indexed reads. Roots and proofs belong in the
 * anchoring cron.
 */

/**
 * The root of the current revoked set, base64url. Cached on the state and invalidated by
 * every insert.
 */
export async function revocationStateRoot(state) {
  assertState(state)
  if (state.root !== null) return state.root
  const leaves = await materialiseLeaves(state)
  const empties = await emptyHashes()
  const root = await subtreeHash(leaves, 0, leaves.length, 0, empties)
  state.root = base64url(root)
  return state.root
}

/**
 * Produce an inclusion or non-inclusion proof for one target.
 *
 * @param {object} state
 * @param {{ kind: 'grant', grantCommitment: string }
 *        |{ kind: 'vehicle', revocationKeyId: string, effectiveFrom: number }} target
 * @returns {Promise<object>} proof object; `present: false` is a NON-inclusion proof, which
 *          is the form an authorisation decision actually needs
 */
export async function revocationProof(state, target) {
  assertState(state)
  const keyBytes = await leafKeyForTarget(target)
  const leaves = await materialiseLeaves(state)
  const empties = await emptyHashes()

  let lo = 0
  let hi = leaves.length
  const siblings = []
  for (let d = 0; d < SMT_DEPTH; d += 1) {
    const mid = partitionPoint(leaves, lo, hi, d)
    const bit = bitAt(keyBytes, d)
    const sibLo = bit === 0 ? mid : lo
    const sibHi = bit === 0 ? hi : mid
    const sibling = await subtreeHash(leaves, sibLo, sibHi, d + 1, empties)
    // null means "the default hash for this depth". Emitting it explicitly would make a
    // proof ~8 KB of mostly-identical constants; the verifier substitutes from its own
    // precomputed table, so a lying prover gains nothing by omitting one.
    siblings.push(bytesEqual(sibling, empties[d + 1]) ? null : base64url(sibling))
    lo = bit === 0 ? lo : mid
    hi = bit === 0 ? mid : hi
  }

  const present = hi - lo === 1
  if (present && !bytesEqual(leaves[lo].key, keyBytes)) {
    throw new Error('internal: leaf at the resolved position has a different key')
  }
  return {
    v: NF4_PROOF_VERSION,
    leaf_kind: target.kind,
    leaf_key: base64url(keyBytes),
    present,
    witness: present ? leaves[lo].witness : null,
    siblings,
  }
}

/**
 * Verify a proof against a root, independently of the broker.
 *
 * The target is recomputed by the VERIFIER from what it holds — the grant, or the
 * kill-switch record — and compared to `proof.leaf_key`. Without that step a prover could
 * hand over a valid proof about some other position and claim it was about this grant, so
 * the check is what makes the proof mean anything.
 *
 * @param {object} proof
 * @param {string} root base64url root, obtained from the ledger anchor
 * @param {object} target same shape as `revocationProof`
 * @returns {Promise<{ valid: boolean, revoked: boolean, reasons: string[], witness: object|null }>}
 */
export async function verifyRevocationProof(proof, root, target) {
  const reasons = []
  try {
    if (!isPlainObject(proof)) return fail('proof_malformed: must be a plain object')
    if (proof.v !== NF4_PROOF_VERSION) return fail(`proof_version_unsupported: "${String(proof.v)}"`)
    if (!isBase64urlBytes(root, DIGEST_BYTES)) return fail('root_malformed: expected a 32-byte base64url root')
    if (typeof proof.present !== 'boolean') return fail('proof_malformed: present must be a boolean')
    if (!Array.isArray(proof.siblings) || proof.siblings.length !== SMT_DEPTH) {
      return fail(`proof_malformed: siblings must be an array of exactly ${SMT_DEPTH} entries`)
    }
    if (!isBase64urlBytes(proof.leaf_key, DIGEST_BYTES)) return fail('proof_malformed: leaf_key malformed')

    const expectedKey = await leafKeyForTarget(target)
    if (!bytesEqual(expectedKey, base64urlToBytes(proof.leaf_key))) {
      return fail(
        'proof_target_mismatch: the proof is about a different leaf than the target recomputed ' +
          'from what the verifier holds',
      )
    }
    if (target.kind !== proof.leaf_kind) {
      return fail(`proof_target_mismatch: proof is a ${String(proof.leaf_kind)} leaf, target is ${target.kind}`)
    }

    const empties = await emptyHashes()
    let node
    if (proof.present) {
      const witnessReasons = witnessShapeReasons(proof.witness)
      if (witnessReasons.length > 0) return fail(`proof_malformed: ${witnessReasons.join('; ')}`)
      node = await leafHash(expectedKey, await witnessValue(proof.witness))
    } else {
      if (proof.witness !== null) return fail('proof_malformed: a non-inclusion proof carries no witness')
      node = empties[SMT_DEPTH]
    }

    for (let d = SMT_DEPTH - 1; d >= 0; d -= 1) {
      const raw = proof.siblings[d]
      let sibling
      if (raw === null) {
        sibling = empties[d + 1]
      } else if (isBase64urlBytes(raw, DIGEST_BYTES)) {
        sibling = base64urlToBytes(raw)
      } else {
        return fail(`proof_malformed: sibling at depth ${d} is neither null nor a 32-byte digest`)
      }
      node = bitAt(expectedKey, d) === 0 ? await nodeHash(node, sibling) : await nodeHash(sibling, node)
    }

    if (base64url(node) !== root) {
      return fail('proof_root_mismatch: the path does not reconstruct the anchored root')
    }
    return { valid: true, revoked: proof.present, reasons, witness: proof.witness }
  } catch (err) {
    return fail(`internal: proof verification aborted (${err?.message ?? String(err)})`)
  }

  function fail(reason) {
    reasons.push(reason)
    return { valid: false, revoked: false, reasons, witness: null }
  }
}

async function leafKeyForTarget(target) {
  if (!isPlainObject(target)) throw new Error('target must be a plain object')
  if (target.kind === 'grant') {
    return revocationLeafKeyForGrant(target.grantCommitment)
  }
  if (target.kind === 'vehicle') {
    return revocationLeafKeyForVehicle(target.revocationKeyId, target.effectiveFrom)
  }
  throw new Error(`unknown proof target kind "${String(target.kind)}"`)
}

/** Sorted (key, value, witness) triples. Sorted order is MSB-first bit order, so every
 *  depth partitions the range contiguously — which is what lets the tree be walked without
 *  materialising nodes. */
async function materialiseLeaves(state) {
  const out = []
  for (const entry of revocationEntries(state)) {
    const key = base64urlToBytes(entry.leaf_key)
    out.push({ key, value: await witnessValue(entry.witness), witness: entry.witness })
  }
  out.sort((a, b) => compareBytes(a.key, b.key))
  return out
}

async function subtreeHash(leaves, lo, hi, depth, empties) {
  if (hi - lo === 0) return empties[depth]
  if (depth === SMT_DEPTH) {
    if (hi - lo !== 1) {
      // Two entries with identical 256-bit leaf keys. The Map keying makes this
      // unreachable, and if it ever were reachable it would be a SHA-256 collision.
      throw new Error('internal: duplicate leaf key at full depth')
    }
    return leafHash(leaves[lo].key, leaves[lo].value)
  }
  const mid = partitionPoint(leaves, lo, hi, depth)
  const left = await subtreeHash(leaves, lo, mid, depth + 1, empties)
  const right = await subtreeHash(leaves, mid, hi, depth + 1, empties)
  return nodeHash(left, right)
}

/** First index in [lo, hi) whose key has bit `depth` set. */
function partitionPoint(leaves, lo, hi, depth) {
  let a = lo
  let b = hi
  while (a < b) {
    const m = (a + b) >> 1
    if (bitAt(leaves[m].key, depth) === 0) a = m + 1
    else b = m
  }
  return a
}

function bitAt(keyBytes, depth) {
  return (keyBytes[depth >> 3] >> (7 - (depth & 7))) & 1
}

/**
 * Leaf and node hashes are domain-separated from each other and from the empty leaf, so no
 * digest produced at one position in the tree can be presented as a digest from another —
 * the second-preimage attack every hash-tree design has to close. The leaf hash also binds
 * the KEY, so a leaf cannot be relocated.
 */
async function leafHash(keyBytes, valueBytes) {
  return sha256(concatBytes(encode(SMT_LEAF_DOMAIN), keyBytes, valueBytes))
}

async function nodeHash(left, right) {
  return sha256(concatBytes(encode(SMT_NODE_DOMAIN), left, right))
}

let emptyHashesPromise = null

/** Default subtree hash per depth. Computed once per isolate; 257 digests. */
function emptyHashes() {
  if (emptyHashesPromise === null) {
    emptyHashesPromise = (async () => {
      const out = new Array(SMT_DEPTH + 1)
      out[SMT_DEPTH] = await sha256(encode(SMT_EMPTY_LEAF_DOMAIN))
      for (let d = SMT_DEPTH - 1; d >= 0; d -= 1) {
        out[d] = await nodeHash(out[d + 1], out[d + 1])
      }
      return out
    })()
  }
  return emptyHashesPromise
}

// ---------------------------------------------------------------------------------
// On-chain anchoring
// ---------------------------------------------------------------------------------

/**
 * The object that goes on the ledger. Four fields, and the absence of a fifth is the point.
 *
 * PUBLISH EVERY EPOCH, whether or not the root changed. An anchor emitted only when the set
 * changes turns the anchor stream into a public timeline of owners' revocation decisions —
 * no names, but volume and timing, which is behavioural data about people. A fixed cadence
 * makes the stream information-free about whether anyone revoked anything.
 *
 * Deliberately absent: entry count, tree size, vehicle count, any per-owner or per-grant
 * field, and any signature by the broker. The broker signing the anchor would make the
 * anchor an operator attestation; it is a commitment, and its integrity comes from the
 * ledger and from anyone else being able to recompute the same root from the same rows.
 */
export function buildAnchor(params) {
  const p = requireParams(params, ['root', 'epoch', 'publishedAt'])
  const anchor = {
    v: NF4_ANCHOR_VERSION,
    root: p.root,
    epoch: assertSafeInteger(p.epoch, 'epoch'),
    published_at: assertSafeInteger(p.publishedAt, 'publishedAt'),
  }
  assertAnchorCarriesNoPayload(anchor)
  return anchor
}

/**
 * Refusal 2, executable. Asserts that an anchor carries nothing but a version, a root and
 * two integers — the analogue of `assertNoRawVin` in nf2-grant.js, and it exists for the
 * same reason: to catch the future commit that adds "just a counter" or "just the vehicle
 * id, for debugging" to the one object in this system that can never be deleted.
 */
export function assertAnchorCarriesNoPayload(anchor) {
  if (!isPlainObject(anchor)) throw new Error('anchor must be a plain object')
  for (const key of Object.keys(anchor)) {
    if (!ANCHOR_KEY_SET.has(key)) {
      throw new Error(
        `REFUSAL 2 VIOLATION: anchor carries "${key}". An immutable ledger may hold a ` +
          'revocation-state commitment and nothing else — not a count, not an identifier, not a ' +
          'timestamp per entry. Anything added here can never be erased',
      )
    }
  }
  for (const key of ANCHOR_KEYS) {
    if (!Object.hasOwn(anchor, key)) throw new Error(`anchor is missing "${key}"`)
  }
  if (anchor.v !== NF4_ANCHOR_VERSION) throw new Error(`anchor version "${String(anchor.v)}" unsupported`)
  if (!isBase64urlBytes(anchor.root, DIGEST_BYTES)) throw new Error('anchor root must be a 32-byte base64url digest')
  if (!Number.isSafeInteger(anchor.epoch) || anchor.epoch < 0) throw new Error('anchor epoch must be a non-negative integer')
  if (!isPlausibleTime(anchor.published_at)) throw new Error('anchor published_at must be plausible Unix seconds')
  return true
}

// ---------------------------------------------------------------------------------
// Deletion is not revocation
// ---------------------------------------------------------------------------------
/**
 * DELETION AND REVOCATION ARE DIFFERENT OPERATIONS AND NEITHER SUBSTITUTES FOR THE OTHER.
 *
 * Revocation ends AUTHORITY. It says: as of now, nobody may read this vehicle's data under
 * this grant. It leaves the record of the grant, the record of the revocation, and the
 * linkage intact — deliberately, because the counterparty may still hold a copy of the
 * grant and the revocation entry is what keeps that copy provably dead. Revocation is
 * monotone and its entries must survive everything, including erasure.
 *
 * Deletion (CCPA erasure; the Delete Act's 45-day cadence, §9.5) ends LINKAGE. The payload
 * rows go, the grant rows go, and — the operative one — the owner's pseudonym salt goes.
 * Destroying the salt is what makes erasure real rather than nominal: `vehiclePseudonym` is
 * an HMAC keyed by that salt, so once it is gone, nobody holding a pseudonym, a grant
 * commitment, a revocation root and a candidate VIN can connect any of them to a vehicle.
 * Not the broker, not a subpoena, not a future adversary with more compute. That is why the
 * salt lives in D1 and never in a commitment.
 *
 * The two failure modes to keep straight:
 *
 *  - Deletion WITHOUT revocation leaves live authority attached to data that has been
 *    erased on one side and copied on another. The counterparty's cached grant still
 *    verifies, still names a pseudonym, and now nobody can tell whose it was. Erase the
 *    linkage only after ending the authority.
 *  - Revocation WITHOUT deletion is not erasure and must never be reported as such. It
 *    ends future reads and leaves the record standing, which is the correct answer to
 *    "withdraw my consent" and the wrong answer to "delete my data".
 *
 * And the rule that connects them: erasure MUST NOT remove revocation entries. Their
 * preimages are gone, so they are inert — nobody can compute the leaf key of a deleted
 * grant, and nothing in the tree is personal information — but removing them would change
 * historical roots and, far worse, un-revoke. `assertRevocationMonotone` is the guard.
 */

/**
 * Assert that a state transition only ever added. Run it across any operation that touches
 * the entry set — an erasure sweep, a migration, a compaction, a replica catch-up.
 *
 * Checks both directions of "monotone": no leaf key disappeared, and no surviving leaf's
 * witness changed. The second matters because rewriting `revoked_at` would silently
 * invalidate every proof issued against the old root while leaving the entry count intact,
 * which is the version of this bug that passes a superficial review.
 */
export function assertRevocationMonotone(before, after) {
  assertState(before)
  assertState(after)
  for (const [leafKey, entry] of before.entries) {
    const now = after.entries.get(leafKey)
    if (now === undefined) {
      throw new Error(
        `REVOCATION MONOTONICITY VIOLATED: entry ${leafKey} was removed. Removing a revocation ` +
          'resurrects authority the owner withdrew. Erasure deletes grants, payloads and the ' +
          'pseudonym salt — never revocation entries, which are not personal information and are ' +
          'inert once their preimages are gone',
      )
    }
    if (canonicalize(now.witness) !== canonicalize(entry.witness)) {
      throw new Error(
        `REVOCATION MONOTONICITY VIOLATED: the witness for ${leafKey} changed. That moves the ` +
          'leaf value and the root, invalidating every inclusion proof already issued. ' +
          'Revocation entries are write-once',
      )
    }
  }
  return true
}

// ---------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------
/**
 * These duplicate private helpers in nf2-grant.js. `isBase64urlBytes` in particular is
 * security-relevant — strict length AND charset before decoding, so a value with padding or
 * standard-alphabet characters cannot round-trip to different bytes on different decoders —
 * and two copies of it will drift. See the report note: nf2-grant.js should export it,
 * `isPlainObject`, `requireParams` and its Ed25519 algorithm resolver.
 */

function encode(str) {
  return new TextEncoder().encode(str)
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

function concatBytes(...parts) {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

function compareBytes(a, b) {
  for (let i = 0; i < a.length && i < b.length; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1
  }
  return a.length - b.length
}

function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

function isPlausibleTime(t) {
  return Number.isSafeInteger(t) && t >= MIN_PLAUSIBLE_TIME_S && t <= MAX_PLAUSIBLE_TIME_S
}

function base64urlLengthFor(byteLength) {
  return Math.ceil((byteLength * 4) / 3)
}

function isBase64urlBytes(s, byteLength) {
  if (typeof s !== 'string') return false
  if (s.length !== base64urlLengthFor(byteLength)) return false
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return false
  try {
    return base64urlToBytes(s).length === byteLength
  } catch {
    return false
  }
}

/** Reject unknown/misspelled parameter names, so a silently ignored option cannot become a
 *  default nobody chose. */
function requireParams(params, allowed) {
  if (!isPlainObject(params)) throw new Error('params must be a plain object')
  const allowedSet = new Set(allowed)
  for (const key of Object.keys(params)) {
    if (!allowedSet.has(key)) {
      throw new Error(`unknown parameter "${key}"; expected one of: ${allowed.join(', ')}`)
    }
  }
  return params
}
