/**
 * NF-2 Consent Grant: the capability object of the consent layer.
 *
 * Nimbus Foundation NF-WP-1 §3.1 (Layer 3), §8.2, §9.5, §10.1, §12.2, §14.
 *
 * A Consent Grant is a non-transferable, non-fungible, owner-revocable capability. It
 * says: *this vehicle's owner authorises this named counterparty to read these
 * enumerated fields for this DPPA purpose until this instant, and can withdraw that at
 * any time.* It is not a token, not an asset, not a receipt for a payment, and there is
 * no price anywhere in this file — the Settlement Credit was cut (§9.7) and Layer 5 is
 * gated out of V1 entirely.
 *
 * The three refusals (§10.1) show up here as structure, not as commentary:
 *
 *  1. *The VIN is never resolved to a credential.* A grant contains no VIN, no owner
 *     identity, and no key material that opens anything. It names a pseudonym, a field
 *     set, a purpose, and a holder's public key. Holding a grant tells you what you may
 *     ask for; it is not the thing you ask with, and `verifyGrant` returning
 *     `{ valid: true }` is not an authorisation decision — see the note on revocation
 *     state below.
 *  2. *No personal information reaches an immutable ledger.* The only artefact this
 *     module will produce for a ledger is `deriveGrantCommitment`: one SHA-256 digest.
 *     The grant itself — pseudonym, field set, holder key, timestamps — lives in D1,
 *     mutable and deletable, because a standing 45-day Delete Act cadence and CCPA
 *     erasure cannot be reconciled with immutability (§9.5).
 *  3. *The Foundation does not operate what it governs.* Nothing here is a market.
 *     There is no operator privilege in the schema: no broker key, no Foundation
 *     signature, no field the Foundation can set that changes what an owner authorised.
 *     `revocation_key_id` names an OWNER-held key and `verifyGrant` will reject a grant
 *     whose revocation key is one the caller has flagged as broker-held.
 *
 * WHAT THIS MODULE DOES NOT KNOW: revocation state. Revocation is mutable state and
 * lives in D1 (NF-4); a hash-committed revocation state is a commitment, not the
 * record. `verifyGrant` is a pure function of the grant object plus the arguments you
 * hand it. A caller that treats `valid: true` as permission to serve data, without
 * having checked the revocation table in the same request, has reintroduced the exact
 * failure the revocable-capability design exists to prevent. Pass `opts.revoked` when
 * you have looked.
 */

import {
  COUNTERPARTY_CLASSES,
  DPPA_PURPOSES,
  isValidCounterpartyClass,
  isValidPurpose,
  validateFieldSet,
} from './fields.js'
import {
  base64url,
  base64urlToBytes,
  PSEUDONYM_DERIVATION,
  validateVin,
  vehiclePseudonym,
} from './vin.js'
import { assertSafeInteger, canonicalize, canonicalizeToBytes, compareCodeUnits } from './jcs.js'

/**
 * Schema version. Versioned because revocation semantics are the part most likely to
 * change, and an unversioned capability object makes "does this grant follow the old or
 * the new revocation rule" unanswerable at exactly the moment it matters. The version
 * is inside the signed bytes, so it cannot be edited after issuance, and it also pins
 * the cryptographic suite (see `counterparty_key` below).
 */
export const SCHEMA_VERSION = 'nf2-grant/1'

/**
 * The closed top-level key set. Present in full on every grant, with `null` where a
 * field does not apply — never omitted.
 *
 * Both halves of that rule are load-bearing. Unknown keys are rejected because a
 * verifier that ignores an unrecognised key will happily accept a grant carrying a
 * field the issuer signed and the verifier does not enforce; that is where "extension"
 * fields become privilege escalation. And optional keys are always present-with-null
 * because absence and explicit null canonicalise to different bytes, so allowing both
 * would give one semantic grant two commitments — and NF-4 revocation is keyed by
 * commitment, so the second form would silently evade a revocation entry.
 */
export const GRANT_KEYS = Object.freeze([
  'v',
  'grant_id',
  'vehicle_pseudonym',
  'fields',
  'purpose',
  'issued_at',
  'expires_at',
  'counterparty_class',
  'counterparty_key',
  'revocation_key_id',
  'delegation_depth',
  'parent_grant_id',
  'renewal_of',
  'signature',
])

const GRANT_KEY_SET = new Set(GRANT_KEYS)

/** Sub-object key set for `vehicle_pseudonym`, closed for the same reasons. */
const PSEUDONYM_KEYS = Object.freeze(['value', 'epoch', 'audience', 'derivation'])
const PSEUDONYM_KEY_SET = new Set(PSEUDONYM_KEYS)

/**
 * The pseudonym construction tag, recorded in the grant so a verifier holding the
 * salt knows which construction to recompute rather than inferring it from the schema
 * version. Imported from vin.js — which owns the construction — rather than copied,
 * so a versioned change to the derivation cannot leave the two silently disagreeing.
 */
export { PSEUDONYM_DERIVATION }

/**
 * Maximum grant lifetime: 45 days.
 *
 * The cap is pinned to the Delete Act's 45-day deletion-request cadence (§9.5). Two
 * reasons, and the second is the one that actually forces the number:
 *
 *  - Every grant must face the owner at least as often as the erasure machinery runs.
 *    A grant that outlives a full deletion sweep is a standing authorisation the owner
 *    never re-affirmed while the system was, on the same clock, asking whether they
 *    wanted their data gone at all.
 *  - Expiry is the fail-safe for revocation, not a convenience. Revocation depends on
 *    the owner still holding the revocation key and on the revocation table being
 *    reachable. When either fails, the cap is the entire remaining bound on exposure,
 *    so it has to be short enough to be an acceptable worst case on its own.
 *
 * It is a ceiling, not a default. Issue the shortest grant that does the job; a
 * diagnostics read for a single repair order wants hours, not weeks.
 */
export const MAX_GRANT_DURATION_S = 45 * 24 * 60 * 60

/**
 * Maximum delegation depth on a root grant: 2.
 *
 * Two hops covers the real relationship — a fleet operator delegating to the
 * maintenance contractor that actually turns the wrench — and stops there. Each
 * additional level adds a party the owner never chose, and lengthens the chain that
 * revocation has to walk before the last holder actually loses access. Depth is cheap
 * to raise later and expensive to have been wrong about.
 */
export const MAX_DELEGATION_DEPTH = 2

/**
 * Plausible-timestamp window for `issued_at` / `expires_at`, in Unix SECONDS.
 * 2023-11-14 to 2096-10-02.
 *
 * This exists to catch the millisecond/second unit error, which is not a hypothetical:
 * passing `Date.now()` where seconds are expected turns a 30-day grant into an
 * 80,000-year one, and every other check in this file passes. A range test is the only
 * thing that catches it, because a millisecond timestamp is a perfectly well-formed
 * integer.
 */
export const MIN_PLAUSIBLE_TIME_S = 1_700_000_000
export const MAX_PLAUSIBLE_TIME_S = 4_000_000_000

/** Default tolerance for a fast issuer clock, in seconds. */
export const DEFAULT_CLOCK_SKEW_S = 300

const ED25519_PUBLIC_KEY_BYTES = 32
const ED25519_SIGNATURE_BYTES = 64
const GRANT_ID_BYTES = 16
const PSEUDONYM_BYTES = 32
const REVOCATION_KEY_ID_BYTES = 32

/** Domain separation for the on-chain commitment. See `deriveGrantCommitment`. */
const COMMITMENT_DOMAIN = 'nf2-grant-commitment:v1:'

/** Domain separation for revocation-key thumbprints. See `revocationKeyIdFromPublicKey`. */
const REVOCATION_KEY_ID_DOMAIN = 'nf2-revocation-key-id:v1:'

/**
 * Field names that would make a grant transferable. None of them are in `GRANT_KEYS`,
 * so the closed-key check already rejects them; this list is checked a second time by
 * `assertNonTransferable` so that assertion is meaningful when called on an arbitrary
 * object, and so the conformance suite has something concrete to assert against.
 */
const HOLDER_MUTATION_FIELDS = Object.freeze([
  'holder',
  'assignee',
  'transfer_to',
  'transferable',
  'new_holder',
  'bearer',
  'delegate_to',
  'reissue_to',
])

// ---------------------------------------------------------------------------------
// The schema, field by field
// ---------------------------------------------------------------------------------
/**
 * v                  string   SCHEMA_VERSION. Signed, so it cannot be downgraded.
 *
 * grant_id           string   Random 128 bits, base64url (22 chars). Random rather than
 *                             sequential: a counter leaks issuance volume per vehicle and
 *                             lets a holder estimate how many other grants exist, which
 *                             is a side channel on the owner's behaviour. 128 bits is
 *                             collision-free at any plausible scale without needing a
 *                             coordinator.
 *
 * vehicle_pseudonym  object   { value, epoch, audience, derivation }. `value` is the
 *                             output of vehiclePseudonym() — salted, rotating,
 *                             per-audience HMAC over the VIN. THE RAW VIN NEVER APPEARS
 *                             IN A GRANT, and `buildGrant` re-reads its own output to
 *                             prove it. `epoch` and `audience` are recorded so a party
 *                             holding the owner's salt can recompute `value` and confirm
 *                             the binding; the salt itself stays in D1 and is what makes
 *                             erasure real (§9.5). Note what this achieves: the grant is
 *                             bound to a vehicle without naming one.
 *
 * fields             string[] Enumerated members of the NF-2 closed vocabulary, sorted
 *                             by UTF-16 code unit and unique. Validated through
 *                             validateFieldSet(), which is also where the
 *                             non-transactable classes are refused — precise
 *                             geolocation, biometrics and in-cabin A/V have no field id
 *                             to name, so the protocol cannot encode a grant for them
 *                             (§8.2, §12.2). Sorted because JCS treats array order as
 *                             significant, and an unsorted set would give one semantic
 *                             grant several commitments.
 *
 * purpose            string   Exactly one DPPA_PURPOSES key, 18 U.S.C. §2721(b). One,
 *                             not a list: a grant covering several purposes is a grant
 *                             whose purpose limitation cannot be audited, and purpose
 *                             limitation is the entire DPPA compliance story. Two
 *                             purposes means two grants, each independently revocable.
 *
 * issued_at          integer  Unix seconds.
 * expires_at         integer  Unix seconds. MANDATORY — there is no perpetual grant and
 *                             no null here. Bounded by MAX_GRANT_DURATION_S.
 *
 * counterparty_class string   One COUNTERPARTY_CLASSES value. The owner's decision is
 *                             about kinds of counterparty, which is the decision they
 *                             are equipped to make (see fields.js).
 *
 * counterparty_key   string   Raw Ed25519 public key of the holder, base64url (43
 *                             chars). Binding to a KEY rather than a name is what makes
 *                             the grant unreplayable: a name is an assertion someone
 *                             makes about themselves, and a verifier checking a name
 *                             checks whether the presenter *claims* to be the grantee.
 *                             A key is a challenge the presenter either answers or does
 *                             not. Stolen grant plus no private key equals nothing —
 *                             which is also why a grant can be stored and shipped
 *                             around without being a secret. Names change (an insurer
 *                             reorganises), names collide, and names have to be resolved
 *                             through a registry that then becomes a trusted third
 *                             party the architecture is trying not to need.
 *                             No `alg` field anywhere: the suite is pinned by `v`.
 *                             In-band algorithm negotiation is the JWT `alg` class of
 *                             bug, and a verifier that reads the algorithm out of the
 *                             object it is verifying has already lost.
 *
 * revocation_key_id  string   base64url thumbprint (43 chars) of the OWNER-held
 *                             revocation public key. The key never appears in the grant
 *                             and it is never the broker's — verifyGrant recomputes the
 *                             thumbprint of counterparty_key and rejects the grant if it
 *                             matches (a holder who can revoke will decline to, which is
 *                             not revocation), and rejects any id the caller lists as
 *                             broker-held. An id rather than a
 *                             key so the owner can rotate the key without reissuing
 *                             grants, and so the grant carries nothing usable.
 *
 * delegation_depth   integer  0 = this grant may not be delegated. n > 0 = up to n
 *                             further hops, each decrementing. Conformance-testable and
 *                             bounded by MAX_DELEGATION_DEPTH.
 *
 * parent_grant_id    string?  For a delegated sub-grant, the grant_id it descends from.
 *                             null on a root grant. This is the edge NF-4 walks to
 *                             cascade a revocation down a subtree.
 *
 * renewal_of         string?  The grant_id this one supersedes, or null.
 *
 * signature          string   Ed25519, base64url (86 chars), over the JCS
 *                             canonicalisation of the grant with `signature` removed.
 *                             null on an unsigned grant. The signer is the owner for a
 *                             root grant and the delegator for a sub-grant.
 *
 * DELIBERATELY ABSENT: the signer's public key.
 *
 * Putting the owner's key in the grant would undo the pseudonym work entirely. Two
 * counterparties holding grants over the same vehicle get different pseudonyms — that is
 * the point of the per-audience HMAC — but if both grants carried the same owner public
 * key they could join their datasets on it and reconstruct a profile neither was granted
 * (§12.7). So the verifying key is supplied out of band: the broker looks it up by
 * pseudonym, which only a party already entitled to make that lookup can do, and the
 * broker should hold a distinct owner signing key per (vehicle, audience) so the
 * signature is not a join key either. For a *delegated* grant no out-of-band key is
 * needed at all: the expected signer is the parent's `counterparty_key`, so a chain
 * verifies itself up to the root and only the root needs the owner key.
 */

// ---------------------------------------------------------------------------------
// Ed25519 plumbing
// ---------------------------------------------------------------------------------

/**
 * Cloudflare Workers shipped Ed25519 under the non-standard name `NODE-ED25519` (with a
 * matching `namedCurve`) before the WebCrypto Secure Curves draft settled on plain
 * `Ed25519`. Newer builds expose the standard name and older ones do not, so resolve it
 * once by probing and cache the winner. Never hand-roll the curve.
 */
let resolvedEdAlgorithm = null

async function ed25519Algorithm() {
  if (resolvedEdAlgorithm) return resolvedEdAlgorithm
  const candidates = [{ name: 'Ed25519' }, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }]
  for (const alg of candidates) {
    try {
      // generateKey is the cheapest unambiguous probe: importKey('raw', ...) accepts
      // arbitrary 32-byte input on some builds and defers validation to verify time,
      // so a successful import would not prove the algorithm is really supported.
      await crypto.subtle.generateKey(alg, false, ['sign', 'verify'])
      resolvedEdAlgorithm = alg
      return alg
    } catch {
      // Not this name. Try the next.
    }
  }
  throw new Error(
    'no Ed25519 implementation in this runtime WebCrypto (tried "Ed25519" and the legacy ' +
      'Workers name "NODE-ED25519"); refusing to substitute another signature scheme',
  )
}

/** Fresh Ed25519 key pair. The private key is non-extractable. */
export async function generateSigningKeyPair() {
  const alg = await ed25519Algorithm()
  return crypto.subtle.generateKey(alg, false, ['sign', 'verify'])
}

/** Export a public CryptoKey to the base64url raw form the schema uses. */
export async function exportPublicKeyBase64url(publicKey) {
  const raw = await crypto.subtle.exportKey('raw', publicKey)
  return base64url(new Uint8Array(raw))
}

/** Import a base64url raw Ed25519 public key for verification. */
export async function importPublicKeyBase64url(b64) {
  if (!isBase64urlBytes(b64, ED25519_PUBLIC_KEY_BYTES)) {
    throw new Error(`public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes, base64url`)
  }
  const alg = await ed25519Algorithm()
  return crypto.subtle.importKey('raw', base64urlToBytes(b64), alg, true, ['verify'])
}

/**
 * The owner's revocation key identifier: a domain-separated SHA-256 thumbprint of the
 * raw public key. Domain-separated so the digest cannot be mistaken for, or replayed as,
 * any other SHA-256 in the system — notably a grant commitment.
 */
export async function revocationKeyIdFromPublicKey(rawPublicKeyBytes) {
  if (!(rawPublicKeyBytes instanceof Uint8Array) || rawPublicKeyBytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(`revocation public key must be a ${ED25519_PUBLIC_KEY_BYTES}-byte Uint8Array`)
  }
  const prefix = new TextEncoder().encode(REVOCATION_KEY_ID_DOMAIN)
  const buf = new Uint8Array(prefix.length + rawPublicKeyBytes.length)
  buf.set(prefix, 0)
  buf.set(rawPublicKeyBytes, prefix.length)
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return base64url(new Uint8Array(digest))
}

// ---------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------

/** Random 128-bit grant id, base64url. */
export function generateGrantId() {
  const bytes = new Uint8Array(GRANT_ID_BYTES)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

/**
 * Build an unsigned root Consent Grant. Validates hard and fails closed: any unknown
 * parameter, any field outside the closed vocabulary, any implausible timestamp, any
 * over-long duration and any malformed key is a thrown error, never a narrowed or
 * defaulted grant. A grant that quietly covers less — or more — than the owner read is
 * a consent defect, not a convenience (see validateFieldSet in fields.js).
 *
 * The VIN is consumed here and only here, solely to derive the pseudonym, and is never
 * retained. `assertNoRawVin` re-reads the finished object to prove that, so a future
 * refactor that starts copying the VIN into a debug field fails a test instead of
 * shipping.
 *
 * @param {object} params
 * @param {string} params.vin                 raw VIN — consumed, never stored
 * @param {string} params.pseudonymSalt       owner-held salt from generatePseudonymSalt()
 * @param {number} params.pseudonymEpoch      current rotation epoch
 * @param {string[]} params.fields            NF-2 field ids
 * @param {string} params.purpose             DPPA_PURPOSES key
 * @param {string} params.counterpartyClass   COUNTERPARTY_CLASSES value
 * @param {string} params.counterpartyKey     holder's raw Ed25519 public key, base64url
 * @param {string} params.revocationKeyId     owner revocation key thumbprint, base64url
 * @param {number} params.issuedAt            Unix seconds
 * @param {number} [params.expiresAt]         Unix seconds; or give durationSeconds
 * @param {number} [params.durationSeconds]
 * @param {number} [params.delegationDepth=0]
 * @param {string|null} [params.renewalOf=null]
 * @returns {Promise<object>} unsigned grant (`signature: null`)
 */
export async function buildGrant(params) {
  const p = requireParams(params, [
    'vin',
    'pseudonymSalt',
    'pseudonymEpoch',
    'fields',
    'purpose',
    'counterpartyClass',
    'counterpartyKey',
    'revocationKeyId',
    'issuedAt',
    'expiresAt',
    'durationSeconds',
    'delegationDepth',
    'renewalOf',
  ])

  // The VIN must be a syntactically valid name before we will pseudonymise it. Strict
  // check-digit enforcement is left to the enrolment path (vin.js documents why), but a
  // malformed VIN here means the pseudonym would be derived from a typo, and the grant
  // would be bound to a vehicle that does not exist.
  const v = validateVin(p.vin, { strict: false })
  if (!v.syntaxValid) throw new Error(`cannot build a grant for a malformed VIN: ${v.reason}`)

  const issuedAt = assertSafeInteger(p.issuedAt, 'issuedAt')
  const expiresAt = resolveExpiry(issuedAt, p.expiresAt, p.durationSeconds)
  // `=== undefined`, not `??`. NF-5 §6 DD-001 requires an explicit `null` depth to be
  // REFUSED, and it is right to: absence means "the caller did not specify, use the default",
  // while `null` is a value the caller wrote — typically straight out of a JSON request body
  // — and coercing it to 0 is precisely the silent default this module refuses everywhere
  // else. `?? 0` cannot tell the two apart.
  const delegationDepth = assertSafeInteger(
    p.delegationDepth === undefined ? 0 : p.delegationDepth,
    'delegationDepth',
  )

  // Audience === counterparty class. vin.js binds the pseudonym to the audience so two
  // simultaneous counterparties cannot join on it inside one epoch; recorded explicitly
  // in the grant (rather than left implicit) so a later schema version can widen the
  // audience domain without changing every verifier, and checked for equality here so
  // the two cannot disagree today.
  const pseudonym = await vehiclePseudonym(
    p.vin,
    p.pseudonymSalt,
    assertSafeInteger(p.pseudonymEpoch, 'pseudonymEpoch'),
    p.counterpartyClass,
  )

  const grant = assembleGrant({
    grantId: generateGrantId(),
    pseudonym: {
      value: pseudonym,
      epoch: p.pseudonymEpoch,
      audience: p.counterpartyClass,
      derivation: PSEUDONYM_DERIVATION,
    },
    fields: p.fields,
    purpose: p.purpose,
    issuedAt,
    expiresAt,
    counterpartyClass: p.counterpartyClass,
    counterpartyKey: p.counterpartyKey,
    revocationKeyId: p.revocationKeyId,
    delegationDepth,
    parentGrantId: null,
    renewalOf: p.renewalOf ?? null,
  })

  assertNoRawVin(grant, p.vin)
  return grant
}

/**
 * Mint an unsigned delegated sub-grant.
 *
 * WHY DELEGATION IS NOT TRANSFER. A transfer moves a capability from one holder to
 * another: the original holder loses it, the new holder gains it, and the owner's
 * decision — which was about a specific counterparty — is silently reassigned to a party
 * they never evaluated. That is what makes a capability an asset, and an asset is a thing
 * with a market. This module has no such operation and will not acquire one.
 *
 * Delegation is the opposite shape in the three ways that matter:
 *
 *  - It is *additive and bounded*. The parent survives and is unchanged. The child can
 *    only narrow: a subset of the fields, the same purpose, an expiry no later, a
 *    delegation depth one lower. Authority strictly decreases along the chain, so no
 *    sequence of delegations can produce more access than the owner granted once.
 *  - It is *attributable*. `parent_grant_id` records the edge, so the owner can see the
 *    whole subtree hanging off their grant. A transfer erases its own provenance; that
 *    is most of its appeal to the transferring party.
 *  - It *cascades on revocation*. Revoking the parent kills every descendant, because
 *    NF-4 walks `parent_grant_id`. The owner therefore keeps a single lever over
 *    arbitrarily many downstream holders, and the child's `revocation_key_id` is
 *    required to stay the owner's, so the owner can also cut one branch without
 *    disturbing the rest. A transferred capability would leave the owner holding a lever
 *    attached to nothing.
 *
 * Two consequences worth stating plainly, because they look like bugs and are not:
 *
 *  - The child carries the parent's `vehicle_pseudonym` VERBATIM, including the parent's
 *    audience. The delegator does not have the owner's salt and so cannot compute a fresh
 *    per-audience pseudonym — and should not be able to. A new pseudonym would mint a new
 *    linkability domain the owner never authorised; inheriting the parent's means the
 *    delegate's ability to correlate is bounded by the delegator's, which is the correct
 *    semantics for a controller/processor pair.
 *  - The child is signed by the DELEGATOR, whose key is `parent.counterparty_key`. So a
 *    chain is self-verifying: only the root needs an out-of-band owner key.
 *
 * @param {object} parentGrant signed parent
 * @param {object} params { fields, counterpartyClass, counterpartyKey, issuedAt,
 *                          expiresAt|durationSeconds, renewalOf? }
 * @returns {object} unsigned sub-grant
 */
export function mintDelegatedGrant(parentGrant, params) {
  const parentReasons = structuralReasons(parentGrant)
  if (parentReasons.length > 0) {
    throw new Error(`cannot delegate from a malformed parent grant: ${parentReasons.join('; ')}`)
  }
  if (typeof parentGrant.signature !== 'string') {
    throw new Error('cannot delegate from an unsigned grant: the authority being passed on is unproven')
  }
  if (parentGrant.delegation_depth <= 0) {
    throw new Error(
      `parent grant ${parentGrant.grant_id} has delegation_depth 0: the owner did not ` +
        'authorise delegation, and there is no operation that adds depth',
    )
  }

  const p = requireParams(params, [
    'fields',
    'counterpartyClass',
    'counterpartyKey',
    'issuedAt',
    'expiresAt',
    'durationSeconds',
    'renewalOf',
  ])

  const issuedAt = assertSafeInteger(p.issuedAt, 'issuedAt')
  const expiresAt = resolveExpiry(issuedAt, p.expiresAt, p.durationSeconds)
  if (expiresAt > parentGrant.expires_at) {
    throw new Error(
      `sub-grant expiry ${expiresAt} outlives its parent (${parentGrant.expires_at}); ` +
        'delegated authority cannot exceed the authority it derives from',
    )
  }

  const fields = normalizeFields(p.fields)
  const parentFields = new Set(parentGrant.fields)
  const broadened = fields.filter((f) => !parentFields.has(f))
  if (broadened.length > 0) {
    throw new Error(
      `sub-grant would broaden the field set beyond its parent: ${broadened.join(', ')}`,
    )
  }

  return assembleGrant({
    grantId: generateGrantId(),
    // Verbatim, including the parent's audience. See the doc comment.
    pseudonym: { ...parentGrant.vehicle_pseudonym },
    fields,
    // Purpose is inherited, not chosen. A delegate that could repurpose would defeat
    // DPPA purpose limitation by the simple expedient of delegating to itself.
    purpose: parentGrant.purpose,
    issuedAt,
    expiresAt,
    counterpartyClass: p.counterpartyClass,
    counterpartyKey: p.counterpartyKey,
    // The owner's revocation key, unchanged, so the owner can cut this branch directly
    // instead of having to revoke the parent and every sibling with it.
    revocationKeyId: parentGrant.revocation_key_id,
    delegationDepth: parentGrant.delegation_depth - 1,
    parentGrantId: parentGrant.grant_id,
    renewalOf: p.renewalOf ?? null,
  })
}

/**
 * Renew a root grant: mint a NEW grant that supersedes an existing one.
 *
 * Renewal is never an extension. `expires_at` is inside the signed bytes, so editing it
 * produces a different object under the same `grant_id`; a verifier that accepted either
 * form would be accepting a duration the owner never signed, and the two forms would
 * have different commitments so a revocation entry for one would miss the other. A
 * renewal therefore gets a fresh `grant_id`, fresh timestamps, a fresh signature, and
 * `renewal_of` pointing at what it replaces.
 *
 * A renewal may only narrow: subset of fields, same purpose, same holder key and class,
 * delegation depth no higher. Anything broader is a new consent decision and must be
 * built as one, because "renew" is what an owner clicks without reading.
 *
 * The superseded grant is not revoked by this call. Revocation is NF-4's mutable state;
 * the caller revokes the old grant_id (or lets it expire) in the same transaction that
 * stores the new one.
 *
 * Renewal needs the VIN and salt, so it is an owner/broker operation. A delegate renews
 * by asking its delegator to mint again — which is correct: the delegate has no
 * standing to extend its own authority.
 */
export async function renewGrant(previousGrant, params) {
  const reasons = structuralReasons(previousGrant)
  if (reasons.length > 0) {
    throw new Error(`cannot renew a malformed grant: ${reasons.join('; ')}`)
  }
  if (previousGrant.parent_grant_id !== null) {
    throw new Error(
      'cannot renew a delegated sub-grant: only the delegator can re-mint it, via ' +
        'mintDelegatedGrant against a live parent',
    )
  }

  const p = requireParams(params, [
    'vin',
    'pseudonymSalt',
    'pseudonymEpoch',
    'fields',
    'issuedAt',
    'expiresAt',
    'durationSeconds',
    'delegationDepth',
  ])

  const fields = normalizeFields(p.fields ?? previousGrant.fields)
  const previousFields = new Set(previousGrant.fields)
  const broadened = fields.filter((f) => !previousFields.has(f))
  if (broadened.length > 0) {
    throw new Error(
      `renewal would broaden the field set: ${broadened.join(', ')}. A broader grant is a ` +
        'new consent decision — build it with buildGrant',
    )
  }

  const delegationDepth = p.delegationDepth ?? previousGrant.delegation_depth
  if (delegationDepth > previousGrant.delegation_depth) {
    throw new Error('renewal cannot raise delegation_depth')
  }

  const grant = await buildGrant({
    vin: p.vin,
    pseudonymSalt: p.pseudonymSalt,
    // The epoch may have rotated since the previous grant, so the pseudonym is
    // recomputed rather than copied. A renewal under a new epoch is unlinkable to the
    // grant it replaces from the counterparty's side, which is the intended effect.
    pseudonymEpoch: p.pseudonymEpoch,
    fields,
    purpose: previousGrant.purpose,
    counterpartyClass: previousGrant.counterparty_class,
    counterpartyKey: previousGrant.counterparty_key,
    revocationKeyId: previousGrant.revocation_key_id,
    issuedAt: p.issuedAt,
    expiresAt: p.expiresAt,
    durationSeconds: p.durationSeconds,
    delegationDepth,
    renewalOf: previousGrant.grant_id,
  })
  return grant
}

/**
 * Assemble and validate. The single construction point, so every grant in the system —
 * root, delegated or renewed — passes the same structural gate. Key insertion order is
 * irrelevant: JCS sorts, which is the whole reason JCS exists.
 */
function assembleGrant(parts) {
  const grant = {
    v: SCHEMA_VERSION,
    grant_id: parts.grantId,
    vehicle_pseudonym: {
      value: parts.pseudonym.value,
      epoch: parts.pseudonym.epoch,
      audience: parts.pseudonym.audience,
      derivation: parts.pseudonym.derivation,
    },
    fields: normalizeFields(parts.fields),
    purpose: parts.purpose,
    issued_at: parts.issuedAt,
    expires_at: parts.expiresAt,
    counterparty_class: parts.counterpartyClass,
    counterparty_key: parts.counterpartyKey,
    revocation_key_id: parts.revocationKeyId,
    delegation_depth: parts.delegationDepth,
    parent_grant_id: parts.parentGrantId,
    renewal_of: parts.renewalOf,
    signature: null,
  }
  const reasons = structuralReasons(grant)
  if (reasons.length > 0) {
    throw new Error(`refusing to build an invalid grant: ${reasons.join('; ')}`)
  }
  return grant
}

/**
 * Sort and de-duplicate a field set with the same comparator JCS uses for keys, so one
 * semantic field set has exactly one canonical form and therefore exactly one
 * commitment. Duplicates are an error rather than something to collapse —
 * validateFieldSet rejects them, and silently accepting a set the caller wrote wrong is
 * how a grant ends up meaning something the owner did not read.
 */
function normalizeFields(fields) {
  if (!Array.isArray(fields)) throw new Error('fields must be an array')
  const check = validateFieldSet(fields)
  if (!check.ok) throw new Error(`invalid field set: ${check.reason}`)
  return Object.freeze([...fields].sort(compareCodeUnits))
}

function resolveExpiry(issuedAt, expiresAt, durationSeconds) {
  const bothGiven = expiresAt !== undefined && durationSeconds !== undefined
  const neitherGiven = expiresAt === undefined && durationSeconds === undefined
  if (bothGiven || neitherGiven) {
    throw new Error('give exactly one of expiresAt or durationSeconds')
  }
  const resolved =
    expiresAt !== undefined
      ? assertSafeInteger(expiresAt, 'expiresAt')
      : issuedAt + assertSafeInteger(durationSeconds, 'durationSeconds')
  if (resolved <= issuedAt) {
    throw new Error(`expires_at (${resolved}) must be after issued_at (${issuedAt})`)
  }
  if (resolved - issuedAt > MAX_GRANT_DURATION_S) {
    throw new Error(
      `grant duration ${resolved - issuedAt}s exceeds the ${MAX_GRANT_DURATION_S}s cap ` +
        '(45 days, pinned to the Delete Act deletion cadence)',
    )
  }
  return resolved
}

// ---------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------

/**
 * The exact bytes a signature covers: the grant with `signature` removed, canonicalised
 * per RFC 8785 and UTF-8 encoded.
 *
 * No external domain tag. The type binding is already inside the signed bytes as the
 * `v` field, so these bytes cannot be reinterpreted as a different kind of object
 * without changing them — and a future schema version must change `v`, which changes
 * every signature. Adding a second tag outside the canonical bytes would create a
 * second thing that has to agree with the first.
 */
export function grantSigningInput(grant) {
  const reasons = structuralReasons(grant)
  if (reasons.length > 0) {
    throw new Error(`refusing to compute a signing input for an invalid grant: ${reasons.join('; ')}`)
  }
  const unsigned = {}
  for (const key of GRANT_KEYS) {
    if (key === 'signature') continue
    unsigned[key] = grant[key]
  }
  return canonicalizeToBytes(unsigned)
}

/**
 * Sign a grant. Returns a NEW object; the input is not mutated, so a caller cannot end
 * up with two references to one grant disagreeing about whether it is signed.
 *
 * The signer is the owner for a root grant and the delegator for a sub-grant. Re-signing
 * an already-signed grant is refused: the only legitimate reasons to want a second
 * signature over the same content are key rotation and repudiation-shopping, and both
 * are served correctly by minting a new grant.
 *
 * @param {object} grant unsigned grant
 * @param {CryptoKey} privateKey Ed25519 private key
 * @returns {Promise<object>} signed grant
 */
export async function signGrant(grant, privateKey) {
  if (!isPlainObject(grant)) throw new Error('grant must be a plain object')
  if (grant.signature !== null) {
    throw new Error('grant is already signed; mint a new grant rather than re-signing this one')
  }
  const alg = await ed25519Algorithm()
  if (!privateKey || privateKey.type !== 'private') {
    throw new Error('signGrant requires an Ed25519 private CryptoKey')
  }
  if (privateKey.algorithm?.name !== alg.name) {
    // An RSA or ECDSA key would produce a signature no verifier in this system can ever
    // check. Better to refuse than to emit a grant that is permanently unverifiable.
    throw new Error(
      `signing key algorithm is ${privateKey.algorithm?.name}, expected ${alg.name}`,
    )
  }

  const input = grantSigningInput(grant)
  const sig = await crypto.subtle.sign(alg, privateKey, input)
  const signature = base64url(new Uint8Array(sig))
  if (signature.length !== base64urlLengthFor(ED25519_SIGNATURE_BYTES)) {
    throw new Error(`unexpected signature length from WebCrypto: ${signature.length} chars`)
  }
  return { ...grant, signature }
}

// ---------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------

/**
 * Verify a grant and return a structured verdict.
 *
 * Collects EVERY failure rather than stopping at the first, because the conformance
 * suite needs to assert which rule fired and an operator debugging a rejected grant
 * needs the whole picture. Reasons are `code: detail`, with a stable code prefix.
 *
 * Never throws. A verifier that throws on malformed input hands any caller a denial of
 * service, so unexpected errors become a reason and the verdict is invalid.
 *
 * Fails closed on missing inputs: with no verifying key, the verdict is invalid with
 * `verifier_key_missing`. There is no path through this function that returns
 * `valid: true` on an unchecked signature.
 *
 * NOT CHECKED HERE: revocation. That is mutable D1 state (NF-4). Pass `opts.revoked`
 * from the same request that read the revocation table. `valid: true` means the grant is
 * well formed, in date, in vocabulary and correctly signed — not that access is
 * authorised.
 *
 * @param {object} grant
 * @param {object} [opts]
 * @param {string|CryptoKey} [opts.ownerPublicKey] verifying key for a ROOT grant, out of
 *        band (deliberately not in the grant — see the schema note)
 * @param {object} [opts.parentGrant] the parent, required to verify a delegated grant.
 *        Supplies the expected signer key and the cascade invariants.
 * @param {string} [opts.presenterKey] base64url public key the presenter actually proved
 *        possession of in this session. Enforces counterparty binding.
 * @param {string[]} [opts.forbiddenRevocationKeyIds] ids known to be broker-held
 * @param {boolean} [opts.revoked] result of the NF-4 revocation lookup, if performed
 * @param {number} [opts.now] Unix seconds
 * @param {number} [opts.clockSkewS]
 * @returns {Promise<{ valid: boolean, reasons: string[] }>}
 */
export async function verifyGrant(grant, opts = {}) {
  const reasons = []
  try {
    reasons.push(...structuralReasons(grant))

    // Everything below reads specific fields, so only run it on a structurally sound
    // object. Reporting "expired" for something that is not a grant is noise.
    if (reasons.length === 0) {
      reasons.push(...temporalReasons(grant, opts))
      reasons.push(...bindingReasons(grant, opts))
      reasons.push(...(await revocationKeyReasons(grant)))
      reasons.push(...lineageReasons(grant, opts))
      reasons.push(...(await signatureReasons(grant, opts)))
    }

    if (opts.revoked === true) {
      reasons.push(`revoked: grant ${grant?.grant_id ?? '(unknown)'} is revoked in the NF-4 state`)
    }
  } catch (err) {
    // Fail closed on anything unforeseen.
    reasons.push(`internal: verification aborted (${err?.message ?? String(err)})`)
  }
  return { valid: reasons.length === 0, reasons }
}

/** Shape, closed vocabulary, non-transactability, ranges. Pure and synchronous. */
function structuralReasons(grant) {
  const reasons = []
  if (!isPlainObject(grant)) return ['shape: grant must be a plain object']

  for (const key of Object.keys(grant)) {
    if (!GRANT_KEY_SET.has(key)) {
      reasons.push(`unknown_field: "${key}" is not part of ${SCHEMA_VERSION}`)
    }
  }
  for (const key of GRANT_KEYS) {
    if (!Object.hasOwn(grant, key)) {
      reasons.push(`missing_field: "${key}" (optional fields are present as null, never omitted)`)
    }
  }
  for (const key of HOLDER_MUTATION_FIELDS) {
    if (Object.hasOwn(grant, key)) {
      reasons.push(`transferable_field_present: "${key}" — a Consent Grant has no holder-mutation field`)
    }
  }
  if (reasons.length > 0) return reasons

  if (grant.v !== SCHEMA_VERSION) {
    reasons.push(`schema_version_unsupported: "${String(grant.v)}", expected "${SCHEMA_VERSION}"`)
  }
  if (!isBase64urlBytes(grant.grant_id, GRANT_ID_BYTES)) {
    reasons.push(`grant_id_malformed: expected ${GRANT_ID_BYTES} random bytes, base64url`)
  }

  reasons.push(...pseudonymReasons(grant))

  const fieldCheck = validateFieldSet(grant.fields)
  if (!fieldCheck.ok) {
    // validateFieldSet is where the non-transactable classes are refused: precise
    // geolocation, biometrics and in-cabin A/V have no field id, so this is also the
    // non-transactability check (§8.2, §12.2).
    reasons.push(`fields_invalid: ${fieldCheck.reason}`)
  } else {
    const sorted = [...grant.fields].sort(compareCodeUnits)
    if (grant.fields.some((f, i) => f !== sorted[i])) {
      reasons.push(
        'fields_not_canonical_order: field ids must be sorted by UTF-16 code unit so one ' +
          'semantic grant has one commitment',
      )
    }
  }

  if (!isValidPurpose(grant.purpose)) {
    reasons.push(
      `purpose_unknown: "${String(grant.purpose)}" is not a DPPA §2721(b) key ` +
        `(${Object.keys(DPPA_PURPOSES).join(', ')})`,
    )
  }
  if (!isValidCounterpartyClass(grant.counterparty_class)) {
    reasons.push(
      `counterparty_class_unknown: "${String(grant.counterparty_class)}" ` +
        `(${COUNTERPARTY_CLASSES.join(', ')})`,
    )
  }
  if (!isBase64urlBytes(grant.counterparty_key, ED25519_PUBLIC_KEY_BYTES)) {
    reasons.push(`counterparty_key_malformed: expected a raw ${ED25519_PUBLIC_KEY_BYTES}-byte Ed25519 public key, base64url`)
  }
  if (!isBase64urlBytes(grant.revocation_key_id, REVOCATION_KEY_ID_BYTES)) {
    reasons.push(`revocation_key_id_malformed: expected a ${REVOCATION_KEY_ID_BYTES}-byte thumbprint, base64url`)
  }

  reasons.push(...timeShapeReasons(grant))

  if (!Number.isSafeInteger(grant.delegation_depth) || grant.delegation_depth < 0) {
    reasons.push('delegation_depth_invalid: must be a non-negative safe integer (0 = no delegation)')
  } else if (grant.delegation_depth > MAX_DELEGATION_DEPTH) {
    reasons.push(
      `delegation_depth_invalid: ${grant.delegation_depth} exceeds MAX_DELEGATION_DEPTH ${MAX_DELEGATION_DEPTH}`,
    )
  }

  for (const key of ['parent_grant_id', 'renewal_of']) {
    const value = grant[key]
    if (value !== null && !isBase64urlBytes(value, GRANT_ID_BYTES)) {
      reasons.push(`${key}_malformed: must be null or a grant_id`)
    }
  }
  if (grant.parent_grant_id !== null && grant.parent_grant_id === grant.grant_id) {
    reasons.push('parent_grant_id_malformed: a grant cannot be its own parent')
  }
  if (grant.renewal_of !== null && grant.renewal_of === grant.grant_id) {
    reasons.push('renewal_of_malformed: a grant cannot renew itself')
  }

  if (grant.signature !== null && !isBase64urlBytes(grant.signature, ED25519_SIGNATURE_BYTES)) {
    reasons.push(`signature_malformed: expected a ${ED25519_SIGNATURE_BYTES}-byte Ed25519 signature, base64url`)
  }

  return reasons
}

function pseudonymReasons(grant) {
  const reasons = []
  const ps = grant.vehicle_pseudonym
  if (!isPlainObject(ps)) return ['pseudonym_malformed: vehicle_pseudonym must be an object']

  for (const key of Object.keys(ps)) {
    if (!PSEUDONYM_KEY_SET.has(key)) reasons.push(`pseudonym_malformed: unknown member "${key}"`)
  }
  for (const key of PSEUDONYM_KEYS) {
    if (!Object.hasOwn(ps, key)) reasons.push(`pseudonym_malformed: missing member "${key}"`)
  }
  if (reasons.length > 0) return reasons

  // A 43-char base64url value cannot be a 17-character VIN. This is the structural
  // enforcement of Refusal 1 at verification time, where the VIN is not available to
  // compare against: the shape simply has no room for one.
  if (!isBase64urlBytes(ps.value, PSEUDONYM_BYTES)) {
    reasons.push(`pseudonym_malformed: value must be ${PSEUDONYM_BYTES} bytes, base64url`)
  }
  if (!Number.isSafeInteger(ps.epoch) || ps.epoch < 0) {
    reasons.push('pseudonym_malformed: epoch must be a non-negative safe integer')
  }
  if (ps.derivation !== PSEUDONYM_DERIVATION) {
    reasons.push(
      `pseudonym_derivation_unsupported: "${String(ps.derivation)}", expected "${PSEUDONYM_DERIVATION}"`,
    )
  }
  if (typeof ps.audience !== 'string' || ps.audience.length === 0) {
    reasons.push('pseudonym_malformed: audience is required; an unbound pseudonym is a correlation handle')
  } else if (grant.parent_grant_id === null && ps.audience !== grant.counterparty_class) {
    // Root grants only. A delegated grant inherits the parent's pseudonym verbatim, so
    // its audience is the DELEGATOR's class by design — see mintDelegatedGrant.
    reasons.push(
      `pseudonym_audience_mismatch: audience "${ps.audience}" does not match ` +
        `counterparty_class "${String(grant.counterparty_class)}"`,
    )
  }
  return reasons
}

function timeShapeReasons(grant) {
  const reasons = []
  for (const key of ['issued_at', 'expires_at']) {
    const t = grant[key]
    if (!Number.isSafeInteger(t)) {
      reasons.push(`${key}_malformed: must be an integer number of Unix SECONDS within ±(2^53-1)`)
    } else if (t < MIN_PLAUSIBLE_TIME_S || t > MAX_PLAUSIBLE_TIME_S) {
      reasons.push(
        `${key}_implausible: ${t} is outside [${MIN_PLAUSIBLE_TIME_S}, ${MAX_PLAUSIBLE_TIME_S}] — ` +
          'a millisecond timestamp or a broken clock',
      )
    }
  }
  if (reasons.length > 0) return reasons

  if (grant.expires_at <= grant.issued_at) {
    reasons.push(
      `expiry_not_after_issue: expires_at ${grant.expires_at} <= issued_at ${grant.issued_at}. ` +
        'There is no perpetual grant and no zero-length grant',
    )
  } else if (grant.expires_at - grant.issued_at > MAX_GRANT_DURATION_S) {
    reasons.push(
      `duration_exceeds_cap: ${grant.expires_at - grant.issued_at}s > ${MAX_GRANT_DURATION_S}s`,
    )
  }
  return reasons
}

function temporalReasons(grant, opts) {
  const reasons = []
  const now = opts.now ?? Math.floor(Date.now() / 1000)
  const skew = opts.clockSkewS ?? DEFAULT_CLOCK_SKEW_S
  if (!Number.isSafeInteger(now)) return ['internal: opts.now must be an integer number of seconds']

  if (now >= grant.expires_at) {
    reasons.push(`expired: expires_at ${grant.expires_at}, now ${now}`)
  }
  if (grant.issued_at > now + skew) {
    reasons.push(`issued_in_future: issued_at ${grant.issued_at} exceeds now ${now} + ${skew}s skew`)
  }
  return reasons
}

function bindingReasons(grant, opts) {
  const reasons = []

  // Counterparty binding. `presenterKey` is the key the presenter proved possession of
  // in THIS session (a challenge/response at the broker edge). Comparing it to
  // counterparty_key is what makes a stolen grant worthless: the grant is not a bearer
  // token, so replay by a different holder fails here rather than at some later
  // policy layer.
  if (opts.presenterKey !== undefined) {
    if (typeof opts.presenterKey !== 'string' || opts.presenterKey !== grant.counterparty_key) {
      reasons.push(
        'counterparty_binding_mismatch: the presented key is not the key this grant was ' +
          'issued to; a grant is not a bearer token',
      )
    }
  }

  const forbidden = opts.forbiddenRevocationKeyIds
  if (Array.isArray(forbidden) && forbidden.includes(grant.revocation_key_id)) {
    // Refusal 3, made enforceable: the Foundation and the broker do not hold revocation
    // authority over an owner's grant. The caller supplies the ids it operates so that
    // claim is tested rather than asserted.
    reasons.push(
      'revocation_key_forbidden: revocation_key_id is an operator-held key; only the owner ' +
        'may hold revocation authority',
    )
  }
  return reasons
}

/**
 * The holder must not be able to revoke on the owner's behalf. A revocation key the
 * grantee controls is not a revocation key — it is a promise, and a grantee will not
 * exercise it. Checkable from the grant alone, with no external input, because
 * `revocation_key_id` is a thumbprint of a public key and `counterparty_key` is a public
 * key: recompute the one from the other and compare.
 *
 * Both forms are checked. The raw-equality case catches the naive mistake of pasting the
 * key into the id field; the thumbprint case catches the actual attack, which is an
 * operator or a persuasive counterparty arranging for the grantee's own key to be the
 * nominal revocation authority.
 */
async function revocationKeyReasons(grant) {
  if (grant.revocation_key_id === grant.counterparty_key) {
    return [
      'revocation_key_held_by_counterparty: revocation_key_id is literally the grantee key; ' +
        'it must identify an OWNER-held key',
    ]
  }
  try {
    const thumbprint = await revocationKeyIdFromPublicKey(base64urlToBytes(grant.counterparty_key))
    if (thumbprint === grant.revocation_key_id) {
      return [
        'revocation_key_held_by_counterparty: revocation_key_id is the thumbprint of the ' +
          'grantee key, so the grantee would hold revocation authority over the owner',
      ]
    }
  } catch (err) {
    return [`internal: revocation-key thumbprint check failed (${err?.message ?? String(err)})`]
  }
  return []
}

/** Delegation-cascade invariants. Only meaningful when the parent is supplied. */
function lineageReasons(grant, opts) {
  const reasons = []
  const parent = opts.parentGrant

  if (grant.parent_grant_id === null) {
    if (parent !== undefined) {
      reasons.push('delegation_parent_mismatch: a parent grant was supplied for a root grant')
    }
    return reasons
  }

  if (parent === undefined) {
    // Fail closed: a delegated grant whose parent is unavailable cannot be shown to
    // derive from anything, and its expected signer key lives in the parent.
    return [
      `delegation_parent_missing: grant claims parent ${grant.parent_grant_id}, which was not ` +
        'supplied; a chain cannot be verified from its leaf alone',
    ]
  }

  const parentReasons = structuralReasons(parent)
  if (parentReasons.length > 0) {
    return [`delegation_parent_mismatch: supplied parent is malformed (${parentReasons.join('; ')})`]
  }
  if (parent.grant_id !== grant.parent_grant_id) {
    return [
      `delegation_parent_mismatch: supplied parent is ${parent.grant_id}, grant claims ` +
        `${grant.parent_grant_id}`,
    ]
  }
  if (typeof parent.signature !== 'string') {
    reasons.push('delegation_parent_mismatch: parent grant is unsigned')
  }

  if (grant.delegation_depth !== parent.delegation_depth - 1) {
    reasons.push(
      `delegation_depth_not_decremented: child ${grant.delegation_depth}, parent ` +
        `${parent.delegation_depth}; authority must strictly decrease along the chain`,
    )
  }
  const parentFields = new Set(parent.fields)
  const broadened = grant.fields.filter((f) => !parentFields.has(f))
  if (broadened.length > 0) {
    reasons.push(`delegation_fields_broadened: ${broadened.join(', ')} not present in the parent`)
  }
  if (grant.purpose !== parent.purpose) {
    reasons.push(
      `delegation_purpose_changed: "${grant.purpose}" vs parent "${parent.purpose}"; a ` +
        'delegate cannot repurpose',
    )
  }
  if (grant.expires_at > parent.expires_at) {
    reasons.push(
      `delegation_expiry_extends_parent: ${grant.expires_at} > ${parent.expires_at}`,
    )
  }
  if (grant.revocation_key_id !== parent.revocation_key_id) {
    reasons.push(
      'delegation_revocation_key_changed: a sub-grant keeps the owner revocation key so the ' +
        'owner can cut one branch without revoking the parent',
    )
  }
  // Canonicalisation is the cheapest correct deep-equality test available here, and it
  // is exactly the equality the signature cares about.
  if (canonicalize(grant.vehicle_pseudonym) !== canonicalize(parent.vehicle_pseudonym)) {
    reasons.push(
      'delegation_pseudonym_mismatch: a sub-grant carries the parent pseudonym verbatim; a ' +
        'fresh pseudonym would mint a linkability domain the owner never authorised',
    )
  }
  return reasons
}

async function signatureReasons(grant, opts) {
  if (grant.signature === null) return ['signature_missing: grant is unsigned']

  // The expected signer: the delegator for a sub-grant (its key is in the parent, so a
  // chain is self-verifying), the owner for a root grant (supplied out of band, because
  // an owner key inside the grant would be a cross-counterparty join key).
  let keyMaterial = opts.ownerPublicKey
  if (grant.parent_grant_id !== null) {
    const parent = opts.parentGrant
    if (!isPlainObject(parent) || parent.grant_id !== grant.parent_grant_id) {
      return ['verifier_key_missing: delegated grant needs its parent to supply the signer key']
    }
    keyMaterial = parent.counterparty_key
  }
  if (keyMaterial === undefined || keyMaterial === null) {
    return [
      'verifier_key_missing: no verifying key supplied. The signer key is deliberately not ' +
        'in the grant — resolve it by pseudonym',
    ]
  }

  let publicKey
  try {
    publicKey =
      typeof keyMaterial === 'string' ? await importPublicKeyBase64url(keyMaterial) : keyMaterial
  } catch (err) {
    return [`verifier_key_missing: verifying key could not be imported (${err?.message ?? String(err)})`]
  }

  let ok = false
  try {
    const alg = await ed25519Algorithm()
    ok = await crypto.subtle.verify(alg, publicKey, base64urlToBytes(grant.signature), grantSigningInput(grant))
  } catch (err) {
    return [`signature_invalid: verification failed (${err?.message ?? String(err)})`]
  }
  return ok ? [] : ['signature_invalid: Ed25519 signature does not verify over the canonical grant']
}

// ---------------------------------------------------------------------------------
// On-chain commitment (Refusal 2)
// ---------------------------------------------------------------------------------

/**
 * The ONLY thing about a grant that may cross onto an immutable ledger: a
 * domain-separated SHA-256 digest over the canonical grant.
 *
 * Everything else stays in D1, mutable and deletable, because a standing 45-day Delete
 * Act cadence and CCPA erasure rights cannot be reconciled with immutability (§9.5).
 * The digest is not personal information and nothing can be derived from it: it commits
 * to a pseudonym that is itself a keyed HMAC under an owner-held salt, so destroying the
 * salt destroys the linkage even for a party holding both the digest and a candidate
 * VIN. That is what makes erasure real rather than nominal.
 *
 * The digest covers the SIGNATURE as well as the payload, and that is deliberate.
 * Because the grant does not carry the signer's public key (anti-correlation, see the
 * schema note), the payload alone does not bind the issuer — two different owners could
 * in principle produce identical payloads. The signature is the only field that
 * distinguishes them, so a commitment that excluded it would be ambiguous about which
 * grant it commits to, and a revocation entry keyed by it could match a grant the owner
 * never issued. Unsigned grants are therefore refused.
 *
 * @param {object} grant signed grant
 * @returns {Promise<string>} base64url SHA-256 digest (43 chars)
 */
export async function deriveGrantCommitment(grant) {
  const reasons = structuralReasons(grant)
  if (reasons.length > 0) {
    throw new Error(`refusing to commit to an invalid grant: ${reasons.join('; ')}`)
  }
  if (grant.signature === null) {
    throw new Error(
      'refusing to commit to an unsigned grant: the commitment must bind the issuer, and ' +
        'the signature is the only field that does',
    )
  }
  // The domain ends in ':' and canonical JSON begins with '{', so the boundary is
  // unambiguous without a length prefix.
  const bytes = new TextEncoder().encode(COMMITMENT_DOMAIN + canonicalize(grant))
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return base64url(new Uint8Array(digest))
}

// ---------------------------------------------------------------------------------
// Non-transferability
// ---------------------------------------------------------------------------------

/**
 * Assert that a grant is what it claims to be: non-transferable.
 *
 * There is no transfer, assign, or reissue-to-new-holder operation in this module, and
 * there must never be one. This function is the executable statement of that invariant,
 * and it is a refusal rather than a mutation — the only holder-related operation the
 * module offers is checking that a presenter is the holder.
 *
 * Why it matters beyond tidiness: a transferable capability is an asset, an asset has a
 * price, and a priced consent object is Layer 5, which is gated behind securities law,
 * DFAL and Sherman Act §1 clearance and is out of V1 scope. Non-transferability is also
 * what keeps the owner's decision meaningful — they consented to a counterparty class
 * and a key, not to whoever that key later sells to. Delegation is the bounded,
 * attributable, cascade-revocable alternative; see `mintDelegatedGrant` for why the two
 * are different in kind and not in degree.
 *
 * @param {object} grant
 * @param {string} [presentedHolderKey] base64url key the presenter proved possession of
 * @returns {true}
 */
export function assertNonTransferable(grant, presentedHolderKey = null) {
  if (!isPlainObject(grant)) throw new Error('assertNonTransferable: grant must be a plain object')

  for (const key of HOLDER_MUTATION_FIELDS) {
    if (Object.hasOwn(grant, key)) {
      throw new Error(
        `non-transferability violated: grant carries "${key}". A Consent Grant has no ` +
          'holder-mutation field; delegation is the only way authority moves, and it ' +
          'narrows, records its parent, and cascades on revocation',
      )
    }
  }
  if (!isBase64urlBytes(grant.counterparty_key, ED25519_PUBLIC_KEY_BYTES)) {
    throw new Error('non-transferability violated: grant has no well-formed counterparty_key to bind to')
  }
  if (presentedHolderKey !== null && presentedHolderKey !== grant.counterparty_key) {
    throw new Error(
      `grant ${grant.grant_id} is bound to another holder's key and cannot be transferred, ` +
        'assigned or reissued to this one; the holder must obtain their own grant, or a ' +
        'delegated sub-grant from the current holder',
    )
  }
  return true
}

// ---------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------

function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

/** Unpadded base64url length for n bytes. */
function base64urlLengthFor(byteLength) {
  return Math.ceil((byteLength * 4) / 3)
}

/**
 * Strict base64url of an exact byte length. Strict about length AND charset before
 * decoding: a lenient check would let a value with padding, whitespace or standard-
 * alphabet characters round-trip to different bytes on different decoders, and every
 * one of these values is inside a signature.
 */
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

/**
 * Reject unknown parameter names. A silently-ignored misspelled parameter is how a
 * grant ends up with a default nobody chose — `expiresAT` ignored, `durationSeconds`
 * absent, and the call either throws late or produces something unintended.
 */
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

/**
 * Prove Refusal 1 structurally on freshly built grants: the raw VIN must not appear
 * anywhere in the canonical bytes. Cheap, and it catches the specific future mistake of
 * someone adding a convenience field during debugging and leaving it in.
 */
function assertNoRawVin(grant, vin) {
  const canonical = canonicalize(grant)
  const candidates = new Set([String(vin), String(vin).trim().toUpperCase()])
  for (const needle of candidates) {
    if (needle.length >= 11 && canonical.includes(needle)) {
      throw new Error(
        'REFUSAL 1 VIOLATION: the raw VIN appears in the grant payload. The VIN is a public ' +
          'index and must never travel inside a capability object; only the salted, rotating ' +
          'pseudonym may',
      )
    }
  }
}
