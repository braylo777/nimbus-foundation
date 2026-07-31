/**
 * NF-3 VIN Resolution Protocol: the VIN as a DNS name.
 *
 * Nimbus Foundation NF-WP-1 §3.1 (Layer 3), §8.3, §10.1, §12.7, §14.
 *
 * §8.3 names the architecture, and it is not a loose metaphor — it is the design. Mockapetris
 * (RFC 1034/1035, 1987) solved the exact problem the consent layer has: a globally visible,
 * publicly enumerable name must be resolvable by anyone, the answer must come from whoever is
 * authoritative for that part of the namespace rather than from a central registry, and the
 * answer must be cacheable so that resolution does not funnel every lookup through one party.
 *
 *   DNS                                  NF-3
 *   ---------------------------------    ------------------------------------------------
 *   domain name                          VIN — public, enumerable, visible through a windshield
 *   A / AAAA record (an address)          'ce' record — the consent endpoint's URL
 *   NS + DS record (a referral)           'delegation' record — a child zone and its key
 *   NXDOMAIN + SOA MINIMUM                'nxenroll' / 'nxzone' — signed negative answers
 *   TTL, counted down by every cache      ttl, stored as an absolute expiry and counted down
 *   iterative vs. recursive resolution    mode: 'iterative' | 'recursive'
 *   root hints (configuration, unsigned)  trust anchors — but the KEY is what is authoritative
 *   DNSSEC RRSIG chain of trust           Ed25519-signed answers, anchor -> delegation -> answer
 *   bailiwick / in-zone checking          zone scope checks; no zone answers outside its scope
 *   Kaminsky: 16-bit txid + glue          128-bit nonce inside the signature; NO glue section
 *
 * THE POINT OF THE ANALOGY, and the reason it is exact rather than decorative: resolving
 * `example.com` to `93.184.216.34` grants no right to anything at that address. The name
 * system tells you WHERE to ask. Whether you may have what you find there is a separate
 * question, answered by a separate mechanism, at the endpoint. NF-3 has the same shape.
 * Resolution returns a location. Authorisation is an NF-2 Consent Grant presented to the
 * endpoint the location names, and the endpoint decides.
 *
 * The three refusals (§10.1) as they land here:
 *
 *  1. *Never resolve a VIN to a credential.* This is the module where that refusal is most
 *     tempting to break, because "resolve" invites the reader to expect an answer that opens
 *     something. There is no branch in this file that can return a token, credential,
 *     session, cookie, bearer value, or an authorisation decision. That is enforced three
 *     ways, not asserted once: closed key sets on every record and answer type, a recursive
 *     credential-shape scan (`assertNoCredentialSurface`) run on every object that enters or
 *     leaves, and a consent-endpoint URL grammar that forbids the query string, the fragment
 *     and the userinfo component outright — because every real credential-in-a-location is
 *     one of those three (a presigned URL's `?X-Amz-Signature=`, an OAuth implicit-flow
 *     `#access_token=`, an HTTP-Basic `user:pass@`). See `NF3_NO_CREDENTIAL_INVARIANT`,
 *     which exists so NF-5 can assert the absence rather than trust this comment.
 *
 *  2. *No personal information on an immutable ledger.* Nothing in this module writes to a
 *     ledger at all. The resolution cache is D1 and the Workers Cache API — mutable,
 *     deletable, sweepable (`sweepResolutionCache`, `purgeResolutionCache`), because a
 *     45-day Delete Act cadence and CCPA erasure cannot be reconciled with immutability
 *     (§9.5). The cache stores a digest of the name, never the VIN, so the cache is not a
 *     shadow copy of the query log.
 *
 *  3. *The Foundation does not operate what it governs.* The root zone is a DEFAULT, not a
 *     requirement: any zone may be configured as a trust anchor, so a resolver can be pointed
 *     at a WMI zone or an operator zone and never speak to the root. A root that cannot be
 *     bypassed is a licensor of access, which is the thing the Foundation must not be. There
 *     is no price, no payment, no token and no settlement in this file; resolution is free
 *     the way DNS is free, and metering it would be Layer 5 (§9.7).
 */

import { FIELD_CLASSES, NON_TRANSACTABLE } from './fields.js'
import { base64url, base64urlToBytes, validateVin, wmi } from './vin.js'
import { canonicalizeToBytes, compareCodeUnits } from './jcs.js'
import {
  DEFAULT_CLOCK_SKEW_S,
  MAX_PLAUSIBLE_TIME_S,
  MIN_PLAUSIBLE_TIME_S,
  importPublicKeyBase64url,
} from './nf2-grant.js'

// ---------------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------------

/** Version of the resolution *result* this module returns to its caller. */
export const NF3_RESOLUTION_VERSION = 'nf3-resolution/1'

/** Version of the signed answer on the wire. Inside the signed bytes, so undowngradeable. */
export const NF3_ANSWER_VERSION = 'nf3-answer/1'

/** Version of the question on the wire. */
export const NF3_QUESTION_VERSION = 'nf3-question/1'

/**
 * Endpoint protocols a resolved `ce` record may advertise. Closed, and an unknown value is a
 * rejection rather than a pass-through: handing a caller a location it cannot safely speak to
 * is worse than telling it resolution failed, because the caller will try anyway.
 *
 * No `alg` field appears anywhere in this module for the same reason NF-2 has none — the
 * signature suite is pinned by `v`, which is inside the signed bytes. A verifier that reads
 * the algorithm out of the object it is verifying is the JWT `alg` bug class.
 */
export const SUPPORTED_ENDPOINT_PROTOCOLS = Object.freeze(['nf3-endpoint/1'])

// ---------------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------------

/**
 * The four record types, and nothing else. `ce` is the A record; `delegation` is NS+DS;
 * `nxenroll` and `nxzone` are the two authenticated denials.
 *
 * Two kinds of denial because they mean different things to the caller and to the network.
 * `nxenroll` — the authoritative zone for this vehicle exists and this vehicle is not enrolled
 * in it. `nxzone` — no zone claims this VIN's scope at all, so nobody is authoritative and the
 * caller has no one to ask. Collapsing them would hide a manufacturer-scale gap behind what
 * looks like a single owner's choice not to participate.
 */
export const NF3_RECORD_TYPES = Object.freeze(['ce', 'delegation', 'nxenroll', 'nxzone'])

const POSITIVE_RECORD_TYPES = Object.freeze(['ce'])
const NEGATIVE_RECORD_TYPES = Object.freeze(['nxenroll', 'nxzone'])
const TERMINAL_RECORD_TYPES = Object.freeze(['ce', 'nxenroll', 'nxzone'])

/**
 * Closed key sets, one per record type, every key always present with explicit `null` where
 * unused — the NF-2 rule, for the NF-2 reason. Absence and explicit null canonicalise to
 * different bytes, so allowing both would give one semantic answer two signing inputs, and a
 * cache keyed by one form would not recognise the other.
 */
export const NF3_RECORD_KEYS = Object.freeze({
  ce: Object.freeze(['type', 'endpoint', 'protocol_version', 'supported_field_classes', 'broker_key']),
  delegation: Object.freeze(['type', 'child_zone', 'child_zone_key', 'child_endpoint']),
  nxenroll: Object.freeze(['type']),
  nxzone: Object.freeze(['type']),
})

/** Closed key set for the signed answer envelope. */
export const NF3_ANSWER_KEYS = Object.freeze([
  'v',
  'qname_digest',
  'zone',
  'record',
  'ttl',
  'answered_at',
  'nonce',
  'signer_key_id',
  'signature',
])

/** Closed key set for a zone identity. Mirrors the `vehicle_pseudonym` sub-object in NF-2. */
export const NF3_ZONE_KEYS = Object.freeze(['id', 'scope_type', 'scope'])

/** Closed key set for the resolution result. Asserted by `assertResolutionReturnsLocationsOnly`. */
export const NF3_RESULT_KEYS = Object.freeze([
  'v',
  'status',
  'qname_digest',
  'vin_syntax',
  'endpoint',
  'referral',
  'authenticated',
  'ttl_remaining_s',
  'expires_at',
  'source',
  'chain',
  'reasons',
  'notes',
])

/** Closed key set for the endpoint the caller actually gets. Locations only. */
export const NF3_ENDPOINT_KEYS = Object.freeze([
  'url',
  'protocol_version',
  'supported_field_classes',
  'broker_key',
  'zone',
])

/** Closed status set. */
export const NF3_STATUSES = Object.freeze(['resolved', 'not-enrolled', 'no-zone', 'referral', 'error'])

// ---------------------------------------------------------------------------------
// Zone scopes and who may answer what
// ---------------------------------------------------------------------------------

/**
 * Three scope types. `root` is the default entry point, `wmi` is manufacturer-scoped
 * (ISO 3779 World Manufacturer Identifier, the first three VIN characters), `operator` is
 * scoped to a named participant such as a fleet.
 *
 * The delegation grammar is deliberately tiny — root delegates to a WMI zone, a WMI zone
 * delegates to an operator zone, an operator zone is terminal — and it is what makes the
 * namespace distributable *without* making it hijackable. The load-bearing asymmetry:
 *
 *  - A `wmi` zone's bailiwick is computable from the name alone. `wmi('1HGCM82633A004352')`
 *    is `'1HG'`, so any resolver can check offline that a WMI zone is answering inside its
 *    own scope. This is the DNS in-bailiwick rule, and it is why a WMI zone cannot answer
 *    for another manufacturer's vehicles even if it is reached legitimately.
 *  - An `operator` zone's bailiwick is NOT computable from the name — a fleet's VINs are
 *    scattered across manufacturers. So an operator zone gets NO standing namespace claim.
 *    It is introduced per-name, by its parent, in a delegation whose `qname_digest` is the
 *    name being resolved and which is inside the parent's signature. A fleet operator
 *    therefore cannot answer for a vehicle it was not delegated, which is the property that
 *    lets resolution be polycentric without letting any participant claim someone else's
 *    vehicle.
 */
export const NF3_SCOPE_TYPES = Object.freeze(['root', 'wmi', 'operator'])

/**
 * Which record types each scope type may put its signature on. Enforced in
 * `verifyResolutionAnswer`, not left to the zone's good behaviour: the root answering a `ce`
 * record directly would be the root operating the market it governs (Refusal 3), and an
 * operator answering a `delegation` would extend a per-name claim into a standing one.
 */
const ZONE_ANSWER_POLICY = Object.freeze({
  root: Object.freeze(['delegation', 'nxzone']),
  wmi: Object.freeze(['ce', 'delegation', 'nxenroll']),
  operator: Object.freeze(['ce', 'nxenroll']),
})

/** Which scope types a given scope type may delegate to. */
const ZONE_DELEGATION_POLICY = Object.freeze({
  root: Object.freeze(['wmi']),
  wmi: Object.freeze(['operator']),
  operator: Object.freeze([]),
})

/**
 * Referral hop ceiling. The grammar above admits exactly root -> wmi -> operator, so three
 * queries is the whole namespace and anything more is a loop or a zone trying to walk a
 * resolver somewhere. Loop detection by visited-zone set runs as well, because a bound alone
 * turns a cycle into three wasted round trips instead of a refusal.
 */
export const MAX_REFERRAL_HOPS = 3

// ---------------------------------------------------------------------------------
// TTL policy
// ---------------------------------------------------------------------------------

/**
 * TTL floors and ceilings, in seconds, per answer class.
 *
 * WHY A FLOOR AT ALL — this is the non-obvious half. A zone that serves `ttl: 0` forces every
 * resolver in the network to return to it for every lookup. That is not a performance bug, it
 * is a centralisation lever hidden inside a protocol whose entire purpose is polycentrism
 * (§8.3): the zone with the shortest TTL sees the most traffic and becomes the chokepoint and
 * the observation point. The floor makes caching non-optional, so no zone can make itself
 * mandatory-online. It also caps the amplification a zone can inflict on the rest of the
 * network by misconfiguration.
 *
 * WHY THE POSITIVE CEILING IS AN HOUR. The cached `ce` answer carries the endpoint URL, the
 * broker's verification key, and the field classes the broker serves. A stale cache delays
 * three things: key rotation, endpoint withdrawal, and — the one that matters — the network
 * noticing that a broker has been taken out of service. One hour is the exposure window we
 * accept, and it is acceptable *only because a resolution answer is not an authorisation*: a
 * stale location cannot serve data, because the endpoint at that location still demands a
 * valid, unrevoked NF-2 grant. If resolution granted anything, an hour would be indefensible.
 *
 * WHY THE NEGATIVE CEILING IS A MINUTE — SHORTER THAN POSITIVE, DELIBERATELY. An unenrolled
 * vehicle can enrol at any instant. Enrolment is the owner's affirmative act: they decided to
 * be findable. A long negative TTL means the network keeps answering "not enrolled" for that
 * long after the owner has already said otherwise — the resolver becomes the thing that
 * suppresses the owner's own decision, which is a consent defect and not a caching trade-off.
 * A stale positive answer is the milder failure (the endpoint re-checks), a stale negative is
 * the harsher one (the owner is invisible and has no way to tell). RFC 2308 caps negative
 * caching at three hours; we are two orders of magnitude below that, on purpose.
 *
 * `nxzone` gets the same short ceiling as `nxenroll` and not a longer one, even though a
 * manufacturer joining is rarer than a vehicle enrolling. Same reasoning: somebody acted, and
 * the network's job is to notice.
 *
 * WHY REFERRALS GET A DAY. A zone's *existence and key* are stable in a way its per-vehicle
 * contents are not; DNS gives NS records long TTLs for the same reason. The cost is that zone
 * key rotation is slow, which is what `signer_key_id` and `purgeResolutionCache` are for.
 */
export const NF3_TTL_POLICY = Object.freeze({
  positive: Object.freeze({ floor_s: 60, ceiling_s: 3600, default_s: 300 }),
  negative: Object.freeze({ floor_s: 5, ceiling_s: 60, default_s: 30 }),
  referral: Object.freeze({ floor_s: 300, ceiling_s: 86400, default_s: 3600 }),
})

/** Absolute sanity bound on a TTL integer before clamping. Ten years is not a caching hint. */
const MAX_ACCEPTABLE_TTL_S = 10 * 365 * 24 * 60 * 60

/**
 * How stale a *network* answer may be, in seconds, independent of its TTL. Defence in depth
 * behind the nonce: the nonce already makes a replayed answer detectable, and this bounds the
 * window in which a stolen-and-replayed answer is even worth attempting.
 */
export const MAX_ANSWER_AGE_S = 60

/** Default network timeout per zone query. A resolver with no timeout is a hang. */
export const DEFAULT_QUERY_TIMEOUT_MS = 3000

/** Cap on a zone response body. A resolver must not be a memory sink for a hostile zone. */
const MAX_ANSWER_BODY_BYTES = 16 * 1024

/** Cap on an endpoint URL. Nothing legitimate is long, and length is smuggling capacity. */
const MAX_ENDPOINT_URL_LENGTH = 512

const NONCE_BYTES = 16
const ED25519_PUBLIC_KEY_BYTES = 32
const ED25519_SIGNATURE_BYTES = 64
const DIGEST_BYTES = 32

/** Domain separation. Each digest in this system must be unmistakable for any other. */
const QNAME_DIGEST_DOMAIN = 'nf3-qname:v1:'
const ZONE_KEY_ID_DOMAIN = 'nf3-zone-key-id:v1:'

// ---------------------------------------------------------------------------------
// Refusal 1, made structural
// ---------------------------------------------------------------------------------

/**
 * Key names that must never appear anywhere in a record, an answer, or a resolution result.
 *
 * The closed key sets above already reject every one of these, so this list is the second
 * lock, not the first. It exists for two reasons: `assertNoCredentialSurface` can be pointed
 * at an arbitrary object (a zone's raw response, a cache row, a candidate result) where the
 * closed-key check has not run yet, and NF-5 needs a concrete enumeration to assert against
 * rather than a claim in a comment.
 *
 * Matching is on a normalised name — lowercased with `-` and `_` removed — so `Set-Cookie`,
 * `set_cookie` and `setCookie` are one thing.
 */
export const NF3_FORBIDDEN_KEY_NAMES = Object.freeze([
  'token',
  'accesstoken',
  'idtoken',
  'refreshtoken',
  'bearer',
  'bearertoken',
  'authorization',
  'authorisation',
  'credential',
  'credentials',
  'session',
  'sessionid',
  'sessiontoken',
  'cookie',
  'setcookie',
  'apikey',
  'apisecret',
  'secret',
  'secretkey',
  'password',
  'passphrase',
  'privatekey',
  'keymaterial',
  'jwt',
  'assertion',
  'saml',
  'signedurl',
  'presignedurl',
  'sastoken',
  'grant',
  'consentgrant',
  'authorized',
  'authorised',
  'permitted',
  'allowed',
  'decision',
  'scope_granted',
])

const FORBIDDEN_KEY_SET = new Set(NF3_FORBIDDEN_KEY_NAMES.map(normalizeKeyName))

/**
 * Value shapes that are credentials regardless of what they are called. A resolution answer
 * has no legitimate reason to contain a JWT or an `Authorization` header value, so finding
 * one means either a zone is trying to smuggle authority through a location or somebody has
 * wired an OAuth flow into a name system.
 *
 * The JWT pattern requires a literal `.`, which the base64url alphabet excludes — so a
 * signature, a digest and a key can never trip it.
 */
const CREDENTIAL_VALUE_PATTERNS = Object.freeze([
  /^\s*bearer\s+\S/i,
  /^\s*basic\s+[A-Za-z0-9+/=]{8,}/i,
  /^ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./,
])

/**
 * The exported statement of the guarantee, for NF-5 to assert against.
 *
 * NF-5 tests "absence of any code path that resolves a VIN to a credential". A conformance
 * suite cannot prove a negative about arbitrary code, so this constant plus the two exported
 * assertions are the surface that makes the negative checkable: the result key set is closed
 * and enumerated here, the endpoint sub-object key set is closed and enumerated here, the
 * forbidden names are enumerated here, and the URL grammar is enumerated here. A future
 * change that added a credential-shaped output would have to edit this constant to pass, and
 * editing it is a visible act in review.
 */
export const NF3_NO_CREDENTIAL_INVARIANT = Object.freeze({
  id: 'NF3-REFUSAL-1',
  statement:
    'NF-3 resolution returns locations only. No branch of this module can return a token, ' +
    'credential, session, cookie, bearer value, key material, or an authorisation decision. ' +
    'Possession of a VIN, and possession of any resolution answer over that VIN, confers no ' +
    'authority anywhere. Authorisation is an NF-2 Consent Grant presented to the endpoint a ' +
    'resolution names, and the endpoint decides.',
  white_paper: 'NF-WP-1 §8.3, §10.1',
  dns_analogy:
    'Resolving a name to an address grants no right to the resource at that address. NF-3 ' +
    'inherits that property from DNS deliberately, not incidentally.',
  forbidden_key_names: NF3_FORBIDDEN_KEY_NAMES,
  result_keys: NF3_RESULT_KEYS,
  endpoint_keys: NF3_ENDPOINT_KEYS,
  answer_keys: NF3_ANSWER_KEYS,
  record_keys: NF3_RECORD_KEYS,
  endpoint_url_rules: Object.freeze([
    'https only (http permitted for loopback only, and only under an explicit opt-in)',
    'no query string — this is where a presigned-URL credential lives',
    'no fragment — this is where an OAuth implicit-flow access token lives',
    'no userinfo — this is where an HTTP Basic credential lives, and it is also the ' +
      'https://evil.example@good.example origin-confusion trick',
    'no credentials in any component; length capped at ' + MAX_ENDPOINT_URL_LENGTH,
    'hostname must be ASCII letters, digits, dots and hyphens after URL parsing, which ' +
      'eliminates Unicode homograph hosts by construction',
    'no loopback, private, link-local or cloud-metadata address (169.254.169.254) unless ' +
      'explicitly opted into, because a resolver that fetches attacker-chosen URLs is an ' +
      'SSRF primitive',
  ]),
  assertions: Object.freeze(['assertNoCredentialSurface', 'assertResolutionReturnsLocationsOnly']),
  note:
    'broker_key and child_zone_key are PUBLIC verification keys and are not credentials: ' +
    'they let the holder CHECK what a broker or a zone says. A verification key is the ' +
    'opposite of a credential — it confers the ability to detect a lie, not to act.',
})

/**
 * Refuse any object carrying a credential-shaped key or a credential-shaped string value,
 * anywhere in its structure. Throws — this is an invariant, not a validation result.
 *
 * @param {unknown} value
 * @param {string} [label] path label for the error message
 * @returns {true}
 */
export function assertNoCredentialSurface(value, label = '$') {
  walk(value, label, 0)
  return true

  function walk(v, path, depth) {
    if (depth > 32) {
      throw new Error(`${path}: structure too deep to audit for credential surface`)
    }
    if (typeof v === 'string') {
      for (const pattern of CREDENTIAL_VALUE_PATTERNS) {
        if (pattern.test(v)) {
          throw new Error(
            `REFUSAL 1 VIOLATION at ${path}: value has the shape of a credential ` +
              '(bearer/basic/JWT). NF-3 returns locations, never authority',
          )
        }
      }
      return
    }
    if (v === null || typeof v !== 'object') return
    if (Array.isArray(v)) {
      v.forEach((item, i) => walk(item, `${path}[${i}]`, depth + 1))
      return
    }
    for (const [key, sub] of Object.entries(v)) {
      if (FORBIDDEN_KEY_SET.has(normalizeKeyName(key))) {
        throw new Error(
          `REFUSAL 1 VIOLATION at ${path}.${key}: "${key}" is a credential-bearing name. ` +
            'NF-3 resolution returns WHERE to ask for authorisation, never authorisation itself',
        )
      }
      walk(sub, `${path}.${key}`, depth + 1)
    }
  }
}

/**
 * Assert that a resolution result is a location and nothing more. The check NF-5 runs on
 * every result the conformance suite produces, including the error and negative cases —
 * especially those, because an error path is where a convenience field gets added.
 *
 * @param {object} result
 * @returns {true}
 */
export function assertResolutionReturnsLocationsOnly(result) {
  if (!isPlainObject(result)) throw new Error('resolution result must be a plain object')

  const allowed = new Set(NF3_RESULT_KEYS)
  for (const key of Object.keys(result)) {
    if (!allowed.has(key)) {
      throw new Error(`resolution result carries unknown key "${key}"; the key set is closed`)
    }
  }
  for (const key of NF3_RESULT_KEYS) {
    if (!Object.hasOwn(result, key)) throw new Error(`resolution result is missing "${key}"`)
  }
  if (!NF3_STATUSES.includes(result.status)) {
    throw new Error(`resolution result status "${String(result.status)}" is outside the closed set`)
  }

  if (result.endpoint !== null) {
    if (!isPlainObject(result.endpoint)) throw new Error('endpoint must be null or a plain object')
    const endpointAllowed = new Set(NF3_ENDPOINT_KEYS)
    for (const key of Object.keys(result.endpoint)) {
      if (!endpointAllowed.has(key)) {
        throw new Error(`endpoint carries unknown key "${key}"; locations only`)
      }
    }
    // The invariant that makes the whole module safe to call: an endpoint is only ever
    // handed out when its chain of signatures verified. There is no "probably fine" path.
    if (result.authenticated !== true) {
      throw new Error(
        'endpoint present on an unauthenticated result: a resolver that returns an ' +
          'unverified location is a cache-poisoning primitive',
      )
    }
  }
  assertNoCredentialSurface(result, 'result')
  return true
}

// ---------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------

/**
 * The wire name for a VIN: a domain-separated SHA-256 digest, base64url.
 *
 * BE CLEAR ABOUT WHAT THIS IS AND IS NOT. It is NOT confidentiality. A VIN has perhaps 10^8
 * of realistic entropy once make, model and year are known (see vin.js), so an unsalted
 * digest is a rainbow-table lookup and anyone who wants to test a candidate VIN can. Claiming
 * otherwise would be the same mistake as treating a VIN as a secret.
 *
 * It is data minimisation, which is a smaller and real benefit: the raw VIN stays out of
 * cache keys, out of URLs, out of edge logs and out of D1 rows. The Delete Act expressly
 * enumerates vehicle identification numbers as a category of collected personal information
 * (§9.5), so a cache full of raw VINs is a regulated dataset while a cache full of digests is
 * materially less of one. It also binds an answer to its question — the Kaminsky lesson —
 * which is the property `verifyResolutionAnswer` actually depends on.
 *
 * WHY NOT USE THE NF-2 `vehiclePseudonym` AS THE WIRE NAME? Because it cannot work, and the
 * reason is worth writing down before someone tries. The pseudonym is an HMAC under an
 * owner-held salt. A querier resolving a VIN it read off a windshield does not have the salt
 * and never will, so it cannot compute the pseudonym and therefore cannot form the question.
 * A name system whose names only the answerer can compute is not a name system. The pseudonym
 * is for the grant, where the party holding it is already entitled to the linkage; the qname
 * digest is for resolution, where the querier is a stranger.
 *
 * @param {string} vin
 * @returns {Promise<string>} base64url, 43 chars
 */
export async function qnameDigest(vin) {
  const v = validateVin(vin, { strict: false })
  if (!v.syntaxValid) throw new Error(`cannot form a resolution name from a malformed VIN: ${v.reason}`)
  const bytes = new TextEncoder().encode(QNAME_DIGEST_DOMAIN + v.normalized)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return base64url(new Uint8Array(digest))
}

/** A zone's key identifier: domain-separated SHA-256 thumbprint of its raw public key. */
export async function zoneKeyIdFromPublicKey(rawPublicKeyBytes) {
  if (!(rawPublicKeyBytes instanceof Uint8Array) || rawPublicKeyBytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(`zone public key must be a ${ED25519_PUBLIC_KEY_BYTES}-byte Uint8Array`)
  }
  const prefix = new TextEncoder().encode(ZONE_KEY_ID_DOMAIN)
  const buf = new Uint8Array(prefix.length + rawPublicKeyBytes.length)
  buf.set(prefix, 0)
  buf.set(rawPublicKeyBytes, prefix.length)
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return base64url(new Uint8Array(digest))
}

/** Zone key id from the base64url form the records carry. */
export async function zoneKeyIdFromBase64url(b64) {
  if (!isBase64urlBytes(b64, ED25519_PUBLIC_KEY_BYTES)) {
    throw new Error('zone key must be a 32-byte base64url Ed25519 public key')
  }
  return zoneKeyIdFromPublicKey(base64urlToBytes(b64))
}

/**
 * Construct a zone identity. `id` is derived from scope rather than free-form, so two zones
 * cannot claim the same scope under different names and a resolver's visited-set is a real
 * loop detector rather than a set of aliases.
 *
 * @param {'root'|'wmi'|'operator'} scopeType
 * @param {string} scope  '*' for root, the WMI for a wmi zone, an operator id otherwise
 */
export function makeZone(scopeType, scope) {
  if (!NF3_SCOPE_TYPES.includes(scopeType)) {
    throw new Error(`unknown zone scope type "${String(scopeType)}"`)
  }
  if (scopeType === 'root') {
    if (scope !== undefined && scope !== '*') throw new Error('the root zone scope is "*"')
    return Object.freeze({ id: 'root', scope_type: 'root', scope: '*' })
  }
  if (typeof scope !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(scope)) {
    throw new Error(
      `zone scope "${String(scope)}" must be 1-63 chars of [A-Za-z0-9._-] starting alphanumeric`,
    )
  }
  if (scopeType === 'wmi') {
    const upper = scope.toUpperCase()
    // A WMI is three ISO 3779 characters. Anything else is not a manufacturer scope, and a
    // zone claiming a longer prefix would be claiming a slice of the namespace the
    // bailiwick check cannot express.
    if (!/^[A-HJ-NPR-Z0-9]{3}$/.test(upper)) {
      throw new Error(`a wmi zone scope must be 3 ISO 3779 characters, got "${scope}"`)
    }
    return Object.freeze({ id: `wmi:${upper}`, scope_type: 'wmi', scope: upper })
  }
  return Object.freeze({ id: `operator:${scope}`, scope_type: 'operator', scope })
}

// ---------------------------------------------------------------------------------
// The consent endpoint URL grammar — where Refusal 1 is won or lost
// ---------------------------------------------------------------------------------

/**
 * Private, loopback, link-local and cloud-metadata address literals.
 *
 * The resolver fetches zone endpoints, and zone endpoints arrive inside delegation records
 * signed by a parent zone. A parent zone is therefore a party that can name a URL the
 * resolver will fetch — which is an SSRF primitive if the URL may point inside the resolver's
 * own network. 169.254.169.254 is the specific one that matters, because on most cloud
 * providers it hands out instance credentials to anything that asks.
 */
const BLOCKED_HOST_PATTERNS = Object.freeze([
  /^localhost$/i,
  /^127\./,
  /^0\./,
  /^10\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^\[?::1\]?$/,
  /^\[?f[cd]/i,
  /\.local$/i,
  /\.internal$/i,
])

/**
 * Validate a consent-endpoint or zone-endpoint URL. Returns `{ ok, url, reason }` rather than
 * throwing, because it runs inside `verifyResolutionAnswer`, which never throws.
 *
 * The three forbidden URL components are the whole point of this function, and each one maps
 * to a real mechanism by which a "location" smuggles authority:
 *
 *  - QUERY STRING. A presigned URL is a location that *is* a credential:
 *    `?X-Amz-Signature=…`, `?sig=…`, `?token=…`. Every object-storage vendor ships one. If
 *    NF-3 permitted a query string, a broker could hand out a location that opens data with
 *    no grant presented and no revocation check, and the protocol would have resolved a VIN
 *    to a credential while every field name still looked innocent.
 *  - FRAGMENT. OAuth 2.0's implicit flow returns `#access_token=…`. A fragment is also
 *    invisible to the server, so a fragment credential is invisible in exactly the logs an
 *    auditor would read.
 *  - USERINFO. `https://user:pass@host/` is HTTP Basic inline, and `https://evil.example@
 *    good.example/` is the origin-confusion trick that makes a hostile host look like a
 *    trusted one to a human reading the string.
 *
 * Forbidding all three costs nothing — a consent endpoint is a base address that the caller
 * POSTs a grant to — and it converts "we promise not to put credentials in locations" from a
 * policy into a grammar. A design constraint beats a policy statement because it cannot be
 * waived under commercial pressure (the §8.2 argument, applied to a different surface).
 *
 * @param {unknown} raw
 * @param {{ allowInsecureLoopback?: boolean }} [opts]
 */
export function validateEndpointUrl(raw, opts = {}) {
  if (typeof raw !== 'string' || raw.length === 0) {
    return { ok: false, url: null, reason: 'endpoint must be a non-empty string' }
  }
  if (raw.length > MAX_ENDPOINT_URL_LENGTH) {
    return { ok: false, url: null, reason: `endpoint exceeds ${MAX_ENDPOINT_URL_LENGTH} characters` }
  }
  if (raw !== raw.trim()) {
    // Leading/trailing whitespace is how two spellings of one URL end up with two cache
    // entries and two signatures.
    return { ok: false, url: null, reason: 'endpoint has leading or trailing whitespace' }
  }

  let url
  try {
    url = new URL(raw)
  } catch {
    return { ok: false, url: null, reason: 'endpoint is not a parseable absolute URL' }
  }

  const loopbackOk = opts.allowInsecureLoopback === true
  if (url.protocol !== 'https:' && !(loopbackOk && url.protocol === 'http:')) {
    return { ok: false, url: null, reason: `endpoint scheme must be https, got "${url.protocol}"` }
  }
  if (url.username !== '' || url.password !== '') {
    return {
      ok: false,
      url: null,
      reason: 'endpoint carries a userinfo component: that is an inline credential and an ' +
        'origin-confusion vector, and NF-3 locations carry no authority',
    }
  }
  if (url.search !== '') {
    return {
      ok: false,
      url: null,
      reason: 'endpoint carries a query string: presigned-URL credentials live there, so the ' +
        'grammar forbids it outright rather than trusting the parameter names',
    }
  }
  if (url.hash !== '') {
    return {
      ok: false,
      url: null,
      reason: 'endpoint carries a fragment: OAuth implicit-flow access tokens live there',
    }
  }
  // Post-parse hostname is already punycoded, so an ASCII-only check eliminates Unicode
  // homograph hosts by construction rather than by blocklist.
  if (!/^[a-z0-9.-]+$/.test(url.hostname) && !/^\[[0-9a-f:]+\]$/i.test(url.hostname)) {
    return { ok: false, url: null, reason: `endpoint hostname "${url.hostname}" is not ASCII host syntax` }
  }
  if (!loopbackOk) {
    for (const pattern of BLOCKED_HOST_PATTERNS) {
      if (pattern.test(url.hostname)) {
        return {
          ok: false,
          url: null,
          reason: `endpoint host "${url.hostname}" is loopback, private, link-local or a ` +
            'cloud-metadata address; a resolver that fetches those is an SSRF primitive',
        }
      }
    }
  }
  return { ok: true, url: url.href, reason: null }
}

// ---------------------------------------------------------------------------------
// Record constructors (the zone side)
// ---------------------------------------------------------------------------------

/**
 * The consent endpoint record: the A record of this system. It says WHERE to ask.
 *
 * `supported_field_classes` is advertised capability, not permission. A broker listing
 * `diagnostics` is saying "I can serve diagnostics for vehicles enrolled here if you bring a
 * grant", exactly as an A record says "there is a server here" and not "you may read its
 * disk". It is useful because it lets a requester discover before it asks — and it is
 * validated against the CLOSED `FIELD_CLASSES` vocabulary from fields.js, which means a broker
 * cannot advertise `precise_geolocation` even as a lie: the vocabulary has no such class, so
 * the protocol cannot encode the claim (§8.2, §12.2).
 *
 * `broker_key` is the broker's PUBLIC Ed25519 key, so the requester can authenticate what the
 * broker says once it gets there. Note the deliberate asymmetry with NF-2, which pointedly
 * omits the signer's key: there, publishing the owner's key would let two counterparties join
 * their datasets on it and defeat the per-audience pseudonym (§12.7). Here the key belongs to
 * a public infrastructure operator with no privacy interest to protect, and withholding it
 * would leave the requester unable to tell the real broker from a spoofed one. Same protocol,
 * opposite decision, because the threat is different — worth stating so the inconsistency
 * reads as deliberate.
 */
export function makeConsentEndpointRecord(params) {
  const p = requireParams(params, ['endpoint', 'protocolVersion', 'supportedFieldClasses', 'brokerKey', 'allowInsecureLoopback'])
  const urlCheck = validateEndpointUrl(p.endpoint, { allowInsecureLoopback: p.allowInsecureLoopback === true })
  if (!urlCheck.ok) throw new Error(`consent endpoint rejected: ${urlCheck.reason}`)

  if (!SUPPORTED_ENDPOINT_PROTOCOLS.includes(p.protocolVersion)) {
    throw new Error(
      `endpoint protocol "${String(p.protocolVersion)}" is not one of ` +
        `${SUPPORTED_ENDPOINT_PROTOCOLS.join(', ')}`,
    )
  }
  const classes = normalizeFieldClasses(p.supportedFieldClasses)
  if (!isBase64urlBytes(p.brokerKey, ED25519_PUBLIC_KEY_BYTES)) {
    throw new Error('brokerKey must be a 32-byte base64url Ed25519 public key')
  }

  const record = Object.freeze({
    type: 'ce',
    endpoint: urlCheck.url,
    protocol_version: p.protocolVersion,
    supported_field_classes: Object.freeze(classes),
    broker_key: p.brokerKey,
  })
  assertNoCredentialSurface(record, 'ce')
  return record
}

/**
 * The delegation record: NS and DS in one, and deliberately in one.
 *
 * DNS split the referral (NS, in the authority section) from the child's address (A, in the
 * ADDITIONAL section, unsigned, and accepted unsolicited). That split is the Kaminsky attack.
 * The resolver accepted glue it had not asked for, so an attacker who could win a race
 * against a 16-bit transaction id could inject an address for a name it was not authoritative
 * for and own the whole zone.
 *
 * NF-3 HAS NO ADDITIONAL SECTION AND NO GLUE. One question, one record, and the child's
 * endpoint and key are the record's own payload — inside the parent's signature, not beside
 * it. There is nowhere for unsolicited data to ride along, because a message carries exactly
 * one signed record and everything else is discarded before verification even runs.
 */
export function makeDelegationRecord(params) {
  const p = requireParams(params, ['childZone', 'childZoneKey', 'childEndpoint', 'allowInsecureLoopback'])
  const zone = requireZoneShape(p.childZone)
  if (zone.scope_type === 'root') throw new Error('cannot delegate to the root zone')

  const urlCheck = validateEndpointUrl(p.childEndpoint, {
    allowInsecureLoopback: p.allowInsecureLoopback === true,
  })
  if (!urlCheck.ok) throw new Error(`child zone endpoint rejected: ${urlCheck.reason}`)
  if (!isBase64urlBytes(p.childZoneKey, ED25519_PUBLIC_KEY_BYTES)) {
    throw new Error('childZoneKey must be a 32-byte base64url Ed25519 public key')
  }

  const record = Object.freeze({
    type: 'delegation',
    child_zone: zone,
    child_zone_key: p.childZoneKey,
    child_endpoint: urlCheck.url,
  })
  assertNoCredentialSurface(record, 'delegation')
  return record
}

/**
 * A negative record. It carries no payload: the name it denies and the zone denying it are on
 * the answer envelope, both inside the signature.
 *
 * WHY A SIGNED DENIAL AT ALL. An unsigned negative answer is a denial-of-enrolment attack: an
 * attacker who can inject `nxenroll` makes an enrolled vehicle look absent from the network,
 * and the owner has no way to observe it. DNSSEC needed NSEC/NSEC3 for precisely this, and
 * NSEC had a famous side effect — it proved non-existence by naming the surrounding names,
 * which turned authenticated denial into zone enumeration. We sidestep that entirely by
 * signing the specific denial for the specific name, per query. There is no neighbour to
 * disclose, so there is no zone walk.
 */
export function makeNegativeRecord(type) {
  if (!NEGATIVE_RECORD_TYPES.includes(type)) {
    throw new Error(`"${String(type)}" is not a negative record type (${NEGATIVE_RECORD_TYPES.join(', ')})`)
  }
  return Object.freeze({ type })
}

// ---------------------------------------------------------------------------------
// The signed answer envelope
// ---------------------------------------------------------------------------------

/** Fresh 128-bit query nonce, base64url. */
export function generateQueryNonce() {
  const bytes = new Uint8Array(NONCE_BYTES)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

/**
 * Build a question. Sent as a POST body, never as a URL query string — the qname digest is a
 * derivative of a VIN, and a VIN-derived value in a URL ends up in every intermediary's access
 * log and in the Workers Cache key. A POST also cannot be cached by an intermediary that does
 * not understand the protocol, which is the correct default for a signed, nonce-bound exchange.
 */
export function makeQuestion(qnameDigestValue, nonce) {
  if (!isBase64urlBytes(qnameDigestValue, DIGEST_BYTES)) {
    throw new Error('question qname_digest must be a 32-byte base64url digest')
  }
  if (!isBase64urlBytes(nonce, NONCE_BYTES)) {
    throw new Error('question nonce must be a 16-byte base64url value')
  }
  return Object.freeze({ v: NF3_QUESTION_VERSION, qname_digest: qnameDigestValue, nonce })
}

/**
 * Build an unsigned answer. Zone-side helper; also what the conformance suite mints answers
 * with, so the suite exercises the same construction the network does.
 *
 * The TTL is clamped here as well as at verification time, so a zone cannot serve a TTL its
 * own client library would have refused.
 */
export function buildAnswer(params) {
  const p = requireParams(params, ['qnameDigest', 'nonce', 'zone', 'record', 'ttl', 'answeredAt'])
  if (!isBase64urlBytes(p.qnameDigest, DIGEST_BYTES)) {
    throw new Error('answer qname_digest must be a 32-byte base64url digest')
  }
  if (!isBase64urlBytes(p.nonce, NONCE_BYTES)) {
    throw new Error('answer nonce must echo the question nonce: 16 bytes, base64url')
  }
  const zone = requireZoneShape(p.zone)
  const record = requireRecordShape(p.record)

  if (!ZONE_ANSWER_POLICY[zone.scope_type].includes(record.type)) {
    throw new Error(
      `a ${zone.scope_type} zone may not answer with a "${record.type}" record ` +
        `(permitted: ${ZONE_ANSWER_POLICY[zone.scope_type].join(', ')})`,
    )
  }
  if (record.type === 'delegation') {
    const permitted = ZONE_DELEGATION_POLICY[zone.scope_type]
    if (!permitted.includes(record.child_zone.scope_type)) {
      throw new Error(
        `a ${zone.scope_type} zone may not delegate to a ${record.child_zone.scope_type} zone ` +
          `(permitted: ${permitted.length ? permitted.join(', ') : 'none'})`,
      )
    }
  }

  if (!Number.isInteger(p.answeredAt) || p.answeredAt < MIN_PLAUSIBLE_TIME_S || p.answeredAt > MAX_PLAUSIBLE_TIME_S) {
    throw new Error(
      `answeredAt must be Unix SECONDS in [${MIN_PLAUSIBLE_TIME_S}, ${MAX_PLAUSIBLE_TIME_S}]; ` +
        'a millisecond timestamp is a well-formed integer and no other check catches it',
    )
  }
  const clamped = clampTtl(p.ttl, record.type)
  if (!clamped.ok) throw new Error(`ttl rejected: ${clamped.reason}`)

  const answer = {
    v: NF3_ANSWER_VERSION,
    qname_digest: p.qnameDigest,
    zone,
    record,
    ttl: clamped.ttl,
    answered_at: p.answeredAt,
    nonce: p.nonce,
    signer_key_id: null,
    signature: null,
  }
  assertNoCredentialSurface(answer, 'answer')
  return answer
}

/**
 * The bytes a zone signs: JCS canonicalisation of the answer with `signature` removed.
 * `signer_key_id` IS inside the signed bytes — a signature that did not cover its own key
 * identifier could be lifted onto an answer attributed to a different key.
 *
 * No external domain tag: the type binding is the `v` field, which is inside the bytes, so
 * these bytes cannot be reinterpreted as another kind of object and a version bump changes
 * every signature. Same reasoning as `grantSigningInput` in nf2-grant.js; the two modules
 * agreeing on this posture is deliberate.
 */
export function answerSigningInput(answer) {
  const shape = answerShapeReasons(answer, { requireSignature: false })
  if (shape.length > 0) {
    throw new Error(`refusing to compute a signing input for a malformed answer: ${shape.join('; ')}`)
  }
  const unsigned = {}
  for (const key of NF3_ANSWER_KEYS) {
    if (key === 'signature') continue
    unsigned[key] = answer[key]
  }
  return canonicalizeToBytes(unsigned)
}

/**
 * Sign an answer as a zone. Returns a new object; the input is not mutated.
 *
 * PER-QUERY SIGNING, AND ITS COST. Because the querier's nonce is inside the signed bytes, a
 * zone cannot pre-sign its data the way DNSSEC pre-signs a zone file, and its signing key must
 * be online. That is a real loss and it is chosen: the alternative is replayable answers,
 * which moves the risk from the zone operator — a funded participant who can defend a key and
 * rotate it — to the vehicle owner, who cannot. Ed25519 signing is microseconds, so throughput
 * is not the constraint; key custody is, and key custody is the zone operator's job.
 * `signer_key_id` plus `purgeResolutionCache` are the rotation path.
 *
 * The algorithm name is taken from the private key rather than probed. nf2-grant.js already
 * resolves the Workers `Ed25519` / legacy `NODE-ED25519` naming question once and caches it;
 * duplicating that probe here would duplicate a security-relevant decision in two places,
 * which is exactly how the two copies drift.
 *
 * The zone's PUBLIC key is a required third argument rather than something recovered from the
 * private key, because a non-extractably generated Ed25519 private CryptoKey carries no way to
 * recover its public half. Requiring it also means the `signer_key_id` inside the signature is
 * the thumbprint of the key the zone actually publishes: a zone that passes the wrong one
 * produces answers that fail their own signer_key_id check immediately, rather than answers
 * that fail mysteriously at some resolver later.
 *
 * @param {object} answer unsigned answer from `buildAnswer`
 * @param {CryptoKey} privateKey the zone's Ed25519 private key
 * @param {string} zonePublicKeyBase64url the matching raw public key, base64url
 */
export async function signResolutionAnswer(answer, privateKey, zonePublicKeyBase64url) {
  if (!isPlainObject(answer)) throw new Error('answer must be a plain object')
  if (answer.signature !== null) {
    throw new Error('answer is already signed; mint a fresh answer rather than re-signing')
  }
  if (!privateKey || privateKey.type !== 'private') {
    throw new Error('signResolutionAnswer requires an Ed25519 private CryptoKey')
  }
  const alg = algorithmFromKey(privateKey)
  const publicKeyId = await zoneKeyIdFromBase64url(zonePublicKeyBase64url)

  const withKeyId = { ...answer, signer_key_id: publicKeyId }
  const input = answerSigningInput(withKeyId)
  const sig = await crypto.subtle.sign(alg, privateKey, input)
  const signature = base64url(new Uint8Array(sig))
  if (signature.length !== base64urlLengthFor(ED25519_SIGNATURE_BYTES)) {
    throw new Error(`unexpected signature length from WebCrypto: ${signature.length} chars`)
  }
  return { ...withKeyId, signature }
}

/**
 * Verify a resolution answer and return a structured verdict. NEVER THROWS — a verifier that
 * throws on malformed input hands any peer a denial of service, and every input here comes
 * from the network. Collects every reason rather than stopping at the first, so the
 * conformance suite can assert which rule fired. Reason codes are `code: detail`, stable
 * prefixes, enumerated at the bottom of this comment.
 *
 * THE DNS CACHE-POISONING ANALOGY, stated plainly because it is the whole reason this function
 * exists. Pre-DNSSEC, a resolver accepted any UDP packet that matched a 16-bit transaction id,
 * a source port and the question. Kaminsky (2008) showed that was 65,536 guesses against a
 * birthday race you could retry indefinitely with fresh subdomains, and the payoff was
 * injecting glue from the additional section — so the attacker did not merely answer one
 * question, they replaced the authoritative servers for an entire zone in the victim's cache.
 * Every property below is a direct answer to one part of that:
 *
 *   - the answer is signed, so guessing a matching envelope is not enough (DNSSEC's fix);
 *   - the QUESTION is inside the signature via `qname_digest`, so an answer for one name
 *     cannot be re-aimed at another (the bailiwick rule, cryptographically enforced);
 *   - the ZONE is inside the signature and must equal the zone actually queried, so a zone
 *     cannot answer for a name outside its scope even when legitimately reached;
 *   - a 128-bit NONCE is inside the signature, so a validly signed old answer cannot be
 *     replayed — a gap DNSSEC leaves open, since a signed RRset stays signed until its
 *     signature expires;
 *   - there is NO additional section and no glue, so there is nothing unsolicited to inject;
 *   - `signer_key_id` must match the thumbprint of the key we were told to expect, so a
 *     signature made by a key we do trust for zone A cannot be presented as zone B's.
 *
 * A failed verification is terminal for that zone. The resolver does NOT fall back to another
 * source, because "try somewhere else when validation fails" is a downgrade attack: an
 * attacker who can make the good answer fail gets to choose the replacement.
 *
 * @param {object} answer
 * @param {object} opts
 * @param {string} opts.vin                     the VIN being resolved; recomputes qname_digest
 * @param {object} opts.expectedZone            the zone actually queried
 * @param {string} opts.zonePublicKey           base64url raw Ed25519 key we trust for that zone
 * @param {string} [opts.expectedNonce]         required unless fromCache
 * @param {boolean} [opts.fromCache=false]      relaxes nonce + age; see the note below
 * @param {number} [opts.now]                   Unix seconds
 * @param {number} [opts.clockSkewS]
 * @param {boolean} [opts.allowInsecureLoopback=false]
 * @returns {Promise<{ valid: boolean, reasons: string[] }>}
 *
 * `fromCache` is the one deliberate relaxation and it is only reachable from this module's own
 * cache path — never from a network peer, because the network path sets it false. On a cache
 * hit the stored answer necessarily carries the nonce from the query that fetched it, and
 * replaying our own verified answer is exactly what a cache is for. Freshness is enforced by
 * the TTL instead, which is the DNS contract. The signature, the qname binding, the zone
 * binding and the key-id binding are all still checked on every cache read, which is what
 * makes the cache storage rather than authority: a tampered D1 row or a poisoned edge entry
 * fails verification the same way a hostile packet does.
 *
 * Reason codes: answer_shape, unknown_field, missing_field, version_unsupported,
 * qname_mismatch, zone_mismatch, zone_scope_invalid, bailiwick_violation,
 * answer_policy_violation, delegation_policy_violation, nonce_missing, nonce_mismatch,
 * time_implausible, answer_stale, answer_future, ttl_invalid, record_invalid,
 * endpoint_invalid, field_class_invalid, protocol_unsupported, signer_key_id_mismatch,
 * verifier_key_missing, signature_missing, signature_invalid, credential_surface, internal.
 */
export async function verifyResolutionAnswer(answer, opts = {}) {
  const reasons = []
  try {
    reasons.push(...answerShapeReasons(answer, { requireSignature: true }))
    if (reasons.length === 0) {
      reasons.push(...(await questionBindingReasons(answer, opts)))
      reasons.push(...zoneAuthorityReasons(answer, opts))
      reasons.push(...freshnessReasons(answer, opts))
      reasons.push(...recordReasons(answer, opts))
      reasons.push(...(await signatureReasons(answer, opts)))
    }
    try {
      assertNoCredentialSurface(answer, 'answer')
    } catch (err) {
      reasons.push(`credential_surface: ${err?.message ?? String(err)}`)
    }
  } catch (err) {
    reasons.push(`internal: verification aborted (${err?.message ?? String(err)})`)
  }
  return { valid: reasons.length === 0, reasons }
}

/** Shape, closed keys, types. Pure and synchronous, and everything below assumes it passed. */
function answerShapeReasons(answer, { requireSignature }) {
  if (!isPlainObject(answer)) return ['answer_shape: answer must be a plain object']
  const reasons = []

  for (const key of Object.keys(answer)) {
    if (!NF3_ANSWER_KEYS.includes(key)) {
      reasons.push(`unknown_field: "${key}" is not part of ${NF3_ANSWER_VERSION}`)
    }
  }
  for (const key of NF3_ANSWER_KEYS) {
    if (!Object.hasOwn(answer, key)) {
      reasons.push(`missing_field: "${key}" (unused keys are present as null, never omitted)`)
    }
  }
  if (reasons.length > 0) return reasons

  if (answer.v !== NF3_ANSWER_VERSION) {
    reasons.push(`version_unsupported: "${String(answer.v)}", expected "${NF3_ANSWER_VERSION}"`)
  }
  if (!isBase64urlBytes(answer.qname_digest, DIGEST_BYTES)) {
    reasons.push('answer_shape: qname_digest must be a 32-byte base64url digest')
  }
  if (!isBase64urlBytes(answer.nonce, NONCE_BYTES)) {
    reasons.push('answer_shape: nonce must be a 16-byte base64url value')
  }
  if (answer.signer_key_id !== null && !isBase64urlBytes(answer.signer_key_id, DIGEST_BYTES)) {
    reasons.push('answer_shape: signer_key_id must be a 32-byte base64url thumbprint or null')
  }
  if (requireSignature) {
    if (answer.signature === null) {
      reasons.push('signature_missing: an unsigned answer authenticates nothing')
    } else if (!isBase64urlBytes(answer.signature, ED25519_SIGNATURE_BYTES)) {
      reasons.push('answer_shape: signature must be a 64-byte base64url Ed25519 signature')
    }
    if (answer.signer_key_id === null) {
      reasons.push('signature_missing: signer_key_id is null on a signed answer')
    }
  }
  reasons.push(...zoneShapeReasons(answer.zone))
  reasons.push(...recordShapeReasons(answer.record))
  if (!Number.isInteger(answer.ttl) || answer.ttl < 0 || answer.ttl > MAX_ACCEPTABLE_TTL_S) {
    reasons.push(`ttl_invalid: ttl must be an integer in [0, ${MAX_ACCEPTABLE_TTL_S}] seconds`)
  }
  if (!Number.isInteger(answer.answered_at)) {
    reasons.push('answer_shape: answered_at must be an integer of Unix SECONDS')
  }
  return reasons
}

function zoneShapeReasons(zone) {
  if (!isPlainObject(zone)) return ['answer_shape: zone must be a plain object']
  const reasons = []
  for (const key of Object.keys(zone)) {
    if (!NF3_ZONE_KEYS.includes(key)) reasons.push(`unknown_field: zone."${key}"`)
  }
  for (const key of NF3_ZONE_KEYS) {
    if (!Object.hasOwn(zone, key)) reasons.push(`missing_field: zone."${key}"`)
  }
  if (reasons.length > 0) return reasons
  if (!NF3_SCOPE_TYPES.includes(zone.scope_type)) {
    reasons.push(`zone_scope_invalid: scope_type "${String(zone.scope_type)}"`)
    return reasons
  }
  // The id is derived from the scope, so a mismatch means two names for one scope — which
  // would defeat the visited-zone loop detector by aliasing.
  let expected
  try {
    expected = makeZone(zone.scope_type, zone.scope)
  } catch (err) {
    reasons.push(`zone_scope_invalid: ${err?.message ?? String(err)}`)
    return reasons
  }
  if (zone.id !== expected.id || zone.scope !== expected.scope) {
    reasons.push(
      `zone_scope_invalid: id "${String(zone.id)}" is not the canonical id for ` +
        `${zone.scope_type}/${String(zone.scope)} ("${expected.id}"); a zone may not have two names`,
    )
  }
  return reasons
}

function recordShapeReasons(record) {
  if (!isPlainObject(record)) return ['record_invalid: record must be a plain object']
  if (!NF3_RECORD_TYPES.includes(record.type)) {
    return [`record_invalid: unknown record type "${String(record.type)}"`]
  }
  const keys = NF3_RECORD_KEYS[record.type]
  const reasons = []
  for (const key of Object.keys(record)) {
    if (!keys.includes(key)) reasons.push(`unknown_field: ${record.type}."${key}"`)
  }
  for (const key of keys) {
    if (!Object.hasOwn(record, key)) reasons.push(`missing_field: ${record.type}."${key}"`)
  }
  if (record.type === 'delegation' && reasons.length === 0) {
    reasons.push(...zoneShapeReasons(record.child_zone).map((r) => r.replace('zone.', 'child_zone.')))
  }
  return reasons
}

/**
 * Bind the answer to the question. This is the single most important check in the file: without
 * it, any signed answer from any zone we trust could be re-aimed at any other name.
 */
async function questionBindingReasons(answer, opts) {
  const reasons = []
  if (typeof opts.vin !== 'string') {
    return ['qname_mismatch: verification requires the VIN so the qname_digest can be recomputed']
  }
  let expected
  try {
    expected = await qnameDigest(opts.vin)
  } catch (err) {
    return [`qname_mismatch: ${err?.message ?? String(err)}`]
  }
  if (answer.qname_digest !== expected) {
    reasons.push(
      'qname_mismatch: the answer is signed over a different name than the one asked about. ' +
        'This is the bailiwick rule — an answer may not be re-aimed at another name',
    )
  }
  if (opts.fromCache === true) {
    // See the note on verifyResolutionAnswer: replay is what a cache is for, TTL is the bound.
    return reasons
  }
  if (!isBase64urlBytes(opts.expectedNonce, NONCE_BYTES)) {
    reasons.push('nonce_missing: a network answer must be checked against the nonce that was sent')
  } else if (answer.nonce !== opts.expectedNonce) {
    // Not a constant-time comparison, and it does not need to be: the nonce is public in both
    // directions. Its value is unguessability at 128 bits, not secrecy.
    reasons.push(
      'nonce_mismatch: the answer does not echo this query\'s nonce. A 128-bit nonce inside ' +
        'the signature is what closes the replay gap DNSSEC leaves open',
    )
  }
  return reasons
}

/**
 * Zone authority: the answer must come from the zone we actually asked, that zone must be
 * permitted to answer with this record type, and a WMI zone must be answering inside its own
 * manufacturer scope.
 */
function zoneAuthorityReasons(answer, opts) {
  const reasons = []
  const expected = opts.expectedZone
  if (!isPlainObject(expected) || typeof expected.id !== 'string') {
    return ['zone_mismatch: verification requires the identity of the zone that was queried']
  }
  if (answer.zone.id !== expected.id) {
    reasons.push(
      `zone_mismatch: answer is attributed to "${answer.zone.id}" but "${expected.id}" was ` +
        'queried; a zone may not answer as another zone',
    )
    return reasons
  }

  const permitted = ZONE_ANSWER_POLICY[answer.zone.scope_type] ?? []
  if (!permitted.includes(answer.record.type)) {
    reasons.push(
      `answer_policy_violation: a ${answer.zone.scope_type} zone may not answer with a ` +
        `"${answer.record.type}" record (permitted: ${permitted.join(', ') || 'none'})`,
    )
  }

  if (answer.zone.scope_type === 'wmi') {
    // Checkable offline from the name alone, which is what makes a WMI zone's claim verifiable
    // by anyone and not merely asserted by whoever referred us to it.
    const zoneWmi = typeof opts.vin === 'string' ? wmi(opts.vin) : null
    if (zoneWmi === null) {
      reasons.push('bailiwick_violation: cannot derive the WMI from the queried name')
    } else if (zoneWmi !== answer.zone.scope) {
      reasons.push(
        `bailiwick_violation: zone "${answer.zone.id}" answered for a VIN whose WMI is ` +
          `"${zoneWmi}"; a manufacturer zone is authoritative only inside its own prefix`,
      )
    }
  }

  if (answer.record.type === 'delegation') {
    const allowed = ZONE_DELEGATION_POLICY[answer.zone.scope_type] ?? []
    const childType = answer.record.child_zone?.scope_type
    if (!allowed.includes(childType)) {
      reasons.push(
        `delegation_policy_violation: a ${answer.zone.scope_type} zone may not delegate to a ` +
          `"${String(childType)}" zone (permitted: ${allowed.join(', ') || 'none'})`,
      )
    }
    if (childType === 'wmi') {
      const zoneWmi = typeof opts.vin === 'string' ? wmi(opts.vin) : null
      if (zoneWmi !== answer.record.child_zone.scope) {
        reasons.push(
          'delegation_policy_violation: a wmi delegation must name the queried VIN\'s own WMI; ' +
            'referring a resolver to a different manufacturer\'s zone is a hijack',
        )
      }
    }
    if (answer.record.child_zone?.id === answer.zone.id) {
      reasons.push('delegation_policy_violation: a zone may not delegate to itself')
    }
  }
  return reasons
}

function freshnessReasons(answer, opts) {
  const reasons = []
  const now = Number.isInteger(opts.now) ? opts.now : Math.floor(Date.now() / 1000)
  const skew = Number.isInteger(opts.clockSkewS) ? opts.clockSkewS : DEFAULT_CLOCK_SKEW_S

  if (answer.answered_at < MIN_PLAUSIBLE_TIME_S || answer.answered_at > MAX_PLAUSIBLE_TIME_S) {
    reasons.push(
      `time_implausible: answered_at ${answer.answered_at} is outside ` +
        `[${MIN_PLAUSIBLE_TIME_S}, ${MAX_PLAUSIBLE_TIME_S}]; a millisecond timestamp is a ` +
        'well-formed integer and only a range test catches it',
    )
    return reasons
  }
  if (answer.answered_at > now + skew) {
    reasons.push(`answer_future: answered_at is ${answer.answered_at - now}s ahead of this clock`)
  }
  if (opts.fromCache !== true && answer.answered_at < now - skew - MAX_ANSWER_AGE_S) {
    reasons.push(
      `answer_stale: a network answer older than ${MAX_ANSWER_AGE_S}s (plus skew) is refused; ` +
        'defence in depth behind the nonce',
    )
  }
  const clamped = clampTtl(answer.ttl, answer.record.type)
  if (!clamped.ok) reasons.push(`ttl_invalid: ${clamped.reason}`)
  return reasons
}

/** Type-specific record validation: the endpoint grammar, the closed field-class vocabulary. */
function recordReasons(answer, opts) {
  const reasons = []
  const record = answer.record
  const loopback = opts.allowInsecureLoopback === true

  if (record.type === 'ce') {
    const urlCheck = validateEndpointUrl(record.endpoint, { allowInsecureLoopback: loopback })
    if (!urlCheck.ok) reasons.push(`endpoint_invalid: ${urlCheck.reason}`)
    if (!SUPPORTED_ENDPOINT_PROTOCOLS.includes(record.protocol_version)) {
      reasons.push(
        `protocol_unsupported: "${String(record.protocol_version)}" is not one of ` +
          `${SUPPORTED_ENDPOINT_PROTOCOLS.join(', ')}; a location we cannot safely speak to is ` +
          'worse than no location, because the caller will try anyway',
      )
    }
    reasons.push(...fieldClassReasons(record.supported_field_classes))
    if (!isBase64urlBytes(record.broker_key, ED25519_PUBLIC_KEY_BYTES)) {
      reasons.push('record_invalid: broker_key must be a 32-byte base64url Ed25519 public key')
    }
  }

  if (record.type === 'delegation') {
    const urlCheck = validateEndpointUrl(record.child_endpoint, { allowInsecureLoopback: loopback })
    if (!urlCheck.ok) reasons.push(`endpoint_invalid: child_endpoint ${urlCheck.reason}`)
    if (!isBase64urlBytes(record.child_zone_key, ED25519_PUBLIC_KEY_BYTES)) {
      reasons.push('record_invalid: child_zone_key must be a 32-byte base64url Ed25519 public key')
    }
  }
  return reasons
}

/**
 * The advertised field classes must be members of the CLOSED `FIELD_CLASSES` vocabulary from
 * fields.js, sorted, and unique. Sorted because JCS treats array order as significant, so an
 * unsorted list would give one semantic record several signing inputs and several cache
 * identities. And validated against the closed vocabulary because that is where a broker
 * advertising `precise_geolocation` is refused — not by policy, but because there is no such
 * class to name (§8.2, §12.2). `NON_TRANSACTABLE` is checked explicitly as well so the reason
 * an operator sees names the refusal instead of saying "unknown class".
 */
function fieldClassReasons(classes) {
  if (!Array.isArray(classes) || classes.length === 0) {
    return ['field_class_invalid: supported_field_classes must be a non-empty array']
  }
  const reasons = []
  const known = Object.keys(FIELD_CLASSES)
  const seen = new Set()
  for (const c of classes) {
    if (typeof c !== 'string') {
      reasons.push('field_class_invalid: field class ids must be strings')
      continue
    }
    if (seen.has(c)) reasons.push(`field_class_invalid: duplicate field class "${c}"`)
    seen.add(c)
    if (NON_TRANSACTABLE.includes(c)) {
      reasons.push(
        `field_class_invalid: "${c}" is a non-transactable class with no grant type at all; ` +
          'an endpoint cannot advertise support for something the protocol cannot encode',
      )
      continue
    }
    if (!known.includes(c)) {
      reasons.push(`field_class_invalid: "${c}" is not an NF-2 field class (${known.join(', ')})`)
    }
  }
  const sorted = [...classes].sort(compareCodeUnits)
  if (classes.some((c, i) => c !== sorted[i])) {
    reasons.push(
      'field_class_invalid: supported_field_classes must be sorted by UTF-16 code unit so one ' +
        'semantic record has one signing input',
    )
  }
  return reasons
}

async function signatureReasons(answer, opts) {
  if (answer.signature === null || answer.signer_key_id === null) {
    return ['signature_missing: answer is unsigned']
  }
  const keyMaterial = opts.zonePublicKey
  if (typeof keyMaterial !== 'string') {
    return [
      'verifier_key_missing: no zone key supplied. The key comes from a trust anchor or from ' +
        'the parent zone\'s delegation record — never from the answer being verified',
    ]
  }
  let expectedKeyId
  try {
    expectedKeyId = await zoneKeyIdFromBase64url(keyMaterial)
  } catch (err) {
    return [`verifier_key_missing: ${err?.message ?? String(err)}`]
  }
  if (answer.signer_key_id !== expectedKeyId) {
    // Without this, a signature made by a key we legitimately trust for zone A could be
    // presented inside an answer claiming a different signer.
    return [
      `signer_key_id_mismatch: the answer names a signer key we were not told to expect for ` +
        `zone "${answer.zone.id}"`,
    ]
  }

  let publicKey
  try {
    publicKey = await importPublicKeyBase64url(keyMaterial)
  } catch (err) {
    return [`verifier_key_missing: zone key could not be imported (${err?.message ?? String(err)})`]
  }
  let ok = false
  try {
    ok = await crypto.subtle.verify(
      algorithmFromKey(publicKey),
      publicKey,
      base64urlToBytes(answer.signature),
      answerSigningInput(answer),
    )
  } catch (err) {
    return [`signature_invalid: verification failed (${err?.message ?? String(err)})`]
  }
  return ok ? [] : ['signature_invalid: Ed25519 signature does not verify over the canonical answer']
}

// ---------------------------------------------------------------------------------
// The cache layer
// ---------------------------------------------------------------------------------

/**
 * D1 schema for the resolver's cache. Exported as DDL rather than hidden in a migration so the
 * columns are reviewable next to the reasoning about them.
 *
 * WHAT IS NOT IN THIS TABLE, and why that is the point: no VIN, no owner, no counterparty, no
 * grant, nothing derived from a person. `qname_digest` is a digest of a public index and
 * `answer_json` is a signed statement about where a broker lives. This is a cache of the
 * *directory*, not of anybody's data.
 *
 * Why D1 and not something immutable: Refusal 2. Every row must be deletable, and there must be
 * a sweep — `expires_at` is indexed for exactly that. A cache that never sweeps stops being a
 * cache and becomes a shadow copy of the query log, which is a retention problem even when
 * every individual column is innocuous (§9.5).
 *
 * One row per name, because a resolver holds one current answer per name — a positive and a
 * negative answer for the same VIN are mutually exclusive claims and the newer one wins.
 *
 * `zone_key` and `chain_json` are stored alongside the answer because the cache is re-verified
 * on read (see `readCache`): storing only the answer would force a full chain walk to check it,
 * and storing nothing would make the cache a trust boundary.
 */
export const NF3_CACHE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS nf3_resolution_cache (
  qname_digest TEXT    NOT NULL PRIMARY KEY,
  record_type  TEXT    NOT NULL,
  zone_id      TEXT    NOT NULL,
  zone_key     TEXT    NOT NULL,
  answer_json  TEXT    NOT NULL,
  chain_json   TEXT    NOT NULL,
  cached_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nf3_resolution_cache_expiry
  ON nf3_resolution_cache (expires_at);
`.trim()

/**
 * Clamp a TTL into the policy window for its record class.
 *
 * CLAMPING RATHER THAN REJECTING IS A DELIBERATE EXCEPTION to this codebase's fail-closed
 * posture, and it needs its reason stated because the default elsewhere is to refuse. A TTL is
 * advice about caching, not a term of an authorisation. The fail-closed direction for advice we
 * do not accept is to substitute our own bound, not to discard an otherwise authentic answer —
 * refusing would let a zone with one bad config value remove itself from the network, an
 * outage the resolver can trivially avoid and which an attacker could otherwise induce by
 * tampering with a single integer. What IS refused is a TTL that is not a plausible integer at
 * all, because that is malformation rather than misconfiguration.
 */
export function clampTtl(ttl, recordType) {
  if (!Number.isInteger(ttl) || ttl < 0 || ttl > MAX_ACCEPTABLE_TTL_S) {
    return { ok: false, ttl: null, clamped: false, reason: `ttl must be an integer in [0, ${MAX_ACCEPTABLE_TTL_S}]` }
  }
  const policy = ttlPolicyFor(recordType)
  if (policy === null) {
    return { ok: false, ttl: null, clamped: false, reason: `no TTL policy for record type "${String(recordType)}"` }
  }
  const bounded = Math.min(Math.max(ttl, policy.floor_s), policy.ceiling_s)
  return { ok: true, ttl: bounded, clamped: bounded !== ttl, reason: null }
}

function ttlPolicyFor(recordType) {
  if (POSITIVE_RECORD_TYPES.includes(recordType)) return NF3_TTL_POLICY.positive
  if (NEGATIVE_RECORD_TYPES.includes(recordType)) return NF3_TTL_POLICY.negative
  if (recordType === 'delegation') return NF3_TTL_POLICY.referral
  return null
}

/**
 * Cache key URL for the Workers Cache API. The `.invalid` TLD is reserved by RFC 2606 and
 * resolves nowhere, so this synthetic key can never turn into a real outbound request if a
 * future refactor passes it somewhere that fetches. The qname digest rather than the VIN keeps
 * the name out of edge cache keys and out of anything that logs them.
 */
function edgeCacheKey(qnameDigestValue) {
  return `https://nf3-resolver.invalid/v1/${encodeURIComponent(qnameDigestValue)}`
}

function edgeCache() {
  const c = globalThis.caches
  return c && typeof c.default?.match === 'function' ? c.default : null
}

function d1(env) {
  const db = env?.NF3_DB ?? env?.DB ?? null
  return db && typeof db.prepare === 'function' ? db : null
}

/**
 * Read a cached answer. Two tiers, mirroring DNS's stub/recursive split: the per-colo Workers
 * Cache API first because it is nearest, then D1 because it is durable and shared and survives
 * colo eviction. A D1 hit repopulates the edge tier.
 *
 * EVERY HIT IS RE-VERIFIED. That is the design decision worth defending: a cache row can be
 * modified by anything with database access, and an edge entry by anything that can write to
 * the cache namespace, so treating either as trustworthy would move the trust boundary from a
 * signature to a storage ACL. One Ed25519 verification is microseconds; the property bought is
 * that a poisoned row fails exactly like a poisoned packet. The chain root is re-checked
 * against the *current* trust anchors too, so removing an anchor takes effect immediately
 * rather than at TTL expiry.
 *
 * TTL is counted down, not re-served. RFC 1035 requires every cache to decrement the TTL it
 * passes on; storing an absolute `expires_at` at insert time is the same rule expressed as
 * arithmetic. Storing a relative TTL and re-serving it would extend an answer's life at every
 * hop, so a chain of caches could keep a withdrawn endpoint alive indefinitely.
 */
async function readCache(env, qnameDigestValue, vin, anchors, now, opts) {
  const entries = []
  const key = edgeCacheKey(qnameDigestValue)

  const edge = edgeCache()
  if (edge) {
    try {
      const hit = await edge.match(new Request(key, { method: 'GET' }))
      if (hit) entries.push({ source: 'edge-cache', text: await hit.text() })
    } catch {
      // A cache read failure is never fatal: fall through to D1, then to the network.
    }
  }

  const db = d1(env)
  if (entries.length === 0 && db) {
    try {
      const row = await db
        .prepare(
          'SELECT answer_json, zone_key, chain_json, expires_at FROM nf3_resolution_cache ' +
            'WHERE qname_digest = ?1 AND expires_at > ?2',
        )
        .bind(qnameDigestValue, now)
        .first()
      if (row) {
        entries.push({
          source: 'd1-cache',
          text: JSON.stringify({
            answer: JSON.parse(row.answer_json),
            zone_key: row.zone_key,
            chain: JSON.parse(row.chain_json),
            expires_at: row.expires_at,
          }),
        })
      }
    } catch {
      // Same posture. A resolver whose cache is broken must still resolve.
    }
  }

  for (const entry of entries) {
    let parsed
    try {
      parsed = JSON.parse(entry.text)
    } catch {
      continue
    }
    if (!isPlainObject(parsed) || !isPlainObject(parsed.answer)) continue
    if (!Number.isInteger(parsed.expires_at) || parsed.expires_at <= now) continue

    // The chain must still start at a key we currently trust, and "currently trust" means an
    // ANCHOR — not whatever the writer said. This is where anchor removal and zone-key
    // revocation take effect on already-cached answers, and it is also what keeps the shared
    // cache from becoming a trust-laundering path:
    //
    // `opts.fromZone` lets a caller act as its own validator with its own root of trust,
    // which is the DNS stub-vs-recursive split and entirely legitimate FOR THAT CALLER. But
    // D1 is shared. A chain rooted at a caller-supplied key, served later to a resolution
    // anchored somewhere else, would hand any party that can reach this resolver a
    // cache-poisoning primitive — it would choose both the answer and the key that validates
    // it, and every signature check would pass on the way in. Checking the source only when
    // it *claims* to be an anchor is the same hole with an extra step, because the claim is
    // in the row. So: no anchor step, no service. `writeCache` declines to store these at
    // all, and this is the second lock.
    const chain = Array.isArray(parsed.chain) ? parsed.chain : null
    if (chain === null || chain.length === 0) continue
    const rootStep = chain[0]
    if (!isPlainObject(rootStep) || typeof rootStep.zone_id !== 'string') continue
    if (rootStep.source !== 'anchor') continue
    if (anchors.get(rootStep.zone_id)?.key !== rootStep.key) continue

    const verdict = await verifyResolutionAnswer(parsed.answer, {
      vin,
      expectedZone: parsed.answer.zone,
      zonePublicKey: parsed.zone_key,
      fromCache: true,
      now,
      clockSkewS: opts.clockSkewS,
      allowInsecureLoopback: opts.allowInsecureLoopback === true,
    })
    if (!verdict.valid) {
      // A cached answer that no longer verifies is evidence of tampering or of a key change.
      // Drop it and go to the network; never serve it, and never repair it.
      await deleteCacheEntry(env, qnameDigestValue)
      continue
    }
    return {
      answer: parsed.answer,
      zoneKey: parsed.zone_key,
      chain,
      expiresAt: parsed.expires_at,
      source: entry.source,
    }
  }
  return null
}

/**
 * Write a verified answer to both tiers. Internal, and only ever called from the verified path
 * — an exported cache-write would be a poisoning primitive with this module's name on it.
 * `assertNoCredentialSurface` runs again here, so the cache cannot become the place a
 * credential-shaped field enters the system.
 */
async function writeCache(env, qnameDigestValue, { answer, zoneKey, chain, now }) {
  // Only anchored chains are storable. A `fromZone` walk is validated against a key the
  // CALLER chose, so the answer is authentic for that caller and says nothing to anyone
  // else; `readCache` refuses to serve such a row, and writing it anyway would still be
  // harmful — the table is keyed by qname, so the write would evict the anchored answer and
  // let any caller flush another party's cache entry on demand.
  if (!Array.isArray(chain) || chain.length === 0 || chain[0]?.source !== 'anchor') return null

  const clamped = clampTtl(answer.ttl, answer.record.type)
  if (!clamped.ok) return null
  // Expiry counts from when the ZONE answered, not from when we stored it, so latency and
  // queueing cannot silently extend an answer's life.
  const expiresAt = Math.min(answer.answered_at, now) + clamped.ttl
  if (expiresAt <= now) return null

  const payload = { answer, zone_key: zoneKey, chain, expires_at: expiresAt }
  assertNoCredentialSurface(payload, 'cache-entry')
  const body = JSON.stringify(payload)

  const edge = edgeCache()
  if (edge) {
    try {
      await edge.put(
        new Request(edgeCacheKey(qnameDigestValue), { method: 'GET' }),
        new Response(body, {
          headers: {
            'content-type': 'application/json',
            'cache-control': `max-age=${expiresAt - now}`,
          },
        }),
      )
    } catch {
      // Best effort. D1 is the durable tier.
    }
  }

  const db = d1(env)
  if (db) {
    try {
      await db
        .prepare(
          'INSERT INTO nf3_resolution_cache ' +
            '(qname_digest, record_type, zone_id, zone_key, answer_json, chain_json, cached_at, expires_at) ' +
            'VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ' +
            'ON CONFLICT(qname_digest) DO UPDATE SET ' +
            'record_type = ?2, zone_id = ?3, zone_key = ?4, answer_json = ?5, chain_json = ?6, ' +
            'cached_at = ?7, expires_at = ?8',
        )
        .bind(
          qnameDigestValue,
          answer.record.type,
          answer.zone.id,
          zoneKey,
          JSON.stringify(answer),
          JSON.stringify(chain),
          now,
          expiresAt,
        )
        .run()
    } catch {
      // A resolver that cannot cache is slow, not wrong.
    }
  }
  return expiresAt
}

async function deleteCacheEntry(env, qnameDigestValue) {
  const edge = edgeCache()
  if (edge) {
    try {
      await edge.delete(new Request(edgeCacheKey(qnameDigestValue), { method: 'GET' }))
    } catch {
      /* best effort */
    }
  }
  const db = d1(env)
  if (db) {
    try {
      await db.prepare('DELETE FROM nf3_resolution_cache WHERE qname_digest = ?1').bind(qnameDigestValue).run()
    } catch {
      /* best effort */
    }
  }
}

/**
 * Purge the cached answer for one VIN across both tiers.
 *
 * This is the invalidation DNS never had, and it is the reason the TTL ceilings above are
 * tolerable rather than merely conventional: when an owner withdraws, when a broker moves, or
 * when a zone rotates a key, the party that knows can push a purge instead of waiting out a
 * TTL. It is best-effort by nature — a resolver that never hears the purge falls back to the
 * TTL ceiling, which is exactly why the ceiling has to be short enough to be an acceptable
 * worst case on its own.
 */
export async function purgeResolutionCache(vin, env) {
  const digest = await qnameDigest(vin)
  await deleteCacheEntry(env, digest)
  return digest
}

/**
 * Delete expired rows. Call from a scheduled Worker.
 *
 * A cache with no sweep is a growing record of which vehicles someone asked about. Each row is
 * innocuous; the accumulation is not, which is the same distinction the Delete Act draws when
 * it treats an inventory of vehicle identifiers as a regulated category (§9.5).
 */
export async function sweepResolutionCache(env, now = Math.floor(Date.now() / 1000)) {
  const db = d1(env)
  if (!db) return { deleted: 0, swept: false }
  const result = await db.prepare('DELETE FROM nf3_resolution_cache WHERE expires_at <= ?1').bind(now).run()
  return { deleted: result?.meta?.changes ?? 0, swept: true }
}

// ---------------------------------------------------------------------------------
// Trust anchors
// ---------------------------------------------------------------------------------

/**
 * Load the resolver's trust anchors: `{ [zoneId]: { endpoint, key } }`.
 *
 * Read from `env.NF3_TRUST_ANCHORS` (a Worker var or secret, i.e. deployment configuration)
 * first, and only then from `opts.trustAnchors`. The order matters: a caller-supplied anchor is
 * accepted for tests and for a stub resolver doing its own iteration, but configuration wins,
 * because otherwise any code path that reaches `resolveVin` with attacker-influenced options
 * could substitute its own root of trust.
 *
 * VALIDATION IS MANDATORY. With no usable anchor, resolution REFUSES; it does not fall back to
 * an unauthenticated answer. There is no "insecure" and no "indeterminate" state in this
 * protocol — only authenticated or refused. DNSSEC's optional validation is a large part of why
 * it took two decades to matter: as long as unvalidated answers are acceptable somewhere, an
 * attacker's job is to make validation fail rather than to forge a signature.
 *
 * ANY ZONE MAY BE AN ANCHOR, and that is Refusal 3 expressed in the trust model rather than in
 * the topology. A resolver can be configured with the WMI zone it cares about, or an operator
 * zone, and never contact the root at all. A root that every resolver must trust is a licensor
 * of access whatever its bylaws say. The root is a convenience for resolvers that do not know
 * where to start.
 *
 * The endpoint in an anchor is a ROOT HINT in the DNS sense: a bootstrap address, not an
 * authority. Getting it wrong is a denial of service, never a spoof, because the key is what
 * authenticates the answer. That asymmetry is why hints can be plain configuration.
 */
export function loadTrustAnchors(env, opts = {}) {
  const anchors = new Map()
  const sources = []

  const fromEnv = env?.NF3_TRUST_ANCHORS
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    try {
      sources.push(JSON.parse(fromEnv))
    } catch {
      throw new Error('env.NF3_TRUST_ANCHORS is not parseable JSON; refusing to resolve without anchors')
    }
  } else if (isPlainObject(fromEnv)) {
    sources.push(fromEnv)
  }
  if (isPlainObject(opts.trustAnchors)) sources.push(opts.trustAnchors)

  for (const source of sources) {
    for (const [zoneId, spec] of Object.entries(source)) {
      if (anchors.has(zoneId)) continue // first source wins; env is first
      if (!isPlainObject(spec)) continue
      if (!isBase64urlBytes(spec.key, ED25519_PUBLIC_KEY_BYTES)) continue
      const urlCheck = validateEndpointUrl(spec.endpoint, {
        allowInsecureLoopback: opts.allowInsecureLoopback === true,
      })
      if (!urlCheck.ok) continue
      const zone = zoneFromId(zoneId)
      if (zone === null) continue
      anchors.set(zone.id, { zone, key: spec.key, endpoint: urlCheck.url })
    }
  }
  return anchors
}

/** Parse a canonical zone id back into a zone, or null. Rejects anything non-canonical. */
export function zoneFromId(zoneId) {
  if (typeof zoneId !== 'string') return null
  try {
    if (zoneId === 'root') return makeZone('root')
    const idx = zoneId.indexOf(':')
    if (idx <= 0) return null
    const scopeType = zoneId.slice(0, idx)
    const scope = zoneId.slice(idx + 1)
    if (!NF3_SCOPE_TYPES.includes(scopeType) || scopeType === 'root') return null
    const zone = makeZone(scopeType, scope)
    return zone.id === zoneId ? zone : null
  } catch {
    return null
  }
}

/**
 * Choose where to start. Most specific anchor first: an operator anchor, then this VIN's WMI
 * zone, then the root. Preferring the specific one is what makes bypassing the root the normal
 * case for a resolver that has been told something more precise, rather than an escape hatch
 * nobody uses.
 */
function selectStartZone(anchors, vinNormalized) {
  const vinWmi = wmi(vinNormalized)
  for (const anchor of anchors.values()) {
    if (anchor.zone.scope_type === 'operator') return anchor
  }
  if (vinWmi !== null && anchors.has(`wmi:${vinWmi}`)) return anchors.get(`wmi:${vinWmi}`)
  if (anchors.has('root')) return anchors.get('root')
  return null
}

// ---------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------

/**
 * Default zone transport: POST the question to the zone's endpoint, parse one signed answer.
 *
 * Every option here is load-bearing:
 *  - POST, not GET, because the qname digest must not appear in a URL — it would land in every
 *    intermediary's access log and in any cache keyed by URL. A POST also is not cached by an
 *    intermediary that does not understand the protocol, which is right for a nonce-bound
 *    exchange.
 *  - `redirect: 'error'` because following a redirect lets a zone bounce the resolver to an
 *    arbitrary URL: an SSRF primitive, and it also means the response no longer comes from the
 *    endpoint the delegation named. The signature would still be checked, but a resolver that
 *    can be aimed anywhere is a liability regardless.
 *  - `AbortSignal.timeout` because a resolver with no timeout is a hang, and a hung resolver in
 *    a Worker is an outage for every other request sharing the isolate.
 *  - a body-size cap because a hostile zone should not be able to make the resolver a memory
 *    sink.
 *
 * Injectable via `opts.transport` so the conformance suite exercises the resolver with no
 * network at all.
 *
 * @returns {Promise<{ ok: boolean, answer: object|null, reason: string|null }>}
 */
export async function httpZoneTransport(zoneEndpoint, question, opts = {}) {
  const timeoutMs = Number.isInteger(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_QUERY_TIMEOUT_MS
  let response
  try {
    response = await fetch(zoneEndpoint, {
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(question),
      signal: typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(timeoutMs) : undefined,
    })
  } catch (err) {
    return { ok: false, answer: null, reason: `zone unreachable (${err?.message ?? String(err)})` }
  }
  if (!response.ok) {
    return { ok: false, answer: null, reason: `zone returned HTTP ${response.status}` }
  }
  const declared = Number(response.headers.get('content-length') ?? '0')
  if (declared > MAX_ANSWER_BODY_BYTES) {
    return { ok: false, answer: null, reason: `zone answer declares ${declared} bytes, over the cap` }
  }
  let text
  try {
    text = await response.text()
  } catch (err) {
    return { ok: false, answer: null, reason: `zone answer unreadable (${err?.message ?? String(err)})` }
  }
  if (text.length > MAX_ANSWER_BODY_BYTES) {
    return { ok: false, answer: null, reason: 'zone answer exceeds the body cap' }
  }
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    return { ok: false, answer: null, reason: 'zone answer is not parseable JSON' }
  }
  if (!isPlainObject(parsed)) {
    return { ok: false, answer: null, reason: 'zone answer is not a JSON object' }
  }
  // Discard everything that is not the one signed answer. THIS is the absence of DNS's
  // additional section: there is no place for unsolicited records to ride along, so the
  // Kaminsky injection has no target. Unknown top-level keys are then rejected by the closed
  // key set during verification, so a zone cannot smuggle a second record either.
  return { ok: true, answer: parsed, reason: null }
}

// ---------------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------------

/**
 * Resolve a VIN to the location of its consent endpoint.
 *
 * RETURNS A LOCATION. NEVER AUTHORITY. Read `NF3_NO_CREDENTIAL_INVARIANT` and
 * `assertResolutionReturnsLocationsOnly`; the guarantee is structural, and this function's
 * result is passed through that assertion on every path before it is returned, including the
 * error paths.
 *
 * @param {string} vin
 * @param {object} env  Worker bindings: `NF3_DB` or `DB` (D1), `NF3_TRUST_ANCHORS`
 * @param {object} [opts]
 * @param {'recursive'|'iterative'} [opts.mode='recursive']
 *        'recursive' — this resolver follows referrals itself and returns a terminal answer.
 *        'iterative' — one query only, returning a referral for the CALLER to follow. This is
 *        the mode a party uses when it declines to trust a recursive resolver: it does its own
 *        chain walk and its own validation, which is precisely the DNS stub-vs-recursive
 *        distinction. Nothing about the answer is weaker; the trust decision simply moves.
 * @param {object} [opts.fromZone] `{ id, scope_type, scope, endpoint, key }` — continue an
 *        iterative walk from a referral the caller already validated. The resolver still
 *        verifies the answer against `fromZone.key`, so the caller's anchor discipline is what
 *        is load-bearing; the result's chain records that the walk began at a caller-supplied
 *        zone so this is visible downstream and never mistaken for an anchored chain.
 * @param {object} [opts.trustAnchors] fallback anchors; `env` wins where both define a zone
 * @param {boolean} [opts.strictCheckDigit=true]
 * @param {boolean} [opts.noCache=false]
 * @param {Function} [opts.transport] `(endpoint, question, opts) => { ok, answer, reason }`
 * @param {number} [opts.now] Unix seconds
 * @param {number} [opts.clockSkewS]
 * @param {number} [opts.timeoutMs]
 * @param {boolean} [opts.allowInsecureLoopback=false] http + loopback hosts, for local dev only
 * @returns {Promise<object>} a resolution result; see NF3_RESULT_KEYS
 */
export async function resolveVin(vin, env, opts = {}) {
  const now = Number.isInteger(opts.now) ? opts.now : Math.floor(Date.now() / 1000)
  const notes = []

  // 1. The name must be a well-formed name before anything else happens. A resolver that
  //    queries on unvalidated input is a proxy for whatever the caller typed.
  const strict = opts.strictCheckDigit !== false
  const v = validateVin(vin, { strict })
  const vinSyntax = Object.freeze({
    syntax_valid: v.syntaxValid,
    check_digit_valid: v.checkDigitValid,
    strict,
  })
  if (!v.syntaxValid) {
    return makeResult({ status: 'error', vinSyntax, reasons: [`vin_invalid: ${v.reason}`], notes })
  }
  if (!v.valid) {
    // vin.js reports syntax and check digit separately on purpose: some non-North-American and
    // grey-market vehicles carry structurally valid VINs that fail 49 C.F.R. §565.15. Strict is
    // the default because a failed check digit is usually a transcription error, and resolving
    // a mistyped VIN sends the caller to the wrong vehicle's broker. The caller can opt out.
    return makeResult({
      status: 'error',
      vinSyntax,
      reasons: [`vin_check_digit: ${v.reason} (pass strictCheckDigit: false to resolve anyway)`],
      notes,
    })
  }

  const digest = await qnameDigest(v.normalized)

  // 2. No anchor, no resolution. There is no unauthenticated mode.
  let anchors
  try {
    anchors = loadTrustAnchors(env, opts)
  } catch (err) {
    return makeResult({ status: 'error', vinSyntax, qnameDigest: digest, reasons: [`anchor_invalid: ${err?.message ?? String(err)}`], notes })
  }

  const mode = opts.mode ?? 'recursive'
  if (mode !== 'recursive' && mode !== 'iterative') {
    return makeResult({ status: 'error', vinSyntax, qnameDigest: digest, reasons: [`mode_unknown: "${String(mode)}"`], notes })
  }

  // 3. Cache. Only terminal answers are cached, so a hit is always a final answer.
  if (opts.noCache !== true) {
    const hit = await readCache(env, digest, v.normalized, anchors, now, opts)
    if (hit !== null) {
      return resultFromTerminalAnswer({
        answer: hit.answer,
        chain: hit.chain,
        expiresAt: hit.expiresAt,
        now,
        source: hit.source,
        vinSyntax,
        digest,
        notes,
      })
    }
  }

  // 4. Where to start.
  let current
  if (isPlainObject(opts.fromZone)) {
    const zone = zoneFromId(opts.fromZone.id)
    const urlCheck = validateEndpointUrl(opts.fromZone.endpoint, {
      allowInsecureLoopback: opts.allowInsecureLoopback === true,
    })
    if (zone === null || !urlCheck.ok || !isBase64urlBytes(opts.fromZone.key, ED25519_PUBLIC_KEY_BYTES)) {
      return makeResult({ status: 'error', vinSyntax, qnameDigest: digest, reasons: ['from_zone_invalid: fromZone needs a canonical id, a valid endpoint and a 32-byte base64url key'], notes })
    }
    current = { zone, key: opts.fromZone.key, endpoint: urlCheck.url, source: 'caller' }
    notes.push('chain_root_is_caller_supplied: the caller is acting as its own validator')
  } else {
    const anchor = selectStartZone(anchors, v.normalized)
    if (anchor === null) {
      return makeResult({
        status: 'error',
        vinSyntax,
        qnameDigest: digest,
        reasons: [
          'no_trust_anchor: no usable trust anchor for this name. Resolution REFUSES rather ' +
            'than answering without authentication — there is no insecure mode',
        ],
        notes,
      })
    }
    current = { zone: anchor.zone, key: anchor.key, endpoint: anchor.endpoint, source: 'anchor' }
  }

  // 5. Walk.
  const transport = typeof opts.transport === 'function' ? opts.transport : httpZoneTransport
  const chain = []
  const visited = new Set()
  const maxHops = mode === 'iterative' ? 1 : MAX_REFERRAL_HOPS

  for (let hop = 0; hop < maxHops; hop += 1) {
    if (visited.has(current.zone.id)) {
      return makeResult({
        status: 'error',
        vinSyntax,
        qnameDigest: digest,
        chain,
        reasons: [`referral_loop: zone "${current.zone.id}" appears twice in one resolution`],
        notes,
      })
    }
    visited.add(current.zone.id)
    chain.push(Object.freeze({ zone_id: current.zone.id, key: current.key, source: current.source }))

    const nonce = generateQueryNonce()
    const question = makeQuestion(digest, nonce)
    const wire = await transport(current.endpoint, question, {
      timeoutMs: opts.timeoutMs,
      zone: current.zone,
    })
    if (!wire?.ok) {
      return makeResult({
        status: 'error',
        vinSyntax,
        qnameDigest: digest,
        chain,
        reasons: [`zone_query_failed: ${current.zone.id}: ${wire?.reason ?? 'no answer'}`],
        notes,
      })
    }

    const verdict = await verifyResolutionAnswer(wire.answer, {
      vin: v.normalized,
      expectedZone: current.zone,
      zonePublicKey: current.key,
      expectedNonce: nonce,
      now,
      clockSkewS: opts.clockSkewS,
      allowInsecureLoopback: opts.allowInsecureLoopback === true,
    })
    if (!verdict.valid) {
      // Terminal. No fallback to another source, because "try elsewhere when validation fails"
      // hands an attacker who can break the good answer the choice of replacement.
      return makeResult({
        status: 'error',
        vinSyntax,
        qnameDigest: digest,
        chain,
        reasons: verdict.reasons.map((r) => `answer_rejected(${current.zone.id}): ${r}`),
        notes,
      })
    }

    const answer = wire.answer
    if (TERMINAL_RECORD_TYPES.includes(answer.record.type)) {
      const clamped = clampTtl(answer.ttl, answer.record.type)
      if (clamped.clamped) notes.push(`ttl_clamped: ${answer.ttl}s -> ${clamped.ttl}s by NF-3 policy`)
      let expiresAt = Math.min(answer.answered_at, now) + clamped.ttl
      if (opts.noCache !== true) {
        const written = await writeCache(env, digest, { answer, zoneKey: current.key, chain, now })
        if (written !== null) expiresAt = written
      }
      return resultFromTerminalAnswer({
        answer,
        chain,
        expiresAt,
        now,
        source: 'authoritative',
        vinSyntax,
        digest,
        notes,
      })
    }

    // A delegation. In iterative mode hand it to the caller; in recursive mode follow it.
    const child = {
      zone: Object.freeze({ ...answer.record.child_zone }),
      key: answer.record.child_zone_key,
      endpoint: answer.record.child_endpoint,
      source: 'delegation',
    }
    if (mode === 'iterative') {
      const clamped = clampTtl(answer.ttl, 'delegation')
      return makeResult({
        status: 'referral',
        vinSyntax,
        qnameDigest: digest,
        chain,
        authenticated: true,
        referral: Object.freeze({
          zone: child.zone,
          endpoint: child.endpoint,
          key: child.key,
          ttl_s: clamped.ok ? clamped.ttl : null,
        }),
        ttlRemainingS: clamped.ok ? clamped.ttl : null,
        expiresAt: clamped.ok ? Math.min(answer.answered_at, now) + clamped.ttl : null,
        source: 'authoritative',
        notes,
      })
    }
    current = child
  }

  return makeResult({
    status: 'error',
    vinSyntax,
    qnameDigest: digest,
    chain,
    reasons: [
      `referral_exhausted: more than ${maxHops} hop(s) without a terminal answer; the NF-3 ` +
        'namespace is root -> wmi -> operator and nothing legitimate is deeper',
    ],
    notes,
  })
}

// ---------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------

/**
 * The single constructor for every resolution result, success and failure alike.
 *
 * ONE CONSTRUCTOR IS THE POINT. Every result in this module goes through here and through
 * `assertResolutionReturnsLocationsOnly` before it reaches a caller, which is what turns
 * Refusal 1 from a property of twelve return statements into a property of one. A future return
 * path that skipped this function would have to skip the assertion too, and that is a visible
 * thing to do in review.
 *
 * `endpoint` is null unless `authenticated` is true — enforced by the assertion, not by
 * convention — so there is no state in which a caller holds an unverified location.
 *
 * THE VIN IS NOT ECHOED. The caller already has it, and an echoed VIN ends up in the logs of
 * whatever wraps this call. `vin_syntax` reports what was checked without repeating the name
 * (§9.5 data minimisation, applied to our own output).
 */
function makeResult(parts) {
  const result = {
    v: NF3_RESOLUTION_VERSION,
    status: parts.status,
    qname_digest: parts.qnameDigest ?? null,
    vin_syntax: parts.vinSyntax ?? null,
    endpoint: parts.endpoint ?? null,
    referral: parts.referral ?? null,
    authenticated: parts.authenticated === true,
    ttl_remaining_s: parts.ttlRemainingS ?? null,
    expires_at: parts.expiresAt ?? null,
    source: parts.source ?? null,
    chain: Object.freeze([...(parts.chain ?? [])]),
    reasons: Object.freeze([...(parts.reasons ?? [])]),
    notes: Object.freeze([...(parts.notes ?? [])]),
  }
  assertResolutionReturnsLocationsOnly(result)
  return Object.freeze(result)
}

/** Turn a verified terminal answer — `ce`, `nxenroll` or `nxzone` — into a result. */
function resultFromTerminalAnswer({ answer, chain, expiresAt, now, source, vinSyntax, digest, notes }) {
  // TTL counts DOWN. A cache hit reports the time remaining, never the original TTL, which is
  // RFC 1035's rule and the reason a chain of caches cannot extend an answer's life.
  const remaining = Number.isInteger(expiresAt) ? Math.max(0, expiresAt - now) : null

  if (answer.record.type === 'ce') {
    return makeResult({
      status: 'resolved',
      vinSyntax,
      qnameDigest: digest,
      authenticated: true,
      endpoint: Object.freeze({
        url: answer.record.endpoint,
        protocol_version: answer.record.protocol_version,
        supported_field_classes: Object.freeze([...answer.record.supported_field_classes]),
        broker_key: answer.record.broker_key,
        zone: answer.zone,
      }),
      ttlRemainingS: remaining,
      expiresAt,
      source,
      chain,
      notes,
    })
  }

  return makeResult({
    status: answer.record.type === 'nxenroll' ? 'not-enrolled' : 'no-zone',
    vinSyntax,
    qnameDigest: digest,
    // An authenticated denial. The distinction matters: a signed `nxenroll` is a statement by
    // the authoritative zone, whereas an unauthenticated absence would be indistinguishable
    // from an injected denial-of-enrolment. `authenticated: true` on a negative answer means
    // "the zone said no", not "we failed to find anything".
    authenticated: true,
    ttlRemainingS: remaining,
    expiresAt,
    source,
    chain,
    reasons: [
      answer.record.type === 'nxenroll'
        ? `not_enrolled: zone "${answer.zone.id}" authoritatively reports this vehicle is not enrolled`
        : 'no_zone: no zone claims this VIN\'s scope, so there is no authoritative party to ask',
    ],
    notes,
  })
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
 * Strict base64url of an exact byte length — length and charset checked before decoding, so a
 * value carrying padding, whitespace or standard-alphabet characters cannot round-trip to
 * different bytes on different decoders. Every value guarded by this is inside a signature.
 *
 * Duplicated from nf2-grant.js, where it is private. It is a pure predicate rather than a
 * security constant, so a second copy cannot drift into disagreement about a policy — but see
 * the report: both modules want a shared base64url helper.
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

/** Lowercase and strip separators, so `Set-Cookie`, `set_cookie` and `setCookie` are one name. */
function normalizeKeyName(key) {
  return String(key).toLowerCase().replace(/[-_\s]/g, '')
}

/**
 * Reject unknown parameter names. Same reasoning as nf2-grant.js: a silently ignored misspelled
 * parameter is how an object ends up with a default nobody chose.
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

function requireZoneShape(zone) {
  const reasons = zoneShapeReasons(zone)
  if (reasons.length > 0) throw new Error(`invalid zone: ${reasons.join('; ')}`)
  return Object.freeze({ id: zone.id, scope_type: zone.scope_type, scope: zone.scope })
}

function requireRecordShape(record) {
  const reasons = recordShapeReasons(record)
  if (reasons.length > 0) throw new Error(`invalid record: ${reasons.join('; ')}`)
  return record
}

/** Sort and de-duplicate field classes with the JCS comparator. */
function normalizeFieldClasses(classes) {
  if (!Array.isArray(classes) || classes.length === 0) {
    throw new Error('supportedFieldClasses must be a non-empty array')
  }
  const seen = new Set()
  for (const c of classes) {
    if (typeof c !== 'string') throw new Error('field class ids must be strings')
    if (seen.has(c)) throw new Error(`duplicate field class "${c}"`)
    seen.add(c)
  }
  const sorted = [...classes].sort(compareCodeUnits)
  const reasons = fieldClassReasons(sorted)
  if (reasons.length > 0) throw new Error(reasons.join('; '))
  return sorted
}

/**
 * The WebCrypto algorithm object for an Ed25519 CryptoKey, taken from the key itself.
 *
 * Cloudflare Workers shipped Ed25519 as `NODE-ED25519` before the WebCrypto Secure Curves draft
 * settled on plain `Ed25519`; nf2-grant.js resolves that once by probing and caches the winner.
 * Reading the name off the key reuses that resolution instead of duplicating the probe, so
 * there is exactly one place in the codebase that decides which name this runtime uses. The
 * `namedCurve` is included for the legacy name because some builds require it.
 */
function algorithmFromKey(key) {
  const name = key?.algorithm?.name
  if (name !== 'Ed25519' && name !== 'NODE-ED25519') {
    throw new Error(
      `key algorithm is "${String(name)}"; NF-3 answers are Ed25519 only, pinned by the ` +
        'answer version. Refusing to substitute another signature scheme',
    )
  }
  return name === 'NODE-ED25519' ? { name, namedCurve: 'NODE-ED25519' } : { name }
}
