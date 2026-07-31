/**
 * CarNimbus consent broker — the Layer 3 Worker.
 *
 * Nimbus Foundation NF-WP-1 §3.1 (Layer 3), §8.2, §8.3, §8.4, §9.5, §10.1, §12.2, §14.
 * NF-1 §3.3 (L3-1 … L3-10), §4.3 (B3), §4.4 (B4), §10 (SEC-1 … SEC-12), §12 (I-1 … I-6).
 *
 * THIS WORKER IS OPERATED BY CARNIMBUS, INC., NOT BY THE NIMBUS FOUNDATION (Refusal 3).
 * Nothing in this file is a market: there is no price, amount, currency, fee, escrow,
 * balance, token or settlement identifier anywhere, and Layer 5 is gated out of V1 (§9.7).
 * The absence is structural — grep this file for "price" and the answer is the design.
 *
 * ---------------------------------------------------------------------------------
 * THE THREE REFUSALS, AS THEY APPEAR IN THIS FILE
 * ---------------------------------------------------------------------------------
 *
 *  1. A VIN IS NEVER RESOLVED TO A CREDENTIAL (§10.1, NF-1 L3-1/L3-2). `GET /resolve/:vin`
 *     delegates to `resolveVin`, whose every return path is already forced through
 *     `assertResolutionReturnsLocationsOnly`. This file runs that assertion AGAIN at the
 *     edge, immediately before serialisation, because the module boundary is exactly where
 *     a future "convenience field" would be spliced in. Resolution is unauthenticated on
 *     purpose: the input is public, so the answer must be safe to serve to a stranger, and
 *     an endpoint that required authentication would be quietly asserting that the VIN is
 *     worth protecting. It is not (SEC-1).
 *
 *     The other half of Refusal 1 is the one that is easy to miss: no authorisation path
 *     here accepts a VIN as an input at all. `POST /grants` takes a VIN, but only to
 *     compute a blind index and a pseudonym — a VIN with no owner session attached buys
 *     nothing, and there is no route on which possession of a VIN changes an access
 *     outcome.
 *
 *  2. NO PERSONAL INFORMATION REACHES AN IMMUTABLE LEDGER (§9.5, NF-1 B3). Everything this
 *     Worker writes goes to D1 with parameterised statements, because D1 rows can be
 *     destroyed and a standing 45-day Delete Act cadence plus CCPA erasure cannot be
 *     reconciled with an append-only store. The only two values produced here that would
 *     ever be permitted to cross onto a ledger are `deriveGrantCommitment(grant)` and an
 *     NF-4 revocation leaf key; both are fixed-length digests over preimages that the
 *     pseudonym salt makes unrecoverable once the salt is deleted.
 *
 *  3. THE FOUNDATION NEVER OPERATES WHAT IT GOVERNS (§10.2). Enforced here as data, not as
 *     etiquette: `operator_held_key_id` is consulted at issuance AND at verification, and a
 *     grant whose `revocation_key_id` is a key this deployment holds is refused by
 *     `verifyGrant` itself rather than by a policy branch. The broker holds no revocation
 *     private key, has no column for one, and `POST /revocations` therefore takes a record
 *     the OWNER signed — this Worker cannot originate one.
 *
 * ---------------------------------------------------------------------------------
 * THE HARD RULE: THE BROKER NEVER HOLDS AN OWNER'S OEM CREDENTIAL
 * ---------------------------------------------------------------------------------
 * Not in a variable, not in a row, not in a log line, not in a response, not in transit.
 * Layer 3 exists precisely so the accessing party never obtains the owner's manufacturer
 * credentials (NF-1 §3.2, B2, SEC-12), and the broker is not exempt from the property it
 * sells. There is no schema column, no binding, and no secret name for one (wrangler.toml
 * says so in the same words). Enforcement here is three-sided:
 *
 *   - `assertNoOemCredential` scans every REQUEST body before it is used, so a client that
 *     tries to hand us one is refused rather than obeyed;
 *   - the same function scans every RESPONSE body before serialisation, so no future field
 *     can carry one outward;
 *   - nothing in this file ever fetches an OEM endpoint, so there is no place a credential
 *     would be needed. The Layer-2 adapter is a separate deployment behind B2.
 *
 * ---------------------------------------------------------------------------------
 * STACK (NF-WP-1 §14, NF-1 I-1 … I-6)
 * ---------------------------------------------------------------------------------
 * Plain ES module. No npm, no build step, no bundler, no TypeScript, no framework, no
 * dependency. Web-standard APIs only. WebCrypto for everything cryptographic; no curve and
 * no cipher is hand-rolled. D1 through the binding with bound parameters exclusively —
 * there is not one string-interpolated SQL fragment in this file, and any future one is a
 * review failure rather than a style preference (I-4).
 */

import {
  COUNTERPARTY_CLASSES,
  DPPA_PURPOSES,
  isValidCounterpartyClass,
  isValidPurpose,
  layersRequired,
  validateFieldSet,
} from './fields.js'
import {
  base64url,
  base64urlToBytes,
  generatePseudonymSalt,
  validateVin,
} from './vin.js'
import {
  assertNonTransferable,
  buildGrant,
  deriveGrantCommitment,
  exportPublicKeyBase64url,
  MAX_DELEGATION_DEPTH,
  MAX_GRANT_DURATION_S,
  revocationKeyIdFromPublicKey,
  signGrant,
  verifyGrant,
} from './nf2-grant.js'
import {
  assertResolutionReturnsLocationsOnly,
  resolveVin,
} from './nf3-resolve.js'
import {
  createRevocationState,
  revokeGrant,
  revokeVehicle,
  verifyRevocation,
} from './nf4-revocation.js'

// =================================================================================
// Versions and closed vocabularies
// =================================================================================

/** Version of the broker's own wire shapes. Bumped independently of NF-2/NF-3/NF-4. */
const BROKER_API_VERSION = 'nf-broker/1'

/** Version tag on a verification verdict, so a consumer can pin what it parses. */
const VERDICT_VERSION = 'nf-broker-verdict/1'

/**
 * Domain separators. Every keyed digest this file computes is domain-separated, for the
 * reason nf4-revocation.js states at length: a digest producible by two constructions is a
 * digest replayable from one context into another.
 */
const VIN_INDEX_DOMAIN = 'nf-vin-index:v1:'
const RATE_KEY_DOMAIN = 'nf-ratelimit:v1:'
const REQUEST_SIG_DOMAIN = 'nf-request-signature:v1'
const OWNER_KEY_WRAP_DOMAIN = 'nf-owner-key-wrap:v1:'

/**
 * Audit event names. CLOSED, because `audit_log.event` is queried by name and a free-text
 * event field is a place where a request path ends up in durable storage.
 *
 * NOTE WHAT IS ABSENT: there is no resolution event. A log of who resolved which VIN would
 * reconstruct exactly the correlation the pseudonym scheme exists to prevent — it would say
 * which parties are interested in which vehicles, keyed by a public identifier, in a table
 * with no salt protecting it. schema.sql says the same thing; the absence is a control.
 */
const AUDIT_EVENTS = Object.freeze({
  GRANT_ISSUED: 'grant.issued',
  GRANT_REFUSED: 'grant.refused',
  GRANT_STATUS_READ: 'grant.status_read',
  GRANT_VERIFIED: 'grant.verified',
  REVOCATION_RECORDED: 'revocation.recorded',
  REVOCATION_REFUSED: 'revocation.refused',
})

/**
 * Error codes and the status they map to. STABLE AND MACHINE-READABLE (NF-1 R-4/R-5): a
 * code is never renamed and never reused for a different condition, because NF-5 asserts
 * *which rule fired* and a renamed code silently turns a passing assertion into a vacuous
 * one.
 *
 * The message is a FIXED string chosen from this table and never derived from an exception,
 * a database error, a stack, or any request value. That is the whole anti-leak rule for
 * errors: an error body says what the caller did wrong, never what the server is.
 */
const ERRORS = Object.freeze({
  not_found: { status: 404, message: 'no such resource' },
  method_not_allowed: { status: 405, message: 'method not allowed on this route' },
  unsupported_media_type: { status: 415, message: 'request body must be application/json' },
  body_too_large: { status: 413, message: 'request body exceeds the configured limit' },
  malformed_json: { status: 400, message: 'request body is not unambiguous JSON' },
  malformed_request: { status: 400, message: 'request does not match the expected shape' },
  unauthenticated: { status: 401, message: 'request is not authenticated' },
  replayed_request: { status: 401, message: 'request nonce has already been used' },
  forbidden: { status: 403, message: 'authenticated party may not perform this operation' },
  rate_limited: { status: 429, message: 'too many requests' },
  vehicle_not_enrolled: { status: 403, message: 'vehicle is not enrolled to this owner' },
  erasure_pending: { status: 409, message: 'an erasure request is open for this vehicle' },
  requester_unknown: { status: 403, message: 'counterparty key is not registered and active' },
  revocation_key_unknown: { status: 403, message: 'revocation key is not registered for this vehicle' },
  operator_held_revocation_key: { status: 403, message: 'revocation authority may not be operator-held' },
  counterparty_held_revocation_key: { status: 403, message: 'revocation authority may not be held by the grantee' },
  vin_rejected: { status: 422, message: 'vehicle index failed validation' },
  field_set_rejected: { status: 422, message: 'field set is outside the NF-2 closed vocabulary' },
  purpose_rejected: { status: 422, message: 'purpose is not a DPPA 2721(b) identifier' },
  counterparty_class_rejected: { status: 422, message: 'counterparty class is unknown or does not match the registry' },
  duration_rejected: { status: 422, message: 'grant duration is outside the permitted bound' },
  grant_rejected: { status: 422, message: 'grant could not be built or did not verify' },
  revocation_rejected: { status: 422, message: 'revocation record did not verify' },
  configuration_incomplete: { status: 503, message: 'deployment is missing required configuration' },
  store_unavailable: { status: 503, message: 'authoritative store is unavailable' },
  resolution_failed: { status: 502, message: 'resolution could not be completed' },
  internal: { status: 500, message: 'request failed' },
})

/**
 * Key names refused in any request or response body, at any depth.
 *
 * WHY THIS IS NOT `NF3_FORBIDDEN_KEY_NAMES`. nf3-resolve.js exports a forbidden-name list
 * and `assertNoCredentialSurface`, and this file uses BOTH — but only on the resolution
 * response, where they are exactly right. That list also forbids `grant`, `decision`,
 * `allowed` and `permitted`, which are legitimate NF-2/NF-4 vocabulary on the consent
 * routes: a verification verdict is *supposed* to say `decision`. Pointing the resolution
 * assertion at a verdict would fail on the one field the verdict exists to carry.
 *
 * So the broker keeps its own, narrower list: the names an OEM credential actually travels
 * under. The divergence is deliberate and is the reason it is written down here rather than
 * imported.
 */
const OEM_CREDENTIAL_KEY_NAMES = Object.freeze([
  'accesstoken', 'refreshtoken', 'idtoken', 'oemtoken', 'telematicstoken',
  'clientsecret', 'apikey', 'apisecret', 'secret', 'secretkey',
  'password', 'passphrase', 'pin', 'privatekey', 'keymaterial', 'wrappedprivatekey',
  'authorization', 'authorisation', 'bearer', 'bearertoken',
  'cookie', 'setcookie', 'session', 'sessionid', 'sessiontoken',
  'jwt', 'assertion', 'saml', 'credential', 'credentials',
  'oemaccount', 'oemlogin', 'manufacturercredential',
  'signedurl', 'presignedurl', 'sastoken',
])

const OEM_CREDENTIAL_KEY_SET = new Set(OEM_CREDENTIAL_KEY_NAMES.map(normaliseKeyName))

/**
 * Value shapes that are credentials whatever they are called. Copied in spirit from
 * nf3-resolve.js: the JWT pattern needs a literal '.', which base64url excludes, so no
 * signature, digest or public key in this system can trip it.
 */
const CREDENTIAL_VALUE_PATTERNS = Object.freeze([
  /^\s*bearer\s+\S/i,
  /^\s*basic\s+[A-Za-z0-9+/=]{8,}/i,
  /^ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./,
])

// =================================================================================
// Bounds
// =================================================================================

/** Fallback body cap if `env.MAX_REQUEST_BYTES` is absent. A signed grant is under 2 KiB. */
const DEFAULT_MAX_REQUEST_BYTES = 16 * 1024

/**
 * Maximum JSON nesting accepted from any body. SEC-5: unbounded nesting is a stack overflow
 * reachable from any untrusted body, and canonicalisation is a security boundary rather than
 * a formatting concern. 32 matches the depth cap in nf3-resolve.js's credential audit, so
 * one document cannot be deep enough to parse and too deep to audit.
 */
const MAX_JSON_DEPTH = 32

/** Fallback signature skew, seconds, if `env.AUTH_MAX_SKEW_S` is absent. */
const DEFAULT_AUTH_MAX_SKEW_S = 60

/** Fallback nonce memory, seconds. MUST exceed 2 x skew or the replay window outlives it. */
const DEFAULT_NONCE_TTL_S = 300

/** Fallback per-minute ceiling when no rate-limit binding is present. */
const DEFAULT_FALLBACK_RATE_LIMIT_PER_MIN = 120

/** How long a fetched Clerk JWKS is cached. Public keys; rotation is not urgent. */
const JWKS_CACHE_TTL_S = 600

/** Ceiling on a fetched JWKS body. An identity provider's key set is small. */
const MAX_JWKS_BYTES = 64 * 1024

/** Timeout on the JWKS fetch. A Worker with no timeout on an upstream is a hang. */
const JWKS_FETCH_TIMEOUT_MS = 3000

/** Bound on a delegation chain walk, matching NF-2's own ceiling. */
const MAX_ANCESTOR_HOPS = MAX_DELEGATION_DEPTH + 1

/** Probability that an authenticated request also sweeps expired nonces. */
const NONCE_SWEEP_PROBABILITY = 0.02

// =================================================================================
// Entry point
// =================================================================================

export default {
  /**
   * The single entry point. Plain Workers module format, hand-rolled router, no framework:
   * a router is twenty lines and a framework is a supply chain (wrangler.toml explains why
   * that trade is not available here).
   *
   * Every response leaves through `finish()`, so security headers, the no-OEM-credential
   * scan and the log line are properties of the function rather than of each handler.
   */
  async fetch(request, env, ctx) {
    const requestId = crypto.randomUUID()
    const startedAt = Date.now()
    const context = {
      requestId,
      // The route TEMPLATE, never the raw path. `/resolve/:vin` carries a VIN in the path,
      // and a log line containing the path is a log line containing the VIN — which is
      // precisely what §9.5 enumerates as collected personal information. The template is
      // the only form that ever reaches a log.
      route: 'unmatched',
      actorKind: 'anonymous',
      grantId: null,
      code: null,
    }

    try {
      return await route(request, env, ctx, context)
    } catch (err) {
      // Fail closed on anything unforeseen, and say nothing about it on the wire. The
      // message is logged as a boolean-ish marker only: "log the error" is the single most
      // common way a VIN or an Authorization header reaches durable storage.
      context.code = 'internal'
      console.error(
        JSON.stringify({
          at: 'unhandled',
          request_id: requestId,
          route: context.route,
          // Type name only. Never the message, never the stack, never the cause.
          error_type: err?.constructor?.name ?? 'Error',
        }),
      )
      return finish(errorResponse('internal', context), request, context, startedAt)
    }
  },
}

/**
 * Hand-rolled router. Segments are decoded once, up front, so a handler never sees a
 * percent-encoded identifier and no two handlers can disagree about decoding.
 */
async function route(request, env, ctx, context) {
  const startedAt = Date.now()
  const url = new URL(request.url)

  let segments
  try {
    segments = url.pathname.split('/').filter((s) => s.length > 0).map(decodeURIComponent)
  } catch {
    // A malformed percent sequence is a malformed request, not a 500.
    return finish(errorResponse('malformed_request', context), request, context, startedAt)
  }

  const method = request.method.toUpperCase()

  // ---- GET /healthz -------------------------------------------------------------
  if (segments.length === 0 || (segments.length === 1 && segments[0] === 'healthz')) {
    context.route = 'GET /healthz'
    if (method !== 'GET') return finish(errorResponse('method_not_allowed', context), request, context, startedAt)
    return finish(await handleHealthz(env, context), request, context, startedAt)
  }

  // ---- POST /grants -------------------------------------------------------------
  if (segments.length === 1 && segments[0] === 'grants') {
    context.route = 'POST /grants'
    if (method !== 'POST') return finish(errorResponse('method_not_allowed', context), request, context, startedAt)
    return finish(await handleIssueGrant(request, env, ctx, context, url), request, context, startedAt)
  }

  // ---- GET /grants/:id ----------------------------------------------------------
  if (segments.length === 2 && segments[0] === 'grants') {
    context.route = 'GET /grants/:id'
    if (method !== 'GET') return finish(errorResponse('method_not_allowed', context), request, context, startedAt)
    return finish(await handleGrantStatus(request, env, ctx, context, url, segments[1]), request, context, startedAt)
  }

  // ---- POST /grants/:id/verify --------------------------------------------------
  if (segments.length === 3 && segments[0] === 'grants' && segments[2] === 'verify') {
    context.route = 'POST /grants/:id/verify'
    if (method !== 'POST') return finish(errorResponse('method_not_allowed', context), request, context, startedAt)
    return finish(await handleVerifyGrant(request, env, ctx, context, url, segments[1]), request, context, startedAt)
  }

  // ---- POST /revocations --------------------------------------------------------
  if (segments.length === 1 && segments[0] === 'revocations') {
    context.route = 'POST /revocations'
    if (method !== 'POST') return finish(errorResponse('method_not_allowed', context), request, context, startedAt)
    return finish(await handleRevocation(request, env, ctx, context, url), request, context, startedAt)
  }

  // ---- GET /resolve/:vin --------------------------------------------------------
  if (segments.length === 2 && segments[0] === 'resolve') {
    context.route = 'GET /resolve/:vin'
    if (method !== 'GET') return finish(errorResponse('method_not_allowed', context), request, context, startedAt)
    return finish(await handleResolve(request, env, ctx, context, url, segments[1]), request, context, startedAt)
  }

  return finish(errorResponse('not_found', context), request, context, startedAt)
}

// =================================================================================
// GET /healthz
// =================================================================================

/**
 * Liveness, and nothing else.
 *
 * WHAT IT DELIBERATELY DOES NOT REPORT: the operator id, any binding id, any secret's
 * presence-by-name beyond a boolean, any row count, any version of the runtime, and any
 * detail of a failed probe. A health endpoint is unauthenticated by definition, so every
 * field on it is a field an attacker reads for free; the useful set is "is this deployment
 * able to serve" and the rest is reconnaissance.
 *
 * The D1 probe is a bound `SELECT 1`, parameterised like every other statement in this
 * file even though it takes no user input — the rule is unconditional so that no statement
 * in this file is a precedent for interpolation.
 */
async function handleHealthz(env, context) {
  const db = d1(env)
  let store = 'absent'
  if (db) {
    try {
      const row = await db.prepare('SELECT ?1 AS probe').bind(1).first()
      store = row?.probe === 1 ? 'up' : 'down'
    } catch {
      // The reason is not reported. A failing health probe says "down", never why.
      store = 'down'
    }
  }

  let signatureSuite = null
  try {
    signatureSuite = (await ed25519Algorithm()).name
  } catch {
    // A runtime with no Ed25519 cannot issue or verify anything. Reported as null rather
    // than as an error string, and it is the one condition that makes `ok` false while the
    // store is up: a broker that cannot verify a signature must not look healthy.
    signatureSuite = null
  }

  const ok = store !== 'down' && signatureSuite !== null
  return jsonResponse(
    ok ? 200 : 503,
    {
      v: BROKER_API_VERSION,
      status: ok ? 'ok' : 'degraded',
      environment: typeof env?.ENVIRONMENT === 'string' ? env.ENVIRONMENT : 'unknown',
      store,
      signature_suite: signatureSuite,
      bindings: {
        d1: db !== null,
        kv: kv(env) !== null,
        rate_limiter: typeof env?.RATE_LIMITER?.limit === 'function',
      },
    },
    context,
  )
}

// =================================================================================
// GET /resolve/:vin — NF-3. RETURNS A LOCATION. NEVER AUTHORITY.
// =================================================================================

/**
 * Resolve a VIN to the location of its consent endpoint.
 *
 * UNAUTHENTICATED, DELIBERATELY (NF-1 L3-1). The input is public — a VIN is visible through
 * a windshield and enumerable from build data — so the answer must be safe to serve to an
 * anonymous requester. Requiring authentication here would assert that the VIN is worth
 * protecting, which is the 2015/2023 mistake the doctrine exists to refuse, and it would
 * make the resolver a place where identity is collected for a question that needs none.
 *
 * NOTHING HERE CONSULTS THE GRANT TABLES. That is Refusal 1 as control flow: this handler
 * has no access to `consent_grant`, `owner_signing_key` or `revocation`, and there is no
 * branch in which a VIN alone changes an access outcome anywhere in the file (L3-2). The
 * only D1 the resolver touches is its own answer cache, which holds signed zone answers.
 *
 * THE ASSERTION RUNS TWICE. `resolveVin` forces every one of its return paths through
 * `assertResolutionReturnsLocationsOnly`; this handler runs it again on the object it is
 * about to serialise. The duplication is the point: the module boundary is exactly where a
 * later "just add the broker key so clients don't have to look it up" would be spliced in,
 * and a second assertion at the edge means such an edit fails here rather than shipping.
 */
async function handleResolve(request, env, ctx, context, url, rawVin) {
  // The unauthenticated endpoint is the one an enumerator walks, so it gets its own limiter
  // namespace: resolution traffic must not be able to exhaust the budget authenticated
  // grant traffic depends on (wrangler.toml provisions RATE_LIMITER_RESOLVE separately).
  const limited = await enforceRateLimit(env, ctx, {
    limiter: env?.RATE_LIMITER_RESOLVE,
    key: await anonymousRateKey(env, request),
    context,
  })
  if (limited) return limited

  // Closed query vocabulary. `strict` is admitted because vin.js reports syntax and check
  // digit separately for a real reason: 49 C.F.R. §565.15 mandates the check digit for the
  // North American market, ISO 3779 does not require it universally, and a resolver that
  // cannot answer for a legitimately registered grey-market vehicle has a defect rather
  // than a policy (SEC-8). Anything else is refused rather than ignored.
  for (const key of url.searchParams.keys()) {
    if (key !== 'strict') return errorResponse('malformed_request', context)
  }
  const strictParam = url.searchParams.get('strict')
  if (strictParam !== null && strictParam !== 'true' && strictParam !== 'false') {
    return errorResponse('malformed_request', context)
  }

  // Cheap syntax gate before the resolver so a malformed name never reaches the network
  // path. `resolveVin` checks this too; refusing early keeps a garbage-VIN flood off the
  // trust-anchor walk.
  const syntax = validateVin(rawVin, { strict: false })
  if (!syntax.syntaxValid) return errorResponse('vin_rejected', context)

  let result
  try {
    result = await resolveVin(rawVin, env, {
      strictCheckDigit: strictParam !== 'false',
      // Loopback + http is a development affordance and is gated on the environment as well
      // as on the flag, so a production deployment cannot be talked into an SSRF-shaped
      // resolver by a stray variable.
      allowInsecureLoopback:
        env?.ENVIRONMENT === 'development' && env?.NF3_ALLOW_INSECURE_LOOPBACK === 'true',
    })
  } catch {
    // resolveVin is written not to throw; if it does, the honest answer is that resolution
    // failed, with no detail. An exception message here could carry an endpoint URL.
    return errorResponse('resolution_failed', context)
  }

  // Refusal 1, asserted at the edge. A throw here is a bug in this deployment, not a
  // client error, and it must be a 500 with no body detail rather than a leaked object.
  try {
    assertResolutionReturnsLocationsOnly(result)
  } catch {
    console.error(JSON.stringify({ at: 'resolve', request_id: context.requestId, error_type: 'RefusalOneAssertion' }))
    return errorResponse('internal', context)
  }

  const status =
    result.status === 'resolved' || result.status === 'referral'
      ? 200
      : result.status === 'not-enrolled' || result.status === 'no-zone'
        ? 404
        : 502

  const response = jsonResponse(status, result, context)

  // NO HTTP CACHING, AND THE REASON IS NOT PERFORMANCE. The protocol already caches, in two
  // tiers, inside `resolveVin` — keyed by the qname DIGEST, on a synthetic `.invalid` URL,
  // precisely so the raw VIN stays out of cache keys, out of intermediary access logs and
  // out of D1 rows (§9.5). Setting `public, max-age=...` on THIS response would key a shared
  // cache by a URL containing the VIN and undo that in one header. `no-store` is applied by
  // `finish()` to every response in this file, including this one.
  //
  // The VIN in the path is itself a data-minimisation regression against the digest-based
  // design, accepted because the route shape is fixed. It is not a confidentiality failure
  // (SEC-1: the VIN is public), and it is bounded by never logging the path and never
  // emitting a Referer-bearing document.
  return response
}

// =================================================================================
// POST /grants — issue a Consent Grant (owner-authenticated)
// =================================================================================

/** Closed key set for the issuance body. Unknown members are refused, never ignored (SEC-6). */
const ISSUE_BODY_KEYS = Object.freeze([
  'vin',
  'fields',
  'purpose',
  'counterparty_class',
  'counterparty_key',
  'revocation_key_id',
  'duration_seconds',
  'delegation_depth',
])

/**
 * Issue a root Consent Grant.
 *
 * ONLY THE OWNER MAY DO THIS, and "owner" means a verified identity-provider session bound
 * to the `vehicle_enrolment` row for the VIN presented. The VIN alone is not, and never
 * becomes, an input to the decision (L3-2): it is used to compute a blind index for the
 * lookup and a pseudonym for the grant, and a request carrying a valid VIN with no session
 * is refused at the first gate with no lookup performed at all.
 *
 * DURATION, NOT EXPIRY. The caller supplies `duration_seconds` and the broker supplies
 * `issued_at` from its own clock. An issuer-supplied absolute expiry invites exactly the
 * millisecond-for-seconds error SEC-11 describes — a well-formed integer that turns a
 * 30-day grant into an 80,000-year one — and it creates two sources of time that have to
 * agree. One clock, one source.
 *
 * EVERY GATE FAILS CLOSED, and each is a separate refusal rather than a narrowing:
 * a grant that quietly covers less, or lasts less, than the owner read is a consent defect
 * and not a convenience (fields.js says the same about the vocabulary).
 */
async function handleIssueGrant(request, env, ctx, context, url) {
  if ([...url.searchParams.keys()].length > 0) return errorResponse('malformed_request', context)

  // ---- 1. Authenticate the owner BEFORE touching the database ---------------------
  // Ordering is load-bearing: an unauthenticated caller must not be able to make this
  // Worker perform a lookup keyed by a VIN they supplied, or the endpoint becomes an
  // enrolment oracle for anyone holding a windshield photograph.
  const session = await authenticateOwner(request, env, context)
  if (session.error !== null) return errorResponse(session.error, context)
  context.actorKind = 'owner'

  const limited = await enforceRateLimit(env, ctx, {
    limiter: env?.RATE_LIMITER,
    key: await keyedDigest(env, RATE_KEY_DOMAIN, `owner:${session.subject}`),
    context,
  })
  if (limited) return limited

  const db = d1(env)
  if (db === null) return errorResponse('store_unavailable', context)

  // ---- 2. Body ---------------------------------------------------------------------
  const parsed = await readJsonBody(request, env, context)
  if (parsed.error !== null) return errorResponse(parsed.error, context)
  const body = parsed.value
  if (!hasExactlyKeys(body, ISSUE_BODY_KEYS, ['delegation_depth'])) {
    return errorResponse('malformed_request', context)
  }

  // ---- 3. Vocabulary gates, before any secret is touched ---------------------------
  const vin = validateVin(body.vin, { strict: true })
  if (!vin.valid) return errorResponse('vin_rejected', context)

  const fieldCheck = validateFieldSet(body.fields)
  if (!fieldCheck.ok) {
    // This is also the non-transactability gate. Precise geolocation, biometrics and
    // in-cabin A/V have NO FIELD ID in fields.js, so the refusal is "that name is not in the
    // vocabulary" rather than "that name is denied" — there is no encoding for the waiver
    // and therefore nothing for a pressured owner or a persuasive counterparty to waive
    // (§8.2, §12.2). V1 additionally admits no positional field at any precision.
    await audit(env, ctx, context, {
      event: AUDIT_EVENTS.GRANT_REFUSED,
      outcome: 'deny',
      reasonCode: 'field_set_rejected',
    })
    return errorResponse('field_set_rejected', context)
  }
  if (!isValidPurpose(body.purpose)) return errorResponse('purpose_rejected', context)
  if (!isValidCounterpartyClass(body.counterparty_class)) {
    return errorResponse('counterparty_class_rejected', context)
  }
  if (!isBase64urlBytes(body.counterparty_key, 32)) return errorResponse('malformed_request', context)
  if (!isBase64urlBytes(body.revocation_key_id, 32)) return errorResponse('malformed_request', context)

  const duration = body.duration_seconds
  if (!Number.isSafeInteger(duration) || duration <= 0 || duration > MAX_GRANT_DURATION_S) {
    // The 45-day ceiling is pinned to the Delete Act deletion cadence: no grant may outlive
    // a full erasure sweep unaffirmed, and expiry is revocation's fail-safe rather than a
    // convenience (SEC-9). Refused here, in nf2-grant.js, and again by a schema CHECK.
    return errorResponse('duration_rejected', context)
  }
  const delegationDepth = body.delegation_depth ?? 0
  if (!Number.isSafeInteger(delegationDepth) || delegationDepth < 0 || delegationDepth > MAX_DELEGATION_DEPTH) {
    return errorResponse('malformed_request', context)
  }

  // ---- 4. Enrolment, and that this session owns it ---------------------------------
  let vinIndexValue
  try {
    vinIndexValue = await vinIndex(env, vin.normalized)
  } catch {
    // A missing VIN_INDEX_KEY is a deployment fault, not a client error, and it must not
    // fall back to a plaintext lookup.
    return errorResponse('configuration_incomplete', context)
  }

  const enrolment = await db
    .prepare(
      'SELECT vehicle_id, owner_account_id, pseudonym_epoch FROM vehicle_enrolment WHERE vin_index = ?1',
    )
    .bind(vinIndexValue)
    .first()

  // One refusal for "not enrolled" and for "enrolled to somebody else". Distinguishing them
  // would turn this route into an oracle answering "is this VIN enrolled here" for anyone
  // with any valid session, and the VIN is public.
  if (!enrolment || !timingSafeEqualString(String(enrolment.owner_account_id), session.subject)) {
    return errorResponse('vehicle_not_enrolled', context)
  }
  const vehicleId = String(enrolment.vehicle_id)
  const epoch = Number(enrolment.pseudonym_epoch)
  if (!Number.isSafeInteger(epoch) || epoch < 0) return errorResponse('store_unavailable', context)

  // ---- 5. The Delete Act gate (§9.5, M3) -------------------------------------------
  // A deletion request in flight and a fresh 45-day authorisation minted alongside it are
  // contradictory instructions, and the one the consumer actually gave is the deletion.
  const suppression = await db
    .prepare(
      "SELECT 1 AS open FROM drop_suppression WHERE vehicle_id = ?1 AND status IN ('pending', 'processing') LIMIT 1",
    )
    .bind(vehicleId)
    .first()
  if (suppression) {
    await audit(env, ctx, context, {
      event: AUDIT_EVENTS.GRANT_REFUSED,
      outcome: 'deny',
      vehicleId,
      reasonCode: 'erasure_pending',
    })
    return errorResponse('erasure_pending', context)
  }

  // ---- 6. The counterparty is a registered party of the class named ----------------
  // A grant names a `counterparty_class`, and that name means something only because some
  // party vouches that the key belongs to a party of that class. The registry is that
  // vouching, and unlike the grant it is revocable: a repair shop that loses its licence
  // loses service without every owner having to revoke individually.
  const requester = await db
    .prepare(
      'SELECT r.requester_id AS requester_id, r.counterparty_class AS class, r.status AS requester_status, ' +
        'k.status AS key_status FROM requester_key k JOIN requester r ON r.requester_id = k.requester_id ' +
        'WHERE k.public_key = ?1',
    )
    .bind(body.counterparty_key)
    .first()
  if (!requester || requester.key_status !== 'active' || requester.requester_status !== 'active') {
    return errorResponse('requester_unknown', context)
  }
  if (requester.class !== body.counterparty_class) {
    return errorResponse('counterparty_class_rejected', context)
  }

  // ---- 7. Refusal 3, as data ------------------------------------------------------
  // The revocation key must be one the OWNER registered for THIS vehicle, and must not be
  // a key this deployment holds. Both halves matter: the first stops a grant naming a
  // stranger's revocation authority (free griefing), the second stops the broker holding
  // the lever it exists to not hold. verifyGrant re-checks the second below, from the
  // grant alone, so this is defence in depth rather than the only lock.
  const revocationKey = await db
    .prepare('SELECT vehicle_id FROM owner_revocation_key WHERE revocation_key_id = ?1')
    .bind(body.revocation_key_id)
    .first()
  if (!revocationKey || String(revocationKey.vehicle_id) !== vehicleId) {
    return errorResponse('revocation_key_unknown', context)
  }
  if (await isOperatorHeldKeyId(db, body.revocation_key_id)) {
    return errorResponse('operator_held_revocation_key', context)
  }
  // The GRANTEE must not hold revocation authority either. A revocation key the counterparty
  // controls is not a revocation key, it is a promise — and a grantee will not exercise it.
  // `verifyGrant` refuses this from the grant alone and would catch it at the self-check
  // below, but catching it here keeps that self-check meaning what it says: a failure there
  // is a defect in this deployment, not a client mistake, and conflating the two would train
  // an operator to ignore the alarm. Both forms are screened, because the naive mistake
  // (pasting the key into the id field) and the actual attack (arranging for the grantee's
  // own thumbprint to be the nominal authority) look different in the request.
  if (
    timingSafeEqualString(body.revocation_key_id, body.counterparty_key) ||
    timingSafeEqualString(body.revocation_key_id, await thumbprintOf(body.counterparty_key))
  ) {
    return errorResponse('counterparty_held_revocation_key', context)
  }

  // ---- 8. Salt and custodial signing key -------------------------------------------
  const now = nowSeconds()
  let salt
  let signer
  try {
    salt = await loadOrCreateSalt(db, vehicleId, epoch, now)
    signer = await loadOrCreateSigningKey(db, env, vehicleId, body.counterparty_class, now)
  } catch (err) {
    if (err?.nfCode === 'configuration_incomplete') return errorResponse('configuration_incomplete', context)
    return errorResponse('store_unavailable', context)
  }

  // ---- 9. Build, sign, and prove the result -----------------------------------------
  let grant
  let commitment
  try {
    // The VIN is consumed HERE AND ONLY HERE. buildGrant re-reads its own canonical output
    // to prove the raw VIN is absent (L3-5, Refusal 1) — the property is verified against
    // the output rather than asserted about the code.
    const unsigned = await buildGrant({
      vin: vin.normalized,
      pseudonymSalt: salt,
      pseudonymEpoch: epoch,
      fields: body.fields,
      purpose: body.purpose,
      counterpartyClass: body.counterparty_class,
      counterpartyKey: body.counterparty_key,
      revocationKeyId: body.revocation_key_id,
      issuedAt: now,
      durationSeconds: duration,
      delegationDepth,
      renewalOf: null,
    })
    grant = await signGrant(unsigned, signer.privateKey)

    // Non-transferability, asserted rather than assumed. There is no transfer, assign or
    // reissue operation in this Worker and there must never be one: a transferable
    // capability is an asset, an asset has a price, and a priced consent object is Layer 5.
    assertNonTransferable(grant)

    // Verify our own output before storing it. A broker that emits a grant it cannot verify
    // has shipped an unverifiable authorisation, and the owner discovers it at the moment
    // they need it to work. This also re-runs the Refusal 3 check from the grant alone.
    const verdict = await verifyGrant(grant, {
      ownerPublicKey: signer.publicKey,
      presenterKey: body.counterparty_key,
      forbiddenRevocationKeyIds: (await isOperatorHeldKeyId(db, grant.revocation_key_id))
        ? [grant.revocation_key_id]
        : [],
      now,
    })
    if (!verdict.valid) {
      console.error(JSON.stringify({ at: 'issue', request_id: context.requestId, error_type: 'SelfVerifyFailed' }))
      return errorResponse('grant_rejected', context)
    }

    commitment = await deriveGrantCommitment(grant)
  } catch {
    // Every throw from nf2-grant.js is a refusal to build something invalid. The detail is
    // deliberately not surfaced: those messages quote field ids and timestamps, and this
    // response is going to a client that supplied them but should not be handed a mirror.
    return errorResponse('grant_rejected', context)
  }

  // ---- 10. Store. `payload_json` is authoritative; the columns are indexes ----------
  try {
    await db
      .prepare(
        'INSERT INTO consent_grant (grant_id, vehicle_id, payload_json, commitment, pseudonym_value, ' +
          'pseudonym_epoch, audience, counterparty_class, counterparty_key, purpose, revocation_key_id, ' +
          'issued_at, expires_at, delegation_depth, parent_grant_id, renewal_of, created_at) ' +
          'VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)',
      )
      .bind(
        grant.grant_id,
        vehicleId,
        JSON.stringify(grant),
        commitment,
        grant.vehicle_pseudonym.value,
        grant.vehicle_pseudonym.epoch,
        grant.vehicle_pseudonym.audience,
        grant.counterparty_class,
        grant.counterparty_key,
        grant.purpose,
        grant.revocation_key_id,
        grant.issued_at,
        grant.expires_at,
        grant.delegation_depth,
        null,
        null,
        now,
      )
      .run()
  } catch {
    return errorResponse('store_unavailable', context)
  }

  context.grantId = grant.grant_id
  await audit(env, ctx, context, {
    event: AUDIT_EVENTS.GRANT_ISSUED,
    outcome: 'allow',
    vehicleId,
    grantId: grant.grant_id,
    pseudonym: grant.vehicle_pseudonym.value,
    actorId: null, // An owner is never named in an audit row; vehicle_id answers every question the log has.
    detail: {
      counterparty_class: grant.counterparty_class,
      purpose: grant.purpose,
      field_count: grant.fields.length,
      duration_s: grant.expires_at - grant.issued_at,
      delegation_depth: grant.delegation_depth,
    },
  })

  // The grant is returned in full because a grant is NOT A SECRET (SEC-2): it authorises
  // only a presenter who can prove possession of the bound private key, so it may be
  // stored, logged and shipped over an untrusted bearer. `commitment` is returned because
  // it is the one value about this grant that would ever be permitted to cross onto a
  // ledger, and the holder needs it to request a revocation proof.
  return jsonResponse(
    201,
    { v: BROKER_API_VERSION, grant, commitment, status: 'active' },
    context,
    { location: `/grants/${grant.grant_id}` },
  )
}

// =================================================================================
// GET /grants/:id — status only
// =================================================================================

/**
 * Report whether a grant is active, expired or revoked. NOTHING ELSE.
 *
 * NO PAYLOAD LEAKAGE, AND THE LINE IS DRAWN HARDER THAN IT LOOKS. The response carries the
 * grant id, one of three status words, and the instant the check was made. Not the field
 * set, not the purpose, not the counterparty class, not the pseudonym, not the signature,
 * and not `expires_at` — the holder already has every one of those inside the signed object
 * it is holding, so withholding them costs a legitimate caller nothing and denies an
 * illegitimate one a free read of a consent decision.
 *
 * AUTHENTICATED, AND ONE 404 FOR EVERY MISS. A grant id is 128 random bits, but "does this
 * id exist" is still a question with an answer, and answering it differently for "no such
 * grant" and "not yours" turns the route into an enumeration oracle over other people's
 * consent decisions. Unknown id, wrong holder, wrong owner: all 404.
 *
 * REVOKED BEATS EXPIRED when both are true. A grant the owner withdrew is revoked; saying
 * "expired" would report the clock's verdict in place of the owner's, and an owner
 * reviewing their history is entitled to see that their decision took effect.
 */
async function handleGrantStatus(request, env, ctx, context, url, grantId) {
  if ([...url.searchParams.keys()].length > 0) return errorResponse('malformed_request', context)
  if (!isBase64urlBytes(grantId, 16)) return errorResponse('not_found', context)

  const db = d1(env)
  if (db === null) return errorResponse('store_unavailable', context)

  const actor = await authenticateEither(request, env, context, db)
  if (actor.error !== null) return errorResponse(actor.error, context)
  context.actorKind = actor.kind

  const limited = await enforceRateLimit(env, ctx, {
    limiter: env?.RATE_LIMITER,
    key: await keyedDigest(env, RATE_KEY_DOMAIN, `${actor.kind}:${actor.rateSubject}`),
    context,
  })
  if (limited) return limited

  const row = await db
    .prepare(
      'SELECT grant_id, vehicle_id, payload_json, counterparty_key, revocation_key_id, issued_at, ' +
        'expires_at, parent_grant_id FROM consent_grant WHERE grant_id = ?1',
    )
    .bind(grantId)
    .first()
  if (!row) return errorResponse('not_found', context)

  const entitled = await isEntitledToGrant(db, actor, row)
  if (!entitled) return errorResponse('not_found', context)

  let revocation
  try {
    revocation = await revocationStatus(db, {
      grant_id: String(row.grant_id),
      revocation_key_id: String(row.revocation_key_id),
      issued_at: Number(row.issued_at),
      parent_grant_id: row.parent_grant_id === null ? null : String(row.parent_grant_id),
    })
  } catch {
    // FAIL CLOSED. An unreadable revocation store means every grant's status is unknown, and
    // unknown is not active. Reporting "active" here would be the cached-allow failure that
    // §8.4 exists to prevent, expressed as an outage instead of as a cache.
    return errorResponse('store_unavailable', context)
  }

  const now = nowSeconds()
  const status = revocation.revoked ? 'revoked' : now >= Number(row.expires_at) ? 'expired' : 'active'

  context.grantId = grantId
  await audit(env, ctx, context, {
    event: AUDIT_EVENTS.GRANT_STATUS_READ,
    outcome: 'allow',
    vehicleId: String(row.vehicle_id),
    grantId,
    actorId: actor.kind === 'requester' ? actor.requesterId : null,
    detail: { status },
  })

  return jsonResponse(200, { v: BROKER_API_VERSION, grant_id: grantId, status, checked_at: now }, context)
}

// =================================================================================
// POST /grants/:id/verify — the B4 boundary
// =================================================================================

/** Closed key set for the verification body. */
const VERIFY_BODY_KEYS = Object.freeze(['grant'])

/**
 * Verify a presented grant for the requester presenting it, and return a structured verdict.
 *
 * THIS IS THE B4 BOUNDARY (NF-1 §4.4), and the whole reason it is one endpoint rather than
 * two is that a verdict alone MUST NOT cross into Layer 4. A signature proves what the owner
 * authorised at issuance; it says nothing about now (L3-10). So the verdict, the revocation
 * state it was evaluated against, and the projection allowlist derived from the grant leave
 * together or not at all — "I forgot to check revocation" is not reachable by omission here
 * because the same handler that verifies is the handler that reads the revocation table.
 *
 * POSSESSION IS PROVED BY THE REQUEST SIGNATURE, NOT CLAIMED IN THE BODY. `presenterKey` is
 * the key this session authenticated with, never a value the body supplied — a grant is not
 * a bearer token (SEC-2), and a presenter that could name its own key would have turned it
 * back into one. A stolen grant plus no private key is worth nothing, which is exactly why
 * grants can be logged and shipped over untrusted bearers.
 *
 * THE STORED PAYLOAD IS AUTHORITATIVE. The presented object is compared to the stored one by
 * COMMITMENT, with a constant-time comparison, and the verdict is computed over the stored
 * payload. A presenter that submits an edited grant gets a mismatch rather than a verdict
 * about its edit, and the timing of the comparison does not leak how far the two agreed.
 *
 * DENIAL IS A 200. The HTTP status reports whether verification happened; `decision` reports
 * what it concluded. Conflating the two is how a monitoring rule ends up silently treating a
 * transport hiccup as an authorisation and vice versa.
 */
async function handleVerifyGrant(request, env, ctx, context, url, grantId) {
  if ([...url.searchParams.keys()].length > 0) return errorResponse('malformed_request', context)
  if (!isBase64urlBytes(grantId, 16)) return errorResponse('not_found', context)

  const db = d1(env)
  if (db === null) return errorResponse('store_unavailable', context)

  // THE BODY IS READ BEFORE AUTHENTICATION, and the ordering is forced rather than chosen:
  // the request signature covers a digest of the body, so the bytes have to exist before the
  // signature can be checked, and a Request body can only be consumed once. What an
  // unauthenticated caller can therefore make this Worker do is buffer at most
  // `MAX_REQUEST_BYTES` — bounded, counted as it streams, and abandoned the moment it is
  // exceeded. Nothing is parsed, and no database is touched, until the signature verifies.
  const contentType = (request.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase()
  if (contentType !== 'application/json') return errorResponse('unsupported_media_type', context)
  const raw = await readBodyBytes(request, env)
  if (raw.error !== null) return errorResponse(raw.error, context)

  // Requester-only. An owner session cannot stand in for possession of the counterparty
  // key, and a verification performed for a party that cannot answer the challenge is a
  // verification of nothing.
  const actor = await authenticateRequester(request, env, context, db, raw.bytes)
  if (actor.error !== null) return errorResponse(actor.error, context)
  context.actorKind = 'requester'

  const limited = await enforceRateLimit(env, ctx, {
    limiter: env?.RATE_LIMITER,
    key: await keyedDigest(env, RATE_KEY_DOMAIN, `requester:${actor.rateSubject}`),
    context,
  })
  if (limited) return limited

  const parsed = parseJsonBody(raw.bytes)
  if (parsed.error !== null) return errorResponse(parsed.error, context)
  if (!hasExactlyKeys(parsed.value, VERIFY_BODY_KEYS, [])) return errorResponse('malformed_request', context)
  const presented = parsed.value.grant
  if (!isPlainObject(presented) || presented.grant_id !== grantId) {
    return errorResponse('malformed_request', context)
  }

  const row = await db
    .prepare(
      'SELECT grant_id, vehicle_id, payload_json, commitment, audience, counterparty_key, ' +
        'revocation_key_id, issued_at, expires_at, parent_grant_id FROM consent_grant WHERE grant_id = ?1',
    )
    .bind(grantId)
    .first()
  if (!row) return errorResponse('not_found', context)

  // Entitlement before content: a requester may only ask about a grant issued to its own key.
  if (!timingSafeEqualString(String(row.counterparty_key), actor.publicKey)) {
    return errorResponse('not_found', context)
  }

  let stored
  try {
    stored = JSON.parse(String(row.payload_json))
  } catch {
    return errorResponse('store_unavailable', context)
  }

  // Constant-time commitment comparison. The commitment is the value NF-4 keys revocation
  // by, so a comparison that leaked its progress would leak how much of a forged grant
  // matched a real one — and the denormalised column is compared against a digest
  // recomputed from the authoritative payload, never trusted on its own (schema.sql says
  // the same about every denormalised copy).
  let presentedCommitment = null
  let storedCommitment = null
  try {
    presentedCommitment = await deriveGrantCommitment(presented)
    storedCommitment = await deriveGrantCommitment(stored)
  } catch {
    return errorResponse('grant_rejected', context)
  }
  if (
    !timingSafeEqualString(presentedCommitment, storedCommitment) ||
    !timingSafeEqualString(storedCommitment, String(row.commitment))
  ) {
    return errorResponse('not_found', context)
  }

  // The out-of-band verifying key. It is deliberately NOT in the grant: an owner public key
  // inside the object would be a join key two counterparties could correlate on, which
  // would undo the per-audience pseudonym (§12.7). Resolved by (vehicle, audience) — a
  // lookup only a party already entitled to make it can perform.
  const signingKey = await db
    .prepare('SELECT public_key FROM owner_signing_key WHERE vehicle_id = ?1 AND audience = ?2')
    .bind(String(row.vehicle_id), String(row.audience))
    .first()

  // A delegated grant cannot be verified from its leaf alone (SEC-10): the expected signer
  // key lives in the parent, and so do the cascade invariants. verifyGrant fails closed if
  // the parent is missing, so a null here becomes a reason rather than a pass.
  let parentGrant
  if (row.parent_grant_id !== null && row.parent_grant_id !== undefined) {
    const parentRow = await db
      .prepare('SELECT payload_json FROM consent_grant WHERE grant_id = ?1')
      .bind(String(row.parent_grant_id))
      .first()
    if (parentRow) {
      try {
        parentGrant = JSON.parse(String(parentRow.payload_json))
      } catch {
        parentGrant = undefined
      }
    }
  }

  let revocation
  try {
    revocation = await revocationStatus(db, {
      grant_id: String(row.grant_id),
      revocation_key_id: String(row.revocation_key_id),
      issued_at: Number(row.issued_at),
      parent_grant_id: row.parent_grant_id === null || row.parent_grant_id === undefined
        ? null
        : String(row.parent_grant_id),
    })
  } catch {
    // §8.4's posture when the revocation state cannot be read: DENY. The cost of failing
    // closed is an outage; the cost of failing open is serving data the owner has withdrawn
    // consent for, with no bound on how long. Those are not comparable.
    return jsonResponse(
      200,
      {
        v: VERDICT_VERSION,
        grant_id: grantId,
        decision: 'deny',
        valid: false,
        reasons: ['revocation_state_unreachable: fail closed; the revocation table could not be read'],
        revocation: { checked: false, revoked: null, cause: 'revocation_state_unreachable', revoked_at: null },
        projection: null,
        checked_at: nowSeconds(),
      },
      context,
    )
  }

  const now = nowSeconds()
  const verdict = await verifyGrant(stored, {
    ownerPublicKey: signingKey ? String(signingKey.public_key) : undefined,
    parentGrant,
    // Proof of possession from THIS session. Not from the body.
    presenterKey: actor.publicKey,
    // Membership, not the whole inventory: the list of operator-held ids is unbounded and
    // the check only ever asks whether THIS grant's revocation key is one of them. One
    // indexed read, identical semantics.
    forbiddenRevocationKeyIds: (await isOperatorHeldKeyId(db, String(row.revocation_key_id)))
      ? [String(row.revocation_key_id)]
      : [],
    revoked: revocation.revoked,
    now,
  })

  const allowed = verdict.valid && !revocation.revoked
  context.grantId = grantId
  await audit(env, ctx, context, {
    event: AUDIT_EVENTS.GRANT_VERIFIED,
    outcome: allowed ? 'allow' : 'deny',
    vehicleId: String(row.vehicle_id),
    grantId,
    actorId: actor.requesterId,
    reasonCode: allowed ? null : firstReasonCode(verdict.reasons),
    detail: { revoked: revocation.revoked },
  })

  return jsonResponse(
    200,
    {
      v: VERDICT_VERSION,
      grant_id: grantId,
      decision: allowed ? 'allow' : 'deny',
      valid: verdict.valid,
      // EVERY failure, not just the first (NF-1 R-4): NF-5 asserts which rule fired, and a
      // verifier that returns one opaque "invalid" is untestable — and an untestable rule is
      // an unenforced rule.
      reasons: verdict.reasons,
      revocation: {
        checked: true,
        revoked: revocation.revoked,
        cause: revocation.cause,
        revoked_at: revocation.revokedAt,
      },
      // The projection allowlist. This is the third thing that must cross B4 with the
      // verdict, and it is present only on an allow: a denied caller has no projection.
      // `layers_required` states the honest ceiling of §3.3 at authorisation time rather
      // than at delivery time — a `vpic` field set is servable from the M0 cache, anything
      // else needs Layer-2 authenticated access that this broker does not perform.
      projection: allowed
        ? {
            fields: stored.fields,
            purpose: stored.purpose,
            purpose_citation: DPPA_PURPOSES[stored.purpose]?.cite ?? null,
            layers_required: layersRequired(stored.fields),
            expires_at: stored.expires_at,
          }
        : null,
      checked_at: now,
    },
    context,
  )
}

// =================================================================================
// POST /revocations — owner-signed, broker-powerless
// =================================================================================

/** Closed key set for the revocation body. */
const REVOCATION_BODY_KEYS = Object.freeze(['revocation'])

/** Bound on a cascade walk, so a cycle written by a bad migration cannot run forever. */
const MAX_CASCADE_ROWS = 256

/**
 * Record an owner's revocation.
 *
 * NO BROKER AUTHENTICATION, AND THAT IS THE DESIGN (NF-1 L3-6, §8.4). The record is signed
 * by the OWNER-held revocation key and is self-authenticating: it carries the public key, the
 * scope proves itself for the kill switch, and `verifyRevocation` checks it with no policy
 * parameter, no operator allow-list and no approval callback. Requiring a broker session
 * would mean an owner could not revoke while the broker's identity provider was down —
 * revocation must not depend on the cooperation of the party with a commercial interest in
 * continued access, and an availability dependency is cooperation with extra steps.
 *
 * THE BROKER CANNOT ORIGINATE ONE EITHER. It holds no revocation private key and there is no
 * column for one. That symmetry is the point: `applyRevocation` has nothing to configure and
 * no return path for "declined", and the state transition is a pure function of (state,
 * record, population), so a broker that skipped a revocation produces entries anyone else
 * computing the same inputs would notice were missing.
 *
 * RATE LIMITING IS APPLIED TO FAILURES ONLY. A limiter in front of this route would be a
 * broker-held lever for slowing a revocation down, which is the failure mode the whole
 * module is built against. So a record that VERIFIES is never rate-limited, and only the
 * cost of a rejected record — one Ed25519 verification over a body already capped at
 * `MAX_REQUEST_BYTES` — is metered. A replay of a valid record costs one indexed read,
 * because idempotency is checked before anything is written.
 *
 * IDEMPOTENT BY PRIMARY KEY. Re-presenting a valid revocation is a no-op that still reports
 * success: a kill switch that fails when pressed twice is a kill switch that can be lost to
 * a retry.
 */
async function handleRevocation(request, env, ctx, context, url) {
  if ([...url.searchParams.keys()].length > 0) return errorResponse('malformed_request', context)

  const db = d1(env)
  if (db === null) return errorResponse('store_unavailable', context)

  const parsed = await readJsonBody(request, env, context)
  if (parsed.error !== null) return errorResponse(parsed.error, context)
  if (!hasExactlyKeys(parsed.value, REVOCATION_BODY_KEYS, [])) return errorResponse('malformed_request', context)
  const record = parsed.value.revocation

  const now = nowSeconds()
  const check = await verifyRevocation(record, { now })
  if (!check.valid) {
    // Only here — on the failing path — does the limiter apply.
    const limited = await enforceRateLimit(env, ctx, {
      limiter: env?.RATE_LIMITER,
      key: await anonymousRateKey(env, request),
      context,
    })
    if (limited) return limited
    await audit(env, ctx, context, {
      event: AUDIT_EVENTS.REVOCATION_REFUSED,
      outcome: 'deny',
      actorKind: 'anonymous',
      reasonCode: firstReasonCode(check.reasons),
    })
    return errorResponse('revocation_rejected', context)
  }

  try {
    if (record.scope === 'grant') return await applyGrantRevocation(db, env, ctx, context, record, now)
    return await applyVehicleRevocation(db, env, ctx, context, record, now)
  } catch (err) {
    if (err?.nfCode === 'forbidden') return errorResponse('forbidden', context)
    return errorResponse('store_unavailable', context)
  }
}

/**
 * Grant scope: revoke one grant and cascade to every descendant.
 *
 * The authorisation to revoke a grant is a property of the GRANT — its `revocation_key_id` —
 * not of the record, which is why `revokeGrant` refuses without the grant in hand. Skipping
 * that check would let any revocation keypair in the world revoke any grant: free griefing,
 * and a denial of service against a counterparty the owner chose.
 */
async function applyGrantRevocation(db, env, ctx, context, record, now) {
  const target = await db
    .prepare('SELECT grant_id, vehicle_id, payload_json FROM consent_grant WHERE commitment = ?1')
    .bind(record.target)
    .first()

  // Unknown commitment: there is nothing here to revoke. Reported truthfully rather than as
  // a 404, and it is not an oracle — only a holder of the owner's revocation private key can
  // produce a record that gets this far, and such a holder already knows what they signed.
  if (!target) {
    return jsonResponse(
      200,
      { v: BROKER_API_VERSION, recorded: false, scope: 'grant', revoked_grants: 0, recorded_at: now },
      context,
    )
  }

  const grant = JSON.parse(String(target.payload_json))
  const descendants = await loadDescendants(db, String(target.grant_id))

  // nf4-revocation.js is the SINGLE transition point: authorisation, cascade collection,
  // witness construction and leaf-key derivation all happen there, so this handler never
  // invents an entry. What it does is persist what the module produced.
  const state = createRevocationState()
  const result = await revokeGrant(state, record, grant, { population: [grant, ...descendants], now })
  if (!result.applied) {
    await audit(env, ctx, context, {
      event: AUDIT_EVENTS.REVOCATION_REFUSED,
      outcome: 'deny',
      actorKind: 'anonymous',
      vehicleId: String(target.vehicle_id),
      grantId: String(target.grant_id),
      reasonCode: firstReasonCode(result.reasons),
    })
    const err = new Error('revocation not authorised')
    err.nfCode = 'forbidden'
    throw err
  }

  const written = await persistGrantEntries(db, record, result.inserted, now)

  await audit(env, ctx, context, {
    event: AUDIT_EVENTS.REVOCATION_RECORDED,
    outcome: 'allow',
    actorKind: 'owner',
    vehicleId: String(target.vehicle_id),
    grantId: String(target.grant_id),
    detail: { scope: 'grant', reason_code: record.reason, cascaded: Math.max(0, written - 1) },
  })

  return jsonResponse(
    200,
    {
      v: BROKER_API_VERSION,
      recorded: true,
      scope: 'grant',
      grant_id: String(target.grant_id),
      revoked_grants: written,
      // The revocation-state commitments just created. These, and the grant commitments, are
      // the ONLY values in this system that Refusal 2 permits on an immutable ledger.
      commitments: result.inserted.map((e) => e.leaf_key),
      recorded_at: now,
    },
    context,
  )
}

/**
 * Vehicle scope: the kill switch.
 *
 * The target is a KEY THUMBPRINT, never a vehicle identifier, and never a list of
 * counterparties. An owner exercising sovereignty should not have to know or enumerate who
 * holds grants over their car — that asymmetry is the thing the consent layer exists to
 * correct, and a UI that says "select the counterparties to revoke" has reproduced it.
 *
 * MATERIALISED ENTRIES ARE CONVENIENCE, NOT CORRECTNESS. `revocationStatus` consults the
 * kill-switch floor directly, so a broker that under-enumerates the affected grants cannot
 * thereby keep one alive. What the per-grant rows buy is a counterparty being able to check
 * its own grant without being handed the kill-switch record, and without anyone disclosing a
 * different counterparty's grant.
 */
async function applyVehicleRevocation(db, env, ctx, context, record, now) {
  // The broker acts only on keys an owner registered here. A record for an unknown key is
  // valid and simply has nothing to act on: issuance already refuses a grant whose
  // revocation key is unregistered, and NF-4 forbids a future-dated `effective_from`, so
  // there is no grant such a record could ever reach.
  const owner = await db
    .prepare('SELECT vehicle_id FROM owner_revocation_key WHERE revocation_key_id = ?1')
    .bind(record.target)
    .first()
  if (!owner) {
    return jsonResponse(
      200,
      { v: BROKER_API_VERSION, recorded: false, scope: 'vehicle', revoked_grants: 0, recorded_at: now },
      context,
    )
  }
  const vehicleId = String(owner.vehicle_id)

  const rows = await db
    .prepare(
      'SELECT payload_json FROM consent_grant WHERE revocation_key_id = ?1 AND issued_at <= ?2 LIMIT ?3',
    )
    .bind(record.target, record.effective_from, MAX_CASCADE_ROWS)
    .all()
  const population = parsePayloads(rows)

  const state = createRevocationState()
  const result = await revokeVehicle(state, record, { population, now })
  if (!result.applied) {
    const err = new Error('kill switch not authorised')
    err.nfCode = 'forbidden'
    throw err
  }

  const killSwitch = result.inserted.find((e) => e.kind === 'vehicle')
  const grantEntries = result.inserted.filter((e) => e.kind === 'grant')

  if (killSwitch) {
    await db
      .prepare(
        'INSERT INTO revocation_kill_switch (revocation_key_id, effective_from, vehicle_id, commitment, ' +
          'revocation_key, revocation_signature, issued_at, recorded_at, reason_code) ' +
          'VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT DO NOTHING',
      )
      .bind(
        record.target,
        record.effective_from,
        vehicleId,
        killSwitch.leaf_key,
        record.revocation_key,
        record.signature,
        record.issued_at,
        now,
        record.reason,
      )
      .run()
  }

  const written = await persistGrantEntries(db, record, grantEntries, now)

  await audit(env, ctx, context, {
    event: AUDIT_EVENTS.REVOCATION_RECORDED,
    outcome: 'allow',
    actorKind: 'owner',
    vehicleId,
    detail: { scope: 'vehicle', reason_code: record.reason, cascaded: written },
  })

  return jsonResponse(
    200,
    {
      v: BROKER_API_VERSION,
      recorded: true,
      scope: 'vehicle',
      revoked_grants: written,
      commitments: result.inserted.map((e) => e.leaf_key),
      recorded_at: now,
    },
    context,
  )
}

/**
 * Persist the per-grant entries nf4-revocation.js produced.
 *
 * Written as ONE D1 batch, which D1 executes as a single transaction: a cascade that
 * recorded the parent and died before the children would leave live descendants of a dead
 * grant, which is the exact failure revocation exists to prevent. `ON CONFLICT DO NOTHING`
 * makes a replay a no-op rather than an error.
 *
 * `commitment` here is the NF-4 LEAF KEY, not the grant commitment: it is the
 * revocation-state commitment, the second of the only two digest classes Refusal 2 admits
 * on a ledger.
 */
async function persistGrantEntries(db, record, entries, now) {
  const statements = []
  for (const entry of entries) {
    if (entry.kind !== 'grant') continue
    statements.push(
      db
        .prepare(
          'INSERT INTO revocation (grant_id, revoked_at, recorded_at, reason_code, revocation_signature, ' +
            'revocation_key_id, commitment, cascaded_from) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ' +
            'ON CONFLICT DO NOTHING',
        )
        .bind(
          entry.grant_id,
          entry.witness.revoked_at,
          now,
          record.reason,
          record.signature,
          // Grant scope names the owner key by thumbprint; vehicle scope's target already IS
          // that thumbprint. Both forms therefore record which owner key authorised the row.
          record.scope === 'vehicle' ? record.target : await thumbprintOf(record.revocation_key),
          entry.leaf_key,
          entry.witness.cascaded_from,
        ),
    )
  }
  if (statements.length === 0) return 0
  if (typeof db.batch === 'function') {
    await db.batch(statements)
  } else {
    // A binding without `batch` is not a D1 binding; refuse rather than write partially.
    const err = new Error('d1 binding does not support batch')
    err.nfCode = 'store_unavailable'
    throw err
  }
  return statements.length
}

/**
 * The check-time revocation predicate, as SQL.
 *
 * THIS IS THE D1 PROJECTION OF `isRevoked` IN nf4-revocation.js, and the three grounds are
 * the same three, in the same order of cost, each decisive on its own:
 *
 *   1. a grant-scope entry for this grant;
 *   2. a kill switch under this grant's `revocation_key_id` with
 *      `effective_from >= grant.issued_at`, read from the floor rather than from
 *      materialised rows — so a broker that failed to enumerate cannot keep a grant alive;
 *   3. any ancestor revoked, walked with a bound and a cycle guard.
 *
 * It is SQL rather than a call into the module because the module's state is an in-memory
 * sparse Merkle accumulator whose root and proofs belong to the anchoring path; nf4 says so
 * itself, and says the authorisation path is two indexed reads. The cost of the projection
 * is that the two must stay in step: a change to `isRevoked`'s grounds is a change here.
 *
 * A CYCLE IS TREATED AS REVOKED. An unprovable chain must not be served — the same
 * fail-closed direction `isRevoked` takes on `ancestry_cyclic`.
 */
async function revocationStatus(db, grant) {
  const direct = await db
    .prepare('SELECT revoked_at, cascaded_from FROM revocation WHERE grant_id = ?1')
    .bind(grant.grant_id)
    .first()
  if (direct) {
    return {
      revoked: true,
      cause: direct.cascaded_from === null || direct.cascaded_from === undefined ? 'revoked' : 'cascaded',
      revokedAt: Number(direct.revoked_at),
    }
  }

  const floor = await killSwitchFloor(db, grant.revocation_key_id)
  if (floor !== null && Number.isSafeInteger(grant.issued_at) && floor >= grant.issued_at) {
    return { revoked: true, cause: 'vehicle_kill_switch', revokedAt: floor }
  }

  const seen = new Set([grant.grant_id])
  let parentId = grant.parent_grant_id ?? null
  for (let hop = 0; parentId !== null && hop < MAX_ANCESTOR_HOPS; hop += 1) {
    if (seen.has(parentId)) {
      return { revoked: true, cause: 'ancestry_cyclic', revokedAt: null }
    }
    seen.add(parentId)
    const row = await db
      .prepare(
        'SELECT g.revocation_key_id AS revocation_key_id, g.issued_at AS issued_at, ' +
          'g.parent_grant_id AS parent_grant_id, r.revoked_at AS revoked_at ' +
          'FROM consent_grant g LEFT JOIN revocation r ON r.grant_id = g.grant_id WHERE g.grant_id = ?1',
      )
      .bind(parentId)
      .first()
    if (!row) break
    if (row.revoked_at !== null && row.revoked_at !== undefined) {
      return { revoked: true, cause: 'ancestor_revoked', revokedAt: Number(row.revoked_at) }
    }
    const ancestorFloor = await killSwitchFloor(db, String(row.revocation_key_id))
    if (ancestorFloor !== null && ancestorFloor >= Number(row.issued_at)) {
      return { revoked: true, cause: 'ancestor_revoked', revokedAt: ancestorFloor }
    }
    parentId = row.parent_grant_id === null || row.parent_grant_id === undefined
      ? null
      : String(row.parent_grant_id)
  }

  return { revoked: false, cause: null, revokedAt: null }
}

async function killSwitchFloor(db, revocationKeyId) {
  const row = await db
    .prepare('SELECT MAX(effective_from) AS floor FROM revocation_kill_switch WHERE revocation_key_id = ?1')
    .bind(revocationKeyId)
    .first()
  const floor = row?.floor
  return Number.isSafeInteger(floor) ? floor : null
}

/** Every descendant of a grant, bounded. Payload is authoritative, so payloads are what load. */
async function loadDescendants(db, grantId) {
  const rows = await db
    .prepare(
      'WITH RECURSIVE sub(grant_id) AS (' +
        '  SELECT grant_id FROM consent_grant WHERE parent_grant_id = ?1' +
        '  UNION' +
        '  SELECT c.grant_id FROM consent_grant c JOIN sub s ON c.parent_grant_id = s.grant_id' +
        ') SELECT g.payload_json AS payload_json FROM consent_grant g JOIN sub ON sub.grant_id = g.grant_id LIMIT ?2',
    )
    .bind(grantId, MAX_CASCADE_ROWS)
    .all()
  return parsePayloads(rows)
}

function parsePayloads(rows) {
  const out = []
  for (const row of rows?.results ?? []) {
    try {
      const parsed = JSON.parse(String(row.payload_json))
      if (isPlainObject(parsed)) out.push(parsed)
    } catch {
      // A row that does not round-trip cannot be verified and can never be served. It is
      // skipped here rather than aborting the cascade, because refusing to revoke the rest
      // because one row is corrupt is the wrong direction to fail in.
    }
  }
  return out
}

// =================================================================================
// Authentication
// =================================================================================
/**
 * TWO ACTOR KINDS, TWO MECHANISMS, AND NEITHER IS A SHARED SECRET.
 *
 *  - The OWNER presents an identity-provider session (Clerk), verified against the
 *    provider's PUBLIC JWKS with WebCrypto. This Worker holds no provider API key: it only
 *    needs to check a signature, so it only gets what checking a signature requires.
 *  - A COUNTERPARTY SIGNS ITS REQUEST with the Ed25519 key the grant is bound to. There is
 *    no api key, no bearer token and no shared secret anywhere in this file or in
 *    schema.sql, so a stolen database yields no ability to impersonate anyone — the same
 *    reasoning that makes a Consent Grant bound to a key rather than to a name (§1.4).
 *
 * The request signature is also what makes `presenterKey` mean something at verification
 * time: it is proof of possession in THIS session, which is the challenge SEC-2 requires
 * and the reason a stolen grant is worth nothing.
 */

/** Headers carrying the counterparty request signature. Lowercase; Headers is case-insensitive. */
const SIG_HEADER_KEY_ID = 'nf-key-id'
const SIG_HEADER_TIMESTAMP = 'nf-timestamp'
const SIG_HEADER_NONCE = 'nf-nonce'
const SIG_HEADER_SIGNATURE = 'nf-signature'

/**
 * Verify an owner session.
 *
 * ALGORITHM IS PINNED, NOT NEGOTIATED (SEC-7, NF-1 R-1). `alg` is read from the token only
 * to REFUSE anything that is not RS256 — never to select a verification routine. A verifier
 * that reads the algorithm out of the object it is verifying is the JWT `alg` bug class, and
 * `"alg": "none"` is the canonical instance of it.
 *
 * The subject is returned and is used for exactly two things: an equality check against
 * `vehicle_enrolment.owner_account_id`, and a keyed digest for the rate limiter. It is never
 * logged, never written to `audit_log` (there is no column an owner belongs in — a subject
 * id in an audit row is a person in an audit row), and never echoed.
 */
async function authenticateOwner(request, env, context) {
  const fail = (code) => ({ error: code, subject: null })

  const issuer = typeof env?.CLERK_ISSUER === 'string' ? env.CLERK_ISSUER : ''
  const jwksUrl = typeof env?.CLERK_JWKS_URL === 'string' ? env.CLERK_JWKS_URL : ''
  if (issuer.length === 0 || jwksUrl.length === 0) return fail('configuration_incomplete')

  const header = request.headers.get('authorization') ?? ''
  if (!/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(header)) return fail('unauthenticated')
  const token = header.slice(7)
  const parts = token.split('.')

  let head
  let claims
  try {
    head = JSON.parse(new TextDecoder().decode(base64urlToBytes(parts[0])))
    claims = JSON.parse(new TextDecoder().decode(base64urlToBytes(parts[1])))
  } catch {
    return fail('unauthenticated')
  }
  if (!isPlainObject(head) || !isPlainObject(claims)) return fail('unauthenticated')
  if (head.alg !== 'RS256') return fail('unauthenticated')
  if (typeof head.kid !== 'string' || head.kid.length === 0) return fail('unauthenticated')

  const jwks = await loadJwks(env, jwksUrl)
  if (jwks === null) return fail('store_unavailable')
  const jwk = jwks.find((k) => k?.kid === head.kid && k?.kty === 'RSA')
  if (!jwk) return fail('unauthenticated')

  let key
  try {
    key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    )
  } catch {
    return fail('unauthenticated')
  }

  let ok = false
  try {
    ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      base64urlToBytes(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    )
  } catch {
    return fail('unauthenticated')
  }
  if (!ok) return fail('unauthenticated')

  // Claims are checked AFTER the signature, never before: a claim read from an unverified
  // token is attacker-controlled input dressed as configuration.
  const skew = intVar(env, 'AUTH_MAX_SKEW_S', DEFAULT_AUTH_MAX_SKEW_S)
  const now = nowSeconds()
  if (claims.iss !== issuer) return fail('unauthenticated')
  if (!Number.isFinite(claims.exp) || now >= claims.exp + skew) return fail('unauthenticated')
  if (Number.isFinite(claims.nbf) && now + skew < claims.nbf) return fail('unauthenticated')
  if (Number.isFinite(claims.iat) && claims.iat > now + skew) return fail('unauthenticated')
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) return fail('unauthenticated')

  // The authorised-party allowlist. Empty disables the check, which is acceptable only in
  // development — an unconstrained `azp` means any application on the same identity provider
  // can mint sessions this broker will honour.
  const parties = String(env?.CLERK_AUTHORIZED_PARTIES ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
  if (parties.length > 0 && !parties.includes(String(claims.azp ?? ''))) return fail('unauthenticated')

  return { error: null, subject: claims.sub }
}

/**
 * Fetch and cache the identity provider's JWKS.
 *
 * KV IS THE RIGHT STORE FOR EXACTLY THIS AND FOR ALMOST NOTHING ELSE HERE. A JWKS is public,
 * identical for every request, and tolerant of a stale read: KV's read-after-write window of
 * up to a minute is harmless when the worst case is briefly missing a freshly rotated key,
 * and the fallback is a live fetch. The same window makes KV unusable for nonces (a replay
 * inside it simply succeeds) and for revocation state (a revoked grant verifies for a
 * minute), which is why both of those live in D1 — see wrangler.toml.
 */
async function loadJwks(env, jwksUrl) {
  const cache = kv(env)
  const cacheKey = `jwks:${jwksUrl}`
  if (cache) {
    try {
      const cached = await cache.get(cacheKey, { type: 'json' })
      if (Array.isArray(cached?.keys)) return cached.keys
    } catch {
      // A cache miss is a fetch, never a failure.
    }
  }

  let body
  try {
    const response = await fetch(jwksUrl, {
      // No redirects: a redirect on a key-set fetch lets whoever controls the response aim
      // this Worker at an arbitrary URL, and the key set is the root of owner authentication.
      redirect: 'error',
      headers: { accept: 'application/json' },
      signal: typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS) : undefined,
    })
    if (!response.ok) return null
    const text = await readTextCapped(response, MAX_JWKS_BYTES)
    if (text === null) return null
    body = JSON.parse(text)
  } catch {
    return null
  }
  if (!isPlainObject(body) || !Array.isArray(body.keys)) return null

  if (cache) {
    try {
      await cache.put(cacheKey, JSON.stringify({ keys: body.keys }), { expirationTtl: JWKS_CACHE_TTL_S })
    } catch {
      // Best effort. A broker that cannot cache is slow, not wrong.
    }
  }
  return body.keys
}

/**
 * Verify a counterparty's request signature.
 *
 * THE SIGNED STRING, and why each line is in it:
 *
 *   nf-request-signature:v1   domain separation — these bytes cannot be replayed as any
 *                             other signature in the system, including a grant's.
 *   <operator id>             audience binding. Without it, a signature captured against
 *                             staging replays against production, since the two deployments
 *                             share a requester's key but not a nonce table.
 *   <METHOD>                  a signature for a GET must not authorise a POST.
 *   <pathname>                binds the operation and, on /grants/:id, the object.
 *   <timestamp>               bounds the replay window to the skew tolerance.
 *   <nonce>                   makes replay inside that window a single-use failure.
 *   <SHA-256(body)>           binds the body; an empty body hashes to a fixed value, so a
 *                             body cannot be added or removed after signing.
 *
 * The HOST IS DELIBERATELY ABSENT: a Worker behind a proxy may see a rewritten Host, and a
 * signature that depends on a header the operator rewrites is a signature that fails for
 * operational reasons. The operator id does the audience job instead, explicitly.
 *
 * REPLAY PROTECTION IS D1, NOT KV. `INSERT ... ON CONFLICT DO NOTHING` against D1's
 * authoritative primary, with a changed-row count, is real mutual exclusion. KV's
 * eventually-consistent read would let a replay inside its propagation window simply
 * succeed, and that window is longer than the skew tolerance it is meant to enforce.
 */
async function authenticateRequester(request, env, context, db, bodyBytes) {
  const fail = (code) => ({ error: code, publicKey: null, requesterId: null, keyId: null, rateSubject: null })

  const keyId = request.headers.get(SIG_HEADER_KEY_ID)
  const timestamp = request.headers.get(SIG_HEADER_TIMESTAMP)
  const nonce = request.headers.get(SIG_HEADER_NONCE)
  const signature = request.headers.get(SIG_HEADER_SIGNATURE)
  if (!keyId || !timestamp || !nonce || !signature) return fail('unauthenticated')
  if (keyId.length > 128 || nonce.length > 64) return fail('unauthenticated')
  if (!/^[A-Za-z0-9_-]+$/.test(nonce) || !/^[A-Za-z0-9_.:-]+$/.test(keyId)) return fail('unauthenticated')
  if (!isBase64urlBytes(signature, 64)) return fail('unauthenticated')

  const ts = Number(timestamp)
  if (!Number.isSafeInteger(ts)) return fail('unauthenticated')
  const skew = intVar(env, 'AUTH_MAX_SKEW_S', DEFAULT_AUTH_MAX_SKEW_S)
  const now = nowSeconds()
  if (Math.abs(now - ts) > skew) return fail('unauthenticated')

  const row = await db
    .prepare(
      'SELECT k.public_key AS public_key, k.status AS key_status, r.requester_id AS requester_id, ' +
        'r.status AS requester_status FROM requester_key k JOIN requester r ON r.requester_id = k.requester_id ' +
        'WHERE k.key_id = ?1',
    )
    .bind(keyId)
    .first()
  if (!row || row.key_status !== 'active' || row.requester_status !== 'active') return fail('unauthenticated')

  const publicKey = String(row.public_key)
  const url = new URL(request.url)
  const bodyDigest = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', bodyBytes ?? new Uint8Array(0))))
  const signingInput = new TextEncoder().encode(
    [
      REQUEST_SIG_DOMAIN,
      String(env?.OPERATOR_ID ?? ''),
      request.method.toUpperCase(),
      url.pathname,
      String(ts),
      nonce,
      bodyDigest,
    ].join('\n'),
  )

  let ok = false
  try {
    const alg = await ed25519Algorithm()
    const key = await crypto.subtle.importKey('raw', base64urlToBytes(publicKey), alg, true, ['verify'])
    ok = await crypto.subtle.verify(alg, key, base64urlToBytes(signature), signingInput)
  } catch {
    return fail('unauthenticated')
  }
  if (!ok) return fail('unauthenticated')

  // Nonce AFTER signature. Recording a nonce for an unverified request would let anyone burn
  // a requester's nonce space, which is a denial of service with no signature required.
  let inserted
  try {
    inserted = await db
      .prepare('INSERT INTO request_nonce (key_id, nonce, seen_at) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING')
      .bind(keyId, nonce, now)
      .run()
  } catch {
    return fail('store_unavailable')
  }
  if ((inserted?.meta?.changes ?? 0) !== 1) return fail('replayed_request')

  return {
    error: null,
    publicKey,
    requesterId: String(row.requester_id),
    keyId,
    // The rate-limit subject is the key id, which is a business party's opaque label rather
    // than anything about a person.
    rateSubject: keyId,
  }
}

/**
 * Accept either actor on a route both may legitimately use.
 *
 * The signature headers select the mechanism, so there is no negotiation and no fallback: a
 * request carrying `nf-key-id` is judged as a counterparty and never silently retried as an
 * owner. A fallback chain is how an authentication bypass gets built one reasonable step at
 * a time.
 */
async function authenticateEither(request, env, context, db) {
  if (request.headers.get(SIG_HEADER_KEY_ID) !== null) {
    const requester = await authenticateRequester(request, env, context, db, new Uint8Array(0))
    if (requester.error !== null) return { error: requester.error, kind: 'requester' }
    return { error: null, kind: 'requester', ...requester }
  }
  const owner = await authenticateOwner(request, env, context)
  if (owner.error !== null) return { error: owner.error, kind: 'owner' }
  return { error: null, kind: 'owner', subject: owner.subject, rateSubject: owner.subject, requesterId: null }
}

/**
 * May this actor ask about this grant?
 *
 * A counterparty may ask about a grant issued to its own key; an owner may ask about a grant
 * over a vehicle enrolled to them. Nothing else, and a negative answer is reported by the
 * caller as 404 rather than 403 so the route is not an enumeration oracle.
 */
async function isEntitledToGrant(db, actor, row) {
  if (actor.kind === 'requester') {
    return timingSafeEqualString(String(row.counterparty_key), actor.publicKey)
  }
  const enrolment = await db
    .prepare('SELECT owner_account_id FROM vehicle_enrolment WHERE vehicle_id = ?1')
    .bind(String(row.vehicle_id))
    .first()
  return Boolean(enrolment) && timingSafeEqualString(String(enrolment.owner_account_id), actor.subject)
}

// =================================================================================
// Rate limiting
// =================================================================================
/**
 * WHY THIS SHAPE, GIVEN THE WORKERS EXECUTION MODEL.
 *
 * A Worker isolate is ephemeral, unshared and per-colo. There is no process-wide memory to
 * count in, so the three honest options are: the platform rate-limit binding, a Durable
 * Object, or a storage round trip per request.
 *
 *  - `env.RATE_LIMITER.limit({ key })` is the platform binding and is what this file uses.
 *    Its cost is one local call and no storage write. ITS HONEST LIMITATION, repeated here
 *    at the call site because wrangler.toml states it too: the counter is per LOCATION, not
 *    global, so the effective ceiling is roughly (limit x colos). It shapes traffic and
 *    stops one client hammering one endpoint; it is not a quota, and nothing in this system
 *    is priced by it — there is no metering, no billing and no Layer-5 accounting anywhere.
 *  - A Durable Object would give an exact global counter at the cost of a network hop per
 *    request and a new single-point dependency in front of revocation. Deliberately not
 *    added; revisit when an exact quota is actually required.
 *  - KV is NOT used: its read-after-write window is longer than any window worth enforcing,
 *    so a burst inside the window simply succeeds.
 *
 * When the binding is absent (a `wrangler dev` without the unsafe binding), the fallback is
 * an IN-ISOLATE fixed window. It is advisory by construction — a fresh isolate starts at
 * zero — and it is stated as advisory rather than presented as protection, because a limiter
 * that is quietly useless is worse than none.
 *
 * KEYS ARE KEYED DIGESTS, NEVER RAW IDENTIFIERS. An IP address is personal information and
 * an owner subject identifies a person; neither is handed to a limiter, logged, or stored.
 */
const fallbackWindows = new Map()

async function enforceRateLimit(env, ctx, { limiter, key, context }) {
  if (key === null) return null

  if (limiter && typeof limiter.limit === 'function') {
    try {
      const outcome = await limiter.limit({ key })
      if (outcome?.success === false) return errorResponse('rate_limited', context)
      return null
    } catch {
      // A limiter failure must not fail the request open OR closed silently; treat it as
      // unlimited and fall through to the in-isolate backstop, which is at least bounded.
    }
  }

  const perMinute = intVar(env, 'FALLBACK_RATE_LIMIT_PER_MIN', DEFAULT_FALLBACK_RATE_LIMIT_PER_MIN)
  const window = Math.floor(Date.now() / 60000)
  const slot = `${window}:${key}`
  const count = (fallbackWindows.get(slot) ?? 0) + 1
  fallbackWindows.set(slot, count)
  // Bound the map so a key-space flood cannot turn the limiter into the memory leak.
  if (fallbackWindows.size > 4096) {
    for (const existing of fallbackWindows.keys()) {
      if (!existing.startsWith(`${window}:`)) fallbackWindows.delete(existing)
    }
    if (fallbackWindows.size > 4096) fallbackWindows.clear()
  }
  if (count > perMinute) return errorResponse('rate_limited', context)
  return null
}

/**
 * The rate-limit key for an unauthenticated caller.
 *
 * `CF-Connecting-IP` is personal information (§9.5), so it is never used directly, never
 * logged and never stored. What the limiter sees is a keyed digest under a domain separator
 * of its own — domain-separated from the VIN blind index so neither can be replayed as the
 * other, even though both derive from the same deployment secret.
 */
async function anonymousRateKey(env, request) {
  const ip = request.headers.get('cf-connecting-ip') ?? request.headers.get('x-forwarded-for') ?? 'unknown'
  return keyedDigest(env, RATE_KEY_DOMAIN, `ip:${ip}`)
}

/**
 * HMAC under `VIN_INDEX_KEY` where one is configured, plain SHA-256 otherwise.
 *
 * The degradation is acceptable HERE AND ONLY HERE, because a rate-limit key is not a
 * security boundary: it never leaves the limiter and predicting it buys an attacker the
 * ability to be rate-limited. `vinIndex` does NOT degrade — it throws — because a blind
 * index computed without a key is a plain digest of an enumerable value, which is not blind.
 */
async function keyedDigest(env, domain, value) {
  const secret = typeof env?.VIN_INDEX_KEY === 'string' ? env.VIN_INDEX_KEY : null
  const message = new TextEncoder().encode(domain + value)
  if (secret === null) {
    return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', message)))
  }
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return base64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, message)))
}

// =================================================================================
// Bindings, secrets, and the blind index
// =================================================================================

function d1(env) {
  const db = env?.DB ?? null
  return db && typeof db.prepare === 'function' ? db : null
}

function kv(env) {
  const store = env?.CACHE ?? null
  return store && typeof store.get === 'function' ? store : null
}

function intVar(env, name, fallback) {
  const raw = env?.[name]
  const value = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number(raw) : NaN
  return Number.isSafeInteger(value) && value > 0 ? value : fallback
}

/**
 * The blind index over a VIN: HMAC-SHA-256 under `VIN_INDEX_KEY`, domain-separated.
 *
 * WHY THE BROKER STORES NO PLAINTEXT VIN. A VIN at rest is squarely inside the Delete Act's
 * enumerated categories of collected personal information (§9.5), so a table of VINs is a
 * regulated dataset. The blind index lets an owner presenting a VIN be matched to their
 * enrolment and yields nothing in the other direction. It is HMAC and not a bare hash for
 * the reason vin.js gives about pseudonyms: a VIN has perhaps 10^8 of realistic entropy once
 * make, model and year are known, so an unsalted digest is a rainbow-table lookup and anyone
 * holding a VIN could confirm enrolment.
 *
 * THIS THROWS WHEN THE KEY IS ABSENT. There is no unkeyed fallback: a fallback would silently
 * convert the blind index into an enumerable digest, and the failure would be invisible.
 * Rotating the key orphans every enrolment, which is a deliberate second erasure lever
 * (wrangler.toml says so) rather than a hazard.
 */
async function vinIndex(env, normalizedVin) {
  const secret = env?.VIN_INDEX_KEY
  if (typeof secret !== 'string' || secret.length === 0) {
    const err = new Error('VIN_INDEX_KEY is not configured')
    err.nfCode = 'configuration_incomplete'
    throw err
  }
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(VIN_INDEX_DOMAIN + normalizedVin))
  return base64url(new Uint8Array(mac))
}

/** Is this key id one the operator holds? One indexed read; see the note at the call sites. */
async function isOperatorHeldKeyId(db, keyId) {
  const row = await db.prepare('SELECT 1 AS held FROM operator_held_key_id WHERE key_id = ?1').bind(keyId).first()
  return Boolean(row)
}

/** Domain-separated thumbprint of a base64url raw Ed25519 public key. */
async function thumbprintOf(publicKeyBase64url) {
  return revocationKeyIdFromPublicKey(base64urlToBytes(publicKeyBase64url))
}

/**
 * Load the pseudonym salt for (vehicle, epoch), creating it on first use.
 *
 * THIS IS THE ERASURE LEVER. The salt is the HMAC key behind every pseudonym the broker has
 * ever emitted for this vehicle; it exists nowhere else — not on a ledger, not in KV, not in
 * a log, not derivable from anything committed. Deleting it destroys, irreversibly, the
 * ability of anyone (including this broker, including a party holding an anchored commitment
 * and a candidate VIN) to link a pseudonym back to a vehicle or two pseudonyms to each
 * other. That single DELETE is what makes §9.5 erasure real rather than nominal.
 */
async function loadOrCreateSalt(db, vehicleId, epoch, now) {
  const existing = await db
    .prepare('SELECT salt FROM pseudonym_salt WHERE vehicle_id = ?1 AND epoch = ?2')
    .bind(vehicleId, epoch)
    .first()
  if (existing) return String(existing.salt)

  const salt = generatePseudonymSalt()
  await db
    .prepare(
      'INSERT INTO pseudonym_salt (vehicle_id, epoch, salt, created_at) VALUES (?1, ?2, ?3, ?4) ' +
        'ON CONFLICT DO NOTHING',
    )
    .bind(vehicleId, epoch, salt, now)
    .run()

  // Re-read rather than trusting the insert. Two concurrent issuances would otherwise mint
  // two salts for one (vehicle, epoch) — two linkability domains for one vehicle, invisible
  // to the owner — and the loser of that race must adopt the winner's salt, not its own.
  const row = await db
    .prepare('SELECT salt FROM pseudonym_salt WHERE vehicle_id = ?1 AND epoch = ?2')
    .bind(vehicleId, epoch)
    .first()
  if (!row) {
    const err = new Error('salt could not be established')
    err.nfCode = 'store_unavailable'
    throw err
  }
  return String(row.salt)
}

// =================================================================================
// Custodial owner signing keys
// =================================================================================
/**
 * WHY THE BROKER HOLDS A SIGNING KEY AT ALL — stated plainly, because it is the weakest
 * point in the design and hiding it would be dishonest.
 *
 * A root grant must be signed by the owner, and a Workers isolate cannot keep a
 * non-extractable CryptoKey between requests. Custodial issuance therefore requires wrapped
 * key material at rest. The private key is generated extractable ONLY so it can be handed to
 * `wrapKey`, is never exported by any other path, and comes back from `unwrapKey`
 * NON-EXTRACTABLE — so the in-memory object on the verification path cannot be exported at
 * all.
 *
 * WHY THIS IS NOT A REFUSAL-3 VIOLATION: the key that matters for the owner's control is the
 * REVOCATION key, and the broker never has it — there is no column, and every custodial key
 * id is registered in `operator_held_key_id`, which `verifyGrant` consults as
 * `forbiddenRevocationKeyIds`. So a grant that named a broker-held key as its revocation
 * authority fails verification rather than being policed by convention.
 *
 * ONE KEY PER (vehicle, audience), NOT PER VEHICLE. A single per-vehicle signing key would be
 * a join key across counterparty classes: two counterparties get deliberately different
 * pseudonyms, and a shared signer would let them correlate anyway by comparing the key that
 * signed their grants (§12.7). Per-audience separation also bounds one key compromise to one
 * linkability domain.
 *
 * Compensating controls, all structural rather than procedural: the owner-held revocation
 * key, the 45-day cap, per-(vehicle, audience) separation, and the audit log.
 */
async function loadOrCreateSigningKey(db, env, vehicleId, audience, now) {
  const existing = await db
    .prepare('SELECT public_key, wrapped_private_key FROM owner_signing_key WHERE vehicle_id = ?1 AND audience = ?2')
    .bind(vehicleId, audience)
    .first()
  if (existing) {
    return {
      publicKey: String(existing.public_key),
      privateKey: await unwrapOwnerKey(env, vehicleId, audience, String(existing.wrapped_private_key)),
    }
  }

  const alg = await ed25519Algorithm()
  const pair = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
  const publicKey = await exportPublicKeyBase64url(pair.publicKey)
  const wrapped = await wrapOwnerKey(env, vehicleId, audience, pair.privateKey)
  const keyId = await thumbprintOf(publicKey)

  // The insert and the operator-held registration go together as one batch: a custodial key
  // that exists without its id in `operator_held_key_id` is a key the Refusal-3 check cannot
  // see, and that gap must not be reachable by a half-completed write.
  const statements = [
    db
      .prepare(
        'INSERT INTO owner_signing_key (vehicle_id, audience, public_key, wrapped_private_key, key_id, created_at) ' +
          'VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING',
      )
      .bind(vehicleId, audience, publicKey, wrapped, keyId, now),
    db
      .prepare(
        'INSERT INTO operator_held_key_id (key_id, purpose, vehicle_id, created_at) VALUES (?1, ?2, ?3, ?4) ' +
          'ON CONFLICT DO NOTHING',
      )
      .bind(keyId, 'owner-signing-custodial', vehicleId, now),
  ]
  if (typeof db.batch === 'function') {
    await db.batch(statements)
  } else {
    const err = new Error('d1 binding does not support batch')
    err.nfCode = 'store_unavailable'
    throw err
  }

  // Re-read for the same reason the salt is re-read: the loser of a concurrent first
  // issuance must adopt the winner's key, not sign with one nobody stored.
  const row = await db
    .prepare('SELECT public_key, wrapped_private_key FROM owner_signing_key WHERE vehicle_id = ?1 AND audience = ?2')
    .bind(vehicleId, audience)
    .first()
  if (!row) {
    const err = new Error('signing key could not be established')
    err.nfCode = 'store_unavailable'
    throw err
  }
  return {
    publicKey: String(row.public_key),
    privateKey: await unwrapOwnerKey(env, vehicleId, audience, String(row.wrapped_private_key)),
  }
}

/**
 * Wrap: HKDF-SHA-256 from `OWNER_KEY_WRAP_KEY` with a per-row random salt into an AES-GCM
 * key, then `wrapKey('pkcs8', ...)`. Stored as base64url(salt(32) || iv(12) || ciphertext).
 *
 * The (vehicle, audience) pair is bound in twice — as HKDF `info` and as AES-GCM additional
 * authenticated data — so a wrapped blob lifted from one row and pasted into another fails
 * to unwrap instead of yielding a working key for the wrong vehicle.
 */
async function wrapOwnerKey(env, vehicleId, audience, privateKey) {
  const { aesKey, salt, info } = await deriveWrapKey(env, vehicleId, audience, null)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const wrapped = new Uint8Array(
    await crypto.subtle.wrapKey('pkcs8', privateKey, aesKey, { name: 'AES-GCM', iv, additionalData: info }),
  )
  const out = new Uint8Array(salt.length + iv.length + wrapped.length)
  out.set(salt, 0)
  out.set(iv, salt.length)
  out.set(wrapped, salt.length + iv.length)
  return base64url(out)
}

/** Unwrap. The recovered key is NON-EXTRACTABLE and usable only for `sign`. */
async function unwrapOwnerKey(env, vehicleId, audience, wrappedBase64url) {
  const bytes = base64urlToBytes(wrappedBase64url)
  if (bytes.length <= 44) {
    const err = new Error('wrapped key is malformed')
    err.nfCode = 'store_unavailable'
    throw err
  }
  const salt = bytes.slice(0, 32)
  const iv = bytes.slice(32, 44)
  const ciphertext = bytes.slice(44)
  const { aesKey, info } = await deriveWrapKey(env, vehicleId, audience, salt)
  const alg = await ed25519Algorithm()
  return crypto.subtle.unwrapKey(
    'pkcs8',
    ciphertext,
    aesKey,
    { name: 'AES-GCM', iv, additionalData: info },
    alg,
    false,
    ['sign'],
  )
}

async function deriveWrapKey(env, vehicleId, audience, existingSalt) {
  const secret = env?.OWNER_KEY_WRAP_KEY
  if (typeof secret !== 'string' || secret.length === 0) {
    const err = new Error('OWNER_KEY_WRAP_KEY is not configured')
    err.nfCode = 'configuration_incomplete'
    throw err
  }
  const salt = existingSalt ?? crypto.getRandomValues(new Uint8Array(32))
  const info = new TextEncoder().encode(`${OWNER_KEY_WRAP_DOMAIN}${vehicleId}:${audience}`)
  const ikm = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'HKDF', false, ['deriveKey'])
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  )
  return { aesKey, salt, info }
}

/**
 * Ed25519 algorithm-name resolution.
 *
 * Cloudflare Workers shipped Ed25519 under the non-standard `NODE-ED25519` before the
 * WebCrypto Secure Curves draft settled on plain `Ed25519`; newer builds expose the standard
 * name and older ones do not. Probed once and cached.
 *
 * DUPLICATED FROM nf2-grant.js, WHICH DOES NOT EXPORT ITS RESOLVER. That is a defect in the
 * module rather than a choice here — nf4-revocation.js hit the same wall and worked around
 * it by reading the name off a supplied CryptoKey, which is not available on the paths that
 * GENERATE or IMPORT a key. Two copies of one security constant is exactly the drift nf2's
 * own comment about `PSEUDONYM_DERIVATION` warns against; the fix is a one-line export in
 * nf2-grant.js and it is reported rather than made here, because that module is not this
 * agent's to edit.
 */
let resolvedEdAlgorithm = null

async function ed25519Algorithm() {
  if (resolvedEdAlgorithm) return resolvedEdAlgorithm
  const candidates = [{ name: 'Ed25519' }, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }]
  for (const alg of candidates) {
    try {
      await crypto.subtle.generateKey(alg, false, ['sign', 'verify'])
      resolvedEdAlgorithm = alg
      return alg
    } catch {
      // Not this name. Try the next.
    }
  }
  throw new Error('no Ed25519 implementation in this runtime WebCrypto')
}

// =================================================================================
// Request bodies — size, media type, and unambiguous JSON
// =================================================================================

/**
 * Read a request body with a HARD BYTE CAP, counted as the body streams.
 *
 * CONTENT-LENGTH IS NOT TRUSTED. It is a claim by the sender, and a chunked or lying sender
 * can present a small one and stream indefinitely. The cap is enforced against bytes actually
 * received, and the read is abandoned the moment it is exceeded rather than after buffering
 * the whole thing — otherwise the limit protects the parser but not the memory.
 */
async function readBodyBytes(request, env) {
  const max = intVar(env, 'MAX_REQUEST_BYTES', DEFAULT_MAX_REQUEST_BYTES)

  const declared = Number(request.headers.get('content-length') ?? NaN)
  if (Number.isFinite(declared) && declared > max) return { error: 'body_too_large', bytes: null }

  if (request.body === null || request.body === undefined) return { error: null, bytes: new Uint8Array(0) }

  const reader = request.body.getReader()
  const chunks = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > max) {
        try {
          await reader.cancel()
        } catch {
          /* the sender is already being refused */
        }
        return { error: 'body_too_large', bytes: null }
      }
      chunks.push(value)
    }
  } catch {
    return { error: 'malformed_request', bytes: null }
  }

  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return { error: null, bytes }
}

/** Read, media-type check, parse, and refuse a credential in one step. */
async function readJsonBody(request, env, context) {
  const contentType = (request.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase()
  if (contentType !== 'application/json') return { error: 'unsupported_media_type', value: null }
  const body = await readBodyBytes(request, env)
  if (body.error !== null) return { error: body.error, value: null }
  return parseJsonBody(body.bytes)
}

/**
 * Parse a body into a plain object, or refuse.
 *
 * STRICT MEANS THREE SEPARATE THINGS, and each has its own failure:
 *
 *  1. UNAMBIGUOUS (SEC-5). A document with a duplicate key canonicalises differently
 *     depending on which occurrence a parser keeps, and canonicalisation is a security
 *     boundary here: one semantic grant producing two byte sequences produces two
 *     commitments, and NF-4 keys revocation by commitment — so the second form would evade a
 *     revocation entry. `JSON.parse` silently keeps the last occurrence, so the check has to
 *     happen over the TEXT, before parsing. Rejected, never normalised.
 *  2. BOUNDED. Nesting is capped, because unbounded nesting is a stack overflow reachable
 *     from any untrusted body, and the cap matches the depth limit of the credential audit
 *     so nothing can be shallow enough to parse and too deep to inspect.
 *  3. PROTOTYPE-INERT. `__proto__`, `constructor` and `prototype` are refused as key names.
 *     Modern `JSON.parse` does not pollute a prototype, but every body in this file is then
 *     handed to a closed-key-set check, and a key that means something different to the
 *     language than to the schema has no business surviving that far.
 */
function parseJsonBody(bytes) {
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return { error: 'malformed_json', value: null }
  }
  if (text.trim().length === 0) return { error: 'malformed_json', value: null }

  if (!isUnambiguousJson(text, MAX_JSON_DEPTH)) return { error: 'malformed_json', value: null }

  let value
  try {
    value = JSON.parse(text, (key, val) => {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new SyntaxError('prototype-bearing key')
      }
      return val
    })
  } catch {
    return { error: 'malformed_json', value: null }
  }
  if (!isPlainObject(value)) return { error: 'malformed_request', value: null }

  // THE HARD RULE, ON THE INBOUND SIDE. The broker refuses to be handed an OEM credential at
  // all, so there is no window in which it holds one — not even long enough to reject the
  // request on other grounds.
  if (!assertNoOemCredential(value)) return { error: 'malformed_request', value: null }

  return { error: null, value }
}

/**
 * Duplicate-key and depth check over raw JSON text.
 *
 * Written as a small scanner rather than delegated to a parser because no standard parser
 * reports duplicates: `JSON.parse` collapses them, which is precisely the ambiguity being
 * screened for. Key names are compared AFTER unescaping (`"a"` and `"a"` are one name),
 * because a scheme that compared raw tokens would be defeated by an escape.
 */
function isUnambiguousJson(text, maxDepth) {
  const stack = []
  let i = 0
  while (i < text.length) {
    const ch = text[i]
    if (ch === '"') {
      const end = scanStringEnd(text, i)
      if (end === -1) return false
      const top = stack[stack.length - 1]
      if (top && top.object && top.awaitingKey) {
        let name
        try {
          name = JSON.parse(text.slice(i, end + 1))
        } catch {
          return false
        }
        if (top.keys.has(name)) return false
        top.keys.add(name)
      }
      i = end + 1
      continue
    }
    if (ch === '{' || ch === '[') {
      if (stack.length >= maxDepth) return false
      stack.push({ object: ch === '{', keys: ch === '{' ? new Set() : null, awaitingKey: ch === '{' })
      i += 1
      continue
    }
    if (ch === '}' || ch === ']') {
      const top = stack.pop()
      if (top === undefined) return false
      if (top.object !== (ch === '}')) return false
      i += 1
      continue
    }
    if (ch === ':') {
      const top = stack[stack.length - 1]
      if (top && top.object) top.awaitingKey = false
      i += 1
      continue
    }
    if (ch === ',') {
      const top = stack[stack.length - 1]
      if (top && top.object) top.awaitingKey = true
      i += 1
      continue
    }
    i += 1
  }
  return stack.length === 0
}

/** Index of the closing quote of the string starting at `start`, or -1. */
function scanStringEnd(text, start) {
  for (let i = start + 1; i < text.length; i += 1) {
    const ch = text[i]
    if (ch === '\\') {
      i += 1
      continue
    }
    if (ch === '"') return i
  }
  return -1
}

/** Read a response body with a cap, for the one upstream this Worker talks to (the JWKS). */
async function readTextCapped(response, maxBytes) {
  if (response.body === null) return null
  const reader = response.body.getReader()
  const chunks = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      try {
        await reader.cancel()
      } catch {
        /* nothing to do */
      }
      return null
    }
    chunks.push(value)
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

// =================================================================================
// The no-OEM-credential screen
// =================================================================================

/**
 * Refuse any structure carrying a credential-shaped key or a credential-shaped string value.
 *
 * Applied to EVERY request body and EVERY response body. Returns a boolean rather than
 * throwing so a request body can be refused with a 400 and a response body can be turned
 * into a 500 without an exception crossing a handler boundary.
 *
 * See the note on `OEM_CREDENTIAL_KEY_NAMES` for why this is not nf3's list: that one
 * forbids `grant` and `decision`, which are the two words a consent broker's responses exist
 * to say. The resolution response gets nf3's stricter screen instead, where it belongs.
 */
function assertNoOemCredential(value) {
  return walk(value, 0)

  function walk(v, depth) {
    if (depth > MAX_JSON_DEPTH) return false
    if (typeof v === 'string') {
      for (const pattern of CREDENTIAL_VALUE_PATTERNS) {
        if (pattern.test(v)) return false
      }
      return true
    }
    if (v === null || typeof v !== 'object') return true
    if (Array.isArray(v)) {
      for (const item of v) {
        if (!walk(item, depth + 1)) return false
      }
      return true
    }
    for (const [key, sub] of Object.entries(v)) {
      if (OEM_CREDENTIAL_KEY_SET.has(normaliseKeyName(key))) return false
      if (!walk(sub, depth + 1)) return false
    }
    return true
  }
}

/** Lowercase, with separators removed, so `Set-Cookie`, `set_cookie` and `setCookie` are one. */
function normaliseKeyName(name) {
  return String(name).toLowerCase().replace(/[-_]/g, '')
}

// =================================================================================
// Responses
// =================================================================================

/**
 * Security headers, applied to every response without exception.
 *
 * `no-store` is unconditional, INCLUDING on the resolution route. The protocol already
 * caches resolution answers in two tiers keyed by the qname digest, on a synthetic URL, for
 * the express purpose of keeping the raw VIN out of cache keys and intermediary logs; a
 * `public, max-age` header on a URL that contains the VIN would undo that in one line.
 *
 * There is NO `access-control-allow-origin`. These are key-signed machine endpoints, not
 * browser endpoints, and a permissive CORS header in front of a cookie-less but
 * session-bearing route is how a cross-origin read of an owner's consent state gets built.
 * A browser client belongs behind a same-origin server that holds the session.
 *
 * `content-security-policy` and `frame-ancestors` are set even though nothing here serves
 * HTML: a JSON endpoint that one day serves an error page inherits them for free, and the
 * cost is a constant string.
 */
const SECURITY_HEADERS = Object.freeze({
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; sandbox",
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'permissions-policy': 'geolocation=(), camera=(), microphone=()',
})

/**
 * Build a JSON response, screening the body first.
 *
 * The screen runs on the OUTBOUND side too, so no future field can carry an OEM credential
 * out of this Worker. A failure here is a defect in this deployment, not a client error, so
 * it becomes a 500 with an empty structured body rather than a partially-redacted object —
 * redacting a leak is how half of one ships.
 */
function jsonResponse(status, body, context, extraHeaders = {}) {
  if (!assertNoOemCredential(body)) {
    console.error(JSON.stringify({ at: 'response', request_id: context.requestId, error_type: 'CredentialInResponse' }))
    return new Response(
      JSON.stringify({ error: { code: 'internal', message: ERRORS.internal.message, request_id: context.requestId } }),
      { status: 500, headers: { ...SECURITY_HEADERS } },
    )
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...SECURITY_HEADERS, ...extraHeaders },
  })
}

/**
 * A structured error. THE MESSAGE COMES FROM THE TABLE, NEVER FROM AN EXCEPTION.
 *
 * An error body says what the caller did wrong and nothing about what the server is: no
 * exception text, no SQL, no stack, no table name, no row count, no upstream URL, no
 * timing hint, and no echo of any request value. `request_id` is included so an operator can
 * correlate with the log stream, and it is a fresh UUID with no derivation from anything
 * about the caller.
 */
function errorResponse(code, context) {
  const spec = ERRORS[code] ?? ERRORS.internal
  context.code = code
  const headers = { ...SECURITY_HEADERS }
  if (code === 'method_not_allowed') headers.allow = 'GET, POST'
  return new Response(
    JSON.stringify({ error: { code, message: spec.message, request_id: context.requestId } }),
    { status: spec.status, headers },
  )
}

/**
 * The single exit. Emits the one log line this Worker writes per request.
 *
 * WHAT IS IN THE LINE: a request id, the route TEMPLATE, the method, the status, the stable
 * error code if any, the actor KIND, a duration, and a grant id where one is in play.
 *
 * WHAT IS NEVER IN IT, and there is no code path that could put it there: a VIN, a blind
 * index, an owner subject, an IP address, a request or response body, a header, a signature,
 * a key, a salt, or an exception message. Grant ids and pseudonyms are the identifiers this
 * system logs, and both are opaque — a pseudonym is meaningless once the salt is destroyed,
 * which is what makes logging it compatible with §9.5 erasure.
 *
 * The route TEMPLATE rather than the path is the load-bearing detail: `/resolve/:vin` carries
 * a VIN in the URL, and a log line containing the path is a log line containing the VIN.
 */
function finish(response, request, context, startedAt) {
  console.log(
    JSON.stringify({
      request_id: context.requestId,
      route: context.route,
      method: request.method,
      status: response.status,
      code: context.code,
      actor: context.actorKind,
      grant_id: context.grantId,
      duration_ms: Date.now() - startedAt,
    }),
  )
  return response
}

// =================================================================================
// Audit
// =================================================================================

/**
 * Write one audit row.
 *
 * `detail_json` IS BUILT FROM AN ALLOWLIST, NEVER FROM A REQUEST, A RESPONSE OR A CAUGHT
 * ERROR. "Log the error" is the single most common way a VIN or an Authorization header
 * reaches durable storage, so the object handed here is filtered to scalars whose names
 * appear in `AUDIT_DETAIL_KEYS` and whose values are numbers, booleans or short strings
 * drawn from closed vocabularies.
 *
 * An owner is never named: `actor_id` is a requester id or NULL. The vehicle id answers every
 * question the log needs to answer, and a subject id in an audit row is a person in an audit
 * row (schema.sql says the same).
 *
 * A FAILED AUDIT WRITE NEVER FAILS THE REQUEST. The alternative — refusing to serve because
 * a log row would not insert — turns the audit table into an availability dependency in
 * front of revocation, which is the wrong thing to make fragile.
 */
const AUDIT_DETAIL_KEYS = Object.freeze([
  'counterparty_class',
  'purpose',
  'field_count',
  'duration_s',
  'delegation_depth',
  'status',
  'revoked',
  'scope',
  'reason_code',
  'cascaded',
])

async function audit(env, ctx, context, entry) {
  const db = d1(env)
  if (db === null) return

  const detail = {}
  for (const key of AUDIT_DETAIL_KEYS) {
    const value = entry.detail?.[key]
    if (typeof value === 'number' || typeof value === 'boolean') detail[key] = value
    else if (typeof value === 'string' && value.length <= 64) detail[key] = value
  }

  const statement = db
    .prepare(
      'INSERT INTO audit_log (audit_id, at, event, outcome, actor_kind, actor_id, vehicle_id, grant_id, ' +
        'pseudonym, reason_code, detail_json, operator_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ' +
        'ON CONFLICT DO NOTHING',
    )
    .bind(
      context.requestId,
      nowSeconds(),
      entry.event,
      entry.outcome,
      entry.actorKind ?? context.actorKind,
      entry.actorId ?? null,
      entry.vehicleId ?? null,
      entry.grantId ?? null,
      entry.pseudonym ?? null,
      entry.reasonCode ?? null,
      JSON.stringify(detail),
      String(env?.OPERATOR_ID ?? 'unknown'),
    )

  const work = statement
    .run()
    .then(() => maybeSweepNonces(env, db))
    .catch(() => {
      // Deliberately silent on the wire, and the reason is not logged either: a D1 error
      // message can quote a bound value.
      console.error(JSON.stringify({ at: 'audit', request_id: context.requestId, error_type: 'AuditWriteFailed' }))
    })

  // `waitUntil` where available, so the audit write does not sit in the response path; an
  // awaited fallback where it is not, because a floating promise in a Worker is a write that
  // may never happen.
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(work)
  else await work
}

/**
 * Opportunistic nonce GC.
 *
 * A nonce table that is never swept becomes a request-by-request activity log of every
 * requester — a surveillance record accumulated as a side effect of security, which is
 * exactly the shape of thing this architecture refuses elsewhere. Rows are worthless once
 * older than the skew window, so they are deleted rather than retained.
 *
 * Probabilistic rather than scheduled because there is no cron trigger: a scheduled handler
 * is a second entry point with its own authorisation story, and wrangler.toml declines to
 * add one. The cost is that GC is a tendency rather than a guarantee, which is stated here
 * so it is chosen rather than assumed.
 */
async function maybeSweepNonces(env, db) {
  if (Math.random() >= NONCE_SWEEP_PROBABILITY) return
  const ttl = intVar(env, 'NONCE_TTL_S', DEFAULT_NONCE_TTL_S)
  try {
    await db.prepare('DELETE FROM request_nonce WHERE seen_at < ?1').bind(nowSeconds() - ttl).run()
  } catch {
    /* best effort */
  }
}

// =================================================================================
// Small helpers
// =================================================================================

function nowSeconds() {
  return Math.floor(Date.now() / 1000)
}

function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

/**
 * Closed key set over a request body. Unknown members are a REJECTION, never an ignore
 * (SEC-6): a handler that ignores an unrecognised member will happily accept a body carrying
 * a term the client believes is in force and the handler does not enforce, which is where
 * "extension" fields become privilege escalation.
 */
function hasExactlyKeys(value, required, optional) {
  if (!isPlainObject(value)) return false
  const allowed = new Set([...required, ...optional])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) return false
  }
  for (const key of required) {
    if (optional.includes(key)) continue
    if (!Object.hasOwn(value, key)) return false
  }
  return true
}

/**
 * Constant-time string comparison.
 *
 * Used for the grant-commitment comparison at verification time and for every identity
 * equality check (owner subject, counterparty key). None of these is a password, but a
 * commitment is the value NF-4 keys revocation by and an early-exit comparison leaks how far
 * a forged value matched a real one — which is a search oracle, one byte at a time.
 *
 * Length is compared first and unavoidably leaks; every value guarded here is a
 * fixed-length base64url encoding, so the length carries no information. The loop then runs
 * over the full length regardless of the first mismatch.
 */
function timingSafeEqualString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

/** Unpadded base64url length for n bytes. */
function base64urlLengthFor(byteLength) {
  return Math.ceil((byteLength * 4) / 3)
}

/**
 * Strict base64url of an exact byte length: length AND charset checked before any decode, so
 * a value carrying padding, whitespace or standard-alphabet characters cannot round-trip to
 * different bytes on different decoders. Every value guarded by this is inside a signature or
 * a commitment.
 *
 * A third copy of a predicate that is private in nf2-grant.js and duplicated in
 * nf3-resolve.js. Reported, not fixed here: it belongs in a shared helper alongside
 * `base64url`, which vin.js already exports.
 */
function isBase64urlBytes(s, byteLength) {
  if (typeof s !== 'string') return false
  if (s.length !== base64urlLengthFor(byteLength)) return false
  return /^[A-Za-z0-9_-]+$/.test(s)
}

/**
 * The code prefix of a verifier reason, for the audit row.
 *
 * Reasons arrive as `code: detail` (nf2-grant.js and nf4-revocation.js both use that shape),
 * and only the CODE is retained: the detail quotes field ids, timestamps and key material
 * lengths, and none of that belongs in durable storage. The code is the stable, registered
 * half (NF-1 R-4/R-5), which is also the half NF-5 asserts on.
 */
function firstReasonCode(reasons) {
  if (!Array.isArray(reasons) || reasons.length === 0) return null
  const first = String(reasons[0])
  const idx = first.indexOf(':')
  const code = idx > 0 ? first.slice(0, idx) : first
  return code.length <= 64 ? code : code.slice(0, 64)
}

/** Kept exported-adjacent for the conformance suite's benefit: the closed set of codes. */
export const BROKER_REASON_CODES = Object.freeze(Object.keys(ERRORS))

/** Exported so a deployment check can assert the audit vocabulary has not drifted. */
export const BROKER_AUDIT_EVENTS = AUDIT_EVENTS
