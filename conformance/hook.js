/**
 * The NF-5 conformance hook (NF-5 §4.5, CH-1..CH-4).
 *
 * WHAT THIS IS. A test-only module that supplies the three things a production deployment
 * must not have and that the protocol surface therefore cannot supply for itself: a stubbed
 * environment, seeded fixtures, and a way to read persistent state back out. NF-5 §4.5 states
 * plainly why it has to exist at all — assertions in §7 and §8 need clock, fault and canary
 * capabilities that no deployed broker should expose — and states just as plainly what it
 * costs: the audited build is no longer byte-identical to the deployed build. §4.5's honest
 * accounting is the accounting for this file too, and nothing here reduces it.
 *
 * ---------------------------------------------------------------------------------
 * CH-1 AND CH-2, SATISFIED BY CONSTRUCTION AND CHECKABLE FROM THE IMPORT LIST ALONE
 * ---------------------------------------------------------------------------------
 * The dependency arrow points ONE WAY. This module imports the Worker; the Worker does not
 * import this module, directly or transitively, and `broker/src/index.js` names nothing under
 * `conformance/` anywhere in its import list. That is CH-1, and it is decidable by reading the
 * two import lists rather than by trusting this comment.
 *
 * There is no `import()`, no `eval`, no `new Function`, and no module specifier built from a
 * string anywhere in this file or in the test file above it. NF-5 §8.3 forbids those on the
 * Declared Surface precisely so that CH-2 — "the production bundle's static import graph MUST
 * NOT reach that module" — is a decidable question rather than an undecidable one, and a hook
 * that used them would have destroyed the property it exists to demonstrate.
 *
 * WHAT IS DELIBERATELY IMPORTED FROM THE IUT, AND WHAT IS NOT. Exactly one binding: the
 * Worker's default export. Nothing else from `broker/src/` is imported here — not `fields.js`,
 * not `nf2-grant.js`, not `vin.js`, not `nf3-resolve.js` — because a hook that reached into
 * the implementation to build its fixtures would be handing the PROTOCOL profile a set of
 * artifacts that only this implementation can produce, and §4.2 exists to prevent exactly
 * that. Every protocol constant this file needs (domain separators, the request-signature
 * construction, the NF-4 record shape, the JCS rules) is RESTATED here from the specification,
 * with the citation next to it. §4.8 requires that restatement — the suite is the only party
 * entitled to state its own vectors, and reading them from the IUT is how a suite ends up
 * asserting that the IUT agrees with itself.
 *
 * The consequence, stated so it is chosen rather than discovered: an implementation written in
 * another language on another substrate supplies its own `hook.js` — its own env, its own
 * fixture seeding, its own state read-back — and runs `tests/protocol.test.js` unchanged. That
 * is the whole point of the split.
 *
 * ---------------------------------------------------------------------------------
 * STACK (NF-5 §4.3)
 * ---------------------------------------------------------------------------------
 * Plain ES module. No npm, no build step, no dependency. Node built-ins and web-standard APIs
 * only. `node:sqlite` is used for the D1 stub and is a Node built-in requiring no install
 * (Node 22.5+; developed on v24). The alternative — hand-rolling a SQL engine — would have
 * made every assertion above it a claim about my SQL engine rather than about the
 * implementation, which is the failure mode this file's fidelity notes exist to bound.
 * Ed25519 is obtained by feature-detecting `{ name: 'Ed25519' }` and falling back to the
 * legacy Workers name `NODE-ED25519`, as §4.3 requires. No curve and no cipher is hand-rolled.
 *
 * ---------------------------------------------------------------------------------
 * HERMETICITY (NF-5 §4.4(1))
 * ---------------------------------------------------------------------------------
 * Nothing here reaches the network. The two paths on which the Worker would make an outbound
 * request are closed by seeding rather than by patching a global:
 *
 *   - the identity provider's JWKS is pre-seeded into the KV stub under the exact cache key
 *     the Worker reads, so `loadJwks` never falls through to `fetch`;
 *   - the NF-3 resolution answer is pre-seeded into the D1 answer cache, so resolution never
 *     reaches a zone transport.
 *
 * Both configured URLs are under `.invalid` (RFC 2606), which resolves nowhere. So if a future
 * change did make the Worker attempt an outbound request, the request fails and the assertion
 * above it fails with it — the harness fails closed rather than silently going online.
 */

import { DatabaseSync } from 'node:sqlite'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// The ONLY import from the implementation under test: its entry point. See CH-1 above.
import worker from '../broker/src/index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCHEMA_PATH = join(HERE, '..', 'broker', 'schema.sql')

/**
 * The Worker under test, re-exported so `tests/protocol.test.js` never names a module path
 * inside `broker/src/`. §4.2: "A PROTOCOL assertion MUST NOT reference any function name,
 * module path, or internal API." The one thing a black-box harness cannot avoid knowing is
 * where the front door is, so the front door is named here, once.
 */
export { worker }

// =================================================================================
// Protocol constants, RESTATED (NF-5 §4.8)
// =================================================================================

/**
 * Every constant below is a property of the SPECIFICATION, not of this implementation, and is
 * written out here rather than imported for the reason §4.8 gives in its own clause: a suite
 * that reads the forbidden list, the domain separators or the wire vocabulary from the IUT is
 * a suite an IUT passes by shipping an empty list.
 *
 * If one of these strings is wrong, the tests above fail loudly (a signature will not verify,
 * a blind index will not match a seeded row). None of them can be wrong quietly.
 */

/** NF-2 §3.3 / broker: the blind-index domain over a VIN, HMAC-SHA-256 under VIN_INDEX_KEY. */
const VIN_INDEX_DOMAIN = 'nf-vin-index:v1:'

/** NF-2: the owner revocation-key thumbprint domain, SHA-256 over the raw public key. */
const REVOCATION_KEY_ID_DOMAIN = 'nf2-revocation-key-id:v1:'

/** NF-3: the wire name for a VIN — a domain-separated SHA-256, base64url. */
const QNAME_DIGEST_DOMAIN = 'nf3-qname:v1:'

/** NF-3: a zone's key identifier — a domain-separated SHA-256 thumbprint of its public key. */
const ZONE_KEY_ID_DOMAIN = 'nf3-zone-key-id:v1:'

/** The broker's request-signature domain (NF-1 §10, SEC-2). First line of the signed string. */
const REQUEST_SIG_DOMAIN = 'nf-request-signature:v1'

/** NF-4 record version. The type binding lives inside the signed bytes as `v`. */
export const NF4_RECORD_VERSION = 'nf4-revocation/1'

/** NF-2 grant schema version. */
export const NF2_SCHEMA_VERSION = 'nf2-grant/1'

/** NF-3 answer and endpoint-record versions. */
const NF3_ANSWER_VERSION = 'nf3-answer/1'
const NF3_ENDPOINT_PROTOCOL = 'nf3-endpoint/1'

/**
 * The six routes this Worker publishes. NF-5 §8.2 would have this come from a Declared Surface
 * manifest; §8.2 is not present in `specs/`, so the list is enumerated here from the router and
 * that limitation is stated rather than hidden — a route absent from this list is a route the
 * DD-010-shaped sweep in `protocol.test.js` does not cover, which is the standing limitation of
 * every declared-surface check.
 */
export const PUBLISHED_ROUTES = Object.freeze([
  Object.freeze({ method: 'GET', template: '/healthz' }),
  Object.freeze({ method: 'POST', template: '/grants' }),
  Object.freeze({ method: 'GET', template: '/grants/:id' }),
  Object.freeze({ method: 'POST', template: '/grants/:id/verify' }),
  Object.freeze({ method: 'POST', template: '/revocations' }),
  Object.freeze({ method: 'GET', template: '/resolve/:vin' }),
])

/** The origin every synthetic request is made against. `.invalid` resolves nowhere. */
export const BROKER_ORIGIN = 'https://broker.conformance.invalid'

// =================================================================================
// Small primitives — base64url, digests, canonical JSON
// =================================================================================

const TE = new TextEncoder()

export function base64url(bytes) {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64urlToBytes(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  return out
}

export async function sha256Base64url(input) {
  const bytes = typeof input === 'string' ? TE.encode(input) : input
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
}

async function hmacSha256Base64url(secret, message) {
  const key = await crypto.subtle.importKey('raw', TE.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return base64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, TE.encode(message))))
}

function randomBase64url(byteLength) {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

/**
 * RFC 8785 (JCS) canonicalisation, RESTRICTED to the value space the protocol artifacts this
 * harness constructs actually occupy: plain objects, arrays, ASCII strings, safe integers, and
 * null.
 *
 * IT REFUSES EVERYTHING ELSE, LOUDLY, and that refusal is the honesty control. A partial JCS
 * that silently mishandled a float, a non-ASCII string or an unsafe integer would produce
 * signatures that verify against nothing, and the failure would look like a broken
 * implementation rather than a broken harness. Sorting is by UTF-16 code unit — the comparator
 * RFC 8785 specifies and the one the grant's `fields` array uses — which for the ASCII key
 * names here is the same order as a byte sort, but is written as the code-unit rule so the
 * restriction is on the INPUT rather than on the algorithm.
 *
 * This is a harness reimplementation on purpose (§4.2, §4.8): an independent implementer must
 * be able to canonicalise a revocation record from the published rules without borrowing the
 * reference `jcs.js`, and if the two disagreed, the signature would not verify and the
 * assertion would fail — which is exactly the right direction to fail in.
 */
export function canonicalJson(value) {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`canonicalJson: refusing ${String(value)} — this harness canonicalises safe integers only`)
    }
    // Number.isSafeInteger excludes -0 only by returning true for it; pin the sign explicitly,
    // because -0 and 0 are one JSON number and two different JavaScript values.
    return String(value === 0 ? 0 : value)
  }
  if (typeof value === 'string') {
    // eslint-disable-next-line no-control-regex
    if (/[^\x20-\x7e]/.test(value)) {
      throw new Error('canonicalJson: refusing a non-ASCII or control character — outside this harness\'s subset')
    }
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort(compareCodeUnits)
    return `{${keys.map((k) => `${canonicalJson(k)}:${canonicalJson(value[k])}`).join(',')}}`
  }
  throw new Error(`canonicalJson: unsupported value of type ${typeof value}`)
}

/** UTF-16 code-unit order: JavaScript's default string comparison, named rather than implied. */
function compareCodeUnits(a, b) {
  return a < b ? -1 : a > b ? 1 : 0
}

// =================================================================================
// Ed25519 (NF-5 §4.3)
// =================================================================================

let resolvedEd25519 = null

/**
 * §4.3: Ed25519 MUST be obtained by feature-detecting `{ name: 'Ed25519' }` and falling back to
 * the legacy Workers name `NODE-ED25519`. A runtime that resolves neither cannot evaluate any
 * signature-dependent assertion, so this throws rather than degrading — §4.6 counts
 * "could not be evaluated" as FAIL, and a harness that quietly skipped would have converted a
 * failure into a silence.
 */
export async function ed25519Algorithm() {
  if (resolvedEd25519) return resolvedEd25519
  for (const algorithm of [{ name: 'Ed25519' }, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }]) {
    try {
      await crypto.subtle.generateKey(algorithm, false, ['sign', 'verify'])
      resolvedEd25519 = algorithm
      return algorithm
    } catch {
      // Not this name. The throw IS the feature detection.
    }
  }
  throw new Error('no Ed25519 implementation in this runtime WebCrypto; every signature-dependent assertion is INCONCLUSIVE (NF-5 §4.3, §4.6)')
}

/** An Ed25519 keypair plus the raw public key in the base64url form every wire field uses. */
export async function generateEd25519KeyPair() {
  const alg = await ed25519Algorithm()
  const pair = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicKeyBase64url: base64url(raw), rawPublicKey: raw }
}

async function ed25519Sign(privateKey, bytes) {
  const alg = await ed25519Algorithm()
  return base64url(new Uint8Array(await crypto.subtle.sign(alg, privateKey, bytes)))
}

/** The owner revocation-key thumbprint: SHA-256 over the domain separator and the raw key. */
export async function revocationKeyIdFor(rawPublicKey) {
  const prefix = TE.encode(REVOCATION_KEY_ID_DOMAIN)
  const buf = new Uint8Array(prefix.length + rawPublicKey.length)
  buf.set(prefix, 0)
  buf.set(rawPublicKey, prefix.length)
  return sha256Base64url(buf)
}

// =================================================================================
// The D1 stub
// =================================================================================

/**
 * An in-memory D1 binding backed by `node:sqlite`, faithful to the subset of the D1 API that
 * `broker/src/index.js` actually calls: `prepare`, `bind`, `first`, `run`, `all`, `batch`.
 *
 * WHERE IT IS FAITHFUL. D1 is SQLite, and so is this: the recursive descendant walk, the
 * `ON CONFLICT DO NOTHING` idempotency, `MAX(effective_from)` over the kill-switch floor, the
 * STRICT column types and every CHECK constraint in `schema.sql` are the real engine
 * evaluating the real DDL. `bind()` returns a NEW statement rather than mutating, which is D1's
 * semantics and the reason `db.prepare(sql).bind(a, b).first()` composes. `run()` reports
 * `meta.changes` from the engine, which is what the Worker's replay check reads.
 *
 * WHERE IT IS THIN — say this plainly, because a stub that silently diverges turns every
 * assertion above it into a claim about the stub:
 *
 *  1. NO NETWORK, NO LATENCY, NO PARTIAL FAILURE. D1 is a remote service that can time out
 *     mid-batch, return `D1_ERROR`, or be unavailable. Nothing here ever fails, so no assertion
 *     in this suite evidences the Worker's `store_unavailable` paths, and its fail-closed
 *     posture on an unreadable revocation table is asserted nowhere by this harness.
 *  2. NO CONCURRENCY. `node:sqlite` is synchronous and single-threaded, so the two
 *     read-after-insert races the Worker guards against (two issuances minting two pseudonym
 *     salts, or two custodial signing keys, for one vehicle) cannot occur here. The guard is
 *     exercised; the race is not.
 *  3. PLACEHOLDER REWRITING. D1 and SQLite both accept `?N`; `node:sqlite` binds the ordered
 *     arguments to them positionally, which is the same mapping. Nothing is rewritten, but the
 *     equivalence is an assumption and is named as one.
 *  4. PREPARE-TIME PARSING. `node:sqlite` parses at `prepare()`; D1 reports a malformed
 *     statement at execution. A syntax error therefore surfaces one call earlier here.
 *  5. STRICTER, NOT LOOSER. Foreign keys are ON and every table is STRICT, so a type-confused
 *     bind that D1 might coerce is refused here. Divergence in the direction of refusal cannot
 *     manufacture a pass, which is why it is acceptable; it can manufacture a spurious FAIL,
 *     which is why it is written down.
 *  6. INTEGER WIDTH. Values beyond 2^53 come back as JavaScript numbers and lose precision.
 *     No column in `schema.sql` legitimately holds one (every timestamp is bounded by a CHECK),
 *     but a value that got there some other way would be silently rounded.
 *  7. `exec()`, `dump()`, `withSession()` and D1's `.raw()` are not implemented, because the
 *     Worker does not call them. A future call site would throw rather than be quietly wrong.
 */
class D1PreparedStub {
  #db
  #sql
  #values

  constructor(db, sql, values) {
    this.#db = db
    this.#sql = sql
    this.#values = values
  }

  /** D1 returns a new statement; the unbound original stays reusable. */
  bind(...values) {
    return new D1PreparedStub(this.#db, this.#sql, values)
  }

  async first(column) {
    const row = this.#db.prepare(this.#sql).get(...this.#values)
    if (row === undefined || row === null) return null
    const plain = { ...row }
    if (column === undefined) return plain
    return Object.hasOwn(plain, column) ? plain[column] : null
  }

  async run() {
    const result = this.#db.prepare(this.#sql).run(...this.#values)
    const changes = Number(result.changes)
    return {
      success: true,
      results: [],
      meta: { changes, last_row_id: Number(result.lastInsertRowid), duration: 0, rows_read: 0, rows_written: changes },
    }
  }

  async all() {
    const rows = this.#db.prepare(this.#sql).all(...this.#values)
    return {
      success: true,
      results: rows.map((r) => ({ ...r })),
      meta: { changes: 0, last_row_id: 0, duration: 0, rows_read: rows.length, rows_written: 0 },
    }
  }
}

class D1DatabaseStub {
  #db

  constructor(db) {
    this.#db = db
  }

  prepare(sql) {
    return new D1PreparedStub(this.#db, sql, [])
  }

  /**
   * D1 executes a batch as ONE transaction, which is the property the Worker's cascade write
   * depends on: a revocation that recorded the parent and died before the children would leave
   * live descendants of a dead grant. Reproduced with a real SQLite transaction, so a throw
   * mid-batch rolls the whole thing back here as it would there.
   */
  async batch(statements) {
    this.#db.exec('BEGIN')
    try {
      const out = []
      for (const statement of statements) out.push(await statement.run())
      this.#db.exec('COMMIT')
      return out
    } catch (err) {
      this.#db.exec('ROLLBACK')
      throw err
    }
  }
}

/**
 * The KV stub.
 *
 * ITS ONE HONEST LIMITATION, and it is the interesting one: real Workers KV is eventually
 * consistent with a read-after-write window of up to a minute, and the Worker's comments lean
 * on that window being REAL — it is why nonces and revocation state live in D1 and only the
 * public JWKS lives in KV. This stub is immediately consistent, so it cannot demonstrate that
 * reasoning; it can only avoid contradicting it. `expirationTtl` is recorded and never
 * enforced, because nothing in the suite depends on a KV entry expiring.
 */
class KvStub {
  #store = new Map()

  async get(key, options) {
    const value = this.#store.get(key)
    if (value === undefined) return null
    if (options?.type === 'json') {
      try {
        return JSON.parse(value)
      } catch {
        return null
      }
    }
    return value
  }

  async put(key, value, _options) {
    this.#store.set(key, String(value))
  }

  async delete(key) {
    this.#store.delete(key)
  }
}

/**
 * A permissive rate-limit binding.
 *
 * STATED SO IT IS NOT MISREAD AS COVERAGE: this always succeeds, so NO assertion in this suite
 * evidences anything about rate limiting. It is stubbed permissive rather than absent because
 * the Worker's in-isolate fallback limiter is module-global state shared by every request in a
 * test file — leaving it engaged would make an assertion's outcome depend on how many
 * assertions ran before it, which §4.4(4) forbids outright.
 */
function permissiveRateLimiter() {
  return { limit: async () => ({ success: true }) }
}

// =================================================================================
// The harness
// =================================================================================

function nowSeconds() {
  return Math.floor(Date.now() / 1000)
}

/**
 * A VIN with a valid 49 C.F.R. §565.15 check digit, fixed as a suite vector (§4.4(5)).
 * `1HG` is its WMI, which is what the seeded NF-3 zone is scoped to.
 */
export const FIXTURE_VIN = '1HGCM82633A004352'

/** A second well-formed VIN, deliberately NOT enrolled. Same WMI so it shares the zone. */
export const UNENROLLED_VIN = '1HGCM82633A004349'

/**
 * Build a complete, isolated conformance environment: a fresh in-memory database with
 * `broker/schema.sql` applied, a stubbed `env` carrying every binding and var the Worker reads,
 * seeded fixtures, and the request helpers the wire-level assertions drive it with.
 *
 * EVERY CALL RETURNS AN INDEPENDENT WORLD. §4.4(4) requires assertions to pass in any order and
 * to share no mutable state; a single shared database would make "was this grant revoked" a
 * question about execution order. The cost is a keypair generation per harness, which is
 * milliseconds for Ed25519 and tens of milliseconds for the RSA identity-provider key.
 */
export async function createHarness(options = {}) {
  const db = new DatabaseSync(':memory:')
  db.exec('PRAGMA foreign_keys = ON')
  db.exec(readFileSync(SCHEMA_PATH, 'utf8'))

  const d1 = new D1DatabaseStub(db)
  const kv = new KvStub()
  const now = nowSeconds()

  const vin = options.vin ?? FIXTURE_VIN
  const vehicleId = 'veh_conformance_0001'
  const ownerSubject = 'user_conformance_owner'
  const pseudonymEpoch = 0

  // ---- vars and secrets -----------------------------------------------------------
  // Every value the Worker reads with `env?.X`. A missing one is a 503
  // `configuration_incomplete` rather than a silent degradation, so an incomplete env here
  // would fail the assertions above it loudly.
  const env = {
    ENVIRONMENT: 'conformance',
    OPERATOR_ID: 'op_conformance',
    DB: d1,
    CACHE: kv,
    RATE_LIMITER: permissiveRateLimiter(),
    RATE_LIMITER_RESOLVE: permissiveRateLimiter(),
    VIN_INDEX_KEY: 'conformance-vin-index-key-not-a-production-secret',
    OWNER_KEY_WRAP_KEY: 'conformance-owner-key-wrap-key-not-a-production-secret',
    CLERK_ISSUER: 'https://idp.conformance.invalid',
    CLERK_JWKS_URL: 'https://idp.conformance.invalid/.well-known/jwks.json',
    CLERK_AUTHORIZED_PARTIES: 'nf5-conformance-suite',
    AUTH_MAX_SKEW_S: 60,
    NONCE_TTL_S: 300,
    MAX_REQUEST_BYTES: 16 * 1024,
    NF3_TRUST_ANCHORS: null, // filled in below, once the zone key exists
  }

  // ---- the identity provider ------------------------------------------------------
  // An RSA-2048 keypair, its public half seeded into KV under the exact key the Worker's JWKS
  // loader reads. This is what keeps the owner-authenticated routes reachable with no outbound
  // request; see the hermeticity note in the file header.
  const idpKey = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )
  const idpJwk = await crypto.subtle.exportKey('jwk', idpKey.publicKey)
  const idpKid = 'conformance-idp-key-1'
  await kv.put(
    `jwks:${env.CLERK_JWKS_URL}`,
    JSON.stringify({ keys: [{ kty: 'RSA', n: idpJwk.n, e: idpJwk.e, kid: idpKid, alg: 'RS256', use: 'sig' }] }),
  )

  // ---- the owner's revocation key -------------------------------------------------
  // Owner-held, and the broker holds no private half and has no column for one. Registering
  // the public key and its thumbprint is the enrolment step; NF-4 revocation records are signed
  // with the private half by the test, never by the broker.
  const ownerRevocation = await generateEd25519KeyPair()
  const revocationKeyId = await revocationKeyIdFor(ownerRevocation.rawPublicKey)

  // ---- two counterparties ---------------------------------------------------------
  // Two, because "a different holder cannot present this grant" needs a second holder that is
  // itself registered and active — otherwise the refusal could be explained by the second
  // party being unknown rather than by the grant being bound.
  const counterpartyA = await generateEd25519KeyPair()
  const counterpartyB = await generateEd25519KeyPair()

  const vinIndex = await hmacSha256Base64url(env.VIN_INDEX_KEY, VIN_INDEX_DOMAIN + vin)
  const salt = randomBase64url(32)

  await d1
    .prepare(
      'INSERT INTO vehicle_enrolment (vehicle_id, vin_index, wmi, owner_account_id, pseudonym_epoch, ' +
        'enrolled_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)',
    )
    .bind(vehicleId, vinIndex, vin.slice(0, 3), ownerSubject, pseudonymEpoch, now, now)
    .run()

  await d1
    .prepare('INSERT INTO pseudonym_salt (vehicle_id, epoch, salt, created_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(vehicleId, pseudonymEpoch, salt, now)
    .run()

  await d1
    .prepare(
      'INSERT INTO owner_revocation_key (revocation_key_id, vehicle_id, public_key, registered_at) ' +
        'VALUES (?1, ?2, ?3, ?4)',
    )
    .bind(revocationKeyId, vehicleId, ownerRevocation.publicKeyBase64url, now)
    .run()

  const holders = []
  for (const [holder, spec] of [
    [counterpartyA, { id: 'req_alpha_shop', name: 'Alpha Independent Repair', class: 'repair-independent', keyId: 'alpha-key-1' }],
    [counterpartyB, { id: 'req_beta_fleet', name: 'Beta Fleet Operations', class: 'fleet-operator', keyId: 'beta-key-1' }],
  ]) {
    await d1
      .prepare(
        'INSERT INTO requester (requester_id, display_name, counterparty_class, licence_reference, status, ' +
          'registered_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)',
      )
      .bind(spec.id, spec.name, spec.class, null, 'active', now, now)
      .run()
    await d1
      .prepare('INSERT INTO requester_key (key_id, requester_id, public_key, status, added_at) VALUES (?1, ?2, ?3, ?4, ?5)')
      .bind(spec.keyId, spec.id, holder.publicKeyBase64url, 'active', now)
      .run()
    holders.push({ ...holder, requesterId: spec.id, keyId: spec.keyId, counterpartyClass: spec.class })
  }

  // ---- the NF-3 answer cache ------------------------------------------------------
  // Two seeded answers: a positive `ce` answer for the enrolled vehicle and a signed negative
  // answer for a well-formed VIN that is not enrolled. The negative one exists so the
  // not-enrolled path is reachable WITHOUT a network round trip — an unseeded name sends the
  // resolver to its anchor's endpoint, and an assertion that depends on that request failing is
  // an assertion about DNS.
  const zone = await seedResolutionAnswer(d1, env, vin, now)
  await seedNegativeAnswer(d1, zone, UNENROLLED_VIN, now)

  const harness = {
    env,
    db,
    d1,
    now,
    vin,
    vehicleId,
    ownerSubject,
    pseudonymEpoch,
    salt,
    revocationKeyId,
    ownerRevocation,
    counterparty: holders[0],
    otherCounterparty: holders[1],
    zone,
    idp: { privateKey: idpKey.privateKey, kid: idpKid },
  }

  harness.fetch = (request) => driveWorker(harness, request)
  harness.ownerFetch = (path, init) => ownerFetch(harness, path, init)
  harness.holderFetch = (holder, path, init) => holderFetch(harness, holder, path, init)
  harness.anonymousFetch = (path, init) => driveWorker(harness, new Request(new URL(path, BROKER_ORIGIN), init))
  return harness
}

/**
 * Seed one signed NF-3 answer into the resolver's D1 cache, and configure the zone that signed
 * it as a trust anchor.
 *
 * WHY THIS IS THE INJECTION POINT. Resolution is an authenticated protocol with no insecure
 * mode: no anchor, no answer. The Worker exposes no way to inject a zone transport, so the only
 * hermetic path to a positive resolution is the cache the resolver already re-verifies on every
 * read. That re-verification is what makes the fixture meaningful rather than circular — the
 * answer is checked against the anchor, the qname digest, the zone's bailiwick, the answer
 * policy and the signature before the route will serve it, so a wrong fixture fails rather than
 * being rubber-stamped.
 *
 * The zone is a `wmi` zone because NF-3's answer policy forbids the root from answering a
 * consent-endpoint record directly — the root operating what it governs is the thing Refusal 3
 * forbids, expressed in the resolution grammar. Any zone may be an anchor, so anchoring
 * directly at the WMI zone is a legitimate resolver configuration and not a shortcut.
 */
async function seedResolutionAnswer(d1, env, vin, now) {
  const zoneKey = await generateEd25519KeyPair()
  const brokerKey = await generateEd25519KeyPair()
  const zoneId = `wmi:${vin.slice(0, 3)}`
  const zoneObject = { id: zoneId, scope_type: 'wmi', scope: vin.slice(0, 3) }
  const endpoint = 'https://consent.carnimbus.invalid/nf3/v1'

  const qname = await sha256Base64url(QNAME_DIGEST_DOMAIN + vin)
  const prefix = TE.encode(ZONE_KEY_ID_DOMAIN)
  const keyIdInput = new Uint8Array(prefix.length + zoneKey.rawPublicKey.length)
  keyIdInput.set(prefix, 0)
  keyIdInput.set(zoneKey.rawPublicKey, prefix.length)
  const signerKeyId = await sha256Base64url(keyIdInput)

  const answer = {
    v: NF3_ANSWER_VERSION,
    qname_digest: qname,
    zone: zoneObject,
    record: {
      type: 'ce',
      endpoint: `${endpoint}`,
      protocol_version: NF3_ENDPOINT_PROTOCOL,
      // Advertised capability, not permission — and drawn from the CLOSED field-class
      // vocabulary, which is why a zone cannot advertise a forbidden class even as a lie.
      supported_field_classes: ['build_specification', 'diagnostics', 'usage'],
      broker_key: brokerKey.publicKeyBase64url,
    },
    ttl: 300,
    answered_at: now,
    nonce: randomBase64url(16),
    signer_key_id: signerKeyId,
    signature: null,
  }
  const unsigned = {}
  for (const key of Object.keys(answer)) {
    if (key !== 'signature') unsigned[key] = answer[key]
  }
  answer.signature = await ed25519Sign(zoneKey.privateKey, TE.encode(canonicalJson(unsigned)))

  const chain = [{ zone_id: zoneId, key: zoneKey.publicKeyBase64url, source: 'anchor' }]
  await d1
    .prepare(
      'INSERT INTO nf3_resolution_cache (qname_digest, record_type, zone_id, zone_key, answer_json, ' +
        'chain_json, cached_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)',
    )
    .bind(qname, 'ce', zoneId, zoneKey.publicKeyBase64url, JSON.stringify(answer), JSON.stringify(chain), now, now + 300)
    .run()

  // The anchor's endpoint is a ROOT HINT, not an authority: getting it wrong is a denial of
  // service, never a spoof, because the key is what authenticates the answer. It is under
  // `.invalid` so a cache miss cannot silently become a network query.
  env.NF3_TRUST_ANCHORS = JSON.stringify({
    [zoneId]: { endpoint: 'https://zone.conformance.invalid/nf3', key: zoneKey.publicKeyBase64url },
  })

  return { zoneId, zone: zoneObject, endpoint, qnameDigest: qname, zoneKey, brokerKey, answer }
}

// =================================================================================
// Driving the Worker
// =================================================================================

/**
 * One request in, one response out, with `waitUntil` work drained before the response is
 * handed back.
 *
 * DRAINING IS NOT A CONVENIENCE. The Worker defers its audit write to `ctx.waitUntil`, so a
 * harness that returned the moment the response resolved would let an assertion about the audit
 * row race the write that produces it. §4.4(4) forbids ordering dependence; draining converts
 * a race into a sequence.
 */
async function driveWorker(harness, request) {
  const pending = []
  const ctx = { waitUntil: (promise) => pending.push(promise), passThroughOnException: () => {} }
  const response = await worker.fetch(request, harness.env, ctx)
  await Promise.allSettled(pending)
  return response
}

function jsonInit(body, extra = {}) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(extra.headers ?? {}) },
    body: JSON.stringify(body),
    ...extra,
  }
}

/**
 * Mint a fresh identity-provider session token and make an owner-authenticated request.
 *
 * The token is a real RS256 JWT verified against the seeded JWKS: `alg` is pinned to RS256 by
 * the Worker and read only to refuse anything else, so a harness that produced an `alg: none`
 * token would be refused exactly as an attacker's would.
 */
export async function ownerJwt(harness, overrides = {}) {
  const now = nowSeconds()
  const header = { alg: 'RS256', typ: 'JWT', kid: harness.idp.kid, ...(overrides.header ?? {}) }
  const claims = {
    iss: harness.env.CLERK_ISSUER,
    sub: harness.ownerSubject,
    azp: 'nf5-conformance-suite',
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    ...(overrides.claims ?? {}),
  }
  const encode = (obj) => base64url(TE.encode(JSON.stringify(obj)))
  const signingInput = `${encode(header)}.${encode(claims)}`
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', harness.idp.privateKey, TE.encode(signingInput)),
  )
  return `${signingInput}.${base64url(signature)}`
}

async function ownerFetch(harness, path, init = {}) {
  const token = await ownerJwt(harness)
  const headers = { ...(init.headers ?? {}), authorization: `Bearer ${token}` }
  const request = new Request(new URL(path, BROKER_ORIGIN), { ...init, headers })
  return driveWorker(harness, request)
}

/**
 * Make a counterparty request, signed with the Ed25519 key the grant is bound to.
 *
 * THE SIGNED STRING IS RESTATED FROM THE WIRE CONTRACT, not imported (§4.8): domain separator,
 * operator id, method, pathname, timestamp, nonce, and the base64url SHA-256 of the body. An
 * independent implementation has to construct exactly these bytes to be authenticated, which is
 * why writing them out here is the assertion rather than a duplication of it.
 *
 * The signature is proof of possession IN THIS SESSION, which is what makes a Consent Grant not
 * a bearer token: a stolen grant with no private key gains its holder nothing, and the
 * assertions in `protocol.test.js` that show this rely on this helper being the only way a
 * holder can speak.
 */
async function holderFetch(harness, holder, path, init = {}) {
  const url = new URL(path, BROKER_ORIGIN)
  const method = (init.method ?? 'GET').toUpperCase()
  const bodyText = init.body === undefined ? '' : String(init.body)
  const bodyBytes = TE.encode(bodyText)
  const bodyDigest = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', bodyBytes)))
  const timestamp = String(nowSeconds())
  const nonce = randomBase64url(16)

  const signingInput = TE.encode(
    [REQUEST_SIG_DOMAIN, harness.env.OPERATOR_ID, method, url.pathname, timestamp, nonce, bodyDigest].join('\n'),
  )
  const signature = await ed25519Sign(holder.privateKey, signingInput)

  const headers = {
    ...(init.headers ?? {}),
    'nf-key-id': holder.keyId,
    'nf-timestamp': timestamp,
    'nf-nonce': nonce,
    'nf-signature': signature,
  }
  return driveWorker(harness, new Request(url, { ...init, method, headers }))
}

// =================================================================================
// Wire-artifact constructors the tests need
// =================================================================================

/**
 * Issue a grant over the wire and return the parsed response.
 *
 * Every fixture grant in `protocol.test.js` is created THROUGH THE PROTOCOL rather than
 * inserted into the database. That matters more than it looks: a seeded grant row would be a
 * fixture the harness authored, and every assertion about it would be an assertion about the
 * harness. A grant obtained from `POST /grants` is one the implementation actually issued.
 */
export async function issueGrant(harness, overrides = {}) {
  const body = {
    vin: harness.vin,
    fields: ['make', 'odometer_km'],
    purpose: 'dppa-2721b-2',
    counterparty_class: harness.counterparty.counterpartyClass,
    counterparty_key: harness.counterparty.publicKeyBase64url,
    revocation_key_id: harness.revocationKeyId,
    duration_seconds: 3600,
    ...overrides,
  }
  for (const key of Object.keys(body)) {
    if (body[key] === undefined) delete body[key]
  }
  const response = await harness.ownerFetch('/grants', jsonInit(body))
  const text = await response.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    json = null
  }
  return { response, status: response.status, body: json, text }
}

/** Verify a grant over the wire, as the holder that possesses the bound key. */
export async function verifyGrantOverWire(harness, holder, grant) {
  const payload = JSON.stringify({ grant })
  const response = await harness.holderFetch(holder, `/grants/${grant.grant_id}/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: payload,
  })
  const text = await response.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    json = null
  }
  return { response, status: response.status, body: json, text }
}

/**
 * Build and sign an NF-4 revocation record with an OWNER-held key.
 *
 * The record shape, the closed reason vocabulary and the signing rule are restated from NF-4:
 * eight keys, all present, explicit `null` where a scope does not use them, canonicalised with
 * `signature` removed and signed with the owner's revocation private key. There is no domain
 * tag outside the canonical bytes because the type binding is inside them as `v`.
 *
 * THE BROKER CANNOT PRODUCE ONE OF THESE. It holds no revocation private key and has no column
 * for one, which is why this constructor lives in the harness — the test plays the owner, and
 * the broker's only role is to check the signature and record the consequence.
 */
export async function signRevocation(harness, { scope, target, effectiveFrom = null, reason = 'owner_withdrew', issuedAt, key }) {
  const signingKey = key ?? harness.ownerRevocation
  const record = {
    v: NF4_RECORD_VERSION,
    scope,
    target,
    revocation_key: signingKey.publicKeyBase64url,
    issued_at: issuedAt ?? nowSeconds(),
    effective_from: scope === 'vehicle' ? (effectiveFrom ?? issuedAt ?? nowSeconds()) : null,
    reason,
    signature: null,
  }
  const unsigned = {}
  for (const key2 of Object.keys(record)) {
    if (key2 !== 'signature') unsigned[key2] = record[key2]
  }
  record.signature = await ed25519Sign(signingKey.privateKey, TE.encode(canonicalJson(unsigned)))
  return record
}

/** POST a revocation record. Deliberately unauthenticated: the record authenticates itself. */
export async function postRevocation(harness, record, init = {}) {
  const response = await harness.anonymousFetch('/revocations', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(init.headers ?? {}) },
    body: JSON.stringify({ revocation: record }),
  })
  const text = await response.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    json = null
  }
  return { response, status: response.status, body: json, text }
}

// =================================================================================
// State read-back
// =================================================================================

/**
 * The tables whose contents ARE the consent state: what was granted, what was revoked, and the
 * key material and salt that make either meaningful.
 *
 * WHAT IS EXCLUDED, AND WHY IT IS NOT A LOOPHOLE. `audit_log` and `request_nonce` are omitted
 * because both are EXPECTED to change on a refused request — an audit row recording that a
 * request was refused is the point of an audit log, and a nonce row is what makes a signed
 * request non-replayable. NF-5 §5's NT-004 asks for a persistent-state digest that is unchanged
 * across a refusal, and the property it is protecting is stated in its own rationale: "a
 * rejection that still writes a row has created a record of an owner's forbidden-class
 * request". That property is asserted directly in `protocol.test.js` — the audit row written on
 * a forbidden-field refusal is read back and shown to name neither the offending identifier nor
 * the owner — rather than by a digest that would fail for the wrong reason.
 */
const CONSENT_STATE_TABLES = Object.freeze([
  'consent_grant',
  'revocation',
  'revocation_kill_switch',
  'owner_signing_key',
  'operator_held_key_id',
  'owner_revocation_key',
  'pseudonym_salt',
  'vehicle_enrolment',
  'delegation_edge',
])

/**
 * A digest over the consent-bearing state. Row order is normalised by sorting the canonical
 * form of each row, so the digest is a function of CONTENT and not of insertion order.
 */
export async function consentStateDigest(harness) {
  const dump = []
  for (const table of CONSENT_STATE_TABLES) {
    const rows = harness.db
      .prepare(`SELECT * FROM ${table}`) // eslint-disable-line no-template-curly-in-string
      .all()
      .map((row) => JSON.stringify(Object.fromEntries(Object.entries({ ...row }).sort(([a], [b]) => compareCodeUnits(a, b)))))
      .sort(compareCodeUnits)
    dump.push([table, rows])
  }
  return sha256Base64url(JSON.stringify(dump))
}

/**
 * Read the audit log back.
 *
 * The table name is a constant in this file and no value from a test ever reaches the SQL, so
 * this is not an interpolation the §4.3 bound-parameter rule is about; there is no parameter to
 * bind. Every statement in this file that takes a value takes it as a bound parameter.
 */
export function auditRows(harness) {
  return harness.db.prepare('SELECT * FROM audit_log ORDER BY rowid').all().map((row) => ({ ...row }))
}

/** Count rows in one consent table, for the "nothing was persisted" half of a refusal. */
export function countRows(harness, table) {
  if (!CONSENT_STATE_TABLES.includes(table)) throw new Error(`countRows: ${table} is not a consent-state table`)
  const row = harness.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()
  return Number(row.n)
}

/** Close the underlying database. Called from an `after()` hook so nothing leaks between files. */
export function closeHarness(harness) {
  harness.db.close()
}
