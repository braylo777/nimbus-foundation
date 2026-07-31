/**
 * NF-5 conformance — NF-3 resolution (`broker/src/nf3-resolve.js`).
 *
 * NF-WP-1 §8.3, §10.1 Refusal 1. The VIN is a public name and resolution is DNS: it returns
 * WHERE to ask for authorisation and never authorisation itself. Resolving `example.com` to
 * an address grants no right to anything at that address, and NF-3 inherits that property
 * deliberately rather than incidentally.
 *
 * The suite is organised around what can actually go wrong here:
 *
 *   REFUSAL 1   no exported function, on any input, yields a token, credential, session,
 *               bearer value, key material or an authorisation decision — asserted over the
 *               whole export surface, not over a sample.
 *   NAMES       a malformed VIN is refused before a packet is sent.
 *   AUTHENTICITY  a forged, unsigned, re-aimed, replayed or wrong-key answer is refused, and
 *               a failed validation is terminal — no fallback, because "try somewhere else"
 *               hands the attacker the choice of replacement (the Kaminsky lesson).
 *   CACHING     TTL floors and ceilings, negative answers cached strictly shorter than
 *               positive ones, TTL counted down rather than re-served, and a poisoned cache
 *               row failing exactly like a poisoned packet.
 *   TOPOLOGY    zone delegation grammar, bailiwick, hop bound, loop detection.
 *
 * Determinism (NF-5 §4.4): `globalThis.fetch` is replaced with a detonator for the whole
 * file, every zone answer is minted locally, D1 is an in-memory stub, and every instant is
 * injected. A test that reaches the network fails loudly instead of flaking.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import * as nf3 from '../../broker/src/nf3-resolve.js'
import {
  MAX_REFERRAL_HOPS,
  NF3_ANSWER_KEYS,
  NF3_ANSWER_VERSION,
  NF3_CACHE_SCHEMA_SQL,
  NF3_ENDPOINT_KEYS,
  NF3_FORBIDDEN_KEY_NAMES,
  NF3_NO_CREDENTIAL_INVARIANT,
  NF3_RECORD_KEYS,
  NF3_RECORD_TYPES,
  NF3_RESULT_KEYS,
  NF3_STATUSES,
  NF3_TTL_POLICY,
  assertNoCredentialSurface,
  assertResolutionReturnsLocationsOnly,
  buildAnswer,
  clampTtl,
  generateQueryNonce,
  httpZoneTransport,
  loadTrustAnchors,
  makeConsentEndpointRecord,
  makeDelegationRecord,
  makeNegativeRecord,
  makeQuestion,
  makeZone,
  purgeResolutionCache,
  qnameDigest,
  resolveVin,
  signResolutionAnswer,
  sweepResolutionCache,
  validateEndpointUrl,
  verifyResolutionAnswer,
  zoneFromId,
  zoneKeyIdFromBase64url,
} from '../../broker/src/nf3-resolve.js'

import { exportPublicKeyBase64url, generateSigningKeyPair } from '../../broker/src/nf2-grant.js'
import { base64url } from '../../broker/src/vin.js'
import { FIELD_CLASSES, NON_TRANSACTABLE } from '../../broker/src/fields.js'

// ---------------------------------------------------------------------------------
// Hermetic environment
// ---------------------------------------------------------------------------------

/** Any outbound request is a bug in the suite, not a slow test. */
globalThis.fetch = () => {
  throw new Error('NF-5 §4.4: the conformance suite makes no network requests')
}

const T0 = 1_800_000_000
const VIN = '1HGCM82633A004352' // WMI 1HG, valid ISO 3779 check digit
const OTHER_VIN = 'JH4KA7561PC008269'

const ROOT_EP = 'https://root.zone.example/nf3'
const WMI_EP = 'https://wmi.zone.example/nf3'
const OP_EP = 'https://operator.zone.example/nf3'
const BROKER_EP = 'https://consent.broker.example/nf3'
const EVIL_EP = 'https://attacker.example/nf3'

const rootKeys = await generateSigningKeyPair()
const wmiKeys = await generateSigningKeyPair()
const opKeys = await generateSigningKeyPair()
const evilKeys = await generateSigningKeyPair()
const brokerKeys = await generateSigningKeyPair()

const rootPub = await exportPublicKeyBase64url(rootKeys.publicKey)
const wmiPub = await exportPublicKeyBase64url(wmiKeys.publicKey)
const opPub = await exportPublicKeyBase64url(opKeys.publicKey)
const evilPub = await exportPublicKeyBase64url(evilKeys.publicKey)
const brokerPub = await exportPublicKeyBase64url(brokerKeys.publicKey)

const ROOT_ZONE = makeZone('root')
const WMI_ZONE = makeZone('wmi', '1HG')
const OP_ZONE = makeZone('operator', 'acme-fleet')

const FIELD_CLASS_IDS = ['build_specification', 'diagnostics', 'usage']

const ANCHORS = { root: { endpoint: ROOT_EP, key: rootPub } }

const ceRecord = (over = {}) =>
  makeConsentEndpointRecord({
    endpoint: over.endpoint ?? BROKER_EP,
    protocolVersion: over.protocolVersion ?? 'nf3-endpoint/1',
    supportedFieldClasses: over.supportedFieldClasses ?? FIELD_CLASS_IDS,
    brokerKey: over.brokerKey ?? brokerPub,
  })

const delegationRecord = (childZone, childZoneKey, childEndpoint) =>
  makeDelegationRecord({ childZone, childZoneKey, childEndpoint })

/** Mint a signed answer as `zone`, echoing the question's nonce. */
async function answerAs(zone, keys, publicKey, record, question, over = {}) {
  const unsigned = buildAnswer({
    qnameDigest: over.qnameDigest ?? question.qname_digest,
    nonce: over.nonce ?? question.nonce,
    zone,
    record,
    ttl: over.ttl ?? 300,
    answeredAt: over.answeredAt ?? T0,
  })
  return signResolutionAnswer(unsigned, keys.privateKey, publicKey)
}

/**
 * An in-memory D1 binding. Dispatches on the statement text the module actually issues, and
 * refuses anything it does not recognise so a silently unexercised cache cannot pass as a
 * working one. Every call goes through bound parameters, as I-4 requires.
 */
function makeD1() {
  const rows = new Map()
  const binding = {
    rows,
    reads: 0,
    writes: 0,
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async first() {
              if (!sql.startsWith('SELECT answer_json')) throw new Error(`unexpected SELECT: ${sql}`)
              binding.reads += 1
              const [digest, now] = params
              const row = rows.get(digest)
              return row && row.expires_at > now ? { ...row } : null
            },
            async run() {
              if (sql.startsWith('INSERT INTO nf3_resolution_cache')) {
                binding.writes += 1
                const [qname, recordType, zoneId, zoneKey, answerJson, chainJson, cachedAt, expiresAt] = params
                rows.set(qname, {
                  qname_digest: qname,
                  record_type: recordType,
                  zone_id: zoneId,
                  zone_key: zoneKey,
                  answer_json: answerJson,
                  chain_json: chainJson,
                  cached_at: cachedAt,
                  expires_at: expiresAt,
                })
                return { meta: { changes: 1 } }
              }
              if (sql.startsWith('DELETE FROM nf3_resolution_cache WHERE qname_digest')) {
                return { meta: { changes: rows.delete(params[0]) ? 1 : 0 } }
              }
              if (sql.startsWith('DELETE FROM nf3_resolution_cache WHERE expires_at')) {
                let n = 0
                for (const [k, v] of [...rows]) {
                  if (v.expires_at <= params[0]) {
                    rows.delete(k)
                    n += 1
                  }
                }
                return { meta: { changes: n } }
              }
              throw new Error(`unexpected statement: ${sql}`)
            },
          }
        },
      }
    },
  }
  return binding
}

/** A transport over a map of endpoint -> handler(question, zone). Counts every call. */
function makeTransport(handlers) {
  const calls = []
  const transport = async (endpoint, question, opts) => {
    calls.push({ endpoint, question, zone: opts?.zone ?? null })
    const handler = handlers[endpoint]
    if (!handler) return { ok: false, answer: null, reason: `no zone at ${endpoint}` }
    return handler(question, opts?.zone ?? null)
  }
  transport.calls = calls
  return transport
}

/** The happy path: root -> wmi -> operator -> consent endpoint. */
function fullChainHandlers(over = {}) {
  return {
    [ROOT_EP]: async (q) => ({
      ok: true,
      answer: await answerAs(ROOT_ZONE, rootKeys, rootPub, delegationRecord(WMI_ZONE, wmiPub, WMI_EP), q, {
        ttl: over.referralTtl ?? 3600,
        answeredAt: over.answeredAt ?? T0,
      }),
      reason: null,
    }),
    [WMI_EP]: async (q) => ({
      ok: true,
      answer: await answerAs(WMI_ZONE, wmiKeys, wmiPub, delegationRecord(OP_ZONE, opPub, OP_EP), q, {
        ttl: over.referralTtl ?? 3600,
        answeredAt: over.answeredAt ?? T0,
      }),
      reason: null,
    }),
    [OP_EP]: async (q) => ({
      ok: true,
      answer: await answerAs(OP_ZONE, opKeys, opPub, over.terminal ?? ceRecord(), q, {
        ttl: over.ttl ?? 300,
        answeredAt: over.answeredAt ?? T0,
      }),
      reason: null,
    }),
  }
}

const resolveOpts = (over = {}) => ({
  now: T0,
  trustAnchors: ANCHORS,
  ...over,
})

// =================================================================================
// REFUSAL 1 — resolution returns a location, never authority
// =================================================================================

test('[control] the happy path resolves a VIN to a LOCATION and nothing more', async () => {
  const transport = makeTransport(fullChainHandlers())
  const result = await resolveVin(VIN, {}, resolveOpts({ transport }))

  assert.equal(result.status, 'resolved', result.reasons.join('; '))
  assert.equal(result.authenticated, true)
  assert.equal(result.endpoint.url, BROKER_EP)
  assert.equal(result.endpoint.protocol_version, 'nf3-endpoint/1')
  assert.equal(result.endpoint.broker_key, brokerPub)
  assert.deepEqual([...result.endpoint.supported_field_classes], FIELD_CLASS_IDS)
  assert.equal(transport.calls.length, 3)

  // The endpoint sub-object is a location: a URL, a protocol version, an advertised
  // capability list and a PUBLIC verification key. Nothing that opens anything.
  assert.deepEqual(Object.keys(result.endpoint).sort(), [...NF3_ENDPOINT_KEYS].sort())
  assert.equal(assertResolutionReturnsLocationsOnly(result), true)

  // Possession of the answer confers nothing: there is no grant, no token, no decision.
  const serialized = JSON.stringify(result)
  for (const forbidden of ['token', 'credential', 'session', 'cookie', 'bearer', 'authorization', 'decision']) {
    assert.ok(!serialized.toLowerCase().includes(`"${forbidden}"`), `result must carry no "${forbidden}" member`)
  }
  assert.ok(!serialized.includes(VIN), 'the VIN is not echoed into the result or its logs')
})

test('no export, on any input, returns a credential, a session or an authorisation decision', async () => {
  // Refusal 1 asserted over the WHOLE export surface rather than a sample, because the
  // convenience field gets added to the path nobody tested.
  const transport = makeTransport(fullChainHandlers())
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const goodAnswer = await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), question)

  const argMatrix = [
    [],
    [VIN],
    [VIN, {}],
    [VIN, {}, resolveOpts({ transport })],
    [VIN, {}, resolveOpts({ transport, mode: 'iterative' })],
    [goodAnswer],
    [goodAnswer, { vin: VIN, expectedZone: OP_ZONE, zonePublicKey: opPub, expectedNonce: question.nonce, now: T0 }],
    [goodAnswer, { vin: VIN, expectedZone: OP_ZONE, zonePublicKey: evilPub, now: T0 }],
    [ceRecord()],
    [{ token: 'secret' }],
    [null],
    [undefined],
    ['Bearer abcdefghijklmnop'],
    [300, 'ce'],
    [BROKER_EP],
    [BROKER_EP, { allowInsecureLoopback: true }],
    [{ NF3_TRUST_ANCHORS: ANCHORS }, {}],
    ['root'],
    [ROOT_ZONE, opPub],
    [opPub],
  ]

  let called = 0
  for (const [name, value] of Object.entries(nf3)) {
    if (typeof value !== 'function') {
      assert.equal(assertNoCredentialSurface(value, name), true, `${name} exports a credential-shaped constant`)
      continue
    }
    for (const args of argMatrix) {
      let out
      try {
        out = await value(...args)
      } catch {
        continue // a refusal is a perfectly good answer; it is not a credential
      }
      called += 1
      assert.equal(assertNoCredentialSurface(out, `${name}(...)`), true, `${name} returned a credential surface`)
      if (out !== null && typeof out === 'object' && !Array.isArray(out)) {
        for (const key of Object.keys(out)) {
          assert.doesNotMatch(
            key,
            /^(authoriz|authoris|allow|deny|permit|granted|decision|token|secret)/i,
            `${name} returned a decision-shaped member "${key}"`,
          )
        }
      }
    }
  }
  assert.ok(called > 20, 'the export sweep must actually have called things')
})

test('the no-credential invariant is enumerated, not merely asserted in a comment', () => {
  assert.equal(NF3_NO_CREDENTIAL_INVARIANT.id, 'NF3-REFUSAL-1')
  assert.deepEqual(NF3_NO_CREDENTIAL_INVARIANT.forbidden_key_names, NF3_FORBIDDEN_KEY_NAMES)
  assert.deepEqual(NF3_NO_CREDENTIAL_INVARIANT.result_keys, NF3_RESULT_KEYS)
  assert.deepEqual(NF3_NO_CREDENTIAL_INVARIANT.endpoint_keys, NF3_ENDPOINT_KEYS)
  assert.deepEqual(NF3_NO_CREDENTIAL_INVARIANT.answer_keys, NF3_ANSWER_KEYS)

  for (const name of ['token', 'bearer', 'authorization', 'credential', 'session', 'cookie', 'apikey', 'jwt', 'decision']) {
    assert.ok(NF3_FORBIDDEN_KEY_NAMES.includes(name), `"${name}" must be enumerated`)
  }
  // The key sets are closed and disjoint from the forbidden names.
  const normalize = (k) => k.toLowerCase().replace(/[-_\s]/g, '')
  for (const key of [...NF3_RESULT_KEYS, ...NF3_ENDPOINT_KEYS, ...NF3_ANSWER_KEYS]) {
    assert.ok(!NF3_FORBIDDEN_KEY_NAMES.includes(normalize(key)))
  }
  assert.deepEqual(NF3_RECORD_TYPES, ['ce', 'delegation', 'nxenroll', 'nxzone'])
  assert.deepEqual([...NF3_STATUSES], ['resolved', 'not-enrolled', 'no-zone', 'referral', 'error'])
})

test('assertNoCredentialSurface catches names and shapes, however spelled or nested', () => {
  for (const key of ['token', 'Access-Token', 'access_token', 'accessToken', 'Set-Cookie', 'setCookie', 'apiKey', 'JWT']) {
    assert.throws(() => assertNoCredentialSurface({ [key]: 'x' }), /REFUSAL 1 VIOLATION/, `key "${key}"`)
  }
  assert.throws(() => assertNoCredentialSurface({ a: { b: [{ session_id: 'x' }] } }), /REFUSAL 1 VIOLATION/)
  for (const value of [
    'Bearer eyJhbGciOiJIUzI1NiJ9',
    'basic YWxhZGRpbjpvcGVuc2VzYW1l',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig',
  ]) {
    assert.throws(() => assertNoCredentialSurface({ note: value }), /credential/i, `value "${value}"`)
  }
  // Public verification keys and digests are not credentials and must not trip it.
  assert.equal(assertNoCredentialSurface({ broker_key: brokerPub, child_zone_key: wmiPub, signature: 'ey' + 'A'.repeat(60) }), true)
})

test('a resolution result may not carry an unverified location or an unknown member', () => {
  const good = {
    v: 'nf3-resolution/1',
    status: 'resolved',
    qname_digest: null,
    vin_syntax: null,
    endpoint: { url: BROKER_EP, protocol_version: 'nf3-endpoint/1', supported_field_classes: [], broker_key: brokerPub, zone: OP_ZONE },
    referral: null,
    authenticated: true,
    ttl_remaining_s: null,
    expires_at: null,
    source: null,
    chain: [],
    reasons: [],
    notes: [],
  }
  assert.equal(assertResolutionReturnsLocationsOnly(good), true)

  assert.throws(
    () => assertResolutionReturnsLocationsOnly({ ...good, authenticated: false }),
    /cache-poisoning primitive/,
    'an unauthenticated result must never carry an endpoint',
  )
  assert.throws(() => assertResolutionReturnsLocationsOnly({ ...good, access_token: 'x' }), /unknown key/)
  assert.throws(() => assertResolutionReturnsLocationsOnly({ ...good, status: 'authorized' }), /outside the closed set/)
  assert.throws(() => assertResolutionReturnsLocationsOnly({ ...good, endpoint: { ...good.endpoint, token: 'x' } }), /unknown key/)
  const { chain, ...missing } = good
  assert.throws(() => assertResolutionReturnsLocationsOnly(missing), /missing "chain"/)
})

test('a zone cannot smuggle authority through a location: the URL grammar forbids all three', () => {
  assert.equal(validateEndpointUrl(BROKER_EP).ok, true)
  assert.equal(validateEndpointUrl('https://host.example/path/to/endpoint').ok, true)

  const cases = [
    ['https://s3.example/obj?X-Amz-Signature=deadbeef', /query string/],
    ['https://idp.example/cb#access_token=abc', /fragment/],
    ['https://user:pass@host.example/', /userinfo/],
    ['https://evil.example@good.example/', /userinfo/],
    ['http://host.example/', /scheme must be https/],
    ['https://169.254.169.254/latest/meta-data/', /SSRF/],
    ['https://localhost/nf3', /SSRF/],
    ['https://127.0.0.1/nf3', /SSRF/],
    ['https://10.0.0.1/nf3', /SSRF/],
    ['https://192.168.1.1/nf3', /SSRF/],
    ['https://consul.internal/nf3', /SSRF/],
    ['https://printer.local/nf3', /SSRF/],
    [' https://host.example/', /whitespace|parseable/],
    ['https://host.example/ ', /whitespace/],
    ['not a url', /parseable/],
    ['', /non-empty/],
    [null, /non-empty/],
    [42, /non-empty/],
    [`https://host.example/${'a'.repeat(600)}`, /exceeds/],
    ['https://xn--e1awd7f.example/', null], // punycode host is ASCII after parsing: permitted
  ]
  for (const [url, pattern] of cases) {
    const verdict = validateEndpointUrl(url)
    if (pattern === null) {
      assert.equal(verdict.ok, true, `${url} should parse`)
      continue
    }
    assert.equal(verdict.ok, false, `${url} must be refused`)
    assert.equal(verdict.url, null)
    assert.match(verdict.reason, pattern)
  }

  // Loopback is reachable only under an explicit opt-in, never by default.
  assert.equal(validateEndpointUrl('http://127.0.0.1:8787/nf3').ok, false)
  assert.equal(validateEndpointUrl('http://127.0.0.1:8787/nf3', { allowInsecureLoopback: true }).ok, true)

  // And the grammar is enforced at record construction, not only at verification.
  assert.throws(() => ceRecord({ endpoint: 'https://s3.example/o?sig=x' }), /query string/)
  assert.throws(() => makeDelegationRecord({ childZone: OP_ZONE, childZoneKey: opPub, childEndpoint: 'https://a@b.example/' }), /userinfo/)
})

test('a broker cannot advertise a class the vocabulary does not contain', async () => {
  assert.throws(() => ceRecord({ supportedFieldClasses: ['precise_geolocation'] }), /non-transactable|not an NF-2 field class/)
  for (const forbidden of NON_TRANSACTABLE.slice(0, 6)) {
    assert.throws(() => ceRecord({ supportedFieldClasses: [forbidden] }))
  }
  assert.throws(() => ceRecord({ supportedFieldClasses: ['telemetry_blob'] }), /not an NF-2 field class/)
  assert.throws(() => ceRecord({ supportedFieldClasses: [] }), /non-empty/)
  assert.throws(() => ceRecord({ supportedFieldClasses: ['usage', 'usage'] }), /duplicate/)
  assert.equal(ceRecord({ supportedFieldClasses: Object.keys(FIELD_CLASSES).sort() }).type, 'ce')

  // The zone-side constructor canonicalises the order (a class list is a set, so sorting
  // changes nothing an owner reads) — but the WIRE form must be sorted, because JCS treats
  // array order as significant and an unsorted list would give one semantic record two
  // signing inputs and two cache identities. So the verifier refuses it.
  assert.deepEqual([...ceRecord({ supportedFieldClasses: ['usage', 'diagnostics'] }).supported_field_classes], ['diagnostics', 'usage'])
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const unsorted = {
    v: NF3_ANSWER_VERSION,
    qname_digest: question.qname_digest,
    zone: OP_ZONE,
    record: { ...ceRecord(), supported_field_classes: ['usage', 'diagnostics'] },
    ttl: 300,
    answered_at: T0,
    nonce: question.nonce,
    signer_key_id: null,
    signature: null,
  }
  const signed = await signResolutionAnswer(unsorted, opKeys.privateKey, opPub)
  const verdict = await verifyResolutionAnswer(signed, {
    vin: VIN,
    expectedZone: OP_ZONE,
    zonePublicKey: opPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('field_class_invalid')))
})

// =================================================================================
// NAMES — a malformed VIN never reaches the network
// =================================================================================

test('a malformed VIN is refused before any query is made', async () => {
  const transport = makeTransport(fullChainHandlers())
  const malformed = ['', 'SHORT', '1HGCM82633A00435', '1HGCM82633A0043521', '1IGCM82633A004352', '1OGCM82633A004352', '1QGCM82633A004352', '1HGCM82633A00435 ', null, undefined, 42, {}, []]

  for (const bad of malformed) {
    const result = await resolveVin(bad, {}, resolveOpts({ transport }))
    assert.equal(result.status, 'error', `"${String(bad)}" must not resolve`)
    assert.equal(result.endpoint, null)
    assert.equal(result.authenticated, false)
    assert.ok(result.reasons.some((r) => r.startsWith('vin_invalid')), result.reasons.join('; '))
    assert.equal(assertResolutionReturnsLocationsOnly(result), true)
  }
  assert.equal(transport.calls.length, 0, 'a resolver that queries on unvalidated input is a proxy for a typo')
})

test('syntax and check digit are reported separately, and strictness is the caller\'s call', async () => {
  const transport = makeTransport(fullChainHandlers())
  const badCheckDigit = '1HGCM82633A004353'

  const strict = await resolveVin(badCheckDigit, {}, resolveOpts({ transport }))
  assert.equal(strict.status, 'error')
  assert.ok(strict.reasons.some((r) => r.startsWith('vin_check_digit')))
  assert.equal(strict.vin_syntax.syntax_valid, true, 'SEC-8: syntax and check digit are not one boolean')
  assert.equal(strict.vin_syntax.check_digit_valid, false)
  assert.equal(strict.vin_syntax.strict, true)
  assert.equal(transport.calls.length, 0)

  const lenient = await resolveVin(badCheckDigit, {}, resolveOpts({ transport, strictCheckDigit: false }))
  assert.equal(lenient.vin_syntax.strict, false)
  assert.ok(transport.calls.length > 0, 'a structurally valid grey-market VIN is resolvable on request')

  // The wire name is a digest of the VIN, never the VIN.
  const digest = await qnameDigest(VIN)
  assert.equal(digest.length, 43)
  assert.notEqual(digest, await qnameDigest(OTHER_VIN))
  assert.equal(digest, await qnameDigest(` ${VIN.toLowerCase()} `), 'normalised before digesting')
  await assert.rejects(() => qnameDigest('nonsense'), /malformed VIN/)
})

// =================================================================================
// AUTHENTICITY — the cache-poisoning threat
// =================================================================================

test('an unsigned answer authenticates nothing', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const unsigned = buildAnswer({
    qnameDigest: question.qname_digest,
    nonce: question.nonce,
    zone: OP_ZONE,
    record: ceRecord(),
    ttl: 300,
    answeredAt: T0,
  })
  const verdict = await verifyResolutionAnswer(unsigned, {
    vin: VIN,
    expectedZone: OP_ZONE,
    zonePublicKey: opPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('signature_missing')))

  const transport = makeTransport({ [ROOT_EP]: async () => ({ ok: true, answer: unsigned, reason: null }) })
  const result = await resolveVin(VIN, {}, resolveOpts({ transport }))
  assert.equal(result.status, 'error')
  assert.equal(result.endpoint, null)
})

test('an answer signed by the wrong key, or naming another signer, is refused', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())

  // Forged by an attacker who holds a perfectly good Ed25519 key — just not the zone's.
  const forged = await answerAs(OP_ZONE, evilKeys, evilPub, ceRecord({ endpoint: EVIL_EP }), question)
  const verdict = await verifyResolutionAnswer(forged, {
    vin: VIN,
    expectedZone: OP_ZONE,
    zonePublicKey: opPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('signer_key_id_mismatch')))

  // Signed by the right key but with the signer_key_id swapped: the id is inside the bytes.
  const good = await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), question)
  const relabelled = { ...good, signer_key_id: await zoneKeyIdFromBase64url(evilPub) }
  const relabelledVerdict = await verifyResolutionAnswer(relabelled, {
    vin: VIN,
    expectedZone: OP_ZONE,
    zonePublicKey: evilPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(relabelledVerdict.valid, false)
  assert.ok(relabelledVerdict.reasons.some((r) => r.startsWith('signature_invalid')))

  // No verifying key supplied at all is a refusal, not a pass.
  const noKey = await verifyResolutionAnswer(good, {
    vin: VIN,
    expectedZone: OP_ZONE,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(noKey.valid, false)
  assert.ok(noKey.reasons.some((r) => r.startsWith('verifier_key_missing')))
})

test('every field of a signed answer is inside the signature', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const good = await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), question, { ttl: 300 })
  const base = { vin: VIN, expectedZone: OP_ZONE, zonePublicKey: opPub, expectedNonce: question.nonce, now: T0 }

  assert.equal((await verifyResolutionAnswer(good, base)).valid, true, 'positive control')

  const tampered = [
    { ...good, record: { ...good.record, endpoint: EVIL_EP } },
    { ...good, record: { ...good.record, broker_key: evilPub } },
    { ...good, ttl: 3600 },
    { ...good, answered_at: T0 - 1 },
  ]
  for (const answer of tampered) {
    const verdict = await verifyResolutionAnswer(answer, base)
    assert.equal(verdict.valid, false)
    assert.ok(
      verdict.reasons.some((r) => r.startsWith('signature_invalid')),
      `editing a signed field must fail as signature_invalid: ${verdict.reasons.join('; ')}`,
    )
  }
})

test('an answer cannot be re-aimed at another name or replayed against another query', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const answer = await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), question)

  // The bailiwick rule, cryptographically enforced: the question is inside the signature.
  const reaimed = await verifyResolutionAnswer(answer, {
    vin: OTHER_VIN,
    expectedZone: OP_ZONE,
    zonePublicKey: opPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(reaimed.valid, false)
  assert.ok(reaimed.reasons.some((r) => r.startsWith('qname_mismatch')))

  // The Kaminsky gap DNSSEC leaves open: a validly signed OLD answer, replayed.
  const replayed = await verifyResolutionAnswer(answer, {
    vin: VIN,
    expectedZone: OP_ZONE,
    zonePublicKey: opPub,
    expectedNonce: generateQueryNonce(),
    now: T0,
  })
  assert.equal(replayed.valid, false)
  assert.ok(replayed.reasons.some((r) => r.startsWith('nonce_mismatch')))

  const noNonce = await verifyResolutionAnswer(answer, {
    vin: VIN,
    expectedZone: OP_ZONE,
    zonePublicKey: opPub,
    now: T0,
  })
  assert.equal(noNonce.valid, false)
  assert.ok(noNonce.reasons.some((r) => r.startsWith('nonce_missing')))

  // A zone may not answer as another zone even with a valid signature of its own.
  const asOther = await verifyResolutionAnswer(answer, {
    vin: VIN,
    expectedZone: WMI_ZONE,
    zonePublicKey: opPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(asOther.valid, false)
  assert.ok(asOther.reasons.some((r) => r.startsWith('zone_mismatch')))
})

test('answer freshness is bounded independently of the TTL', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const base = { vin: VIN, expectedZone: OP_ZONE, zonePublicKey: opPub, expectedNonce: question.nonce, clockSkewS: 0 }

  const answer = await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), question, { answeredAt: T0 })
  assert.equal((await verifyResolutionAnswer(answer, { ...base, now: T0 + 60 })).valid, true)

  const stale = await verifyResolutionAnswer(answer, { ...base, now: T0 + 61 })
  assert.equal(stale.valid, false)
  assert.ok(stale.reasons.some((r) => r.startsWith('answer_stale')))

  const future = await verifyResolutionAnswer(answer, { ...base, now: T0 - 1 })
  assert.equal(future.valid, false)
  assert.ok(future.reasons.some((r) => r.startsWith('answer_future')))

  // SEC-11: a millisecond timestamp is a well-formed integer and only a range test catches it.
  assert.throws(
    () => buildAnswer({ qnameDigest: question.qname_digest, nonce: question.nonce, zone: OP_ZONE, record: ceRecord(), ttl: 300, answeredAt: T0 * 1000 }),
    /Unix SECONDS/,
  )
  const msAnswer = { ...answer, answered_at: T0 * 1000 }
  const msVerdict = await verifyResolutionAnswer(msAnswer, { ...base, now: T0 })
  assert.equal(msVerdict.valid, false)
  assert.ok(msVerdict.reasons.some((r) => r.startsWith('time_implausible')))
})

test('an answer carrying an unknown or missing member is refused, not tolerated', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const good = await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), question)
  const base = { vin: VIN, expectedZone: OP_ZONE, zonePublicKey: opPub, expectedNonce: question.nonce, now: T0 }

  const extra = await verifyResolutionAnswer({ ...good, access_token: 'x' }, base)
  assert.equal(extra.valid, false)
  assert.ok(extra.reasons.some((r) => r.startsWith('unknown_field')))

  const { nonce, ...omitted } = good
  const missing = await verifyResolutionAnswer(omitted, base)
  assert.equal(missing.valid, false)
  assert.ok(missing.reasons.some((r) => r.startsWith('missing_field')))

  const downgraded = await verifyResolutionAnswer({ ...good, v: 'nf3-answer/0' }, base)
  assert.equal(downgraded.valid, false)
  assert.ok(downgraded.reasons.some((r) => r.startsWith('version_unsupported')))

  // A record carrying a credential-shaped member is refused twice over.
  const smuggled = await verifyResolutionAnswer({ ...good, record: { ...good.record, session_token: 'x' } }, base)
  assert.equal(smuggled.valid, false)
  assert.ok(smuggled.reasons.some((r) => r.startsWith('unknown_field') || r.startsWith('credential_surface')))
})

test('verifyResolutionAnswer never throws, whatever a hostile zone sends', async () => {
  const base = { vin: VIN, expectedZone: OP_ZONE, zonePublicKey: opPub, expectedNonce: generateQueryNonce(), now: T0 }
  const hostile = [
    null,
    undefined,
    42,
    'string',
    [],
    {},
    { v: NF3_ANSWER_VERSION },
    { __proto__: null },
    { v: NF3_ANSWER_VERSION, qname_digest: 1, zone: 1, record: 1, ttl: 'x', answered_at: 'x', nonce: 1, signer_key_id: 1, signature: 1 },
    { v: NF3_ANSWER_VERSION, qname_digest: await qnameDigest(VIN), zone: { id: 'wmi:ZZZ', scope_type: 'wmi', scope: 'ZZZ' }, record: { type: 'ce' }, ttl: -1, answered_at: T0, nonce: generateQueryNonce(), signer_key_id: null, signature: null },
    { v: NF3_ANSWER_VERSION, qname_digest: await qnameDigest(VIN), zone: ROOT_ZONE, record: { type: 'nope' }, ttl: 1, answered_at: T0, nonce: generateQueryNonce(), signer_key_id: null, signature: null },
  ]
  for (const answer of hostile) {
    const verdict = await verifyResolutionAnswer(answer, base)
    assert.equal(verdict.valid, false)
    assert.ok(verdict.reasons.length > 0)
  }
  // ...and with hostile options too.
  for (const opts of [undefined, {}, { vin: 42 }, { vin: VIN }, { vin: VIN, expectedZone: 'root' }]) {
    const verdict = await verifyResolutionAnswer(hostile[6], opts)
    assert.equal(verdict.valid, false)
  }
})

test('a failed validation is terminal: the resolver does not shop for a second opinion', async () => {
  let opCalls = 0
  const transport = makeTransport({
    ...fullChainHandlers(),
    [OP_EP]: async (q) => {
      opCalls += 1
      // A hostile operator zone: correctly shaped, signed by the wrong key.
      return { ok: true, answer: await answerAs(OP_ZONE, evilKeys, evilPub, ceRecord({ endpoint: EVIL_EP }), q), reason: null }
    },
  })
  const result = await resolveVin(VIN, {}, resolveOpts({ transport }))

  assert.equal(result.status, 'error')
  assert.equal(result.endpoint, null)
  assert.equal(result.authenticated, false)
  assert.ok(result.reasons.every((r) => r.startsWith('answer_rejected(operator:acme-fleet)')))
  assert.equal(opCalls, 1, 'no retry, no fallback: the attacker does not get to pick the replacement')
  assert.equal(transport.calls.length, 3)
})

test('a zone that is unreachable or answers garbage produces an error, never a location', async () => {
  const cases = [
    { ok: false, answer: null, reason: 'zone unreachable' },
    { ok: true, answer: null, reason: null },
    { ok: true, answer: 'not an object', reason: null },
    undefined,
  ]
  for (const wire of cases) {
    const transport = makeTransport({ [ROOT_EP]: async () => wire })
    const result = await resolveVin(VIN, {}, resolveOpts({ transport }))
    assert.equal(result.status, 'error')
    assert.equal(result.endpoint, null)
    assert.equal(assertResolutionReturnsLocationsOnly(result), true)
  }
})

test('resolution refuses outright when it has no trust anchor: there is no insecure mode', async () => {
  const transport = makeTransport(fullChainHandlers())

  const noAnchors = await resolveVin(VIN, {}, { now: T0, transport })
  assert.equal(noAnchors.status, 'error')
  assert.ok(noAnchors.reasons.some((r) => r.startsWith('no_trust_anchor')))
  assert.equal(transport.calls.length, 0, 'no anchor, no packet')

  const badAnchors = await resolveVin(VIN, { NF3_TRUST_ANCHORS: '{not json' }, { now: T0, transport })
  assert.equal(badAnchors.status, 'error')
  assert.ok(badAnchors.reasons.some((r) => r.startsWith('anchor_invalid')))
  assert.equal(transport.calls.length, 0)
})

test('configuration anchors win over caller-supplied ones', () => {
  const env = { NF3_TRUST_ANCHORS: JSON.stringify({ root: { endpoint: ROOT_EP, key: rootPub } }) }
  const anchors = loadTrustAnchors(env, { trustAnchors: { root: { endpoint: EVIL_EP, key: evilPub } } })
  assert.equal(anchors.get('root').key, rootPub, 'an attacker-influenced option must not replace the root of trust')
  assert.equal(anchors.get('root').endpoint, ROOT_EP)

  // Malformed anchors are dropped rather than half-trusted.
  const junk = loadTrustAnchors({}, {
    trustAnchors: {
      root: { endpoint: ROOT_EP, key: 'short' },
      'wmi:1HG': { endpoint: 'http://insecure.example/', key: wmiPub },
      'wmi:lower': { endpoint: WMI_EP, key: wmiPub },
      'not a zone id': { endpoint: WMI_EP, key: wmiPub },
      'operator:acme-fleet': { endpoint: OP_EP, key: opPub },
    },
  })
  assert.deepEqual([...junk.keys()], ['operator:acme-fleet'])

  assert.equal(zoneFromId('root').id, 'root')
  assert.equal(zoneFromId('wmi:1HG').scope, '1HG')
  for (const bad of ['wmi:1hg', 'root:x', 'wmi', 'nonsense', 'operator:', '', null, 'wmi:TOOLONG']) {
    assert.equal(zoneFromId(bad), null, `"${String(bad)}" is not a canonical zone id`)
  }
})

// =================================================================================
// TOPOLOGY — delegation, bailiwick, hops, loops
// =================================================================================

test('zone answer policy: nobody answers outside their role', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())

  // The root answering a `ce` directly would be the root operating the market it governs.
  assert.throws(
    () => buildAnswer({ qnameDigest: question.qname_digest, nonce: question.nonce, zone: ROOT_ZONE, record: ceRecord(), ttl: 300, answeredAt: T0 }),
    /root zone may not answer with a "ce" record/,
  )
  // An operator answering a delegation would extend a per-name claim into a standing one.
  assert.throws(
    () => buildAnswer({ qnameDigest: question.qname_digest, nonce: question.nonce, zone: OP_ZONE, record: delegationRecord(WMI_ZONE, wmiPub, WMI_EP), ttl: 300, answeredAt: T0 }),
    /operator zone may not answer with a "delegation" record/,
  )
  assert.throws(
    () => buildAnswer({ qnameDigest: question.qname_digest, nonce: question.nonce, zone: ROOT_ZONE, record: makeNegativeRecord('nxenroll'), ttl: 30, answeredAt: T0 }),
    /root zone may not answer with a "nxenroll" record/,
  )

  // The same policy is enforced on the verification side, so a hand-built answer gains nothing.
  const handBuilt = {
    v: NF3_ANSWER_VERSION,
    qname_digest: question.qname_digest,
    zone: ROOT_ZONE,
    record: ceRecord(),
    ttl: 300,
    answered_at: T0,
    nonce: question.nonce,
    signer_key_id: null,
    signature: null,
  }
  const signed = await signResolutionAnswer(handBuilt, rootKeys.privateKey, rootPub)
  const verdict = await verifyResolutionAnswer(signed, {
    vin: VIN,
    expectedZone: ROOT_ZONE,
    zonePublicKey: rootPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('answer_policy_violation')))
})

test('delegation grammar: root -> wmi -> operator, and nothing else', async () => {
  // Permitted hops.
  assert.equal(delegationRecord(WMI_ZONE, wmiPub, WMI_EP).child_zone.scope_type, 'wmi')
  assert.equal(delegationRecord(OP_ZONE, opPub, OP_EP).child_zone.scope_type, 'operator')
  assert.throws(() => makeDelegationRecord({ childZone: ROOT_ZONE, childZoneKey: rootPub, childEndpoint: ROOT_EP }), /cannot delegate to the root zone/)

  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const params = { qnameDigest: question.qname_digest, nonce: question.nonce, ttl: 3600, answeredAt: T0 }

  // root may not delegate straight to an operator; wmi may not delegate to a wmi.
  assert.throws(() => buildAnswer({ ...params, zone: ROOT_ZONE, record: delegationRecord(OP_ZONE, opPub, OP_EP) }), /may not delegate to a operator zone/)
  assert.throws(() => buildAnswer({ ...params, zone: WMI_ZONE, record: delegationRecord(makeZone('wmi', '2HG'), wmiPub, WMI_EP) }), /may not delegate to a wmi zone/)

  // A zone may not delegate to itself — the reachable form of a referral loop.
  const selfDelegation = {
    v: NF3_ANSWER_VERSION,
    qname_digest: question.qname_digest,
    zone: WMI_ZONE,
    record: delegationRecord(WMI_ZONE, wmiPub, WMI_EP),
    ttl: 3600,
    answered_at: T0,
    nonce: question.nonce,
    signer_key_id: null,
    signature: null,
  }
  const signedSelf = await signResolutionAnswer(selfDelegation, wmiKeys.privateKey, wmiPub)
  const verdict = await verifyResolutionAnswer(signedSelf, {
    vin: VIN,
    expectedZone: WMI_ZONE,
    zonePublicKey: wmiPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('delegation_policy_violation')))

  // The grammar is therefore acyclic by construction: an operator zone is terminal, so no
  // sequence of legal referrals can revisit a zone. MAX_REFERRAL_HOPS is the belt to that
  // brace, and it is exactly the length of the longest legal chain.
  assert.equal(MAX_REFERRAL_HOPS, 3)
})

test('a WMI zone is authoritative only inside its own manufacturer prefix', async () => {
  const foreign = makeZone('wmi', '2HG')
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const answer = await answerAs(foreign, wmiKeys, wmiPub, ceRecord(), question)

  const verdict = await verifyResolutionAnswer(answer, {
    vin: VIN, // WMI 1HG
    expectedZone: foreign,
    zonePublicKey: wmiPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('bailiwick_violation')))

  // And a root delegation must name the queried VIN's own WMI: referring a resolver to a
  // different manufacturer's zone is a hijack.
  const hijack = await answerAs(ROOT_ZONE, rootKeys, rootPub, delegationRecord(foreign, wmiPub, WMI_EP), question, { ttl: 3600 })
  const hijackVerdict = await verifyResolutionAnswer(hijack, {
    vin: VIN,
    expectedZone: ROOT_ZONE,
    zonePublicKey: rootPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(hijackVerdict.valid, false)
  assert.ok(hijackVerdict.reasons.some((r) => r.startsWith('delegation_policy_violation')))

  // Zone identity is derived from scope, so a zone cannot hold two names and defeat the
  // visited-zone loop detector by aliasing.
  const aliased = { ...answer, zone: { id: 'wmi:ALIAS', scope_type: 'wmi', scope: '1HG' } }
  const aliasVerdict = await verifyResolutionAnswer(aliased, {
    vin: VIN,
    expectedZone: { id: 'wmi:ALIAS', scope_type: 'wmi', scope: '1HG' },
    zonePublicKey: wmiPub,
    expectedNonce: question.nonce,
    now: T0,
  })
  assert.equal(aliasVerdict.valid, false)
  assert.ok(aliasVerdict.reasons.some((r) => r.startsWith('zone_scope_invalid')))

  assert.throws(() => makeZone('wmi', 'TOOLONG'), /3 ISO 3779 characters/)
  assert.throws(() => makeZone('wmi', '1IG'), /3 ISO 3779 characters/)
  assert.throws(() => makeZone('galaxy', 'x'), /unknown zone scope type/)
  assert.throws(() => makeZone('root', 'x'), /root zone scope is/)
})

test('the referral walk is bounded: the resolver never makes a fourth query', async () => {
  // Every zone in the chain answers with a further referral. The grammar refuses the third
  // one, and the hop bound would have stopped the walk regardless.
  const transport = makeTransport({
    ...fullChainHandlers(),
    [OP_EP]: async (q) => ({
      ok: true,
      answer: await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), q, { ttl: 300 }),
      reason: null,
    }),
  })
  const ok = await resolveVin(VIN, {}, resolveOpts({ transport }))
  assert.equal(ok.status, 'resolved')
  assert.equal(transport.calls.length, MAX_REFERRAL_HOPS, 'the whole namespace is three queries')
  assert.deepEqual(ok.chain.map((c) => c.zone_id), ['root', 'wmi:1HG', 'operator:acme-fleet'])
  assert.deepEqual(ok.chain.map((c) => c.source), ['anchor', 'delegation', 'delegation'])

  // A zone that keeps referring gets cut off rather than walked.
  const looping = makeTransport({
    ...fullChainHandlers(),
    [OP_EP]: async (q) => {
      const record = delegationRecord(makeZone('operator', 'second'), opPub, OP_EP)
      const handBuilt = {
        v: NF3_ANSWER_VERSION,
        qname_digest: q.qname_digest,
        zone: OP_ZONE,
        record,
        ttl: 3600,
        answered_at: T0,
        nonce: q.nonce,
        signer_key_id: null,
        signature: null,
      }
      return { ok: true, answer: await signResolutionAnswer(handBuilt, opKeys.privateKey, opPub), reason: null }
    },
  })
  const capped = await resolveVin(VIN, {}, resolveOpts({ transport: looping }))
  assert.equal(capped.status, 'error')
  assert.equal(capped.endpoint, null)
  assert.equal(looping.calls.length, MAX_REFERRAL_HOPS, 'bounded: no fourth query is ever made')
  assert.ok(capped.reasons.some((r) => r.includes('answer_policy_violation')))
})

test('iterative mode makes exactly one query and hands the referral to the caller', async () => {
  const transport = makeTransport(fullChainHandlers())
  const referral = await resolveVin(VIN, {}, resolveOpts({ transport, mode: 'iterative' }))

  assert.equal(referral.status, 'referral')
  assert.equal(transport.calls.length, 1, 'the trust decision moves to the caller; the walk does not')
  assert.equal(referral.endpoint, null, 'a referral is not a resolution')
  assert.equal(referral.authenticated, true)
  assert.equal(referral.referral.zone.id, 'wmi:1HG')
  assert.equal(referral.referral.endpoint, WMI_EP)
  assert.equal(referral.referral.key, wmiPub)
  assert.equal(referral.referral.ttl_s, 3600)
  assert.equal(assertResolutionReturnsLocationsOnly(referral), true)

  // The caller continues the walk itself, validating against the key it just learned.
  const second = await resolveVin(VIN, {}, resolveOpts({
    transport,
    mode: 'iterative',
    fromZone: { id: referral.referral.zone.id, endpoint: referral.referral.endpoint, key: referral.referral.key },
  }))
  assert.equal(second.status, 'referral')
  assert.equal(second.referral.zone.id, 'operator:acme-fleet')
  assert.ok(second.notes.some((n) => n.startsWith('chain_root_is_caller_supplied')))

  const third = await resolveVin(VIN, {}, resolveOpts({
    transport,
    mode: 'iterative',
    fromZone: { id: second.referral.zone.id, endpoint: second.referral.endpoint, key: second.referral.key },
  }))
  assert.equal(third.status, 'resolved')
  assert.equal(third.endpoint.url, BROKER_EP)
  assert.equal(transport.calls.length, 3, 'the iterative walk costs exactly what the recursive one does')

  // A malformed continuation is refused, not guessed at.
  for (const fromZone of [
    { id: 'wmi:lower', endpoint: WMI_EP, key: wmiPub },
    { id: 'wmi:1HG', endpoint: 'http://wmi.example/', key: wmiPub },
    { id: 'wmi:1HG', endpoint: WMI_EP, key: 'short' },
  ]) {
    const bad = await resolveVin(VIN, {}, resolveOpts({ transport, mode: 'iterative', fromZone }))
    assert.equal(bad.status, 'error')
    assert.ok(bad.reasons.some((r) => r.startsWith('from_zone_invalid')))
  }

  const badMode = await resolveVin(VIN, {}, resolveOpts({ transport, mode: 'sideways' }))
  assert.equal(badMode.status, 'error')
  assert.ok(badMode.reasons.some((r) => r.startsWith('mode_unknown')))
})

test('the two authenticated denials are distinct and neither is a location', async () => {
  for (const [type, status, zone, keys, pub] of [
    ['nxenroll', 'not-enrolled', OP_ZONE, opKeys, opPub],
    ['nxzone', 'no-zone', ROOT_ZONE, rootKeys, rootPub],
  ]) {
    const handlers = type === 'nxzone'
      ? { [ROOT_EP]: async (q) => ({ ok: true, answer: await answerAs(zone, keys, pub, makeNegativeRecord(type), q, { ttl: 30 }), reason: null }) }
      : { ...fullChainHandlers(), [OP_EP]: async (q) => ({ ok: true, answer: await answerAs(zone, keys, pub, makeNegativeRecord(type), q, { ttl: 30 }), reason: null }) }

    const transport = makeTransport(handlers)
    const result = await resolveVin(VIN, {}, resolveOpts({ transport }))
    assert.equal(result.status, status)
    assert.equal(result.endpoint, null)
    assert.equal(result.authenticated, true, 'a signed denial is the zone saying no, not a failure to find')
    assert.ok(result.reasons.length > 0)
    assert.equal(assertResolutionReturnsLocationsOnly(result), true)
  }
  assert.throws(() => makeNegativeRecord('ce'), /not a negative record type/)
  assert.throws(() => makeNegativeRecord('nope'), /not a negative record type/)
  assert.deepEqual(Object.keys(makeNegativeRecord('nxenroll')), [...NF3_RECORD_KEYS.nxenroll])
})

// =================================================================================
// CACHING — floors, ceilings, and the shorter negative TTL
// =================================================================================

test('TTL floors and ceilings are enforced per answer class', () => {
  const { positive, negative, referral } = NF3_TTL_POLICY

  assert.equal(clampTtl(0, 'ce').ttl, positive.floor_s)
  assert.equal(clampTtl(positive.floor_s, 'ce').ttl, positive.floor_s)
  assert.equal(clampTtl(1800, 'ce').ttl, 1800)
  assert.equal(clampTtl(999_999, 'ce').ttl, positive.ceiling_s)
  assert.equal(clampTtl(0, 'ce').clamped, true)
  assert.equal(clampTtl(1800, 'ce').clamped, false)

  for (const type of ['nxenroll', 'nxzone']) {
    assert.equal(clampTtl(0, type).ttl, negative.floor_s)
    assert.equal(clampTtl(999_999, type).ttl, negative.ceiling_s)
  }
  assert.equal(clampTtl(0, 'delegation').ttl, referral.floor_s)
  assert.equal(clampTtl(999_999, 'delegation').ttl, referral.ceiling_s)

  // A floor at all, because a zone serving ttl 0 makes itself mandatory-online — a
  // centralisation lever hidden inside a protocol whose purpose is polycentrism.
  assert.ok(positive.floor_s > 0 && negative.floor_s > 0 && referral.floor_s > 0)

  // Malformation is refused; misconfiguration is clamped.
  for (const bad of [-1, 1.5, '300', null, undefined, NaN, Infinity, 10 * 365 * 24 * 3600 + 1]) {
    assert.equal(clampTtl(bad, 'ce').ok, false, `ttl ${String(bad)} must be refused`)
  }
  assert.equal(clampTtl(300, 'nope').ok, false)
})

test('a negative answer is cached STRICTLY shorter than a positive one', () => {
  // A stale positive answer is the milder failure: the endpoint re-checks. A stale negative
  // suppresses the owner's own decision to be findable, and they cannot observe it.
  assert.ok(NF3_TTL_POLICY.negative.ceiling_s < NF3_TTL_POLICY.positive.ceiling_s)
  assert.ok(NF3_TTL_POLICY.negative.default_s < NF3_TTL_POLICY.positive.default_s)
  assert.ok(NF3_TTL_POLICY.negative.floor_s < NF3_TTL_POLICY.positive.floor_s)
  assert.ok(NF3_TTL_POLICY.negative.ceiling_s < NF3_TTL_POLICY.referral.ceiling_s)

  // The strongest form: no negative answer, however large a TTL its zone serves, is ever
  // cached longer than the shortest positive answer. (The negative ceiling and the positive
  // floor are the same 60 seconds, so the bound is "no longer than", and every other
  // comparison above is strict.)
  const worstNegative = clampTtl(Number.MAX_SAFE_INTEGER - 1, 'nxenroll')
  assert.equal(worstNegative.ok, false, 'an absurd integer is malformation, not a caching hint')
  for (const type of ['nxenroll', 'nxzone']) {
    assert.equal(clampTtl(10 * 365 * 24 * 3600, type).ttl, NF3_TTL_POLICY.negative.ceiling_s)
    assert.ok(clampTtl(10 * 365 * 24 * 3600, type).ttl <= clampTtl(0, 'ce').ttl)
    assert.ok(clampTtl(10 * 365 * 24 * 3600, type).ttl < clampTtl(999_999, 'ce').ttl)
  }
})

test('the observed TTL of a negative answer is shorter than that of a positive one', async () => {
  const positiveTransport = makeTransport(fullChainHandlers({ ttl: 999_999 }))
  const positive = await resolveVin(VIN, {}, resolveOpts({ transport: positiveTransport }))
  assert.equal(positive.status, 'resolved')
  assert.equal(positive.ttl_remaining_s, NF3_TTL_POLICY.positive.ceiling_s)
  assert.deepEqual(positive.notes, [], 'a well-behaved zone clamps its own TTL before signing')

  const negativeTransport = makeTransport({
    ...fullChainHandlers(),
    [OP_EP]: async (q) => ({
      ok: true,
      answer: await answerAs(OP_ZONE, opKeys, opPub, makeNegativeRecord('nxenroll'), q, { ttl: 999_999 }),
      reason: null,
    }),
  })
  const negative = await resolveVin(VIN, {}, resolveOpts({ transport: negativeTransport }))
  assert.equal(negative.status, 'not-enrolled')
  assert.equal(negative.ttl_remaining_s, NF3_TTL_POLICY.negative.ceiling_s)
  assert.ok(negative.ttl_remaining_s < positive.ttl_remaining_s)

  // A HOSTILE zone that hand-signs an out-of-policy TTL cannot make itself sticky either:
  // the resolver clamps on the way in and says so, rather than refusing an authentic answer
  // over a caching hint it does not accept.
  const greedy = makeTransport({
    ...fullChainHandlers(),
    [OP_EP]: async (q) => {
      const handBuilt = {
        v: NF3_ANSWER_VERSION,
        qname_digest: q.qname_digest,
        zone: OP_ZONE,
        record: ceRecord(),
        ttl: 999_999,
        answered_at: T0,
        nonce: q.nonce,
        signer_key_id: null,
        signature: null,
      }
      return { ok: true, answer: await signResolutionAnswer(handBuilt, opKeys.privateKey, opPub), reason: null }
    },
  })
  const clampedResult = await resolveVin(VIN, {}, resolveOpts({ transport: greedy }))
  assert.equal(clampedResult.status, 'resolved')
  assert.equal(clampedResult.ttl_remaining_s, NF3_TTL_POLICY.positive.ceiling_s)
  assert.ok(clampedResult.notes.some((n) => n.startsWith('ttl_clamped')))
})

test('a cached answer counts its TTL down and is re-verified on every read', async () => {
  const env = { NF3_DB: makeD1() }
  const transport = makeTransport(fullChainHandlers({ ttl: 600 }))

  const first = await resolveVin(VIN, env, resolveOpts({ transport }))
  assert.equal(first.source, 'authoritative')
  assert.equal(first.ttl_remaining_s, 600)
  assert.equal(env.NF3_DB.writes, 1)

  // RFC 1035: every cache decrements the TTL it passes on. Storing an absolute expiry is
  // the same rule as arithmetic, so a chain of caches cannot extend an answer's life.
  const later = await resolveVin(VIN, env, resolveOpts({ transport, now: T0 + 120 }))
  assert.equal(later.source, 'd1-cache')
  assert.equal(later.ttl_remaining_s, 480)
  assert.equal(later.endpoint.url, BROKER_EP)
  assert.equal(transport.calls.length, 3, 'a cache hit makes no query')

  // Past the expiry, the cache is a miss and the network is consulted again.
  const expired = await resolveVin(VIN, env, resolveOpts({ transport, now: T0 + 601, answeredAt: T0 + 601 }))
  assert.equal(expired.status, 'error', 'the stale answer is refused rather than served')
  assert.ok(transport.calls.length > 3, 'the resolver went back to the network')

  // noCache bypasses both tiers.
  const fresh = makeTransport(fullChainHandlers({ ttl: 600 }))
  const bypass = await resolveVin(VIN, env, resolveOpts({ transport: fresh, noCache: true }))
  assert.equal(bypass.source, 'authoritative')
  assert.equal(fresh.calls.length, 3)
})

test('a poisoned cache row fails exactly like a poisoned packet', async () => {
  const env = { NF3_DB: makeD1() }
  const transport = makeTransport(fullChainHandlers({ ttl: 600 }))
  await resolveVin(VIN, env, resolveOpts({ transport }))
  const digest = await qnameDigest(VIN)

  // Anyone with database access edits the stored answer.
  const row = env.NF3_DB.rows.get(digest)
  const tampered = JSON.parse(row.answer_json)
  tampered.record.endpoint = EVIL_EP
  env.NF3_DB.rows.set(digest, { ...row, answer_json: JSON.stringify(tampered) })

  const after = await resolveVin(VIN, env, resolveOpts({ transport, now: T0 + 10 }))
  assert.notEqual(after.endpoint?.url, EVIL_EP, 'a tampered row must never be served')
  assert.equal(after.endpoint.url, BROKER_EP)
  assert.equal(after.source, 'authoritative', 'the resolver fell through to the network')
  assert.equal(transport.calls.length, 6, 'the whole chain was walked again')
  // The bad row was dropped rather than repaired; what is in the table now is the freshly
  // verified answer, not the attacker's edit.
  assert.ok(!env.NF3_DB.rows.get(digest).answer_json.includes(EVIL_EP))

  // The same holds for a row that is merely corrupt rather than hostile.
  for (const broken of ['not json', '{}', JSON.stringify({ answer: {}, expires_at: T0 + 600, chain: [] })]) {
    env.NF3_DB.rows.set(digest, { ...env.NF3_DB.rows.get(digest), answer_json: broken })
    const verdict = await resolveVin(VIN, env, resolveOpts({ transport, now: T0 + 20 }))
    assert.notEqual(verdict.source, 'd1-cache')
  }
})

test('removing a trust anchor takes effect on already-cached answers immediately', async () => {
  const env = { NF3_DB: makeD1() }
  const transport = makeTransport(fullChainHandlers({ ttl: 3600 }))
  const first = await resolveVin(VIN, env, resolveOpts({ transport }))
  assert.equal(first.status, 'resolved')

  // Same cache, different anchor key: the chain no longer starts at a key we trust.
  const rotated = await resolveVin(VIN, env, {
    now: T0 + 10,
    transport,
    trustAnchors: { root: { endpoint: ROOT_EP, key: evilPub } },
  })
  assert.notEqual(rotated.source, 'd1-cache', 'anchor removal must not wait for the TTL')
})

test('a caller-rooted answer is never served to a resolution anchored elsewhere', async () => {
  // `fromZone` lets a caller act as its own validator, which is the stub-vs-recursive split.
  // But the D1 cache is SHARED. If a caller-supplied root of trust could be written to it and
  // then served to a later, anchored resolution, any caller able to reach the resolver would
  // be a cache-poisoning primitive — the exact threat the signature checks exist to close.
  const env = { NF3_DB: makeD1() }
  const attackerTransport = makeTransport({
    [WMI_EP]: async (q) => ({
      ok: true,
      // Correctly signed — by the attacker's own key, which the attacker also supplied as the
      // trust root for its own walk. Entirely legitimate for the caller who asked for it.
      answer: await answerAs(WMI_ZONE, evilKeys, evilPub, ceRecord({ endpoint: EVIL_EP, brokerKey: evilPub }), q, { ttl: 3600 }),
      reason: null,
    }),
  })
  const attackerView = await resolveVin(VIN, env, resolveOpts({
    transport: attackerTransport,
    fromZone: { id: 'wmi:1HG', endpoint: WMI_EP, key: evilPub },
  }))
  assert.equal(attackerView.status, 'resolved', 'the caller gets what it asked for, on its own head')
  assert.equal(attackerView.chain[0].source, 'caller')

  // A different, properly anchored resolution must not inherit that root of trust.
  const honest = makeTransport(fullChainHandlers({ ttl: 600 }))
  const result = await resolveVin(VIN, env, resolveOpts({ transport: honest, now: T0 + 10 }))
  assert.notEqual(
    result.endpoint?.url,
    EVIL_EP,
    'a chain rooted at a caller-supplied key must never be served to an anchored resolution',
  )
  assert.equal(result.endpoint?.url, BROKER_EP)
  assert.equal(honest.calls.length, 3, 'the anchored resolver did its own walk')
})

test('the cache is swept and purgeable, because a cache that never sweeps is a query log', async () => {
  const env = { NF3_DB: makeD1() }
  const transport = makeTransport(fullChainHandlers({ ttl: 600 }))
  await resolveVin(VIN, env, resolveOpts({ transport }))
  const digest = await qnameDigest(VIN)
  assert.equal(env.NF3_DB.rows.size, 1)

  // The stored row holds a digest of a public index and a signed statement about where a
  // broker lives. No VIN, no owner, no counterparty.
  const stored = JSON.stringify([...env.NF3_DB.rows.values()])
  assert.ok(!stored.includes(VIN))
  assert.equal([...env.NF3_DB.rows.keys()][0], digest)
  assert.equal(assertNoCredentialSurface(JSON.parse(env.NF3_DB.rows.get(digest).answer_json)), true)

  assert.deepEqual(await sweepResolutionCache(env, T0 + 100), { deleted: 0, swept: true })
  assert.equal(env.NF3_DB.rows.size, 1)
  assert.equal((await sweepResolutionCache(env, T0 + 10_000)).deleted, 1)
  assert.equal(env.NF3_DB.rows.size, 0)

  await resolveVin(VIN, env, resolveOpts({ transport: makeTransport(fullChainHandlers({ ttl: 600 })) }))
  assert.equal(await purgeResolutionCache(VIN, env), digest)
  assert.equal(env.NF3_DB.rows.size, 0)

  assert.deepEqual(await sweepResolutionCache({}, T0), { deleted: 0, swept: false })
  assert.match(NF3_CACHE_SCHEMA_SQL, /CREATE TABLE IF NOT EXISTS nf3_resolution_cache/)
  assert.ok(!/vin|owner|grant/i.test(NF3_CACHE_SCHEMA_SQL.replace(/qname_digest/g, '')))
})

test('a resolver whose cache is broken is slow, not wrong', async () => {
  const broken = {
    prepare() {
      return { bind() { return { first: async () => { throw new Error('D1 down') }, run: async () => { throw new Error('D1 down') } } } }
    },
  }
  const transport = makeTransport(fullChainHandlers({ ttl: 600 }))
  const result = await resolveVin(VIN, { NF3_DB: broken }, resolveOpts({ transport }))
  assert.equal(result.status, 'resolved')
  assert.equal(result.endpoint.url, BROKER_EP)
})

// =================================================================================
// Transport
// =================================================================================

test('the default transport POSTs, refuses redirects, and caps the body', async () => {
  const question = makeQuestion(await qnameDigest(VIN), generateQueryNonce())
  const answer = await answerAs(OP_ZONE, opKeys, opPub, ceRecord(), question)
  const realFetch = globalThis.fetch
  const seen = []

  globalThis.fetch = async (url, init) => {
    seen.push({ url, init })
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } })
  }
  try {
    const wire = await httpZoneTransport(OP_EP, question, { timeoutMs: 100 })
    assert.equal(wire.ok, true)
    assert.deepEqual(wire.answer, JSON.parse(JSON.stringify(answer)))
    assert.equal(seen[0].init.method, 'POST', 'the qname digest must not appear in a URL')
    assert.equal(seen[0].init.redirect, 'error', 'following a redirect is an SSRF primitive')
    assert.equal(seen[0].url, OP_EP)
    assert.ok(!seen[0].url.includes(question.qname_digest))

    globalThis.fetch = async () => new Response('not json', { status: 200 })
    assert.equal((await httpZoneTransport(OP_EP, question)).ok, false)

    globalThis.fetch = async () => new Response('[]', { status: 200 })
    assert.equal((await httpZoneTransport(OP_EP, question)).ok, false)

    globalThis.fetch = async () => new Response('{}', { status: 503 })
    assert.match((await httpZoneTransport(OP_EP, question)).reason, /HTTP 503/)

    globalThis.fetch = async () => new Response('x'.repeat(17 * 1024), { status: 200 })
    assert.match((await httpZoneTransport(OP_EP, question)).reason, /body cap|over the cap/)

    globalThis.fetch = async () => {
      throw new Error('connection refused')
    }
    assert.match((await httpZoneTransport(OP_EP, question)).reason, /zone unreachable/)
  } finally {
    globalThis.fetch = realFetch
  }
})

test('questions and answers refuse malformed inputs at construction', async () => {
  const digest = await qnameDigest(VIN)
  const nonce = generateQueryNonce()
  assert.equal(makeQuestion(digest, nonce).v, 'nf3-question/1')
  assert.equal(nonce.length, 22)
  assert.notEqual(generateQueryNonce(), generateQueryNonce())

  assert.throws(() => makeQuestion('short', nonce), /32-byte base64url digest/)
  assert.throws(() => makeQuestion(digest, 'short'), /16-byte base64url/)
  assert.throws(() => buildAnswer({ qnameDigest: digest, nonce, zone: OP_ZONE, record: ceRecord(), ttl: 300, answeredAt: T0, extra: 1 }), /unknown parameter/)
  assert.throws(() => buildAnswer({ qnameDigest: digest, nonce, zone: { id: 'x' }, record: ceRecord(), ttl: 300, answeredAt: T0 }), /invalid zone/)
  assert.throws(() => buildAnswer({ qnameDigest: digest, nonce, zone: OP_ZONE, record: { type: 'ce' }, ttl: 300, answeredAt: T0 }), /invalid record/)
  assert.throws(() => buildAnswer({ qnameDigest: digest, nonce, zone: OP_ZONE, record: ceRecord(), ttl: -1, answeredAt: T0 }), /ttl rejected/)

  const built = buildAnswer({ qnameDigest: digest, nonce, zone: OP_ZONE, record: ceRecord(), ttl: 300, answeredAt: T0 })
  assert.deepEqual(Object.keys(built).sort(), [...NF3_ANSWER_KEYS].sort())
  assert.equal(built.signature, null)
  assert.equal(built.signer_key_id, null)

  const signed = await signResolutionAnswer(built, opKeys.privateKey, opPub)
  assert.equal(signed.signature.length, 86)
  assert.equal(signed.signer_key_id, await zoneKeyIdFromBase64url(opPub))
  await assert.rejects(() => signResolutionAnswer(signed, opKeys.privateKey, opPub), /already signed/)
  await assert.rejects(() => signResolutionAnswer(built, opKeys.publicKey, opPub), /private CryptoKey/)
  await assert.rejects(() => signResolutionAnswer(built, opKeys.privateKey, 'short'), /32-byte base64url/)
})
