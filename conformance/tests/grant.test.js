/**
 * NF-5 conformance — Consent Grant core, delegation depth, and non-transferability.
 * MODULE profile, over `broker/src/nf2-grant.js`.
 *
 * Nimbus Foundation NF-5 §5 (Group NT), §6 (Group DD), §5.6 (Group GC), §4.3 (harness),
 * §4.4 (determinism). NF-WP-1 §3.1, §8.2, §9.5, §10.1, §12.2.
 *
 * THE THREE REFUSALS ARE THE SPINE OF THIS FILE.
 *
 *  1. No VIN is ever resolved to a credential, and no VIN ever reaches a grant payload.
 *     Asserted over the CANONICAL BYTES, because that is the only representation a
 *     signature and a commitment actually cover.
 *  2. The only artefact this module offers a ledger is `deriveGrantCommitment` — one
 *     fixed-length opaque digest. Everything payload-shaped stays in mutable D1.
 *  3. Nothing here is a market. There is no price, amount, currency, fee, escrow or
 *     settlement export, and no operator-held revocation authority. Both are asserted
 *     structurally rather than described.
 *
 * DETERMINISM (NF-5 §4.4). No wall clock: every temporal assertion injects `opts.now`.
 * Signing keys are imported from FIXED 32-byte seeds via PKCS#8 rather than generated, so
 * two runs sign identical bytes. The only randomness anywhere is `generateGrantId`, whose
 * unpredictability is itself required by the schema (a counter would leak issuance volume
 * per vehicle); no assertion depends on a particular id, only on distinctness.
 *
 * NF-5 §4.3: Ed25519 is obtained by feature-detecting `{ name: 'Ed25519' }` and falling
 * back to the legacy Workers name, exactly as the module does. A run that cannot resolve
 * it is INCONCLUSIVE, which counts as FAIL (§4.6) — hence the throw rather than a skip.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  DEFAULT_CLOCK_SKEW_S,
  GRANT_KEYS,
  MAX_DELEGATION_DEPTH,
  MAX_GRANT_DURATION_S,
  MAX_PLAUSIBLE_TIME_S,
  MIN_PLAUSIBLE_TIME_S,
  PSEUDONYM_DERIVATION,
  SCHEMA_VERSION,
  assertNonTransferable,
  buildGrant,
  deriveGrantCommitment,
  generateGrantId,
  grantSigningInput,
  importPublicKeyBase64url,
  mintDelegatedGrant,
  renewGrant,
  revocationKeyIdFromPublicKey,
  signGrant,
  verifyGrant,
} from '../../broker/src/nf2-grant.js'
import * as nf2 from '../../broker/src/nf2-grant.js'
import { canonicalize, canonicalizeToBytes } from '../../broker/src/jcs.js'
import { base64url, base64urlToBytes } from '../../broker/src/vin.js'

// ---------------------------------------------------------------------------------
// Fixtures — fixed vectors only (NF-5 §4.4(5))
// ---------------------------------------------------------------------------------

/** NF-5 §4.3: probe, never hand-roll, and never substitute another scheme. */
const ED = await (async () => {
  for (const alg of [{ name: 'Ed25519' }, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }]) {
    try {
      await crypto.subtle.generateKey(alg, false, ['sign', 'verify'])
      return alg
    } catch {
      /* not this name */
    }
  }
  throw new Error('INCONCLUSIVE: no Ed25519 in this runtime WebCrypto (NF-5 §4.3, counts as FAIL)')
})()

/** RFC 8410 PKCS#8 prefix for an Ed25519 private key: 16 bytes of DER, then the 32-byte seed. */
const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])

async function sha256(input) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)))
}

/** A signer whose key material is a pure function of `label`. Same run, same bytes, always. */
async function signer(label) {
  const seed = await sha256(`NF5/1.0:key:${label}`)
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32)
  pkcs8.set(PKCS8_ED25519_PREFIX, 0)
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length)
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, ED, true, ['sign'])
  const jwk = await crypto.subtle.exportKey('jwk', priv)
  return { priv, pub: jwk.x, label }
}

const OWNER = await signer('owner')
const OWNER_2 = await signer('owner-2')
const CP_A = await signer('counterparty-a')
const CP_B = await signer('counterparty-b')
const DELEGATE = await signer('delegate')
const SIBLINGS = await Promise.all([1, 2, 3, 4, 5].map((n) => signer(`sibling-${n}`)))
const REVOCATION = await signer('owner-revocation')

const REVOCATION_KEY_ID = await revocationKeyIdFromPublicKey(base64urlToBytes(REVOCATION.pub))

/** Syntactically valid VIN. `buildGrant` validates syntax, not the check digit (vin.js §). */
const VIN = '1M8GDM9AXKP042788'
const SALT = base64url(await sha256('NF5/1.0:pseudonym-salt:owner'))

const T0 = 1_800_000_000 // inside [MIN_PLAUSIBLE_TIME_S, MAX_PLAUSIBLE_TIME_S]
const DAY = 24 * 60 * 60
const EXPIRES = T0 + DAY
const NOW = T0 + 3600 // injected everywhere; Date.now() appears in no decision path

const BASE_PARAMS = Object.freeze({
  vin: VIN,
  pseudonymSalt: SALT,
  pseudonymEpoch: 7,
  fields: ['make', 'odometer_km'],
  purpose: 'dppa-2721b-2',
  counterpartyClass: 'fleet-operator',
  counterpartyKey: CP_A.pub,
  revocationKeyId: REVOCATION_KEY_ID,
  issuedAt: T0,
  expiresAt: EXPIRES,
  delegationDepth: 0,
})

/**
 * V.holder_mutation_fields (NF-5 §4.8). Stated by the suite: `nf2-grant.js` keeps its own
 * copy private, and a test that imported it would be asserting the module agrees with
 * itself.
 */
const V_HOLDER_MUTATION_FIELDS = Object.freeze([
  'holder', 'assignee', 'transfer_to', 'transferable', 'new_holder', 'bearer',
  'delegate_to', 'reissue_to',
])

/** V.layer5_tokens — vocabulary that must not exist anywhere in V1 (NF-WP-1 §8, NF-1 §8). */
const V_LAYER5_TOKENS = Object.freeze([
  'price', 'amount', 'currency', 'fee', 'escrow', 'settle', 'settlement', 'payment',
  'token', 'mint', 'burn', 'balance', 'transfer', 'assign', 'sell', 'buy', 'bid', 'ask',
  'collateral', 'royalty',
])

function build(overrides = {}) {
  return buildGrant({ ...BASE_PARAMS, ...overrides })
}

/** The grant minus `signature`, in the shape `grantSigningInput` covers. */
function unsignedView(grant) {
  const out = {}
  for (const key of GRANT_KEYS) {
    if (key !== 'signature') out[key] = grant[key]
  }
  return out
}

/**
 * Sign an object the module would refuse to sign. NF-5 §5 NT-007 and §6 DD-003 both require
 * presenting a GENUINELY signed but structurally invalid grant, which `signGrant` will not
 * produce — it validates first. So the suite plays the attacker directly.
 */
async function handSign(grant, privateKey) {
  const sig = await crypto.subtle.sign(ED, privateKey, canonicalizeToBytes(unsignedView(grant)))
  return { ...grant, signature: base64url(new Uint8Array(sig)) }
}

function codes(reasons) {
  return reasons.map((r) => r.slice(0, r.indexOf(':')))
}

async function fixedB64(label, byteLength) {
  return base64url((await sha256(`NF5/1.0:b64:${label}`)).subarray(0, byteLength))
}

// Chain fixtures, built once. Every assertion below treats them as read-only.
const ROOT0 = await signGrant(await build({ delegationDepth: 0 }), OWNER.priv)
const ROOT1 = await signGrant(await build({ delegationDepth: 1 }), OWNER.priv)
const ROOT2 = await signGrant(
  await build({ delegationDepth: 2, fields: ['dtc_codes', 'make', 'odometer_km'] }),
  OWNER.priv,
)
const CHILD = await signGrant(
  mintDelegatedGrant(ROOT2, {
    fields: ['make', 'odometer_km'],
    counterpartyClass: 'repair-independent',
    counterpartyKey: DELEGATE.pub,
    issuedAt: T0,
    expiresAt: EXPIRES,
  }),
  CP_A.priv,
)
const GRANDCHILD = await signGrant(
  mintDelegatedGrant(CHILD, {
    fields: ['make'],
    counterpartyClass: 'repair-franchised',
    counterpartyKey: CP_B.pub,
    issuedAt: T0,
    expiresAt: EXPIRES,
  }),
  DELEGATE.priv,
)

// =================================================================================
// Group GC — the positive controls first. Everything after them is a refusal, and a
// suite of refusals that never exercises the success path is a vacuous pass (§4.7).
// =================================================================================

test('[control] NF5-NT-010 a vpic-only, a layer2-only and a mixed grant all issue, verify and commit', async () => {
  const specs = [
    ['vpic-only', ['body_class', 'make', 'model_year']],
    ['layer2-only', ['dtc_codes', 'state_of_charge_pct']],
    ['mixed', ['aggregation_window_s', 'odometer_km', 'speed_mean_kph']],
  ]
  const commitments = new Set()
  for (const [label, fields] of specs) {
    const grant = await build({ fields })
    assert.equal(grant.signature, null, `${label}: buildGrant returns an UNSIGNED grant`)
    const signed = await signGrant(grant, OWNER.priv)

    const verdict = await verifyGrant(signed, { ownerPublicKey: OWNER.pub, now: NOW })
    assert.deepEqual(verdict, { valid: true, reasons: [] }, `${label}: ${verdict.reasons}`)

    const commitment = await deriveGrantCommitment(signed)
    assert.equal(commitment.length, 43, `${label}: commitment must be 43 base64url chars`)
    assert.match(commitment, /^[A-Za-z0-9_-]+$/)
    commitments.add(commitment)
  }
  assert.equal(commitments.size, 3, 'three distinct grants must have three distinct commitments')
})

test('[control] a signed grant carries exactly the 14 closed keys, in the shape the schema fixes', async () => {
  assert.deepEqual(Object.keys(ROOT0).sort(), [...GRANT_KEYS].sort())
  assert.equal(GRANT_KEYS.length, 14)
  assert.equal(ROOT0.v, SCHEMA_VERSION)
  assert.equal(ROOT0.purpose, 'dppa-2721b-2')
  assert.equal(ROOT0.counterparty_key, CP_A.pub)
  assert.equal(ROOT0.revocation_key_id, REVOCATION_KEY_ID)
  assert.equal(ROOT0.issued_at, T0)
  assert.equal(ROOT0.expires_at, EXPIRES)
  assert.equal(ROOT0.delegation_depth, 0)
  assert.equal(ROOT0.parent_grant_id, null)
  assert.equal(ROOT0.renewal_of, null)
  assert.deepEqual([...ROOT0.fields], ['make', 'odometer_km'])
  assert.deepEqual(Object.keys(ROOT0.vehicle_pseudonym).sort(), [
    'audience',
    'derivation',
    'epoch',
    'value',
  ])
  assert.equal(ROOT0.vehicle_pseudonym.derivation, PSEUDONYM_DERIVATION)
  assert.equal(ROOT0.vehicle_pseudonym.audience, 'fleet-operator')
  assert.equal(ROOT0.vehicle_pseudonym.epoch, 7)
  assert.equal(ROOT0.vehicle_pseudonym.value.length, 43)
})

test('[control] optional keys are present as null, never omitted', async () => {
  // Absence and explicit null canonicalise to different bytes, so allowing both would give
  // one semantic grant two commitments — and NF-4 keys revocation BY commitment, so the
  // second form would silently evade a revocation entry filed against the first.
  for (const key of ['parent_grant_id', 'renewal_of', 'signature']) {
    assert.ok(Object.hasOwn(ROOT0, key), key)
  }
  const stripped = { ...ROOT0 }
  delete stripped.renewal_of
  const verdict = await verifyGrant(stripped, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('missing_field: "renewal_of"')))
})

test('[control] signGrant returns a new object and never mutates its input', async () => {
  const unsigned = await build()
  const before = canonicalize(unsigned)
  const signed = await signGrant(unsigned, OWNER.priv)
  assert.equal(unsigned.signature, null, 'the caller must not end up with two views of one grant')
  assert.equal(canonicalize(unsigned), before)
  assert.equal(signed.signature.length, 86)
  assert.equal(base64urlToBytes(signed.signature).length, 64)
  assert.notEqual(signed, unsigned)
})

test('[control] grant_ids are unique and unguessable-shaped, not sequential', async () => {
  // A counter would leak issuance volume per vehicle and let a holder estimate how many
  // other grants exist — a side channel on the owner's behaviour.
  const ids = new Set()
  for (let i = 0; i < 64; i += 1) {
    const id = generateGrantId()
    assert.equal(id.length, 22)
    assert.equal(base64urlToBytes(id).length, 16)
    ids.add(id)
  }
  assert.equal(ids.size, 64)
})

// =================================================================================
// Refusal 1 — the VIN is an index, never a credential, and never a payload member
// =================================================================================

test('REFUSAL 1 the raw VIN never appears in the canonical bytes of a grant', async () => {
  // Asserted over the canonical bytes rather than over the object, because the bytes are
  // what a signature covers and what a commitment digests. A debug field added during a
  // refactor would show up here and nowhere else.
  const vins = [
    VIN,
    '1M8GDM9AXKP042788',
    'WBA3A5C57DF123456',
    'JH4KA7561PC008269',
    '5YJ3E1EA7JF000316',
  ]
  for (const vin of vins) {
    for (const supplied of [vin, vin.toLowerCase(), `  ${vin}  `]) {
      const grant = await build({ vin: supplied })
      const canonical = canonicalize(grant)
      assert.equal(canonical.includes(vin), false, `raw VIN in payload: ${vin}`)
      assert.equal(canonical.toUpperCase().includes(vin), false, `case-folded VIN in payload: ${vin}`)
      assert.equal(canonical.includes(supplied.trim()), false)
      // Not even a substantial fragment survives.
      for (let start = 0; start + 8 <= 17; start += 1) {
        assert.equal(
          canonical.toUpperCase().includes(vin.slice(start, start + 8)),
          false,
          `VIN fragment ${vin.slice(start, start + 8)} in payload`,
        )
      }
      const signed = await signGrant(grant, OWNER.priv)
      const signedBytes = new TextDecoder().decode(grantSigningInput(signed))
      assert.equal(signedBytes.toUpperCase().includes(vin), false, 'VIN inside the SIGNED bytes')
    }
  }
})

test('REFUSAL 1 no grant key is VIN-shaped, and the pseudonym slot has no room for one', async () => {
  // A 43-character base64url value cannot be a 17-character VIN. The structural check is
  // the enforcement point at verification time, where the VIN is not available to compare
  // against — the shape simply has no room for it.
  assert.equal(GRANT_KEYS.includes('vin'), false)
  assert.equal(GRANT_KEYS.includes('raw_vin'), false)
  assert.equal(GRANT_KEYS.includes('vehicle_id'), false)
  for (const key of GRANT_KEYS) assert.equal(/vin|plate|licen[cs]e/i.test(key), false, key)

  const vinShaped = { ...ROOT0, vehicle_pseudonym: { ...ROOT0.vehicle_pseudonym, value: VIN } }
  const verdict = await verifyGrant(vinShaped, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('pseudonym_malformed')), verdict.reasons)
})

test('REFUSAL 1 a VIN alone changes no outcome: buildGrant refuses a malformed one and grants nothing', async () => {
  for (const bad of ['', 'NOT-A-VIN', '1M8GDM9AXKP04278I', 'A'.repeat(16), null, 42, {}]) {
    await assert.rejects(() => build({ vin: bad }), /malformed VIN/, String(bad))
  }
})

// =================================================================================
// Refusal 2 — commitments only, and nothing payload-shaped, may reach a ledger
// =================================================================================

test('REFUSAL 2 deriveGrantCommitment is a fixed-length opaque digest and nothing else', async () => {
  // The ONLY artefact this module offers an immutable ledger. Everything else — pseudonym,
  // field set, holder key, timestamps — stays in mutable, deletable D1, because a standing
  // 45-day Delete Act cadence and CCPA erasure cannot be reconciled with immutability.
  const lengths = new Set()
  const seen = new Set()
  for (let i = 0; i < 16; i += 1) {
    const signed = await signGrant(await build({ pseudonymEpoch: i }), OWNER.priv)
    const commitment = await deriveGrantCommitment(signed)
    lengths.add(commitment.length)
    seen.add(commitment)
    assert.match(commitment, /^[A-Za-z0-9_-]{43}$/)
    // Nothing recoverable: no field id, no pseudonym, no purpose, no timestamp survives.
    for (const leak of ['make', 'odometer', 'dppa', 'fleet', String(T0), signed.grant_id]) {
      assert.equal(commitment.includes(leak), false, `commitment leaks ${leak}`)
    }
    assert.equal(commitment.includes(signed.vehicle_pseudonym.value.slice(0, 8)), false)
  }
  assert.deepEqual([...lengths], [43], 'commitment length must not vary with content')
  assert.equal(seen.size, 16)
})

test('REFUSAL 2 the commitment is domain-separated from a bare SHA-256 of the grant', async () => {
  // Domain separation so the digest cannot be replayed as, or mistaken for, any other
  // SHA-256 in the system — notably a revocation-key thumbprint.
  const commitment = await deriveGrantCommitment(ROOT0)
  const bare = base64url(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalize(ROOT0)))),
  )
  assert.notEqual(commitment, bare)
  const thumbprint = await revocationKeyIdFromPublicKey(base64urlToBytes(ROOT0.counterparty_key))
  assert.notEqual(commitment, thumbprint)
})

test('REFUSAL 2 no export produces anything a ledger could carry except the commitment', async () => {
  const producers = Object.keys(nf2).filter((k) => /commit|chain|ledger|onchain|on_chain|publish|anchor/i.test(k))
  assert.deepEqual(producers, ['deriveGrantCommitment'])
})

// =================================================================================
// Refusal 3 — no operator-held revocation, and no market anywhere in the module
// =================================================================================

test('REFUSAL 3 a revocation key held by the counterparty is refused, raw and as a thumbprint', async () => {
  // A revocation key the grantee controls is not a revocation key, it is a promise — and a
  // grantee will not exercise it. Checkable from the grant alone, with no external input.
  const raw = { ...ROOT0, revocation_key_id: ROOT0.counterparty_key }
  const rawVerdict = await verifyGrant(raw, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(rawVerdict.valid, false)
  assert.ok(
    rawVerdict.reasons.some((r) => r.startsWith('revocation_key_held_by_counterparty')),
    rawVerdict.reasons,
  )

  const thumbprint = await revocationKeyIdFromPublicKey(base64urlToBytes(ROOT0.counterparty_key))
  const sneaky = { ...ROOT0, revocation_key_id: thumbprint }
  const sneakyVerdict = await verifyGrant(sneaky, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(sneakyVerdict.valid, false)
  assert.ok(
    sneakyVerdict.reasons.some((r) => r.startsWith('revocation_key_held_by_counterparty')),
    sneakyVerdict.reasons,
  )
})

test('REFUSAL 3 an operator-held revocation key id is refused when the caller declares it', async () => {
  // The caller supplies the ids it operates so the claim "the Foundation and the broker hold
  // no revocation authority" is TESTED rather than asserted.
  const verdict = await verifyGrant(ROOT0, {
    ownerPublicKey: OWNER.pub,
    now: NOW,
    forbiddenRevocationKeyIds: ['some-other-id', REVOCATION_KEY_ID],
  })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('revocation_key_forbidden')), verdict.reasons)

  // Control: an unrelated forbidden list must not poison a legitimate grant.
  const clean = await verifyGrant(ROOT0, {
    ownerPublicKey: OWNER.pub,
    now: NOW,
    forbiddenRevocationKeyIds: ['some-other-id'],
  })
  assert.deepEqual(clean, { valid: true, reasons: [] })
})

test('REFUSAL 3 / V1 SCOPE no export, grant key or constant names a market primitive', async () => {
  // Absence is structural, not policy: if no price, amount, currency or fee field exists,
  // Layer 5 cannot be switched on by configuration. NF-1 §8 holds the gate.
  // Two exemptions, each with a named reason, on the same discipline NF-5 §5 NT-003 applies
  // to its pattern screen: a substring heuristic will collide eventually, and the fix is a
  // written rationale rather than a quietly shortened token list.
  //   assertNonTransferable — the word `transfer` appears in the export whose entire job is
  //     to refuse transfer. Removing the token would blind the screen.
  //   mintDelegatedGrant   — `mint` here is "construct a sub-grant", not "mint a token".
  //     A Consent Grant is non-fungible, non-transferable and has no supply.
  const EXEMPT_EXPORTS = new Set(['assertNonTransferable', 'mintDelegatedGrant'])
  for (const exportName of Object.keys(nf2)) {
    if (EXEMPT_EXPORTS.has(exportName)) continue
    for (const token of V_LAYER5_TOKENS) {
      assert.equal(
        exportName.toLowerCase().includes(token),
        false,
        `export "${exportName}" names a Layer-5 primitive ("${token}")`,
      )
    }
  }
  // The exemptions must stay live, or they are holes waiting for a future export.
  for (const exempt of EXEMPT_EXPORTS) {
    assert.ok(Object.hasOwn(nf2, exempt), `stale Layer-5 screen exemption: ${exempt}`)
  }
  for (const key of GRANT_KEYS) {
    for (const token of V_LAYER5_TOKENS) {
      assert.equal(key.toLowerCase().includes(token), false, `grant key "${key}" names "${token}"`)
    }
  }
  const canonical = canonicalize(ROOT0)
  for (const token of V_LAYER5_TOKENS) {
    assert.equal(canonical.toLowerCase().includes(`"${token}"`), false, token)
  }
})

// =================================================================================
// Group NT — non-transactability at the grant boundary
// =================================================================================

const V_NON_TRANSACTABLE = Object.freeze([
  'precise_geolocation', 'coarse_geolocation', 'gps_trace', 'latitude', 'longitude',
  'geohash', 'biometric_identifier', 'driver_face_template', 'fingerprint', 'voiceprint',
  'in_cabin_audio', 'in_cabin_video', 'driver_monitoring_video', 'raw_vin', 'owner_name',
  'owner_address', 'owner_phone', 'owner_email',
])

test('NF5-NT-004 buildGrant refuses every forbidden identifier in every position', async () => {
  let cases = 0
  for (const f of V_NON_TRANSACTABLE) {
    for (const fields of [[f], ['odometer_km', f, 'make'], [f, f], ['make', 'odometer_km', f]]) {
      cases += 1
      await assert.rejects(
        () => build({ fields }),
        (err) => {
          assert.ok(err instanceof Error)
          assert.ok(err.message.includes(f), `refusal does not name ${f}: ${err.message}`)
          assert.match(err.message, /invalid field set/)
          return true
        },
        `${f} accepted in ${JSON.stringify(fields)}`,
      )
    }
  }
  assert.equal(cases, 72)
})

test('NF5-NT-007 a VALID signature does not rescue a forbidden field, and the set is not severable', async () => {
  // Structural validity is evaluated independently of, and its failure is not cured by,
  // cryptographic validity. An IUT that served the admitted subset would let a counterparty
  // harvest the maximum admitted set by appending a forbidden field to every request.
  const template = await build({ fields: ['make', 'odometer_km'] })
  const forbidden = { ...template, fields: ['in_cabin_video', 'odometer_km'] }
  const signed = await handSign(forbidden, OWNER.priv)

  // The signature really is genuine over the canonical payload — the attack is not a forgery.
  const ownerKey = await importPublicKeyBase64url(OWNER.pub)
  assert.equal(
    await crypto.subtle.verify(
      ED,
      ownerKey,
      base64urlToBytes(signed.signature),
      canonicalizeToBytes(unsignedView(signed)),
    ),
    true,
    'fixture is not genuinely signed; the assertion below would be vacuous',
  )

  const verdict = await verifyGrant(signed, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('fields_invalid')), verdict.reasons)
  assert.ok(verdict.reasons.some((r) => r.includes('in_cabin_video')), verdict.reasons)
  // Not severable: the admitted member is not quietly kept.
  assert.equal(verdict.reasons.some((r) => r.startsWith('fields_narrowed')), false)
  await assert.rejects(() => deriveGrantCommitment(signed), /refusing to commit to an invalid grant/)
})

test('NF5-NT-008 delegation cannot introduce or broaden toward a forbidden field', async () => {
  const attempts = [
    [['precise_geolocation'], /non-transactable/],
    [['in_cabin_audio', 'make'], /non-transactable/],
    [['dtc_codes', 'make'], /broaden the field set/],
  ]
  for (const [fields, expected] of attempts) {
    assert.throws(
      () =>
        mintDelegatedGrant(CHILD, {
          fields,
          counterpartyClass: 'repair-franchised',
          counterpartyKey: CP_B.pub,
          issuedAt: T0,
          expiresAt: EXPIRES,
        }),
      expected,
      JSON.stringify(fields),
    )
  }
  // [control] the narrowing sub-grant succeeds.
  const ok = mintDelegatedGrant(CHILD, {
    fields: ['make'],
    counterpartyClass: 'repair-franchised',
    counterpartyKey: CP_B.pub,
    issuedAt: T0,
    expiresAt: EXPIRES,
  })
  assert.deepEqual([...ok.fields], ['make'])

  // A hand-assembled sub-grant naming a forbidden class, genuinely signed by the delegator,
  // still verifies as invalid: the delegator is not the owner and has no standing to widen
  // the CLASS of data at issue.
  const smuggled = await handSign({ ...ok, fields: ['gps_trace', 'make'] }, DELEGATE.priv)
  const verdict = await verifyGrant(smuggled, { parentGrant: CHILD, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('fields_invalid')), verdict.reasons)
})

test('NF5-NT-009 renewal cannot introduce a forbidden field or broaden the set', async () => {
  // "Renew" is what an owner clicks without reading, which makes it the highest-value place
  // to widen a grant.
  for (const fields of [['voiceprint'], ['make', 'owner_email'], ['in_cabin_video']]) {
    await assert.rejects(
      () =>
        renewGrant(ROOT0, {
          vin: VIN,
          pseudonymSalt: SALT,
          pseudonymEpoch: 8,
          fields,
          issuedAt: T0 + DAY,
          expiresAt: T0 + 2 * DAY,
        }),
      /invalid field set|broaden/,
      JSON.stringify(fields),
    )
  }
  await assert.rejects(
    () =>
      renewGrant(ROOT0, {
        vin: VIN,
        pseudonymSalt: SALT,
        pseudonymEpoch: 8,
        fields: ['dtc_codes', 'make', 'odometer_km'],
        issuedAt: T0 + DAY,
        expiresAt: T0 + 2 * DAY,
      }),
    /renewal would broaden the field set/,
  )
})

test('[control] NF5-NT-009 a narrowing renewal mints a NEW grant and leaves the old one untouched', async () => {
  const before = canonicalize(ROOT0)
  const renewed = await renewGrant(ROOT0, {
    vin: VIN,
    pseudonymSalt: SALT,
    pseudonymEpoch: 8,
    fields: ['make'],
    issuedAt: T0 + DAY,
    expiresAt: T0 + 2 * DAY,
  })
  assert.notEqual(renewed.grant_id, ROOT0.grant_id, 'a renewal must not reuse the grant_id')
  assert.equal(renewed.renewal_of, ROOT0.grant_id)
  assert.equal(renewed.issued_at, T0 + DAY)
  assert.equal(renewed.expires_at, T0 + 2 * DAY)
  assert.equal(renewed.signature, null, 'a renewal needs a FRESH signature, not an inherited one')
  assert.deepEqual([...renewed.fields], ['make'])
  assert.equal(renewed.purpose, ROOT0.purpose)
  assert.equal(renewed.counterparty_key, ROOT0.counterparty_key)
  // A rotated epoch makes the renewal unlinkable to what it replaces from the
  // counterparty's side, which is the intended effect.
  assert.notEqual(renewed.vehicle_pseudonym.value, ROOT0.vehicle_pseudonym.value)
  assert.equal(canonicalize(ROOT0), before, 'renewal mutated the previous grant in place')

  const signed = await signGrant(renewed, OWNER.priv)
  const verdict = await verifyGrant(signed, { ownerPublicKey: OWNER.pub, now: T0 + DAY + 60 })
  assert.deepEqual(verdict, { valid: true, reasons: [] })
  assert.notEqual(await deriveGrantCommitment(signed), await deriveGrantCommitment(ROOT0))
})

// =================================================================================
// The closed key set — an unknown key is privilege escalation, not extensibility
// =================================================================================

test('an unknown top-level key is refused even though it is OUTSIDE the signed bytes', async () => {
  // THE CANONICALISATION-MISMATCH ATTACK in its purest form. `grantSigningInput` builds its
  // payload from GRANT_KEYS only, so an appended key changes not one byte of what the
  // signature covers — the raw signature still verifies. The closed-key check is therefore
  // the ONLY thing standing between an "extension" field and a verifier enforcing a rule
  // the issuer never signed.
  const attacked = { ...ROOT0, unlimited_access: true }
  const originalBytes = canonicalizeToBytes(unsignedView(ROOT0))
  const attackedBytes = canonicalizeToBytes(unsignedView(attacked))
  assert.deepEqual([...attackedBytes], [...originalBytes], 'fixture assumption: signed bytes unchanged')

  const ownerKey = await importPublicKeyBase64url(OWNER.pub)
  assert.equal(
    await crypto.subtle.verify(ED, ownerKey, base64urlToBytes(attacked.signature), attackedBytes),
    true,
    'the raw signature really does still verify; only the closed-key check catches this',
  )

  const verdict = await verifyGrant(attacked, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('unknown_field')), verdict.reasons)
  await assert.rejects(() => deriveGrantCommitment(attacked), /refusing to commit/)
  assert.throws(() => grantSigningInput(attacked), /refusing to compute a signing input/)
})

test('every omitted key is reported by name, and extra keys are reported too', async () => {
  for (const key of GRANT_KEYS) {
    const stripped = { ...ROOT0 }
    delete stripped[key]
    const verdict = await verifyGrant(stripped, { ownerPublicKey: OWNER.pub, now: NOW })
    assert.equal(verdict.valid, false, key)
    assert.ok(
      verdict.reasons.some((r) => r.startsWith(`missing_field: "${key}"`)),
      `${key}: ${verdict.reasons}`,
    )
  }
  const many = { ...ROOT0, a: 1, b: 2 }
  const verdict = await verifyGrant(many, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.equal(codes(verdict.reasons).filter((c) => c === 'unknown_field').length, 2)
})

test('the pseudonym sub-object is closed on the same reasoning', async () => {
  const cases = [
    [{ ...ROOT0.vehicle_pseudonym, extra: 1 }, /pseudonym_malformed: unknown member "extra"/],
    [
      { value: ROOT0.vehicle_pseudonym.value, epoch: 7, audience: 'fleet-operator' },
      /missing member "derivation"/,
    ],
    [{ ...ROOT0.vehicle_pseudonym, derivation: 'nf2-pseudonym:v2' }, /pseudonym_derivation_unsupported/],
    [{ ...ROOT0.vehicle_pseudonym, audience: '' }, /pseudonym_malformed: audience is required/],
    [{ ...ROOT0.vehicle_pseudonym, audience: 'academic-research' }, /pseudonym_audience_mismatch/],
    [{ ...ROOT0.vehicle_pseudonym, epoch: -1 }, /epoch must be a non-negative safe integer/],
    [{ ...ROOT0.vehicle_pseudonym, epoch: 2 ** 53 }, /epoch must be a non-negative safe integer/],
    [{ ...ROOT0.vehicle_pseudonym, value: 'short' }, /value must be 32 bytes/],
    ['not-an-object', /vehicle_pseudonym must be an object/],
    [null, /vehicle_pseudonym must be an object/],
  ]
  for (const [pseudonym, expected] of cases) {
    const verdict = await verifyGrant(
      { ...ROOT0, vehicle_pseudonym: pseudonym },
      { ownerPublicKey: OWNER.pub, now: NOW },
    )
    assert.equal(verdict.valid, false, JSON.stringify(pseudonym))
    assert.ok(
      verdict.reasons.some((r) => expected.test(r)),
      `expected ${expected} in ${JSON.stringify(verdict.reasons)}`,
    )
  }
})

test('buildGrant refuses an unknown PARAMETER rather than defaulting around it', async () => {
  // A silently-ignored misspelling is how a grant ends up with a default nobody chose:
  // `expiresAT` ignored, `durationSeconds` absent, and the call produces something
  // unintended or throws somewhere far away.
  for (const bad of ['expiresAT', 'delegation_depth', 'fields2', 'price', 'holder']) {
    await assert.rejects(
      () => buildGrant({ ...BASE_PARAMS, [bad]: 1 }),
      /unknown parameter/,
      bad,
    )
  }
  await assert.rejects(() => buildGrant(null), /params must be a plain object/)
  await assert.rejects(() => buildGrant('x'), /params must be a plain object/)
})

test('exactly one of expiresAt or durationSeconds, and the 45-day cap is a hard ceiling', async () => {
  // The cap is pinned to the Delete Act's 45-day deletion cadence: every grant must face the
  // owner at least as often as the erasure machinery runs, and expiry is the fail-safe for
  // revocation rather than a convenience.
  assert.equal(MAX_GRANT_DURATION_S, 45 * 24 * 60 * 60)
  await assert.rejects(
    () => buildGrant({ ...BASE_PARAMS, durationSeconds: DAY }),
    /exactly one of expiresAt or durationSeconds/,
  )
  const noExpiry = { ...BASE_PARAMS }
  delete noExpiry.expiresAt
  await assert.rejects(() => buildGrant(noExpiry), /exactly one of expiresAt or durationSeconds/)

  const atCap = await buildGrant({ ...noExpiry, durationSeconds: MAX_GRANT_DURATION_S })
  assert.equal(atCap.expires_at - atCap.issued_at, MAX_GRANT_DURATION_S)
  await assert.rejects(
    () => buildGrant({ ...noExpiry, durationSeconds: MAX_GRANT_DURATION_S + 1 }),
    /exceeds the .* cap/,
  )
  await assert.rejects(() => build({ expiresAt: T0 }), /must be after issued_at/)
  await assert.rejects(() => build({ expiresAt: T0 - 1 }), /must be after issued_at/)

  // A grant that got past construction is still refused at verification.
  const overlong = await handSign(
    { ...ROOT0, expires_at: ROOT0.issued_at + MAX_GRANT_DURATION_S + 1 },
    OWNER.priv,
  )
  const verdict = await verifyGrant(overlong, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.ok(verdict.reasons.some((r) => r.startsWith('duration_exceeds_cap')), verdict.reasons)
})

test('an implausible timestamp is caught: the millisecond/second unit error is not hypothetical', async () => {
  // Passing Date.now() where seconds are expected turns a 30-day grant into an 80,000-year
  // one, and every other check in the module passes — a millisecond timestamp is a perfectly
  // well-formed integer. A range test is the only thing that catches it.
  assert.equal(MIN_PLAUSIBLE_TIME_S, 1_700_000_000)
  assert.equal(MAX_PLAUSIBLE_TIME_S, 4_000_000_000)
  await assert.rejects(
    () => build({ issuedAt: 1_800_000_000_000, expiresAt: 1_800_000_086_400 }),
    /implausible/,
  )
  for (const [issued, expires] of [
    [MIN_PLAUSIBLE_TIME_S - 1, MIN_PLAUSIBLE_TIME_S + DAY],
    [MAX_PLAUSIBLE_TIME_S - 10, MAX_PLAUSIBLE_TIME_S + 1],
  ]) {
    await assert.rejects(() => build({ issuedAt: issued, expiresAt: expires }), /implausible/)
  }
  for (const bad of [1.5, '1800000000', null, NaN, Infinity, 2 ** 53]) {
    await assert.rejects(() => build({ issuedAt: bad }), /issuedAt|issued_at/)
  }
})

// =================================================================================
// Group DD — delegation depth. Depth decreases by exactly one at each hop, is bounded
// above by 2 at issuance, and NO operation and NO party can increase it.
// =================================================================================

test('NF5-DD-001 root issuance is bounded at MAX_DELEGATION_DEPTH and coerces nothing', async () => {
  assert.equal(MAX_DELEGATION_DEPTH, 2)
  for (const depth of [0, 1, 2]) {
    const grant = await build({ delegationDepth: depth })
    assert.equal(grant.delegation_depth, depth, `depth ${depth} was not carried through exactly`)
    assert.equal(typeof grant.delegation_depth, 'number')
  }
  // 2**53 and 2**53 + 1 are here because both canonicalise to the SAME JSON number under
  // IEEE-754 doubles, so accepting either gives a value whose signature authenticates a
  // different value. "2" is here because "2" and 2 canonicalise differently, so the same
  // semantic grant would carry two commitments and a revocation entry against one would
  // miss the other.
  for (const depth of [3, 4, 255, 2 ** 31, 2 ** 53, 2 ** 53 + 1, -1, 1.5, '2', null, true, [], {}]) {
    await assert.rejects(
      () => build({ delegationDepth: depth }),
      /delegation|delegationDepth/,
      `depth ${String(depth)} accepted`,
    )
  }
  // Omission — and ONLY omission — takes the default.
  const omitted = { ...BASE_PARAMS }
  delete omitted.delegationDepth
  assert.equal((await buildGrant(omitted)).delegation_depth, 0)
  assert.equal((await build({ delegationDepth: undefined })).delegation_depth, 0)
})

test('NF5-DD-002 a depth-0 grant cannot be delegated, not even to depth 0', async () => {
  // Depth 0 is the owner's decision that this counterparty may not pass the authority on.
  // The tempting bug is to permit a depth-0 child of a depth-0 parent on the reasoning that
  // it adds no further delegable authority; it adds a HOLDER the owner never evaluated,
  // which is the thing being prevented.
  assert.throws(
    () =>
      mintDelegatedGrant(ROOT0, {
        fields: ['make'],
        counterpartyClass: 'repair-independent',
        counterpartyKey: DELEGATE.pub,
        issuedAt: T0,
        expiresAt: EXPIRES,
      }),
    /delegation_depth 0|did not\s+authorise delegation/,
  )
  assert.equal(ROOT0.delegation_depth, 0, 'the parent must be untouched by the refusal')
})

test('NF5-DD-002 an unsigned or malformed parent cannot be delegated from', async () => {
  const unsigned = { ...ROOT2, signature: null }
  assert.throws(
    () =>
      mintDelegatedGrant(unsigned, {
        fields: ['make'],
        counterpartyClass: 'repair-independent',
        counterpartyKey: DELEGATE.pub,
        issuedAt: T0,
        expiresAt: EXPIRES,
      }),
    /cannot delegate from an unsigned grant/,
  )
  for (const bad of [null, undefined, 42, 'x', [], { ...ROOT2, fields: ['gps_trace'] }]) {
    assert.throws(
      () =>
        mintDelegatedGrant(bad, {
          fields: ['make'],
          counterpartyClass: 'repair-independent',
          counterpartyKey: DELEGATE.pub,
          issuedAt: T0,
          expiresAt: EXPIRES,
        }),
      /malformed parent grant|unsigned/,
      String(bad),
    )
  }
})

test('NF5-DD-003 each minted hop decrements by exactly one', async () => {
  assert.equal(ROOT2.delegation_depth, 2)
  assert.equal(CHILD.delegation_depth, 1)
  assert.equal(GRANDCHILD.delegation_depth, 0)
  assert.equal(CHILD.parent_grant_id, ROOT2.grant_id)
  assert.equal(GRANDCHILD.parent_grant_id, CHILD.grant_id)

  assert.deepEqual(await verifyGrant(CHILD, { parentGrant: ROOT2, now: NOW }), {
    valid: true,
    reasons: [],
  })
  assert.deepEqual(await verifyGrant(GRANDCHILD, { parentGrant: CHILD, now: NOW }), {
    valid: true,
    reasons: [],
  })
})

test('NF5-DD-003 only the child whose depth is parent-1 verifies; a SAME-depth child is refused', async () => {
  // Strict decrease is what makes the bound a bound. The same-depth child is the interesting
  // failure: it looks harmless and it permits an unbounded chain, which means unbounded
  // parties and an unbounded revocation walk. The offsets are applied to GENUINELY SIGNED
  // objects, so this also shows the depth check is independent of signature validity — a
  // delegator cannot buy depth with a correct signature.
  const correct = ROOT2.delegation_depth - 1
  for (const offset of [0, -1, 1, 2, -2]) {
    const depth = correct + offset
    const forged = await handSign({ ...CHILD, delegation_depth: depth }, CP_A.priv)
    const verdict = await verifyGrant(forged, { parentGrant: ROOT2, now: NOW })

    if (offset === 0) {
      assert.deepEqual(verdict, { valid: true, reasons: [] }, 'the correct depth must verify')
      continue
    }
    assert.equal(verdict.valid, false, `depth ${depth} (offset ${offset}) verified as valid`)
    assert.equal(
      verdict.reasons.some((r) => r.startsWith('signature_invalid')),
      false,
      'the refusal must be about depth, not a broken signature',
    )
    if (depth >= 0 && depth <= MAX_DELEGATION_DEPTH) {
      assert.ok(
        verdict.reasons.some((r) => r.startsWith('delegation_depth_not_decremented')),
        `${depth}: ${verdict.reasons}`,
      )
    } else {
      // Out of range is caught one layer earlier, by the structural bound, and the
      // structural refusal short-circuits the lineage check. Refusing sooner is correct;
      // note only that the reason code differs from NF-5 §6 DD-003's literal text.
      assert.ok(
        verdict.reasons.some((r) => r.startsWith('delegation_depth_invalid')),
        `${depth}: ${verdict.reasons}`,
      )
    }
  }
})

test('NF5-DD-004 the ladder terminates at exactly three grants, and refuses at MINTING', async () => {
  // Refusal at minting matters because a grant that exists but never verifies is an artifact
  // in a database, presented to a counterparty as authority, that will be honoured by any
  // enforcement point with a bug. The failure should occur before the object exists.
  const chain = [ROOT2]
  let current = ROOT2
  let refusal = null
  for (let hop = 0; hop < 8; hop += 1) {
    try {
      const child = mintDelegatedGrant(current, {
        fields: ['make'],
        counterpartyClass: 'repair-independent',
        counterpartyKey: SIBLINGS[hop % SIBLINGS.length].pub,
        issuedAt: T0,
        expiresAt: EXPIRES,
      })
      const signerKey = current === ROOT2 ? CP_A : SIBLINGS[(hop - 1 + SIBLINGS.length) % SIBLINGS.length]
      current = await signGrant(child, signerKey.priv)
      chain.push(current)
    } catch (err) {
      refusal = err
      break
    }
  }
  assert.equal(chain.length, 3, `expected root -> child -> grandchild, got ${chain.length}`)
  assert.deepEqual(chain.map((g) => g.delegation_depth), [2, 1, 0])
  assert.ok(refusal instanceof Error)
  assert.match(refusal.message, /delegation_depth 0|no operation that adds depth/)
})

test('[control] NF5-DD-005 breadth is permitted; only depth is bounded', async () => {
  // NF-WP-1 bounds DEPTH, not fan-out. Breadth is governed by attributability and cascade
  // instead: every sibling records the same parent_grant_id, so the owner sees the whole
  // subtree and one revocation cuts all of it. An implementation that limited fan-out would
  // be adding a restriction the standard does not contain — and one that limited depth by
  // accident of limiting fan-out would pass DD-004 vacuously.
  const before = canonicalize(ROOT2)
  const ids = new Set()
  for (const sibling of SIBLINGS) {
    const child = mintDelegatedGrant(ROOT2, {
      fields: ['make', 'odometer_km'],
      counterpartyClass: 'fleet-operator',
      counterpartyKey: sibling.pub,
      issuedAt: T0,
      expiresAt: EXPIRES - 1,
    })
    const signed = await signGrant(child, CP_A.priv)
    assert.equal(signed.delegation_depth, 1)
    assert.equal(signed.parent_grant_id, ROOT2.grant_id)
    assert.deepEqual(await verifyGrant(signed, { parentGrant: ROOT2, now: NOW }), {
      valid: true,
      reasons: [],
    })
    ids.add(signed.grant_id)
  }
  assert.equal(ids.size, 5, 'siblings must have distinct grant_ids')
  assert.equal(canonicalize(ROOT2), before, 'minting a sibling altered the root')
})

test('NF5-DD-006 a delegated grant cannot be verified from its leaf alone', async () => {
  // The expected signer of a sub-grant is the delegator, whose key lives in the PARENT. A
  // verifier with no parent has no signer key and therefore cannot have checked the
  // signature; returning valid in that state is the failure this assertion exists to catch.
  const noParent = await verifyGrant(CHILD, { now: NOW })
  assert.equal(noParent.valid, false)
  assert.ok(noParent.reasons.some((r) => r.startsWith('delegation_parent_missing')), noParent.reasons)

  // Even handing it the owner key must not rescue it: the owner did not sign this link.
  const wrongKey = await verifyGrant(CHILD, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(wrongKey.valid, false)

  const unrelated = await verifyGrant(CHILD, { parentGrant: ROOT1, now: NOW })
  assert.equal(unrelated.valid, false)
  assert.ok(unrelated.reasons.some((r) => r.startsWith('delegation_parent_mismatch')), unrelated.reasons)

  const unsignedParent = await verifyGrant(CHILD, { parentGrant: { ...ROOT2, signature: null }, now: NOW })
  assert.equal(unsignedParent.valid, false)
  assert.ok(unsignedParent.reasons.some((r) => /parent grant is unsigned/.test(r)), unsignedParent.reasons)

  // [control]
  assert.deepEqual(await verifyGrant(CHILD, { parentGrant: ROOT2, now: NOW }), {
    valid: true,
    reasons: [],
  })
})

test('NF5-DD-006 a parent supplied for a ROOT grant is itself a mismatch', async () => {
  const verdict = await verifyGrant(ROOT0, { ownerPublicKey: OWNER.pub, parentGrant: ROOT2, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('delegation_parent_mismatch')), verdict.reasons)
})

test('NF5-DD-007 depth is inside the signed bytes', async () => {
  // Depth would be worthless as a bound if a holder could edit it. This pins the MECHANISM
  // rather than the outcome: the bound is enforced by the signature covering the field, not
  // by a range check some downstream component might skip. A verifier that rejected the
  // tampered grant for any OTHER reason would be signalling that depth is not authenticated.
  const tampered = { ...ROOT1, delegation_depth: 2 }
  const verdict = await verifyGrant(tampered, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('signature_invalid')), verdict.reasons)
  assert.deepEqual(codes(verdict.reasons), ['signature_invalid'])
})

test('NF5-DD-008 sub-grant narrowing invariants hold on every axis', async () => {
  const child = mintDelegatedGrant(ROOT2, {
    fields: ['make', 'odometer_km'],
    counterpartyClass: 'fleet-operator',
    counterpartyKey: DELEGATE.pub,
    issuedAt: T0,
    expiresAt: EXPIRES,
  })
  const freshPseudonym = { ...child.vehicle_pseudonym, value: await fixedB64('other-pseudonym', 32) }

  const cases = [
    ['a fields broadened', { fields: ['make', 'odometer_km', 'state_of_charge_pct'] }, 'delegation_fields_broadened'],
    ['b purpose changed', { purpose: 'dppa-2721b-6' }, 'delegation_purpose_changed'],
    ['c expiry extends parent', { expires_at: ROOT2.expires_at + 1 }, 'delegation_expiry_extends_parent'],
    ['d revocation key changed', { revocation_key_id: await fixedB64('fresh-thumbprint', 32) }, 'delegation_revocation_key_changed'],
    ['e pseudonym recomputed', { vehicle_pseudonym: freshPseudonym }, 'delegation_pseudonym_mismatch'],
  ]
  for (const [label, override, expected] of cases) {
    const forged = await handSign({ ...child, ...override }, CP_A.priv)
    const verdict = await verifyGrant(forged, { parentGrant: ROOT2, now: NOW })
    assert.equal(verdict.valid, false, label)
    assert.ok(verdict.reasons.some((r) => r.startsWith(expected)), `${label}: ${verdict.reasons}`)
  }

  // f — a grant that is its own parent. The cheapest possible cycle.
  const selfParent = await handSign({ ...child, parent_grant_id: child.grant_id }, CP_A.priv)
  const selfVerdict = await verifyGrant(selfParent, { parentGrant: ROOT2, now: NOW })
  assert.equal(selfVerdict.valid, false)
  assert.ok(
    selfVerdict.reasons.some((r) => r.startsWith('parent_grant_id_malformed')),
    selfVerdict.reasons,
  )
  const selfRenewal = { ...ROOT0, renewal_of: ROOT0.grant_id }
  const renewalVerdict = await verifyGrant(selfRenewal, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.ok(renewalVerdict.reasons.some((r) => r.startsWith('renewal_of_malformed')), renewalVerdict.reasons)

  // g [control]
  const good = await signGrant(child, CP_A.priv)
  assert.deepEqual(await verifyGrant(good, { parentGrant: ROOT2, now: NOW }), { valid: true, reasons: [] })
})

test('NF5-DD-009 renewal cannot raise depth, and a delegate cannot renew itself', async () => {
  // Renewal is the second place depth could be synthesised, and (c) settles who may extend a
  // delegate's authority: the delegator, by minting again against a live parent. A renewal
  // path open to the delegate would let it extend its own authority.
  await assert.rejects(
    () =>
      renewGrant(ROOT0, {
        vin: VIN,
        pseudonymSalt: SALT,
        pseudonymEpoch: 8,
        fields: ['make'],
        issuedAt: T0 + DAY,
        expiresAt: T0 + 2 * DAY,
        delegationDepth: 1,
      }),
    /renewal cannot raise delegation_depth/,
  )
  const control = await renewGrant(ROOT0, {
    vin: VIN,
    pseudonymSalt: SALT,
    pseudonymEpoch: 8,
    fields: ['make'],
    issuedAt: T0 + DAY,
    expiresAt: T0 + 2 * DAY,
    delegationDepth: 0,
  })
  assert.equal(control.delegation_depth, 0)

  await assert.rejects(
    () =>
      renewGrant(CHILD, {
        vin: VIN,
        pseudonymSalt: SALT,
        pseudonymEpoch: 8,
        fields: ['make'],
        issuedAt: T0 + DAY,
        expiresAt: T0 + 2 * DAY,
      }),
    /cannot renew a delegated sub-grant/,
  )
})

test('depth cannot be laundered by RE-SIGNING', async () => {
  // Two paths a holder might try. (1) Sign the grant again: refused outright, because the
  // only legitimate reasons to want a second signature over one payload are key rotation and
  // repudiation-shopping, both of which are served by minting a new grant. (2) Strip the
  // signature, raise the depth, and sign afresh with the delegator's own key: the signature
  // is then genuinely valid and the grant is still refused, because the depth invariant is
  // checked against the parent and not against the signature.
  await assert.rejects(() => signGrant(CHILD, CP_A.priv), /already signed/)
  await assert.rejects(() => signGrant(ROOT0, OWNER.priv), /already signed/)

  const laundered = await handSign({ ...CHILD, delegation_depth: 2 }, CP_A.priv)
  const verdict = await verifyGrant(laundered, { parentGrant: ROOT2, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(
    verdict.reasons.some((r) => r.startsWith('delegation_depth_not_decremented')),
    verdict.reasons,
  )
  assert.equal(verdict.reasons.some((r) => r.startsWith('signature_invalid')), false)
})

test('depth cannot be laundered by FORGING a parent id', async () => {
  const forgedId = generateGrantId()
  const claimsElsewhere = await handSign({ ...CHILD, parent_grant_id: forgedId }, CP_A.priv)

  const noParent = await verifyGrant(claimsElsewhere, { now: NOW })
  assert.ok(noParent.reasons.some((r) => r.startsWith('delegation_parent_missing')), noParent.reasons)

  const wrongParent = await verifyGrant(claimsElsewhere, { parentGrant: ROOT2, now: NOW })
  assert.equal(wrongParent.valid, false)
  assert.ok(
    wrongParent.reasons.some((r) => r.startsWith('delegation_parent_mismatch')),
    wrongParent.reasons,
  )
})

test('a fabricated parent does not launder authority, because the parent must itself verify', async () => {
  // A DELIBERATE PROPERTY OF THE CONTRACT, recorded so it is chosen rather than discovered.
  // `verifyGrant` checks a child against the parent it is HANDED; it does not verify the
  // parent's own signature, because the parent's signer key is one link further up. So an
  // enforcement point must walk and verify the whole chain — which is the same walk
  // revocation makes, so the two cannot drift apart.
  const fabricated = {
    ...ROOT2,
    fields: ['dtc_codes', 'make', 'odometer_km', 'state_of_charge_pct'],
  }
  const broaderChild = await handSign(
    { ...CHILD, fields: ['make', 'odometer_km', 'state_of_charge_pct'] },
    CP_A.priv,
  )
  const againstFabricated = await verifyGrant(broaderChild, { parentGrant: fabricated, now: NOW })
  assert.equal(againstFabricated.valid, true, 'fixture assumption for the assertion below')

  // …and the fabricated parent is exactly what fails, which is where the chain walk catches it.
  const parentVerdict = await verifyGrant(fabricated, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(parentVerdict.valid, false)
  assert.ok(parentVerdict.reasons.some((r) => r.startsWith('signature_invalid')), parentVerdict.reasons)

  // Against the REAL parent the broadened child dies on its own merits.
  const real = await verifyGrant(broaderChild, { parentGrant: ROOT2, now: NOW })
  assert.equal(real.valid, false)
  assert.ok(real.reasons.some((r) => r.startsWith('delegation_fields_broadened')), real.reasons)
})

test('depth cannot be laundered by CONSTRUCTING A CYCLE', async () => {
  // Two grants each claiming the other as parent. No depth assignment satisfies both
  // directions at once — d = d' - 1 and d' = d - 1 have no solution — so a cycle is
  // structurally impossible rather than merely detected by a visited-set the walker might
  // forget to keep.
  const idA = generateGrantId()
  const idB = generateGrantId()
  const a = await handSign({ ...CHILD, grant_id: idA, parent_grant_id: idB }, DELEGATE.priv)
  const b = await handSign({ ...CHILD, grant_id: idB, parent_grant_id: idA }, DELEGATE.priv)

  for (const [child, parent, label] of [[a, b, 'A under B'], [b, a, 'B under A']]) {
    const verdict = await verifyGrant(child, { parentGrant: parent, now: NOW })
    assert.equal(verdict.valid, false, label)
    assert.ok(
      verdict.reasons.some((r) => r.startsWith('delegation_depth_not_decremented')),
      `${label}: ${verdict.reasons}`,
    )
  }

  // A three-cycle fails on the same arithmetic, at whichever link is inspected.
  const idC = generateGrantId()
  const c1 = await handSign({ ...CHILD, grant_id: idA, parent_grant_id: idB, delegation_depth: 2 }, DELEGATE.priv)
  const c2 = await handSign({ ...CHILD, grant_id: idB, parent_grant_id: idC, delegation_depth: 1 }, DELEGATE.priv)
  const c3 = await handSign({ ...CHILD, grant_id: idC, parent_grant_id: idA, delegation_depth: 0 }, DELEGATE.priv)
  const closing = await verifyGrant(c3, { parentGrant: c1, now: NOW })
  assert.equal(closing.valid, false, 'the cycle-closing link must fail')
  assert.ok(
    closing.reasons.some((r) => r.startsWith('delegation_depth_not_decremented')),
    closing.reasons,
  )
  assert.equal(c2.delegation_depth, 1)
})

// =================================================================================
// Group GC — sign/verify round trip, tamper detection, clock, binding, commitment
// =================================================================================

test('[control] the round trip verifies with the key supplied as a string OR as a CryptoKey', async () => {
  const asString = await verifyGrant(ROOT0, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.deepEqual(asString, { valid: true, reasons: [] })
  const asKey = await verifyGrant(ROOT0, {
    ownerPublicKey: await importPublicKeyBase64url(OWNER.pub),
    now: NOW,
  })
  assert.deepEqual(asKey, { valid: true, reasons: [] })
})

test('the WRONG owner key fails, and a missing key fails closed rather than passing', async () => {
  // There is no path through verifyGrant that returns valid on an unchecked signature. The
  // signer key is deliberately NOT in the grant: an owner key inside it would be a
  // cross-counterparty join key and would undo the per-audience pseudonym work entirely.
  const wrong = await verifyGrant(ROOT0, { ownerPublicKey: OWNER_2.pub, now: NOW })
  assert.equal(wrong.valid, false)
  assert.ok(wrong.reasons.some((r) => r.startsWith('signature_invalid')), wrong.reasons)

  for (const opts of [{ now: NOW }, { ownerPublicKey: undefined, now: NOW }, { ownerPublicKey: null, now: NOW }]) {
    const verdict = await verifyGrant(ROOT0, opts)
    assert.equal(verdict.valid, false)
    assert.ok(verdict.reasons.some((r) => r.startsWith('verifier_key_missing')), verdict.reasons)
  }
  for (const junk of ['not-a-key', 'A'.repeat(43), 42, {}]) {
    const verdict = await verifyGrant(ROOT0, { ownerPublicKey: junk, now: NOW })
    assert.equal(verdict.valid, false, String(junk))
  }
  assert.equal(GRANT_KEYS.includes('owner_public_key'), false)
  assert.equal(GRANT_KEYS.includes('issuer_key'), false)
})

test('an unsigned grant never verifies', async () => {
  const unsigned = await build()
  const verdict = await verifyGrant(unsigned, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('signature_missing')), verdict.reasons)
})

test('tamper detection on EVERY field of a signed grant', async () => {
  const otherId = generateGrantId()
  const cases = [
    ['v', { v: 'nf2-grant/2' }, 'schema_version_unsupported'],
    ['grant_id', { grant_id: otherId }, 'signature_invalid'],
    ['vehicle_pseudonym.value', { vehicle_pseudonym: { ...ROOT0.vehicle_pseudonym, value: await fixedB64('tamper-pseudonym', 32) } }, 'signature_invalid'],
    ['vehicle_pseudonym.epoch', { vehicle_pseudonym: { ...ROOT0.vehicle_pseudonym, epoch: 8 } }, 'signature_invalid'],
    ['fields', { fields: ['make'] }, 'signature_invalid'],
    ['purpose', { purpose: 'dppa-2721b-5' }, 'signature_invalid'],
    ['issued_at', { issued_at: T0 - 60 }, 'signature_invalid'],
    ['expires_at', { expires_at: EXPIRES + 60 }, 'signature_invalid'],
    ['counterparty_class', { counterparty_class: 'insurer', vehicle_pseudonym: { ...ROOT0.vehicle_pseudonym, audience: 'insurer' } }, 'signature_invalid'],
    ['counterparty_key', { counterparty_key: CP_B.pub }, 'signature_invalid'],
    ['revocation_key_id', { revocation_key_id: await fixedB64('tamper-revocation', 32) }, 'signature_invalid'],
    ['delegation_depth', { delegation_depth: 1 }, 'signature_invalid'],
    ['renewal_of', { renewal_of: otherId }, 'signature_invalid'],
    ['parent_grant_id', { parent_grant_id: otherId }, 'delegation_parent_missing'],
    ['signature', { signature: `${ROOT0.signature[0] === 'A' ? 'B' : 'A'}${ROOT0.signature.slice(1)}` }, 'signature_invalid'],
  ]
  const covered = new Set()
  for (const [label, override, expected] of cases) {
    const tampered = { ...ROOT0, ...override }
    assert.notEqual(canonicalize(tampered), canonicalize(ROOT0), `${label}: fixture did not change the grant`)
    const verdict = await verifyGrant(tampered, { ownerPublicKey: OWNER.pub, now: NOW })
    assert.equal(verdict.valid, false, `${label} tampering went undetected`)
    assert.ok(verdict.reasons.some((r) => r.startsWith(expected)), `${label}: ${verdict.reasons}`)
    covered.add(label.split('.')[0])
  }
  // Every key in the closed set is exercised.
  assert.deepEqual([...covered].sort(), [...GRANT_KEYS].sort())
})

test('CANONICALISATION MISMATCH: key insertion order is not part of the signature', async () => {
  // The point of JCS. A grant reconstructed from a D1 row in a different column order must
  // produce the same bytes, the same verdict, and the same commitment — otherwise the
  // signature would verify for the issuer and fail for everyone else.
  const shuffled = {}
  for (const key of [...GRANT_KEYS].reverse()) shuffled[key] = ROOT0[key]
  assert.notDeepEqual(Object.keys(shuffled), Object.keys(ROOT0))
  assert.equal(canonicalize(shuffled), canonicalize(ROOT0))
  assert.deepEqual(await verifyGrant(shuffled, { ownerPublicKey: OWNER.pub, now: NOW }), {
    valid: true,
    reasons: [],
  })
  assert.equal(await deriveGrantCommitment(shuffled), await deriveGrantCommitment(ROOT0))
})

test('CANONICALISATION MISMATCH: an out-of-order field array is refused', async () => {
  // JCS treats array order as significant and gives arrays no sort, so an unsorted set would
  // give one semantic grant several commitments — and NF-4 keys revocation by commitment.
  const unsorted = await handSign({ ...ROOT0, fields: ['odometer_km', 'make'] }, OWNER.priv)
  const verdict = await verifyGrant(unsorted, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  assert.ok(verdict.reasons.some((r) => r.startsWith('fields_not_canonical_order')), verdict.reasons)
})

test('CANONICALISATION MISMATCH: type confusion and un-canonicalisable numbers are refused', async () => {
  const cases = [
    [{ delegation_depth: '0' }, 'delegation_depth_invalid'],
    [{ delegation_depth: 1.5 }, 'delegation_depth_invalid'],
    [{ delegation_depth: -1 }, 'delegation_depth_invalid'],
    [{ delegation_depth: 3 }, 'delegation_depth_invalid'],
    [{ issued_at: '1800000000' }, 'issued_at_malformed'],
    [{ expires_at: 1.5 }, 'expires_at_malformed'],
    [{ grant_id: 123 }, 'grant_id_malformed'],
    [{ counterparty_key: `${CP_A.pub}=` }, 'counterparty_key_malformed'],
    [{ signature: 'A'.repeat(85) }, 'signature_malformed'],
  ]
  for (const [override, expected] of cases) {
    const verdict = await verifyGrant({ ...ROOT0, ...override }, { ownerPublicKey: OWNER.pub, now: NOW })
    assert.equal(verdict.valid, false, JSON.stringify(override))
    assert.ok(verdict.reasons.some((r) => r.startsWith(expected)), `${JSON.stringify(override)}: ${verdict.reasons}`)
  }

  // Negative zero passes every range check (Number.isSafeInteger(-0) is true and -0 < 0 is
  // false) and is then refused by canonicalisation, which is where the ambiguity actually
  // lives: RFC 8785 would serialise it as "0", so the caller could not tell afterwards which
  // value was signed. It fails closed — never valid — which is the property that matters.
  const negZero = await verifyGrant({ ...ROOT0, delegation_depth: -0 }, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(negZero.valid, false)
  assert.ok(negZero.reasons.some((r) => r.startsWith('signature_invalid')), negZero.reasons)
  await assert.rejects(() => build({ delegationDepth: -0 }).then((g) => signGrant(g, OWNER.priv)), /negative zero/)
})

test('EXPIRY is injected, never read from the wall clock', async () => {
  const key = { ownerPublicKey: OWNER.pub }
  assert.equal((await verifyGrant(ROOT0, { ...key, now: T0 })).valid, true)
  assert.equal((await verifyGrant(ROOT0, { ...key, now: EXPIRES - 1 })).valid, true)

  for (const now of [EXPIRES, EXPIRES + 1, EXPIRES + 10 * DAY]) {
    const verdict = await verifyGrant(ROOT0, { ...key, now })
    assert.equal(verdict.valid, false, `now=${now}`)
    assert.ok(verdict.reasons.some((r) => r.startsWith('expired')), verdict.reasons)
  }
  // The boundary is exclusive at expiry: `now >= expires_at` is expired, so a grant is never
  // live on the instant it dies.
  assert.equal((await verifyGrant(ROOT0, { ...key, now: EXPIRES })).valid, false)

  // Injection really is what decides: one grant, two verdicts, no clock involved.
  assert.notDeepEqual(
    await verifyGrant(ROOT0, { ...key, now: NOW }),
    await verifyGrant(ROOT0, { ...key, now: EXPIRES + 1 }),
  )
})

test('CLOCK SKEW is bounded and configurable, and a future grant is refused past the bound', async () => {
  assert.equal(DEFAULT_CLOCK_SKEW_S, 300)
  const key = { ownerPublicKey: OWNER.pub }

  // Inside the default tolerance for a fast issuer clock.
  assert.equal((await verifyGrant(ROOT0, { ...key, now: T0 - DEFAULT_CLOCK_SKEW_S })).valid, true)
  // One second past it.
  const past = await verifyGrant(ROOT0, { ...key, now: T0 - DEFAULT_CLOCK_SKEW_S - 1 })
  assert.equal(past.valid, false)
  assert.ok(past.reasons.some((r) => r.startsWith('issued_in_future')), past.reasons)

  // With tolerance switched off, even one second early is refused.
  const strict = await verifyGrant(ROOT0, { ...key, now: T0 - 1, clockSkewS: 0 })
  assert.equal(strict.valid, false)
  assert.ok(strict.reasons.some((r) => r.startsWith('issued_in_future')), strict.reasons)
  assert.equal((await verifyGrant(ROOT0, { ...key, now: T0, clockSkewS: 0 })).valid, true)

  // A malformed `now` is an internal refusal, not a fall-back to the wall clock.
  for (const bad of [1.5, '1800000000', NaN, Infinity, 2 ** 53]) {
    const verdict = await verifyGrant(ROOT0, { ...key, now: bad })
    assert.equal(verdict.valid, false, String(bad))
    assert.ok(verdict.reasons.some((r) => /opts\.now must be an integer/.test(r)), verdict.reasons)
  }
})

test('COUNTERPARTY BINDING: a different holder cannot present the grant', async () => {
  // A grant is not a bearer token. Binding to a KEY rather than a name is what makes it
  // unreplayable: a name is an assertion the presenter makes about themselves, a key is a
  // challenge they either answer or do not. Stolen grant plus no private key equals nothing
  // — which is also why a grant can be logged and shipped over an untrusted bearer.
  const bound = await verifyGrant(ROOT0, { ownerPublicKey: OWNER.pub, now: NOW, presenterKey: CP_A.pub })
  assert.deepEqual(bound, { valid: true, reasons: [] })

  for (const impostor of [CP_B.pub, OWNER.pub, DELEGATE.pub, '', 'x', 42, null, {}]) {
    const verdict = await verifyGrant(ROOT0, {
      ownerPublicKey: OWNER.pub,
      now: NOW,
      presenterKey: impostor,
    })
    assert.equal(verdict.valid, false, String(impostor))
    assert.ok(
      verdict.reasons.some((r) => r.startsWith('counterparty_binding_mismatch')),
      `${String(impostor)}: ${verdict.reasons}`,
    )
  }

  // Omitting presenterKey skips the check: the binding is proved at the broker edge by
  // challenge/response, and this function is a pure predicate over what it is handed.
  const unbound = await verifyGrant(ROOT0, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.deepEqual(unbound, { valid: true, reasons: [] })

  // The delegated case binds to the DELEGATE, not to the original counterparty.
  assert.equal(
    (await verifyGrant(CHILD, { parentGrant: ROOT2, now: NOW, presenterKey: DELEGATE.pub })).valid,
    true,
  )
  assert.equal(
    (await verifyGrant(CHILD, { parentGrant: ROOT2, now: NOW, presenterKey: CP_A.pub })).valid,
    false,
  )
})

test('REVOCATION is not this module’s knowledge, and opts.revoked is honoured when supplied', async () => {
  // `valid: true` is NOT an authorisation decision. A caller that serves data on it without
  // having read the NF-4 revocation table in the same request has reintroduced the exact
  // failure the revocable-capability design exists to prevent.
  const revoked = await verifyGrant(ROOT0, { ownerPublicKey: OWNER.pub, now: NOW, revoked: true })
  assert.equal(revoked.valid, false)
  assert.ok(revoked.reasons.some((r) => r.startsWith('revoked')), revoked.reasons)
  assert.ok(revoked.reasons.some((r) => r.includes(ROOT0.grant_id)))

  for (const value of [false, undefined, 'true', 1]) {
    const verdict = await verifyGrant(ROOT0, { ownerPublicKey: OWNER.pub, now: NOW, revoked: value })
    assert.equal(verdict.valid, true, `revoked=${String(value)} must not be truthy-coerced`)
  }
  assert.equal(GRANT_KEYS.includes('revoked'), false, 'revocation state must not live in the grant')
})

test('verifyGrant NEVER throws, whatever it is handed', async () => {
  // A verifier that throws on malformed input hands any caller a denial of service.
  const throwingGetter = { ...ROOT0 }
  Object.defineProperty(throwingGetter, 'v', {
    get() {
      throw new Error('boom')
    },
    enumerable: true,
    configurable: true,
  })
  const cyclic = { ...ROOT0 }
  cyclic.vehicle_pseudonym = { ...ROOT0.vehicle_pseudonym }
  cyclic.vehicle_pseudonym.value = cyclic

  const junk = [
    undefined, null, 0, -1, NaN, '', 'grant', true, false, [], [ROOT0], () => ROOT0,
    new Date(0), new Map(), Symbol('g'), Object.create(null), {}, { v: SCHEMA_VERSION },
    throwingGetter, cyclic, { ...ROOT0, fields: null }, { ...ROOT0, vehicle_pseudonym: [] },
    JSON.parse(JSON.stringify(ROOT0)),
  ]
  // `String(Object.create(null))` itself throws, so labels go through a safe stringifier.
  // The harness must not be the thing that blows up while testing that nothing blows up.
  const label = (v) => {
    try {
      return v !== null && typeof v === 'object' ? Object.prototype.toString.call(v) : String(v)
    } catch {
      return '(unstringifiable)'
    }
  }

  for (const input of junk) {
    let verdict
    await assert.doesNotReject(async () => {
      verdict = await verifyGrant(input, { ownerPublicKey: OWNER.pub, now: NOW })
    }, `verifyGrant threw on ${label(input)}`)
    assert.equal(typeof verdict.valid, 'boolean', label(input))
    assert.ok(Array.isArray(verdict.reasons), label(input))
    for (const reason of verdict.reasons) assert.equal(typeof reason, 'string')
    // `valid` is exactly "no reasons" — there is no third state and no partial credit.
    assert.equal(
      verdict.valid,
      verdict.reasons.length === 0,
      `valid must be exactly "no reasons" for ${label(input)}`,
    )
  }
  // Explicitly: a JSON round trip of a real grant still verifies, and the throwing getter
  // becomes a reason rather than an exception.
  assert.deepEqual(
    await verifyGrant(JSON.parse(JSON.stringify(ROOT0)), { ownerPublicKey: OWNER.pub, now: NOW }),
    { valid: true, reasons: [] },
  )
  const internal = await verifyGrant(throwingGetter, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(internal.valid, false)
  assert.ok(internal.reasons.some((r) => r.startsWith('internal')), internal.reasons)
})

test('verifyGrant never throws on a malformed OPTIONS bag either', async () => {
  for (const opts of [undefined, {}, null, { parentGrant: 42 }, { forbiddenRevocationKeyIds: 'x' }, { clockSkewS: 'x' }]) {
    let verdict
    await assert.doesNotReject(async () => {
      verdict = await verifyGrant(ROOT0, opts ?? undefined)
    }, JSON.stringify(opts))
    assert.equal(typeof verdict.valid, 'boolean')
  }
})

test('verifyGrant collects EVERY reason rather than stopping at the first', async () => {
  // The suite needs to assert which rule fired, and an operator debugging a rejected grant
  // needs the whole picture.
  const broken = await handSign(
    {
      ...ROOT0,
      purpose: 'not-a-dppa-purpose',
      counterparty_class: 'data-broker',
      delegation_depth: 7,
      grant_id: 'too-short',
    },
    OWNER.priv,
  )
  const verdict = await verifyGrant(broken, { ownerPublicKey: OWNER.pub, now: NOW })
  assert.equal(verdict.valid, false)
  for (const expected of [
    'grant_id_malformed',
    'purpose_unknown',
    'counterparty_class_unknown',
    'delegation_depth_invalid',
    'pseudonym_audience_mismatch',
  ]) {
    assert.ok(verdict.reasons.some((r) => r.startsWith(expected)), `${expected} missing: ${verdict.reasons}`)
  }
  assert.ok(verdict.reasons.length >= 5)

  // Multiple simultaneous failures across different phases are all reported.
  const multi = await verifyGrant(
    { ...ROOT0, revocation_key_id: ROOT0.counterparty_key },
    { ownerPublicKey: OWNER.pub, now: EXPIRES + 1, presenterKey: CP_B.pub, revoked: true },
  )
  assert.equal(multi.valid, false)
  for (const expected of [
    'expired',
    'counterparty_binding_mismatch',
    'revocation_key_held_by_counterparty',
    'signature_invalid',
    'revoked',
  ]) {
    assert.ok(multi.reasons.some((r) => r.startsWith(expected)), `${expected} missing: ${multi.reasons}`)
  }
})

test('deriveGrantCommitment refuses unsigned and invalid grants, and is stable', async () => {
  const unsigned = await build()
  await assert.rejects(() => deriveGrantCommitment(unsigned), /refusing to commit to an unsigned grant/)
  await assert.rejects(() => deriveGrantCommitment({ ...ROOT0, extra: 1 }), /refusing to commit to an invalid grant/)
  await assert.rejects(() => deriveGrantCommitment(null), /refusing to commit to an invalid grant/)
  await assert.rejects(() => deriveGrantCommitment('x'), /refusing to commit to an invalid grant/)

  const first = await deriveGrantCommitment(ROOT0)
  for (let i = 0; i < 8; i += 1) assert.equal(await deriveGrantCommitment(ROOT0), first)
  assert.equal(await deriveGrantCommitment(JSON.parse(JSON.stringify(ROOT0))), first)
  assert.notEqual(await deriveGrantCommitment(ROOT1), first)
})

test('the commitment binds the ISSUER, which is why unsigned grants are refused', async () => {
  // The grant carries no signer public key (anti-correlation), so the payload alone does not
  // identify the issuer — two owners could in principle produce identical payloads. The
  // signature is the only field that distinguishes them, so a commitment excluding it would
  // be ambiguous about which grant it commits to, and an NF-4 revocation entry keyed by it
  // could match a grant the owner never issued.
  const payload = await build()
  const byOwner = await signGrant(payload, OWNER.priv)
  const byOther = await signGrant(payload, OWNER_2.priv)

  assert.deepEqual(
    [...grantSigningInput(byOwner)],
    [...grantSigningInput(byOther)],
    'fixture assumption: the two grants share a byte-identical payload',
  )
  assert.notEqual(byOwner.signature, byOther.signature)
  assert.notEqual(
    await deriveGrantCommitment(byOwner),
    await deriveGrantCommitment(byOther),
    'the commitment does not cover the signature: two issuers would collide',
  )
})

// =================================================================================
// Non-transferability — a transferable capability is an asset, and an asset has a price
// =================================================================================

test('[control] assertNonTransferable accepts a well-formed grant and the true holder', async () => {
  assert.equal(assertNonTransferable(ROOT0), true)
  assert.equal(assertNonTransferable(ROOT0, ROOT0.counterparty_key), true)
  assert.equal(assertNonTransferable(ROOT0, null), true)
})

test('a grant cannot be presented by, transferred to, or reissued to another holder', async () => {
  for (const other of [CP_B.pub, DELEGATE.pub, OWNER.pub, '', 'x']) {
    assert.throws(
      () => assertNonTransferable(ROOT0, other),
      /bound to another holder's key and cannot be transferred/,
      other,
    )
  }
  assert.throws(() => assertNonTransferable({ ...ROOT0, counterparty_key: 'bad' }), /no well-formed counterparty_key/)
  for (const bad of [null, undefined, 42, 'x', []]) {
    assert.throws(() => assertNonTransferable(bad), /must be a plain object/, String(bad))
  }
})

test('every holder-mutation field is refused, by assertNonTransferable AND by verifyGrant', async () => {
  // None of these are in GRANT_KEYS, so the closed-key check already rejects them; the second
  // check exists so the assertion is meaningful on an arbitrary object and so the conformance
  // suite has something concrete to assert against.
  for (const field of V_HOLDER_MUTATION_FIELDS) {
    const mutated = { ...ROOT0, [field]: CP_B.pub }
    assert.throws(
      () => assertNonTransferable(mutated),
      new RegExp(`non-transferability violated: grant carries "${field}"`),
      field,
    )
    const verdict = await verifyGrant(mutated, { ownerPublicKey: OWNER.pub, now: NOW })
    assert.equal(verdict.valid, false, field)
    assert.ok(
      verdict.reasons.some((r) => r.startsWith('transferable_field_present') && r.includes(field)),
      `${field}: ${verdict.reasons}`,
    )
  }
})

test('the module offers no operation that moves a capability to a new holder', async () => {
  // Delegation is the bounded, attributable, cascade-revocable alternative — different in
  // kind from transfer, not in degree. A transfer erases its own provenance, which is most of
  // its appeal to the transferring party.
  const surface = Object.keys(nf2)
  for (const name of ['transferGrant', 'assignGrant', 'reissueGrant', 'setHolder', 'changeCounterparty']) {
    assert.equal(surface.includes(name), false, `${name} must not exist`)
  }
  // The parent survives delegation unchanged: additive and bounded, never a move.
  const before = canonicalize(ROOT2)
  mintDelegatedGrant(ROOT2, {
    fields: ['make'],
    counterpartyClass: 'municipal-agency',
    counterpartyKey: CP_B.pub,
    issuedAt: T0,
    expiresAt: EXPIRES,
  })
  assert.equal(canonicalize(ROOT2), before)
  assert.equal(ROOT2.counterparty_key, CP_A.pub)
})
