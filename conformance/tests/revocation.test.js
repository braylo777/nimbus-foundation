/**
 * NF-5 conformance — NF-4 revocation (`broker/src/nf4-revocation.js`).
 *
 * NF-WP-1 §8.4 (propagation, cascade, staleness bound), §9.5 (mutable storage), §10.1
 * (Refusals 1 and 2). A Consent Grant is a *revocable* capability only if three things hold
 * at once, and this file is organised as those three plus the commitment:
 *
 *   AUTHORITY   only the key the GRANT names may revoke; the broker can neither revoke on the
 *               owner's behalf nor refuse a valid owner revocation.
 *   REACH       revocation reaches every transitive descendant, idempotently and cycle-safely,
 *               and the kill switch reaches everything under one owner-held key.
 *   TIMELINESS  a cached ALLOW older than the staleness bound is re-derived, never honoured.
 *   REFUSAL 2   the on-chain artefact is a commitment and nothing else: it yields inclusion
 *               and non-inclusion proofs, and it is not invertible back to a VIN or a
 *               pseudonym by anyone enumerating the (enumerable) VIN space.
 *
 * Determinism (NF-5 §4.4): no network, no wall clock — every instant is injected — and the
 * VIN, salt, epoch and field set are fixtures. Ed25519 keypairs are generated because a
 * non-extractable CryptoKey cannot be a literal; no assertion depends on their values.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ANCHOR_KEYS,
  DECISION_KEYS,
  DEFAULT_MAX_DECISION_AGE_S,
  MAX_PERMITTED_DECISION_AGE_S,
  REVOCATION_KEYS,
  REVOCATION_REASONS,
  REVOCATION_SCOPES,
  SMT_DEPTH,
  applyRevocation,
  assertAnchorCarriesNoPayload,
  assertDecisionAgeBound,
  assertRevocationMonotone,
  buildAnchor,
  buildRevocation,
  createRevocationState,
  decisionOnStateUnavailable,
  deriveDecision,
  evaluateCachedDecision,
  isRevoked,
  revocationEntries,
  revocationLeafKeyForGrant,
  revocationLeafKeyForVehicle,
  revocationProof,
  revocationRecordDigest,
  revocationStateFromRows,
  revocationStateRoot,
  revokeGrant,
  revokeVehicle,
  signRevocation,
  verifyRevocation,
  verifyRevocationProof,
} from '../../broker/src/nf4-revocation.js'

import {
  MAX_DELEGATION_DEPTH,
  buildGrant,
  deriveGrantCommitment,
  exportPublicKeyBase64url,
  generateSigningKeyPair,
  mintDelegatedGrant,
  revocationKeyIdFromPublicKey,
  signGrant,
} from '../../broker/src/nf2-grant.js'
import { COUNTERPARTY_CLASSES } from '../../broker/src/fields.js'
import { base64url, base64urlToBytes, vehiclePseudonym } from '../../broker/src/vin.js'

// ---------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------

const T0 = 1_800_000_000 // inside [MIN_PLAUSIBLE_TIME_S, MAX_PLAUSIBLE_TIME_S]
const DAY = 86_400
const VIN = '1HGCM82633A004352'
/** Deterministic 32-byte salt — NF-5 §4.4(3) forbids unseeded randomness in an input. */
const SALT = base64url(new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff)))
const EPOCH = 4
const AUDIENCE = 'fleet-operator'

const ownerKeys = await generateSigningKeyPair()
const ownerRevocationKeys = await generateSigningKeyPair()
const strangerRevocationKeys = await generateSigningKeyPair()
const secondOwnerRevocationKeys = await generateSigningKeyPair()
const fleetKeys = await generateSigningKeyPair()
const wrenchKeys = await generateSigningKeyPair()
const subcontractorKeys = await generateSigningKeyPair()
const otherCounterpartyKeys = await generateSigningKeyPair()

const ownerRevocationPublic = await exportPublicKeyBase64url(ownerRevocationKeys.publicKey)
const strangerRevocationPublic = await exportPublicKeyBase64url(strangerRevocationKeys.publicKey)
const secondOwnerRevocationPublic = await exportPublicKeyBase64url(secondOwnerRevocationKeys.publicKey)

const OWNER_REVOCATION_KEY_ID = await revocationKeyIdFromPublicKey(base64urlToBytes(ownerRevocationPublic))
const SECOND_REVOCATION_KEY_ID = await revocationKeyIdFromPublicKey(base64urlToBytes(secondOwnerRevocationPublic))

const fleetPublic = await exportPublicKeyBase64url(fleetKeys.publicKey)
const wrenchPublic = await exportPublicKeyBase64url(wrenchKeys.publicKey)
const subcontractorPublic = await exportPublicKeyBase64url(subcontractorKeys.publicKey)
const otherPublic = await exportPublicKeyBase64url(otherCounterpartyKeys.publicKey)

const ROOT_FIELDS = ['make', 'odometer_km', 'dtc_codes']

/** A signed root grant under the owner's revocation key. */
async function makeRootGrant(over = {}) {
  const grant = await buildGrant({
    vin: VIN,
    pseudonymSalt: SALT,
    pseudonymEpoch: EPOCH,
    fields: over.fields ?? ROOT_FIELDS,
    purpose: 'dppa-2721b-2',
    counterpartyClass: AUDIENCE,
    counterpartyKey: over.counterpartyKey ?? fleetPublic,
    revocationKeyId: over.revocationKeyId ?? OWNER_REVOCATION_KEY_ID,
    issuedAt: over.issuedAt ?? T0,
    durationSeconds: over.durationSeconds ?? 30 * DAY,
    delegationDepth: over.delegationDepth ?? MAX_DELEGATION_DEPTH,
  })
  return signGrant(grant, ownerKeys.privateKey)
}

/** A signed sub-grant, signed by the delegator (whose key is parent.counterparty_key). */
async function makeSubGrant(parent, delegatorPrivateKey, over = {}) {
  const sub = mintDelegatedGrant(parent, {
    fields: over.fields ?? parent.fields,
    counterpartyClass: over.counterpartyClass ?? parent.counterparty_class,
    counterpartyKey: over.counterpartyKey,
    issuedAt: over.issuedAt ?? parent.issued_at,
    expiresAt: over.expiresAt ?? parent.expires_at,
  })
  return signGrant(sub, delegatorPrivateKey)
}

/** A signed grant-scope revocation for `grant`, by the owner's revocation key. */
async function ownerRevocationFor(grant, at = T0 + 3600) {
  const record = buildRevocation({
    scope: 'grant',
    target: await deriveGrantCommitment(grant),
    revocationPublicKey: ownerRevocationPublic,
    issuedAt: at,
    effectiveFrom: null,
    reason: 'owner_withdrew',
  })
  return signRevocation(record, ownerRevocationKeys.privateKey)
}

/** The kill switch under the owner's revocation key. */
async function killSwitch(effectiveFrom, at = T0 + 3600, keys = ownerRevocationKeys, pub = ownerRevocationPublic) {
  const target = await revocationKeyIdFromPublicKey(base64urlToBytes(pub))
  const record = buildRevocation({
    scope: 'vehicle',
    target,
    revocationPublicKey: pub,
    issuedAt: at,
    effectiveFrom,
    reason: 'vehicle_transferred',
  })
  return signRevocation(record, keys.privateKey)
}

/** root (depth 2) -> child (depth 1) -> grandchild (depth 0), all signed. */
async function makeChain() {
  const root = await makeRootGrant()
  const child = await makeSubGrant(root, fleetKeys.privateKey, {
    counterpartyKey: wrenchPublic,
    counterpartyClass: 'repair-independent',
    fields: ['make', 'odometer_km'],
  })
  const grandchild = await makeSubGrant(child, wrenchKeys.privateKey, {
    counterpartyKey: subcontractorPublic,
    counterpartyClass: 'repair-independent',
    fields: ['make'],
  })
  return { root, child, grandchild }
}

const chain = await makeChain()
const CHAIN_POPULATION = [chain.root, chain.child, chain.grandchild]

// ---------------------------------------------------------------------------------
// Sanity of the fixtures themselves (a vacuous suite is a failing suite — NF-5 §4.7)
// ---------------------------------------------------------------------------------

test('[control] the fixture chain is a real, signed, three-deep delegation', async () => {
  assert.equal(chain.root.delegation_depth, MAX_DELEGATION_DEPTH)
  assert.equal(chain.child.delegation_depth, 1)
  assert.equal(chain.grandchild.delegation_depth, 0)
  assert.equal(chain.child.parent_grant_id, chain.root.grant_id)
  assert.equal(chain.grandchild.parent_grant_id, chain.child.grant_id)
  assert.equal(chain.root.revocation_key_id, OWNER_REVOCATION_KEY_ID)
  assert.equal(chain.grandchild.revocation_key_id, OWNER_REVOCATION_KEY_ID)
  for (const g of CHAIN_POPULATION) {
    assert.equal(typeof g.signature, 'string')
    assert.equal((await deriveGrantCommitment(g)).length, 43)
  }
})

test('[control] nothing is revoked in a fresh state', async () => {
  const state = createRevocationState()
  for (const g of CHAIN_POPULATION) {
    const verdict = await isRevoked(state, g, { ancestors: [] })
    assert.equal(verdict.revoked, false)
    assert.equal(verdict.cause, null)
  }
  assert.deepEqual(revocationEntries(state), [])
})

// ---------------------------------------------------------------------------------
// REACH — cascade
// ---------------------------------------------------------------------------------

test('revoking the root cascades to every transitive descendant', async () => {
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root)
  const result = await revokeGrant(state, record, chain.root, { population: CHAIN_POPULATION, now: T0 + 3600 })

  assert.equal(result.applied, true, result.reasons.join('; '))
  assert.deepEqual(result.reasons, [])
  assert.equal(result.inserted.length, 3, 'root, child and grandchild all get entries')

  const rootVerdict = await isRevoked(state, chain.root)
  assert.equal(rootVerdict.revoked, true)
  assert.equal(rootVerdict.cause, 'revoked')
  assert.equal(rootVerdict.revoked_at, record.issued_at)

  const childVerdict = await isRevoked(state, chain.child, { ancestors: [chain.root] })
  assert.equal(childVerdict.revoked, true)

  // The grandchild is TWO hops from the revoked grant: a lever that cuts only the root is
  // theatre (§8.4).
  const grandVerdict = await isRevoked(state, chain.grandchild, { ancestors: [chain.child, chain.root] })
  assert.equal(grandVerdict.revoked, true)
  assert.equal(grandVerdict.cause, 'cascaded')
  assert.equal(grandVerdict.entry.witness.cascaded_from, chain.root.grant_id)
})

test('cascade reaches a descendant the population never mentioned, via the ancestor walk', async () => {
  // A population read that raced with an insert, or a row written by an older build.
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root)
  await revokeGrant(state, record, chain.root, { population: [chain.root], now: T0 + 3600 })

  const missed = await isRevoked(state, chain.grandchild, { ancestors: [chain.child, chain.root] })
  assert.equal(missed.revoked, true)
  assert.equal(missed.cause, 'ancestor_revoked')

  // And without the chain the caller is told the check was incomplete rather than being
  // handed a bare "not revoked".
  const blind = await isRevoked(state, chain.grandchild)
  assert.equal(blind.revoked, false)
  assert.ok(blind.notes.some((n) => n.startsWith('ancestors_not_supplied')))
})

test('cascade is idempotent: applying the same record twice changes nothing', async () => {
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root)

  const first = await revokeGrant(state, record, chain.root, { population: CHAIN_POPULATION, now: T0 + 3600 })
  const rootAfterFirst = await revocationStateRoot(state)
  const entriesAfterFirst = revocationEntries(state).map((e) => e.leaf_key).sort()

  const second = await revokeGrant(state, record, chain.root, { population: CHAIN_POPULATION, now: T0 + 7200 })
  assert.equal(second.applied, true)
  assert.equal(second.inserted.length, 0, 'a re-application inserts nothing')
  assert.equal(second.alreadyPresent.length, first.inserted.length)

  assert.deepEqual(revocationEntries(state).map((e) => e.leaf_key).sort(), entriesAfterFirst)
  assert.equal(await revocationStateRoot(state), rootAfterFirst, 'the root must not move')

  // First write wins: revoked_at is not rewritten by the later application, because moving
  // it would invalidate every proof already issued against the old root.
  for (const entry of revocationEntries(state)) {
    assert.equal(entry.witness.revoked_at, record.issued_at)
  }
})

test('cascade is cycle-safe and terminates on a corrupt delegation graph', async () => {
  // parent_grant_id comes out of D1; a cycle there must not hang the revocation path.
  const cyclic = [
    { ...chain.root, parent_grant_id: chain.grandchild.grant_id },
    chain.child,
    chain.grandchild,
  ]
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root)
  const result = await revokeGrant(state, record, chain.root, { population: cyclic, now: T0 + 3600 })

  assert.equal(result.applied, true)
  assert.ok(
    result.warnings.some((w) => w.startsWith('cascade_cycle')),
    'a cycle must be reported, not silently walked',
  )
  assert.equal(await isRevoked(state, chain.child, { ancestors: [chain.root] }).then((v) => v.revoked), true)

  // A grant naming itself as parent is an ignored edge, reported.
  const selfParent = { ...chain.child, parent_grant_id: chain.child.grant_id }
  const state2 = createRevocationState()
  const r2 = await revokeGrant(state2, record, chain.root, {
    population: [chain.root, selfParent],
    now: T0 + 3600,
  })
  assert.equal(r2.applied, true)
  assert.ok(r2.warnings.some((w) => w.startsWith('cascade_self_parent')))
})

test('cascade walks past MAX_DELEGATION_DEPTH rather than leaving live descendants', async () => {
  // An over-deep chain means the population is malformed. Truncating the walk would leave a
  // holder with authority derived from a grant the owner just revoked.
  const great = { ...chain.grandchild, grant_id: 'AAAAAAAAAAAAAAAAAAAAAA', parent_grant_id: chain.grandchild.grant_id }
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root)
  const result = await revokeGrant(state, record, chain.root, {
    population: [...CHAIN_POPULATION, great],
    now: T0 + 3600,
  })

  assert.equal(result.applied, true)
  assert.ok(result.warnings.some((w) => w.startsWith('cascade_depth_exceeds_declared_bound')))
  assert.equal(await isRevoked(state, chain.grandchild).then((v) => v.revoked), true)
})

test('cascade does not touch grants outside the revoked subtree', async () => {
  const sibling = await makeRootGrant({ counterpartyKey: otherPublic })
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.child)

  const result = await applyRevocation(state, record, {
    grant: chain.child,
    population: [...CHAIN_POPULATION, sibling],
    now: T0 + 3600,
  })
  assert.equal(result.applied, true)
  assert.equal(result.inserted.length, 2, 'child and grandchild only')

  assert.equal(await isRevoked(state, chain.child).then((v) => v.revoked), true)
  assert.equal(await isRevoked(state, chain.grandchild).then((v) => v.revoked), true)
  assert.equal(
    await isRevoked(state, chain.root, { ancestors: [] }).then((v) => v.revoked),
    false,
    'revoking a branch must not revoke its parent',
  )
  assert.equal(await isRevoked(state, sibling, { ancestors: [] }).then((v) => v.revoked), false)
})

test('a cyclic ancestor chain supplied at check time fails CLOSED', async () => {
  const state = createRevocationState()
  const verdict = await isRevoked(state, chain.grandchild, { ancestors: [chain.child, chain.child] })
  assert.equal(verdict.revoked, true, 'an unprovable chain must not be served')
  assert.equal(verdict.cause, 'ancestry_cyclic')

  await assert.rejects(
    () => isRevoked(state, chain.grandchild, { ancestors: new Array(MAX_DELEGATION_DEPTH + 2).fill(chain.root) }),
    /MAX_DELEGATION_DEPTH/,
  )
})

// ---------------------------------------------------------------------------------
// AUTHORITY — only the owner's key, and the broker cannot refuse
// ---------------------------------------------------------------------------------

test('the broker cannot revoke on the owner\'s behalf: a stranger key is refused', async () => {
  const commitment = await deriveGrantCommitment(chain.root)
  const forged = await signRevocation(
    buildRevocation({
      scope: 'grant',
      target: commitment,
      revocationPublicKey: strangerRevocationPublic, // a broker-held key, correctly signed
      issuedAt: T0 + 3600,
      effectiveFrom: null,
      reason: 'owner_withdrew',
    }),
    strangerRevocationKeys.privateKey,
  )

  // The record itself is cryptographically impeccable...
  const verdict = await verifyRevocation(forged, { now: T0 + 3600 })
  assert.equal(verdict.valid, true, '...it verifies as a well-formed signed record')

  // ...and it still cannot revoke a grant that names a different revocation key.
  const state = createRevocationState()
  const result = await applyRevocation(state, forged, {
    grant: chain.root,
    population: CHAIN_POPULATION,
    now: T0 + 3600,
  })
  assert.equal(result.applied, false)
  assert.ok(result.reasons.some((r) => r.startsWith('not_owner_revocation_key')))
  assert.equal(result.inserted.length, 0)
  assert.equal(revocationEntries(state).length, 0, 'a refused revocation writes no row')
  assert.equal(await isRevoked(state, chain.root, { ancestors: [] }).then((v) => v.revoked), false)
})

test('a grant-scope revocation cannot be applied without the grant it targets', async () => {
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root)
  const result = await applyRevocation(state, record, { population: CHAIN_POPULATION, now: T0 + 3600 })

  assert.equal(result.applied, false)
  assert.ok(result.reasons.some((r) => r.startsWith('authorisation_grant_unavailable')))
  assert.equal(revocationEntries(state).length, 0)
})

test('a revocation aimed at another grant\'s commitment is refused', async () => {
  const other = await makeRootGrant({ counterpartyKey: otherPublic })
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root)

  const result = await applyRevocation(state, record, { grant: other, now: T0 + 3600 })
  assert.equal(result.applied, false)
  assert.ok(result.reasons.some((r) => r.startsWith('target_mismatch')))
})

test('a tampered or unsigned revocation record is refused', async () => {
  const record = await ownerRevocationFor(chain.root)

  const unsigned = { ...record, signature: null }
  const unsignedVerdict = await verifyRevocation(unsigned, { now: T0 + 3600 })
  assert.equal(unsignedVerdict.valid, false)
  assert.ok(unsignedVerdict.reasons.some((r) => r.startsWith('signature_missing')))

  const tampered = { ...record, reason: 'counterparty_breach' }
  const tamperedVerdict = await verifyRevocation(tampered, { now: T0 + 3600 })
  assert.equal(tamperedVerdict.valid, false)
  assert.ok(tamperedVerdict.reasons.some((r) => r.startsWith('signature_invalid')))

  const unknownMember = { ...record, operator_approved: true }
  const unknownVerdict = await verifyRevocation(unknownMember, { now: T0 + 3600 })
  assert.equal(unknownVerdict.valid, false)
  assert.ok(unknownVerdict.reasons.some((r) => r.startsWith('unknown_field')))

  const state = createRevocationState()
  for (const bad of [unsigned, tampered, unknownMember]) {
    const result = await applyRevocation(state, bad, { grant: chain.root, now: T0 + 3600 })
    assert.equal(result.applied, false)
  }
  assert.equal(revocationEntries(state).length, 0)
})

test('verifyRevocation never throws, whatever the network hands it', async () => {
  const hostile = [
    null,
    undefined,
    42,
    'a string',
    [],
    {},
    { v: 'nf4-revocation/1' },
    { ...(await ownerRevocationFor(chain.root)), issued_at: 1.5 },
    { ...(await ownerRevocationFor(chain.root)), issued_at: T0 * 1000 },
    { ...(await ownerRevocationFor(chain.root)), target: 'short' },
    { ...(await ownerRevocationFor(chain.root)), reason: 'sold to a named person at an address' },
    { ...(await ownerRevocationFor(chain.root)), revocation_key: 'not-a-key' },
    { ...(await ownerRevocationFor(chain.root)), signature: 'AAAA' },
    { __proto__: null, v: 'nf4-revocation/1' },
  ]
  for (const input of hostile) {
    const verdict = await verifyRevocation(input, { now: T0 + 3600 })
    assert.equal(verdict.valid, false)
    assert.ok(verdict.reasons.length > 0, 'every refusal names a reason')
  }
})

test('a valid owner revocation cannot be refused: there is no policy input to refuse it with', async () => {
  // Refusal 3, by ABSENCE. Nothing to configure, no list, no callback, no "declined" path.
  const record = await ownerRevocationFor(chain.root)
  const hostileOpts = [
    { policy: 'deny', grant: chain.root, now: T0 + 3600 },
    { allowList: [], denyList: [OWNER_REVOCATION_KEY_ID], grant: chain.root, now: T0 + 3600 },
    { approve: () => false, operatorKey: strangerRevocationPublic, grant: chain.root, now: T0 + 3600 },
    { decline: true, refuse: true, grant: chain.root, now: T0 + 3600 },
  ]
  for (const opts of hostileOpts) {
    const state = createRevocationState()
    const result = await applyRevocation(state, record, opts)
    assert.equal(result.applied, true, `an operator knob must not defeat a valid revocation: ${Object.keys(opts)}`)
    assert.equal(await isRevoked(state, chain.root, { ancestors: [] }).then((v) => v.revoked), true)
  }
})

test('refusal by a broker is detectable: the state root is a pure function of the inputs', async () => {
  const record = await ownerRevocationFor(chain.root)

  const honest = createRevocationState()
  await revokeGrant(honest, record, chain.root, { population: CHAIN_POPULATION, now: T0 + 3600 })

  // A second party recomputing from the same rows, in a different order, gets the same root.
  const independent = createRevocationState()
  await revokeGrant(independent, record, chain.root, {
    population: [chain.grandchild, chain.root, chain.child],
    now: T0 + 3600,
  })
  assert.equal(await revocationStateRoot(independent), await revocationStateRoot(honest))

  // A broker that skipped the revocation publishes a root nobody else computes.
  const skipping = createRevocationState()
  assert.notEqual(await revocationStateRoot(skipping), await revocationStateRoot(honest))
})

test('the module exposes no un-revoke and no operator override', async () => {
  // Monotonicity is the property; the absence of an inverse is how it is held. An operator
  // who can remove an entry can resurrect authority the owner withdrew, which is strictly
  // worse than never having had revocation, because the owner believes they are protected.
  const surface = await import('../../broker/src/nf4-revocation.js')
  const operations = Object.entries(surface).filter(([, v]) => typeof v === 'function').map(([k]) => k)
  assert.ok(operations.length > 10, 'the export sweep must see the real module')
  for (const name of operations) {
    assert.doesNotMatch(
      name,
      /unrevoke|un_revoke|undo|restore|reinstate|reactivate|override|approveRevocation|refuseRevocation/i,
      `"${name}" would be an inverse of revocation`,
    )
  }
  assert.deepEqual(REVOCATION_SCOPES, ['grant', 'vehicle'])
})

test('revocation is monotone across any state transition', async () => {
  const before = createRevocationState()
  const record = await ownerRevocationFor(chain.root)
  await revokeGrant(before, record, chain.root, { population: CHAIN_POPULATION, now: T0 + 3600 })

  // Additive transitions are fine.
  const after = createRevocationState()
  for (const [k, v] of before.entries) after.entries.set(k, v)
  for (const [k, v] of before.vehicleFloor) after.vehicleFloor.set(k, v)
  const extra = await makeRootGrant({ counterpartyKey: otherPublic })
  await revokeGrant(after, await ownerRevocationFor(extra), extra, { now: T0 + 7200 })
  assert.equal(assertRevocationMonotone(before, after), true)

  // Removing an entry — refusal-by-deletion, or an over-eager erasure sweep — is caught.
  const pruned = createRevocationState()
  for (const [k, v] of before.entries) pruned.entries.set(k, v)
  pruned.entries.delete(revocationEntries(before)[0].leaf_key)
  assert.throws(() => assertRevocationMonotone(before, pruned), /MONOTONICITY VIOLATED/)

  // Rewriting a witness keeps the count intact and still invalidates every issued proof.
  const rewritten = createRevocationState()
  for (const [k, v] of before.entries) rewritten.entries.set(k, v)
  const first = revocationEntries(before)[0]
  rewritten.entries.set(first.leaf_key, {
    ...first,
    witness: { ...first.witness, revoked_at: first.witness.revoked_at + 1 },
  })
  assert.throws(() => assertRevocationMonotone(before, rewritten), /witness for .* changed/)
})

// ---------------------------------------------------------------------------------
// REACH — the kill switch
// ---------------------------------------------------------------------------------

test('the kill switch revokes everything under one owner-held key', async () => {
  const early = await makeRootGrant({ counterpartyKey: otherPublic, issuedAt: T0 - 10 * DAY })
  const other = await makeRootGrant({
    counterpartyKey: otherPublic,
    revocationKeyId: SECOND_REVOCATION_KEY_ID,
  })
  const state = createRevocationState()
  const record = await killSwitch(T0 + 100, T0 + 3600)

  const result = await revokeVehicle(state, record, {
    population: [...CHAIN_POPULATION, early, other],
    now: T0 + 3600,
  })
  assert.equal(result.applied, true, result.reasons.join('; '))

  for (const g of [...CHAIN_POPULATION, early]) {
    const verdict = await isRevoked(state, g, { ancestors: [] })
    assert.equal(verdict.revoked, true, 'every grant under the killed key is dead')
  }
  assert.equal(
    await isRevoked(state, other, { ancestors: [] }).then((v) => v.revoked),
    false,
    'a grant under a different revocation key is untouched — the switch is scoped by key',
  )
})

test('the kill switch is decisive without a population: it is not an enumeration', async () => {
  // The owner never lists counterparties. A broker that fails to enumerate the affected
  // grants cannot thereby keep one alive.
  const state = createRevocationState()
  const record = await killSwitch(T0 + 100, T0 + 3600)
  const result = await revokeVehicle(state, record, { now: T0 + 3600 })
  assert.equal(result.applied, true)
  assert.equal(result.inserted.length, 1, 'one kill-switch leaf, no per-grant materialisation')

  const unseen = await makeRootGrant({ counterpartyKey: otherPublic })
  const verdict = await isRevoked(state, unseen, { ancestors: [] })
  assert.equal(verdict.revoked, true)
  assert.equal(verdict.cause, 'vehicle_kill_switch')
  assert.equal(verdict.revoked_at, T0 + 100)
})

test('the kill switch cuts at effective_from and does not pre-revoke future consent', async () => {
  const state = createRevocationState()
  const record = await killSwitch(T0 + 100, T0 + 3600)
  await revokeVehicle(state, record, { now: T0 + 3600 })

  const before = await makeRootGrant({ issuedAt: T0 + 100, counterpartyKey: otherPublic })
  const after = await makeRootGrant({ issuedAt: T0 + 101, counterpartyKey: otherPublic })

  assert.equal(
    await isRevoked(state, before, { ancestors: [] }).then((v) => v.revoked),
    true,
    'issued at effective_from is inside the switch',
  )
  assert.equal(
    await isRevoked(state, after, { ancestors: [] }).then((v) => v.revoked),
    false,
    're-consent after the switch must be possible, or the kill switch is permanent',
  )

  // And a prospective switch is refused outright at construction.
  assert.throws(
    () =>
      buildRevocation({
        scope: 'vehicle',
        target: OWNER_REVOCATION_KEY_ID,
        revocationPublicKey: ownerRevocationPublic,
        issuedAt: T0,
        effectiveFrom: T0 + 1,
        reason: 'owner_withdrew',
      }),
    /pre-revoke/,
  )
})

test('a vehicle-scope record must be signed by the key it targets', async () => {
  const mismatched = buildRevocation({
    scope: 'vehicle',
    target: SECOND_REVOCATION_KEY_ID, // not the thumbprint of the signing key
    revocationPublicKey: ownerRevocationPublic,
    issuedAt: T0 + 3600,
    effectiveFrom: T0 + 100,
    reason: 'owner_withdrew',
  })
  await assert.rejects(() => signRevocation(mismatched, ownerRevocationKeys.privateKey), /vehicle_scope_target_mismatch/)

  assert.equal(
    (await verifyRevocation({ ...mismatched, signature: base64url(new Uint8Array(64)) }, { now: T0 + 3600 })).valid,
    false,
  )
})

test('revokeGrant and revokeVehicle refuse each other\'s scopes', async () => {
  const state = createRevocationState()
  const grantRecord = await ownerRevocationFor(chain.root)
  const vehicleRecord = await killSwitch(T0 + 100, T0 + 3600)

  const a = await revokeGrant(state, vehicleRecord, chain.root, { now: T0 + 3600 })
  assert.equal(a.applied, false)
  assert.ok(a.reasons.some((r) => r.startsWith('scope_mismatch')))

  const b = await revokeVehicle(state, grantRecord, { now: T0 + 3600 })
  assert.equal(b.applied, false)
  assert.ok(b.reasons.some((r) => r.startsWith('scope_mismatch')))

  await assert.rejects(() => revokeVehicle(state, vehicleRecord, { grant: chain.root }), /takes no single grant/)
  assert.equal(revocationEntries(state).length, 0)
})

test('a state rebuilt from its rows still enforces the kill switch', async () => {
  // The tree is a derived index and the entries are D1 rows, so a broker rebuilds the state
  // on every cold start. `vehicleFloor` is a SECOND index over those same rows, and the
  // naive rebuild — copy the entries — silently drops it. The failure mode is under-
  // revocation: every kill switch stops being enforced and nothing reports it. So the
  // rehydration has to rebuild both indexes together, from the rows alone.
  const live = createRevocationState()
  await revokeVehicle(live, await killSwitch(T0 + 100, T0 + 3600), { now: T0 + 3600 })
  await revokeGrant(live, await ownerRevocationFor(chain.child, T0 + 60), chain.child, {
    population: CHAIN_POPULATION,
    now: T0 + 60,
  })

  const rows = revocationEntries(live)
  const restored = revocationStateFromRows(rows)

  assert.equal(await revocationStateRoot(restored), await revocationStateRoot(live))
  assert.equal(assertRevocationMonotone(live, restored), true)
  assert.equal(assertRevocationMonotone(restored, live), true)

  const unseen = await makeRootGrant({ counterpartyKey: otherPublic })
  const verdict = await isRevoked(restored, unseen, { ancestors: [] })
  assert.equal(verdict.revoked, true, 'the kill switch must survive a restart')
  assert.equal(verdict.cause, 'vehicle_kill_switch')
  assert.equal(await isRevoked(restored, chain.grandchild).then((v) => v.revoked), true)

  // A row that does not round-trip is refused rather than half-loaded: a partially rebuilt
  // revocation index answers "not revoked" for everything it failed to read.
  assert.throws(() => revocationStateFromRows([{ ...rows[0], leaf_key: 'short' }]), /leaf_key/)
  assert.throws(() => revocationStateFromRows([{ ...rows[0], kind: 'other' }]), /kind/)
  assert.throws(() => revocationStateFromRows([{ ...rows[0], witness: null }]), /witness/)
  assert.throws(() => revocationStateFromRows('not rows'), /rows/)

  // D1 stores the witness across four columns, so a row in that shape loads too.
  const flat = rows.map((r) => ({
    leaf_key: r.leaf_key,
    kind: r.kind,
    target: r.target,
    effective_from: r.effective_from,
    grant_id: r.grant_id,
    cause: r.witness.cause,
    revoked_at: r.witness.revoked_at,
    cascaded_from: r.witness.cascaded_from,
    record_digest: r.witness.record_digest,
  }))
  const fromColumns = revocationStateFromRows(flat)
  assert.equal(await revocationStateRoot(fromColumns), await revocationStateRoot(live))
  assert.equal(
    await isRevoked(fromColumns, unseen, { ancestors: [] }).then((v) => v.cause),
    'vehicle_kill_switch',
  )
})

// ---------------------------------------------------------------------------------
// TIMELINESS — the staleness bound (§8.4)
// ---------------------------------------------------------------------------------

const decisionFixture = async (over = {}) => {
  const state = over.state ?? createRevocationState()
  return deriveDecision({
    grantCommitment: over.grantCommitment ?? (await deriveGrantCommitment(chain.root)),
    presenterKey: over.presenterKey ?? fleetPublic,
    allowed: over.allowed ?? true,
    cause: over.cause ?? 'not_revoked',
    derivedAt: over.derivedAt ?? T0,
    stateRoot: over.stateRoot ?? (await revocationStateRoot(state)),
  })
}

test('a cached ALLOW is honoured up to the bound and re-derived one second past it', async () => {
  const cached = await decisionFixture()

  const fresh = evaluateCachedDecision(cached, { now: T0 + 1, maxAgeS: 60 })
  assert.equal(fresh.decision, 'allow')
  assert.equal(fresh.mustRederive, false)

  const onBound = evaluateCachedDecision(cached, { now: T0 + 60, maxAgeS: 60 })
  assert.equal(onBound.decision, 'allow', 'exactly at the bound is still fresh')
  assert.equal(onBound.ageS, 60)

  const past = evaluateCachedDecision(cached, { now: T0 + 61, maxAgeS: 60 })
  assert.equal(past.decision, 'unknown', 'a stale ALLOW is UNKNOWN, never allow')
  assert.notEqual(past.decision, 'allow')
  assert.equal(past.mustRederive, true)
  assert.match(past.reason, /^stale_allow/)

  // Default bound is 60s and it is itself bounded.
  assert.equal(DEFAULT_MAX_DECISION_AGE_S, 60)
  assert.equal(evaluateCachedDecision(cached, { now: T0 + 61 }).decision, 'unknown')
})

test('a stale ALLOW is re-derived against the state, and re-derivation denies once revoked', async () => {
  // The end-to-end shape of §8.4: the cache cannot outrun the revocation.
  const state = createRevocationState()
  const commitment = await deriveGrantCommitment(chain.root)
  const cached = await decisionFixture({ state, grantCommitment: commitment, derivedAt: T0 })

  await revokeGrant(state, await ownerRevocationFor(chain.root, T0 + 30), chain.root, {
    population: CHAIN_POPULATION,
    now: T0 + 30,
  })

  const stale = evaluateCachedDecision(cached, { now: T0 + 61, maxAgeS: 60 })
  assert.equal(stale.decision, 'unknown')

  const rederived = await isRevoked(state, chain.root, { ancestors: [] })
  assert.equal(rederived.revoked, true, 'the re-derivation is what the caller must do, and it denies')
})

test('a root change invalidates a cached ALLOW immediately, inside the age bound', async () => {
  const state = createRevocationState()
  const cached = await decisionFixture({ state })
  await revokeGrant(state, await ownerRevocationFor(chain.child, T0 + 1), chain.child, { now: T0 + 1 })
  const movedRoot = await revocationStateRoot(state)

  const verdict = evaluateCachedDecision(cached, { now: T0 + 2, maxAgeS: 60, currentStateRoot: movedRoot })
  assert.equal(verdict.decision, 'unknown')
  assert.match(verdict.reason, /^state_root_moved/)
  assert.equal(verdict.ageS, 2, 'age alone would have honoured it — the root is the immediate signal')
})

test('a cached DENY caused by revocation is monotone; any other DENY is re-derived', async () => {
  for (const cause of ['revoked', 'cascaded', 'vehicle_kill_switch']) {
    const denied = await decisionFixture({ allowed: false, cause })
    const verdict = evaluateCachedDecision(denied, { now: T0 + 10 * 365 * DAY, maxAgeS: 60 })
    assert.equal(verdict.decision, 'deny', `${cause} can never become wrong`)
    assert.equal(verdict.mustRederive, false)
  }
  for (const cause of ['expired', 'read_failed', 'signature_invalid']) {
    const denied = await decisionFixture({ allowed: false, cause })
    const verdict = evaluateCachedDecision(denied, { now: T0 + 10, maxAgeS: 60 })
    assert.equal(verdict.decision, 'unknown', `${cause} may no longer hold`)
    assert.equal(verdict.mustRederive, true)
  }
})

test('a cached decision is not a bearer token: presenter and target are bound', async () => {
  const cached = await decisionFixture()

  const otherPresenter = evaluateCachedDecision(cached, { now: T0 + 1, presenterKey: wrenchPublic })
  assert.equal(otherPresenter.decision, 'unknown')
  assert.match(otherPresenter.reason, /^cache_presenter_mismatch/)

  const otherGrant = evaluateCachedDecision(cached, {
    now: T0 + 1,
    grantCommitment: await deriveGrantCommitment(chain.child),
  })
  assert.equal(otherGrant.decision, 'unknown')
  assert.match(otherGrant.reason, /^cache_target_mismatch/)

  const correct = evaluateCachedDecision(cached, {
    now: T0 + 1,
    presenterKey: fleetPublic,
    grantCommitment: await deriveGrantCommitment(chain.root),
  })
  assert.equal(correct.decision, 'allow')
})

test('a future-dated or malformed cache row is never an ALLOW', async () => {
  const cached = await decisionFixture({ derivedAt: T0 + 3600 })
  const verdict = evaluateCachedDecision(cached, { now: T0, maxAgeS: 60, clockSkewS: 5 })
  assert.equal(verdict.decision, 'unknown')
  assert.match(verdict.reason, /^cache_future_dated/)

  for (const bad of [null, {}, 42, 'x', { ...cached, decision: 'maybe' }, { ...cached, v: 'nf4-decision/2' }, { ...cached, extra: 1 }]) {
    const v = evaluateCachedDecision(bad, { now: T0 + 1 })
    assert.equal(v.decision, 'unknown')
    assert.equal(v.mustRederive, true)
  }
})

test('the staleness bound cannot be configured away', async () => {
  assert.equal(assertDecisionAgeBound(0), 0)
  assert.equal(assertDecisionAgeBound(MAX_PERMITTED_DECISION_AGE_S), MAX_PERMITTED_DECISION_AGE_S)
  assert.throws(() => assertDecisionAgeBound(MAX_PERMITTED_DECISION_AGE_S + 1), /hard ceiling/)
  assert.throws(() => assertDecisionAgeBound(-1), /negative/)
  assert.throws(() => assertDecisionAgeBound(86_400), /hard ceiling/)
  assert.throws(() => assertDecisionAgeBound(1.5))
  assert.ok(DEFAULT_MAX_DECISION_AGE_S <= MAX_PERMITTED_DECISION_AGE_S)

  const cached = await decisionFixture()
  assert.throws(() => evaluateCachedDecision(cached, { now: T0 + 1, maxAgeS: 86_400 }), /hard ceiling/)
})

test('an unreachable revocation store denies', () => {
  const verdict = decisionOnStateUnavailable()
  assert.equal(verdict.decision, 'deny')
  assert.match(verdict.reason, /^fail_closed/)
  assert.equal(verdict.mustRederive, false)
})

// ---------------------------------------------------------------------------------
// REFUSAL 2 — the commitment, its proofs, and what it does not leak
// ---------------------------------------------------------------------------------

test('the state root is a function of the set, not of insertion order', async () => {
  const a = createRevocationState()
  const b = createRevocationState()
  const grants = [chain.root, chain.child, chain.grandchild]

  for (const g of grants) await revokeGrant(a, await ownerRevocationFor(g, T0 + 60), g, { now: T0 + 60 })
  for (const g of [...grants].reverse()) await revokeGrant(b, await ownerRevocationFor(g, T0 + 60), g, { now: T0 + 60 })

  const rootA = await revocationStateRoot(a)
  assert.equal(rootA.length, 43, 'a fixed-length opaque commitment')
  assert.match(rootA, /^[A-Za-z0-9_-]+$/)
  assert.equal(rootA, await revocationStateRoot(b))
  assert.equal(rootA, await revocationStateRoot(a), 'stable when nothing changed')
})

test('an inclusion proof verifies against the anchored root and reports the witness', async () => {
  const state = createRevocationState()
  await revokeGrant(state, await ownerRevocationFor(chain.root, T0 + 60), chain.root, {
    population: CHAIN_POPULATION,
    now: T0 + 60,
  })
  const root = await revocationStateRoot(state)
  const target = { kind: 'grant', grantCommitment: await deriveGrantCommitment(chain.grandchild) }

  const proof = await revocationProof(state, target)
  assert.equal(proof.present, true)
  assert.equal(proof.siblings.length, SMT_DEPTH)

  const verdict = await verifyRevocationProof(proof, root, target)
  assert.equal(verdict.valid, true, verdict.reasons.join('; '))
  assert.equal(verdict.revoked, true)
  assert.equal(verdict.witness.cause, 'cascade')
  assert.equal(verdict.witness.revoked_at, T0 + 60)
})

test('a NON-inclusion proof is what an authorisation decision actually needs', async () => {
  const state = createRevocationState()
  await revokeGrant(state, await ownerRevocationFor(chain.child, T0 + 60), chain.child, { now: T0 + 60 })
  const root = await revocationStateRoot(state)

  const target = { kind: 'grant', grantCommitment: await deriveGrantCommitment(chain.root) }
  const proof = await revocationProof(state, target)
  assert.equal(proof.present, false)
  assert.equal(proof.witness, null, 'a non-inclusion proof carries no witness')

  const verdict = await verifyRevocationProof(proof, root, target)
  assert.equal(verdict.valid, true, verdict.reasons.join('; '))
  assert.equal(verdict.revoked, false)
})

test('a kill-switch leaf proves inclusion at its own (key, effective_from) position', async () => {
  const state = createRevocationState()
  await revokeVehicle(state, await killSwitch(T0 + 100, T0 + 3600), { now: T0 + 3600 })
  const root = await revocationStateRoot(state)

  const target = { kind: 'vehicle', revocationKeyId: OWNER_REVOCATION_KEY_ID, effectiveFrom: T0 + 100 }
  const proof = await revocationProof(state, target)
  assert.equal(proof.present, true)
  assert.equal((await verifyRevocationProof(proof, root, target)).revoked, true)

  // A different effective_from is a different leaf, so an old switch cannot be replayed as a
  // newer one.
  const shifted = { kind: 'vehicle', revocationKeyId: OWNER_REVOCATION_KEY_ID, effectiveFrom: T0 + 101 }
  const shiftedProof = await revocationProof(state, shifted)
  assert.equal(shiftedProof.present, false)
  assert.notEqual(base64url(await revocationLeafKeyForVehicle(OWNER_REVOCATION_KEY_ID, T0 + 100)),
    base64url(await revocationLeafKeyForVehicle(OWNER_REVOCATION_KEY_ID, T0 + 101)))
})

test('a proof cannot be re-aimed, replayed against another root, or forged', async () => {
  const state = createRevocationState()
  await revokeGrant(state, await ownerRevocationFor(chain.root, T0 + 60), chain.root, {
    population: CHAIN_POPULATION,
    now: T0 + 60,
  })
  const root = await revocationStateRoot(state)
  const target = { kind: 'grant', grantCommitment: await deriveGrantCommitment(chain.root) }
  const proof = await revocationProof(state, target)

  // Re-aimed at a different grant.
  const reaimed = await verifyRevocationProof(proof, root, {
    kind: 'grant',
    grantCommitment: await deriveGrantCommitment(chain.child),
  })
  assert.equal(reaimed.valid, false)
  assert.ok(reaimed.reasons.some((r) => r.startsWith('proof_target_mismatch')))

  // Presented against a root it was not built over.
  const stale = createRevocationState()
  const staleRoot = await revocationStateRoot(stale)
  const wrongRoot = await verifyRevocationProof(proof, staleRoot, target)
  assert.equal(wrongRoot.valid, false)
  assert.ok(wrongRoot.reasons.some((r) => r.startsWith('proof_root_mismatch')))

  // A tampered witness moves the leaf value and breaks the path.
  const tampered = { ...proof, witness: { ...proof.witness, revoked_at: proof.witness.revoked_at + 1 } }
  assert.equal((await verifyRevocationProof(tampered, root, target)).valid, false)

  // A fabricated non-inclusion proof for a leaf that IS present.
  const denied = { ...proof, present: false, witness: null }
  assert.equal((await verifyRevocationProof(denied, root, target)).valid, false)

  // Malformed proofs never throw.
  for (const bad of [null, 42, {}, { ...proof, siblings: [] }, { ...proof, v: 'nf4-proof/2' }, { ...proof, leaf_key: 'x' }]) {
    const v = await verifyRevocationProof(bad, root, target)
    assert.equal(v.valid, false)
    assert.ok(v.reasons.length > 0)
  }
  assert.equal((await verifyRevocationProof(proof, 'not-a-root', target)).valid, false)
})

test('the on-chain anchor carries a commitment and nothing else', async () => {
  const state = createRevocationState()
  await revokeGrant(state, await ownerRevocationFor(chain.root, T0 + 60), chain.root, { now: T0 + 60 })
  const root = await revocationStateRoot(state)

  const anchor = buildAnchor({ root, epoch: 7, publishedAt: T0 + 3600 })
  assert.deepEqual(Object.keys(anchor).sort(), [...ANCHOR_KEYS].sort())
  assert.equal(assertAnchorCarriesNoPayload(anchor), true)

  // Anything that could never be erased is refused at the boundary.
  for (const extra of ['entry_count', 'vehicle_pseudonym', 'vin', 'grant_id', 'owner', 'revoked_at', 'tree_size']) {
    assert.throws(
      () => assertAnchorCarriesNoPayload({ ...anchor, [extra]: 1 }),
      /REFUSAL 2 VIOLATION/,
      `an anchor must refuse "${extra}"`,
    )
  }
  assert.throws(() => buildAnchor({ root, epoch: 7, publishedAt: T0 + 3600, count: 3 }), /unknown parameter/)
  assert.throws(() => buildAnchor({ root: 'short', epoch: 7, publishedAt: T0 + 3600 }))
  assert.throws(() => buildAnchor({ root, epoch: -1, publishedAt: T0 + 3600 }))
  assert.throws(() => buildAnchor({ root, epoch: 7, publishedAt: (T0 + 3600) * 1000 }))

  // An anchor is fixed-size regardless of population, so it publishes no volume.
  const bigger = createRevocationState()
  await revokeGrant(bigger, await ownerRevocationFor(chain.root, T0 + 60), chain.root, {
    population: CHAIN_POPULATION,
    now: T0 + 60,
  })
  const biggerAnchor = buildAnchor({ root: await revocationStateRoot(bigger), epoch: 7, publishedAt: T0 + 3600 })
  assert.equal(biggerAnchor.root.length, anchor.root.length)
  assert.deepEqual(Object.keys(biggerAnchor), Object.keys(anchor))
})

test('no committed artefact carries a VIN, a pseudonym, or any free text', async () => {
  const state = createRevocationState()
  const record = await ownerRevocationFor(chain.root, T0 + 60)
  await revokeGrant(state, record, chain.root, { population: CHAIN_POPULATION, now: T0 + 60 })
  const root = await revocationStateRoot(state)
  const anchor = buildAnchor({ root, epoch: 1, publishedAt: T0 + 3600 })
  const proof = await revocationProof(state, {
    kind: 'grant',
    grantCommitment: await deriveGrantCommitment(chain.root),
  })

  const pseudonym = chain.root.vehicle_pseudonym.value
  const surface = JSON.stringify({ anchor, proof, entries: revocationEntries(state), record })
  assert.ok(!surface.includes(VIN), 'no raw VIN anywhere on the committed surface')
  assert.ok(!surface.includes(VIN.toLowerCase()))
  assert.ok(!surface.includes(SALT), 'the salt is the erasure mechanism and never leaves D1')
  assert.ok(!surface.includes(pseudonym), 'not even the pseudonym reaches a commitment')

  // The reason vocabulary is closed, so there is no free-text channel to leak through.
  assert.ok(REVOCATION_REASONS.includes(record.reason))
  assert.throws(
    () =>
      buildRevocation({
        scope: 'grant',
        target: OWNER_REVOCATION_KEY_ID,
        revocationPublicKey: ownerRevocationPublic,
        issuedAt: T0,
        effectiveFrom: null,
        reason: 'sold to a person, who lives at an address',
      }),
    /reason_unknown/,
  )
  assert.deepEqual([...REVOCATION_KEYS].sort(), [...new Set(REVOCATION_KEYS)].sort())
  assert.equal(DECISION_KEYS.includes('vin'), false)
})

test('the commitment is not brute-forceable back to a VIN or a pseudonym', async () => {
  // Refusal 2's arithmetic: a VIN has ~10^8 realistic entropy and is enumerable from a
  // parking lot, so a commitment scheme whose preimage space is VIN-sized is a lookup table.
  // Here every committed value's preimage chain passes through either an owner-held HMAC salt
  // or a 32-byte key thumbprint, so enumerating the VIN space yields nothing.
  const state = createRevocationState()
  await revokeGrant(state, await ownerRevocationFor(chain.root, T0 + 60), chain.root, {
    population: CHAIN_POPULATION,
    now: T0 + 60,
  })
  await revokeVehicle(state, await killSwitch(T0 + 100, T0 + 3600), { now: T0 + 3600 })

  const published = new Set()
  published.add(await revocationStateRoot(state))
  for (const entry of revocationEntries(state)) {
    published.add(entry.leaf_key)
    published.add(entry.target)
    published.add(entry.witness.record_digest)
  }
  assert.ok(published.size >= 5, 'the published surface under test is non-empty')

  // The attacker's enumeration: candidate VINs, every domain prefix this system uses, and
  // pseudonyms under guessed salts, epochs and audiences.
  const domains = [
    '',
    'nf3-qname:v1:',
    'nf4-leaf-grant:v1:',
    'nf4-leaf-vehicle:v1:',
    'nf4-record-digest:v1:',
    'nf4-witness-digest:v1:',
    'nf2-grant-commitment:v1:',
    'nf2-revocation-key-id:v1:',
    'nf4-smt-leaf:v1:',
  ]
  const candidates = [VIN]
  for (let i = 0; i < 24; i += 1) {
    // Deterministic neighbours of the real VIN — the plausible enumeration a fleet-yard
    // adversary actually runs.
    const digits = '0123456789'
    candidates.push(VIN.slice(0, 12) + digits[i % 10] + VIN.slice(13))
  }
  const guessedSalts = [
    base64url(new Uint8Array(32)),
    base64url(new Uint8Array(Array.from({ length: 32 }, (_, i) => i))),
    base64url(new Uint8Array(Array.from({ length: 32 }, () => 0xff))),
  ]

  const derived = new Set()
  const enc = new TextEncoder()
  for (const candidate of candidates) {
    for (const domain of domains) {
      const digest = await crypto.subtle.digest('SHA-256', enc.encode(domain + candidate))
      derived.add(base64url(new Uint8Array(digest)))
    }
    for (const salt of guessedSalts) {
      for (const epoch of [EPOCH, EPOCH - 1]) {
        for (const audience of [AUDIENCE, COUNTERPARTY_CLASSES[0]]) {
          derived.add(await vehiclePseudonym(candidate, salt, epoch, audience))
        }
      }
    }
  }
  assert.ok(derived.size > 200, 'the enumeration under test is real')

  for (const guess of derived) {
    assert.equal(published.has(guess), false, 'a VIN-derived value must never appear on the ledger surface')
  }

  // Non-vacuity control, in both directions.
  // (a) The search would have found a match had the construction been VIN-only: with the
  //     owner's salt, the pseudonym IS reproducible from the VIN.
  assert.equal(await vehiclePseudonym(VIN, SALT, EPOCH, AUDIENCE), chain.root.vehicle_pseudonym.value)
  // (b) A party holding the GRANT can locate its leaf — that is the whole point, and it is
  //     not an enumeration capability, because the grant is not derivable from the VIN.
  const leaf = base64url(await revocationLeafKeyForGrant(await deriveGrantCommitment(chain.root)))
  assert.equal(published.has(leaf), true)
  // (c) The pseudonym itself, which a counterparty holds, still does not locate a leaf.
  assert.equal(published.has(chain.root.vehicle_pseudonym.value), false)
})

test('leaf keys and record digests refuse malformed inputs rather than hashing them', async () => {
  await assert.rejects(() => revocationLeafKeyForGrant('short'), /32-byte base64url/)
  await assert.rejects(() => revocationLeafKeyForGrant(null), /32-byte base64url/)
  await assert.rejects(() => revocationLeafKeyForVehicle('short', T0), /thumbprint/)
  await assert.rejects(() => revocationLeafKeyForVehicle(OWNER_REVOCATION_KEY_ID, 1.5))

  const record = await ownerRevocationFor(chain.root)
  assert.equal((await revocationRecordDigest(record)).length, 43)
  await assert.rejects(() => revocationRecordDigest({ ...record, signature: null }), /unsigned/)
  await assert.rejects(() => revocationRecordDigest({ ...record, extra: 1 }), /unknown_field/)
})
