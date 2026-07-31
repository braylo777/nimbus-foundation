/**
 * M3 — Delete Act / DROP compliance Worker.
 *
 * Nimbus Foundation NF-WP-1 §9.5, §14 (M3), §15 rec. 2.
 * California Delete Act, Civ. Code §§ 1798.99.80 et seq. (SB 362).
 *
 * THE HARD DATE. The DROP processing obligation begins 2026-08-01 (§9.5). DROP has been
 * live for consumers since 2026-01-01, registration is annual with the fee set at $6,000
 * for 2026, and a missed deadline accrues $200/day (CPPA Enforcement Advisory No. 2025-01).
 * Enforcement is not theoretical: the CPPA fined Accurate Append, Inc. $55,400 in July
 * 2025 for failing to register, stood up a Data Broker Enforcement Strike Force, and
 * issued a $56,600 fine on 2025-12-03 — its eighth registration-failure fine. The Delete
 * Act's required broker disclosures expressly enumerate vehicle identification numbers as
 * a category of personal information collected, which places a VIN-indexed consent broker
 * squarely inside the regime. There is no reading of §9.5 in which this milestone is
 * optional or deferrable.
 *
 * WHAT THIS WORKER DOES, in the order the statute cares about:
 *   1. Accesses DROP at least every 45 days (CLOCK A1) — in practice daily, see wrangler.toml.
 *   2. Records each retrieval as a batch and starts TWO independent deadlines on it:
 *      a status report at +45 days (CLOCK A2) and deletion completion at +90 days (CLOCK B).
 *      The two clocks are the whole point of src/clocks.js; read its header before
 *      touching anything here that mentions a deadline.
 *   3. Matches each request against local records, maintains the suppression list, and
 *      fans the deletion out to every service provider and contractor with per-recipient
 *      acknowledgement tracking.
 *   4. Completes deletions and reports status — and PRODUCES THE AUDIT FILE BEFORE the
 *      status file is returned to CalPrivacy. That ordering is an M3 acceptance criterion,
 *      so it is enforced in three independent places: a NOT NULL foreign key plus two
 *      triggers in schema.sql, a re-read-and-verify guard in `submitStatusReportForBatch`
 *      below, and `stepOrderViolations` in clocks.js which the status endpoint surfaces.
 *      The report payload is DERIVED FROM the sealed audit file's stored content, never
 *      from a fresh query, so a report cannot assert anything that was not audited first.
 *
 * REFUSAL 2 HYGIENE (§9.5, §10.1). Nothing here writes personal information anywhere
 * durable except D1, and even in D1 consumer identifiers are reduced to a keyed digest at
 * the boundary (`subjectDigest`). The audit file — the artefact most likely to be
 * exported, mailed and retained longest — carries counts, states, digests and DROP's own
 * opaque request ids, and no identifiers at all. The only value in this system eligible to
 * become an on-chain integrity commitment is `audit_file.head_digest`.
 *
 * REFUSAL 1 (§10.1). No endpoint here resolves a VIN, accepts a VIN, or returns anything
 * that authorises access to a vehicle. This is a compliance ledger, not a resolver.
 *
 * STACK (§14). Plain ES modules, no npm, no build step, no third-party dependencies.
 * WebCrypto for digests; D1 through prepared statements with bound parameters only.
 */

import {
  CLOCKS,
  DAY_S,
  INTERNAL_ACCESS_CADENCE_S,
  PROCESSING_OBLIGATION_START_S,
  accessClockState,
  assertInstant,
  batchClockStates,
  deadlinesForRetrieval,
  findOverdue,
  internalTargetsForRetrieval,
  isProcessingObligationActive,
  nextDueAt,
  registrationClockState,
  stepOrderViolations,
} from './clocks.js'
import { canonicalize } from '../../broker/src/jcs.js'
import { base64url } from '../../broker/src/vin.js'

const AUDIT_FILE_SCHEMA = 'nf-m3-audit-file/1'
const DIRECTIVE_SCHEMA = 'nf-m3-deletion-directive/1'
const DISPOSITION_SCHEMA = 'nf-m3-drop-disposition/1'

/** Domain separation, so no digest here can be replayed as a grant commitment. */
const AUDIT_EVENT_DOMAIN = 'nf-m3-audit-event:v1:'
const AUDIT_FILE_DOMAIN = 'nf-m3-audit-file:v1:'
const SUBJECT_DIGEST_DOMAIN = 'nf-m3-subject:v1:'
const PAYLOAD_DIGEST_DOMAIN = 'nf-m3-payload:v1:'

/** Chain root. A fixed, recognisable value so an empty chain is distinguishable from a truncated one. */
const AUDIT_GENESIS_DIGEST = 'GENESIS'

const LEASE_NAME = 'drop-compliance-cycle'
const LEASE_TTL_S = 10 * 60

// =========================================================================================
// DROP adapter — STUB. Read this before deploying anything.
// =========================================================================================
/**
 * The DROP API contract is NOT in NF-WP-1, and nothing in this file invents one.
 *
 * There is no endpoint URL, no request body and no status vocabulary hardcoded anywhere in
 * this Worker. A fabricated endpoint that returns 404 in production is a bad outcome; a
 * fabricated endpoint that looks plausible in code review and is never checked is a worse
 * one, because it converts an open question into an assumption nobody re-opens.
 *
 * ADAPTER INTERFACE (what a real implementation must provide):
 *
 *   id: string                                        stable identifier recorded on every batch
 *   async retrieveDeletionRequests({ cursor }) -> {
 *     requests: [{ drop_request_id, identifiers: { <class>: <value>, ... }, submitted_at? }],
 *     cursor: string|null,        opaque continuation token, null when the list is exhausted
 *     retrieved_at: number        Unix SECONDS, the instant the access completed
 *   }
 *   async submitStatusReport({ disposition }) -> { receipt: string }
 *
 * WHAT MUST BE CONFIRMED AGAINST CPPA'S PUBLISHED DROP INTERFACE BEFORE LAUNCH — each of
 * these changes code, not just configuration:
 *   1. Base URL, API version, and whether access is REST, a signed file download, or both.
 *   2. Authentication: the credential type, where it is presented, and its rotation cadence.
 *   3. Whether retrieval is pull (we poll) or push (they call us). This Worker assumes pull;
 *      a push model needs an authenticated inbound route and the cadence obligation then
 *      becomes "confirm the subscription is live every 45 days" rather than "fetch".
 *   4. The identifier classes DROP supplies, their exact normalisation, and — critically —
 *      whether matching is expected to be EXACT or PROBABILISTIC. `subjectDigest` below
 *      implements exact match over normalised values. If DROP expects fuzzy matching
 *      (name variants, partial addresses), digest-only storage is insufficient and the
 *      privacy/accuracy trade-off must be re-decided with counsel, not patched here.
 *   5. Pagination and cursor semantics, including whether a cursor expires.
 *   6. The status vocabulary: the enumerated dispositions DROP accepts (deleted, no match,
 *      exempt with basis, in progress, ...). `deletion_state` in schema.sql uses our own
 *      names; the adapter maps them, and the mapping is where a wrong guess shows up.
 *   7. Idempotency and retry: whether re-submitting a status report for the same batch is
 *      safe, and whether a receipt is durable evidence of submission.
 *   8. Rate limits and the required user agent.
 *
 * Until a real adapter is bound, the stub REFUSES rather than returning empty results. An
 * adapter that returned `{ requests: [] }` would let the Worker record a successful access
 * every day, reset CLOCK A1, and report perfect compliance while never having spoken to
 * DROP. Fail closed and loud: the refusal is recorded as a `failed` batch with severity
 * `breach` once the obligation is active, so the gap is visible on the status endpoint from
 * 2026-08-01 onward instead of surfacing in an enforcement letter.
 */
export class DropAdapterNotConfigured extends Error {
  constructor(message) {
    super(message)
    this.name = 'DropAdapterNotConfigured'
  }
}

export class ErasureAdapterNotConfigured extends Error {
  constructor(message) {
    super(message)
    this.name = 'ErasureAdapterNotConfigured'
  }
}

export class AuditOrderingViolation extends Error {
  constructor(message) {
    super(message)
    this.name = 'AuditOrderingViolation'
  }
}

export const stubDropAdapter = Object.freeze({
  id: 'stub',
  stub: true,
  async retrieveDeletionRequests() {
    throw new DropAdapterNotConfigured(
      'no DROP adapter bound. This is the documented stub and it will not fabricate an ' +
        'endpoint, a request schema, or an empty result set. Implement the adapter against ' +
        "CPPA's published DROP interface (see the checklist in src/index.js) and pass it to " +
        'runComplianceCycle({ dropAdapter }).',
    )
  },
  async submitStatusReport() {
    throw new DropAdapterNotConfigured(
      'no DROP adapter bound; refusing to pretend a status report was filed with CalPrivacy',
    )
  },
})

/**
 * Local erasure adapter. Also a stub, for a different reason: M1/M2 own the vehicle, grant
 * and twin tables, and they do not exist in this repo yet. Naming their tables here would
 * be inventing a schema on another milestone's behalf.
 *
 * INTERFACE:
 *   async findMatches(subjectDigest) -> [{ store, local_ref }]
 *   async erase(matches) -> [{ store, local_ref, erased: boolean, salt_destroyed: boolean, receipt }]
 *
 * The load-bearing step is `salt_destroyed`. Per vin.js and §9.5, destroying the owner-held
 * pseudonym salt destroys the linkage between every commitment and the vehicle, which is
 * what makes erasure real rather than nominal — a party holding both a grant commitment and
 * a candidate VIN still cannot connect them. Row deletion without salt destruction is
 * incomplete erasure.
 *
 * A missing adapter marks matching as `error`, NEVER as `no_match`. Reporting "no match" to
 * CalPrivacy because the matcher was not wired up is a false statement to a regulator, and
 * it is the single most tempting default in this file.
 */
export const stubErasureAdapter = Object.freeze({
  id: 'stub',
  stub: true,
  async findMatches() {
    throw new ErasureAdapterNotConfigured(
      'no erasure adapter bound. Matching cannot report "no match" without having looked; ' +
        'wire M1/M2 record stores in and pass { erasureAdapter } to runComplianceCycle.',
    )
  },
  async erase() {
    throw new ErasureAdapterNotConfigured('no erasure adapter bound; refusing to record an erasure that did not happen')
  },
})

/**
 * Downstream dispatch. `https_webhook` is implemented because it needs no third party:
 * the endpoint is read from a NAMED env var (`downstream_recipient.endpoint_ref`), never
 * from a column, so a compromised database row cannot redirect a deletion directive to an
 * attacker's collector.
 *
 * NOT SIGNED. A directive should carry a broker signature so a recipient can later prove
 * what it was told to delete; that needs a broker key and key-rotation policy, which is
 * M1/M2 territory. Recorded here as a known gap rather than half-built.
 */
export function defaultDispatchAdapter(env) {
  return {
    id: 'https_webhook/1',
    async dispatch(recipient, payload) {
      if (recipient.channel === 'manual_attestation') {
        // Nothing to send. The directive stays 'pending' and shows up in the chase query
        // until an operator records the attestation through /compliance/directives/{id}/ack.
        return { dispatched: false, reason: 'manual_attestation: awaiting operator-recorded attestation' }
      }
      if (recipient.channel !== 'https_webhook') {
        throw new Error(
          `dispatch channel "${recipient.channel}" is not implemented; email delivery needs the ` +
            'Cloudflare/Twilio path wired and is not built here',
        )
      }
      const endpoint = recipient.endpoint_ref ? env[recipient.endpoint_ref] : null
      if (typeof endpoint !== 'string' || !endpoint.startsWith('https://')) {
        throw new Error(
          `recipient ${recipient.recipient_id} has endpoint_ref="${recipient.endpoint_ref}" which is ` +
            'not a configured https endpoint in env; refusing to dispatch',
        )
      }
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) throw new Error(`recipient ${recipient.recipient_id} returned HTTP ${res.status}`)
      // A synchronous 2xx is delivery, not acknowledgement. Acknowledgement is a separate,
      // recorded act with its own deadline — conflating them would let a recipient that
      // returns 200 and drops the message count as having confirmed deletion.
      return { dispatched: true, reason: null }
    },
  }
}

// =========================================================================================
// Small utilities
// =========================================================================================

function randomId(bytes = 16) {
  const b = new Uint8Array(bytes)
  crypto.getRandomValues(b)
  return base64url(b)
}

async function sha256b64(domain, text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain + text))
  return base64url(new Uint8Array(digest))
}

/** Constant-time string compare for the admin bearer token. */
function timingSafeEqual(a, b) {
  const enc = new TextEncoder()
  const x = enc.encode(String(a))
  const y = enc.encode(String(b))
  if (x.length !== y.length) return false
  let diff = 0
  for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i]
  return diff === 0
}

/**
 * Identifier normalisation, per class. Deliberately narrow and exact-match only.
 *
 * These are OUR canonicalisation rules, not DROP's. Item 4 of the adapter checklist: the
 * classes DROP actually supplies and the normalisation it expects must be confirmed. A
 * mismatch here produces false "no match" dispositions, which is the worst failure mode in
 * the file — it is a wrong answer to a regulator that looks like a right one.
 */
const IDENTIFIER_NORMALISERS = Object.freeze({
  email: (v) => String(v).trim().toLowerCase(),
  phone: (v) => String(v).replace(/\D+/g, '').replace(/^1(?=\d{10}$)/, ''),
  name_zip: (v) => String(v).trim().toLowerCase().replace(/\s+/g, ' '),
})

/**
 * Keyed digest of a subject's identifiers. HMAC, not a bare hash, for exactly the reason
 * vin.js keys the vehicle pseudonym: an unkeyed SHA-256 of an email address is a
 * rainbow-table lookup, so an unkeyed suppression list would be a queryable roster of
 * every consumer who has asked to be deleted — a new privacy harm created by the privacy
 * machinery. The key lives in env (a Workers secret) and never in D1.
 *
 * One digest per identifier CLASS, not one over the whole tuple: DROP may supply only a
 * phone number in one request and only an email in another, and a tuple digest would fail
 * to match the same person across the two.
 */
async function subjectDigests(env, identifiers) {
  const key = env.SUBJECT_MATCH_KEY
  if (typeof key !== 'string' || key.length < 32) {
    throw new Error(
      'SUBJECT_MATCH_KEY is missing or too short (>= 32 chars). Refusing to fall back to an ' +
        'unkeyed digest: an unkeyed suppression list is a roster of everyone who asked to be deleted',
    )
  }
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const out = []
  for (const [cls, raw] of Object.entries(identifiers ?? {})) {
    const normalise = IDENTIFIER_NORMALISERS[cls]
    if (!normalise) {
      // Fail closed on an unknown identifier class: silently dropping one means matching on
      // less than DROP gave us, and reporting "no match" we did not earn.
      throw new Error(`unknown identifier class "${cls}" from DROP; add a normaliser or reject the batch`)
    }
    const value = normalise(raw)
    if (value.length === 0) continue
    const mac = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(`${SUBJECT_DIGEST_DOMAIN}${cls}:${value}`))
    out.push({ class: cls, digest: base64url(new Uint8Array(mac)) })
  }
  if (out.length === 0) throw new Error('deletion request carried no usable identifier; refusing to record a matchable-as-nothing request')
  return out
}

// =========================================================================================
// Audit chain
// =========================================================================================

/**
 * Append one hash-chained audit event and return its digest.
 *
 * Serialisation assumption: the chain is only well-formed if appends do not interleave.
 * The cron loop holds `run_lease` for its whole cycle and the HTTP routes that append are
 * admin-only, so in practice appends are serial. If that ever stops being true the chain
 * forks silently, so `verifyAuditChain` exists and the status endpoint reports its result
 * rather than assuming it.
 */
async function appendAudit(db, event) {
  const head = await db.prepare('SELECT digest FROM audit_log ORDER BY seq DESC LIMIT 1').first()
  const prev = head?.digest ?? AUDIT_GENESIS_DIGEST
  const row = {
    at: event.at,
    event_type: event.event_type,
    severity: event.severity ?? 'info',
    batch_id: event.batch_id ?? null,
    request_id: event.request_id ?? null,
    recipient_id: event.recipient_id ?? null,
    clock_id: event.clock_id ?? null,
    detail: canonicalize(event.detail ?? {}),
    prev_digest: prev,
  }
  const digest = await sha256b64(AUDIT_EVENT_DOMAIN, canonicalize(row))
  await db
    .prepare(
      `INSERT INTO audit_log (at, event_type, severity, batch_id, request_id, recipient_id, clock_id, detail, prev_digest, digest)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(row.at, row.event_type, row.severity, row.batch_id, row.request_id, row.recipient_id, row.clock_id, row.detail, row.prev_digest, digest)
    .run()
  return digest
}

/** Recompute the chain over a range and report the first break. Cheap tamper evidence, no ledger. */
async function verifyAuditChain(db, fromSeq = 0) {
  const { results } = await db
    .prepare('SELECT * FROM audit_log WHERE seq >= ? ORDER BY seq ASC')
    .bind(fromSeq)
    .all()
  let prev = null
  for (const r of results) {
    const recomputed = await sha256b64(
      AUDIT_EVENT_DOMAIN,
      canonicalize({
        at: r.at,
        event_type: r.event_type,
        severity: r.severity,
        batch_id: r.batch_id,
        request_id: r.request_id,
        recipient_id: r.recipient_id,
        clock_id: r.clock_id,
        detail: r.detail,
        prev_digest: r.prev_digest,
      }),
    )
    if (recomputed !== r.digest) return { ok: false, broken_at_seq: r.seq, reason: 'digest mismatch' }
    if (prev !== null && r.prev_digest !== prev) return { ok: false, broken_at_seq: r.seq, reason: 'chain link mismatch' }
    prev = r.digest
  }
  return { ok: true, broken_at_seq: null, reason: null, head_digest: prev ?? AUDIT_GENESIS_DIGEST, event_count: results.length }
}

/**
 * Produce and seal the audit file for a batch. THIS RUNS BEFORE ANY STATUS REPORT.
 *
 * The file is the report's only input, so its contents define what can be reported. It
 * carries DROP's own opaque request ids, our state names, counts, deadline states and
 * digests — and no consumer identifiers, not even the keyed ones. The audit file outlives
 * every other record here and gets exported; it is the last place PI should be allowed to
 * accumulate.
 */
export async function sealAuditFile(env, batchId, now) {
  assertInstant(now, 'now')
  const db = requireDb(env)
  const batch = await db.prepare('SELECT * FROM retrieval_batch WHERE batch_id = ?').bind(batchId).first()
  if (!batch) throw new Error(`unknown batch ${batchId}`)

  const { results: requests } = await db
    .prepare(
      `SELECT request_id, drop_request_id, received_at, report_due_at, deletion_due_at, match_state,
              deletion_state, deletion_completed_at, reported_status, exemption_basis
         FROM deletion_request WHERE batch_id = ? ORDER BY drop_request_id ASC`,
    )
    .bind(batchId)
    .all()

  const { results: directives } = await db
    .prepare(
      `SELECT d.directive_id, d.request_id, d.recipient_id, d.state, d.created_at, d.dispatched_at,
              d.ack_required_by, d.acknowledged_at, d.ack_digest, d.attempts
         FROM downstream_directive d
         JOIN deletion_request r ON r.request_id = d.request_id
        WHERE r.batch_id = ? ORDER BY d.directive_id ASC`,
    )
    .bind(batchId)
    .all()

  const { results: matches } = await db
    .prepare(
      `SELECT m.request_id, m.store, m.erasure_state, m.erased_at, m.salt_destroyed_at, m.evidence_digest
         FROM subject_match m JOIN deletion_request r ON r.request_id = m.request_id
        WHERE r.batch_id = ? ORDER BY m.match_id ASC`,
    )
    .bind(batchId)
    .all()

  const chainRange = await db
    .prepare('SELECT MIN(seq) AS from_seq, MAX(seq) AS to_seq, COUNT(*) AS n FROM audit_log WHERE batch_id = ?')
    .bind(batchId)
    .first()
  const head = await db.prepare('SELECT digest FROM audit_log ORDER BY seq DESC LIMIT 1').first()

  const pendingAcks = directives.filter((d) => d.acknowledged_at === null && d.state !== 'refused').length
  const clockStates = batchClockStates({ ...batch, pending_ack_count: pendingAcks }, now)

  const content = {
    v: AUDIT_FILE_SCHEMA,
    sealed_at: now,
    batch: {
      batch_id: batch.batch_id,
      adapter_id: batch.adapter_id,
      attempted_at: batch.attempted_at,
      outcome: batch.outcome,
      retrieved_at: batch.retrieved_at,
      request_count: batch.request_count,
      matched_count: batch.matched_count,
    },
    // Both clocks, named and separated, in the artefact a regulator reads. The audit file
    // is where the 45/90 distinction has to be legible without reading the code.
    clock_definitions: CLOCKS,
    clocks: {
      status_report: clockStates.status_report,
      deletion_completion: clockStates.deletion_completion,
    },
    step_order_violations: stepOrderViolations({ ...batch, pending_ack_count: pendingAcks }),
    internal_targets: batch.retrieved_at === null ? null : internalTargetsForRetrieval(batch.retrieved_at),
    counts: {
      requests: requests.length,
      by_match_state: tally(requests, 'match_state'),
      by_deletion_state: tally(requests, 'deletion_state'),
      directives: directives.length,
      directives_acknowledged: directives.filter((d) => d.acknowledged_at !== null).length,
      directives_pending_ack: pendingAcks,
      matches: matches.length,
      matches_erased: matches.filter((m) => m.erasure_state === 'erased').length,
      salts_destroyed: matches.filter((m) => m.salt_destroyed_at !== null).length,
    },
    // Per-request disposition. `drop_request_id` is DROP's own opaque handle, which is what
    // a regulator reconciles against; no identifier or subject digest appears.
    requests: requests.map((r) => ({
      drop_request_id: r.drop_request_id,
      received_at: r.received_at,
      report_due_at: r.report_due_at,
      deletion_due_at: r.deletion_due_at,
      match_state: r.match_state,
      deletion_state: r.deletion_state,
      deletion_completed_at: r.deletion_completed_at,
      exemption_basis: r.exemption_basis,
      downstream: directives
        .filter((d) => d.request_id === r.request_id)
        .map((d) => ({
          recipient_id: d.recipient_id,
          state: d.state,
          dispatched_at: d.dispatched_at,
          ack_required_by: d.ack_required_by,
          acknowledged_at: d.acknowledged_at,
          ack_digest: d.ack_digest,
          attempts: d.attempts,
        })),
      erasures: matches
        .filter((m) => m.request_id === r.request_id)
        .map((m) => ({
          store: m.store,
          erasure_state: m.erasure_state,
          erased_at: m.erased_at,
          salt_destroyed_at: m.salt_destroyed_at,
          evidence_digest: m.evidence_digest,
        })),
    })),
    audit_chain: {
      from_seq: chainRange?.from_seq ?? 0,
      to_seq: chainRange?.to_seq ?? 0,
      event_count: chainRange?.n ?? 0,
      head_digest: head?.digest ?? AUDIT_GENESIS_DIGEST,
    },
  }

  const canonical = canonicalize(content)
  const contentDigest = await sha256b64(AUDIT_FILE_DOMAIN, canonical)
  const auditFileId = randomId()

  await db
    .prepare(
      `INSERT INTO audit_file (audit_file_id, batch_id, sealed_at, from_seq, to_seq, event_count, head_digest, content, content_digest)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      auditFileId,
      batchId,
      now,
      content.audit_chain.from_seq,
      content.audit_chain.to_seq,
      content.audit_chain.event_count,
      content.audit_chain.head_digest,
      canonical,
      contentDigest,
    )
    .run()

  // The batch-level seal instant is what the CHECK on retrieval_batch and the triggers on
  // status_report compare against. Written in the same step as the file, never later.
  await db
    .prepare('UPDATE retrieval_batch SET audit_sealed_at = ? WHERE batch_id = ? AND (audit_sealed_at IS NULL OR audit_sealed_at > ?)')
    .bind(now, batchId, now)
    .run()

  await appendAudit(db, {
    at: now,
    event_type: 'audit_file.sealed',
    batch_id: batchId,
    detail: { audit_file_id: auditFileId, content_digest: contentDigest, event_count: content.audit_chain.event_count },
  })

  return { audit_file_id: auditFileId, sealed_at: now, content_digest: contentDigest, content }
}

function tally(rows, column) {
  const out = {}
  for (const r of rows) out[r[column]] = (out[r[column]] ?? 0) + 1
  return out
}

// =========================================================================================
// The cycle
// =========================================================================================

function requireDb(env) {
  if (!env?.DB || typeof env.DB.prepare !== 'function') {
    throw new Error('D1 binding "DB" is missing; see wrangler.toml')
  }
  return env.DB
}

async function acquireLease(db, now, holder) {
  const res = await db
    .prepare(
      `INSERT INTO run_lease (lease_name, holder, acquired_at, lease_until) VALUES (?, ?, ?, ?)
         ON CONFLICT(lease_name) DO UPDATE SET holder = excluded.holder, acquired_at = excluded.acquired_at,
                                              lease_until = excluded.lease_until
          WHERE run_lease.lease_until < ?`,
    )
    .bind(LEASE_NAME, holder, now, now + LEASE_TTL_S, now)
    .run()
  return (res.meta?.changes ?? 0) > 0
}

async function releaseLease(db, holder) {
  await db.prepare('UPDATE run_lease SET lease_until = 0 WHERE lease_name = ? AND holder = ?').bind(LEASE_NAME, holder).run()
}

async function lastSuccessfulAccessAt(db) {
  const row = await db
    .prepare("SELECT retrieved_at FROM retrieval_batch WHERE outcome = 'retrieved' ORDER BY retrieved_at DESC LIMIT 1")
    .first()
  return row?.retrieved_at ?? null
}

async function latestCursor(db) {
  const row = await db
    .prepare("SELECT drop_cursor_after FROM retrieval_batch WHERE outcome = 'retrieved' ORDER BY retrieved_at DESC LIMIT 1")
    .first()
  return row?.drop_cursor_after ?? null
}

/**
 * Step 1 — access DROP (CLOCK A1) and open a batch.
 *
 * The attempt row is written BEFORE the adapter is called, so a Worker that dies mid-call
 * leaves evidence that an attempt happened. An access is only credited as `retrieved` when
 * the adapter returns; a thrown adapter marks the row `failed`/`adapter_unconfigured` and
 * leaves CLOCK A1 running, which is the entire reason failed attempts are rows.
 */
async function retrieveIfDue(env, now, adapters, force = false) {
  const db = requireDb(env)
  const lastAccess = await lastSuccessfulAccessAt(db)
  const access = accessClockState(lastAccess, now)

  // Internal target, not the statutory floor: acting only at the floor means the first
  // failure is already a violation. See INTERNAL_ACCESS_CADENCE_S in clocks.js.
  const due = force || access.internal_target_missed || access.state === 'overdue' || lastAccess === null
  if (!due) return { ran: false, reason: 'access not yet due under the internal cadence', access }

  if (!isProcessingObligationActive(now) && !force) {
    // Before 2026-08-01 there is nothing to retrieve. Recorded, not skipped silently, so
    // the audit trail shows the system was live and waiting rather than absent.
    await appendAudit(db, {
      at: now,
      event_type: 'access.deferred_pre_obligation',
      clock_id: 'access_cadence',
      detail: { obligation_starts_at: PROCESSING_OBLIGATION_START_S },
    })
    return { ran: false, reason: 'DROP processing obligation begins 2026-08-01', access }
  }

  const batchId = randomId()
  const cursorBefore = await latestCursor(db)
  await db
    .prepare(
      `INSERT INTO retrieval_batch (batch_id, attempted_at, outcome, adapter_id, drop_cursor_before)
       VALUES (?, ?, 'in_progress', ?, ?)`,
    )
    .bind(batchId, now, adapters.drop.id, cursorBefore)
    .run()
  await appendAudit(db, {
    at: now,
    event_type: 'access.attempted',
    batch_id: batchId,
    clock_id: 'access_cadence',
    detail: { adapter_id: adapters.drop.id, last_access_at: lastAccess, due_at: access.due_at },
  })

  let result
  try {
    result = await adapters.drop.retrieveDeletionRequests({ cursor: cursorBefore })
  } catch (err) {
    const unconfigured = err instanceof DropAdapterNotConfigured
    await db
      .prepare('UPDATE retrieval_batch SET outcome = ?, error = ? WHERE batch_id = ?')
      .bind(unconfigured ? 'adapter_unconfigured' : 'failed', String(err.message).slice(0, 900), batchId)
      .run()
    await appendAudit(db, {
      at: now,
      event_type: 'access.failed',
      batch_id: batchId,
      clock_id: 'access_cadence',
      // A failed access after the obligation date is a breach-severity event even though
      // CLOCK A1 has not expired yet: the daily cron means a failure repeated for 45 days
      // is the only way to breach, and each individual failure is the early warning.
      severity: isProcessingObligationActive(now) ? 'breach' : 'warn',
      detail: { error_name: err.name, unconfigured },
    })
    return { ran: true, ok: false, batch_id: batchId, error: err.message, access }
  }

  const retrievedAt = Number.isInteger(result?.retrieved_at) ? result.retrieved_at : now
  assertInstant(retrievedAt, 'adapter retrieved_at')
  const deadlines = deadlinesForRetrieval(retrievedAt)
  const requests = Array.isArray(result?.requests) ? result.requests : []

  // The batch is credited as 'retrieved' only AFTER every request has been persisted, at
  // the bottom of this function. Ordering matters: `outcome = 'retrieved'` is what resets
  // CLOCK A1, so writing it first and then failing halfway through the request loop would
  // credit a full access while silently dropping requests — the one bookkeeping error in
  // this file that converts into unprocessed deletion requests nobody knows about.
  try {
    await persistRequests()
  } catch (err) {
    await db
      .prepare("UPDATE retrieval_batch SET outcome = 'failed', error = ? WHERE batch_id = ?")
      .bind(`partial retrieval: ${String(err.message).slice(0, 860)}`, batchId)
      .run()
    await appendAudit(db, {
      at: now,
      event_type: 'access.partial_failed',
      severity: 'breach',
      batch_id: batchId,
      clock_id: 'access_cadence',
      detail: { error_name: err.name, requests_offered: requests.length },
    })
    return { ran: true, ok: false, batch_id: batchId, error: err.message, access }
  }

  await db
    .prepare(
      `UPDATE retrieval_batch
          SET outcome = 'retrieved', retrieved_at = ?, report_due_at = ?, deletion_due_at = ?,
              next_access_due_at = ?, internal_next_access_at = ?, request_count = ?, drop_cursor_after = ?
        WHERE batch_id = ?`,
    )
    .bind(
      deadlines.retrieved_at,
      deadlines.report_due_at,
      deadlines.deletion_due_at,
      deadlines.next_access_due_at,
      deadlines.internal_next_access_at,
      requests.length,
      result?.cursor ?? null,
      batchId,
    )
    .run()

  await appendAudit(db, {
    at: now,
    event_type: 'access.retrieved',
    batch_id: batchId,
    clock_id: 'access_cadence',
    detail: {
      request_count: requests.length,
      report_due_at: deadlines.report_due_at,
      deletion_due_at: deadlines.deletion_due_at,
      next_access_due_at: deadlines.next_access_due_at,
    },
  })

  return { ran: true, ok: true, batch_id: batchId, request_count: requests.length, deadlines, access }

  async function persistRequests() {
    for (const req of requests) {
    if (typeof req?.drop_request_id !== 'string' || req.drop_request_id.length === 0) {
      throw new Error('DROP request without a drop_request_id; refusing to record an unidentifiable request')
    }
    const digests = await subjectDigests(env, req.identifiers)
    const requestId = randomId()
    // The primary digest is the first class present, in the adapter's own order; every
    // digest is written to the suppression list so a later match on any single identifier
    // still finds the suppression entry.
    //
    // Uniqueness is (batch_id, drop_request_id), so a request DROP serves again in a later
    // batch becomes a second row with its own pair of deadlines rather than being skipped.
    // That is the deliberate direction: cursor-replay semantics are unconfirmed (adapter
    // checklist item 5), and re-processing a request costs a duplicate report line, while
    // suppressing it as "already seen" costs a missed deletion. Re-verify once the cursor
    // contract is known — if DROP guarantees at-most-once delivery this can tighten.
    await db
      .prepare(
        `INSERT OR IGNORE INTO deletion_request
           (request_id, batch_id, drop_request_id, subject_digest, identifier_classes, received_at,
            report_due_at, deletion_due_at, purge_after)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        requestId,
        batchId,
        req.drop_request_id,
        digests[0].digest,
        canonicalize(digests.map((d) => d.class)),
        retrievedAt,
        deadlines.report_due_at,
        deadlines.deletion_due_at,
        stagingPurgeAt(env, retrievedAt),
      )
      .run()

    // Re-read the persisted id rather than trusting `requestId`: the INSERT above is OR
    // IGNORE, so if the same drop_request_id appeared twice in one page the row we are
    // about to reference is the FIRST one, not ours. Binding a request_id that was never
    // inserted would violate suppression_list's foreign key and abort the whole retrieval.
    const persisted = await db
      .prepare('SELECT request_id FROM deletion_request WHERE batch_id = ? AND drop_request_id = ?')
      .bind(batchId, req.drop_request_id)
      .first()
    const sourceRequestId = persisted?.request_id ?? null

    // Suppression is created for EVERY request, matched or not: a consumer who owns no
    // vehicle today and enrols one next month is exactly who the list is for. See the
    // note on suppression_list in schema.sql.
    for (const d of digests) {
      await db
        .prepare(
          `INSERT INTO suppression_list (subject_digest, first_added_at, last_affirmed_at, source_request_id, scope, active)
           VALUES (?, ?, ?, ?, 'all', 1)
             ON CONFLICT(subject_digest) DO UPDATE SET last_affirmed_at = excluded.last_affirmed_at`,
        )
        .bind(d.digest, retrievedAt, retrievedAt, sourceRequestId)
        .run()
    }
  }

  await appendAudit(db, {
    at: now,
    event_type: 'access.retrieved',
    batch_id: batchId,
    clock_id: 'access_cadence',
    detail: {
      request_count: requests.length,
      report_due_at: deadlines.report_due_at,
      deletion_due_at: deadlines.deletion_due_at,
      next_access_due_at: deadlines.next_access_due_at,
    },
  })

  return { ran: true, ok: true, batch_id: batchId, request_count: requests.length, deadlines, access }
}

/**
 * Staging retention. Returns null unless the operator has configured a period.
 *
 * No default: the retention period trades audit-defence value against the
 * data-minimisation duty that motivated the whole regime, and that is a decision for
 * counsel. A hardcoded default here would become the policy by accident.
 */
function stagingPurgeAt(env, retrievedAt) {
  const days = Number(env?.REQUEST_STAGING_RETENTION_DAYS)
  if (!Number.isInteger(days) || days <= 0) return null
  return retrievedAt + days * DAY_S
}

/** Step 2 — match each open request against local records. */
async function matchOpenRequests(env, now, adapters) {
  const db = requireDb(env)
  const { results } = await db
    .prepare("SELECT * FROM deletion_request WHERE match_state IN ('unmatched', 'error') ORDER BY received_at ASC LIMIT 200")
    .all()
  let matched = 0
  let errored = 0
  for (const req of results) {
    try {
      const found = await adapters.erasure.findMatches(req.subject_digest)
      if (!Array.isArray(found)) throw new Error('erasure adapter findMatches must return an array')
      for (const m of found) {
        await db
          .prepare(
            `INSERT OR IGNORE INTO subject_match (match_id, request_id, store, local_ref, matched_at, match_method)
             VALUES (?, ?, ?, ?, ?, 'exact_digest')`,
          )
          .bind(randomId(), req.request_id, String(m.store), String(m.local_ref), now)
          .run()
      }
      const state = found.length === 0 ? 'no_match' : 'matched'
      await db
        .prepare('UPDATE deletion_request SET match_state = ?, deletion_state = ? WHERE request_id = ?')
        .bind(state, found.length === 0 ? 'no_action_required' : 'in_progress', req.request_id)
        .run()
      if (found.length > 0) matched += 1
      await appendAudit(db, {
        at: now,
        event_type: 'request.matched',
        batch_id: req.batch_id,
        request_id: req.request_id,
        detail: { match_state: state, match_count: found.length },
      })
    } catch (err) {
      // 'error', never 'no_match'. See stubErasureAdapter.
      errored += 1
      await db.prepare("UPDATE deletion_request SET match_state = 'error' WHERE request_id = ?").bind(req.request_id).run()
      await appendAudit(db, {
        at: now,
        event_type: 'request.match_failed',
        severity: 'breach',
        batch_id: req.batch_id,
        request_id: req.request_id,
        detail: { error_name: err.name },
      })
    }
  }
  if (matched > 0) {
    await db
      .prepare(
        `UPDATE retrieval_batch SET matched_count = (
           SELECT COUNT(*) FROM deletion_request WHERE deletion_request.batch_id = retrieval_batch.batch_id AND match_state = 'matched')
         WHERE outcome = 'retrieved'`,
      )
      .run()
  }
  return { considered: results.length, matched, errored }
}

/**
 * Step 3 — create and dispatch downstream deletion directives.
 *
 * Only matched requests fan out. If nothing local matched, nothing was ever shared with a
 * service provider under that subject, so there is nothing to direct — which is also why
 * matching has an earlier internal target (day 7) than dispatch (day 14).
 *
 * The directive names LOCAL RECORD REFERENCES, not the consumer. A recipient holding data
 * keyed by our pseudonyms can act on refs; sending them the consumer's identifiers would
 * disclose more PI in the course of deleting PI.
 */
async function fanOutDirectives(env, now, adapters) {
  const db = requireDb(env)
  const { results: recipients } = await db.prepare('SELECT * FROM downstream_recipient WHERE active = 1').all()
  const { results: requests } = await db
    .prepare("SELECT * FROM deletion_request WHERE match_state = 'matched' AND deletion_completed_at IS NULL LIMIT 200")
    .all()

  let created = 0
  let dispatched = 0
  let failed = 0
  for (const req of requests) {
    const { results: refs } = await db
      .prepare("SELECT store, local_ref FROM subject_match WHERE request_id = ? AND erasure_state <> 'not_found'")
      .bind(req.request_id)
      .all()
    for (const rec of recipients) {
      const directiveId = randomId()
      const ins = await db
        .prepare(
          `INSERT OR IGNORE INTO downstream_directive (directive_id, request_id, recipient_id, created_at, ack_required_by, state)
           VALUES (?, ?, ?, ?, ?, 'pending')`,
        )
        .bind(directiveId, req.request_id, rec.recipient_id, now, now + rec.ack_window_s)
        .run()
      if ((ins.meta?.changes ?? 0) > 0) created += 1

      const directive = await db
        .prepare('SELECT * FROM downstream_directive WHERE request_id = ? AND recipient_id = ?')
        .bind(req.request_id, rec.recipient_id)
        .first()
      if (!directive || directive.acknowledged_at !== null || directive.state === 'refused') continue
      if (directive.dispatched_at !== null && directive.attempts >= 3) continue

      const payload = {
        v: DIRECTIVE_SCHEMA,
        directive_id: directive.directive_id,
        action: 'delete',
        issued_at: now,
        ack_required_by: directive.ack_required_by,
        deletion_due_at: req.deletion_due_at,
        drop_request_ref: req.drop_request_id,
        records: refs.map((r) => ({ store: r.store, local_ref: r.local_ref })),
      }
      try {
        const out = await adapters.dispatch.dispatch(rec, payload)
        const payloadDigest = await sha256b64(PAYLOAD_DIGEST_DOMAIN, canonicalize(payload))
        if (out.dispatched) {
          dispatched += 1
          await db
            .prepare(
              "UPDATE downstream_directive SET state = 'dispatched', dispatched_at = ?, attempts = attempts + 1, last_error = NULL WHERE directive_id = ?",
            )
            .bind(now, directive.directive_id)
            .run()
        } else {
          await db
            .prepare('UPDATE downstream_directive SET attempts = attempts + 1, last_error = ? WHERE directive_id = ?')
            .bind(String(out.reason).slice(0, 400), directive.directive_id)
            .run()
        }
        await appendAudit(db, {
          at: now,
          event_type: out.dispatched ? 'directive.dispatched' : 'directive.awaiting_manual',
          batch_id: req.batch_id,
          request_id: req.request_id,
          recipient_id: rec.recipient_id,
          detail: { directive_id: directive.directive_id, payload_digest: payloadDigest, record_count: refs.length },
        })
      } catch (err) {
        failed += 1
        await db
          .prepare("UPDATE downstream_directive SET state = 'failed', attempts = attempts + 1, last_error = ? WHERE directive_id = ?")
          .bind(String(err.message).slice(0, 400), directive.directive_id)
          .run()
        await appendAudit(db, {
          at: now,
          event_type: 'directive.dispatch_failed',
          severity: 'warn',
          batch_id: req.batch_id,
          request_id: req.request_id,
          recipient_id: rec.recipient_id,
          detail: { directive_id: directive.directive_id, error_name: err.name },
        })
      }
    }
  }
  return { created, dispatched, failed }
}

/**
 * Step 4 — perform the local erasure and, when every downstream recipient has
 * acknowledged, mark the request complete (CLOCK B).
 *
 * `deletion_completed_at` is set only when (a) the adapter positively confirmed erasure of
 * every match INCLUDING salt destruction, and (b) no directive is outstanding. Marking
 * completion on a non-throwing delete call, or while a contractor has not answered, is how
 * a 90-day obligation gets reported as satisfied with the data still live somewhere.
 */
async function completeDeletions(env, now, adapters) {
  const db = requireDb(env)
  const { results: requests } = await db
    .prepare("SELECT * FROM deletion_request WHERE deletion_state = 'in_progress' AND deletion_completed_at IS NULL LIMIT 200")
    .all()
  let completed = 0
  let blocked = 0
  for (const req of requests) {
    const { results: pending } = await db
      .prepare("SELECT * FROM subject_match WHERE request_id = ? AND erasure_state = 'pending'")
      .bind(req.request_id)
      .all()
    if (pending.length > 0) {
      try {
        const receipts = await adapters.erasure.erase(pending.map((m) => ({ store: m.store, local_ref: m.local_ref })))
        for (const r of receipts ?? []) {
          const evidence = r.receipt ? await sha256b64(PAYLOAD_DIGEST_DOMAIN, canonicalize(r.receipt)) : null
          await db
            .prepare(
              `UPDATE subject_match SET erasure_state = ?, erased_at = ?, salt_destroyed_at = ?, evidence_digest = ?
                WHERE request_id = ? AND store = ? AND local_ref = ?`,
            )
            .bind(
              r.erased ? 'erased' : 'failed',
              r.erased ? now : null,
              r.salt_destroyed ? now : null,
              evidence,
              req.request_id,
              String(r.store),
              String(r.local_ref),
            )
            .run()
        }
      } catch (err) {
        blocked += 1
        await db.prepare("UPDATE deletion_request SET deletion_state = 'blocked' WHERE request_id = ?").bind(req.request_id).run()
        await appendAudit(db, {
          at: now,
          event_type: 'erasure.failed',
          severity: 'breach',
          batch_id: req.batch_id,
          request_id: req.request_id,
          clock_id: 'deletion_completion',
          detail: { error_name: err.name },
        })
        continue
      }
    }

    const outstanding = await db
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM subject_match WHERE request_id = ? AND erasure_state <> 'erased' AND erasure_state <> 'not_found') AS matches_open,
           (SELECT COUNT(*) FROM downstream_directive WHERE request_id = ? AND acknowledged_at IS NULL AND state <> 'refused') AS acks_open`,
      )
      .bind(req.request_id, req.request_id)
      .first()
    if ((outstanding?.matches_open ?? 1) > 0 || (outstanding?.acks_open ?? 1) > 0) continue

    await db
      .prepare("UPDATE deletion_request SET deletion_state = 'complete', deletion_completed_at = ? WHERE request_id = ?")
      .bind(now, req.request_id)
      .run()
    completed += 1
    await appendAudit(db, {
      at: now,
      event_type: 'request.deletion_completed',
      batch_id: req.batch_id,
      request_id: req.request_id,
      clock_id: 'deletion_completion',
      detail: { due_at: req.deletion_due_at, late: now > req.deletion_due_at },
    })
  }

  // Batch-level CLOCK B closes only when every request in it is terminal. 'exempt' and
  // 'no_action_required' are terminal; 'blocked' and 'error' are not, and a batch carrying
  // one stays open and overdue rather than being rounded up to complete.
  await db
    .prepare(
      `UPDATE retrieval_batch SET deletion_completed_at = ?
        WHERE outcome = 'retrieved' AND deletion_completed_at IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM deletion_request r WHERE r.batch_id = retrieval_batch.batch_id
              AND r.deletion_state NOT IN ('complete', 'no_action_required', 'exempt'))`,
    )
    .bind(now)
    .run()

  return { considered: requests.length, completed, blocked }
}

/**
 * Step 5 — status report (CLOCK A2). AUDIT FILE FIRST, ALWAYS.
 *
 * Ordering enforcement, in the order it executes:
 *   1. `sealAuditFile` writes the file and stamps `retrieval_batch.audit_sealed_at`.
 *   2. The file is RE-READ from D1 and its `content_digest` recomputed. A seal we cannot
 *      re-read and verify does not count — otherwise the guarantee rests on a variable in
 *      this function's scope, which proves nothing about what was persisted.
 *   3. The report payload is derived from the re-read file's stored content. It is not
 *      rebuilt from live tables, so it cannot contain an unaudited claim.
 *   4. The `status_report` row is inserted (trigger: sealed_at <= built_at).
 *   5. Only then is the adapter called, and `reported_at` written (CHECK on
 *      retrieval_batch: audit_sealed_at <= reported_at).
 */
async function submitStatusReportForBatch(env, batchId, now, adapters) {
  const db = requireDb(env)
  const sealed = await sealAuditFile(env, batchId, now)

  const stored = await db.prepare('SELECT * FROM audit_file WHERE audit_file_id = ?').bind(sealed.audit_file_id).first()
  if (!stored) throw new AuditOrderingViolation('audit file was not persisted; refusing to file a status report')
  if (!Number.isInteger(stored.sealed_at) || stored.sealed_at > now) {
    throw new AuditOrderingViolation(`audit file ${stored.audit_file_id} has no usable sealed_at; refusing to file a status report`)
  }
  const recomputed = await sha256b64(AUDIT_FILE_DOMAIN, stored.content)
  if (recomputed !== stored.content_digest) {
    throw new AuditOrderingViolation(
      `audit file ${stored.audit_file_id} digest mismatch (stored ${stored.content_digest}, recomputed ${recomputed}); ` +
        'refusing to file a status report derived from an unverifiable audit file',
    )
  }

  // Derived from the audit file, not from the database.
  const audited = JSON.parse(stored.content)
  const disposition = {
    v: DISPOSITION_SCHEMA,
    batch_id: audited.batch.batch_id,
    retrieved_at: audited.batch.retrieved_at,
    report_due_at: audited.clocks.status_report.due_at,
    deletion_due_at: audited.clocks.deletion_completion.due_at,
    // Both clocks are stated separately in the filing itself. If the disposition we file
    // ever carries one date, this is where the conflation would have re-entered.
    audit_file: { audit_file_id: stored.audit_file_id, sealed_at: stored.sealed_at, content_digest: stored.content_digest },
    counts: audited.counts,
    requests: audited.requests.map((r) => ({
      drop_request_id: r.drop_request_id,
      match_state: r.match_state,
      deletion_state: r.deletion_state,
      deletion_completed_at: r.deletion_completed_at,
      exemption_basis: r.exemption_basis,
    })),
  }
  const payloadDigest = await sha256b64(PAYLOAD_DIGEST_DOMAIN, canonicalize(disposition))

  const reportId = randomId()
  await db
    .prepare(
      `INSERT INTO status_report (report_id, batch_id, audit_file_id, due_at, built_at, payload_digest, adapter_id, state)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'built')`,
    )
    .bind(reportId, batchId, stored.audit_file_id, disposition.report_due_at, now, payloadDigest, adapters.drop.id)
    .run()

  try {
    const res = await adapters.drop.submitStatusReport({ disposition })
    const submittedAt = now
    await db
      .prepare("UPDATE status_report SET state = 'submitted', submitted_at = ?, drop_receipt = ? WHERE report_id = ?")
      .bind(submittedAt, String(res?.receipt ?? '').slice(0, 400) || null, reportId)
      .run()
    await db.prepare('UPDATE retrieval_batch SET reported_at = ? WHERE batch_id = ?').bind(submittedAt, batchId).run()
    await db.prepare('UPDATE deletion_request SET reported_at = ?, reported_status = deletion_state WHERE batch_id = ?').bind(submittedAt, batchId).run()
    await appendAudit(db, {
      at: submittedAt,
      event_type: 'status_report.submitted',
      batch_id: batchId,
      clock_id: 'status_report',
      severity: submittedAt > disposition.report_due_at ? 'breach' : 'info',
      detail: {
        report_id: reportId,
        audit_file_id: stored.audit_file_id,
        payload_digest: payloadDigest,
        due_at: disposition.report_due_at,
        late: submittedAt > disposition.report_due_at,
      },
    })
    return { ok: true, report_id: reportId, audit_file_id: stored.audit_file_id }
  } catch (err) {
    await db
      .prepare("UPDATE status_report SET state = 'failed', error = ? WHERE report_id = ?")
      .bind(String(err.message).slice(0, 900), reportId)
      .run()
    await appendAudit(db, {
      at: now,
      event_type: 'status_report.submit_failed',
      batch_id: batchId,
      clock_id: 'status_report',
      severity: now > disposition.report_due_at ? 'breach' : 'warn',
      detail: { report_id: reportId, audit_file_id: stored.audit_file_id, error_name: err.name },
    })
    return { ok: false, report_id: reportId, error: err.message }
  }
}

/** Step 5 driver — every batch whose internal report target has arrived and is unreported. */
async function reportDueBatches(env, now, adapters) {
  const db = requireDb(env)
  const { results } = await db
    .prepare(
      `SELECT batch_id, retrieved_at, report_due_at FROM retrieval_batch
        WHERE outcome = 'retrieved' AND reported_at IS NULL AND retrieved_at IS NOT NULL
        ORDER BY report_due_at ASC LIMIT 25`,
    )
    .all()
  const out = []
  for (const b of results) {
    const targets = internalTargetsForRetrieval(b.retrieved_at)
    if (now < targets.report_by) continue
    out.push(await submitStatusReportForBatch(env, b.batch_id, now, adapters))
  }
  return out
}

/** Step 6 — record every breached deadline as a breach-severity audit event, once per day. */
async function recordOverdue(env, now) {
  const db = requireDb(env)
  const lastAccess = await lastSuccessfulAccessAt(db)
  const { results: batches } = await db
    .prepare(
      `SELECT batch_id, retrieved_at, report_due_at, deletion_due_at, reported_at, deletion_completed_at, audit_sealed_at
         FROM retrieval_batch WHERE outcome = 'retrieved'
          AND (reported_at IS NULL OR deletion_completed_at IS NULL)`,
    )
    .all()
  const overdue = findOverdue({ batches, lastAccessAt: lastAccess }, now)
  for (const o of overdue) {
    if (o.remediated) continue
    const already = await db
      .prepare("SELECT 1 FROM audit_log WHERE event_type = 'clock.overdue' AND clock_id = ? AND IFNULL(batch_id, '') = IFNULL(?, '') AND at > ?")
      .bind(o.id, o.batch_id, now - DAY_S)
      .first()
    if (already) continue
    await appendAudit(db, {
      at: now,
      event_type: 'clock.overdue',
      severity: 'breach',
      batch_id: o.batch_id,
      clock_id: o.id,
      detail: { clock: o.clock, due_at: o.due_at, overdue_by_s: o.overdue_by_s },
    })
  }
  return overdue
}

/** Step 7 — purge staged request material once the configured retention has elapsed. */
async function purgeExpiredStaging(env, now) {
  const db = requireDb(env)
  const res = await db
    .prepare(
      `DELETE FROM deletion_request
        WHERE purge_after IS NOT NULL AND purge_after < ?
          AND reported_at IS NOT NULL
          AND (deletion_completed_at IS NOT NULL OR deletion_state IN ('no_action_required', 'exempt'))`,
    )
    .bind(now)
    .run()
  const purged = res.meta?.changes ?? 0
  if (purged > 0) {
    // Suppression entries are NOT purged with the request; the direction not to re-collect
    // outlives the record of the request that created it.
    await appendAudit(db, { at: now, event_type: 'staging.purged', detail: { rows: purged } })
  }
  return { purged }
}

/**
 * The whole cycle, single-flighted. Steps run in dependency order and each one is
 * independently retryable, because the failure mode that matters is a partial run — and a
 * partial run that cannot be resumed becomes a missed deadline.
 */
export async function runComplianceCycle(env, now, options = {}) {
  assertInstant(now, 'now')
  const db = requireDb(env)
  const adapters = {
    drop: options.dropAdapter ?? env.DROP_ADAPTER ?? stubDropAdapter,
    erasure: options.erasureAdapter ?? env.ERASURE_ADAPTER ?? stubErasureAdapter,
    dispatch: options.dispatchAdapter ?? defaultDispatchAdapter(env),
  }
  const holder = randomId(8)
  if (!(await acquireLease(db, now, holder))) {
    return { ran: false, reason: 'another compliance cycle holds the lease' }
  }
  const steps = {}
  try {
    steps.retrieval = await retrieveIfDue(env, now, adapters, options.force === true)
    steps.matching = await matchOpenRequests(env, now, adapters)
    steps.fanout = await fanOutDirectives(env, now, adapters)
    steps.deletion = await completeDeletions(env, now, adapters)
    steps.reporting = await reportDueBatches(env, now, adapters)
    steps.overdue = await recordOverdue(env, now)
    steps.purge = await purgeExpiredStaging(env, now)
  } finally {
    await releaseLease(db, holder)
  }
  return { ran: true, at: now, adapters: { drop: adapters.drop.id, erasure: adapters.erasure.id, dispatch: adapters.dispatch.id }, steps }
}

// =========================================================================================
// HTTP surface
// =========================================================================================

const ROUTES = [
  { method: 'GET', pattern: new URLPattern({ pathname: '/health' }), handler: handleHealth, public: true },
  { method: 'GET', pattern: new URLPattern({ pathname: '/compliance/clocks' }), handler: handleClocks, public: true },
  { method: 'GET', pattern: new URLPattern({ pathname: '/compliance/status' }), handler: handleStatus },
  { method: 'GET', pattern: new URLPattern({ pathname: '/compliance/overdue' }), handler: handleOverdue },
  { method: 'POST', pattern: new URLPattern({ pathname: '/compliance/run' }), handler: handleRun },
  { method: 'POST', pattern: new URLPattern({ pathname: '/compliance/batches/:batchId/audit-file' }), handler: handleSealAudit },
  { method: 'GET', pattern: new URLPattern({ pathname: '/compliance/batches/:batchId/audit-file' }), handler: handleGetAudit },
  { method: 'POST', pattern: new URLPattern({ pathname: '/compliance/directives/:directiveId/ack' }), handler: handleAck },
]

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

/**
 * Admin authentication. Bearer token in the Authorization header only — never a query
 * parameter, because URLs are logged by every hop and this token opens a compliance
 * ledger. If the secret is unset the whole /compliance surface returns 503: an operator
 * who forgot to set it gets a closed door, not an open one.
 */
function requireAdmin(request, env) {
  const expected = env.COMPLIANCE_ADMIN_TOKEN
  if (typeof expected !== 'string' || expected.length < 32) {
    return json({ error: 'COMPLIANCE_ADMIN_TOKEN is not configured; the compliance surface is closed' }, 503)
  }
  const header = request.headers.get('authorization') ?? ''
  const presented = header.startsWith('Bearer ') ? header.slice(7) : ''
  if (!timingSafeEqual(presented, expected)) return json({ error: 'unauthorized' }, 401)
  return null
}

async function handleHealth(request, env, ctx, now) {
  return json({ ok: true, service: 'm3-drop-compliance', now, obligation_active: isProcessingObligationActive(now) })
}

/** The teaching endpoint: the two clocks, in machine-readable form, with no auth needed. */
async function handleClocks(request, env, ctx, now) {
  return json({
    note:
      'There is no single 45-day rule. Access cadence (45d, recurring) and status report ' +
      '(45d from retrieval) run on one clock; deletion completion (90d from the same ' +
      'retrieval) runs on another. Both govern. NF-WP-1 §9.5.',
    clocks: CLOCKS,
    processing_obligation_starts_at: PROCESSING_OBLIGATION_START_S,
    internal_access_cadence_s: INTERNAL_ACCESS_CADENCE_S,
  })
}

/**
 * Compliance status. Emits counts, states, deadlines and digests — never a subject digest,
 * an identifier, or a local record reference. A status endpoint is the easiest place for a
 * compliance system to become a data-disclosure surface.
 */
async function handleStatus(request, env, ctx, now) {
  const db = requireDb(env)
  const lastAccess = await lastSuccessfulAccessAt(db)
  const { results: batches } = await db
    .prepare(
      `SELECT batch_id, attempted_at, outcome, retrieved_at, report_due_at, deletion_due_at, reported_at,
              deletion_completed_at, audit_sealed_at, request_count, matched_count
         FROM retrieval_batch ORDER BY attempted_at DESC LIMIT 50`,
    )
    .all()
  const { results: ackPending } = await db
    .prepare("SELECT COUNT(*) AS n FROM downstream_directive WHERE acknowledged_at IS NULL AND state <> 'refused'")
    .all()
  const registration = await db.prepare('SELECT * FROM broker_registration ORDER BY registration_year DESC LIMIT 1').first()
  const chain = await verifyAuditChain(db, 0)

  return json({
    now,
    obligation_active: isProcessingObligationActive(now),
    access_cadence: accessClockState(lastAccess, now),
    next_due_at: nextDueAt({ batches, lastAccessAt: lastAccess }, now),
    directives_pending_ack: ackPending[0]?.n ?? 0,
    registration: registrationClockState(registration?.deadline_at ?? null, registration?.registered_at ?? null, now),
    audit_chain: chain,
    batches: batches.map((b) => ({
      batch_id: b.batch_id,
      outcome: b.outcome,
      attempted_at: b.attempted_at,
      retrieved_at: b.retrieved_at,
      request_count: b.request_count,
      matched_count: b.matched_count,
      audit_sealed_at: b.audit_sealed_at,
      clocks: batchClockStates(b, now),
      step_order_violations: stepOrderViolations(b),
    })),
  })
}

async function handleOverdue(request, env, ctx, now) {
  const db = requireDb(env)
  const lastAccess = await lastSuccessfulAccessAt(db)
  const { results: batches } = await db
    .prepare(
      `SELECT batch_id, retrieved_at, report_due_at, deletion_due_at, reported_at, deletion_completed_at
         FROM retrieval_batch WHERE outcome = 'retrieved'`,
    )
    .all()
  const { results: acks } = await db
    .prepare(
      `SELECT directive_id, recipient_id, ack_required_by FROM downstream_directive
        WHERE acknowledged_at IS NULL AND state <> 'refused' AND ack_required_by < ?
        ORDER BY ack_required_by ASC LIMIT 200`,
    )
    .bind(now)
    .all()
  return json({ now, clocks: findOverdue({ batches, lastAccessAt: lastAccess }, now), overdue_acknowledgements: acks })
}

async function handleRun(request, env, ctx, now) {
  const url = new URL(request.url)
  const force = url.searchParams.get('force') === '1'
  return json(await runComplianceCycle(env, now, { force }))
}

async function handleSealAudit(request, env, ctx, now, params) {
  const sealed = await sealAuditFile(env, params.batchId, now)
  return json({ audit_file_id: sealed.audit_file_id, sealed_at: sealed.sealed_at, content_digest: sealed.content_digest }, 201)
}

async function handleGetAudit(request, env, ctx, now, params) {
  const db = requireDb(env)
  const row = await db
    .prepare('SELECT * FROM audit_file WHERE batch_id = ? ORDER BY sealed_at DESC LIMIT 1')
    .bind(params.batchId)
    .first()
  if (!row) return json({ error: 'no sealed audit file for this batch; POST to this path to produce one' }, 404)
  const recomputed = await sha256b64(AUDIT_FILE_DOMAIN, row.content)
  return json({
    audit_file_id: row.audit_file_id,
    batch_id: row.batch_id,
    sealed_at: row.sealed_at,
    content_digest: row.content_digest,
    digest_verified: recomputed === row.content_digest,
    head_digest: row.head_digest,
    content: JSON.parse(row.content),
  })
}

/**
 * Record a downstream acknowledgement. Admin-authenticated: this is an operator or an
 * authenticated callback recording that a recipient confirmed deletion, and it is the
 * input that lets a request reach `complete`. It is therefore exactly the write an
 * attacker would want, so it is never open, and the ack payload is stored as a digest.
 */
async function handleAck(request, env, ctx, now, params) {
  const db = requireDb(env)
  let body
  try {
    body = await request.json()
  } catch {
    return json({ error: 'body must be JSON' }, 400)
  }
  const state = body?.refused === true ? 'refused' : 'acknowledged'
  const digest = await sha256b64(PAYLOAD_DIGEST_DOMAIN, canonicalize(body ?? {}))
  const res = await db
    .prepare(
      `UPDATE downstream_directive
          SET state = ?, acknowledged_at = ?, ack_reference = ?, ack_digest = ?
        WHERE directive_id = ? AND acknowledged_at IS NULL`,
    )
    .bind(state, state === 'acknowledged' ? now : null, String(body?.reference ?? '').slice(0, 200) || null, digest, params.directiveId)
    .run()
  if ((res.meta?.changes ?? 0) === 0) return json({ error: 'unknown directive, or already acknowledged' }, 409)
  const d = await db.prepare('SELECT request_id, recipient_id FROM downstream_directive WHERE directive_id = ?').bind(params.directiveId).first()
  await appendAudit(db, {
    at: now,
    event_type: state === 'refused' ? 'directive.refused' : 'directive.acknowledged',
    severity: state === 'refused' ? 'breach' : 'info',
    request_id: d?.request_id ?? null,
    recipient_id: d?.recipient_id ?? null,
    detail: { directive_id: params.directiveId, ack_digest: digest },
  })
  return json({ ok: true, directive_id: params.directiveId, state })
}

async function handleFetch(request, env, ctx) {
  const now = Math.floor(Date.now() / 1000)
  const url = new URL(request.url)
  for (const route of ROUTES) {
    if (route.method !== request.method) continue
    const match = route.pattern.exec(url)
    if (!match) continue
    if (!route.public) {
      const denied = requireAdmin(request, env)
      if (denied) return denied
    }
    try {
      return await route.handler(request, env, ctx, now, match.pathname.groups)
    } catch (err) {
      // Error text can quote a database message; keep it out of the response body and let
      // it go to the Worker log instead. Names, not narratives.
      console.error(`${route.method} ${url.pathname} failed`, err)
      const status = err instanceof AuditOrderingViolation ? 409 : 500
      return json({ error: err.name, message: err instanceof AuditOrderingViolation ? err.message : 'internal error' }, status)
    }
  }
  return json({ error: 'not found' }, 404)
}

/**
 * Cron entry point. Awaited rather than handed to ctx.waitUntil, so a failing cycle fails
 * the cron invocation and shows up in Workers observability instead of succeeding silently.
 */
async function handleScheduled(event, env, ctx) {
  const now = Math.floor((event?.scheduledTime ?? Date.now()) / 1000)
  try {
    const result = await runComplianceCycle(env, now)
    console.log('drop-compliance cycle', JSON.stringify(result))
    return result
  } catch (err) {
    console.error('drop-compliance cycle failed', err)
    try {
      await appendAudit(requireDb(env), {
        at: now,
        event_type: 'cycle.failed',
        severity: 'breach',
        detail: { error_name: err.name },
      })
    } catch (auditErr) {
      console.error('could not record cycle failure in the audit log', auditErr)
    }
    throw err
  }
}

export default { fetch: handleFetch, scheduled: handleScheduled }
