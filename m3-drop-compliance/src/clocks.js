/**
 * Delete Act / DROP deadline arithmetic.
 *
 * Nimbus Foundation NF-WP-1 §9.5, §14 (M3), §15 rec. 2.
 * California Delete Act, Civ. Code §§ 1798.99.80 et seq. (SB 362).
 *
 * ============================ THE TWO CLOCKS ============================
 *
 * THERE IS NO SINGLE "45-DAY RULE". Vendor summaries routinely collapse the Delete Act's
 * obligations into one 45-day figure, and that collapse IS the compliance failure this
 * file exists to prevent. NF-WP-1 §9.5 separates them, and both govern simultaneously:
 *
 *   CLOCK A — 45 days.  Two distinct duties run on it, and they are not the same duty:
 *     A1. ACCESS CADENCE: access the DROP deletion-request list at least once every
 *         45 days. Anchored to the LAST ACCESS, recurring, and it runs whether or not
 *         the previous access returned any requests. A run that errors is not an access.
 *     A2. STATUS REPORT: report the disposition of a retrieved batch within 45 days
 *         OF THAT RETRIEVAL. Anchored per batch, one-shot.
 *
 *   CLOCK B — 90 days.  DELETION COMPLETION: actually complete the deletions within
 *         90 days of the same retrieval. Anchored per batch, one-shot.
 *
 * Why conflation is dangerous in both directions:
 *
 *   - Reading everything as 45 days makes the deletion window look 45 days tighter than
 *     it is, which sounds harmless until an operator "discovers" the extra 45 days late
 *     and quietly re-plans around a deadline they have already blown.
 *   - Reading everything as 90 days is the expensive error: the status report is due at
 *     day 45 REGARDLESS of whether deletion has finished. A batch whose deletions are
 *     lawfully still in progress on day 45 still owes a report on day 45 saying so.
 *     Completing a deletion on day 80 does not cure a report that was due on day 45.
 *
 * So the two clocks are tracked as INDEPENDENT deadlines per retrieval batch. Neither
 * one's satisfaction is allowed to mark the other satisfied, and a satisfied-but-late
 * deadline stays visible as `satisfied-late` rather than collapsing to `satisfied` —
 * a breach that disappears from the dashboard the moment it is remediated is a breach
 * nobody reports to counsel.
 *
 * "Stricter step-by-step satisfied" (§14 M3): the statutory dates are the outer bound,
 * never the plan. `internalTargetsForRetrieval` returns earlier per-step targets so that
 * an error, a retry, or a slow downstream recipient consumes margin instead of consuming
 * the deadline. See INTERNAL_MARGINS for the reasoning behind each number.
 *
 * ============================ PURITY CONTRACT ============================
 *
 * Every function here takes `now` explicitly and NOTHING reads the ambient clock. That is
 * not stylistic: a compliance deadline calculator that consults Date.now() internally can
 * only be tested by faking global time, so in practice it does not get tested at the
 * boundaries — which is the only place these functions are ever wrong. The conformance
 * suite pins day 44, 45, 46, 89, 90 and 91 exactly. Callers pass their own `now`; the
 * Worker reads the clock once per invocation and threads it through.
 *
 * ============================ TIME BASE ============================
 *
 * All instants are Unix SECONDS (integers), matching the grant schema in
 * broker/src/nf2-grant.js, and windows are fixed multiples of 86,400 seconds.
 *
 * Two consequences, both deliberately on the conservative side:
 *
 *  1. Statutory day-counts in California run on California local time. Anchoring on the
 *     retrieval INSTANT and adding N × 86,400 s is never later than a calendar-day
 *     reading, because retrievedAt + N days <= startOfLocalDay(retrievedAt) + (N+1) days,
 *     and the calendar reading's deadline is the end of the Nth day. We are early by up
 *     to one day; being early is not a violation.
 *  2. Fixed 86,400-second days ignore the ±1 hour DST shift. Immaterial: every internal
 *     target carries days of margin, so a one-hour drift cannot move a step across its
 *     own target, let alone across the statutory bound.
 */

// Timestamp plausibility bounds are imported rather than redefined. They exist to catch
// the milliseconds-for-seconds unit error, which here would turn a 90-day deletion
// window into an 80,000-year one while every other check still passes — see the note on
// MIN_PLAUSIBLE_TIME_S in nf2-grant.js. Reported as a defect candidate: these constants
// are about time, not about grants, and belong in a shared module.
import { MAX_PLAUSIBLE_TIME_S, MIN_PLAUSIBLE_TIME_S } from '../../broker/src/nf2-grant.js'

export const DAY_S = 86_400

/** CLOCK A1 — maximum interval between two DROP accesses. */
export const ACCESS_CADENCE_MAX_S = 45 * DAY_S

/** CLOCK A2 — status report due, measured from retrieval. */
export const STATUS_REPORT_WINDOW_S = 45 * DAY_S

/** CLOCK B — deletion completion due, measured from the SAME retrieval. */
export const DELETION_COMPLETION_WINDOW_S = 90 * DAY_S

/**
 * The three duties as data, so the audit file and the status endpoint describe them in
 * one voice and the conformance suite can assert the windows have not been "harmonised"
 * into a single number by a later editor.
 */
export const CLOCKS = Object.freeze({
  access_cadence: Object.freeze({
    id: 'access_cadence',
    clock: 'A1',
    window_s: ACCESS_CADENCE_MAX_S,
    anchor: 'last successful DROP access',
    recurring: true,
    duty: 'access the DROP deletion-request list at least once every 45 days',
  }),
  status_report: Object.freeze({
    id: 'status_report',
    clock: 'A2',
    window_s: STATUS_REPORT_WINDOW_S,
    anchor: 'retrieval of the batch',
    recurring: false,
    duty: 'report the disposition of each retrieved request within 45 days of retrieval',
  }),
  deletion_completion: Object.freeze({
    id: 'deletion_completion',
    clock: 'B',
    window_s: DELETION_COMPLETION_WINDOW_S,
    anchor: 'retrieval of the batch',
    recurring: false,
    duty: 'complete the deletions within 90 days of retrieval',
  }),
})

/**
 * 2026-08-01T00:00:00Z — the date the DROP processing obligation begins (NF-WP-1 §9.5).
 * This is the hard date the whole milestone is built around.
 *
 * UTC midnight is 7 hours EARLIER than California midnight, so anchoring here starts our
 * obligation before the statutory one rather than after it. Wrong in the safe direction.
 */
export const PROCESSING_OBLIGATION_START_S = 1_785_542_400

/** 2026-01-01T00:00:00Z — DROP went live for consumers (NF-WP-1 §9.5). Informational. */
export const DROP_CONSUMER_LIVE_S = 1_767_225_600

/**
 * Registration economics, for the status endpoint's exposure line. Registration failure —
 * not deletion failure — is what the CPPA has actually been fining: Accurate Append, Inc.,
 * $55,400 (July 2025); a $56,600 fine on 2025-12-03, the eighth registration-failure fine;
 * and a standing Data Broker Enforcement Strike Force. $200/day accrues per missed
 * deadline (CPPA Enforcement Advisory No. 2025-01).
 *
 * There is deliberately NO hardcoded annual registration DEADLINE here. NF-WP-1 §9.5
 * states the fee, the annual cadence and the per-day penalty; it does not state the
 * calendar date, and inventing one in code would be worse than not having it. The date is
 * operator-configured (see `registrationClockState`) and must be read off the CPPA's
 * published registration requirements before launch.
 */
export const REGISTRATION_FEE_2026_USD = 6_000
export const REGISTRATION_LATE_FEE_PER_DAY_USD = 200

/**
 * Internal step targets, as seconds after retrieval. Each is strictly earlier than the
 * statutory bound it protects, and each margin answers a specific way the run fails.
 *
 *  - `match_by` (day 7): matching is local work with no external dependency, so it has no
 *    excuse to be slow. Doing it early is also what makes the day-45 report truthful:
 *    you cannot report a disposition you have not computed.
 *  - `fanout_dispatch_by` (day 14): service providers and contractors have to be told
 *    before they can be chased. Dispatch late and the acknowledgement clock has nowhere
 *    to run.
 *  - `fanout_ack_by` (day 45): acknowledgements are the one step gated on third parties,
 *    so it gets the longest runway. Aligned with the report so the report can state
 *    per-recipient acknowledgement status as fact.
 *  - `report_by` (day 35): ten days of margin on a statutory date whose miss is a
 *    reportable breach. A 45-day target with no margin fails the first time the audit
 *    seal, the adapter or the network errors on day 45.
 *  - `deletion_complete_by` (day 75): fifteen days of margin, because completion depends
 *    on erasure across every downstream recipient and is the step most likely to surface
 *    a straggler that needs a second dispatch.
 */
export const INTERNAL_MARGINS = Object.freeze({
  match_by_s: 7 * DAY_S,
  fanout_dispatch_by_s: 14 * DAY_S,
  fanout_ack_by_s: 45 * DAY_S,
  report_by_s: 35 * DAY_S,
  deletion_complete_by_s: 75 * DAY_S,
})

/**
 * Internal access cadence: 7 days, against a 45-day statutory floor.
 *
 * The margin is the point. At a 45-day cadence the first failed run is already a
 * violation, because there is no second attempt inside the window. At 7 days, six
 * consecutive weekly failures still leave three days of statutory room, and the daily
 * cron (see wrangler.toml) gives 45 independent attempts before the floor is reached.
 */
export const INTERNAL_ACCESS_CADENCE_S = 7 * DAY_S

/** How far ahead of a deadline `clockState` starts reporting 'due-soon'. */
export const DUE_SOON_WINDOW_S = 5 * DAY_S

/** Deadline states. `satisfied-late` is distinct on purpose — see the header. */
export const CLOCK_STATES = Object.freeze([
  'not-applicable',
  'pending',
  'due-soon',
  'overdue',
  'satisfied',
  'satisfied-late',
])

/**
 * Reject anything that is not a plausible Unix-seconds instant. Fails closed: a caller
 * that hands us `null`, a millisecond timestamp, a Date, or a numeric string gets an
 * exception, not a deadline in the year 82,000.
 */
export function assertInstant(value, label = 'instant') {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new TypeError(`${label} must be an integer number of Unix seconds, got ${typeof value}`)
  }
  if (value < MIN_PLAUSIBLE_TIME_S || value > MAX_PLAUSIBLE_TIME_S) {
    throw new RangeError(
      `${label}=${value} is outside the plausible range ` +
        `[${MIN_PLAUSIBLE_TIME_S}, ${MAX_PLAUSIBLE_TIME_S}]; a millisecond timestamp passed ` +
        'where seconds are expected is the usual cause',
    )
  }
  return value
}

/** True once the DROP processing obligation has begun. */
export function isProcessingObligationActive(now) {
  assertInstant(now, 'now')
  return now >= PROCESSING_OBLIGATION_START_S
}

/**
 * Both per-batch deadlines from one retrieval instant, plus the next access deadline the
 * same access resets.
 *
 * Returned keys are snake_case and match the D1 column names in schema.sql exactly, so a
 * row can be handed back into `batchClockStates` without translation. A translation layer
 * between the deadline calculator and the deadline storage is a place for the 45 and the
 * 90 to get swapped.
 */
export function deadlinesForRetrieval(retrievedAt) {
  assertInstant(retrievedAt, 'retrievedAt')
  return Object.freeze({
    retrieved_at: retrievedAt,
    report_due_at: retrievedAt + STATUS_REPORT_WINDOW_S,
    deletion_due_at: retrievedAt + DELETION_COMPLETION_WINDOW_S,
    next_access_due_at: retrievedAt + ACCESS_CADENCE_MAX_S,
    internal_next_access_at: retrievedAt + INTERNAL_ACCESS_CADENCE_S,
  })
}

/** The internal (earlier-than-statutory) step targets for a batch. */
export function internalTargetsForRetrieval(retrievedAt) {
  assertInstant(retrievedAt, 'retrievedAt')
  return Object.freeze({
    match_by: retrievedAt + INTERNAL_MARGINS.match_by_s,
    fanout_dispatch_by: retrievedAt + INTERNAL_MARGINS.fanout_dispatch_by_s,
    fanout_ack_by: retrievedAt + INTERNAL_MARGINS.fanout_ack_by_s,
    report_by: retrievedAt + INTERNAL_MARGINS.report_by_s,
    deletion_complete_by: retrievedAt + INTERNAL_MARGINS.deletion_complete_by_s,
  })
}

/**
 * When the next DROP access is due (CLOCK A1).
 *
 * `lastAccessAt === null` means we have never successfully accessed DROP. The answer is
 * then the moment the obligation begins, NOT "45 days from now": a broker that has never
 * accessed the list does not get a grace period, and defaulting to now+45d would silently
 * grant one. Fail closed — if the obligation has already begun, the access is due.
 */
export function nextAccessDueAt(lastAccessAt) {
  if (lastAccessAt === null || lastAccessAt === undefined) return PROCESSING_OBLIGATION_START_S
  assertInstant(lastAccessAt, 'lastAccessAt')
  return lastAccessAt + ACCESS_CADENCE_MAX_S
}

/** When the next access SHOULD happen under the internal cadence (the margin, not the floor). */
export function nextAccessTargetAt(lastAccessAt) {
  if (lastAccessAt === null || lastAccessAt === undefined) return PROCESSING_OBLIGATION_START_S
  assertInstant(lastAccessAt, 'lastAccessAt')
  return lastAccessAt + INTERNAL_ACCESS_CADENCE_S
}

/**
 * Generic single-deadline evaluation. `satisfiedAt === null` means the duty is still open.
 *
 * A duty satisfied after its deadline returns 'satisfied-late' and keeps `overdue_by_s`,
 * because the fact that matters to counsel is the size of the miss, and it must survive
 * remediation.
 */
export function clockState(dueAt, satisfiedAt, now) {
  assertInstant(now, 'now')
  if (dueAt === null || dueAt === undefined) {
    return Object.freeze({ state: 'not-applicable', due_at: null, satisfied_at: null, seconds_remaining: null, overdue_by_s: 0 })
  }
  assertInstant(dueAt, 'dueAt')
  if (satisfiedAt !== null && satisfiedAt !== undefined) {
    assertInstant(satisfiedAt, 'satisfiedAt')
    const late = satisfiedAt > dueAt
    return Object.freeze({
      state: late ? 'satisfied-late' : 'satisfied',
      due_at: dueAt,
      satisfied_at: satisfiedAt,
      seconds_remaining: null,
      overdue_by_s: late ? satisfiedAt - dueAt : 0,
    })
  }
  if (now > dueAt) {
    return Object.freeze({ state: 'overdue', due_at: dueAt, satisfied_at: null, seconds_remaining: 0, overdue_by_s: now - dueAt })
  }
  const remaining = dueAt - now
  return Object.freeze({
    state: remaining <= DUE_SOON_WINDOW_S ? 'due-soon' : 'pending',
    due_at: dueAt,
    satisfied_at: null,
    seconds_remaining: remaining,
    overdue_by_s: 0,
  })
}

/**
 * CLOCK A1 as a state object. Deliberately not 'satisfied'-able: the access duty is
 * recurring, so it is always either pending, due-soon or overdue. There is no terminal
 * state, and modelling one would be how a system stops checking.
 */
export function accessClockState(lastAccessAt, now) {
  assertInstant(now, 'now')
  const dueAt = nextAccessDueAt(lastAccessAt)
  const targetAt = nextAccessTargetAt(lastAccessAt)
  const state = clockState(dueAt, null, now)
  return Object.freeze({
    ...state,
    clock: 'A1',
    id: 'access_cadence',
    last_access_at: lastAccessAt ?? null,
    internal_target_at: targetAt,
    internal_target_missed: now > targetAt,
    obligation_active: isProcessingObligationActive(now),
  })
}

/**
 * Both per-batch clocks, evaluated independently.
 *
 * @param {object} batch row with `retrieved_at`, `report_due_at`, `deletion_due_at`,
 *   `reported_at`, `deletion_completed_at`. Missing due columns are recomputed from
 *   `retrieved_at` so a row written before a schema migration still evaluates, and so a
 *   stored deadline can be cross-checked against the arithmetic.
 */
export function batchClockStates(batch, now) {
  assertInstant(now, 'now')
  if (batch === null || typeof batch !== 'object') throw new TypeError('batch must be an object')
  const retrievedAt = batch.retrieved_at ?? null
  if (retrievedAt === null) {
    // No retrieval means neither per-batch clock has started. An access ATTEMPT that
    // failed is exactly this case: it owes nothing per-batch, but it also did not reset
    // CLOCK A1 — which is why the two are evaluated separately.
    return Object.freeze({
      status_report: clockState(null, null, now),
      deletion_completion: clockState(null, null, now),
    })
  }
  assertInstant(retrievedAt, 'batch.retrieved_at')
  const derived = deadlinesForRetrieval(retrievedAt)
  // A stored deadline may only be STRICTER than the statute, never later.
  //
  // The stored columns exist so an operator can pull a deadline forward (an internal target,
  // a settlement commitment). They must not be able to push one back, and the reason is the
  // whole subject of this file: a row whose `report_due_at` was written with the 90-day
  // window — a migration, a copy-paste, an editor "harmonising" the two numbers — would
  // otherwise make the dashboard report 'pending' on day 60 for a report the Delete Act made
  // due on day 45 (NF-WP-1 §9.5). Taking the earlier of (stored, arithmetic) fails closed:
  // the statutory bound is a ceiling on the deadline, and `matches_arithmetic` still exposes
  // that the two disagreed so the bad row gets fixed rather than silently tolerated.
  const reportDue = Math.min(batch.report_due_at ?? derived.report_due_at, derived.report_due_at)
  const deletionDue = Math.min(batch.deletion_due_at ?? derived.deletion_due_at, derived.deletion_due_at)
  // Compared against what was STORED, not against what we decided to use — otherwise clamping
  // a bad row would also erase the evidence that the row is bad.
  const storedReportDue = batch.report_due_at ?? derived.report_due_at
  const storedDeletionDue = batch.deletion_due_at ?? derived.deletion_due_at
  return Object.freeze({
    status_report: Object.freeze({
      ...clockState(reportDue, batch.reported_at ?? null, now),
      clock: 'A2',
      id: 'status_report',
      matches_arithmetic: storedReportDue === derived.report_due_at,
    }),
    deletion_completion: Object.freeze({
      ...clockState(deletionDue, batch.deletion_completed_at ?? null, now),
      clock: 'B',
      id: 'deletion_completion',
      matches_arithmetic: storedDeletionDue === derived.deletion_due_at,
    }),
  })
}

export function isReportOverdue(batch, now) {
  return batchClockStates(batch, now).status_report.state === 'overdue'
}

export function isDeletionOverdue(batch, now) {
  return batchClockStates(batch, now).deletion_completion.state === 'overdue'
}

export function isAccessOverdue(lastAccessAt, now) {
  return accessClockState(lastAccessAt, now).state === 'overdue'
}

/**
 * Every unmet deadline across the whole compliance surface, worst first.
 *
 * Returns one entry per (batch, clock) pair rather than one per batch, because "batch 7
 * is late" is not actionable and "batch 7 owes a status report, 3 days over" is.
 */
export function findOverdue({ batches = [], lastAccessAt = null } = {}, now) {
  assertInstant(now, 'now')
  const out = []
  const access = accessClockState(lastAccessAt, now)
  if (access.state === 'overdue') {
    out.push({ subject: 'broker', batch_id: null, clock: 'A1', id: 'access_cadence', due_at: access.due_at, overdue_by_s: access.overdue_by_s })
  }
  for (const batch of batches) {
    const states = batchClockStates(batch, now)
    for (const key of ['status_report', 'deletion_completion']) {
      const s = states[key]
      if (s.state === 'overdue' || s.state === 'satisfied-late') {
        out.push({
          subject: 'batch',
          batch_id: batch.batch_id ?? batch.id ?? null,
          clock: s.clock,
          id: s.id,
          due_at: s.due_at,
          overdue_by_s: s.overdue_by_s,
          remediated: s.state === 'satisfied-late',
        })
      }
    }
  }
  return out.sort((a, b) => b.overdue_by_s - a.overdue_by_s)
}

/**
 * The earliest unmet deadline, for scheduling. Returns null only when nothing is
 * outstanding, which for a live broker should never happen — CLOCK A1 always has a next
 * due instant, so a null here means the caller passed no access history at all.
 */
export function nextDueAt({ batches = [], lastAccessAt = null } = {}, now) {
  assertInstant(now, 'now')
  const candidates = [nextAccessDueAt(lastAccessAt)]
  for (const batch of batches) {
    const states = batchClockStates(batch, now)
    if (states.status_report.state !== 'satisfied' && states.status_report.state !== 'satisfied-late' && states.status_report.due_at !== null) {
      candidates.push(states.status_report.due_at)
    }
    if (
      states.deletion_completion.state !== 'satisfied' &&
      states.deletion_completion.state !== 'satisfied-late' &&
      states.deletion_completion.due_at !== null
    ) {
      candidates.push(states.deletion_completion.due_at)
    }
  }
  return candidates.length === 0 ? null : Math.min(...candidates)
}

/**
 * Step-order violations, as a pure predicate over a batch row.
 *
 * This is the "stricter step-by-step satisfied" requirement made checkable, and one of
 * the entries is the M3 acceptance criterion itself: a status report may not exist
 * without a sealed audit file that predates it. schema.sql enforces the same thing with a
 * NOT NULL foreign key and a CHECK, and index.js enforces it a third time at the call
 * site. Three independent enforcements because a documented ordering is not an ordering.
 */
export function stepOrderViolations(batch) {
  if (batch === null || typeof batch !== 'object') throw new TypeError('batch must be an object')
  const v = []
  const retrieved = batch.retrieved_at ?? null
  const reported = batch.reported_at ?? null
  const sealed = batch.audit_sealed_at ?? null
  const completed = batch.deletion_completed_at ?? null
  const pendingAcks = batch.pending_ack_count ?? 0

  if (reported !== null && retrieved === null) {
    v.push('reported a batch that was never retrieved')
  }
  if (reported !== null && sealed === null) {
    v.push('status report exists with no sealed audit file (M3 acceptance criterion: the audit file is produced BEFORE the status file is returned to CalPrivacy)')
  }
  if (reported !== null && sealed !== null && sealed > reported) {
    v.push(`audit file sealed at ${sealed} AFTER the status report was submitted at ${reported}; the ordering is inverted`)
  }
  if (completed !== null && pendingAcks > 0) {
    v.push(`deletion marked complete with ${pendingAcks} downstream acknowledgement(s) still outstanding`)
  }
  if (completed !== null && retrieved === null) {
    v.push('deletion marked complete on a batch that was never retrieved')
  }
  return v
}

/**
 * Accrued late fee for a missed registration deadline, in whole USD.
 *
 * `deadlineAt` is supplied by the caller and is NOT defaulted: the Delete Act's annual
 * registration date is not stated in NF-WP-1, so there is nothing here to default to.
 * Confirm it against the CPPA's published registration requirements and configure it.
 */
export function registrationClockState(deadlineAt, registeredAt, now) {
  assertInstant(now, 'now')
  if (deadlineAt === null || deadlineAt === undefined) {
    return Object.freeze({
      state: 'unconfigured',
      reason:
        'annual DROP registration deadline is not configured. NF-WP-1 §9.5 gives the fee ' +
        `($${REGISTRATION_FEE_2026_USD} for 2026) and the penalty ` +
        `($${REGISTRATION_LATE_FEE_PER_DAY_USD}/day, CPPA Enforcement Advisory No. 2025-01) ` +
        'but not the calendar date; it must be read off the CPPA registration requirements',
      accrued_late_fee_usd: null,
    })
  }
  const base = clockState(deadlineAt, registeredAt ?? null, now)
  const lateDays = base.overdue_by_s > 0 ? Math.ceil(base.overdue_by_s / DAY_S) : 0
  return Object.freeze({
    ...base,
    id: 'annual_registration',
    late_days: lateDays,
    accrued_late_fee_usd: lateDays * REGISTRATION_LATE_FEE_PER_DAY_USD,
  })
}

/** Whole days late, rounded up, for a per-day penalty. Exposed for the audit file. */
export function lateDays(overdueBySeconds) {
  if (typeof overdueBySeconds !== 'number' || !Number.isFinite(overdueBySeconds)) {
    throw new TypeError('overdueBySeconds must be a finite number')
  }
  return overdueBySeconds > 0 ? Math.ceil(overdueBySeconds / DAY_S) : 0
}
