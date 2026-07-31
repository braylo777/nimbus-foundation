/**
 * NF-5 conformance — M3 TWO CLOCKS (`m3-drop-compliance/src/clocks.js`).
 *
 * NF-WP-1 §9.5. There is no single "45-day rule", and the collapse of the Delete Act's
 * obligations into one number IS the compliance failure this module exists to prevent:
 *
 *   CLOCK A1  access the DROP list at least every 45 days   (recurring, anchored to last access)
 *   CLOCK A2  report the disposition within 45 days         (one-shot, anchored to retrieval)
 *   CLOCK B   complete the deletions within 90 days         (one-shot, anchored to the SAME
 *                                                            retrieval as A2)
 *
 * A2 and B run from one instant and are two different deadlines. Every assertion below pins
 * one clock and checks that the other did not move with it — because a suite that only ever
 * asserted "45 days" would pass against an implementation that had harmonised both windows to
 * 45, and a suite that only asserted "90" would pass against one that had harmonised to 90.
 *
 * Determinism (NF-5 §4.4): every instant is injected. `Date.now` is not merely unused — one
 * assertion below breaks it deliberately and re-runs the whole surface, because a purity
 * contract that is only documented is a purity contract nobody is holding.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ACCESS_CADENCE_MAX_S,
  CLOCKS,
  CLOCK_STATES,
  DAY_S,
  DELETION_COMPLETION_WINDOW_S,
  DUE_SOON_WINDOW_S,
  INTERNAL_ACCESS_CADENCE_S,
  INTERNAL_MARGINS,
  PROCESSING_OBLIGATION_START_S,
  REGISTRATION_LATE_FEE_PER_DAY_USD,
  STATUS_REPORT_WINDOW_S,
  accessClockState,
  assertInstant,
  batchClockStates,
  clockState,
  deadlinesForRetrieval,
  findOverdue,
  internalTargetsForRetrieval,
  isAccessOverdue,
  isDeletionOverdue,
  isProcessingObligationActive,
  isReportOverdue,
  lateDays,
  nextAccessDueAt,
  nextAccessTargetAt,
  nextDueAt,
  registrationClockState,
  stepOrderViolations,
} from '../../m3-drop-compliance/src/clocks.js'

// ---------------------------------------------------------------------------------
// Fixtures — every instant derived from one injected anchor, never from a clock.
// ---------------------------------------------------------------------------------

/** A retrieval well after the obligation start, so no assertion straddles that edge. */
const RETRIEVED_AT = PROCESSING_OBLIGATION_START_S + 30 * DAY_S

/** Days after retrieval, in seconds. */
const day = (n) => RETRIEVED_AT + n * DAY_S

const batchAt = (over = {}) => ({
  batch_id: 'batch-1',
  retrieved_at: RETRIEVED_AT,
  report_due_at: RETRIEVED_AT + STATUS_REPORT_WINDOW_S,
  deletion_due_at: RETRIEVED_AT + DELETION_COMPLETION_WINDOW_S,
  reported_at: null,
  deletion_completed_at: null,
  ...over,
})

// ---------------------------------------------------------------------------------
// The windows themselves
// ---------------------------------------------------------------------------------

test('the 45-day and 90-day windows are separate constants and are not equal', () => {
  assert.equal(STATUS_REPORT_WINDOW_S, 45 * DAY_S)
  assert.equal(DELETION_COMPLETION_WINDOW_S, 90 * DAY_S)
  assert.equal(ACCESS_CADENCE_MAX_S, 45 * DAY_S)
  assert.equal(DAY_S, 86_400)

  // The whole point: the two per-batch windows differ, by exactly 45 days.
  assert.notEqual(STATUS_REPORT_WINDOW_S, DELETION_COMPLETION_WINDOW_S)
  assert.equal(DELETION_COMPLETION_WINDOW_S - STATUS_REPORT_WINDOW_S, 45 * DAY_S)
})

test('CLOCKS describes three duties with the right windows, anchors and recurrence', () => {
  assert.deepEqual(Object.keys(CLOCKS).sort(), ['access_cadence', 'deletion_completion', 'status_report'])

  assert.equal(CLOCKS.access_cadence.clock, 'A1')
  assert.equal(CLOCKS.access_cadence.window_s, ACCESS_CADENCE_MAX_S)
  assert.equal(CLOCKS.access_cadence.recurring, true)

  assert.equal(CLOCKS.status_report.clock, 'A2')
  assert.equal(CLOCKS.status_report.window_s, STATUS_REPORT_WINDOW_S)
  assert.equal(CLOCKS.status_report.recurring, false)

  assert.equal(CLOCKS.deletion_completion.clock, 'B')
  assert.equal(CLOCKS.deletion_completion.window_s, DELETION_COMPLETION_WINDOW_S)
  assert.equal(CLOCKS.deletion_completion.recurring, false)

  // A1 and A2 share a window length but are NOT one duty: different anchor, different
  // recurrence. Collapsing them is the other half of the conflation error.
  assert.equal(CLOCKS.access_cadence.window_s, CLOCKS.status_report.window_s)
  assert.notEqual(CLOCKS.access_cadence.anchor, CLOCKS.status_report.anchor)
  assert.notEqual(CLOCKS.access_cadence.recurring, CLOCKS.status_report.recurring)
})

test('deadlinesForRetrieval derives both clocks from one retrieval instant', () => {
  const d = deadlinesForRetrieval(RETRIEVED_AT)
  assert.equal(d.retrieved_at, RETRIEVED_AT)
  assert.equal(d.report_due_at, day(45))
  assert.equal(d.deletion_due_at, day(90))
  assert.equal(d.next_access_due_at, day(45))
  assert.equal(d.internal_next_access_at, day(7))
  // Both per-batch deadlines are anchored to the same instant and are 45 days apart.
  assert.equal(d.deletion_due_at - d.report_due_at, 45 * DAY_S)
})

// ---------------------------------------------------------------------------------
// CLOCK A2 — status report, at the boundary
// ---------------------------------------------------------------------------------

test('CLOCK A2: report is not overdue ON day 45 and is overdue one second later', () => {
  const batch = batchAt()

  assert.equal(batchClockStates(batch, day(44)).status_report.state, 'due-soon')
  assert.equal(isReportOverdue(batch, day(44)), false)

  const onDeadline = batchClockStates(batch, day(45)).status_report
  assert.equal(onDeadline.state, 'due-soon', 'the deadline instant is still inside the window')
  assert.equal(onDeadline.seconds_remaining, 0)
  assert.equal(onDeadline.overdue_by_s, 0)
  assert.equal(isReportOverdue(batch, day(45)), false)

  const oneSecondPast = batchClockStates(batch, day(45) + 1).status_report
  assert.equal(oneSecondPast.state, 'overdue')
  assert.equal(oneSecondPast.overdue_by_s, 1)
  assert.equal(isReportOverdue(batch, day(45) + 1), true)

  assert.equal(batchClockStates(batch, day(46)).status_report.overdue_by_s, DAY_S)
})

test('CLOCK A2 carries its own identity and never borrows CLOCK B\'s window', () => {
  const s = batchClockStates(batchAt(), day(10)).status_report
  assert.equal(s.clock, 'A2')
  assert.equal(s.id, 'status_report')
  assert.equal(s.due_at, day(45))
  assert.notEqual(s.due_at, day(90))
  assert.equal(s.matches_arithmetic, true)
})

// ---------------------------------------------------------------------------------
// CLOCK B — deletion completion, at the boundary
// ---------------------------------------------------------------------------------

test('CLOCK B: deletion is not overdue ON day 90 and is overdue one second later', () => {
  const batch = batchAt()

  assert.equal(batchClockStates(batch, day(89)).deletion_completion.state, 'due-soon')
  assert.equal(isDeletionOverdue(batch, day(89)), false)

  const onDeadline = batchClockStates(batch, day(90)).deletion_completion
  assert.equal(onDeadline.state, 'due-soon')
  assert.equal(onDeadline.seconds_remaining, 0)
  assert.equal(isDeletionOverdue(batch, day(90)), false)

  const oneSecondPast = batchClockStates(batch, day(90) + 1).deletion_completion
  assert.equal(oneSecondPast.state, 'overdue')
  assert.equal(oneSecondPast.overdue_by_s, 1)
  assert.equal(isDeletionOverdue(batch, day(90) + 1), true)

  assert.equal(batchClockStates(batch, day(91)).deletion_completion.overdue_by_s, DAY_S)
})

test('CLOCK B carries its own identity and never borrows CLOCK A2\'s window', () => {
  const s = batchClockStates(batchAt(), day(10)).deletion_completion
  assert.equal(s.clock, 'B')
  assert.equal(s.id, 'deletion_completion')
  assert.equal(s.due_at, day(90))
  assert.notEqual(s.due_at, day(45))
  assert.equal(s.matches_arithmetic, true)
})

// ---------------------------------------------------------------------------------
// Non-conflation — the assertions the module exists for
// ---------------------------------------------------------------------------------

test('between day 46 and day 90 the report is overdue while deletion is not', () => {
  const batch = batchAt()
  for (const d of [46, 50, 60, 75, 89, 90]) {
    const states = batchClockStates(batch, day(d))
    assert.equal(states.status_report.state, 'overdue', `report should be overdue on day ${d}`)
    assert.notEqual(
      states.deletion_completion.state,
      'overdue',
      `deletion must NOT be overdue on day ${d}: reading everything as 45 days is the tightening error`,
    )
    assert.equal(isReportOverdue(batch, day(d)), true)
    assert.equal(isDeletionOverdue(batch, day(d)), false)
  }
})

test('completing the deletions does not cure a missed status report', () => {
  // Deletion finished on day 80 — lawful, inside CLOCK B. The report was never filed.
  const batch = batchAt({ deletion_completed_at: day(80) })
  const states = batchClockStates(batch, day(85))

  assert.equal(states.deletion_completion.state, 'satisfied')
  assert.equal(
    states.status_report.state,
    'overdue',
    'a completed deletion must not mark the report duty satisfied — they are different duties',
  )
  assert.equal(states.status_report.overdue_by_s, day(85) - day(45))
})

test('filing the status report does not mark the deletions complete', () => {
  const batch = batchAt({ reported_at: day(40) })
  const states = batchClockStates(batch, day(95))

  assert.equal(states.status_report.state, 'satisfied')
  assert.equal(
    states.deletion_completion.state,
    'overdue',
    'a filed report must not mark the deletion duty satisfied',
  )
  assert.equal(states.deletion_completion.overdue_by_s, day(95) - day(90))
})

test('a report due on day 45 is owed even while deletion is lawfully still in progress', () => {
  // The expensive error: reading everything as 90 days. The report is due at day 45
  // REGARDLESS of deletion progress, and a day-80 completion does not cure it.
  const batch = batchAt({ reported_at: null, deletion_completed_at: null })
  const atDay46 = batchClockStates(batch, day(46))
  assert.equal(atDay46.status_report.state, 'overdue')
  assert.equal(atDay46.deletion_completion.state, 'pending')

  const late = batchClockStates(batchAt({ reported_at: day(60), deletion_completed_at: day(80) }), day(95))
  assert.equal(
    late.status_report.state,
    'satisfied-late',
    'a breach that disappears once remediated is a breach nobody reports to counsel',
  )
  assert.equal(late.status_report.overdue_by_s, 15 * DAY_S)
  assert.equal(late.deletion_completion.state, 'satisfied')
  assert.equal(late.deletion_completion.overdue_by_s, 0)
})

test('a stored deadline that conflates the two clocks cannot extend the statutory bound', () => {
  // The migration/typo case: a row whose report_due_at was written with the 90-day window.
  // Honouring it would make the dashboard say "pending" on day 60 when the statute says the
  // report was due on day 45 — which is precisely the conflation this module exists to stop.
  const conflated = batchAt({ report_due_at: RETRIEVED_AT + DELETION_COMPLETION_WINDOW_S })
  const states = batchClockStates(conflated, day(60))

  assert.equal(states.status_report.matches_arithmetic, false, 'the discrepancy must be visible')
  assert.equal(
    states.status_report.due_at,
    day(45),
    'the statutory arithmetic governs; a stored deadline may only be stricter, never later',
  )
  assert.equal(states.status_report.state, 'overdue')

  // The converse must still hold: a stricter stored deadline is honoured as stored.
  const stricter = batchAt({ report_due_at: day(30) })
  const strict = batchClockStates(stricter, day(31)).status_report
  assert.equal(strict.due_at, day(30))
  assert.equal(strict.state, 'overdue')
  assert.equal(strict.matches_arithmetic, false)

  // And a conflated deletion deadline (45 where 90 belongs) is stricter, so it stands.
  const tightened = batchAt({ deletion_due_at: RETRIEVED_AT + STATUS_REPORT_WINDOW_S })
  const t = batchClockStates(tightened, day(46)).deletion_completion
  assert.equal(t.due_at, day(45))
  assert.equal(t.matches_arithmetic, false)
})

test('a batch that was never retrieved owes neither per-batch clock', () => {
  const states = batchClockStates({ batch_id: 'b', retrieved_at: null }, day(200))
  assert.equal(states.status_report.state, 'not-applicable')
  assert.equal(states.deletion_completion.state, 'not-applicable')
  assert.equal(states.status_report.due_at, null)
  assert.equal(states.deletion_completion.due_at, null)
})

test('missing due columns are recomputed independently, not from one shared window', () => {
  const states = batchClockStates({ batch_id: 'b', retrieved_at: RETRIEVED_AT }, day(46))
  assert.equal(states.status_report.due_at, day(45))
  assert.equal(states.deletion_completion.due_at, day(90))
  assert.equal(states.status_report.state, 'overdue')
  assert.equal(states.deletion_completion.state, 'pending')
})

// ---------------------------------------------------------------------------------
// CLOCK A1 — access cadence
// ---------------------------------------------------------------------------------

test('CLOCK A1: never accessed means due at the obligation start, not now + 45 days', () => {
  const beforeStart = PROCESSING_OBLIGATION_START_S - DAY_S
  assert.equal(nextAccessDueAt(null), PROCESSING_OBLIGATION_START_S)
  assert.equal(nextAccessDueAt(undefined), PROCESSING_OBLIGATION_START_S)
  assert.equal(nextAccessTargetAt(null), PROCESSING_OBLIGATION_START_S)

  assert.equal(isProcessingObligationActive(beforeStart), false)
  assert.equal(isProcessingObligationActive(PROCESSING_OBLIGATION_START_S), true)

  // Once the obligation is live and nothing has ever been accessed, the access is overdue.
  const s = accessClockState(null, PROCESSING_OBLIGATION_START_S + 1)
  assert.equal(s.state, 'overdue')
  assert.equal(s.overdue_by_s, 1)
  assert.equal(s.obligation_active, true)
  assert.equal(isAccessOverdue(null, PROCESSING_OBLIGATION_START_S + 1), true)

  // Not a grace period: the due instant never becomes "45 days from whenever you asked".
  assert.notEqual(nextAccessDueAt(null), PROCESSING_OBLIGATION_START_S + ACCESS_CADENCE_MAX_S)
})

test('CLOCK A1: the deadline is anchored to the last access and recurs', () => {
  const last = RETRIEVED_AT
  assert.equal(nextAccessDueAt(last), last + 45 * DAY_S)
  assert.equal(nextAccessTargetAt(last), last + INTERNAL_ACCESS_CADENCE_S)

  assert.equal(accessClockState(last, day(45)).state, 'due-soon', 'on the deadline, still inside')
  assert.equal(isAccessOverdue(last, day(45)), false)
  assert.equal(accessClockState(last, day(45) + 1).state, 'overdue')
  assert.equal(isAccessOverdue(last, day(45) + 1), true)

  // A1 has no terminal state: it is always pending, due-soon or overdue.
  for (const d of [0, 7, 8, 40, 41, 45, 46, 200]) {
    const st = accessClockState(last, day(d)).state
    assert.notEqual(st, 'satisfied', `A1 must never report satisfied (day ${d})`)
    assert.notEqual(st, 'satisfied-late', `A1 must never report satisfied-late (day ${d})`)
    assert.ok(CLOCK_STATES.includes(st))
  }
})

test('CLOCK A1: the internal 7-day cadence is a margin, never the statutory floor', () => {
  const last = RETRIEVED_AT
  assert.ok(INTERNAL_ACCESS_CADENCE_S < ACCESS_CADENCE_MAX_S)
  const s = accessClockState(last, day(8))
  assert.equal(s.internal_target_missed, true, 'the internal target is missed on day 8')
  assert.equal(s.state, 'pending', 'but the statutory clock is nowhere near due')
  assert.equal(s.due_at, day(45))
  assert.equal(accessClockState(last, day(7)).internal_target_missed, false)
})

test('CLOCK A1 is evaluated independently of the per-batch clocks', () => {
  // An access on day 40 resets A1 to day 85 and touches neither A2 nor B for the
  // batch retrieved on day 0.
  const batch = batchAt()
  const overdue = findOverdue({ batches: [batch], lastAccessAt: day(40) }, day(46))
  assert.deepEqual(
    overdue.map((o) => o.id),
    ['status_report'],
    'only A2 is overdue on day 46: A1 was reset on day 40 and B has 44 days left',
  )
  assert.equal(accessClockState(day(40), day(46)).state, 'pending')
})

// ---------------------------------------------------------------------------------
// clockState — the generic evaluator
// ---------------------------------------------------------------------------------

test('clockState: due-soon starts exactly DUE_SOON_WINDOW_S before the deadline', () => {
  const due = day(45)
  assert.equal(clockState(due, null, due - DUE_SOON_WINDOW_S - 1).state, 'pending')
  assert.equal(clockState(due, null, due - DUE_SOON_WINDOW_S).state, 'due-soon')
  assert.equal(clockState(due, null, due).state, 'due-soon')
  assert.equal(clockState(due, null, due + 1).state, 'overdue')
})

test('clockState: satisfied on the deadline is on time; one second later is satisfied-late', () => {
  const due = day(45)
  const onTime = clockState(due, due, day(100))
  assert.equal(onTime.state, 'satisfied')
  assert.equal(onTime.overdue_by_s, 0)

  const late = clockState(due, due + 1, day(100))
  assert.equal(late.state, 'satisfied-late')
  assert.equal(late.overdue_by_s, 1, 'the size of the miss must survive remediation')
})

test('clockState: a null deadline is not-applicable, never silently zero', () => {
  const s = clockState(null, null, day(1))
  assert.equal(s.state, 'not-applicable')
  assert.equal(s.due_at, null)
  assert.equal(s.seconds_remaining, null)
  assert.equal(s.overdue_by_s, 0)
})

// ---------------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------------

test('nextDueAt returns the earliest unmet deadline across both clocks and A1', () => {
  const batch = batchAt()

  // Nothing satisfied: A2 (day 45) ties with the A1 deadline (last access = retrieval).
  assert.equal(nextDueAt({ batches: [batch], lastAccessAt: RETRIEVED_AT }, day(1)), day(45))

  // Report filed: the next thing owed is CLOCK B on day 90, unless A1 comes first.
  const reported = batchAt({ reported_at: day(20) })
  assert.equal(nextDueAt({ batches: [reported], lastAccessAt: day(80) }, day(30)), day(90))
  assert.equal(
    nextDueAt({ batches: [reported], lastAccessAt: day(20) }, day(30)),
    day(65),
    'A1 (day 20 + 45) is due before CLOCK B on day 90',
  )

  // Both per-batch duties satisfied: only A1 remains.
  const done = batchAt({ reported_at: day(20), deletion_completed_at: day(80) })
  assert.equal(nextDueAt({ batches: [done], lastAccessAt: day(80) }, day(85)), day(125))

  // A satisfied-late duty is not rescheduled — it is reported, not re-owed.
  const lateDone = batchAt({ reported_at: day(60) })
  assert.equal(nextDueAt({ batches: [lateDone], lastAccessAt: day(80) }, day(85)), day(90))
})

test('nextDueAt schedules per batch, so two batches do not share one deadline', () => {
  const first = batchAt({ batch_id: 'a' })
  const second = { ...batchAt({ batch_id: 'b' }), retrieved_at: day(10), report_due_at: day(55), deletion_due_at: day(100) }
  assert.equal(nextDueAt({ batches: [first, second], lastAccessAt: day(10) }, day(11)), day(45))
  assert.equal(
    nextDueAt({ batches: [second], lastAccessAt: day(10) }, day(11)),
    day(55),
    'the second batch runs on its own retrieval instant',
  )
})

test('findOverdue reports one entry per (batch, clock) and keeps remediated misses visible', () => {
  const batch = batchAt({ reported_at: day(60) }) // late report, deletion still open
  const out = findOverdue({ batches: [batch], lastAccessAt: day(50) }, day(100))

  const ids = out.map((o) => `${o.clock}:${o.id}`)
  assert.deepEqual(new Set(ids).size, ids.length, 'one entry per (batch, clock) pair, no duplicates')
  assert.ok(ids.includes('A1:access_cadence'))
  assert.ok(ids.includes('A2:status_report'))
  assert.ok(ids.includes('B:deletion_completion'))

  const report = out.find((o) => o.id === 'status_report')
  assert.equal(report.remediated, true, 'satisfied-late stays on the dashboard')
  assert.equal(report.overdue_by_s, 15 * DAY_S)

  const deletion = out.find((o) => o.id === 'deletion_completion')
  assert.equal(deletion.remediated, false)
  assert.equal(deletion.overdue_by_s, 10 * DAY_S)

  // Worst first.
  for (let i = 1; i < out.length; i += 1) {
    assert.ok(out[i - 1].overdue_by_s >= out[i].overdue_by_s, 'findOverdue must sort worst first')
  }
})

test('findOverdue is empty when both clocks are inside their windows', () => {
  assert.deepEqual(findOverdue({ batches: [batchAt()], lastAccessAt: RETRIEVED_AT }, day(44)), [])
})

// ---------------------------------------------------------------------------------
// Internal margins
// ---------------------------------------------------------------------------------

test('internal targets are strictly earlier than the statutory bounds they protect', () => {
  const t = internalTargetsForRetrieval(RETRIEVED_AT)
  const d = deadlinesForRetrieval(RETRIEVED_AT)

  assert.ok(t.match_by < t.fanout_dispatch_by)
  assert.ok(t.fanout_dispatch_by < t.report_by)
  assert.ok(t.report_by < d.report_due_at, 'the report target must carry margin on CLOCK A2')
  assert.ok(t.deletion_complete_by < d.deletion_due_at, 'completion must carry margin on CLOCK B')
  assert.ok(t.fanout_ack_by <= d.report_due_at)

  // The margins are on the right clocks: the report target is inside 45 days, the deletion
  // target inside 90. A single harmonised margin would break one of these.
  assert.equal(INTERNAL_MARGINS.report_by_s, 35 * DAY_S)
  assert.equal(INTERNAL_MARGINS.deletion_complete_by_s, 75 * DAY_S)
  assert.ok(INTERNAL_MARGINS.report_by_s < STATUS_REPORT_WINDOW_S)
  assert.ok(INTERNAL_MARGINS.deletion_complete_by_s < DELETION_COMPLETION_WINDOW_S)
})

// ---------------------------------------------------------------------------------
// Step order and registration
// ---------------------------------------------------------------------------------

test('stepOrderViolations catches the M3 acceptance criterion and the inverted seal', () => {
  assert.deepEqual(stepOrderViolations(batchAt({ reported_at: day(40), audit_sealed_at: day(39) })), [])

  const noSeal = stepOrderViolations(batchAt({ reported_at: day(40) }))
  assert.equal(noSeal.length, 1)
  assert.match(noSeal[0], /sealed audit file/)

  const inverted = stepOrderViolations(batchAt({ reported_at: day(40), audit_sealed_at: day(41) }))
  assert.equal(inverted.length, 1)
  assert.match(inverted[0], /ordering is inverted/)

  const openAcks = stepOrderViolations(
    batchAt({ deletion_completed_at: day(80), pending_ack_count: 2 }),
  )
  assert.equal(openAcks.length, 1)
  assert.match(openAcks[0], /acknowledgement/)

  const neverRetrieved = stepOrderViolations({ retrieved_at: null, reported_at: day(40), audit_sealed_at: day(39) })
  assert.ok(neverRetrieved.some((r) => /never retrieved/.test(r)))
})

test('registration is unconfigured rather than invented, and accrues $200/day when missed', () => {
  const unconfigured = registrationClockState(null, null, day(1))
  assert.equal(unconfigured.state, 'unconfigured')
  assert.equal(unconfigured.accrued_late_fee_usd, null)

  const deadline = day(10)
  assert.equal(registrationClockState(deadline, null, day(9)).accrued_late_fee_usd, 0)
  assert.equal(registrationClockState(deadline, null, day(10)).accrued_late_fee_usd, 0)

  const oneDayLate = registrationClockState(deadline, null, day(10) + 1)
  assert.equal(oneDayLate.state, 'overdue')
  assert.equal(oneDayLate.late_days, 1, 'a partial day rounds up')
  assert.equal(oneDayLate.accrued_late_fee_usd, REGISTRATION_LATE_FEE_PER_DAY_USD)

  const threeDaysLate = registrationClockState(deadline, null, day(13))
  assert.equal(threeDaysLate.late_days, 3)
  assert.equal(threeDaysLate.accrued_late_fee_usd, 3 * REGISTRATION_LATE_FEE_PER_DAY_USD)

  assert.equal(lateDays(0), 0)
  assert.equal(lateDays(-1), 0)
  assert.equal(lateDays(1), 1)
  assert.equal(lateDays(DAY_S), 1)
  assert.equal(lateDays(DAY_S + 1), 2)
})

// ---------------------------------------------------------------------------------
// Unit safety and the purity contract
// ---------------------------------------------------------------------------------

test('assertInstant rejects the millisecond-for-seconds error and every non-instant', () => {
  assert.equal(assertInstant(RETRIEVED_AT), RETRIEVED_AT)

  assert.throws(() => assertInstant(RETRIEVED_AT * 1000), RangeError, 'ms timestamp must be refused')
  assert.throws(() => assertInstant(0), RangeError)
  assert.throws(() => assertInstant(-1), RangeError)

  for (const bad of [null, undefined, '1785542400', 1.5, NaN, Infinity, new Date(), {}, [], true]) {
    assert.throws(() => assertInstant(bad), (err) => err instanceof TypeError || err instanceof RangeError)
  }
})

test('a millisecond timestamp cannot silently create a deadline in the year 82,000', () => {
  assert.throws(() => deadlinesForRetrieval(RETRIEVED_AT * 1000), RangeError)
  assert.throws(() => internalTargetsForRetrieval(RETRIEVED_AT * 1000), RangeError)
  assert.throws(() => nextAccessDueAt(RETRIEVED_AT * 1000), RangeError)
  assert.throws(() => batchClockStates(batchAt(), RETRIEVED_AT * 1000), RangeError)
  assert.throws(() => batchClockStates(batchAt({ retrieved_at: RETRIEVED_AT * 1000 }), day(1)), RangeError)
  assert.throws(() => clockState(day(45), RETRIEVED_AT * 1000, day(1)), RangeError)
})

test('every clock function refuses to run without an injected `now`', () => {
  // NF-5 §4.4(2): `Date.now()` must not appear in an assertion's decision path. The module
  // enforces that by refusing an absent `now` rather than defaulting to the ambient clock.
  assert.throws(() => clockState(day(45), null, undefined), TypeError)
  assert.throws(() => accessClockState(RETRIEVED_AT, undefined), TypeError)
  assert.throws(() => batchClockStates(batchAt(), undefined), TypeError)
  assert.throws(() => findOverdue({ batches: [] }, undefined), TypeError)
  assert.throws(() => nextDueAt({ batches: [] }, undefined), TypeError)
  assert.throws(() => registrationClockState(day(10), null, undefined), TypeError)
  assert.throws(() => isProcessingObligationActive(undefined), TypeError)
})

test('nothing in clocks.js reads the ambient clock', () => {
  // Stronger than "we always pass now": break Date.now outright and re-run the surface.
  const realNow = Date.now
  Date.now = () => {
    throw new Error('clocks.js read the ambient clock')
  }
  try {
    const batch = batchAt()
    assert.equal(batchClockStates(batch, day(46)).status_report.state, 'overdue')
    assert.equal(batchClockStates(batch, day(46)).deletion_completion.state, 'pending')
    assert.equal(accessClockState(RETRIEVED_AT, day(46)).state, 'overdue')
    assert.equal(nextDueAt({ batches: [batch], lastAccessAt: RETRIEVED_AT }, day(1)), day(45))
    assert.equal(findOverdue({ batches: [batch], lastAccessAt: RETRIEVED_AT }, day(46)).length, 2)
    assert.deepEqual(stepOrderViolations(batch), [])
    assert.equal(deadlinesForRetrieval(RETRIEVED_AT).deletion_due_at, day(90))
    assert.equal(internalTargetsForRetrieval(RETRIEVED_AT).report_by, day(35))
    assert.equal(registrationClockState(day(10), null, day(12)).late_days, 2)
    assert.equal(isProcessingObligationActive(day(1)), true)
  } finally {
    Date.now = realNow
  }
})

/**
 * NF-5 §4.7 positive control for the supplementary DA area.
 *
 * Every other assertion in this file is a refusal — bad input rejected, the two clocks never
 * conflated. A file of refusals passes unchanged against a module whose functions all returned
 * a frozen empty object, so §4.7 requires at least one assertion that fails if the machinery
 * stops doing anything. This is that assertion: it requires specific, non-trivial state
 * transitions and a measured overdue interval, not merely the absence of a wrong answer.
 */
test('[control] DA: the clock machinery fires — overdue is detected and measured, not merely refused', () => {
  const retrievedAt = PROCESSING_OBLIGATION_START_S

  // NF-WP-1 §9.5: report status within 45 days of retrieval; COMPLETE deletions within 90.
  // Two clocks, both governing. If these ever coincide, the conflation this file exists to
  // prevent has happened upstream in the constants.
  const reportDue = retrievedAt + STATUS_REPORT_WINDOW_S
  const completionDue = retrievedAt + DELETION_COMPLETION_WINDOW_S
  assert.notEqual(reportDue, completionDue, 'the 45-day and 90-day clocks must remain distinct')
  assert.equal(completionDue - reportDue, 45 * DAY_S, 'the gap between the clocks is 45 days')

  // Exactly at the deadline is still met; one second past is not. A boundary that does not
  // move here is a boundary that never fires.
  const atDeadline = clockState(reportDue, null, reportDue)
  const pastDeadline = clockState(reportDue, null, reportDue + 1)
  assert.notEqual(atDeadline.state, 'overdue', 'meeting a deadline exactly must not be overdue')
  assert.equal(pastDeadline.state, 'overdue')
  assert.equal(pastDeadline.overdue_by_s, 1, 'lateness must be measured, not just flagged')

  // A duty discharged after its deadline is recorded as late rather than quietly as done —
  // an audit file that cannot distinguish the two is not an audit file.
  const lateCompletion = clockState(completionDue, completionDue + DAY_S, completionDue + DAY_S)
  assert.equal(lateCompletion.state, 'satisfied-late')
  assert.equal(lateCompletion.overdue_by_s, DAY_S)

  // And the ordinary case still reads as healthy, so the control cannot pass by everything
  // being reported as broken.
  const healthy = clockState(reportDue, null, retrievedAt + DAY_S)
  assert.equal(healthy.state, 'pending')
  assert.equal(healthy.overdue_by_s, 0)
})
