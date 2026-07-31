-- ---------------------------------------------------------------------------------------
-- M3 — Delete Act / DROP compliance store.
--
-- Nimbus Foundation NF-WP-1 §9.5, §14 (M3), §15 rec. 2.
-- California Delete Act, Civ. Code §§ 1798.99.80 et seq. (SB 362); CCPA, Civ. Code
-- § 1798.105 (erasure) and § 1798.140(ae) (sensitive PI).
--
-- WHY THIS IS D1 AND NOT A LEDGER (Refusal 2, §9.5). Every row here is deletion-request
-- material: consumer identifiers, match state, and the record of what was erased. A
-- standing 45-day retrieval cadence plus CCPA erasure rights are irreconcilable with an
-- immutable ledger — the compliance system itself would become the thing that cannot
-- comply. The only artefact in this schema that could ever cross onto a ledger is
-- `audit_file.head_digest`: one integrity commitment over a hash chain, from which no
-- personal information can be derived.
--
-- WHAT IS DELIBERATELY NOT STORED. No raw consumer identifiers. DROP supplies identifiers
-- so a broker can match; we store only `subject_digest`, an HMAC under a broker-held key
-- (env.SUBJECT_MATCH_KEY), for the same reason vin.js keys the vehicle pseudonym: an
-- unkeyed digest of an email address is a rainbow-table lookup, and a suppression list of
-- unkeyed digests is a queryable roster of everyone who asked to be deleted. No VIN in
-- cleartext anywhere: the Delete Act's broker disclosures expressly enumerate vehicle
-- identification numbers as a category of personal information collected, so a VIN in a
-- compliance table is not untidy, it is in-scope PI (NF-WP-1 §9.5, fields.js
-- NON_TRANSACTABLE).
--
-- DEADLINE COLUMNS. `report_due_at` (45 days) and `deletion_due_at` (90 days) are stored
-- separately and are never derived from one another. They are the two clocks in
-- src/clocks.js; the column names match that module's return keys exactly so a row can be
-- handed straight to `batchClockStates(row, now)`. Collapsing them into one column would
-- bake the exact conflation §9.5 exists to correct into the storage layer.
--
-- All instants are INTEGER Unix SECONDS, matching clocks.js and the grant schema. No
-- TEXT dates: a lexicographic comparison on a mixed-offset ISO string is a silent
-- deadline bug, and the partial indexes below need integer ordering.
-- ---------------------------------------------------------------------------------------

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------------------
-- CLOCK A1 — access cadence. One row per ACCESS ATTEMPT, successful or not.
--
-- Failed attempts are rows too, because the cadence obligation is proved by the interval
-- between SUCCESSFUL accesses and the interval is only defensible if the failures are
-- visible next to it. A table that records only successes cannot distinguish "no requests
-- were waiting" from "we never looked", and those have opposite legal consequences.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS retrieval_batch (
  batch_id              TEXT    PRIMARY KEY,          -- random 128-bit base64url, not sequential
  attempted_at          INTEGER NOT NULL,
  outcome               TEXT    NOT NULL
                          CHECK (outcome IN ('in_progress', 'retrieved', 'failed', 'adapter_unconfigured')),

  -- NULL until the attempt succeeds. Both per-batch clocks anchor here, and a failed
  -- attempt therefore owes nothing per-batch while still not resetting CLOCK A1.
  retrieved_at          INTEGER,

  -- CLOCK A2 (45 days from retrieved_at) and CLOCK B (90 days from the same instant).
  report_due_at         INTEGER,
  deletion_due_at       INTEGER,
  -- CLOCK A1's next statutory floor, and the tighter internal target the cron aims at.
  next_access_due_at    INTEGER,
  internal_next_access_at INTEGER,

  -- Satisfaction instants, tracked independently. Neither implies the other.
  reported_at           INTEGER,
  deletion_completed_at INTEGER,
  audit_sealed_at       INTEGER,

  request_count         INTEGER NOT NULL DEFAULT 0,
  matched_count         INTEGER NOT NULL DEFAULT 0,
  drop_cursor_before    TEXT,
  drop_cursor_after     TEXT,
  adapter_id            TEXT    NOT NULL,             -- which DROP adapter produced this; 'stub' is never a success
  error                 TEXT,

  -- A retrieval without deadlines is the failure mode this constraint exists to make
  -- impossible: the row that "succeeded" but whose clocks never started.
  CHECK (retrieved_at IS NULL OR (report_due_at IS NOT NULL AND deletion_due_at IS NOT NULL)),
  CHECK (outcome <> 'retrieved' OR retrieved_at IS NOT NULL),
  CHECK (reported_at IS NULL OR retrieved_at IS NOT NULL),
  CHECK (deletion_completed_at IS NULL OR retrieved_at IS NOT NULL),
  -- The M3 acceptance criterion, at the storage layer: the audit file is sealed BEFORE the
  -- status file goes to CalPrivacy. Also enforced by trigger on status_report and by a
  -- re-read guard in src/index.js.
  CHECK (reported_at IS NULL OR (audit_sealed_at IS NOT NULL AND audit_sealed_at <= reported_at))
);

-- Overdue queries. Partial indexes so the scan is proportional to what is OUTSTANDING,
-- not to compliance history: after two years of weekly batches the satisfied rows
-- outnumber the open ones by orders of magnitude, and a full index would make the daily
-- overdue sweep grow without bound.
CREATE INDEX IF NOT EXISTS idx_batch_report_overdue
  ON retrieval_batch (report_due_at)
  WHERE reported_at IS NULL AND retrieved_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_batch_deletion_overdue
  ON retrieval_batch (deletion_due_at)
  WHERE deletion_completed_at IS NULL AND retrieved_at IS NOT NULL;

-- "When did we last successfully access DROP" — the CLOCK A1 query. Descending because
-- the answer is always the newest row.
CREATE INDEX IF NOT EXISTS idx_batch_last_success
  ON retrieval_batch (retrieved_at DESC)
  WHERE outcome = 'retrieved';

CREATE INDEX IF NOT EXISTS idx_batch_attempts
  ON retrieval_batch (attempted_at DESC);

-- ---------------------------------------------------------------------------------------
-- Deletion requests retrieved from DROP. One row per consumer request per batch.
--
-- Each request INHERITS its batch's two deadlines rather than referencing them. The
-- duplication is intentional: the deadlines belong to the retrieval instant, and copying
-- them makes the per-request overdue query a single-table index scan instead of a join,
-- which is what the daily sweep runs.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS deletion_request (
  request_id        TEXT    PRIMARY KEY,              -- local random id
  batch_id          TEXT    NOT NULL REFERENCES retrieval_batch (batch_id) ON DELETE CASCADE,
  drop_request_id   TEXT    NOT NULL,                 -- DROP-side identifier, opaque to us

  -- Keyed digest of the normalised identifier tuple DROP supplied. NOT the identifiers.
  subject_digest    TEXT    NOT NULL,
  -- Which identifier CLASSES were present (JSON array of e.g. "email","phone","name_zip").
  -- Classes, not values: enough to explain a no-match to an auditor, useless for
  -- re-identification.
  identifier_classes TEXT   NOT NULL DEFAULT '[]',

  received_at       INTEGER NOT NULL,
  report_due_at     INTEGER NOT NULL,                 -- CLOCK A2
  deletion_due_at   INTEGER NOT NULL,                 -- CLOCK B

  match_state       TEXT    NOT NULL DEFAULT 'unmatched'
                      CHECK (match_state IN ('unmatched', 'no_match', 'matched', 'ambiguous', 'error')),
  deletion_state    TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (deletion_state IN ('pending', 'in_progress', 'complete', 'no_action_required', 'blocked', 'exempt')),

  -- Set only from a positive confirmation by the erasure adapter. Never set optimistically:
  -- a request marked complete because the delete call did not throw is how a 90-day
  -- obligation gets reported satisfied while the data is still there.
  deletion_completed_at INTEGER,
  reported_at       INTEGER,
  reported_status   TEXT,                             -- the status value sent to DROP

  -- Exemption claims are recorded with their basis or not at all. An unexplained exemption
  -- is indistinguishable from a failure to process.
  exemption_basis   TEXT,

  -- Staging retention bound. The request record is itself PI; it is kept only as long as
  -- the audit trail requires and then reduced to digests. See src/index.js purge step.
  purge_after       INTEGER,

  UNIQUE (batch_id, drop_request_id),
  CHECK (deletion_state <> 'complete' OR deletion_completed_at IS NOT NULL),
  CHECK (deletion_state <> 'exempt' OR exemption_basis IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_request_report_overdue
  ON deletion_request (report_due_at)
  WHERE reported_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_request_deletion_overdue
  ON deletion_request (deletion_due_at)
  WHERE deletion_completed_at IS NULL AND deletion_state NOT IN ('no_action_required', 'exempt');

CREATE INDEX IF NOT EXISTS idx_request_batch ON deletion_request (batch_id);
CREATE INDEX IF NOT EXISTS idx_request_subject ON deletion_request (subject_digest);

-- ---------------------------------------------------------------------------------------
-- Per-subject match state: zero or more local records matched to one request.
--
-- Separate from deletion_request because "did this consumer's request match anything we
-- hold" and "what exactly did we erase" are different questions with different retention
-- profiles, and because a match is 1:N — one consumer can hold several vehicles.
--
-- `local_ref` is an opaque reference into the store named by `store`, never a VIN and
-- never an owner identity. For the vehicle store it is the vehicle pseudonym, which is
-- itself an HMAC under an owner-held salt; destroying that salt is the erasure that makes
-- the linkage unrecoverable (vin.js, §9.5), which is why `salt_destroyed_at` is tracked
-- as its own column and not folded into a generic "deleted" flag.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS subject_match (
  match_id          TEXT    PRIMARY KEY,
  request_id        TEXT    NOT NULL REFERENCES deletion_request (request_id) ON DELETE CASCADE,
  store             TEXT    NOT NULL,                 -- logical store name, e.g. 'vehicle', 'grant', 'twin'
  local_ref         TEXT    NOT NULL,                 -- pseudonym or opaque row reference
  matched_at        INTEGER NOT NULL,
  match_method      TEXT    NOT NULL
                      CHECK (match_method IN ('exact_digest', 'operator_confirmed')),
  erasure_state     TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (erasure_state IN ('pending', 'erased', 'failed', 'not_found')),
  erased_at         INTEGER,
  salt_destroyed_at INTEGER,
  evidence_digest   TEXT,                             -- digest of the adapter's erasure receipt
  error             TEXT,

  UNIQUE (request_id, store, local_ref),
  CHECK (erasure_state <> 'erased' OR erased_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_match_pending
  ON subject_match (request_id)
  WHERE erasure_state = 'pending';

-- ---------------------------------------------------------------------------------------
-- Suppression list.
--
-- A deletion request is also a standing direction not to re-collect or re-sell. Entries
-- are created for EVERY request, matched or not: a no-match today plus an enrolment
-- tomorrow is precisely the case the list exists for, and conditioning suppression on a
-- current match would let the obligation lapse the moment the consumer acquires a
-- vehicle. This is the conservative reading and it is cheap.
--
-- There is no delete path from this table in the Worker. `released_at` exists for a
-- lawful, recorded release only (e.g. the consumer's own later re-authorisation).
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suppression_list (
  subject_digest    TEXT    PRIMARY KEY,              -- same keyed digest as deletion_request
  first_added_at    INTEGER NOT NULL,
  last_affirmed_at  INTEGER NOT NULL,
  source_request_id TEXT    REFERENCES deletion_request (request_id) ON DELETE SET NULL,
  scope             TEXT    NOT NULL DEFAULT 'all'
                      CHECK (scope IN ('all', 'sale_share_only')),
  active            INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  released_at       INTEGER,
  release_basis     TEXT,

  CHECK (active = 1 OR (released_at IS NOT NULL AND release_basis IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_suppression_active
  ON suppression_list (subject_digest)
  WHERE active = 1;

-- ---------------------------------------------------------------------------------------
-- Downstream service providers and contractors.
--
-- The Delete Act obligation runs through them: directing them is part of completing the
-- deletion, so an unacknowledged directive is an incomplete deletion, not a loose end.
-- `active = 0` recipients are retained because historical directives must still resolve.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS downstream_recipient (
  recipient_id      TEXT    PRIMARY KEY,
  label             TEXT    NOT NULL,
  relationship      TEXT    NOT NULL
                      CHECK (relationship IN ('service_provider', 'contractor', 'third_party')),
  -- How the directive is delivered and how the acknowledgement comes back. No credentials
  -- in this table; the adapter resolves secrets from env at dispatch time.
  channel           TEXT    NOT NULL
                      CHECK (channel IN ('https_webhook', 'email', 'manual_attestation')),
  endpoint_ref      TEXT,                             -- env var NAME holding the endpoint, not the endpoint
  ack_window_s      INTEGER NOT NULL DEFAULT 1209600, -- 14 days; contractual, tighter than statute
  active            INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  added_at          INTEGER NOT NULL,
  retired_at        INTEGER
);

-- ---------------------------------------------------------------------------------------
-- Fan-out receipts: one row per (request, recipient), with acknowledgement tracking.
--
-- UNIQUE(request_id, recipient_id) is the idempotency key. D1 has no interactive
-- transaction, so a run that dies mid-fan-out will be retried; without this constraint the
-- retry sends a second directive and the acknowledgement count double-counts, which would
-- let a batch appear fully acknowledged while a recipient never answered.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS downstream_directive (
  directive_id      TEXT    PRIMARY KEY,
  request_id        TEXT    NOT NULL REFERENCES deletion_request (request_id) ON DELETE CASCADE,
  recipient_id      TEXT    NOT NULL REFERENCES downstream_recipient (recipient_id),
  created_at        INTEGER NOT NULL,
  dispatched_at     INTEGER,
  attempts          INTEGER NOT NULL DEFAULT 0,
  ack_required_by   INTEGER NOT NULL,                 -- created_at + recipient.ack_window_s
  acknowledged_at   INTEGER,
  ack_reference     TEXT,                             -- recipient's own receipt id
  ack_digest        TEXT,                             -- digest of the ack payload, for the audit file
  state             TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (state IN ('pending', 'dispatched', 'acknowledged', 'refused', 'failed')),
  last_error        TEXT,

  UNIQUE (request_id, recipient_id),
  CHECK (state <> 'acknowledged' OR acknowledged_at IS NOT NULL),
  CHECK (state <> 'dispatched' OR dispatched_at IS NOT NULL)
);

-- The chase query: outstanding acknowledgements, oldest deadline first.
CREATE INDEX IF NOT EXISTS idx_directive_ack_overdue
  ON downstream_directive (ack_required_by)
  WHERE acknowledged_at IS NULL AND state <> 'refused';

CREATE INDEX IF NOT EXISTS idx_directive_request ON downstream_directive (request_id);

-- ---------------------------------------------------------------------------------------
-- Audit log: append-only, hash-chained.
--
-- `prev_digest`/`digest` form a chain so tampering with history is detectable without
-- putting anything on a ledger. The head digest is the ONLY value in this schema that is
-- eligible to become an on-chain integrity commitment (Refusal 2): it is a digest over
-- digests and no personal information can be derived from it.
--
-- `detail` carries counts, states and digests. It must not carry identifiers — the audit
-- file is the artefact most likely to be exported, mailed, and retained past every other
-- record's purge date, so it is the worst possible place for PI to accumulate.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
  seq               INTEGER PRIMARY KEY AUTOINCREMENT, -- chain order; monotonic per database
  at                INTEGER NOT NULL,
  event_type        TEXT    NOT NULL,
  severity          TEXT    NOT NULL DEFAULT 'info'
                      CHECK (severity IN ('info', 'warn', 'breach')),
  batch_id          TEXT,
  request_id        TEXT,
  recipient_id      TEXT,
  clock_id          TEXT,                              -- 'access_cadence' | 'status_report' | 'deletion_completion'
  detail            TEXT    NOT NULL DEFAULT '{}',     -- canonical JSON, digests and counts only
  prev_digest       TEXT    NOT NULL,
  digest            TEXT    NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_audit_batch ON audit_log (batch_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_breach ON audit_log (at DESC) WHERE severity = 'breach';

-- ---------------------------------------------------------------------------------------
-- Sealed audit files. One per batch per seal; the artefact the status report is DERIVED
-- FROM.
--
-- `content` is the canonical JSON of the file, `content_digest` its SHA-256. The status
-- report is built from this stored content and not from a fresh query, so the report
-- cannot assert anything that was not audited first. That is the teeth of the M3 ordering
-- criterion: making the audit file the report's only input means the ordering cannot be
-- skipped by a caller who forgets to call the sealer.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_file (
  audit_file_id     TEXT    PRIMARY KEY,
  batch_id          TEXT    NOT NULL REFERENCES retrieval_batch (batch_id) ON DELETE CASCADE,
  sealed_at         INTEGER NOT NULL,
  from_seq          INTEGER NOT NULL,
  to_seq            INTEGER NOT NULL,
  event_count       INTEGER NOT NULL,
  head_digest       TEXT    NOT NULL,                  -- audit_log.digest at to_seq
  content           TEXT    NOT NULL,
  content_digest    TEXT    NOT NULL,

  CHECK (to_seq >= from_seq)
);

CREATE INDEX IF NOT EXISTS idx_audit_file_batch ON audit_file (batch_id, sealed_at DESC);

-- ---------------------------------------------------------------------------------------
-- Status reports submitted through DROP (CLOCK A2).
--
-- `audit_file_id` is NOT NULL: a status report cannot be recorded without an audit file to
-- have come from. The trigger below adds what a foreign key cannot say — that the audit
-- file was SEALED, and sealed no later than the report was built and submitted.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS status_report (
  report_id         TEXT    PRIMARY KEY,
  batch_id          TEXT    NOT NULL REFERENCES retrieval_batch (batch_id) ON DELETE CASCADE,
  audit_file_id     TEXT    NOT NULL REFERENCES audit_file (audit_file_id),
  due_at            INTEGER NOT NULL,                  -- retrieved_at + 45 days
  built_at          INTEGER NOT NULL,
  submitted_at      INTEGER,
  payload_digest    TEXT    NOT NULL,
  drop_receipt      TEXT,
  adapter_id        TEXT    NOT NULL,
  state             TEXT    NOT NULL DEFAULT 'built'
                      CHECK (state IN ('built', 'submitted', 'failed')),
  error             TEXT,

  CHECK (submitted_at IS NULL OR submitted_at >= built_at),
  CHECK (state <> 'submitted' OR submitted_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_report_unsubmitted
  ON status_report (due_at)
  WHERE submitted_at IS NULL;

-- The acceptance criterion as a database refusal. A CHECK cannot reach another table, so
-- this is a trigger; it fires regardless of whether foreign-key enforcement is on, which
-- matters because PRAGMA state is a deployment detail and this ordering is not.
CREATE TRIGGER IF NOT EXISTS trg_status_report_requires_sealed_audit
BEFORE INSERT ON status_report
FOR EACH ROW
WHEN (
  SELECT COUNT(*) FROM audit_file
   WHERE audit_file.audit_file_id = NEW.audit_file_id
     AND audit_file.sealed_at <= NEW.built_at
) = 0
BEGIN
  SELECT RAISE(ABORT,
    'M3 ordering violation: a status report must be built from an audit file sealed at or before built_at (NF-WP-1 §14 M3)');
END;

CREATE TRIGGER IF NOT EXISTS trg_status_report_submit_after_seal
BEFORE UPDATE OF submitted_at ON status_report
FOR EACH ROW
WHEN NEW.submitted_at IS NOT NULL AND (
  SELECT COUNT(*) FROM audit_file
   WHERE audit_file.audit_file_id = NEW.audit_file_id
     AND audit_file.sealed_at <= NEW.submitted_at
) = 0
BEGIN
  SELECT RAISE(ABORT,
    'M3 ordering violation: the audit file must be sealed before the status file is returned to CalPrivacy');
END;

-- ---------------------------------------------------------------------------------------
-- Annual DROP registration.
--
-- Registration failure is what the CPPA has actually been enforcing — a $55,400 fine
-- against Accurate Append, Inc. (July 2025), a $56,600 fine on 2025-12-03 (the eighth
-- registration-failure fine), and a standing Data Broker Enforcement Strike Force — so
-- the clock is tracked here rather than left to a calendar reminder.
--
-- `deadline_at` is NULL until configured. NF-WP-1 §9.5 gives the annual cadence, the
-- $6,000 fee for 2026 and the $200/day penalty, but not the calendar date; the date must
-- be read off the CPPA's published registration requirements. clocks.js reports
-- 'unconfigured' rather than guessing.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS broker_registration (
  registration_year INTEGER PRIMARY KEY,
  deadline_at       INTEGER,
  registered_at     INTEGER,
  fee_paid_usd      INTEGER,
  confirmation_ref  TEXT,
  notes             TEXT
);

-- ---------------------------------------------------------------------------------------
-- Single-flight lease for the cron loop.
--
-- Two overlapping runs would fork the audit hash chain and could double-dispatch
-- directives. A lease acquired with a conditional UPDATE is enough: the loop is idempotent
-- everywhere else, so the lease only has to prevent the interleaving, not guarantee
-- exclusivity forever.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS run_lease (
  lease_name        TEXT    PRIMARY KEY,
  holder            TEXT    NOT NULL,
  acquired_at       INTEGER NOT NULL,
  lease_until       INTEGER NOT NULL
);
