-- M0 VIN-yield study — D1 schema.
-- Generated from SCHEMA_SQL in src/index.js, which remains the source of truth.
-- Committed as a file because the database must exist BEFORE the Worker is deployed:
-- fetching the DDL from GET /schema.sql on a running Worker cannot bootstrap the DB that
-- Worker needs to boot. Regenerate with the command in RUNBOOK.md after editing SCHEMA_SQL.

CREATE TABLE IF NOT EXISTS m0_run (
  run_id                   TEXT PRIMARY KEY,
  sample_id                TEXT NOT NULL,
  provenance               TEXT NOT NULL,
  study_version            TEXT NOT NULL,
  strict_check_digit       INTEGER NOT NULL,
  started_at               INTEGER NOT NULL,
  finished_at              INTEGER,
  vins_submitted           INTEGER NOT NULL DEFAULT 0,
  vins_duplicate           INTEGER NOT NULL DEFAULT 0,
  vins_syntax_invalid      INTEGER NOT NULL DEFAULT 0,
  vins_check_digit_invalid INTEGER NOT NULL DEFAULT 0,
  vins_eligible            INTEGER NOT NULL DEFAULT 0,
  vins_attempted           INTEGER NOT NULL DEFAULT 0,
  vins_decoded             INTEGER NOT NULL DEFAULT 0,
  vins_from_cache          INTEGER NOT NULL DEFAULT 0,
  vins_unreached           INTEGER NOT NULL DEFAULT 0,
  null_decodes             INTEGER NOT NULL DEFAULT 0,
  batches_total            INTEGER NOT NULL DEFAULT 0,
  batches_failed           INTEGER NOT NULL DEFAULT 0,
  truncated                INTEGER NOT NULL DEFAULT 0,
  truncation_reason        TEXT,
  error_code_histogram     TEXT,
  anomalies                TEXT,
  tripwires                TEXT
);

CREATE TABLE IF NOT EXISTS m0_observation (
  run_id     TEXT NOT NULL,
  vin        TEXT NOT NULL,
  field_id   TEXT NOT NULL,
  source_key TEXT,
  state      TEXT NOT NULL,
  PRIMARY KEY (run_id, vin, field_id)
);

CREATE INDEX IF NOT EXISTS m0_observation_run_field
  ON m0_observation (run_id, field_id, state);

CREATE TABLE IF NOT EXISTS m0_probe (
  run_id    TEXT NOT NULL,
  vin       TEXT NOT NULL,
  field_id  TEXT NOT NULL,
  probe_key TEXT NOT NULL,
  state     TEXT NOT NULL,
  PRIMARY KEY (run_id, vin, field_id, probe_key)
);

CREATE INDEX IF NOT EXISTS m0_probe_run_field
  ON m0_probe (run_id, field_id, probe_key, state);

CREATE TABLE IF NOT EXISTS m0_vin_reject (
  run_id             TEXT NOT NULL,
  vin_input          TEXT NOT NULL,
  reason             TEXT NOT NULL,
  syntax_valid       INTEGER,
  check_digit_valid  INTEGER,
  expected_check_digit TEXT,
  PRIMARY KEY (run_id, vin_input)
);

CREATE TABLE IF NOT EXISTS m0_unreached (
  run_id TEXT NOT NULL,
  vin    TEXT NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY (run_id, vin)
);

CREATE TABLE IF NOT EXISTS m0_vpic_cache (
  vin        TEXT PRIMARY KEY,
  fetched_at INTEGER NOT NULL,
  error_code TEXT,
  payload    TEXT NOT NULL
);
