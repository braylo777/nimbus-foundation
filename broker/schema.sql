-- CarNimbus consent broker — D1/SQLite schema.
--
-- Nimbus Foundation NF-WP-1 §3.1 (Layer 3), §9.5 (Delete Act / CCPA erasure), §10.1
-- (the three refusals), §12.7 (linkability), §14 (M1).
--
-- ===================================================================================
-- WHY EVERY TABLE HERE IS MUTABLE, AND WHY THAT IS THE ARCHITECTURE RATHER THAN A
-- STORAGE CHOICE
-- ===================================================================================
--
-- Refusal 2: no personal information — and nothing from which PI can be derived — goes on
-- an immutable ledger. The reason is not squeamishness. California's Delete Act requires a
-- registered data broker to process deletion requests on a standing 45-day cadence, and the
-- CCPA gives a consumer an erasure right that a ledger cannot honour. Those two obligations
-- and immutability are irreconcilable (§9.5), so the system is built the other way round:
--
--   * ON-CHAIN, if a chain is ever anchored at all: consent-grant commitments, revocation-
--     state commitments, integrity commitments. Digests. Nothing else. Ever.
--   * HERE, IN D1: every identifier, every payload, every linkage — precisely BECAUSE these
--     rows can be destroyed. `DELETE` is a first-class compliance primitive in this design,
--     not a maintenance operation.
--
-- Consequences that are load-bearing and easy to undo by accident:
--
--   * NO SOFT DELETES. There is no `deleted_at` column anywhere in this file. A tombstoned
--     row is a retained row wearing a flag, and an erasure regime that leaves the data in
--     place has not erased anything. Deletion means the row is gone.
--   * NO APPEND-ONLY TABLE, including the audit log. See `audit_log`.
--   * NO TRIGGERS THAT COPY ROWS ELSEWHERE. A history table populated by a trigger is an
--     immutable ledger built by accident, and it will be discovered during a deletion audit
--     rather than during review.
--
-- ===================================================================================
-- WHAT IS NOT IN THIS FILE, AND WHY THE ABSENCE IS THE POINT
-- ===================================================================================
--
--   * NO PLAINTEXT VIN COLUMN. The broker stores HMAC(VIN) under an operator-held key (a
--     blind index, `vin_index`) so an owner presenting a VIN can be matched to their
--     enrolment, and stores nothing that yields a VIN back. The VIN transits requests; it
--     never rests. See src/index.js vinIndex(). A VIN at rest is squarely inside the Delete
--     Act's enumerated categories of collected personal information (§9.5).
--   * NO OWNER NAME, ADDRESS, PHONE, OR EMAIL. The only human identifier is an opaque
--     identity-provider subject id (`owner_account_id`). Contact details live in Clerk,
--     which is the system of record for them and can delete them on its own schedule.
--   * NO OEM CREDENTIAL COLUMN OF ANY KIND — no access token, refresh token, password,
--     client secret, cookie or session for a manufacturer's telematics account. Layer 3
--     exists so that the accessing party never obtains the owner's credentials, and the
--     broker is not exempt from that: it issues scoped authorisations, it does not hold
--     keys to someone else's account. There is no column, so there is no migration that
--     quietly starts holding one; adding one is a schema change that has to be reviewed.
--   * NO PRICE, AMOUNT, CURRENCY, INVOICE, ESCROW, TOKEN, BALANCE OR SETTLEMENT COLUMN.
--     Layer 5 is deferred and gated behind securities, DFAL and Sherman Act §1 clearance
--     (§9.7). The Settlement Credit was cut. A grant here has no economic attribute to
--     denominate, and the absence of the column is what makes that non-negotiable at the
--     storage layer instead of in a policy document.
--   * NO GEOLOCATION, BIOMETRIC OR IN-CABIN A/V COLUMN, at any precision. Those classes
--     have no field id in the NF-2 vocabulary (broker/src/fields.js), so no grant can name
--     them and no row can hold them.
--   * NO `transferable`, `holder`, `assignee` OR `transfer_to` COLUMN on a grant. Consent
--     Grants are non-transferable capability objects; delegation is the only way authority
--     moves and it gets its own table with its own invariants.
--
-- STRICT tables throughout. SQLite's default type affinity will happily store the integer
-- 42 in a TEXT column, and every base64url value in this schema is inside a signature or a
-- commitment — a value that changes type between write and read changes bytes, and changed
-- bytes mean a signature that no longer verifies or a revocation entry that no longer
-- matches. STRICT turns that class of bug into an error at write time.
--
-- Foreign keys are declared with ON DELETE CASCADE and D1 enforces them by default. The
-- explicit erasure routine at the bottom of this file exists ANYWAY, and the reason is
-- stated there.
--
-- Apply:
--   npx wrangler d1 execute nimbus-broker --local  --file=./schema.sql
--   npx wrangler d1 execute nimbus-broker --remote --file=./schema.sql

-- ===================================================================================
-- 1. vehicle_enrolment — the subject root
-- ===================================================================================
-- MUTABLE BECAUSE: this is the row that says "a person enrolled this vehicle". It is the
-- root of every linkage in the database, so it is the row an erasure request must be able
-- to destroy. Deleting it cascades to the salt, the signing keys, the grants, the edges and
-- the revocations, and after that no query in this schema can associate the vehicle with the
-- account or with any counterparty.
--
-- ERASING IT DESTROYS: the account -> vehicle association, and by cascade the entire consent
-- history for that vehicle. What survives is any grant commitment already anchored off-box,
-- which is a digest over a pseudonym keyed by a salt that the same cascade destroys — so
-- what survives is unlinkable to a vehicle or a person even by a party holding both the
-- digest and a candidate VIN.
CREATE TABLE IF NOT EXISTS vehicle_enrolment (
  vehicle_id        TEXT    NOT NULL PRIMARY KEY,  -- opaque, broker-minted; never derived from the VIN
  -- Blind index: HMAC-SHA-256(VIN) under VIN_INDEX_KEY, base64url. Lets the broker find this
  -- row when an owner presents the VIN, and yields nothing in the other direction. UNIQUE so
  -- one vehicle cannot be enrolled twice and quietly accumulate two salts (which would be two
  -- linkability domains for one vehicle, invisible to the owner).
  vin_index         TEXT    NOT NULL,
  -- World Manufacturer Identifier, first three VIN characters. Stored in the clear because a
  -- WMI identifies a manufacturer, not a vehicle or a person: ~10^7 vehicles share one. Kept
  -- because NF-3 resolution is zoned by WMI and the alternative is re-deriving it from a VIN
  -- the broker deliberately does not retain.
  wmi               TEXT    NOT NULL,
  -- Identity-provider subject (Clerk `sub`). Opaque. NOT a name, email or phone: the broker
  -- has no use for those and therefore does not become their custodian.
  owner_account_id  TEXT    NOT NULL,
  -- Current pseudonym rotation epoch. Incrementing it rotates every future pseudonym for this
  -- vehicle, which is how linkability is bounded in time (§12.7). Monotonic, never reused.
  pseudonym_epoch   INTEGER NOT NULL DEFAULT 0,
  enrolled_at       INTEGER NOT NULL,             -- Unix SECONDS everywhere in this schema
  updated_at        INTEGER NOT NULL,
  CHECK (length(vin_index) = 43),
  CHECK (length(wmi) = 3),
  CHECK (pseudonym_epoch >= 0),
  CHECK (enrolled_at > 1700000000 AND enrolled_at < 4000000000)
) STRICT;

-- Enrolment lookup by presented VIN. UNIQUE is the constraint, not just the index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vehicle_enrolment_vin_index
  ON vehicle_enrolment (vin_index);
-- Owner's vehicle list, and the erasure query "every vehicle belonging to this subject".
CREATE INDEX IF NOT EXISTS idx_vehicle_enrolment_owner
  ON vehicle_enrolment (owner_account_id);

-- ===================================================================================
-- 2. pseudonym_salt — THE table whose deletion is irreversible
-- ===================================================================================
-- MUTABLE BECAUSE: this is the erasure lever. The salt is the HMAC key behind every
-- `vehicle_pseudonym` the broker has ever emitted for this vehicle. It exists nowhere else:
-- not on a ledger, not in KV, not in a log, not derivable from anything committed.
--
-- ERASING IT DESTROYS, IRREVERSIBLY: the ability of anyone — including the broker, including
-- a party holding a grant commitment and a candidate VIN — to link a pseudonym back to a
-- vehicle, or to link two pseudonyms to each other. Grants become opaque blobs; anchored
-- commitments become digests over an unrecoverable preimage. This single DELETE is what makes
-- Delete Act erasure real rather than nominal (§9.5), and it is why the erasure routine at
-- the bottom of this file deletes this table LAST-BUT-ONE, immediately before the enrolment:
-- if the routine dies halfway, the linkage key must already be gone.
--
-- One row per (vehicle, epoch): old salts are kept only while grants issued under them are
-- still live, and are deleted with them.
CREATE TABLE IF NOT EXISTS pseudonym_salt (
  vehicle_id  TEXT    NOT NULL,
  epoch       INTEGER NOT NULL,
  salt        TEXT    NOT NULL,  -- base64url, 32 bytes, from generatePseudonymSalt()
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (vehicle_id, epoch),
  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE CASCADE,
  -- 43 chars is 32 bytes unpadded base64url. Enforced here as well as in code because
  -- vin.js accepts any string of >= 32 CHARACTERS, which for a hex salt is 16 bytes — a third
  -- of the advertised entropy. The storage layer refuses the weak case outright.
  CHECK (length(salt) = 43),
  CHECK (epoch >= 0)
) STRICT;

-- ===================================================================================
-- 3. owner_signing_key — custodial issuance, per (vehicle, audience)
-- ===================================================================================
-- MUTABLE BECAUSE: it is key material scoped to one vehicle. Erasing it destroys the ability
-- to issue any further grant for that vehicle and the ability to verify the signature on any
-- grant already issued for it — both correct outcomes for an erased subject.
--
-- WHY THE BROKER HOLDS THIS AT ALL, stated plainly because it is the weakest point in the
-- design: a root grant must be signed by the owner, and a Workers isolate cannot keep a
-- non-extractable CryptoKey between requests. Custodial issuance therefore requires wrapped
-- key material at rest. `wrapped_private_key` is an Ed25519 PKCS#8 blob sealed with AES-GCM
-- under a per-row HKDF salt derived from the OWNER_KEY_WRAP_KEY secret; the secret is not in
-- the database, so a D1 dump alone does not yield signing capability.
--
-- WHY THIS IS NOT A REFUSAL-3 VIOLATION: the key that matters for the owner's control is the
-- REVOCATION key, and the broker never has it (see `owner_revocation_key`, and note that
-- src/index.js feeds every key id it holds to verifyGrant as `forbiddenRevocationKeyIds`, so
-- a grant naming an operator-held revocation key fails verification rather than being
-- policed by convention).
--
-- ONE KEY PER (vehicle, audience), NOT PER VEHICLE. A single per-vehicle signing key would be
-- a join key across counterparty classes: two counterparties get deliberately different
-- pseudonyms, and a shared signer key would let them correlate anyway by comparing the key
-- that signed their grants (§12.7). Per-audience separation also bounds a single key
-- compromise to one linkability domain.
CREATE TABLE IF NOT EXISTS owner_signing_key (
  vehicle_id          TEXT    NOT NULL,
  audience            TEXT    NOT NULL,  -- COUNTERPARTY_CLASSES value; equals the grant's audience
  public_key          TEXT    NOT NULL,  -- raw Ed25519, base64url (43 chars); the out-of-band verifier key
  wrapped_private_key TEXT    NOT NULL,  -- base64url: hkdf_salt || iv || AES-GCM(PKCS#8)
  -- Domain-separated thumbprint of `public_key`, computed with the SAME construction as
  -- revocation key ids (revocationKeyIdFromPublicKey). Stored so the broker can answer "is
  -- this revocation_key_id one of mine?" with an indexed lookup instead of a scan.
  key_id              TEXT    NOT NULL,
  created_at          INTEGER NOT NULL,
  PRIMARY KEY (vehicle_id, audience),
  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE CASCADE,
  CHECK (length(public_key) = 43),
  CHECK (length(key_id) = 43)
) STRICT;

-- Verify-path lookup: given a stored grant, fetch the key that must have signed it.
CREATE INDEX IF NOT EXISTS idx_owner_signing_key_key_id
  ON owner_signing_key (key_id);

-- ===================================================================================
-- 4. owner_revocation_key — PUBLIC key only. The private half is never here.
-- ===================================================================================
-- MUTABLE BECAUSE: it binds a revocation authority to a vehicle, which is subject data.
-- Erasing it destroys the broker's ability to authenticate a future revocation for that
-- vehicle — harmless once the grants are gone in the same cascade.
--
-- THE PRIVATE KEY IS THE OWNER'S AND ONLY THE OWNER'S. That is Refusal 3 made structural:
-- there is no column for it. An operator that could revoke on the owner's behalf could also
-- decline to, and a revocation right held by the party with a commercial interest in
-- continued access is not a right. This table holds the public key so a signed revocation
-- can be verified, and the key id so a grant can name the authority without carrying
-- anything usable.
CREATE TABLE IF NOT EXISTS owner_revocation_key (
  revocation_key_id TEXT    NOT NULL PRIMARY KEY,  -- base64url thumbprint, 43 chars
  vehicle_id        TEXT    NOT NULL,
  public_key        TEXT    NOT NULL,              -- raw Ed25519, base64url, 43 chars
  registered_at     INTEGER NOT NULL,
  -- Rotation: a new row supersedes an old one, and the old row survives while grants naming
  -- it are still live. NOT a status flag — an inactive key is deleted, because a retained
  -- "revoked" key is retained data.
  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE CASCADE,
  CHECK (length(revocation_key_id) = 43),
  CHECK (length(public_key) = 43)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_owner_revocation_key_vehicle
  ON owner_revocation_key (vehicle_id);

-- ===================================================================================
-- 5. operator_held_key_id — the Refusal 3 denylist, as data
-- ===================================================================================
-- MUTABLE BECAUSE: it is an operational inventory of the broker's own key ids, not subject
-- data. It is the ONE table in this schema that erasing a subject must NOT touch, because it
-- is not about a subject. (It still cascades away if the vehicle it belongs to is erased —
-- see the FK — since a per-vehicle signing key id is meaningless once the vehicle is gone.)
--
-- WHY IT EXISTS: src/index.js reads every row into `forbiddenRevocationKeyIds` and passes it
-- to verifyGrant, and refuses at issuance to accept a `revocation_key_id` that appears here.
-- That turns "the operator does not hold revocation authority" from an assertion in a white
-- paper into a check that fails a request and can be asserted by the conformance suite.
CREATE TABLE IF NOT EXISTS operator_held_key_id (
  key_id     TEXT    NOT NULL PRIMARY KEY,  -- base64url thumbprint, 43 chars
  purpose    TEXT    NOT NULL,              -- e.g. 'owner-signing-custodial'
  vehicle_id TEXT,                          -- NULL for operator-wide keys
  created_at INTEGER NOT NULL,
  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE CASCADE,
  CHECK (length(key_id) = 43)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_operator_held_key_id_vehicle
  ON operator_held_key_id (vehicle_id);

-- ===================================================================================
-- 6. consent_grant — the payload store
-- ===================================================================================
-- MUTABLE BECAUSE: a grant is the record of a consent decision about a vehicle, which makes
-- it subject data even though it contains no direct identifier. Erasing it destroys the
-- record that a particular counterparty was ever authorised over a particular vehicle.
--
-- `payload_json` IS AUTHORITATIVE. It holds the exact signed object — the bytes the signature
-- covers, as canonicalised by JCS. Every other column here is a DENORMALISED COPY that exists
-- only so the queries src/index.js actually runs can use an index.
--
-- THOSE COPIES MUST NEVER BE USED FOR A SECURITY DECISION. A verifier reads `payload_json`,
-- re-canonicalises and re-checks the signature. If a copy and the payload ever disagree — a
-- bad migration, a hand-edited row, a bug — the copy is wrong by definition, and code that
-- trusted `expires_at` from the column rather than from the signed payload would be honouring
-- a duration the owner never signed. `commitment` is stored for the same reason and compared
-- with a constant-time comparison at verify time.
--
-- NOTE WHAT IS ABSENT: no `revoked` flag. Revocation state lives in its own table so that
-- revoking is an INSERT rather than an UPDATE to the grant, which keeps the signed payload
-- untouched and makes "was this revoked" a question with one answer in one place.
CREATE TABLE IF NOT EXISTS consent_grant (
  grant_id           TEXT    NOT NULL PRIMARY KEY,  -- 128 random bits, base64url (22 chars)
  vehicle_id         TEXT    NOT NULL,
  -- The full signed NF-2 grant, exactly as issued. The source of truth.
  payload_json       TEXT    NOT NULL,
  -- SHA-256 commitment over the signed grant (deriveGrantCommitment). The ONLY value in this
  -- row that would ever be permitted to cross onto an immutable ledger (Refusal 2).
  commitment         TEXT    NOT NULL,

  -- ---- denormalised, for indexing only; see the warning above ----
  pseudonym_value    TEXT    NOT NULL,  -- base64url, 43 chars
  pseudonym_epoch    INTEGER NOT NULL,
  audience           TEXT    NOT NULL,
  counterparty_class TEXT    NOT NULL,
  counterparty_key   TEXT    NOT NULL,  -- raw Ed25519, base64url, 43 chars
  purpose            TEXT    NOT NULL,  -- one DPPA_PURPOSES key, 18 U.S.C. §2721(b)
  revocation_key_id  TEXT    NOT NULL,
  issued_at          INTEGER NOT NULL,
  expires_at         INTEGER NOT NULL,
  delegation_depth   INTEGER NOT NULL,
  parent_grant_id    TEXT,              -- NULL on a root grant
  renewal_of         TEXT,              -- NULL unless this supersedes another grant
  created_at         INTEGER NOT NULL,

  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE CASCADE,
  -- Self-reference for lineage. ON DELETE CASCADE so erasing a root grant cannot leave
  -- orphaned children that would verify against a parent nobody can produce.
  FOREIGN KEY (parent_grant_id) REFERENCES consent_grant (grant_id) ON DELETE CASCADE,
  CHECK (length(grant_id) = 22),
  CHECK (length(commitment) = 43),
  CHECK (length(pseudonym_value) = 43),
  CHECK (length(counterparty_key) = 43),
  CHECK (length(revocation_key_id) = 43),
  CHECK (delegation_depth >= 0 AND delegation_depth <= 2),      -- MAX_DELEGATION_DEPTH
  CHECK (expires_at > issued_at),
  -- 45 days, pinned to the Delete Act deletion cadence (§9.5). Enforced in nf2-grant.js and
  -- again here, because a grant that outlives a full erasure sweep is a standing
  -- authorisation the owner never re-affirmed, and the storage layer is the last place that
  -- can refuse one.
  CHECK (expires_at - issued_at <= 3888000),
  CHECK (issued_at > 1700000000 AND issued_at < 4000000000)
) STRICT;

-- Owner's live grants for a vehicle; also the "does this vehicle have anything outstanding"
-- check at issuance and the per-vehicle sweep at erasure.
CREATE INDEX IF NOT EXISTS idx_consent_grant_vehicle_expiry
  ON consent_grant (vehicle_id, expires_at);
-- A requester asking what it holds; and the counterparty-binding check on presentation.
CREATE INDEX IF NOT EXISTS idx_consent_grant_counterparty_key
  ON consent_grant (counterparty_key);
-- Lineage walks in both directions: the descendant cascade at revocation and the ancestor
-- walk at verification.
CREATE INDEX IF NOT EXISTS idx_consent_grant_parent
  ON consent_grant (parent_grant_id);
-- Resolving a grant to the signing key by pseudonym, and detecting duplicate issuance within
-- an epoch for one audience.
CREATE INDEX IF NOT EXISTS idx_consent_grant_pseudonym
  ON consent_grant (pseudonym_value);
-- Expiry sweep: delete rows whose authority is already dead, without scanning.
CREATE INDEX IF NOT EXISTS idx_consent_grant_expires_at
  ON consent_grant (expires_at);
-- Renewal chains, so superseding a grant can find what it supersedes.
CREATE INDEX IF NOT EXISTS idx_consent_grant_renewal_of
  ON consent_grant (renewal_of);
-- A grant-scope NF-4 revocation names its target BY COMMITMENT, never by grant_id (the
-- commitment is the only value that binds the issuer, because the grant deliberately carries
-- no signer public key). `POST /revocations` therefore looks the grant up by this column, and
-- without an index that lookup is a full scan on the one request path an owner needs to be
-- fast. UNIQUE rather than plain: two rows sharing a commitment would mean one revocation
-- entry matching two grants, and NF-4 keys revocation by commitment.
CREATE UNIQUE INDEX IF NOT EXISTS idx_consent_grant_commitment
  ON consent_grant (commitment);

-- ===================================================================================
-- 7. delegation_edge — the cascade graph, materialised
-- ===================================================================================
-- MUTABLE BECAUSE: an edge records that a specific downstream party was let in under this
-- owner's grant. Erasing it destroys the provenance of that access.
--
-- WHY A SEPARATE TABLE when `consent_grant.parent_grant_id` already holds the edge: this is
-- the relation the revocation cascade walks with a recursive CTE, and keeping it narrow means
-- the walk touches an index of two short columns rather than rows carrying payload JSON. The
-- child's payload remains authoritative; a disagreement between this table and
-- `parent_grant_id` means this table is wrong.
--
-- DELEGATION IS NOT TRANSFER, and the columns say so: there is no `from`/`to` pair and no
-- operation that moves a grant. An edge is additive — the parent survives unchanged, the
-- child can only narrow, and revoking the parent kills the subtree.
CREATE TABLE IF NOT EXISTS delegation_edge (
  child_grant_id  TEXT    NOT NULL PRIMARY KEY,  -- one parent per child, enforced by the PK
  parent_grant_id TEXT    NOT NULL,
  -- Depth of the CHILD below the root. Bounded so a cycle introduced by a bad write cannot
  -- make the cascade walk unbounded; the CTE also carries its own depth guard.
  depth           INTEGER NOT NULL,
  -- The delegator's key, copied from the parent's `counterparty_key` at registration time.
  -- This is the key that signed the child, recorded so an audit can answer "who let them in"
  -- without reconstructing the chain.
  delegator_key   TEXT    NOT NULL,
  created_at      INTEGER NOT NULL,
  FOREIGN KEY (child_grant_id)  REFERENCES consent_grant (grant_id) ON DELETE CASCADE,
  FOREIGN KEY (parent_grant_id) REFERENCES consent_grant (grant_id) ON DELETE CASCADE,
  CHECK (child_grant_id <> parent_grant_id),   -- no self-edge; the trivial cycle
  CHECK (depth >= 1 AND depth <= 2),           -- MAX_DELEGATION_DEPTH
  CHECK (length(delegator_key) = 43)
) STRICT;

-- The cascade walk: "every child of this grant", applied recursively.
CREATE INDEX IF NOT EXISTS idx_delegation_edge_parent
  ON delegation_edge (parent_grant_id);

-- ===================================================================================
-- 8. revocation — NF-4 state
-- ===================================================================================
-- MUTABLE BECAUSE: a revocation names a grant, which names a vehicle. Erasing it destroys the
-- record that access was withdrawn. Note the ordering consequence: revocations are deleted
-- BEFORE grants in the erasure routine, because the FK points at the grant and because a
-- revocation surviving its grant would be a dangling accusation about a party nobody can
-- identify.
--
-- WHY REVOCATION IS AN INSERT, NOT AN UPDATE TO THE GRANT: the grant's signed bytes are
-- immutable by construction — editing `expires_at` would produce a different object with a
-- different commitment under the same grant_id, and a verifier accepting either form would be
-- honouring a duration the owner never signed. So revocation is state kept alongside the
-- payload, never inside it.
--
-- IDEMPOTENT BY PRIMARY KEY. Re-presenting a valid revocation is a no-op rather than an
-- error, because a kill switch that fails when pressed twice is a kill switch that can be
-- lost to a retry.
CREATE TABLE IF NOT EXISTS revocation (
  grant_id          TEXT    NOT NULL PRIMARY KEY,
  revoked_at        INTEGER NOT NULL,  -- owner-asserted, inside the signed revocation
  recorded_at       INTEGER NOT NULL,  -- broker clock; the two differing is normal and audited
  reason_code       TEXT    NOT NULL,  -- closed vocabulary, validated by nf4-revocation.js
  -- The owner's signature over the canonical revocation. Retained so the broker can prove it
  -- did not revoke on its own initiative — the counterpart to Refusal 3 on the audit side.
  revocation_signature TEXT NOT NULL,
  revocation_key_id TEXT    NOT NULL,  -- which owner key authorised it
  -- Revocation-state commitment. The second of the only two digest classes Refusal 2 permits
  -- on an immutable ledger.
  commitment        TEXT    NOT NULL,
  -- NULL when the owner revoked this grant directly; the ancestor's grant_id when this row
  -- exists because a parent was revoked and the cascade walked down to it. Distinguishing the
  -- two matters: a direct revocation is a decision, a cascaded one is a consequence, and an
  -- owner reviewing their history should see which is which.
  cascaded_from     TEXT,
  FOREIGN KEY (grant_id)      REFERENCES consent_grant (grant_id) ON DELETE CASCADE,
  FOREIGN KEY (cascaded_from) REFERENCES consent_grant (grant_id) ON DELETE CASCADE,
  CHECK (length(grant_id) = 22),
  CHECK (length(revocation_signature) = 86),  -- Ed25519, base64url
  CHECK (length(revocation_key_id) = 43),
  CHECK (length(commitment) = 43),
  CHECK (revoked_at > 1700000000 AND revoked_at < 4000000000)
) STRICT;

-- "What did this owner key revoke", for the owner's own history view.
CREATE INDEX IF NOT EXISTS idx_revocation_key_id
  ON revocation (revocation_key_id);
-- Cascade provenance, and the reverse question "what did revoking that grant take down".
CREATE INDEX IF NOT EXISTS idx_revocation_cascaded_from
  ON revocation (cascaded_from);
-- Retention sweep once the underlying grants have expired past any dispute window.
CREATE INDEX IF NOT EXISTS idx_revocation_recorded_at
  ON revocation (recorded_at);

-- ===================================================================================
-- 8b. revocation_kill_switch — NF-4 VEHICLE SCOPE. The owner's one lever.
-- ===================================================================================
-- ADDED WHEN src/index.js WAS WRITTEN, because table 8 above could only express a
-- GRANT-scope revocation and nf4-revocation.js has two scopes. Without this table the kill
-- switch — the half of NF-4 an owner reaches for when they sell the car or lose control of a
-- counterparty — had nowhere to land, and `POST /revocations` would have had to refuse the
-- one operation the whole module is named after. That is a gap in the schema, not a feature
-- request.
--
-- MUTABLE BECAUSE: a row binds an owner-held revocation key to a vehicle and an instant,
-- which is subject data. It is erased with the vehicle (see the routine at the bottom).
--
-- THE TARGET IS A KEY THUMBPRINT, NOT A VEHICLE IDENTIFIER, and that is nf4's design rather
-- than a storage convenience: an owner exercising sovereignty should not have to know or
-- enumerate who holds grants over their car. `vehicle_id` is recorded alongside so erasure
-- can find the row, and it is resolved by the broker from `owner_revocation_key` — it is not
-- part of what the owner signed.
--
-- `effective_from` IS PART OF THE PRIMARY KEY, mirroring nf4's leaf-key construction
-- H(domain || revocation_key_id || ':' || effective_from). A kill switch at one instant is a
-- different leaf from a kill switch at another, so a later switch cannot silently rewrite an
-- earlier one's entry and invalidate proofs already issued against the old root.
--
-- THE FULL RECORD IS RECONSTRUCTIBLE FROM THIS ROW — scope, target, key, timestamps, reason
-- and signature — so the broker can re-verify what it acted on, and can prove it did not
-- revoke on its own initiative. That is the audit-side counterpart to Refusal 3, and it is
-- the same reason table 8 retains `revocation_signature`.
--
-- IDEMPOTENT BY PRIMARY KEY: a kill switch that fails when pressed twice is a kill switch
-- that can be lost to a retry.
CREATE TABLE IF NOT EXISTS revocation_kill_switch (
  revocation_key_id    TEXT    NOT NULL,          -- base64url thumbprint, 43 chars; the target
  effective_from       INTEGER NOT NULL,          -- grants issued at or before this are dead
  vehicle_id           TEXT,                      -- resolved by the broker; NULL if unresolvable
  -- Revocation-state commitment: the NF-4 leaf key for this entry. One of the only two digest
  -- classes Refusal 2 permits on an immutable ledger.
  commitment           TEXT    NOT NULL,
  revocation_key       TEXT    NOT NULL,          -- raw Ed25519 PUBLIC key, base64url. Never private.
  revocation_signature TEXT    NOT NULL,          -- owner's signature over the canonical record
  issued_at            INTEGER NOT NULL,          -- owner-asserted, inside the signed record
  recorded_at          INTEGER NOT NULL,          -- broker clock; the two differing is normal
  reason_code          TEXT    NOT NULL,          -- closed vocabulary, validated by nf4-revocation.js
  PRIMARY KEY (revocation_key_id, effective_from),
  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE CASCADE,
  CHECK (length(revocation_key_id) = 43),
  CHECK (length(commitment) = 43),
  CHECK (length(revocation_key) = 43),
  CHECK (length(revocation_signature) = 86),      -- Ed25519, base64url
  -- nf4-revocation.js refuses a future-dated effective_from: a kill switch that pre-revoked
  -- grants the owner has not yet decided to issue could never be followed by re-consent under
  -- the same key. Enforced there and again here, because the storage layer is the last place
  -- that can refuse one.
  CHECK (effective_from <= issued_at),
  CHECK (issued_at > 1700000000 AND issued_at < 4000000000)
) STRICT;

-- THE HOT PATH. `revocationStatus()` in src/index.js reads MAX(effective_from) for a grant's
-- revocation_key_id on every verification, and consults this floor DIRECTLY rather than the
-- materialised per-grant rows in table 8 — so a broker that failed to enumerate the affected
-- grants cannot thereby keep a killed grant alive. Without this index that read is a scan on
-- the authorisation path.
CREATE INDEX IF NOT EXISTS idx_revocation_kill_switch_key
  ON revocation_kill_switch (revocation_key_id, effective_from);
-- Erasure, and the sweep for rows whose vehicle was never resolved.
CREATE INDEX IF NOT EXISTS idx_revocation_kill_switch_vehicle
  ON revocation_kill_switch (vehicle_id);

-- ===================================================================================
-- 9. resolution_zone — NF-3 records. THE ONLY TABLE HERE THAT HOLDS NO SUBJECT DATA.
-- ===================================================================================
-- MUTABLE BECAUSE: zone records change when an OEM moves an endpoint or a zone is
-- decommissioned. Nothing here is personal information: a row is keyed by WMI, which
-- identifies a manufacturer, and its contents are the same for every vehicle that
-- manufacturer ever built. This is why resolution can be cached publicly while everything
-- else in the system is `no-store`.
--
-- REFUSAL 1 IS ENFORCED BY WHAT THIS TABLE CANNOT HOLD. There is no token column, no
-- credential column, no key column, no "access" column. A resolution answer says WHERE to ask
-- for authorization and by WHAT protocol. It never says "here is authorization", because
-- possession of a VIN must confer no authority anywhere in any code path. The VIN is a name
-- exactly like a DNS name, and a DNS answer is an address, not a login.
CREATE TABLE IF NOT EXISTS resolution_zone (
  zone_id                TEXT    NOT NULL PRIMARY KEY,
  wmi                    TEXT    NOT NULL,  -- ISO 3779 World Manufacturer Identifier
  -- WHERE to present a request for authorization. A URL. Not a credential, not a bearer
  -- endpoint the caller is pre-authorised against.
  authorization_endpoint TEXT    NOT NULL,
  -- Which Layer-2 access protocol the endpoint speaks, e.g. 'iso-20078'. Recorded so a
  -- requester knows what to speak rather than probing, and so the honest ceiling of §3.3 is
  -- machine-readable at resolution time instead of at delivery time.
  protocol               TEXT    NOT NULL,
  -- Human-readable policy document for the zone. A URL. Advisory.
  policy_uri             TEXT,
  ttl_s                  INTEGER NOT NULL,
  active                 INTEGER NOT NULL DEFAULT 1,  -- 0 disables without deleting history
  updated_at             INTEGER NOT NULL,
  CHECK (length(wmi) = 3),
  CHECK (ttl_s > 0 AND ttl_s <= 86400),
  CHECK (active IN (0, 1)),
  -- Fail closed on the endpoint scheme at the storage layer. A zone record that resolved to
  -- http:// would send an authorization request over cleartext, and the request is where the
  -- credential the broker refuses to hold actually gets presented.
  CHECK (authorization_endpoint LIKE 'https://%'),
  CHECK (policy_uri IS NULL OR policy_uri LIKE 'https://%')
) STRICT;

-- Resolution's hot path: WMI -> active zone. Partial index so the lookup never considers
-- retired rows.
CREATE UNIQUE INDEX IF NOT EXISTS idx_resolution_zone_wmi_active
  ON resolution_zone (wmi) WHERE active = 1;

-- ===================================================================================
-- 10. resolution_delegation — per-vehicle zone override
-- ===================================================================================
-- MUTABLE BECAUSE: keyed by `vin_index`, so it IS subject data — it records that a specific
-- vehicle resolves somewhere other than its manufacturer's zone, which is a fact about that
-- vehicle. Erasing it destroys that fact and the vehicle falls back to WMI resolution, which
-- is the same answer every other vehicle of that make gets.
--
-- WHY IT EXISTS: a fleet operator or an aftermarket telematics provider can legitimately be
-- the authorization authority for a vehicle its manufacturer never provisioned. Without an
-- override, resolution would be a permanent OEM monopoly on the index — which is the
-- structural problem the layer exists to avoid.
CREATE TABLE IF NOT EXISTS resolution_delegation (
  vin_index  TEXT    NOT NULL PRIMARY KEY,  -- blind index, same construction as the enrolment
  zone_id    TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (zone_id) REFERENCES resolution_zone (zone_id) ON DELETE CASCADE,
  CHECK (length(vin_index) = 43)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_resolution_delegation_zone
  ON resolution_delegation (zone_id);

-- READ THIS BEFORE ASSUMING TABLES 9 AND 10 ARE ON A REQUEST PATH. They are not, in V1.
-- src/index.js is an NF-3 *resolver* (a client): `GET /resolve/:vin` calls `resolveVin`,
-- which walks a trust-anchored chain of SIGNED zone answers and verifies every one. A zone's
-- answer must be signed by a zone key, and this deployment holds no zone signing key — there
-- is no column for one and no secret named for one — so this broker cannot serve the ZONE
-- role and does not read these two tables. They are the seed data for a zone deployment that
-- is a separate concern. Stated here rather than deleted because the erasure routine below
-- already accounts for them and because an unexplained empty table invites someone to wire it
-- into the resolver and reintroduce an unsigned answer path.

-- ===================================================================================
-- 10b. nf3_resolution_cache — the RESOLVER's answer cache. OWNED BY nf3-resolve.js.
-- ===================================================================================
-- ADDED WHEN src/index.js WAS WRITTEN. nf3-resolve.js reads and writes this table on every
-- resolution and exports its DDL as `NF3_CACHE_SCHEMA_SQL`, but nothing applied it — the
-- module swallows cache errors by design ("a resolver that cannot cache is slow, not
-- wrong"), so the omission was invisible: every resolution silently missed the durable tier
-- and went to the network. The columns below are that export, restated as STRICT to match the
-- rest of this file.
--
-- NO SUBJECT DATA IN THE SENSE THE OTHER TABLES HAVE IT, but not nothing either. A row is
-- keyed by the qname DIGEST — a domain-separated SHA-256 of the VIN, which is data
-- minimisation and expressly NOT confidentiality (a VIN has ~10^8 realistic entropy, so a
-- digest is a rainbow-table lookup for anyone testing a candidate). What a row records is
-- that SOMEBODY asked about a vehicle. It records no requester, so it cannot say who; that is
-- exactly why resolution is not audited (see table 14) and why this table is swept.
--
-- WHY THE ANSWER, THE ZONE KEY AND THE CHAIN ARE ALL STORED: the cache is RE-VERIFIED ON
-- READ. A cache row can be modified by anything with database access, so treating it as
-- trustworthy would move the trust boundary from a signature to a storage ACL. Storing only
-- the answer would force a full chain walk to check it; storing nothing extra would make the
-- cache a trust boundary.
--
-- `expires_at` IS ABSOLUTE, not a stored TTL. RFC 1035 requires every cache to decrement the
-- TTL it passes on; re-serving a stored relative TTL would extend an answer's life at every
-- hop, so a chain of caches could keep a withdrawn endpoint alive indefinitely.
CREATE TABLE IF NOT EXISTS nf3_resolution_cache (
  qname_digest TEXT    NOT NULL PRIMARY KEY,  -- base64url SHA-256 over the VIN, 43 chars
  record_type  TEXT    NOT NULL,              -- 'ce' | 'nxenroll' | 'nxzone'; only terminal answers cache
  zone_id      TEXT    NOT NULL,
  zone_key     TEXT    NOT NULL,              -- the zone's PUBLIC verification key, base64url
  answer_json  TEXT    NOT NULL,              -- the signed answer, verbatim
  chain_json   TEXT    NOT NULL,              -- the validated delegation chain
  cached_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  CHECK (length(qname_digest) = 43),
  CHECK (length(zone_key) = 43),
  CHECK (record_type IN ('ce', 'nxenroll', 'nxzone'))
) STRICT;

-- The sweep. A cache with no sweep becomes a growing record of which vehicles someone asked
-- about: each row innocuous, the accumulation not — the same distinction the Delete Act draws
-- when it treats an inventory of vehicle identifiers as a regulated category (§9.5).
-- `sweepResolutionCache(env, now)` in nf3-resolve.js is the caller.
CREATE INDEX IF NOT EXISTS nf3_resolution_cache_expiry
  ON nf3_resolution_cache (expires_at);

-- ===================================================================================
-- 11. requester — the counterparty registry
-- ===================================================================================
-- MUTABLE BECAUSE: it is business-party data, and a requester that leaves the network should
-- be removable rather than flagged. Erasing a REQUESTER does not erase a SUBJECT and the two
-- routines are separate; note though that deleting a requester leaves grants issued to it
-- verifiable-but-unservable, which is the correct end state (the grant's authority is bounded
-- by its own expiry, not by the registry).
--
-- WHY THE CLASS BINDING LIVES HERE AND NOT IN THE GRANT ALONE: a grant names a
-- `counterparty_class`, and that name is only meaningful if somebody vouches that the key
-- belongs to a party of that class. This registry is that vouching, and unlike the grant it is
-- revocable — a repair shop that loses its licence loses service without every owner having
-- to revoke individually.
--
-- THIS IS NOT PREFERENTIAL ACCESS LICENSING. CarNimbus operates this broker; the Nimbus
-- Foundation does not (Refusal 3). Registration is a class attestation with a documented
-- admission rule, not a paid tier — there is no price, priority, rate multiplier or
-- entitlement column, and adding one would be a Layer-5 change requiring the clearances of
-- §9.7.
CREATE TABLE IF NOT EXISTS requester (
  requester_id       TEXT    NOT NULL PRIMARY KEY,
  display_name       TEXT    NOT NULL,  -- a business name, not a natural person's
  counterparty_class TEXT    NOT NULL,  -- one COUNTERPARTY_CLASSES value
  -- Jurisdictional licence reference where the class requires one (e.g. a California dealer
  -- licence for 'dealer-licensed-ca'). Free text because the issuing authority's format is
  -- not ours to constrain; verified out of band, recorded here for audit.
  licence_reference  TEXT,
  status             TEXT    NOT NULL,  -- 'active' | 'suspended'
  registered_at      INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  CHECK (status IN ('active', 'suspended')),
  CHECK (counterparty_class IN (
    'repair-independent', 'repair-franchised', 'dealer-licensed-ca', 'fleet-operator',
    'municipal-agency', 'academic-research', 'insurer', 'oem-warranty'
  ))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_requester_class_status
  ON requester (counterparty_class, status);

-- ===================================================================================
-- 12. requester_key — request-signing keys, rotatable
-- ===================================================================================
-- MUTABLE BECAUSE: keys rotate and compromised keys must be removable, not annotated.
--
-- PUBLIC KEYS ONLY, AND THAT IS THE WHOLE AUTHENTICATION STORY. There is no api_key column,
-- no shared secret, no bearer token: a requester authenticates by SIGNING the request, and
-- the broker holds only what it needs to check the signature. A stolen database therefore
-- yields no ability to impersonate a requester — which is the same reasoning that makes a
-- Consent Grant bound to a key rather than to a name.
--
-- `public_key` is UNIQUE across the whole table: the same key must not be claimed by two
-- requesters, or the class attestation behind a grant's `counterparty_class` would be
-- ambiguous at exactly the moment it is relied on.
CREATE TABLE IF NOT EXISTS requester_key (
  key_id       TEXT    NOT NULL PRIMARY KEY,  -- opaque label the requester sends in a header
  requester_id TEXT    NOT NULL,
  public_key   TEXT    NOT NULL,              -- raw Ed25519, base64url, 43 chars
  status       TEXT    NOT NULL,              -- 'active' | 'retired'
  added_at     INTEGER NOT NULL,
  FOREIGN KEY (requester_id) REFERENCES requester (requester_id) ON DELETE CASCADE,
  CHECK (length(public_key) = 43),
  CHECK (status IN ('active', 'retired'))
) STRICT;

-- Every authenticated request does this lookup: key_id -> key + owning requester.
CREATE UNIQUE INDEX IF NOT EXISTS idx_requester_key_public_key
  ON requester_key (public_key);
-- Issuance does the reverse: given a grant's `counterparty_key`, which registered party and
-- class is this, and is the key still active.
CREATE INDEX IF NOT EXISTS idx_requester_key_requester
  ON requester_key (requester_id, status);

-- ===================================================================================
-- 13. request_nonce — replay protection
-- ===================================================================================
-- MUTABLE BECAUSE: entries are worthless after the signature skew window closes, and keeping
-- them would build a request-by-request activity log of every requester — a surveillance
-- record accumulated as a side effect of security, which is exactly the shape of thing this
-- architecture refuses elsewhere. Rows are deleted opportunistically once older than
-- NONCE_TTL_S.
--
-- WHY D1 AND NOT KV, stated because KV is the obvious choice and it is wrong here: KV is
-- eventually consistent with a propagation window on the order of a minute. A nonce store
-- with a read-after-write window is not a nonce store — a replay inside the window simply
-- succeeds, and the window is longer than the skew tolerance it is supposed to enforce. D1's
-- primary is authoritative, so `INSERT ... ON CONFLICT DO NOTHING` and a changed-row count is
-- a real mutual exclusion.
--
-- NOTE what a row does NOT contain: no path, no body, no headers. Only that a given key used
-- a given nonce at a given second. Enough to refuse a replay, not enough to reconstruct
-- behaviour.
CREATE TABLE IF NOT EXISTS request_nonce (
  key_id   TEXT    NOT NULL,
  nonce    TEXT    NOT NULL,
  seen_at  INTEGER NOT NULL,
  PRIMARY KEY (key_id, nonce)
) STRICT;

-- The GC sweep. Without this the sweep is a full scan and gets skipped, and a nonce table
-- that is never swept becomes the activity log this design refuses to keep.
CREATE INDEX IF NOT EXISTS idx_request_nonce_seen_at
  ON request_nonce (seen_at);

-- ===================================================================================
-- 14. audit_log — MUTABLE, AND DELIBERATELY NOT APPEND-ONLY
-- ===================================================================================
-- MUTABLE BECAUSE: this is the table where a well-intentioned engineer recreates the
-- immutable ledger by accident. An append-only, never-pruned audit log containing anything
-- about a subject is the same irreconcilability as an on-chain record (§9.5) with none of the
-- integrity benefit — and it is worse than a ledger in one respect, because nobody thinks of
-- a log as a data store subject to an erasure request. So: deletable, cascading with the
-- vehicle, and swept by retention.
--
-- WHAT MAY BE IN A ROW: grant ids, pseudonyms, requester ids, event names, outcomes, reason
-- CODES. All of it either opaque, keyed under a salt this database can destroy, or a business
-- party rather than a person.
--
-- WHAT MAY NEVER BE IN A ROW, and there is no column for any of it: a VIN, a blind index, an
-- owner account id, a signature, a key, a request body, a header, a token, an error object.
-- `detail_json` is written from an explicit allowlist in src/index.js — never from a request,
-- a response or a caught error — because "log the error" is the single most common way a VIN
-- or an Authorization header reaches durable storage.
--
-- Resolution queries are NOT audited, deliberately. A log of who resolved which VIN would
-- reconstruct exactly the correlation the pseudonym scheme exists to prevent: it would say
-- which parties are interested in which vehicles, keyed by a public identifier, in a table
-- with no salt protecting it. The absence of those rows is a security control.
CREATE TABLE IF NOT EXISTS audit_log (
  audit_id    TEXT    NOT NULL PRIMARY KEY,  -- request id; also correlates with the log stream
  at          INTEGER NOT NULL,
  event       TEXT    NOT NULL,  -- closed set, see src/index.js AUDIT_EVENTS
  outcome     TEXT    NOT NULL,  -- 'allow' | 'deny' | 'error'
  actor_kind  TEXT    NOT NULL,  -- 'owner' | 'requester' | 'anonymous' | 'system'
  -- Requester id for a counterparty, NULL for an owner. An owner is NOT identified here: the
  -- vehicle_id is enough to answer every question the log needs to answer, and an account id
  -- in an audit row is a person in an audit row.
  actor_id    TEXT,
  vehicle_id  TEXT,
  grant_id    TEXT,
  pseudonym   TEXT,              -- base64url pseudonym; meaningless once the salt is gone
  reason_code TEXT,              -- the structured error code, never a free-text message
  detail_json TEXT,              -- allowlisted scalars only
  operator_id TEXT    NOT NULL,  -- which deployment wrote this
  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE CASCADE,
  -- Deliberately NOT a foreign key to consent_grant: an audit row for a REFUSED issuance
  -- references a grant id that was never stored, and an FK would either reject the row or
  -- force a placeholder. The id is a correlation handle here, not a reference.
  CHECK (outcome IN ('allow', 'deny', 'error')),
  CHECK (actor_kind IN ('owner', 'requester', 'anonymous', 'system')),
  CHECK (at > 1700000000 AND at < 4000000000)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_log_at            ON audit_log (at);
CREATE INDEX IF NOT EXISTS idx_audit_log_grant         ON audit_log (grant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_vehicle_at    ON audit_log (vehicle_id, at);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor         ON audit_log (actor_id, at);

-- ===================================================================================
-- 15. drop_suppression — the M3 join point (California Delete Act, SB 362)
-- ===================================================================================
-- OWNERSHIP: the M3 worker (m3-drop-compliance/) polls DROP — the CPPA's Delete Request and
-- Opt-Out Platform — matches requests to enrolments, and WRITES this table. This broker only
-- READS it, and does so at exactly one place: before issuing a grant. That split is
-- deliberate. Deletion processing is a scheduled, retrying, externally-paced job; grant
-- issuance is a latency-sensitive request path. Coupling them would mean either a slow
-- issuance or a deletion obligation on a best-effort timer.
--
-- MUTABLE BECAUSE: a suppression row is a claim linking a consumer to a vehicle, which makes
-- it some of the most sensitive data in the schema — it is the one place where an external
-- consumer identifier meets an internal vehicle. Erasing it destroys that link. Note the
-- ordering hazard the routine at the bottom handles explicitly: the row must be deleted as
-- part of the subject's erasure, but only AFTER the deletion it requested has actually been
-- carried out, or the request is lost and the obligation with it.
--
-- `subject_hash` NOT a consumer identifier. DROP supplies hashed consumer identifiers; only
-- the hash is stored, and no column exists for an email, phone or name.
--
-- FAIL CLOSED, AND WHY: while a row here is `pending` or `processing` for a vehicle, this
-- broker refuses to issue new grants for it. A deletion request in flight and a fresh
-- 45-day authorisation minted alongside it are contradictory instructions, and the one the
-- consumer actually gave is the deletion.
CREATE TABLE IF NOT EXISTS drop_suppression (
  drop_request_id TEXT    NOT NULL PRIMARY KEY,  -- DROP's identifier for the request
  subject_hash    TEXT    NOT NULL,              -- hashed consumer identifier, from DROP
  -- Resolved linkage, both nullable because M3 writes the row on receipt and resolves the
  -- match afterwards. A row with both NULL is a request that matched nothing — which must
  -- still be retained until processed, because "we found nothing" is itself the response the
  -- statute requires us to be able to substantiate.
  vin_index       TEXT,
  vehicle_id      TEXT,
  status          TEXT    NOT NULL,  -- 'pending' | 'processing' | 'completed' | 'rejected'
  received_at     INTEGER NOT NULL,  -- starts the 45-day clock (§9.5)
  processed_at    INTEGER,
  -- Which rows the erasure routine actually removed, as counts only. Enough to substantiate
  -- compliance; not a copy of what was deleted, because a receipt containing the deleted data
  -- has not deleted it.
  erased_counts_json TEXT,
  source          TEXT    NOT NULL,  -- 'drop' | 'direct-ccpa' | 'operator'
  FOREIGN KEY (vehicle_id) REFERENCES vehicle_enrolment (vehicle_id) ON DELETE SET NULL,
  CHECK (status IN ('pending', 'processing', 'completed', 'rejected')),
  CHECK (source IN ('drop', 'direct-ccpa', 'operator')),
  CHECK (vin_index IS NULL OR length(vin_index) = 43),
  CHECK (received_at > 1700000000 AND received_at < 4000000000)
) STRICT;

-- ON DELETE SET NULL above, not CASCADE, and it is the one exception to the no-tombstone
-- rule in this file: erasing the vehicle must NOT erase the record that erasure was
-- requested, or the 45-day obligation disappears together with the thing it applied to and
-- there is nothing left to substantiate compliance with. What survives is a hash and a
-- timestamp, linked to no vehicle and no person.

-- The issuance gate: "is there an open deletion request for this vehicle". Partial index so
-- the check reads only open rows.
CREATE INDEX IF NOT EXISTS idx_drop_suppression_open_vehicle
  ON drop_suppression (vehicle_id) WHERE status IN ('pending', 'processing');
-- M3's own matching path, before `vehicle_id` is resolved.
CREATE INDEX IF NOT EXISTS idx_drop_suppression_open_vin_index
  ON drop_suppression (vin_index) WHERE status IN ('pending', 'processing');
-- The 45-day queue, oldest first.
CREATE INDEX IF NOT EXISTS idx_drop_suppression_status_received
  ON drop_suppression (status, received_at);
-- Deduplication when DROP re-delivers a request for a consumer already seen.
CREATE INDEX IF NOT EXISTS idx_drop_suppression_subject
  ON drop_suppression (subject_hash);

-- ===================================================================================
-- ERASURE ROUTINE — ordered, cascading, and provably total
-- ===================================================================================
--
-- SQLite has no stored procedures, so this is a statement sequence rather than a callable. It
-- is written to be run as ONE D1 batch, which D1 executes as a single transaction: a partial
-- erasure that left the salt in place while removing the grants would be the worst of both
-- outcomes, since the linkage key would survive with nothing to justify keeping it.
--
--   const stmts = [ ... ].map((sql) => env.DB.prepare(sql).bind(vehicleId))
--   await env.DB.batch(stmts)
--
-- WHY THIS EXISTS AT ALL WHEN EVERY FOREIGN KEY ALREADY SAYS `ON DELETE CASCADE`:
-- because the cascade is only as complete as the last person to add a table remembered to
-- make it. A table added without an FK — a cache, a metrics rollup, a "temporary" export —
-- survives `DELETE FROM vehicle_enrolment` silently, and nothing fails. This routine is the
-- checklist that a reviewer reads and the conformance suite asserts against: if a table
-- exists in this schema and is not named below, that is a finding. The cascade is the
-- mechanism; this list is the specification.
--
-- ORDER IS LOAD-BEARING. Two rules:
--   1. Children before parents, so no statement depends on FK cascade order.
--   2. THE SALT GOES SECOND-TO-LAST, immediately before the enrolment. If the batch fails
--      after the salt is gone, everything remaining is already unlinkable; if it failed
--      before, a retry still has the linkage intact and can be re-run. The failure mode is
--      therefore "erased too much" rather than "erased the evidence and kept the key".
--
-- THE ONE IRREVERSIBLE STATEMENT is step 9:
--
--     DELETE FROM pseudonym_salt WHERE vehicle_id = ?1;
--
-- Everything above it removes records. That statement removes the KEY, and with it any
-- possibility — for the broker, for a counterparty, for a party holding an anchored
-- commitment and a candidate VIN, for a subpoena — of linking a pseudonym to a vehicle or two
-- pseudonyms to each other. It is the difference between deleting the database and making the
-- data unrecoverable, and it is why §9.5 erasure is real here rather than nominal.
--
-- ?1 = vehicle_id throughout.
--
--   -- 1. audit rows. First, because an audit row referencing a deleted grant is the easiest
--   --    thing to leave behind and the hardest to notice.
--   DELETE FROM audit_log            WHERE vehicle_id = ?1;
--
--   -- 2. revocations for this vehicle's grants — before the grants, because the FK points
--   --    that way and because a revocation without its grant is an accusation with no
--   --    subject.
--   DELETE FROM revocation
--     WHERE grant_id IN (SELECT grant_id FROM consent_grant WHERE vehicle_id = ?1)
--        OR cascaded_from IN (SELECT grant_id FROM consent_grant WHERE vehicle_id = ?1);
--
--   -- 2b. kill switches naming this vehicle's owner revocation keys. BEFORE the grants and
--   --     before `owner_revocation_key`, so the FK never has to cascade mid-batch. A row
--   --     here binds an owner key to a vehicle and an instant, which is subject data.
--   DELETE FROM revocation_kill_switch WHERE vehicle_id = ?1;
--
--   -- 3. delegation edges, both directions. Matching on either endpoint catches an edge
--   --    whose other end belongs to a different vehicle, which should be impossible (a
--   --    sub-grant inherits its parent's pseudonym and vehicle) and is therefore exactly the
--   --    kind of thing to sweep rather than assume.
--   DELETE FROM delegation_edge
--     WHERE child_grant_id  IN (SELECT grant_id FROM consent_grant WHERE vehicle_id = ?1)
--        OR parent_grant_id IN (SELECT grant_id FROM consent_grant WHERE vehicle_id = ?1);
--
--   -- 4. delegated grants before their roots, so the self-referential FK never has to
--   --    cascade during the batch.
--   DELETE FROM consent_grant WHERE vehicle_id = ?1 AND parent_grant_id IS NOT NULL;
--
--   -- 5. root grants. After this statement the payloads are gone: no field set, no purpose,
--   --    no counterparty key, no signature.
--   DELETE FROM consent_grant WHERE vehicle_id = ?1;
--
--   -- 6. the broker's custodial signing keys for this vehicle. Wrapped or not, key material
--   --    for an erased subject is retained data.
--   DELETE FROM owner_signing_key WHERE vehicle_id = ?1;
--
--   -- 7. the operator-held key inventory for this vehicle, or it becomes a list of
--   --    thumbprints for keys that no longer exist — and a thumbprint is a persistent
--   --    identifier for the (vehicle, audience) pair it was minted for.
--   DELETE FROM operator_held_key_id WHERE vehicle_id = ?1;
--
--   -- 8. the owner's registered revocation public keys.
--   DELETE FROM owner_revocation_key WHERE vehicle_id = ?1;
--
--   -- 9. THE SALT. IRREVERSIBLE. See above.
--   DELETE FROM pseudonym_salt WHERE vehicle_id = ?1;
--
--   -- 10. per-vehicle resolution override, keyed by the blind index rather than the
--   --     vehicle_id, so it is easy to miss and is named explicitly here.
--   DELETE FROM resolution_delegation
--     WHERE vin_index IN (SELECT vin_index FROM vehicle_enrolment WHERE vehicle_id = ?1);
--
--   -- 11. the enrolment root. The blind index dies with it, so a future presentation of the
--   --     same VIN matches nothing and enrols fresh with a new salt — unlinkable to anything
--   --     that came before, which is the correct outcome and not a bug.
--   DELETE FROM vehicle_enrolment WHERE vehicle_id = ?1;
--
--   -- 12. finally, close the DROP request. NOT a delete: the request row survives with
--   --     `vehicle_id` set to NULL by its ON DELETE SET NULL, retaining only a hash, a
--   --     timestamp and counts. That is what substantiates compliance without retaining the
--   --     data whose deletion is being substantiated.
--   UPDATE drop_suppression
--      SET status = 'completed', processed_at = ?2, erased_counts_json = ?3
--    WHERE vehicle_id = ?1 AND status IN ('pending', 'processing');
--
-- NOT ERASED BY THIS ROUTINE, and each absence is deliberate:
--   * request_nonce — keyed by requester key id, never by subject; swept on its own TTL.
--   * requester / requester_key — business parties, not subjects. A separate routine, and
--     deleting a requester does not delete the grants issued to it (their authority is
--     bounded by expiry, which is the point of the 45-day cap).
--   * resolution_zone — WMI-scoped, no subject data, shared by every vehicle of a make.
--   * nf3_resolution_cache — AND THIS ONE IS AN HONEST LIMITATION RATHER THAN A CLEAN
--     ABSENCE, so it is written out in full. The row is keyed by the qname digest, which is
--     SHA-256 over the VIN — and this broker deliberately does not retain the VIN, so the
--     routine above CANNOT COMPUTE THE KEY and cannot locate the row. Three things bound
--     what that leaves behind: the row contains no account id, no vehicle_id and no
--     requester, so it links to nothing the routine destroyed; it expires within an hour at
--     the NF-3 positive ceiling and is swept by `sweepResolutionCache`; and when the VIN IS
--     in hand — which it is at the moment a consumer submits an erasure request naming their
--     vehicle — `purgeResolutionCache(vin, env)` removes it from both tiers immediately.
--     Call it there. The design tension is real: the same data minimisation that keeps the
--     VIN out of D1 is what stops a VIN-less routine from finding a VIN-keyed row.
--   * The kill switch is NOT in this list — see step 2b. A `revocation_kill_switch` row whose
--     `vehicle_id` never resolved (an owner key this broker does not know) is unreachable by
--     the routine for the same structural reason, and is swept by retention on `recorded_at`.
--
-- VERIFY TOTALITY, against a real database, before believing any of the above:
--   SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';
-- Every name returned must appear either in the routine or in the "not erased" list with a
-- reason. A new name in neither is an erasure defect.
