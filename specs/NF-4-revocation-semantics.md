# NF-4 — Revocation Semantics, Revocation State and Cascade

    Document:    NF-4
    Title:       Revocation Semantics, Revocation State and Cascade
    Status:      Draft Standard
    Version:     1.0.0-draft
    Date:        2026-07
    Series:      Nimbus Foundation Specifications (NF-1 … NF-5)
    Derives from: NF-WP-1, "The Consent-Governed Catallaxy" (July 2026),
                  §8.4 (this document), §9.5 (mutable storage, Delete Act),
                  §10.1 (the three refusals), §12.7 (correlation), §14 (stack)
    Requires:    NF-1 (layer model, conformance vocabulary), NF-2 (Consent Grant)
    Supersedes:  no prior NF-series document

## Abstract

NF-4 defines what it means for a Consent Grant to be revoked: who may revoke, what a
revocation record is, how revocation propagates to every cached authorization decision
and every delegated descendant, how long a cached decision may be trusted, and how
revocation state is committed to an immutable ledger without placing personal
information on one.

NF-4 is the document that makes the word "revocable" in NF-2 mean something. An
owner-revocable capability whose revocation is slow, refusable, censorable, or
unverifiable is not revocable; it is a promise. This document specifies the mechanisms
that turn the promise into a property, and it specifies them conservatively, because
every one of them is a mechanism the owner cannot inspect and must nevertheless rely on.

Two constraints shape everything here. First, revocation state is **the one thing in
this architecture that may be committed to an immutable ledger** (NF-1 §4, boundary B3;
NF-WP-1 §9.5) — because revocation must be real, and a revocation an operator can
quietly undo is not real. Second, the payload that revocation governs must live in
mutable, deletable storage, because a 45-day Delete Act cadence and CCPA erasure rights
cannot be reconciled with immutability. NF-4 therefore has to hold a commitment scheme
and an erasure regime in the same hand, and §7.6 does the privacy analysis that
justifies the pairing rather than asserting it.

---

## 1. Introduction

### 1.1 Scope

This document is normative for:

- the Revocation Record object, its closed key set and its signature (§3);
- who may authorize a revocation, and the operator's inability either to issue one or to
  refuse one (§4);
- the revocation state machine, cascade along delegation edges, idempotency,
  cycle-safety, and total per-vehicle revocation (§5);
- the staleness bound on a cached authorization decision, its default value, and the
  requirement that an expired decision be treated as unknown rather than as allowed (§6);
- the on-chain revocation-state commitment, its inclusion and non-membership proofs, and
  precisely what an observer can and cannot derive from it (§7);
- the distinction between REVOCATION and DELETION, and the ordering constraint between
  them (§8);
- the NF-4 Revocation Reason Code registry (§11.4) required by NF-1 §9.2.

### 1.2 What this document is not

NF-4 does not define the grant object; that is NF-2. It does not define index resolution
or authorization-endpoint discovery; that is NF-3, which is RESERVED and unwritten, and
NF-4 MUST NOT be read as supplying any part of it.

NF-4 defines no price, no fee, no settlement, no token and no transfer. Revocation is
free (A-14). A charge to withdraw consent is a charge for the exercise of a right, and
the Settlement Credit was cut in any case (NF-WP-1 §9.7); Layer 5 is gated out of V1
(NF-1 §8).

NF-4 does not specify which ledger. It specifies what may be committed, in what form,
and what the system must continue to do when the ledger is unreachable (C-16).

### 1.3 Relationship to NF-2

NF-2 `verifyGrant()` returns `{ valid, reasons }` and states loudly that it does not know
revocation state. That is correct and it is also a trap: `valid: true` is *not* an
authorization decision, and the boolean channel NF-2 offers (`opts.revoked`) cannot
distinguish "checked, not revoked" from "not checked" — both present as a grant that
verifies. NF-4 closes the trap by defining a four-part authorization predicate (F-6) in
which a verified grant is one of four required inputs, and by forbidding any caller from
treating an NF-2 verdict as permission to serve data (F-7).

### 1.4 Implementation status

At the time of writing, `broker/src/nf4-revocation.js` does not exist. §11 specifies the
module surface normatively so that the implementation and this document cannot diverge by
accident; where §11 names a JavaScript identifier, that name is REQUIRED. Appendix B
records the gap and what has and has not been verified against running code.

---

## 2. Conformance

### 2.1 Requirements notation

BCP 14 (RFC 2119, RFC 8174) applies, together with the two NF-series conventions in NF-1
§2.1: **MUST NOT is not waivable by agreement**, and **SHOULD means an implementer who
deviates must be able to say why**.

One convention is specific to this document.

**Fail closed means over-revoke, not under-serve.** Elsewhere in the NF series, failing
closed means denying. In revocation processing it means the same denial reached from the
other direction: when the cascade walker cannot establish the shape of a subtree, it
revokes the whole subtree; when a freshness check cannot be completed, the decision
becomes UNKNOWN and access is denied. An implementation that resolves an ambiguity by
leaving authority in place has not failed closed, however defensible the ambiguity.

### 2.2 Conformance targets

NF-4 binds four of the NF-1 §2.2 roles:

| Role | NF-4 obligations |
|---|---|
| `owner-agent` | Holds the revocation key(s). Builds and signs Revocation Records. MUST NOT depend on the broker for the ability to revoke (A-9). |
| `broker` | Accepts, verifies, applies, cascades, commits and receipts records. MUST NOT be able to issue (A-6) or refuse (A-8) one. |
| `verifier` | Evaluates the four-part predicate (F-6). Honours a directly presented record (A-11). |
| `counterparty` | Ceases use on revocation. MAY demand the opening of any revocation asserted against it (C-12). |

A deployment claiming NF-4 conformance MUST pass the assertions in §11.5.

---

## 3. Objects

### 3.1 The Revocation Record

A Revocation Record is a signed, self-authenticating statement by an owner that a
described set of grants no longer carries authority. It is the only object in this
architecture that ends authority.

    v                      string   REQUIRED. "nf4-revocation/1". Signed, so it cannot be
                                    downgraded, and it pins the signature suite. There is
                                    no `alg` field, for the reason NF-2 gives: in-band
                                    algorithm negotiation is the JWT `alg` bug class.

    revocation_id          string   REQUIRED. 16 random bytes, base64url (22 chars).
                                    Random, not sequential: a counter over an owner's
                                    revocations leaks how often that owner changes their
                                    mind, which is behavioural information about a person.

    scope                  string   REQUIRED. Exactly one of "grant", "lineage",
                                    "vehicle". See §5.4. The enumeration is closed; an
                                    unrecognised scope is a rejected record, never a
                                    narrower one.

    grant_commitment       string   REQUIRED, and non-null if and only if scope ==
                                    "grant". The NF-2 `deriveGrantCommitment()` output,
                                    base64url (43 chars). Commitment, not grant_id: the
                                    commitment covers `expires_at`, the field set and the
                                    signature, so a revocation naming a commitment cannot
                                    be satisfied by producing a differently-scoped object
                                    under the same id.

    revocation_key_id      string   REQUIRED. base64url (43 chars) thumbprint of the key
                                    being exercised, computed by the NF-2
                                    `revocationKeyIdFromPublicKey()` construction. For
                                    scope "grant" and "lineage" it MUST equal the target
                                    grant's `revocation_key_id`. For scope "vehicle" it is
                                    the vehicle Revocation Root key id (§3.2), which by
                                    construction appears in no grant.

    revocation_public_key  string   REQUIRED. The raw Ed25519 public key, base64url (43
                                    chars), whose thumbprint is `revocation_key_id`. It
                                    must be here because NF-2 deliberately keeps keys out
                                    of grants: the grant carries only the id, so the
                                    verifier needs the key from the record and recomputes
                                    the thumbprint to bind the two (A-3). It MUST NOT be
                                    disclosed to counterparties (A-13) and MUST NOT be
                                    committed on-chain (C-4).

    enrolment_id           string   REQUIRED, and non-null if and only if scope ==
                                    "vehicle". 16 bytes, base64url (22 chars). An opaque
                                    broker-assigned per-vehicle handle that lives only in
                                    D1, appears in no grant, and is destroyed by erasure.
                                    It is not derived from the VIN.

    declared_at            integer  REQUIRED. Unix SECONDS, the owner's clock. Subject to
                                    the NF-2 plausible-time window
                                    [MIN_PLAUSIBLE_TIME_S, MAX_PLAUSIBLE_TIME_S], which
                                    is what catches a millisecond timestamp.

    reason_code            string   REQUIRED as a key, MAY be null. One identifier from
                                    the NF-4 Revocation Reason Code registry (§11.4).
                                    Closed vocabulary, never free text (A-12). Metadata
                                    only: no verifier behaviour depends on it, and it is
                                    destroyed by erasure (D-8).

    signature              string   REQUIRED. Ed25519, base64url (86 chars), over the
                                    RFC 8785 (JCS) canonicalization of the record with
                                    `signature` removed, UTF-8 encoded. null on an
                                    unsigned record. No external domain tag: the type
                                    binding is the signed `v` field, exactly as in NF-2
                                    `grantSigningInput()`.

- R4-1. The top-level key set is CLOSED and every key is ALWAYS PRESENT, with explicit
  `null` where it does not apply. Unknown keys MUST cause rejection; omitted keys MUST
  cause rejection. This is NF-2's rule and it is load-bearing for the same reason:
  absence and explicit null canonicalise to different bytes, so permitting both would
  give one semantic record two commitments, and the on-chain leaf is keyed by a
  commitment (§7.3). A second canonical form is a second leaf, and a second leaf is a
  revocation an auditor cannot match to the one the owner made.

- R4-2. The following keys MUST NOT appear in a Revocation Record. Each is an operation
  this document refuses to have:

      cascade, cascade_depth, descendants_only, no_cascade
          A revocation that does not cascade would leave a delegate holding authority
          the owner just withdrew from its source. Cascade is unconditional (S-6); a
          field that must always be `true` is a field an attacker will set to `false`
          and some future implementation will honour.

      effective_at, not_before
          A future-dated revocation is an authority extension written in the vocabulary
          of withdrawal. Revocation takes effect on receipt (S-9).

      expires_at, valid_until, ttl
          A revocation that expires is not a revocation. Reinstatement is a new grant
          (S-3).

      reason, reason_text, note, comment
          Free text authored by an owner about their own vehicle is unbounded personal
          information in an object the broker stores and may commit against. The closed
          `reason_code` registry carries everything a conformance suite or an auditor
          needs.

      revoked_by, operator_id, broker_signature, on_behalf_of
          There is no operator-authored revocation (A-6). A field naming the party that
          revoked, other than by the key that signed, invites one.

- R4-3. A record is valid only if the Ed25519 signature verifies under
  `revocation_public_key` AND the NF-2 thumbprint of `revocation_public_key` equals
  `revocation_key_id`. Both checks are REQUIRED; the second is what binds the record to a
  grant, since the grant carries only the id.

- R4-4. `verifyRevocationRecord()` MUST NOT throw. It MUST collect every failure, and it
  MUST emit the stable codes of §11.4. NF-1 R-4 applies: a verifier returning a single
  opaque failure is untestable.

### 3.2 The Revocation Authority Binding

Total per-vehicle revocation (§5.4) needs one key with authority over several lineages,
and §4.4 forbids that key from appearing in any grant. The binding is how the broker
learns that a Revocation Root key speaks for a lineage key.

    v                          string  REQUIRED. "nf4-authority-binding/1".
    enrolment_id               string  REQUIRED. The vehicle handle (§3.1).
    lineage_revocation_key_id  string  REQUIRED. The id that appears in grants.
    root_revocation_key_id     string  REQUIRED. Thumbprint of the root public key.
    root_public_key            string  REQUIRED. Raw Ed25519, base64url.
    created_at                 integer REQUIRED. Unix seconds.
    signature                  string  REQUIRED. Ed25519 by the ROOT key over
                                       JCS(binding sans signature).

- R4-5. Bindings are deposited by the `owner-agent` at enrolment and whenever a new
  lineage key is first used. They live in D1 only. A binding MUST NOT be committed
  on-chain: it relates two long-lived owner-held key ids, and §7.7 prohibits committing
  any stable identifier.

- R4-6. A missing or unverifiable binding MUST NOT be grounds to reject a `lineage`- or
  `grant`-scoped record. Bindings gate only `vehicle` scope. The broker holds the
  bindings, so making them a precondition for any other scope would hand the broker a
  veto over revocation by the simple expedient of losing a row (SEC-1).

### 3.3 The Revocation Receipt

- R4-7. On accepting a record the broker MUST return a receipt, synchronously, after the
  state transition is durable and before any notification is dispatched:

      v              "nf4-receipt/1"
      revocation_id  the record's id
      record_digest  deriveRevocationCommitment(record)  (§7.3)
      accepted_at    Unix seconds, broker clock
      state_seq      the monotonic sequence number at which the record was applied
      anchor_epoch   the commitment epoch that will contain it (§7.4)
      signature      Ed25519 by the broker's published receipt key

  The receipt is the owner's evidence. Its only purpose is to make omission provable: a
  receipted record that never appears under the anchored root of `anchor_epoch` is a
  broker equivocation any third party can verify (SEC-1). A broker that declines to
  receipt has refused the revocation (A-8).

### 3.4 The Revocation State Head

- R4-8. The broker MUST publish, and refresh at least every `MAX_DECISION_STALENESS_S`
  (§6), a signed head:

      v            "nf4-head/1"
      state_seq    monotonic, incremented once per applied record
      root         the current sparse Merkle root (§7.2), base64url
      leaf_count   number of non-empty leaves
      as_of        Unix seconds
      anchor       { epoch, root } of the most recently anchored commitment
      signature    Ed25519 by the broker's published head key

- R4-9. `state_seq` MUST be strictly monotonic and MUST NOT be reused. Two heads with the
  same `state_seq` and different `root` values are a signed confession of equivocation.
  This is the property that lets an enforcement point trust a head instead of the ledger
  on the hot path (§7.4).

---

## 4. Authorisation of revocation

### 4.1 The owner key, and nothing else

- A-1. The ONLY input that may cause a grant to become revoked is a Revocation Record
  valid under §3.1 whose `revocation_key_id` has authority over the target (A-2). No
  other input — not an operator action, not a support ticket, not a database migration,
  not a Foundation instruction — is a revocation.

- A-2. Authority is established as follows and in no other way:

  - scope `grant`: `record.revocation_key_id` == the target grant's
    `revocation_key_id`.
  - scope `lineage`: same equality, applied to every grant carrying that id.
  - scope `vehicle`: a verified Authority Binding (§3.2) exists linking
    `record.revocation_key_id` as root to each lineage key id being revoked, under the
    named `enrolment_id`.

- A-3. The verifier MUST recompute the NF-2 thumbprint of `revocation_public_key` and
  compare it to `revocation_key_id`, and MUST reject on mismatch. Accepting the id as
  presented would let anyone claim any authority by writing a different number in a field.

- A-4. The verifier MUST apply NF-2's own refusal: a record whose
  `revocation_public_key` is, or whose thumbprint matches, the target grant's
  `counterparty_key` MUST be rejected with `revocation_key_held_by_counterparty`. NF-2
  already refuses to issue such a grant; NF-4 refuses to honour the resulting record, so
  the invariant does not depend on which module saw the object first.

- A-5. A record whose `revocation_key_id` appears on the deployment's list of
  operator-held key ids MUST be rejected (`revocation_key_forbidden`), mirroring NF-2
  `opts.forbiddenRevocationKeyIds`. Refusal 3 is tested here, not asserted: the broker
  supplies the ids it operates, and the check fires against them.

### 4.2 The broker cannot revoke

- A-6. There MUST be no broker-signed revocation, no operator scope, and no
  administrative path that transitions a grant to `revoked`. The state machine (§5.1) has
  exactly one authorized input, and it is owner-signed.

- A-7. An operator MAY need to stop serving a counterparty for its own reasons — abuse,
  a lawful order, a terminated subscription, an integrity failure. Such a stop is a
  distinct state, `suspended`, and it:

  1. MUST NOT be called revocation in any interface, log, notification or export;
  2. MUST NOT produce a leaf in the revocation tree (§7.3);
  3. MUST NOT be reported to the owner as a revocation, and MUST be distinguishable by
     the owner from one;
  4. MAY be reversed by the operator, which is precisely what a revocation may not be
     (S-3).

  Conflating the two is how "the owner can revoke" becomes "the operator decides who
  gets served, and sometimes the owner asks". The states have opposite ownership and
  opposite reversibility, and one word for both would hide that. Note the asymmetry that
  makes this safe: `suspended` can only deny. There is no operator state that grants.

### 4.3 The broker cannot refuse

- A-8. On receiving a syntactically well-formed record the broker MUST verify it and, if
  valid, MUST apply it and MUST return a receipt. The following are each a refusal and
  each MUST NOT be required or performed:

  1. **Authentication of the submitter.** The signature is the authorization. A record
     MUST be accepted over an unauthenticated channel, from any submitter, including one
     with no account. Requiring a login to revoke means that losing an account, a phone,
     or a password means losing the ability to withdraw consent — the failure mode
     revocation exists to survive.
  2. **A reason.** `reason_code` MAY be null and a null MUST NOT affect processing.
  3. **A notice period, cooling-off window, dispute process, confirmation step, or
     counterparty consultation.** Revocation is unilateral and immediate (S-9).
  4. **A payment, subscription, tier, or account standing** of any kind (A-14).
  5. **Rate limiting of the first revocation of any target.** A limiter MAY protect
     against resource exhaustion by duplicate submissions, and MUST be structured so
     that the first valid record for a given target is never delayed by it. Since
     re-application is a no-op (S-7), a limiter can shed duplicates safely.
  6. **A live grant.** A record naming an unknown, expired, or already-revoked target
     MUST be accepted and receipted (S-7). The response MUST be identical in content and
     substantially identical in timing across those cases, so the endpoint is not an
     oracle for grant existence (SEC-6).

- A-9. The owner's ability to revoke MUST NOT depend on any broker-held state other than
  the record itself. In particular the revocation key has no expiry, no renewal, and no
  registration requirement beyond the grant that already names its thumbprint.

- A-10. Any party MAY relay a record. Records are not secret and their disclosure harms
  no one: the only thing a record does is remove authority.

- A-11. **Records are self-authenticating.** A `verifier` presented with a valid record
  for a grant it is evaluating MUST treat that grant as revoked, whether or not the
  broker's state says so, and whether or not the broker is reachable. This is the
  provision that makes censorship survivable: the worst a broker can do by suppressing a
  record is fail to propagate it, and the owner can propagate it themselves — to the
  counterparty, to a regulator, to anyone.

- A-12. `reason_code` MUST come from the closed registry (§11.4) and MUST NOT be
  free text. A broker MUST NOT reject a record for a reason code it does not recognise;
  it MUST apply the record and record the code verbatim. An unrecognised *reason* is not
  an unrecognised *revocation*.

- A-13. `revocation_public_key` MUST NOT be included in a revocation notification to a
  counterparty. The counterparty receives the `grant_commitment` and, on demand, the
  proof (§7.5) and the record's opening (C-12) — never the key. If one revocation key
  served two counterparty classes, disclosing it would let those two counterparties join
  on it and undo the per-audience pseudonym (§4.4, NF-WP-1 §12.7).

- A-14. Revocation MUST be free. No fee, no gas pass-through, no metered anchoring cost,
  no per-record charge, and no tier in which revocation is faster. A cost to withdraw
  consent is a cost imposed at the moment of least bargaining power, and a
  faster-for-payers revocation path is preferential access, which the Foundation may not
  operate (NF-1 §7).

### 4.4 Key structure: one revocation key per lineage

- A-15. An `owner-agent` MUST use a distinct revocation key per
  (vehicle, `counterparty_class`) pair, and MUST NOT reuse one revocation key across
  counterparty classes for the same vehicle.

  This is a requirement NF-2 does not currently state, and its absence is a gap in the
  spine (Appendix B, finding 1). The argument is exactly the argument NF-2 makes for
  keeping the owner's *signing* key out of the grant. Two counterparties in different
  classes holding grants over one vehicle receive different pseudonyms, because the
  pseudonym is a per-audience HMAC — that is the whole point of the construction. But
  both grants carry `revocation_key_id` in the clear, and if the owner used one
  revocation key for the vehicle, that id is identical in both. The two counterparties
  then hold a shared, stable, vehicle-scoped join key, and the per-audience pseudonym
  buys nothing. A field placed in the grant to make revocation possible would have
  reintroduced the correlation NF-2 spent its schema design avoiding.

- A-16. Delegated sub-grants inherit `revocation_key_id` from their parent, per NF-2
  `mintDelegatedGrant()`. This is correct and MUST be preserved. It is also what makes
  lineage-scoped revocation cascade-free (S-8): every descendant already carries the
  lineage id, so revoking the lineage reaches the whole forest with one indexed write and
  no tree walk. The correlation exposure is bounded to parties within one lineage, all of
  whom already know each other — a delegate knows its delegator by construction.

- A-17. Revocation authority MUST be 1-of-n, never m-of-n. An `owner-agent` SHOULD
  register more than one revocation key per lineage (via §3.2 bindings for the root, and
  by naming a lineage key in the grant), and ANY one of them MUST suffice.

  Thresholds are a control on *granting* authority, where a single compromised key
  causes disclosure. Revocation only ever removes authority, so requiring a quorum to
  revoke converts a lost key into standing authorization — it protects the counterparty
  against the owner. The compromise of a revocation key costs availability, not
  confidentiality (SEC-8), and availability is the correct thing to trade here.

- A-18. If every revocation key for a lineage is lost, the remaining bound on exposure is
  the grant's `expires_at`, which NF-2 caps at 45 days. There MUST NOT be an
  identity-proofed broker-side recovery path, because a broker that can revoke on proof
  of identity is a broker that can revoke (A-6), and the same mechanism run by a
  compromised or coerced operator is an unauthorized revocation. The ≤45-day worst case
  is the documented price of that refusal, and it is the reason
  `MAX_GRANT_DURATION_S` exists.

---

## 5. Revocation state, propagation and cascade

### 5.1 States

Authoritative revocation state lives in D1, keyed by `grant_commitment` (NF-1 L3-8: all
mutable state is mutable and deletable). A grant commitment is in exactly one of:

    absent      no record. The grant is not revoked. NOT the same as authorized — see F-6.
    revoked     an owner record has been applied. Terminal.
    suspended   an operator stop (A-7). Reversible, operator-owned, not a revocation, and
                never a leaf in the tree.

`revoked` and `suspended` are independent; a grant MAY be both, and `revoked` dominates
in every decision.

- S-1. The state store MUST be keyed by `grant_commitment`, not by `grant_id`. Two objects
  sharing an id but differing in expiry, field set or signature are different grants with
  different commitments, and a revocation naming one MUST NOT be satisfiable by producing
  the other. NF-2 already guarantees one canonical form per semantic grant; S-1 is the
  half of that guarantee NF-4 has to hold up.

- S-2. State MUST be durable before the receipt is returned (R4-7) and before any
  notification is dispatched. Notifications are an accelerant, never the mechanism (S-11).

- S-3. Revocation is MONOTONE. There MUST be no un-revoke, no reinstate, no undo, no
  administrative reversal, and no expiry of a revocation. Restoring access is
  accomplished by issuing a new grant, which has a new `grant_id`, a new commitment, and
  a new consent decision behind it.

  Monotonicity is not tidiness; it is what makes the rest of this document cheap.
  Because the state lattice is a join-semilattice with `absent < revoked`, applying
  records is idempotent and commutative (S-7), out-of-order delivery is harmless,
  negative caching is safe forever (F-8), and the on-chain tree only ever grows (C-9),
  which is what makes broker omission detectable by anyone holding one old proof.

### 5.2 Propagation targets

- S-4. Applying a record MUST, before the receipt:

  1. write the `revoked` state for every target commitment resolvable at that instant;
  2. compute and durably record the cascade set (§5.3) for scope `grant`;
  3. advance `state_seq` and update the tree root (§7.2) in the same transaction as (1)
     and (2), so no head can ever be signed over a state that omits an applied record;
  4. invalidate every cached authorization decision for the affected commitments in
     every cache the deployment controls, on a best-effort basis (S-11), and
  5. abort every in-flight streaming or multi-response delivery bound to those
     commitments (F-10).

- S-5. Steps (4) and (5) are best-effort by nature — a cache in another colo may be
  unreachable, a stream may be mid-flush. Correctness MUST NOT depend on them. The
  guarantee that access actually stops is the staleness bound (§6), which requires no
  successful delivery of anything.

### 5.3 Cascade along delegation edges

- S-6. Revoking a grant MUST revoke every descendant of it. Cascade is unconditional and
  not parameterised (R4-2). A delegate holding authority derived from a grant the owner
  just withdrew is holding authority from nowhere; NF-2 justifies delegation partly on
  the ground that it cascades, so a non-cascading revocation would retroactively make
  delegation a transfer.

- S-7. Cascade MUST be idempotent and commutative. Re-applying a record, or applying two
  records whose cascade sets overlap, MUST produce byte-identical state and MUST NOT
  produce a second state transition, a second leaf, or a second `state_seq` increment for
  an already-revoked commitment. Implementations MUST achieve this with a primary key on
  `grant_commitment` and a conflict-ignoring insert (D1: `ON CONFLICT DO NOTHING`), not by
  reading first and then writing — the read-then-write form races against a concurrent
  cascade and the loser silently drops a revocation.

- S-8. Scope `lineage` requires NO walk. Every descendant inherits `revocation_key_id`
  (A-16), so a single indexed statement over that column reaches the entire forest. Scope
  `grant` is the only scope that walks.

- S-9. The walk MUST be breadth-first over the `parent_grant_id` edge, and MUST be bounded
  by all three of:

  - **Depth**: at most `target.delegation_depth` levels below the target, and never more
    than NF-2 `MAX_DELEGATION_DEPTH` (2). The budget comes from the signed grant, so it is
    the owner's declared number, not a broker parameter. A descendant discovered *beyond*
    that depth is an integrity failure: NF-2 forbids it at mint time, so its existence
    means the store has been corrupted or written around. Such a node MUST be revoked
    anyway and the condition MUST be reported (`cascade_depth_exceeded`).
  - **A visited set** keyed by `grant_commitment`. A cycle in `parent_grant_id` cannot
    arise from correctly minted grants — a child names a parent that was already signed,
    so the edges form a forest — but the walker reads D1, and a corrupted or adversarially
    written row can present one. A walker without a visited set does not merely loop; it
    loops while holding a transaction.
  - **A node budget**, exceeding which MUST fail closed: the walk aborts, and every node
    reached AND every node whose subtree was not fully explored MUST be marked `revoked`.
    Marking the unexplored frontier is the point. An abort that leaves the frontier
    untouched converts a resource limit into a revocation bypass, which is a
    denial-of-service with a privilege-escalation payload: an attacker who can inflate a
    subtree can outrun the walker and keep a descendant alive.

- S-10. A grant whose `parent_grant_id` names a commitment absent from the store MUST be
  treated as revoked. NF-2 refuses to verify such a grant at all
  (`delegation_parent_missing`), and NF-4 agrees from the other side: unverifiable
  lineage is not lineage. Note the interaction with erasure — after a vehicle's records
  are destroyed, every surviving delegated grant is an orphan by this rule, which is the
  correct outcome and is why erasure cannot be a bypass (D-5).

- S-11. Notification of affected counterparties SHOULD be dispatched asynchronously
  (Inngest, per NF-WP-1 §14) with an idempotency key of
  `(revocation_id, grant_commitment)`. Enforcement MUST NOT depend on delivery. A
  counterparty that never receives a notification still loses access at the staleness
  bound, and a counterparty that receives one twice must not see two different states.

### 5.4 Total per-vehicle revocation

An owner MUST be able to withdraw everything at once. Because A-15 requires a distinct
revocation key per lineage, "everything" spans several keys, and the specification has to
say how one owner action covers them all without reintroducing a vehicle-wide identifier
into grants.

- S-12. Scope `vehicle` names an `enrolment_id` and is signed by the vehicle Revocation
  Root key. The broker MUST resolve, via the §3.2 bindings, every lineage key id bound to
  that enrolment, and MUST apply the record to every grant carrying any of them,
  cascading per S-6.

- S-13. The root key id MUST NOT appear in any grant. That is the whole reason the
  binding object exists: a vehicle-scoped authority that appeared in grants would be
  precisely the cross-audience join key A-15 removes.

- S-14. If some bindings are missing, the broker MUST apply the record to every lineage it
  can resolve, MUST NOT reject the record, and MUST report which lineages remain
  unrevoked. Partial application is strictly better than none, and an all-or-nothing rule
  would let one missing row preserve authority across an entire vehicle.

- S-15. The `owner-agent` MUST present total revocation as a single owner action, and MUST
  additionally be able to perform it as a set of independent `lineage`-scoped records
  signed by the lineage keys, with no dependence on the broker's bindings. This second
  path is the one that survives a broker that has lost, or withheld, the bindings
  (SEC-1). One action for the owner; two independent mechanisms underneath, only one of
  which requires the operator to cooperate.

- S-16. Total revocation MUST NOT require the VIN, the pseudonym salt, or any Layer-2
  credential. It operates on key ids and an opaque enrolment handle. An owner locked out
  of their vehicle, or whose vehicle has been sold or destroyed, can still revoke.

---

## 6. Freshness: the staleness bound

### 6.1 Definition and default

**Staleness bound** — the maximum age, measured from the instant a decision was DERIVED,
for which a cached authorization decision may be used.

- F-1. `MAX_DECISION_STALENESS_S` = **60** seconds. This is the default and the
  RECOMMENDED value.

- F-2. A deployment MUST NOT use a value above `MAX_DECISION_STALENESS_CEILING_S` = **300**
  seconds. Values above 60 s are SHOULD-NOT and must be justified per NF-1 §2.1.

- F-3. The deployed value MUST be published in the owner-facing disclosure, in seconds,
  as the answer to "how long after I revoke can my data still be read?" A bound that is
  not disclosed is an undisclosed retention window.

- F-4. The bound MUST be uniform across counterparties. A longer bound for one
  counterparty is preferential access (NF-1 §7); a shorter bound for one is a service
  level sold on the owner's revocation.

**Why 60 seconds.** The bound is the honest worst case between an owner revoking and the
last enforcement point ceasing to serve, so it is a number that must be defensible to the
owner, not merely to the operator.

The floor is set by architecture, not by preference. Enforcement happens in Cloudflare
Workers across many colos; D1 reads from a non-primary region carry replication lag and
cross-region latency, and Layer-4 delivery includes long-running work that cannot consult
the store per byte. A bound near zero would mean a synchronous authoritative read on
every request from every colo, which does not merely cost latency — under load it makes
the revocation store the availability bottleneck for the entire read path, and a store
that is down while decisions must still be made is precisely the condition that produces
a fail-open shortcut in some future patch. Choosing a bound the architecture can actually
honour is what keeps the fail-closed rule (F-7) enforceable.

The ceiling is set by exposure. Vehicle telematics polling operates on cadences of
roughly a second to a minute; a bound of 60 s therefore admits on the order of one
additional sample or aggregation window past the owner's revocation, which is a
defensible worst case to state plainly in a disclosure. At 300 s it is several, and past
that the sentence "access stops when you revoke" stops being true in any ordinary sense.
The value is also small enough to be irrelevant against the other clocks in the system —
five orders of magnitude below the 45-day grant cap — so it never becomes the binding
constraint on anything except its own promise (§9).

The bound is deliberately NOT derived from the on-chain anchoring interval. Coupling it to
consensus latency would put a ledger in the enforcement path, and §7.4 forbids that.

### 6.2 Stale means unknown

- F-5. A cached decision whose age exceeds the bound MUST be treated as **UNKNOWN** and
  MUST be re-derived. It MUST NOT be treated as ALLOW under any circumstance, including:
  the store being unreachable, the head being unobtainable, a degraded mode, a
  configuration flag, an operator override, or an in-progress delivery. There is no
  deployment condition in which a stale ALLOW may be served. UNKNOWN denies.

- F-6. **The authorization predicate.** A `verifier` MUST return ALLOW only if all four
  hold, each established within the bound:

  1. **Verified** — NF-2 `verifyGrant()` returns `valid: true`, with `presenterKey` bound
     to the key the presenter proved possession of in this session, and with the parent
     chain supplied for a delegated grant;
  2. **Issued** — the commitment is present in the broker's issuance index. Non-membership
     in the revocation tree proves only that the grant was never revoked; it says nothing
     about whether it was ever issued, and a well-formed self-signed grant naming a
     stranger's pseudonym is not revoked either;
  3. **Not revoked** — state `absent` for this commitment and for every ancestor in the
     chain, established against a head no older than the bound (F-9) or against an
     authoritative read;
  4. **Fresh** — the age of the oldest of the above is within the bound.

  Any of the four unestablished yields UNKNOWN, and UNKNOWN denies. The predicate is
  conjunctive and it is the entire authorization interface; there is no other way to
  reach ALLOW.

- F-7. An NF-2 verdict MUST NOT be used as an authorization decision. Callers MUST use
  the NF-4 entry point (`decideAuthorization()`, §11.1), which returns
  `'allow' | 'deny' | 'unknown'` and has no boolean form. The three-valued return is
  deliberate: NF-2's `opts.revoked` is a boolean whose absence means "not checked" and
  whose absence still permits `valid: true`, so a caller that forgets the revocation
  lookup gets an affirmative-looking result. A tri-state that must be explicitly narrowed
  cannot be forgotten into an ALLOW (Appendix B, finding 5).

### 6.3 Caching asymmetry

- F-8. DENY decisions arising from revocation MAY be cached without expiry, and SHOULD be.
  Revocation is monotone (S-3), so a `revoked` answer can never become wrong. ALLOW
  decisions MUST NOT be cached beyond the bound. This asymmetry is what makes the design
  affordable: the expensive direction to cache is the one that is safe to cache forever,
  and revocation storms are self-limiting because each revoked commitment is answered
  from cache thereafter.

- F-9. A cache entry MUST record `derived_at` and the `state_seq` of the head it was
  derived under. An enforcement point that observes a head with a higher `state_seq`
  SHOULD re-derive immediately rather than waiting for the bound; it MUST NOT extend any
  entry's life on the strength of a newer head.

- F-10. Any delivery that outlives a single response — a stream, a batch export, a
  federated-learning round, a paginated pull — MUST be modelled as a sequence of
  decisions, MUST re-derive at least every `MAX_DECISION_STALENESS_S`, and MUST terminate
  on anything other than ALLOW. It MUST be abortable by S-4(5). This is NF-1 L4-5 read
  strictly: a four-hour export authorized once, one second before revocation, is a
  four-hour leak that satisfies every other requirement in this document.

- F-11. A cache entry's lifetime MUST be measured from `derived_at` and MUST NOT be
  refreshed on access. TTL-on-access is the specific defect that makes a frequently-used
  authorization immortal: the busiest grant in the system, which is the one worth
  revoking, becomes the one revocation reaches last (SEC-3).

- F-12. A cache entry MUST be keyed to include the presenter key it was derived for, and
  MUST NOT serve a decision to any other key. Otherwise the cache silently converts a
  key-bound grant into a bearer token, defeating NF-2's counterparty binding.

---

## 7. The on-chain revocation-state commitment

### 7.1 Why this, and only this, is committed

Refusal 2 forbids personal information, or anything from which it can be derived, on an
immutable ledger (NF-WP-1 §10.1, §9.5; NF-1 boundary B3). Revocation state is the single
exception, and the exception is forced rather than convenient.

Revocation must be real. Everything in §4 constrains what the operator may do, but an
operator that controls the only record of revocation state can quietly not have revoked:
delete a row, replay an older snapshot, tell the owner yes and the counterparty nothing.
No amount of MUST NOT in a specification detects that. A commitment to an append-only,
publicly verifiable log does detect it, because the operator must either publish a state
containing the revocation or publish a state that provably omits a record it receipted
(R4-7). That converts an unauditable trust assumption into a detectable, attributable
equivocation, and it is the only mechanism in this document that constrains the operator
rather than instructing it.

- C-1. The ONLY values that may be written to a ledger are: a fixed-length state root
  (§7.2), the epoch number that root belongs to, and the NF-2 grant commitments that other
  documents already permit. Nothing else. No record, no key, no id, no pseudonym, no
  count, no timestamp of an individual revocation, no reason code, no counterparty.

- C-2. The ledger is a WITNESS, not a store and not an enforcement path (C-16). Its
  function is to make omission and reordering provable after the fact. Nothing in the
  request path reads it.

### 7.2 Construction: sparse Merkle tree over commitments

A plain Merkle tree proves what is in it. That is insufficient here: an enforcement point
needs to establish that a grant is NOT revoked, and a structure that can only prove
membership leaves "not revoked" resting on the operator's word — the exact assumption §7.1
exists to remove. The structure is therefore a sparse Merkle tree (SMT), which proves both.

- C-3. The revocation tree is an SMT of depth 256, keyed by `grant_commitment`, with the
  following construction. All hashing is SHA-256 via `crypto.subtle.digest` (NF-WP-1 §14:
  WebCrypto only, no third-party code).

      EMPTY        := 32 zero bytes
      KEY(c)       := the 32 raw bytes of the base64url-decoded grant_commitment
      LEAF(k, v)   := SHA-256( 0x00 || k[32] || v[32] )
      NODE(l, r)   := EMPTY                              if l == EMPTY and r == EMPTY
                      SHA-256( 0x01 || l[32] || r[32] )  otherwise
      ROOT         := the node at depth 0
      empty tree   := ROOT == EMPTY

  The path from the root to a key's slot is read from the key's bits most-significant-first
  over byte 0 through byte 31: at depth *i* (0 ≤ i ≤ 255), bit *i* selects the left child
  when 0 and the right child when 1. A key's slot is at depth 256.

- C-4. The leaf value is `deriveRevocationCommitment(record)`:

      SHA-256( "nf4-revocation-commitment:v1:" || JCS(record) )   → base64url

  domain-separated exactly as NF-2's `deriveGrantCommitment()` is, and covering the
  `signature`, so the value binds to the owner's actual signed record and the broker
  cannot fabricate a value it could later be asked to open (C-12). The domain string ends
  in `:` and canonical JSON begins with `{`, so the boundary needs no length prefix.

- C-5. The leaf and internal prefixes (`0x00`, `0x01`) are REQUIRED. Without domain
  separation between leaf and internal hashing, a 64-byte leaf value can be reinterpreted
  as a pair of children — the classic Merkle second-preimage confusion, and the family the
  Bitcoin CVE-2012-2459 duplicate-transaction bug belongs to. Any implementation that
  hashes leaves and nodes with the same function is non-conformant even if its roots
  happen to match on the test vectors.

- C-6. EMPTY propagation (a node with two empty children is EMPTY, not a hash of zeros) is
  REQUIRED and is what makes depth 256 affordable: every default subtree at every level is
  the same 32 zero bytes, an insertion costs at most 256 SHA-256 evaluations, and a proof
  omits every default sibling. Implementations MUST NOT substitute per-level precomputed
  default hashes; that is a different tree with different roots.

- C-7. Leaves MUST NOT be removed and values MUST NOT be overwritten. Revocation is
  monotone (S-3), so the tree is insert-only. A value of EMPTY at an occupied slot is
  therefore not representable, which is deliberate: "delete the leaf" is exactly the
  operation an operator undoing a revocation would need.

- C-8. `suspended` (A-7) MUST NOT produce a leaf. The tree is the record of what OWNERS
  did. An operator stop in the tree would be indistinguishable, to every future observer,
  from an owner's revocation, and would make the log evidence for a claim it cannot
  support.

- C-9. **Monotonicity is spot-checkable, and that is the point.** Any party holding an
  inclusion proof at epoch *E* MUST be able to obtain one for the same key at every epoch
  after *E*. A broker that cannot produce one has removed a leaf, and the two proofs
  together are a self-contained, publicly verifiable demonstration of it that requires no
  access to the broker's database. Owners SHOULD retain the proof for each revocation they
  make, and `owner-agent` implementations SHOULD fetch and store it automatically; that
  retention is what makes C-9 a real check rather than an available one.

### 7.3 What the leaf commits to, and what survives erasure

- C-10. The SMT key MUST be `grant_commitment` and MUST NOT be any structured or
  long-lived identifier. §7.6(4) gives the analysis; the short form is that a uniformly
  distributed key makes prefix locality in the tree semantically empty, and a structured
  key would make the tree's shape leak grouping.

- C-11. The record itself lives in D1 and is deletable. The tree holds only the key and the
  32-byte value. This is the pairing the abstract promises: the immutable artefact is a
  digest whose opening is mutable and destroyable, so the *fact* of revocation is
  permanent (which safety requires) while the *attributable record* of it is erasable
  (which erasure requires).

- C-12. **Openings on demand.** A counterparty against whom a revocation is asserted MUST
  be able to obtain, on request, the record that opens the leaf, together with the
  inclusion proof (§7.5) — while the record exists. A revocation asserted against a
  counterparty for which the broker cannot produce an owner-signed opening is a suspension
  mislabelled (A-7), and the broker MUST relabel it. This is the check that stops the tree
  from becoming a place to launder operator decisions as owner decisions.

- C-13. On erasure (§8) the broker MUST destroy `revocation_public_key`, `signature` and
  `reason_code` from the record and MUST retain the tombstone
  `{ grant_commitment, revoked_at_epoch }` plus the leaf. Erasure removes ATTRIBUTION;
  it MUST NOT remove ENFORCEMENT. The retained tombstone is what stops a retained copy of
  a grant from being replayed after the vehicle's records are gone (D-5), and it contains
  no owner-linked material: a commitment to a grant nobody can any longer open, and an
  epoch number.

- C-14. After erasure the opening is unobtainable, by construction, and C-12 is satisfied
  vacuously — there is no live grant left to dispute. Implementations MUST NOT retain the
  signature "for audit" past erasure; the signature is the only owner-linked value in the
  record and retaining it defeats the erasure it was supposed to survive.

### 7.4 Epochs, heads and anchoring

- C-15. The broker MUST anchor a commitment at fixed intervals of
  `COMMITMENT_EPOCH_S` = 3600 seconds, publishing `{ epoch, root }` and nothing else
  (C-1). Anchoring MUST be on a fixed schedule and MUST NOT be per-event: a per-revocation
  anchor publishes the timing of individual owners' decisions to the nearest transaction,
  which is a behavioural signal about a person, and a fixed schedule coarsens it to the
  epoch (§7.6(1)).

- C-16. **The ledger MUST NOT be in the enforcement path.** Freshness (§6) is established
  against the broker's signed head (§3.4), not against an anchored root. A system that
  read the ledger to authorize would inherit its latency (up to one hour of staleness,
  sixty times the bound), its availability, and — if that ledger charged for reads or
  writes — a per-decision cost, which is how a consent layer acquires a toll booth. The
  system MUST remain fully correct and fully operational with the ledger unreachable for
  an arbitrary period; what degrades is public auditability, and the broker MUST report
  the degradation (`anchor_overdue`) rather than continuing silently.

- C-17. The heads of §3.4 carry the same root between anchors, signed and sequenced. The
  hourly anchor is what makes those heads non-repudiable in retrospect: a head whose root
  never appears in the anchored history, or two heads sharing a `state_seq` with different
  roots, are each a provable equivocation (R4-9). So the fast path is authenticated by a
  broker signature and the slow path removes the need to trust that signature over time.

- C-18. Anchoring costs MUST NOT be passed through per revocation (A-14). An epoch's
  anchor is a single fixed-size write regardless of how many revocations it covers, which
  is also why the scheme scales to any revocation volume at constant ledger cost.

- C-19. The ledger requirement is a capability, not a product: an append-only, publicly
  readable, tamper-evident log with availability independent of the broker. NF-4 selects
  none. A ledger choice MUST NOT introduce a token, a fee to owners, gas-metered access,
  or governance rights over the log's contents (NF-1 §8, NF-WP-1 §9.7); the log stores
  32-byte roots and confers nothing.

### 7.5 Proofs

- C-20. A proof is:

      v        "nf4-smt-proof/1"
      epoch    the epoch whose root this proves against
      root     base64url, 32 bytes
      key      the grant_commitment, base64url
      value    base64url leaf value, or null for a non-membership proof
      siblings array of base64url non-empty siblings, ordered TOP-DOWN
      bitmap   base64url 32 bytes; bit i (MSB-first) is 1 iff the sibling at depth i
               is non-empty

- C-21. Verification MUST be:

      cur := (value == null) ? EMPTY : LEAF(KEY(key), decode(value))
      for i := 255 down to 0:
          sib := bitmap_bit(i) ? siblings.pop() : EMPTY
          cur := (key_bit(i) == 0) ? NODE(cur, sib) : NODE(sib, cur)
      accept iff cur == root and siblings is empty

  The residual-siblings check is REQUIRED: a proof carrying unconsumed siblings is
  malformed, and accepting it means the bitmap and the array disagreed about the path.

- C-22. A **non-membership proof** (`value == null`) establishes that the key's slot is
  empty under `root`, i.e. that the grant was never revoked as of that epoch. It MUST NOT
  be treated as evidence of authorization: it says nothing about issuance, expiry,
  signature validity, or the presenter. F-6 requires all four inputs; C-22 supplies
  exactly one of them.

- C-23. A `verifier` that consumes proofs MUST validate the proof against a root it
  obtained independently of the party supplying the proof — an anchored root, or a head
  whose signature it checked. A proof verified against a root supplied alongside it proves
  only internal consistency, which any party can manufacture.

### 7.6 What an observer can and cannot derive

Refusal 2 turns on this analysis, so it is stated as an enumeration of what each class of
observer actually learns, including the residual leaks. Asserting privacy here would be
worthless; the claim has to be checkable.

**Observer A — the public, holding only ledger data (roots and epoch numbers).**

Learns:

1. That the system exists and that its revocation state changed between two epochs, if
   the root changed. Because anchoring is fixed-interval (C-15) and the leaf count is not
   published on-chain (C-1), the observable is one bit per epoch — *something* was revoked
   in that hour — and not a volume.

   This bit is a genuine residual leak and is stated rather than dismissed. At scale it is
   a business metric with no subject. In a small early deployment, an observer who
   independently knows that a specific owner revoked at approximately a given time can
   confirm that an hour-long window contains a revocation. That confirmation yields no
   identifier, no vehicle, no field, no counterparty and no person; it converts prior
   knowledge into slightly more confident prior knowledge. The mitigation available —
   publishing a root every epoch whether or not anything changed — is RECOMMENDED, and
   reduces the leak to nothing at the cost of a constant write rate.

Cannot learn, and this is what the construction buys: any vehicle, VIN, pseudonym, owner,
counterparty, class, field, purpose, reason, key, count, or per-revocation timestamp. The
root is a hash of hashes over keys that are themselves SHA-256 outputs of high-entropy
inputs. There is no query an observer can pose to the ledger about a subject they do not
already hold a grant for, and no dictionary they can build (see (3) below).

**Observer B — a party holding a copy of a grant.**

Learns: whether that grant is revoked, as of each epoch, and hence the epoch in which it
was revoked. This is intentional. It is the same capability that makes the operator
honest, and it is the reason a counterparty cannot claim it was never told, and a
regulator can check the system without the operator's cooperation.

2. **This is a deliberate trade and it is worth naming.** The alternative — blinding each
   leaf with a broker-held nonce — would hide revocation timing from a party that already
   holds the grant, and would simultaneously hand the broker the ability to produce an
   unopenable leaf, or to claim any leaf opens to any record. Non-repudiation by the
   operator is worth more than hiding a timestamp from a party that was a counterparty to
   the very grant in question. Blinding is therefore forbidden (C-25).

3. **Brute force is infeasible, and this is what distinguishes the scheme from a Refusal-2
   violation.** The SMT key is `deriveGrantCommitment(grant)`, whose preimage contains a
   128-bit random `grant_id` and a 64-byte Ed25519 signature over the whole payload. An
   adversary who knows the make, model, year, owner and counterparty of a vehicle still
   cannot construct a candidate grant object that hashes to the right key, because they
   cannot produce the signature and cannot guess the id. The commitment is a high-entropy
   commitment, not a hash of a low-entropy identifier.

   Contrast the constructions this rules out. `SHA-256(VIN)` has a realistic search space
   on the order of 10^8 once make, model and year are known (vin.js states this) — it is a
   rainbow table, and committing it would place a directly re-identifiable value on an
   immutable ledger. That is why C-24 forbids committing any value whose preimage space is
   enumerable, and why the prohibition is a schema rule rather than a review note.

4. **What a proof leaks about other keys, and why it is nothing.** An SMT proof discloses
   the digests and positions of the non-empty siblings along one path — roughly log₂(N) of
   them. An observer therefore learns that other occupied subtrees exist sharing a prefix
   of some length with their own key, and learns those subtrees' root digests.

   Because keys are `grant_commitment` values, i.e. SHA-256 outputs, they are uniformly
   distributed and statistically independent of every attribute of the grant. A shared
   prefix is therefore not evidence that a neighbouring leaf concerns the same vehicle,
   the same owner, the same counterparty, the same class, or the same epoch. The
   information content of prefix locality is exactly the information content of the
   uniform distribution, which is none.

   This is the entire justification for C-10, and it fails immediately under a different
   key choice. Had the key been `pseudonym || sequence`, all revocations for one
   (vehicle, audience) would share a long prefix and sit in one subtree, and any party
   holding one proof could count and track the others. Had it been derived from an
   enrolment id, the tree's shape would group by vehicle. The key must be a digest, and it
   must be a digest of something the tree does not otherwise reveal.

**Observer C — anyone, after erasure.**

5. The root and the leaves persist forever; that is what immutable means, and NF-4 does not
   pretend otherwise. What persists is: a 32-byte key that is a commitment to a grant
   nobody can any longer open, and a 32-byte value whose opening (the signed record) has
   been destroyed (C-13). The salt is gone, so the pseudonym inside that unreachable grant
   cannot be re-derived from a candidate VIN even by a party who guesses the VIN correctly
   (NF-WP-1 §9.5). No party can move from ledger data to a person, a vehicle, or a field
   value.

6. A party who independently retained a copy of the grant before erasure retains the
   ability to check revocation of that grant forever. The honest statement is that this
   residual capability comes from *their retained copy*, not from the ledger: the ledger
   adds a revocation status to information they already hold about a relationship they were
   party to. Their retained copy is the personal-information exposure, and it is addressed
   by their own deletion obligation, not by the commitment scheme. NF-4 does not claim the
   ledger makes erasure complete; it claims that on-chain data standing alone is not
   personal information and is not a lever for re-identification, and §7.6(1)–(5) is the
   argument for that narrower claim.

### 7.7 Prohibited commitment designs

- C-24. The following MUST NOT be committed to a ledger, in any encoding, hashed or
  otherwise. Each is prohibited for a stated reason, and the list is normative:

  | Prohibited | Reason |
  |---|---|
  | A VIN, or any hash of one | Enumerable preimage (~10^8); a rainbow table on an immutable ledger. |
  | A `vehicle_pseudonym` value, or a hash of one | Not enumerable, but stable per (vehicle, audience). Committing it gives that audience a permanent, unerasable tracker for the vehicle, surviving destruction of the salt — the exact thing erasure is supposed to end. |
  | A `revocation_key_id`, `enrolment_id`, `counterparty_key`, or hash of any | Stable long-lived identifiers. Same defect as above, plus they aggregate across grants. |
  | A `revocation_public_key` or a `signature` | Owner-linked material; unerasable attribution (C-13, C-14). |
  | A `reason_code` | Reveals *why* an owner withdrew — a behavioural fact about a person, per subject, permanently. |
  | A leaf count, per-revocation timestamp, or per-event anchor | Volume and timing channels (§7.6(1), C-15). |
  | Any payload field, or any value from the NF-2 field vocabulary | NF-1 boundary B3; this is the whole of Refusal 2. |
  | Any structured tree key | Prefix locality leaks grouping (§7.6(4), C-10). |

- C-25. Per-leaf blinding MUST NOT be used (§7.6(2)).

- C-26. A ledger MUST NOT be used to store any object of §3, nor a mapping from a
  commitment to anything. The only mapping in the tree is key → 32 bytes, and both sides
  are digests.

---

## 8. Revocation and deletion are different operations

The two are routinely conflated, including in the language of the statutes that motivate
them, and conflating them produces one of two defects: a system that thinks erasing data
ends authority, or a system that thinks ending authority satisfies an erasure request.
Both are wrong, and the second is the more dangerous because it looks like compliance.

### 8.1 Definitions

**REVOCATION** ends authority, prospectively, over a described set of grants. It is
owner-authorized (§4), monotone (S-3), immediate (S-9), cascading (S-6), and it
**creates** state: the revocation record, the tombstone and the leaf all exist because a
revocation happened, and they must continue to exist for the revocation to keep being
enforced.

**DELETION** destroys data. It is the Delete Act / CCPA erasure operation (NF-WP-1 §9.5):
it removes the payload, the enrolment row, the grant records, the linkage tables, and —
decisively — the **pseudonym salt**. Destroying the salt destroys the VIN↔pseudonym
linkage, so a party holding both a correct guess at the VIN and a pseudonym can no longer
connect them (vin.js; NF-WP-1 §9.5). Deletion **removes** state.

They point in opposite directions. Revocation writes the thing that must survive;
deletion destroys the thing that must not.

### 8.2 Why both are required

- D-1. **Revocation without deletion is not erasure.** Authority ends, but everything
  already held remains held, the vehicle remains enrolled, the salt still links pseudonym
  to VIN, and the owner is still as re-identifiable as they were the day before. An owner
  who asked to be forgotten and was merely de-authorized has had a different request
  answered.

- D-2. **Deletion without revocation is an authorization bypass, not merely incomplete.**
  This is the non-obvious half. A grant's authority is evaluated against its commitment
  and the revocation state (F-6) — not against the salt, and not against the enrolment
  row. Destroying the vehicle's records therefore does nothing to a grant a counterparty
  already holds. Worse, it removes the broker's ability to *evaluate* that grant at all:
  the issuance index entry is gone, the parent chain is gone. If any of those absences
  were read as "no objection", deletion would be the most reliable way to escalate a
  revoked or expired grant into a working one.

  F-6(2) and S-10 are what close this: absence of an issuance record is UNKNOWN, and
  UNKNOWN denies; a missing parent makes a delegated grant revoked. Deletion consequently
  fails safe rather than open — but only because those two rules exist, and an
  implementation that treated a missing row as a non-obstacle would have the bypass.

- D-3. The two rights are also distinct in law and cannot substitute for one another: DPPA
  consent (18 U.S.C. §2721(b)) governs whether a use is permissible while it continues,
  and the Delete Act and CCPA erasure rights govern what must be destroyed afterwards
  (NF-WP-1 §9.5). A protocol offering one operation would be non-conformant to whichever
  regime it had chosen to model.

### 8.3 Mandatory ordering

- D-4. Erasure of a vehicle MUST be sequenced:

      1. revoke every live grant for the vehicle (scope "vehicle", §5.4), and
         durably record the tombstones and leaves;
      2. wait at least MAX_DECISION_STALENESS_S, or positively confirm that every
         cache holding a decision for those commitments has drained;
      3. destroy the payload, the enrolment row, the grant records and the salt;
      4. destroy the attribution fields of the revocation records (C-13), retaining
         the tombstones and the leaves.

- D-5. Step (1) MUST precede step (3). If the records are destroyed first, there is no
  commitment left to write a tombstone against — the broker cannot recompute
  `deriveGrantCommitment()` for a grant it no longer holds — and any retained copy of that
  grant becomes permanently unrevokable-against. The window would close only at
  `expires_at`, up to 45 days later, and would be invisible to everyone including the
  owner who asked for erasure.

- D-6. Step (2) is what stops a cached ALLOW from outliving the payload it authorizes. It
  is at most one staleness bound of waiting, which is the practical argument for keeping
  the bound small (§6.1): the bound is not only a leak window, it is a floor on how quickly
  an erasure can be completed.

- D-7. Erasure MUST NOT destroy revocation state (C-13). A tombstone is a commitment plus
  an epoch number: it identifies no person, opens to nothing, and is retained for the
  security purpose of preventing replay of a grant that was withdrawn. Deleting it in the
  name of erasure would trade an owner's already-satisfied erasure for a stranger's
  standing ability to replay.

- D-8. Everything owner-linked in the revocation record — public key, signature, reason
  code — MUST be destroyed at step (4). The reason code in particular is a statement about
  why a person changed their mind and has no function after erasure.

- D-9. A deletion sweep MUST NOT be the mechanism by which authority ends. It runs on a
  45-day cadence and revocation is required to take effect within seconds; the two differ
  by roughly five orders of magnitude (§9). An implementation that ends access by waiting
  for the next sweep has no revocation, whatever it calls the endpoint.

---

## 9. The clocks, and how they interact

| Clock | Value | Owner | What it bounds |
|---|---|---|---|
| Staleness bound (F-1) | 60 s | NF-4 | Time from revocation until the last enforcement point stops serving. |
| Staleness ceiling (F-2) | 300 s | NF-4 | The most a deployment may choose. |
| Commitment epoch (C-15) | 3600 s | NF-4 | Granularity of public auditability and of the timing leak in §7.6(1). Not in the enforcement path. |
| Grant lifetime cap | 45 days | NF-2 | Worst-case exposure when revocation is impossible (lost key, A-18). |
| Deletion cadence | 45 days | NF-WP-1 §9.5 | How often erasure machinery runs. |

- K-1. `MAX_DECISION_STALENESS_S` ≪ grant lifetime, by design and by five orders of
  magnitude. The staleness bound governs the normal case (revocation works); the 45-day cap
  governs the failure case (it cannot). Neither substitutes for the other, and the large gap
  between them is what makes it safe for the cap to be as long as the deletion cadence.

- K-2. NF-2 pins the grant cap to the deletion cadence so that every grant faces at least
  one erasure boundary within its life. NF-4 inherits the consequence: at any sweep, some
  live grants are mid-life, so D-4's ordering is not an edge case — it is the normal path
  through an erasure.

- K-3. Where a deployment's response obligation extends beyond the 45-day cadence to an
  outer bound of 90 days, nothing in §8 changes except magnitude: the pessimistic gap
  between an owner's erasure request and its completion doubles, the ordering requirements
  are identical, and the ≤45-day grant cap continues to bound what a lost revocation key
  can cost. NF-4 states no view on which clock a given deployment is under; the
  requirements hold under either.

- K-4. The commitment epoch MUST NOT be shortened in the belief that it improves
  enforcement latency (C-16), and MUST NOT be lengthened past the point where an anchored
  root is available for each day's heads — an epoch long enough that heads routinely expire
  before their root is anchored removes the retrospective check that makes heads trustable
  (C-17).

- K-5. Raising the staleness bound to reduce load has three costs that MUST be weighed
  together, not one: it lengthens the disclosed leak window (F-3), it slows every erasure
  by the same amount (D-6), and it widens the window in which cache-outrunning (SEC-3) can
  operate. It buys only D1 read volume.

---

## 10. Security considerations

NF-1 SEC-9 states that revocation is the weakest link and expiry is its fail-safe. This
section enumerates how revocation fails and what each failure costs. Following NF-1's
convention, items are numbered for citation by NF-5.

### SEC-1 — Revocation censorship

**Threat.** The broker is the party that would most like a revocation not to happen: it
loses a serving relationship, and the counterparty is its participant while the owner
often is not. Censorship can be silent (drop the record, return success), selective (apply
in D1 so the owner's dashboard is satisfied, omit from the tree so an independent check
says otherwise), or passive (lose the §3.2 bindings so `vehicle` scope cannot resolve).

**Defences, in the order they bite.**

1. Records are self-authenticating (A-11). A verifier presented a valid record MUST honour
   it regardless of broker state. Suppression therefore cannot make a revocation invalid,
   only unpropagated, and the owner can propagate it themselves to the counterparty, a
   regulator, or an auditor.
2. Receipts (R4-7) make the broker commit, in writing and under signature, to including a
   specific record at a specific epoch. A receipted record absent from that epoch's
   anchored root is provable omission, attributable to the broker, verifiable by anyone,
   with no access to the broker's database.
3. Sequenced heads (R4-9) make selective equivocation between fast and slow paths
   detectable: two heads at one `state_seq` with different roots, or a head whose root never
   anchors, is a signed confession.
4. Monotonic spot-checks (C-9) catch quiet leaf removal, and the party motivated to check
   is the owner, who holds the proof.
5. Lineage-scoped revocation never needs the bindings (R4-6, S-15), so the passive variant
   fails: the owner always retains a path that requires nothing of the broker but a write.
6. Freshness failure denies (F-5). An enforcement point that cannot obtain a head newer
   than the bound MUST return UNKNOWN.

**Residual risk, stated honestly.** Defence (6) converts censorship-by-silence from a leak
against the owner into a denial of service against the counterparty — which is the right
direction, and it is a real cost. A broker whose head-publishing pipeline breaks stops
serving; a broker that deliberately withholds heads to avoid propagating revocations stops
serving too, which removes the motive. Detection is retrospective, not preventive: the
mechanisms above prove that censorship happened, they do not make it impossible. Nothing
in a protocol can, once one party operates the store, which is why NF-1 keeps the
Foundation out of operating the market it governs (Refusal 3) and why the log exists at
all.

### SEC-2 — Replay of stale or superseded grants

**Threat.** A counterparty presents a grant that has been revoked, has expired, was
renewed and superseded, or was edited.

**Defences.** A grant is not a bearer token: NF-2 binds it to `counterparty_key` and the
verifier MUST supply `presenterKey` from a challenge in the same session (F-6(1)), so a
copied grant is worthless without the private key. `expires_at` is inside the signed bytes,
so it cannot be edited; any edit produces a different commitment, and a different
commitment is `absent` from the revocation tree — which is why F-6(2) requires an issuance
record. **Non-membership is not authorization** (C-22): the most important consequence of
keying state by commitment is that a modified grant looks un-revoked, and it must therefore
be caught by the issuance check rather than by the revocation check.

Renewal (NF-2 `renewGrant()`) mints a fresh id and commitment, so revoking the old grant
does not touch the new one and — importantly — the old grant's revocation cannot be
laundered into the new one's status, nor vice versa. Implementations MUST revoke or expire
the superseded grant explicitly; NF-2 states that `renewGrant()` does not do it.

**Residual risk.** A counterparty in possession of both a valid grant and its private key,
inside the staleness bound after revocation, is authorized. That window is the bound, and
it is the thing §6 exists to keep small and disclosed.

### SEC-3 — Cache-outrunning

**Threat.** A counterparty that expects to be revoked maximizes what it can read afterwards.
Three concrete variants:

1. **Fan-out warming.** Distribute requests across many colos immediately before an
   expected revocation so that many independent enforcement points each hold a fresh ALLOW.
   *Defence:* the bound is per-decision-age, measured from `derived_at` (F-11), not
   per-cache and not per-node. N caches do not produce N × 60 s; they produce 60 s in
   parallel. Warming buys breadth, not duration.
2. **Keep-alive.** Poll a cached decision continuously so an access-refreshed TTL never
   expires. *Defence:* F-11 forbids refresh-on-access. This is the single most likely
   implementation defect in this document, because refresh-on-access is the default
   behaviour of most cache libraries and it makes exactly the busiest grant immortal.
3. **Long delivery.** Start a large export or an open stream one second before revocation
   and let it run. *Defence:* F-10 requires any delivery outliving a single response to
   re-derive at the bound and terminate on anything but ALLOW, and S-4(5) requires
   revocation to actively abort in-flight deliveries. Without F-10, every other requirement
   in this document is satisfiable by a system that leaks for four hours.

**Residual risk.** Actively aborting a stream depends on the broker's own machinery, so a
partitioned node may keep streaming until its next re-derivation. That is bounded by the
staleness bound, provided re-derivation is implemented as a *failure to continue* rather
than as a *successful continuation pending a check* — implementations MUST NOT emit bytes
while a re-derivation is outstanding.

### SEC-4 — Interaction of the staleness bound with the deletion clocks

The bound is not only a leak window; it is a floor on erasure completion (D-6), because
step (2) of D-4 must wait it out before the salt is destroyed. Three failures follow from
getting the interaction wrong:

- Destroying the payload before the caches drain leaves cached ALLOW decisions pointing at
  data that no longer exists; benign if the store returns nothing, but an implementation
  that treats a missing payload as a reason to fetch fresh Layer-2 data has turned an
  erasure into a collection event.
- Destroying records before revoking (violating D-5) opens an unrevokable window up to the
  45-day cap, invisible to the owner who requested erasure.
- Choosing a long bound to reduce load silently lengthens every erasure by the same amount
  (K-5). A 300 s bound means no erasure can complete in under five minutes, which must be
  reflected in whatever the deployment tells owners about erasure timing.

The 45-day grant cap is pinned to the deletion cadence (K-2), so mid-life grants at a sweep
are the normal case, not an edge case. Under a 90-day outer response bound the analysis is
unchanged in kind (K-3).

### SEC-5 — Cascade amplification

**Threat.** A single revocation triggers unbounded work: a wide delegation forest, or an
adversarially inflated subtree, turns one signed record into a long transaction and a
denial of service against the revocation path itself — the worst possible component to be
able to stall.

**Defences.** Depth is bounded by the signed grant and by NF-2's `MAX_DELEGATION_DEPTH` of
2 (S-9), so the walk is shallow by construction. Lineage scope needs no walk at all (S-8),
which is the cheap path for the common case of "revoke everything for this counterparty".
The node budget MUST fail closed by revoking the unexplored frontier (S-9), so exhausting
the budget cannot preserve authority. Notifications are asynchronous and idempotent (S-11)
so fan-out does not extend the synchronous transaction.

### SEC-6 — The revocation endpoint as an oracle

**Threat.** Distinguishable responses for unknown, revoked and live targets make the
endpoint an enumeration oracle for grant existence.

**Defence.** A-8(6) requires identical content and substantially identical timing across
those cases.

**Honest scope.** This is defence in depth, not a load-bearing control: `grant_id` is 128
random bits and `grant_commitment` is a SHA-256 output over a signature, so enumeration is
infeasible regardless (§7.6(3)). The requirement exists because the cost is near zero and
because a future schema with a shorter identifier would need it.

### SEC-7 — Equivocation between the store and the tree

**Threat.** The broker applies a revocation in D1 but omits it from the tree (or the
reverse), so different observers see different states.

**Defence.** S-4(3) requires the state write, the cascade set and the root update to occur
in one transaction, so no head can be signed over a state that omits an applied record. The
root MUST be a deterministic function of the revocation table, and an auditor recomputing
it from an export MUST obtain the same value (§11.5). The reverse direction — a leaf with no
row — is safe for access (it can only over-deny) but MUST still be reported, because it
means either a lost row or a fabricated leaf, and C-12 requires an opening for every
asserted revocation.

### SEC-8 — Revocation-key compromise

An attacker holding a revocation key can only revoke, and revocation only removes
authority. The compromise therefore costs availability, not confidentiality — which is why
revocation is 1-of-n (A-17) and why an unauthenticated submitter is acceptable (A-8(1)).

The cost is nonetheless real: a stolen key can kill a fleet's access, and a rate limiter
cannot mitigate it without also being able to delay legitimate revocations (A-8(5)).
Mitigation is on the re-issuance side, which is authenticated: the owner mints new grants
under a new lineage revocation key, which happens naturally at renewal because
`revocation_key_id` is per-grant. Implementations MUST NOT respond to this threat by adding
a quorum requirement, an authentication requirement, or an operator override to the
revocation path; each of those trades a confidentiality guarantee for an availability one
in the wrong direction.

### SEC-9 — Correlation via the revocation key id

`revocation_key_id` is the one long-lived, owner-scoped identifier that NF-2 places in the
clear inside a grant. Reusing one key across counterparty classes gives two counterparties a
stable join key over one vehicle and voids the per-audience pseudonym (A-15). The
requirement is on the `owner-agent`, so a conformant broker cannot enforce it on the
owner's behalf — but a broker MAY detect it, and SHOULD report as a finding any case where
one `revocation_key_id` appears across grants of differing `counterparty_class` for what it
believes to be one vehicle. Notifications MUST NOT disclose the key itself (A-13).

### SEC-10 — Operator suspension mislabelled as revocation

If `suspended` and `revoked` are merged, the owner loses the ability to tell whether their
withdrawal took effect or the operator simply stopped serving, and the operator gains the
ability to point at the log as evidence of an owner decision it made itself. A-7 keeps the
states distinct in every interface, keeps suspension out of the tree (C-8), and C-12 lets a
counterparty force the distinction by demanding an owner-signed opening. This is the
Refusal 3 failure mode expressed in revocation vocabulary: not the Foundation running a
market, but an operator quietly holding the owner's lever.

<!-- SECTION-11-ONWARD -->




