# NF-2 — The Consent Grant and the Closed Field Vocabulary

    Document:    NF-2
    Title:       The Consent Grant and the Closed Field Vocabulary
    Status:      Draft Standard
    Version:     1.0.0-draft
    Date:        2026-07
    Series:      Nimbus Foundation Specifications (NF-1 … NF-5)
    Schema:      nf2-grant/1
    Derives from: NF-WP-1, "The Consent-Governed Catallaxy" (July 2026),
                  §3.1 (Layer 3), §6.4 (agentic separation), §8.2 (this document),
                  §9.5 (Delete Act, CCPA erasure), §10.1 (the three refusals),
                  §12.2 (non-transactable classes), §12.7 (correlation), §14 (stack)
    Requires:    NF-1 (layer model, conformance vocabulary, registries)
    Related:     NF-3 (index resolution), NF-4 (revocation), NF-5 (conformance)
    Reference implementation: broker/src/nf2-grant.js, broker/src/fields.js,
                  broker/src/vin.js, broker/src/jcs.js — all present; see Appendix E for
                  what has and has not been verified against running code
    Supersedes:  no prior NF-series document

## Abstract

NF-2 defines the Consent Grant: the object in which a vehicle owner's authorization is
expressed, carried, verified and withdrawn. A Consent Grant is a **non-transferable,
non-fungible, owner-revocable capability object**. It names a vehicle by a salted,
epoch-rotating, per-audience pseudonym rather than by its index; it enumerates a field set
drawn from a closed vocabulary; it cites exactly one DPPA permissible use; it binds to a
counterparty's public key rather than to a counterparty's name; it carries a mandatory
expiry bounded by the Delete Act deletion cadence; it names an owner-held revocation key
without carrying it; it carries a delegation budget that only decreases; and it is signed
with EdDSA over the RFC 8785 canonicalization of itself.

NF-2 also defines the closed data-field vocabulary, the Non-Transactable Classes that have
no field identifier at all, the encoding profile and media type, the on-chain grant
commitment — the single artifact of a grant that may cross the immutability boundary — and
the reason-code vocabulary that makes verification testable.

What NF-2 deliberately does not contain is as load-bearing as what it does. There is no
price, amount, currency, fee or settlement member; no holder, assignee, bearer or transfer
member; no `alg` member; no field identifier for any Non-Transactable Class; and no member
carrying the raw Vehicle Index or the signer's public key. Each absence is structural, and
§4.5 states why each one is an absence rather than a rule about a member that exists.

---

## 1. Introduction

### 1.1 Scope

This document is normative for:

- the capability semantics of the Consent Grant, and the requirement that it never acquire
  ownership-token semantics (§3);
- the object model: the closed top-level key set, every member, its type, its presence rule
  and its value constraints (§4);
- the vehicle pseudonym construction, its three properties, and the honest scope of the
  anti-correlation claim each property supports (§5);
- the closed data-field vocabulary, canonical field ordering, and the Non-Transactable
  Classes (§6);
- purpose limitation and its binding to 18 U.S.C. §2721(b) (§7);
- counterparty class, counterparty key binding, and proof of possession (§8);
- duration, the maximum lifetime, the plausible-time window, clock skew, and renewal (§9);
- the owner-held revocation key reference (§10);
- delegation: depth, narrowing invariants, signer, and why delegation is not transfer (§11);
- the encoding profile, media type, the JCS canonicalization requirement, the signing input,
  the EdDSA signature, and the grant commitment (§4.1, §12);
- the verification verdict and the reason-code vocabulary it emits (§13);
- the storage profile that keeps the grant on the mutable side of boundary B3 (§14);
- the agentic three-layer separation and how it is encoded in a grant (§15).

### 1.2 What this document is not

NF-2 does not define index resolution or authorization-endpoint discovery; that is NF-3.
NF-2 does not define revocation records, revocation state, cascade, the staleness bound, or
the on-chain revocation commitment; that is NF-4. NF-2 defines the *shape* of the hooks
NF-4 uses — `revocation_key_id`, `parent_grant_id`, and `deriveGrantCommitment()` — and
nothing about how they are exercised.

NF-2 does not define a transport, an endpoint path, an authentication scheme for a broker
API, or a payload projection format. It defines an object and the rules for producing and
checking one.

NF-2 defines **no price, fee, quote, bid, escrow, settlement, token, or transfer**. Layer 5
is deferred and gated (NF-1 §8). The absence is structural: there is no member to populate
and no operation to invoke (NF-1 L5-1, L5-2).

NF-2 is not a legal opinion. It cites statutes because the object's constraints are derived
from them, and §15.5 and Appendix E record where the legal position is unsettled.

### 1.3 Relationship to the other NF documents

NF-1 supplies the layer model, the conformance-target roles, the trust boundaries, and the
registry policies that NF-2's registries sit under. Every NF-2 requirement below is an
instance of an NF-1 requirement made concrete; where a clause implements a specific NF-1
requirement, the requirement is cited inline (`L3-3`, `C-7`, `R-1`, and so on).

NF-3 resolves a Vehicle Index to the endpoint at which a grant may be *requested*. It never
returns a grant, and a grant never contains an index. The two documents meet at exactly one
point: the pseudonym in a grant is derived from the same canonical VIN form NF-3 defines
(§3.1 of that document), via `validateVin()`.

NF-4 makes the word "revocable" mean something. NF-2's `verifyGrant()` returns
`{ valid, reasons }` and **does not know revocation state**; NF-4 §1.3 correctly identifies
this as a trap and closes it with a four-part authorization predicate. NF-2 states the
matching obligation here as `VF-6`.

NF-5 is the conformance suite. Its groups `NT` (non-transactability), `DD`
(delegation depth) and `GC` (grant core) assert against this document, and its assertion
surface is the reason-code vocabulary of §13.4. A code renamed here silently vacates a
passing NF-5 assertion (NF-1 R-5).

### 1.4 Reading order, and the authority of the code

Read `broker/src/fields.js` and `broker/src/vin.js` first: they are the machine-readable
form of the vocabulary and the pseudonym construction. Read `broker/src/jcs.js` for the
canonicalization profile, and `broker/src/nf2-grant.js` for the object and its operations.

Where this document names a JavaScript identifier — `buildGrant`, `verifyGrant`,
`MAX_DELEGATION_DEPTH`, `PSEUDONYM_DERIVATION` — the name is REQUIRED of an implementation
that reuses the reference modules, and is descriptive only for an implementation in another
language. The **PROTOCOL profile of NF-5 §4.2 is the gate**; nothing in this document may be
satisfiable only by importing `broker/src/`.

Where this document and the reference implementation disagree, this document governs and the
disagreement is a defect in the implementation. Appendix E enumerates the disagreements known
at publication rather than leaving them to be discovered.

---

## 2. Conformance

### 2.1 Requirements notation

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY** and **OPTIONAL** in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
when, they appear in all capitals, as shown here.

The two NF-series conventions of NF-1 §2.1 apply in full:

**MUST NOT is not waivable by agreement.** A deployment does not become conformant because
an owner, a counterparty, or a regulator consented to the violation. Several requirements
below exist precisely because they cannot be waived by a pressured or unsophisticated owner
(NF-WP-1 §8.2), and a waiver channel would return the decision to the party least able to
make it.

**SHOULD means an implementer who deviates must be able to say why.** NF-5 records SHOULD
deviations as findings. A deviation with no stated reason is a finding.

One convention is specific to this document.

**Refusal is whole-object, never partial.** Where NF-2 requires that an input be refused,
the conforming outcome is that no grant object is produced, stored, or served, and that no
narrower object is substituted. An implementation that silently drops an offending member
and issues the remainder has produced a grant that covers something other than what the
owner read, which is a consent defect and not a convenience (NF-5 NF5-NT-004, NF5-NT-007).

### 2.2 Conformance targets

NF-2 binds five of the NF-1 §2.2 roles. As in NF-1, conformance is asserted against roles,
not products; a deployment implementing several roles MUST satisfy each independently and
MUST NOT rely on co-location to satisfy a requirement that assumes separation.

| Role | NF-2 obligations |
|---|---|
| `owner-agent` | Holds the owner signing key and the revocation key. Originates root grants. MUST hold a distinct signing key and revocation key per (vehicle, `counterparty_class`) lineage (§5.3, §10). |
| `broker` | Holds the pseudonym salt, derives pseudonyms, assembles grants, stores them in mutable storage, and derives commitments. MUST NOT hold revocation authority (§10, `RK-4`). |
| `counterparty` | Holds the private half of `counterparty_key`. Presents a grant and proves possession. MAY delegate within its depth budget (§11). MUST NOT treat a grant as a bearer token. |
| `verifier` | Evaluates a grant against §13. MUST fail closed, MUST NOT throw, MUST emit the §13.4 codes, and MUST NOT return a positive verdict on an unchecked signature. |
| `tester` | Runs NF-5 groups `NT`, `DD` and `GC` against another role. |

The Nimbus Foundation is not a conformance target, holds no grant, no owner key, no
revocation key and no pseudonym salt, and appears nowhere in this object model (NF-1 §2.2,
§5 Refusal 3, B5).

### 2.3 Terminology

Terms defined in NF-1 §2.3 — Vehicle Index, Resolution, Consent Grant, Vehicle Pseudonym,
Non-Transactable Class, Authoritative State, Projection, Layer 5 Function — are used here
with those meanings. Additional terms:

**Capability object.** A datum that authorizes a named principal to perform an enumerated
operation on a named resource, evaluated at the moment of exercise by a party that is not
the holder. It is not a claim about title, and its possession is not its authority.

**Root grant.** A grant with `parent_grant_id: null`, signed by the owner.

**Sub-grant (delegated grant).** A grant with a non-null `parent_grant_id`, signed by the
delegator, whose key is the parent's `counterparty_key`.

**Lineage.** A root grant together with every grant reachable from it by following
`parent_grant_id` edges downward. The unit NF-4 cascades over.

**Audience.** The value bound into the pseudonym derivation. In `nf2-grant/1` the audience
of a root grant is its `counterparty_class`; a sub-grant inherits the parent's audience
verbatim (§5.2, §11.3).

**Epoch.** The monotonic non-negative rotation counter under which a pseudonym was derived.
Held per vehicle by the broker; incrementing it rotates every subsequently issued pseudonym
for that vehicle.

**Grant commitment.** The domain-separated SHA-256 digest over the canonical signed grant
(§12.6). The only artifact of a grant that MAY cross onto an immutable ledger.

**Signing input.** The UTF-8 encoding of the RFC 8785 canonicalization of the grant with the
`signature` member removed (§12.3).

**Wrapper.** The legal person that holds a grant on behalf of a principal operating through
an automated agent. See §15.

---

## 3. The Consent Grant is a capability, not a token

### 3.1 What the object has to answer

A Consent Grant exists to answer one question at one moment: *may this presenter read these
enumerated fields about this vehicle for this purpose, right now?* That question is answered
by a party who is not the holder — an enforcement point — and the answer can change between
one request and the next without anything about the object changing.

That is the definition of a capability. The object is an authorization, evaluated at
exercise, against state the holder does not control.

- CG-1. A Consent Grant MUST be a capability object as defined in §2.3. It MUST NOT be
  represented, described, documented, marketed, or implemented as an ownership interest, a
  title, a receipt, a certificate, a security, a token, a non-fungible token, a
  controllable electronic record, or an asset.

- CG-2. A Consent Grant MUST be **non-transferable**. No NF-defined object may encode
  assignment, sale, gift, bearer semantics, collateralization, or any other change of holder
  (NF-1 L3-4).

- CG-3. A Consent Grant MUST be **non-fungible** in the strict sense: no two grants are
  interchangeable, and no operation may substitute one grant for another. There is no
  denomination, no quantity, no unit, and no member that could carry one.

- CG-4. A Consent Grant MUST be **owner-revocable** without the cooperation of the broker or
  the counterparty (NF-1 L3-6). NF-2 supplies the reference (`revocation_key_id`); NF-4
  supplies the mechanism.

- CG-5. A Consent Grant MUST carry a mandatory expiry and MUST NOT be perpetual (NF-1 L3-3).

### 3.2 Why the ownership-token model is wrong

The alternative design is obvious enough that it has to be refused explicitly: mint a token
per consent decision, let the holder be whoever holds it, and let a registry record transfers.
Seven arguments against, in ascending order of how hard they are to work around.

**1. The owner's decision is about a counterparty, and transfer destroys the decision.**
Consent under 18 U.S.C. §2721(b) and under the CCPA is a decision about *who*, *what*, *why*
and *for how long*. Change the holder and one of the four terms has been rewritten by a party
that is not the owner. A capability that can be handed on is a consent decision that has been
silently reassigned to someone the owner never evaluated.

**2. Fungibility defeats purpose limitation.** Two grants over the same field set for
different DPPA purposes are not interchangeable, and if an exchange treated them as
interchangeable, purpose limitation would be defeated by trade rather than by argument.
Purpose limitation is the whole of the DPPA compliance story (NF-1 P3), so anything that
makes two grants substitutable dissolves it.

**3. Revocability and title are in tension; capability and revocation are not.** A token's
worth to its holder depends on the holder's confidence that it cannot be taken away.
Revocation is exactly a taking. A design that promises both is promising one of them
falsely. A capability has no such tension: withdrawal is its normal end state, and the
holder never had title to lose.

**4. Transfer erases provenance, which is most of its appeal to the transferring party.**
Delegation records `parent_grant_id`, so the owner can see the entire subtree hanging off
their decision and can cut any branch of it. A transferred capability leaves the owner
holding a lever attached to nothing.

**5. An ownership model needs an authoritative holder registry, and the natural
implementation of that registry violates Refusal 2.** "Who holds this now" must be answered
by some canonical store; the obvious store is a ledger; and a persistent per-vehicle or
per-grant ownership record on an immutable ledger is undeletable behavioural metadata even
when it carries no payload at all (NF-1 §4.3 B3, DOCTRINE Refusal 2). The token model does
not merely permit a Refusal-2 violation — it requires one.

**6. Tokens tend toward bearer semantics, and a bearer consent object is compromised
permanently on first disclosure.** NF grants are safe to log, cache and ship over an
untrusted bearer precisely because they are key-bound (NF-1 L1-3, SEC-2). Bearer semantics
would remove that property and put every log aggregator inside the trust boundary.

**7. A transferable capability is an asset; an asset has a price; a priced consent object is
a Layer 5 Function.** Layer 5 is deferred behind securities-law, Digital Financial Assets
Law, money-transmission, Sherman Act §1, privacy and UCC Article 12 clearances (NF-1 §8).
Non-transferability is therefore not only correct design — it is what keeps V1 inside its
declared scope structurally rather than by policy, and NF-1 G-5 keeps it in force even after
the gate opens.

- CG-6. An implementation MUST NOT offer an operation that changes the holder of an existing
  grant, under any name — transfer, assign, reissue-to, rebind, migrate, or hand-off.
  Delegation (§11) mints a **new, narrower, independently revocable** grant and does not move
  an existing one (NF-1 L3-4).

- CG-7. The following member names MUST NOT appear at the top level of a Consent Grant, and
  their presence MUST cause rejection with `transferable_field_present`:

      holder   assignee   transfer_to   transferable   new_holder   bearer
      delegate_to   reissue_to

  This list is redundant against the closed key set of §4.2, which already rejects any
  unknown member. It is stated separately because a redundant check that names the specific
  operation being refused is what makes the refusal assertable by NF-5 against an arbitrary
  object, and because the reference implementation exposes it as `assertNonTransferable()`.

- CG-8. No member of a Consent Grant may carry a price, an amount, a currency, a fee, a rate,
  a bid, a quantity, or a reference to any of them, and no such member may be added by an
  extension, a profile, or a local convention (NF-1 L5-2). The closed key set of §4.2 is the
  enforcement point: there is no member to populate.

### 3.3 Where each property is enforced

| Property | Enforced by | Assertable at |
|---|---|---|
| Non-transferable | Closed key set (§4.2); `HOLDER_MUTATION_FIELDS` refusal (CG-7); binding to `counterparty_key` (§8.2) | `assertNonTransferable()`; NF-5 group `GC` |
| Non-fungible | No quantity, denomination or unit member exists (CG-8); `grant_id` is 128 random bits | Schema inspection |
| Owner-revocable | `revocation_key_id` names an owner-held key; the grantee-key refusal of §10; the operator-key refusal of §10 | `revocation_key_held_by_counterparty`, `revocation_key_forbidden`; NF-4 §4 |
| Expiring | `expires_at` REQUIRED and non-null; 45-day cap | `expiry_not_after_issue`, `duration_exceeds_cap`, `expired` |
| Purpose-limited | Exactly one `purpose` from a statute-bound registry | `purpose_unknown`; NF-1 R-8 |
| Scope-limited | Closed field vocabulary, no free-text member | `fields_invalid`; NF-5 group `NT` |
| Index-free | No member accepts a VIN; the pseudonym member is a fixed 43-character base64url value | `pseudonym_malformed`; `assertNoRawVin()` at construction |

---

## 4. Object model

### 4.1 Encoding profile and media type

- E-1. A Consent Grant is a JSON object (RFC 8259) whose serialized form for all
  cryptographic and interchange purposes is the RFC 8785 (JCS) canonicalization defined in
  §12, UTF-8 encoded, with no byte-order mark and no insignificant whitespace.

- E-2. The media type is:

      Type name:               application
      Subtype name:            nf2-grant+json
      Required parameters:     none
      Optional parameters:     none
      Encoding considerations: binary; UTF-8, as produced by JSON canonicalization (RFC 8785)
      Security considerations: §16 of this document; NF-1 §10
      Interoperability:        the top-level key set is CLOSED; a member not in that set
                               MUST cause rejection, not tolerance
      Fragment identifiers:    none defined

- E-3. The media type MUST NOT carry an `alg` parameter or any other algorithm-negotiation
  parameter, and MUST NOT carry a version parameter (NF-1 R-1, R-2). The cryptographic suite
  and the schema version are both pinned by the signed `v` member. A transport-level version
  can disagree with the in-band one, and the question of which governs has no good answer.

- E-4. A new schema version MUST use a new subtype (`application/nf2-grantN+json`) or rely
  solely on the in-band signed `v` member — never a parameter (NF-1 R-3).

- E-5. A Consent Grant is **not a secret**. It MAY be stored, logged, cached and transmitted
  over an untrusted bearer, because it authorizes only a presenter who can prove possession
  of the bound private key (NF-1 L1-3, SEC-2). Correspondingly, an implementation MUST
  challenge for possession (§8.3) and MUST NOT accept a presented grant as a bearer token.

- E-6. A grant MUST NOT be transmitted or stored in a re-serialized form that differs from
  its canonicalization. Where a transport requires an envelope, the grant MUST appear inside
  it as the canonical bytes, and the receiver MUST re-canonicalize before verifying rather
  than trusting the received byte sequence.

### 4.2 The closed top-level key set

- SH-1. The top-level key set of `nf2-grant/1` is CLOSED and consists of exactly these
  fourteen members:

      v                 grant_id            vehicle_pseudonym   fields
      purpose           issued_at           expires_at          counterparty_class
      counterparty_key  revocation_key_id   delegation_depth    parent_grant_id
      renewal_of        signature

- SH-2. Every member MUST be present on every grant. A member that does not apply is present
  with an explicit `null`; it is never omitted. An omitted member MUST cause rejection with
  `missing_field`.

- SH-3. A member not in the set of SH-1 MUST cause rejection with `unknown_field`. A verifier
  MUST NOT ignore, pass through, or preserve an unrecognized member.

- SH-4. `vehicle_pseudonym` is the only nested object. Its key set is likewise CLOSED and
  consists of exactly `value`, `epoch`, `audience`, `derivation`; the SH-2 and SH-3 rules
  apply to it unchanged, with code `pseudonym_malformed`.

- SH-5. There is no extension point. A deployment needing to carry additional data about a
  grant MUST carry it outside the grant, keyed by `grant_id`, in mutable storage. It MUST NOT
  be inside the signed bytes.

*Why both halves of SH-2/SH-3 are load-bearing.* Rejecting unknown members is a
privilege-escalation defence: a verifier that tolerates an unrecognized member will accept a
grant carrying a term the issuer signed and the verifier does not enforce, which is exactly
how an "extension" becomes an escalation (NF-1 SEC-6). Requiring explicit nulls is a
canonicalization requirement: **absence and explicit null canonicalize to different bytes**,
so permitting both would give one semantic grant two canonical forms and therefore two
commitments — and NF-4 keys revocation state by commitment, so a revocation entry filed
against one form would silently miss the other. A schema latitude becomes a revocation bypass
(§16 SEC-5, NF-4 R4-1).

### 4.3 Members, field by field

Lengths below are unpadded base64url character counts, which for *n* bytes is
`ceil(n × 4 / 3)`. All timestamps are Unix **seconds**.

| Member | Type | Presence | Value constraint | Failure code |
|---|---|---|---|---|
| `v` | string | REQUIRED, non-null | Exactly `"nf2-grant/1"`. Pins schema and cryptographic suite. | `schema_version_unsupported` |
| `grant_id` | string | REQUIRED, non-null | 16 cryptographically random bytes, base64url, 22 chars. | `grant_id_malformed` |
| `vehicle_pseudonym` | object | REQUIRED, non-null | Closed 4-member object; see below. | `pseudonym_malformed` |
| `vehicle_pseudonym.value` | string | REQUIRED, non-null | 32 bytes, base64url, 43 chars. Output of the §5.1 derivation. | `pseudonym_malformed` |
| `vehicle_pseudonym.epoch` | integer | REQUIRED, non-null | Safe integer ≥ 0. | `pseudonym_malformed` |
| `vehicle_pseudonym.audience` | string | REQUIRED, non-null | Non-empty. On a root grant MUST equal `counterparty_class`. On a sub-grant it is the parent's audience verbatim. | `pseudonym_malformed`, `pseudonym_audience_mismatch` |
| `vehicle_pseudonym.derivation` | string | REQUIRED, non-null | Exactly `"nf2-pseudonym:v1"`. | `pseudonym_derivation_unsupported` |
| `fields` | array of string | REQUIRED, non-null | Non-empty; every member in the closed vocabulary (§6); no duplicates; sorted by UTF-16 code unit. | `fields_invalid`, `fields_not_canonical_order` |
| `purpose` | string | REQUIRED, non-null | Exactly one DPPA purpose identifier (§7). | `purpose_unknown` |
| `issued_at` | integer | REQUIRED, non-null | Safe integer in `[1700000000, 4000000000]`. | `issued_at_malformed`, `issued_at_implausible` |
| `expires_at` | integer | REQUIRED, non-null | Safe integer in the same window; `> issued_at`; `expires_at − issued_at ≤ 3888000`. | `expires_at_malformed`, `expires_at_implausible`, `expiry_not_after_issue`, `duration_exceeds_cap` |
| `counterparty_class` | string | REQUIRED, non-null | One of the eight classes of §8.1. | `counterparty_class_unknown` |
| `counterparty_key` | string | REQUIRED, non-null | Raw Ed25519 public key, 32 bytes, base64url, 43 chars. | `counterparty_key_malformed` |
| `revocation_key_id` | string | REQUIRED, non-null | 32-byte thumbprint, base64url, 43 chars; §10 construction. MUST NOT be, or be the thumbprint of, `counterparty_key`. | `revocation_key_id_malformed`, `revocation_key_held_by_counterparty`, `revocation_key_forbidden` |
| `delegation_depth` | integer | REQUIRED, non-null | Safe integer in `[0, 2]`. `0` = no delegation. | `delegation_depth_invalid` |
| `parent_grant_id` | string \| null | REQUIRED as a key; `null` on a root grant | When non-null: a `grant_id`, and MUST NOT equal this grant's own `grant_id`. | `parent_grant_id_malformed` |
| `renewal_of` | string \| null | REQUIRED as a key; `null` unless this grant supersedes another | When non-null: a `grant_id`, and MUST NOT equal this grant's own `grant_id`. | `renewal_of_malformed` |
| `signature` | string \| null | REQUIRED as a key; `null` only on an unsigned grant | Ed25519 signature, 64 bytes, base64url, 86 chars, over the §12.3 signing input. | `signature_malformed`, `signature_missing`, `signature_invalid` |

Member-by-member rationale for the choices that are not self-evident:

**`v`.** Versioned because revocation semantics are the part most likely to change, and an
unversioned capability object makes "does this grant follow the old rule or the new one"
unanswerable at exactly the moment it matters. It is inside the signed bytes, so it cannot be
downgraded after issuance, and it pins the signature suite in place of an `alg` member
(§4.5).

**`grant_id`.** Random, not sequential. A counter over an owner's issuance leaks issuance
volume per vehicle and lets a holder estimate how many other grants exist, which is a side
channel on the owner's behaviour. 128 bits is collision-free at any plausible scale with no
coordinator, which matters because there is no central minting authority in this
architecture.

- SH-6. `grant_id` MUST be generated from a cryptographically secure random source. It MUST
  NOT be a counter, a timestamp, a hash of the grant's contents, or derived from the vehicle,
  the owner or the counterparty.

**`fields`.** An enumerated set, sorted, unique, non-empty. Sorting is not cosmetic: JCS
gives arrays no ordering rule because array order is semantically significant, so an
unsorted set would give one semantic grant several canonical forms and therefore several
commitments (§6.2, §16 SEC-5).

**`issued_at` / `expires_at`.** Seconds, never milliseconds, and range-checked. See §9.3 for
why a range check is the only thing that catches the unit error.

**`counterparty_key`.** Binding to a key rather than a name is what makes a stolen grant
worthless (§8.2).

**`revocation_key_id`.** An identifier, not a key, so the owner can rotate the revocation key
without reissuing grants and so the grant carries nothing usable (§10).

**`parent_grant_id`.** The edge NF-4 walks to cascade a revocation down a subtree (NF-4 §5.3).
Its presence on the child rather than a child list on the parent is deliberate: the parent is
inside signed bytes and cannot be amended when a child is minted.

**`renewal_of`.** Supersession lineage, in the clear. See §9.4, and note the honest reading in
§16 SEC-3: `renewal_of` is a deliberate link visible to the holder, not an anonymized one.

### 4.4 Explicit nulls, restated as a rule about bytes

- SH-7. Exactly three members MAY hold `null`: `parent_grant_id`, `renewal_of`, and
  `signature`. Every other member MUST be non-null on a well-formed grant.

- SH-8. An implementation MUST NOT accept a grant in which an applicable member is `null`,
  and MUST NOT accept a grant in which an inapplicable member is present with a value. A root
  grant with a non-null `parent_grant_id` is a delegated grant that has lost its parent, and
  it MUST be rejected, not reinterpreted.

- SH-9. `signature: null` is a well-formed *unsigned* grant. An unsigned grant MUST NOT be
  verified as valid (`signature_missing`), MUST NOT be committed (§12.6), MUST NOT be
  delegated from (§11.1), and MUST NOT be served as authority for anything. It exists only as
  the input to signing.

### 4.5 Deliberately absent members

Four absences, each of which would look like an improvement and each of which is a defect.

**The signer's public key is absent — this is the load-bearing one.** A grant does not carry
the key that signed it. Including it would undo the per-audience pseudonym entirely: two
counterparties holding grants over the same vehicle receive deliberately different
pseudonyms, but if both grants carried the same owner public key they could join their
datasets on it and reconstruct a profile neither was granted (NF-WP-1 §12.7). The verifying
key is therefore supplied **out of band**.

- SH-10. A Consent Grant MUST NOT contain the signer's public key, a key identifier for it, a
  certificate, a JWK, a `kid`, a URL from which it can be fetched, or any other value from
  which the signer's key can be obtained or distinguished. This applies to root and delegated
  grants alike.

- SH-11. For a **root** grant the verifying key MUST be resolved out of band by the party
  entitled to make the lookup — in the reference deployment, by `vehicle_pseudonym.value`
  against the broker's mutable store. For a **delegated** grant no out-of-band key is needed:
  the expected signer is the parent's `counterparty_key`, so a chain verifies itself up to
  its root, and only the root requires the owner key (§11.4).

- SH-12. An `owner-agent` MUST hold a distinct owner signing key per
  (vehicle, `counterparty_class`). A single per-vehicle signing key is itself a join key
  across classes for any party that can test a candidate public key against two grants, which
  reintroduces exactly the correlation SH-10 removes.

**There is no `alg` member.** The suite is pinned by the signed `v`.

- SH-13. A Consent Grant MUST NOT contain an algorithm, suite, curve, hash or key-type
  member, at the top level or nested, and a verifier MUST NOT read the algorithm to use from
  the object it is verifying. This is the JWT `alg`-confusion bug class: anything the verifier
  reads *before* checking the signature, in order to decide *how* to check the signature, is
  attacker-controlled (NF-1 SEC-7, R-1). The same prohibition applies to the media type
  (E-3).

**There is no holder-mutation member.** CG-7.

**There is no economic member.** CG-8. Note the shape of the requirement: it is not that a
price member exists and must be left empty, it is that no such member exists anywhere in the
schema, so there is nothing for a later profile to populate and no migration that quietly
starts carrying one (NF-1 L5-2).

---

## 5. The vehicle pseudonym

### 5.1 Derivation (normative)

- PS-1. `vehicle_pseudonym.value` MUST be computed as:

      value = base64url( HMAC-SHA-256( K, M ) )

      K = UTF-8( salt )
      M = UTF-8( "nf2-pseudonym:v1" ":" VIN ":" epoch ":" audience )

  where:

  - `salt` is the owner-held pseudonym salt, a base64url string matching `^[A-Za-z0-9_-]+$`
    that decodes to at least 32 bytes;
  - `VIN` is the canonical Vehicle Index: exactly 17 characters, trimmed and upper-cased,
    from the ISO 3779 set `[A-HJ-NPR-Z0-9]`, as produced by `validateVin()`;
  - `epoch` is the decimal rendering of a non-negative safe integer;
  - `audience` is a non-empty string, equal to `counterparty_class` for a root grant;
  - the four `":"` separators are literal U+003A;
  - the output is the 32-byte MAC, base64url, unpadded, 43 characters.

- PS-2. The HMAC key is the **UTF-8 encoding of the salt string as presented**, not the
  decoded salt bytes. This is stated explicitly because it is the one place two conforming
  implementations can silently disagree and produce pseudonyms that never match, with a
  failure that reads as a data problem rather than as a version skew. The entropy requirement
  is nevertheless measured in **decoded bytes** (PS-3): a 43-character base64url string
  carries the entropy of the 32 bytes it encodes, and encoding it does not add any.

- PS-3. The salt MUST decode to at least 32 bytes and MUST come from a cryptographically
  secure random source. An implementation MUST reject a salt that is not base64url, and MUST
  measure length after decoding. A 32-*character* hex salt is 16 bytes — half the advertised
  strength, against a search space the salt exists to defend (PS-5).

- PS-4. `derivation` MUST be present in the grant and MUST equal the construction tag
  `"nf2-pseudonym:v1"`. It is recorded in the object so that a party holding the salt knows
  which construction to recompute rather than inferring it from `v`, and so that a versioned
  change to the derivation is visible in the signed bytes. An implementation MUST NOT hard-code
  a second copy of this constant; in the reference implementation it is exported once from
  `vin.js` and re-exported by `nf2-grant.js`.

- PS-5. HMAC, not a bare hash. The salt is a key and is used as one, which removes
  length-extension and multi-target concerns outright rather than arguing that they do not
  apply.

- PS-6. `epoch` and `audience` MUST be recorded in the grant alongside `value`, so a party
  holding the salt can recompute `value` and confirm the binding. The salt itself MUST NOT
  appear in the grant, MUST NOT be disclosed to a counterparty, and MUST NOT be derivable
  from anything committed to a ledger (NF-1 SEC-4).

### 5.2 The three properties, and the failure each answers

**Salted.** A VIN carries perhaps 10⁸ of realistic entropy once make, model and year are
known, and the index is public and enumerable by design (NF-1 SEC-1). An unsalted digest is
therefore a rainbow-table lookup: anyone holding a VIN could confirm enrolment and enumerate
a fleet from a parking lot. The salt is what makes the pseudonym a keyed value rather than a
public function of a public input.

**Rotating by epoch.** A stable pseudonym is a permanent correlation handle. Rotation bounds
linkability to one epoch, which is the mechanism the re-identification literature the white
paper cites at §12.7 argues for.

**Per-audience.** Rotation alone still permits a join *inside* one epoch between two
simultaneously-held grants. Binding the derivation to an audience makes that join fail across
audiences even within an epoch.

- PS-7. All three properties are REQUIRED. An implementation MUST NOT issue an unsalted, a
  non-rotating, or an unbound-audience pseudonym, and MUST reject a grant whose `audience` is
  absent or empty — an unbound pseudonym is a correlation handle wearing the vocabulary of a
  pseudonym.

- PS-8. The epoch counter MUST be monotonic per vehicle and MUST NOT be reused. Reusing an
  epoch re-opens a linkability domain the owner had closed.

- PS-9. A root grant's `vehicle_pseudonym.audience` MUST equal its `counterparty_class`
  (`pseudonym_audience_mismatch`). A delegated grant's audience is the parent's, verbatim, and
  the equality check MUST NOT be applied to it (§11.3).

### 5.3 The honest scope of the anti-correlation claim

This subsection exists because the property is easy to overstate, and the overstatement
appears in the reference implementation's own commentary (Appendix E, finding 2).

In `nf2-grant/1` the **audience is the counterparty class, not the counterparty**. The
consequences follow mechanically:

1. Two counterparties in **different** classes holding grants over the same vehicle in the
   same epoch receive different pseudonyms. They cannot join on the pseudonym. This is the
   property the design buys.
2. Two counterparties in the **same** class holding grants over the same vehicle in the same
   epoch receive **the same pseudonym value**, because every input to the derivation is
   identical. They *can* join on it. Two independent `repair-independent` shops are exactly
   this case, and it is not a rare one.
3. A delegate holds the pseudonym of its delegator's audience, so a sub-grant extends the
   delegator's linkability domain to the delegate. This is intended (§11.3) and bounded: the
   delegate can correlate no more than the delegator could.

- PS-10. An implementation MUST NOT describe the per-audience derivation as preventing joins
  between arbitrary counterparties. The accurate statement is that it prevents **cross-class**
  joins within an epoch and bounds all joins in time by epoch rotation.

- PS-11. An implementation MUST NOT describe pseudonymization as anonymization (NF-1 SEC-3).
  What remains after all three properties is that a counterparty can link its own observations
  within one epoch, which is inherent in receiving a stream at all.

- PS-12. Closing the intra-class join requires binding the audience to the counterparty's key
  rather than to its class. That is a different derivation, it changes every pseudonym, and it
  MUST therefore be a schema version bump under §18 rather than a local variation. An
  implementation MUST NOT vary the audience domain within `nf2-grant/1`.

*Why the class was chosen anyway, stated so the trade is visible rather than inherited.*
`counterparty_class` is the axis the owner's decision is actually about (§8.1), and a
key-bound audience would mint one pseudonym per counterparty, which multiplies the broker's
per-vehicle pseudonym state and makes the epoch-rotation sweep proportional to the number of
counterparties rather than to the number of vehicles. That is a defensible trade. It is not
the trade the current commentary describes making, which is why PS-10 exists.

### 5.4 The salt is the erasure mechanism

- PS-13. The pseudonym salt MUST live only in mutable, deletable storage. It MUST NOT be
  escrowed with a counterparty, MUST NOT be backed up to append-only storage, and MUST NOT be
  derivable from anything committed to an immutable ledger (NF-1 SEC-4, B3).

- PS-14. Destroying the salt destroys the linkage between the Vehicle Index and every
  pseudonym derived from it, including pseudonyms inside grant commitments already anchored
  off-box. This is what makes erasure real rather than nominal (NF-WP-1 §9.5), and it is the
  reason a grant commitment is not personal information even though it commits to a specific
  vehicle: a party holding both the digest and a candidate VIN cannot connect them without
  the salt.

- PS-15. An erasure MUST destroy the salt, not merely mark it deleted. A tombstoned salt is a
  retained salt wearing a flag.

---

## 6. The field set and the closed vocabulary

### 6.1 The vocabulary is closed

- FV-1. `fields` MUST be a non-empty array of identifiers drawn from the NF-2 Data Field
  Vocabulary. There is no `other` identifier, no free-text identifier, no wildcard, no glob,
  no class-level identifier that expands to its members, and no mechanism by which a
  requester's own string becomes a scope.

- FV-2. An identifier not in the vocabulary MUST cause the **whole grant** to be refused with
  `fields_invalid`. It MUST NOT be ignored, filtered out, or normalized into a neighbouring
  identifier. Silently narrowing a field set produces a grant that covers less than the owner
  read, which is a consent defect (§2.1).

- FV-3. Comparison MUST be exact string equality against the closed set. An implementation
  MUST NOT case-fold, trim, transliterate, NFKC/NFKD-normalize, or otherwise canonicalize an
  identifier before comparison. The danger runs in the direction people do not expect: an
  implementation that normalizes before comparing can map a confusable *into* a valid
  identifier, and the resulting grant canonicalizes to bytes the owner never saw (NF-5
  NF5-NT-005).

- FV-4. Duplicate identifiers MUST cause rejection, not de-duplication.

- FV-5. Membership MUST be tested against a set-like structure that is not the property table
  of a plain object. `__proto__`, `constructor`, `prototype` and `toString` are grantable-
  looking strings under an object-literal-keyed test and are not members of the vocabulary
  (NF-5 NF5-NT-006).

The vocabulary for `nf2-grant/1` is **40 identifiers in 6 classes**. Each class carries a
`layer` provenance tag recording where the data actually comes from, which is NF-1's §6
ceiling made machine-readable (NF-1 C-1, C-2):

| Class | Layer | Count | Meaning of the layer tag |
|---|---|---|---|
| `build_specification` | `vpic` | 14 | Derivable from the index alone via public build data (49 C.F.R. Part 565) |
| `diagnostics` | `layer2` | 6 | Requires Layer 2 authenticated access or a diagnostic interface |
| `battery_health` | `layer2` | 6 | Requires Layer 2 authenticated access |
| `motion_aggregate` | `layer2` | 6 | Requires Layer 2 authenticated access; non-positional only |
| `usage` | `layer2` | 4 | Requires Layer 2 authenticated access |
| `service_history` | `operator` | 4 | Supplied by a bonded participant |

The 40 identifiers are enumerated in Appendix A. The authoritative machine-readable form is
`FIELD_CLASSES` / `FIELDS` in `broker/src/fields.js`.

- FV-6. An implementation MUST tag every field with the layer that produces it and MUST NOT
  represent a `layer2` or `operator` field as index-derivable (NF-1 C-2, L2-5). The
  distinction is the difference between a lookup and a relationship with a manufacturer.

### 6.2 Canonical ordering

- FV-7. `fields` MUST be sorted ascending by UTF-16 code unit — the same comparator RFC 8785
  uses for object keys, exported as `compareCodeUnits()` — and MUST contain no duplicates. A
  grant whose `fields` array is not in that order MUST be rejected with
  `fields_not_canonical_order`.

- FV-8. An implementation MUST NOT use `localeCompare` or any locale-sensitive comparison.
  That would make the canonical form of a grant depend on the server's ICU data, and the
  canonical form is inside a signature.

*Why an ordering rule is needed at all.* JCS sorts object keys and deliberately does not sort
arrays, because array order is semantically significant in JSON. A field set is semantically
unordered, so the producer must impose the order. Without FV-7 the same semantic grant has
`n!` canonical forms and therefore `n!` commitments, and a revocation entry against one of
them misses the rest (§16 SEC-5).

### 6.3 Non-Transactable Classes have no grant type at all

- FV-9. Precise geolocation, biometric identifiers, and in-cabin audio and video MUST have
  **no field identifier** in the vocabulary. They are not identifiers carrying a deny flag;
  they are absent, and the protocol therefore cannot encode a grant for them (NF-WP-1 §8.2,
  §12.2; NF-1 C-7).

- FV-10. The NF-2 Non-Transactable Classes registry is **CLOSED** (NF-1 R-7). The Foundation
  MUST refuse any request to add a field identifier for a registered class and MUST refuse
  any request to remove an entry. Removal would be an amendment to Refusal 2's reasoning and
  to NF-1 §6.3, requiring the process of NF-1 §8/G-6 — it is not a registry action.

- FV-11. The registered non-transactable identifiers exist **solely** so that NF-5 can assert
  their absence from the vocabulary. Nothing in the protocol consumes the list to *permit*
  anything, and an implementation MUST NOT expose it as a configurable denylist. A
  configurable denylist is a waiver channel, and the entire point of refusal-by-schema is
  that there is no encoding for the waiver — which is stronger than consent, because consent
  can be extracted from a party with poor bargaining position and there is nothing here to
  extract (NF-1 P2).

The 18 registered identifiers are enumerated in Appendix B. Three of them deserve explicit
comment:

**`raw_vin`.** The Vehicle Index is itself non-transactable inside a payload. The Delete Act's
broker disclosures expressly enumerate vehicle identification numbers as a category of
personal information collected (NF-WP-1 §9.5), so a VIN in a payload does not merely offend
tidiness — it drags the payload into the regime (NF-1 C-9).

**`owner_name`, `owner_address`, `owner_phone`, `owner_email`.** The consent layer authorizes
access to data about a *vehicle*, never to contact details of a person. A broker that held
them would become their custodian for no protocol reason.

**`coarse_geolocation` and `geohash`.** Registered despite NF-2 forbidding only *precise*
geolocation. See §6.4.

- FV-12. A grant MUST NOT contain the raw Vehicle Index, nor any value from which the index
  or the owner's identity is derivable without the owner-held salt (NF-1 L3-5). An
  implementation MUST **verify this property against its own output** rather than asserting
  it: the reference implementation re-reads the canonicalization of every freshly built grant
  and refuses to return one in which the VIN appears (`assertNoRawVin()`). The check is cheap
  and it catches the specific future mistake of a convenience member added during debugging
  and left in.

### 6.4 V1 admits no positional field at any precision

- FV-13. `nf2-grant/1` admits **no positional field at any precision**. This is deliberate
  conservatism beyond the letter of NF-WP-1 §8.2, which forbids *precise* geolocation, and
  beyond the CCPA definition, which turns on a radius of roughly 1,850 feet (Civ. Code
  §1798.140(ae)).

  A coarse-position class is defensible in principle — a geohash-5 cell is roughly 4.9 km,
  far outside the statutory radius — but before any positional identifier earns a place in
  the vocabulary it REQUIRES a documented precision floor, a written re-identification
  analysis, and CPPA-aligned counsel review (NF-1 C-8, R-9). Until those exist the honest
  position is that we do not ship it.

- FV-14. Non-positional motion data — speed aggregates, acceleration and cornering event
  counts — is not geolocation and is admitted as the `motion_aggregate` class.

- FV-15. **Stated gap, not papered over.** A field set names identifiers; the data plane
  carries values, and NF-WP-1 §8.2's "anything from which PI can be derived" is a property of
  values. At a sufficiently short `aggregation_window_s`, a sequence of `speed_mean_kph` and
  `harsh_corner_count` values is a trajectory in all but name — the derivation is dead
  reckoning. `nf2-grant/1` specifies **no window floor and no maximum sample rate**, because
  none is specified anywhere in NF-WP-1 and this document will not invent an empirical
  threshold. Closing the gap requires a minimum `aggregation_window_s` and a per-class maximum
  sample rate derived from a documented re-identification analysis and reviewed against the
  CCPA sensitive-PI category. Until then, the honest statement of what NF-2 conformance means
  with respect to §8.2 is: *the protocol admits no grant type for the forbidden classes* — not
  *the implementation cannot leak positional inference* (NF-5 §5.2).

### 6.5 Publication

- FV-16. An implementation MUST publish its grantable vocabulary as a static `NF2-VOCAB/1`
  document, retrievable without authentication, in the form NF-5 §5.1 specifies, with
  `fields`, `purposes` and `counterparty_classes` each sorted by UTF-16 code unit and free of
  duplicates. A vocabulary a party must ask permission to read is a vocabulary that can differ
  per asker, which is preferential access by another name (NF-1 S-9).

- FV-17. The published vocabulary is **not** authoritative for conformance. NF-5 §4.8 reads
  the expected vocabulary and the forbidden list from its own Vector File, because an
  implementation that ships an empty forbidden list would otherwise pass perfectly.

---

## 7. Purpose limitation

### 7.1 Exactly one DPPA purpose

- PU-1. `purpose` MUST carry exactly one identifier from the NF-2 DPPA Purpose Identifier
  registry. It is a string, never an array.

- PU-2. A grant covering several purposes MUST NOT be issued. Two purposes are two grants,
  each independently revocable. A multi-purpose grant has a purpose limitation nobody can
  audit, and purpose limitation is the entire DPPA compliance story (NF-1 P3, L3-3).

The registry for `nf2-grant/1` is six identifiers:

| Identifier | Citation | Permissible use |
|---|---|---|
| `dppa-2721b-2` | 18 U.S.C. §2721(b)(2) | Motor vehicle or driver safety, theft, emissions, recalls, performance monitoring, parts and dealers |
| `dppa-2721b-3` | 18 U.S.C. §2721(b)(3) | Legitimate business need to verify accuracy of information or prevent fraud |
| `dppa-2721b-5` | 18 U.S.C. §2721(b)(5) | Research activities and statistical reports, personal information not published or redisclosed |
| `dppa-2721b-6` | 18 U.S.C. §2721(b)(6) | Insurance: claims investigation, antifraud, rating, underwriting |
| `dppa-2721b-11` | 18 U.S.C. §2721(b)(11) | Express consent of the individual to whom the information pertains |
| `dppa-2721b-13` | 18 U.S.C. §2721(b)(13) | Use for which the requester has demonstrated written consent of the individual |

### 7.2 The registry is statute-bound

- PU-3. A purpose identifier exists only where a cited permissible use exists in 18 U.S.C.
  §2721(b). The Foundation MUST NOT mint a purpose identifier with no statutory citation
  (NF-1 R-8). An unmoored purpose is a laundering channel for purpose limitation: it lets a
  requester describe an unpermitted use in permitted vocabulary.

- PU-4. Every registry entry MUST record its statutory citation and the document version that
  introduced it (NF-1 R-12). Identifiers MUST NOT be reused or repurposed; deprecation marks
  an entry historical and never frees the name (NF-1 R-10).

- PU-5. The presence of an identifier in this registry is a statement that the statute
  contains the permissible use, and **nothing more**. It is not a determination that a given
  requester qualifies under it, that the DPPA governs a given transaction, or that a state
  analogue is satisfied. Those are questions for the enforcement point and for counsel; NF-2
  supplies the vocabulary in which the answer is recorded.

### 7.3 Purpose does not change along a lineage

- PU-6. A delegated sub-grant MUST inherit its parent's `purpose` unchanged
  (`delegation_purpose_changed`). A delegate that could repurpose would defeat DPPA purpose
  limitation by the simple expedient of delegating to itself.

- PU-7. A renewal MUST carry the previous grant's `purpose` unchanged. A different purpose is
  a new consent decision and MUST be issued as a root grant (§9.4).

---

## 8. Counterparty class and key binding

### 8.1 Class, not identity

- CP-1. `counterparty_class` MUST be exactly one identifier from the NF-2 Counterparty Class
  registry. For `nf2-grant/1` the registry is eight identifiers:

      repair-independent    repair-franchised    dealer-licensed-ca    fleet-operator
      municipal-agency      academic-research    insurer               oem-warranty

- CP-2. An enforcement point MUST refuse to serve a requester outside the grant's class. The
  class check is independent of, and not cured by, a valid signature.

*Why a class and not a named entity.* The owner's decision is about *kinds* of counterparty,
which is the decision they are actually equipped to make; and a class-scoped grant does not
have to be reissued when an insurer changes corporate form, which is the failure mode of
identity-scoped consent (NF-1 P5). The identity of the specific holder is carried by
`counterparty_key`, which is a stronger binding than a name would have been (§8.2).

*Note on `insurer`.* It is admitted in the schema and is not the California entry wedge:
Proposition 103 and 10 C.C.R. §2632.5 mandate rating-factor order and constrain usage-based
insurance more tightly than most states (NF-WP-1 §9.9). Nothing in NF-2 turns on this; it is
recorded because a reader will otherwise assume the presence of the class implies a
recommended market.

### 8.2 Key, not name

- CP-3. A grant MUST be bound to the counterparty's raw Ed25519 public key, and MUST NOT be
  bound to a name, a domain, an account identifier, a company number, or any other assertion
  the presenter makes about themselves (NF-1 L3-3).

A name is an assertion the presenter makes about themselves; a verifier checking a name
checks whether the presenter *claims* to be the grantee. A key is a challenge the presenter
either answers or does not. Stolen grant plus no private key equals nothing — which is
exactly why a grant is not a secret and can be logged and shipped over an untrusted bearer
(E-5). Names also change, collide, and require a registry to resolve, and that registry then
becomes a trusted third party the architecture is trying not to need.

This is the doctrine's positive form: **authority must be proved, never inferred from a
name** (DOCTRINE, "Identifier, not credential"). The 2015 Jeep compromise and the 2023 "Web
Hackers vs. the Auto Industry" results were both access-control failures in which a public
name was accepted where proof of authority was required. NF-2 is written so that the
equivalent mistake has no encoding.

### 8.3 Proof of possession

- CP-4. An enforcement point MUST challenge the presenter for possession of the private half
  of `counterparty_key` in the **same session** as the request it authorizes, and MUST compare
  the proved key to `counterparty_key`. A mismatch MUST produce
  `counterparty_binding_mismatch`.

- CP-5. A verifier that is not supplied the presenter's proved key MUST NOT be read as having
  checked the binding. In the reference implementation, `verifyGrant()` performs the
  comparison only when `opts.presenterKey` is supplied, so an enforcement point that omits it
  can obtain `valid: true` on a grant it has not bound to anyone. **An enforcement point MUST
  supply the proved key on every authorization decision.** See §16 SEC-7 and Appendix E
  finding 3 — this is a fail-open-by-omission in an otherwise fail-closed interface, and it
  is the caller's obligation to close it.

- CP-6. The proof of possession MUST be bound to the request — by a server-supplied nonce, a
  channel binding, or an equivalent — so that a captured proof cannot be replayed against a
  different request. NF-2 does not specify the challenge protocol; it specifies that the
  comparison is mandatory and that the proof is per-session.

---

## 9. Duration and renewal

### 9.1 Expiry is mandatory

- TM-1. `expires_at` MUST be present, non-null, and strictly greater than `issued_at`. There
  is no perpetual grant, no null expiry, and no zero-length grant (`expiry_not_after_issue`).

- TM-2. Both timestamps MUST be integer Unix **seconds** and MUST be safe integers under
  IEEE-754 (|value| ≤ 2⁵³−1). A value outside the safe-integer range MUST be refused, because
  beyond it two distinct integers canonicalize to identical bytes, so a signature over one
  would authenticate the other (§12.2).

### 9.2 The 45-day cap

- TM-3. `expires_at − issued_at` MUST NOT exceed **3 888 000 seconds (45 days)**
  (`duration_exceeds_cap`; NF-1 L3-7).

The number is pinned to the Delete Act's 45-day deletion-request cadence, for two reasons,
and the second is the one that actually forces it:

- Every grant must face the owner at least as often as the erasure machinery runs. A grant
  that outlives a full deletion sweep is a standing authorization the owner never re-affirmed
  while the system was, on the same clock, asking whether they wanted their data gone at all.
- **Expiry is the fail-safe for revocation, not a convenience.** Revocation depends on the
  owner still holding the revocation key and on the revocation state being reachable. When
  either fails, the cap is the *entire* remaining bound on exposure, so it has to be short
  enough to be an acceptable worst case standing alone (NF-1 SEC-9; NF-4 K-1).

- TM-4. The cap is a **ceiling, not a default**. An implementation SHOULD issue the shortest
  grant that accomplishes the stated purpose; a diagnostics read for a single repair order
  wants hours, not weeks (NF-1 P7).

- TM-5. The cap MUST be enforced at construction and again at verification, and SHOULD be
  enforced a third time at the storage layer. A grant that outlives an erasure sweep is
  precisely the artifact the storage layer is the last place able to refuse.

- TM-6. NF-4 K-1 governs the relationship between this cap and the revocation staleness
  bound. They are five orders of magnitude apart by design and neither substitutes for the
  other: the staleness bound governs the normal case in which revocation works, and the cap
  governs the failure case in which it cannot.

### 9.3 The plausible-time window and clock skew

- TM-7. `issued_at` and `expires_at` MUST each fall within
  `[1 700 000 000, 4 000 000 000]` — approximately 2023-11-14 through 2096-10-02 —
  and a value outside it MUST be refused with `issued_at_implausible` /
  `expires_at_implausible`.

*Why a range test and not just a type test.* The millisecond/second unit error is not
hypothetical: passing a millisecond epoch where seconds are expected turns a 30-day grant
into an 80,000-year one, and every other check in the schema passes, because a millisecond
timestamp is a perfectly well-formed positive safe integer. A range test against a plausible
window is the only check that catches it (NF-1 SEC-11).

- TM-8. A verifier MUST treat a grant as expired when `now ≥ expires_at`. Expiry is not
  subject to skew tolerance in the permissive direction: a verifier MUST NOT extend the life
  of a grant to accommodate a slow clock.

- TM-9. A verifier MUST reject a grant whose `issued_at` exceeds `now + skew`
  (`issued_in_future`). The default skew tolerance is **300 seconds** and applies **only** to
  `issued_at`. The asymmetry is deliberate: tolerating a fast issuer clock costs nothing,
  while tolerating a fast *verifier* clock would extend authority past the instant the owner
  set.

- TM-10. `now` MUST be injectable by the caller for conformance purposes, and an assertion's
  decision path MUST NOT read the wall clock (NF-5 §4.4(2)). In the reference implementation
  this is `opts.now`; a PROTOCOL-profile implementation MUST expose the equivalent hook under
  NF-5 §4.5's conformance-interface constraints.

- TM-11. An implementation SHOULD source `now` from a monotonic, disciplined clock and SHOULD
  treat a clock it cannot trust as a reason to deny rather than to serve. A verifier whose
  clock is wrong in the permissive direction is a verifier that has silently lengthened every
  grant it evaluates.

### 9.4 Renewal

- TM-12. Renewal MUST mint a **new grant** with a fresh `grant_id`, fresh `issued_at` and
  `expires_at`, a fresh signature, and `renewal_of` set to the superseded grant's `grant_id`.

- TM-13. An implementation MUST NOT extend a grant by editing `expires_at` in place.
  `expires_at` is inside the signed bytes, so an edit produces a different object under the
  same `grant_id`: a verifier accepting either form would be accepting a duration the owner
  never signed, and the two forms have different commitments, so a revocation entry filed
  against one would miss the other (NF-5 NF5-NT-009; NF-4 SEC-2).

- TM-14. A renewal may only **narrow**. Its `fields` MUST be a subset of the previous grant's;
  its `purpose`, `counterparty_class` and `counterparty_key` MUST be unchanged; its
  `delegation_depth` MUST NOT exceed the previous grant's. Anything broader is a new consent
  decision and MUST be issued with the root-grant path, because "renew" is what an owner
  clicks without reading.

- TM-15. Renewal recomputes the pseudonym under the current epoch rather than copying it, so
  a renewal issued after a rotation carries a fresh pseudonym.

- TM-16. Renewal does **not** revoke the superseded grant. Revocation is NF-4's mutable state.
  The caller MUST revoke the superseded `grant_id`, or let it expire, in the same transaction
  that stores the renewal; NF-4 SEC-2 states the consequence of not doing so.

- TM-17. A **delegated** grant MUST NOT be renewed. A delegate has no standing to extend its
  own authority; the delegator re-mints against a live parent (§11), which is the only path
  by which a delegate's authority is extended (NF-5 NF5-DD-009).

- TM-18. Renewal requires the VIN and the salt and is therefore an `owner-agent`/`broker`
  operation. A counterparty MUST NOT be able to invoke it.

- TM-19. An implementation MUST NOT renew from an unsigned grant. `renewal_of` pointing at an
  object that was never issued is a supersession claim with nothing under it. See Appendix E
  finding 4: the reference implementation does not currently enforce this, while the
  structurally analogous delegation path does.

---

## 10. The revocation key reference

- RK-1. `revocation_key_id` MUST be the base64url rendering of a domain-separated SHA-256
  thumbprint of the owner-held revocation **public** key:

      revocation_key_id = base64url( SHA-256( UTF-8("nf2-revocation-key-id:v1:") || raw_pk ) )

  where `raw_pk` is the 32 raw bytes of the Ed25519 public key. The output is 43 characters.

- RK-2. The domain separator is REQUIRED. Without it the digest could be mistaken for, or
  replayed as, any other SHA-256 in the system — notably a grant commitment, which is also a
  43-character base64url SHA-256 output.

- RK-3. A grant MUST carry the **identifier**, never the key. An identifier lets the owner
  rotate the revocation key without reissuing live grants, and it means the grant carries
  nothing usable. NF-4 §3.1 requires the revocation *record* to carry the public key and
  requires the verifier to recompute the thumbprint and compare, which is what binds the two
  objects.

- RK-4. `revocation_key_id` MUST identify a key held by the **owner**. It MUST NOT be, and
  MUST NOT be the thumbprint of, `counterparty_key`; both forms MUST be checked and both
  MUST produce `revocation_key_held_by_counterparty`. The raw-equality case catches the naive
  mistake of pasting a key into the identifier member; the thumbprint case catches the actual
  attack, which is an operator or a persuasive counterparty arranging for the grantee's own
  key to be the nominal revocation authority. A revocation key the grantee controls is not a
  revocation key — it is a promise, and a grantee will not exercise it.

- RK-5. `revocation_key_id` MUST NOT identify a key held by the broker, the Foundation, or
  any operator. A verifier MUST accept a caller-supplied list of operator-held key
  identifiers and MUST reject a grant naming one, with `revocation_key_forbidden`. This is
  Refusal 3 made enforceable rather than asserted: the caller supplies the identifiers it
  actually operates, so the claim is tested (DOCTRINE, "Where the doctrine is enforced"; NF-1
  L3-6, S-4).

- RK-6. An `owner-agent` MUST use a **distinct revocation key per (vehicle,
  `counterparty_class`) lineage**. `revocation_key_id` is the one long-lived, owner-scoped
  identifier NF-2 places in the clear inside a grant; reusing one key across classes hands
  two counterparties a stable join key over one vehicle and voids the per-audience pseudonym
  entirely (NF-4 A-15, SEC-9; §16 SEC-8 below).

- RK-7. RK-6 is not enforceable from a single grant, and a conformant broker cannot enforce it
  on the owner's behalf. A broker MAY detect it and SHOULD report as a finding any case in
  which one `revocation_key_id` appears across grants of differing `counterparty_class` for
  what it believes to be one vehicle. A broker MUST NOT disclose the revocation public key to
  a counterparty (NF-4 A-13).

- RK-8. A delegated sub-grant MUST carry its parent's `revocation_key_id` unchanged
  (`delegation_revocation_key_changed`). A child bearing its own revocation key is a child the
  owner cannot cut without revoking the parent and every sibling with it (§11.3; NF-5
  NF5-DD-008 case d).

---

## 11. Delegation

### 11.1 Delegation is not transfer

A transfer moves a capability from one holder to another: the original holder loses it, the
new holder gains it, and the owner's decision — which was about a specific counterparty — is
silently reassigned to a party they never evaluated. That is what makes a capability an
asset, and an asset is a thing with a market (§3.2). NF-2 has no such operation and MUST NOT
acquire one.

Delegation is the opposite shape in the three ways that matter:

- **Additive and bounded.** The parent survives unchanged. The child can only narrow: a
  subset of the fields, the same purpose, an expiry no later, a delegation depth exactly one
  lower. Authority strictly decreases along the chain, so no sequence of delegations can
  produce more access than the owner granted once.
- **Attributable.** `parent_grant_id` records the edge, so the owner can see the whole
  subtree hanging off their grant.
- **Cascade-revocable.** Revoking the parent kills every descendant, because NF-4 walks
  `parent_grant_id` (NF-4 §5.3). The owner keeps a single lever over arbitrarily many
  downstream holders, and because the child keeps the owner's `revocation_key_id` (RK-8) the
  owner can also cut one branch without disturbing the rest.

- DL-1. Delegation MUST mint a new grant. It MUST NOT modify the parent, and the parent's
  bytes MUST be unchanged by the operation.

- DL-2. A sub-grant MUST NOT be minted from an **unsigned** parent: the authority being passed
  on would be unproven.

- DL-3. A sub-grant MUST NOT be minted from a parent with `delegation_depth` of 0. There is no
  operation that adds depth, and a depth-0 child of a depth-0 parent is not a harmless
  no-authority addition — it adds a holder the owner never evaluated, which is the thing being
  prevented (NF-5 NF5-DD-002).

- DL-4. Refusal MUST occur at **minting**, not deferred to verification. A grant that exists
  but never verifies is an artifact in a database, presented to a counterparty as authority,
  that will be honoured by any enforcement point with a bug (NF-5 NF5-DD-004).

### 11.2 Depth

- DL-5. `delegation_depth` is a non-negative safe integer. `0` means this grant MUST NOT be
  delegated. `n > 0` means up to `n` further hops, each decrementing by exactly one.

- DL-6. `MAX_DELEGATION_DEPTH` is **2**. A root grant MUST NOT be issued with a depth above
  it, and any grant carrying a greater depth MUST be rejected with `delegation_depth_invalid`.

Two hops covers the real relationship — a fleet operator delegating to the maintenance
contractor that actually turns the wrench — and stops there. Each additional level adds a
party the owner never chose and lengthens the chain revocation must walk before the last
holder actually loses access (NF-1 SEC-10). Depth is cheap to raise later and expensive to
have been wrong about.

- DL-7. A child's `delegation_depth` MUST equal `parent.delegation_depth − 1` exactly. A
  same-depth child MUST be rejected with `delegation_depth_not_decremented`. Strict decrease
  is what makes the bound a bound: a same-depth child looks harmless and permits an unbounded
  chain, which means unbounded parties and an unbounded revocation walk.

- DL-8. `delegation_depth` MUST be inside the signed bytes, and the depth check MUST be
  independent of signature validity. A delegator MUST NOT be able to buy depth with a correct
  signature, and a holder MUST NOT be able to edit depth without invalidating the signature
  (NF-5 NF5-DD-007).

- DL-9. Depth MUST NOT be increased by any operation, published or unpublished — no refresh,
  upgrade, reissue, or administrative path may return a grant at a greater depth than the one
  submitted (NF-5 NF5-DD-010).

- DL-10. **Depth is bounded; fan-out is not.** NF-2 places no limit on the number of siblings
  minted from one parent. Breadth is governed by attributability and cascade instead: every
  sibling records the same `parent_grant_id`, so the owner sees the whole subtree and one
  revocation cuts all of it. An implementation MUST NOT impose a fan-out limit and represent
  it as an NF-2 requirement (NF-5 NF5-DD-005).

### 11.3 Narrowing invariants

- DL-11. A sub-grant MUST satisfy every one of the following against its parent. Each is
  checked independently and each has its own code:

  | Axis | Requirement | Code on violation |
  |---|---|---|
  | Fields | `child.fields ⊆ parent.fields` | `delegation_fields_broadened` |
  | Purpose | identical | `delegation_purpose_changed` |
  | Expiry | `child.expires_at ≤ parent.expires_at` | `delegation_expiry_extends_parent` |
  | Revocation key | identical | `delegation_revocation_key_changed` |
  | Pseudonym | identical object, member for member | `delegation_pseudonym_mismatch` |
  | Depth | exactly `parent − 1` | `delegation_depth_not_decremented` |
  | Parent id | `child.parent_grant_id == parent.grant_id`, and ≠ child's own id | `delegation_parent_mismatch`, `parent_grant_id_malformed` |

- DL-12. The child carries the parent's `vehicle_pseudonym` **verbatim, including the
  parent's audience**. This looks like a defect and is not one. The delegator does not hold
  the owner's salt and therefore cannot compute a fresh per-audience pseudonym — and must not
  be able to. A fresh pseudonym would mint a linkability domain the owner never authorized;
  inheriting the parent's means the delegate's ability to correlate is bounded by the
  delegator's, which is the correct semantics for a controller/processor pair (NF-5
  NF5-DD-008 case e).

- DL-13. Consequently, a sub-grant's `vehicle_pseudonym.audience` will differ from its
  `counterparty_class` whenever the delegate is in a different class, and the root-grant
  equality check of PS-9 MUST NOT be applied to a grant with a non-null `parent_grant_id`.

- DL-14. Pseudonym equality MUST be tested over the canonicalization of the two
  `vehicle_pseudonym` objects, not by reference or by comparing a single member. That is
  exactly the equality the signature cares about, and it is the cheapest correct deep
  comparison available.

- DL-15. Delegation MUST NOT introduce a field outside the closed vocabulary, and MUST NOT
  introduce a Non-Transactable identifier, even where the parent's field set is unrelated
  (NF-5 NF5-NT-008). "Strictly decreases" must also mean "cannot be entered from outside": the
  delegator signing a sub-grant is not the owner and has no standing to widen the class of
  data at issue.

### 11.4 The parent supplies the signer key

- DL-16. A sub-grant MUST be signed by the **delegator**, whose key is the parent's
  `counterparty_key`. A chain therefore verifies itself up to its root, and only the root
  requires an out-of-band owner key (SH-11).

- DL-17. A delegated grant MUST NOT be verifiable from its leaf alone. A verifier presented a
  sub-grant with no parent MUST return invalid with `delegation_parent_missing`; with an
  unrelated parent, `delegation_parent_mismatch`; with an unsigned parent, invalid citing the
  parent's unsigned state (NF-5 NF5-DD-006).

- DL-18. A verifier MUST verify **every link** of a chain, not only the leaf. Establishing
  that a leaf is correctly signed by its parent's `counterparty_key` says nothing about
  whether the parent itself is authentic; the root's signature MUST be checked against the
  out-of-band owner key, and each intermediate link MUST be checked in turn. In the reference
  implementation, `verifyGrant()` checks the structural lineage invariants and the leaf's
  signature and requires the caller to iterate — see Appendix E finding 5.

- DL-19. That a chain cannot be verified from its leaf is a deliberate property, not a
  defect: it means an enforcement point must hold or fetch the whole chain, which is the same
  walk revocation makes, so the two cannot drift apart (NF-5 NF5-DD-006).

- DL-20. Minting a sub-grant requires no VIN and no salt, and is therefore an operation a
  counterparty can perform on its own. That is intended, and it is bounded by DL-3, DL-6,
  DL-7 and DL-11: everything a delegate can produce is narrower than what it holds.

---

## 12. Canonicalization and signature

### 12.1 Canonicalization is a security property, not a formatting preference

An EdDSA signature is a signature over **bytes**. A Consent Grant is a JSON object. Unless
the issuer and every verifier serialize that object to byte-for-byte identical output, "the
signature verifies" is a statement about one serializer rather than about the grant.

There are two failure directions and they are not equally bad.

**One object, two byte strings.** The benign reading is an availability bug: the issuer's
signature fails for everyone else. The real cost is elsewhere. One semantic grant with two
canonical forms has **two commitments**, and NF-4 keys revocation state by commitment
(NF-4 §7.3) — so a revocation entry filed against the form the owner saw does not match the
form the counterparty presents. A serialization latitude has become a revocation bypass. This
is why the closed key set (SH-3), the explicit nulls (SH-2), and the field ordering rule
(FV-7) are all stated as canonicalization requirements rather than as schema tidiness.

**Two objects, one byte string.** This is forgery: a signature over one object authenticates
another. The JavaScript data model supplies several ready-made instances —
`-0` serializing as `0`; two distinct integers above 2⁵³−1 collapsing onto one double;
`undefined` members silently dropped; array holes rendered as `null`; `Date` coerced through
`toJSON`; getters invoked; symbol keys ignored; and, most mundanely, a grant reconstructed
from a database row in a different column order serializing differently from the grant that
was signed.

- SG-1. Every signature and every digest in this document MUST be computed over the RFC 8785
  (JCS) canonicalization of the relevant object, UTF-8 encoded. An implementation MUST NOT
  sign or hash `JSON.stringify` output, a database representation, a pretty-printed form, or
  a received byte sequence.

- SG-2. A canonicalizer MUST **reject, never normalize**. Every case in which a value has no
  faithful canonical form MUST be a hard error. Normalization is a many-to-one mapping and it
  destroys the caller's ability to know which value was signed.

- SG-3. Canonicalization MUST be depth-bounded. It is recursive and reachable from any
  untrusted request body, so unbounded nesting is a stack overflow, not merely a wrong answer
  (NF-1 SEC-5). The reference profile bounds depth at 64; a Consent Grant nests three levels.

- SG-4. Canonicalization MUST reject cyclic structures, non-plain objects (class instances,
  `Date`, `Map`, `Set`, `RegExp`, typed arrays, boxed primitives), symbol-keyed properties,
  non-enumerable properties, accessor properties, sparse arrays, arrays carrying non-index own
  properties, `undefined`, `BigInt`, functions, `NaN` and infinities.

### 12.2 The NF profile of RFC 8785

`nf2-grant/1` follows RFC 8785 exactly — object keys sorted by UTF-16 code unit, no
insignificant whitespace, the seven two-character escapes, lowercase `\u00xx` for remaining
C0 controls, ECMAScript `Number::toString` for numbers — with **two deliberate deviations,
both in the fail-closed direction**. Both are normative for `nf2-grant/1`, because a
canonicalizer that differs from them produces different bytes and therefore a different
signature.

- SG-5. **Negative zero MUST be rejected.** RFC 8785 inherits the ECMAScript number
  serialization, under which `-0` becomes `"0"`. That is a lossy normalization: two distinct
  inputs produce one output, and the caller cannot afterwards tell which was signed. A
  conforming NF canonicalizer throws instead and requires the caller to normalize
  deliberately.

- SG-6. **Lone surrogates MUST be rejected.** A JavaScript string is a sequence of UTF-16
  code units and may contain an unpaired surrogate, which is not a Unicode scalar value and
  therefore has no UTF-8 encoding — while RFC 8785 output is defined as UTF-8 bytes. Historic
  ES6 `JSON.stringify` emitted such code units raw, producing invalid UTF-8; ES2019
  well-formed stringify escapes them as `\udXXX`. Both behaviours exist in the wild, so the
  same input canonicalizes two ways depending on runtime age, and a value inside signed bytes
  that canonicalizes two ways is a value whose signature means two things. NF-2 refuses the
  input rather than picking a winner (NF-5 NF5-NT-005).

- SG-7. Any security-relevant integer — timestamps, `delegation_depth`, `epoch` — MUST be
  asserted to be a safe integer before it enters a signed object. Past 2⁵³−1, consecutive
  integers collapse onto the same double, so an attacker can supply a distinct value that
  canonicalizes identically to an authorized one (NF-5 NF5-DD-001).

- SG-8. String coercion MUST NOT occur anywhere in the pipeline. `"2"` and `2` canonicalize
  differently, so a coerced value yields a second commitment for one semantic grant (NF-5
  NF5-DD-001).

### 12.3 The signing input

- SG-9. The signing input is the UTF-8 encoding of the RFC 8785 canonicalization of the grant
  with the `signature` member **removed** — not set to null, removed. The remaining thirteen
  members are present in full, each with its value, including explicit nulls where they apply.

- SG-10. The signing input MUST be constructed from the closed key set of SH-1 and MUST NOT
  be constructed by deleting a member from an arbitrary received object. An implementation
  MUST refuse to compute a signing input for a structurally invalid grant.

- SG-11. There is **no external domain tag** on the signing input. The type binding is
  already inside the signed bytes as the `v` member, so the bytes cannot be reinterpreted as a
  different kind of object without changing them, and a future schema version must change `v`,
  which changes every signature. Adding a second tag outside the canonical bytes would create
  a second thing that has to agree with the first, and a place for the two to disagree.

### 12.4 The signature

- SG-12. `signature` MUST be an Ed25519 (EdDSA over edwards25519, RFC 8032, PureEdDSA)
  signature over the SG-9 signing input, rendered base64url unpadded, 86 characters.

- SG-13. The suite is pinned by `v` and MUST NOT be negotiated in band (SH-13). A verifier
  MUST NOT accept a signature produced under any other algorithm, and an implementation MUST
  refuse to sign with a key of another algorithm rather than emitting a grant no verifier in
  the system can ever check.

- SG-14. All cryptography MUST go through WebCrypto (`crypto.subtle`). An implementation MUST
  NOT hand-roll a curve or a cipher (NF-1 I-3).

- SG-15. Ed25519 MUST be obtained by feature detection: try the standard
  `{ name: 'Ed25519' }` and fall back to the legacy Cloudflare Workers name
  `NODE-ED25519`. The probe MUST be a key generation, not an import: `importKey('raw', …)`
  accepts arbitrary 32-byte input on some builds and defers validation to verify time, so a
  successful import would not prove the algorithm is supported. A runtime in which neither
  name resolves MUST fail rather than substitute another signature scheme, and NF-5 §4.3
  requires every signature-dependent assertion in such a run to report INCONCLUSIVE, which
  counts as FAIL.

- SG-16. Re-signing an already-signed grant MUST be refused. The only legitimate reasons to
  want a second signature over the same content are key rotation and repudiation-shopping, and
  both are correctly served by minting a new grant.

- SG-17. Signing MUST return a new object. Mutating the input in place leaves a caller holding
  two references to one grant that disagree about whether it is signed.

### 12.5 Key material is rooted in the owner's control

- SG-18. The signer of a **root** grant MUST be the owner, and the signing key MUST be one the
  owner controls. The signer of a **sub-grant** is the delegator (DL-16).

- SG-19. The Foundation MUST NOT hold an owner signing key, a revocation key, or a pseudonym
  salt, and MUST NOT be a signer of, or a required participant in, any grant (NF-1 S-4, B5).

- SG-20. Where a deployment holds owner signing key material custodially — as the reference
  broker does, because a Workers isolate cannot keep a non-extractable `CryptoKey` between
  requests — the deployment MUST state so plainly, MUST seal the material at rest under a
  secret that is not in the same store, and MUST NOT hold the **revocation** key under any
  circumstances. The revocation key is the key that matters for the owner's control: RK-5
  makes a grant naming an operator-held revocation key fail verification, so the separation is
  tested rather than promised.

- SG-21. An owner signing key MUST be per (vehicle, `counterparty_class`) (SH-12). A single
  per-vehicle signing key bounds a compromise to a whole vehicle rather than to one
  linkability domain, and is a cross-class join key besides.

### 12.6 The grant commitment

- SG-22. The grant commitment is:

      commitment = base64url( SHA-256( UTF-8( "nf2-grant-commitment:v1:" || JCS(grant) ) ) )

  where `JCS(grant)` is the canonicalization of the **complete signed grant**, signature
  included. The output is 43 characters. The domain separator ends in `:` and canonical JSON
  begins with `{`, so the boundary is unambiguous without a length prefix.

- SG-23. The commitment is the **only** artifact of a grant that MAY cross onto an immutable
  ledger (NF-1 B3; DOCTRINE Refusal 2). Everything else — pseudonym, field set, holder key,
  timestamps, lineage — stays in mutable, deletable storage.

- SG-24. The commitment MUST cover the signature. Because the grant does not carry the
  signer's public key (SH-10), the payload alone does not bind the issuer: two different
  owners could in principle produce identical payloads, and the signature is the only member
  that distinguishes them. A commitment excluding it would be ambiguous about which grant it
  commits to, and a revocation entry keyed by it could match a grant the owner never issued.

- SG-25. An unsigned grant MUST NOT be committed (SH-9, SG-24).

- SG-26. Commitments MUST be compared with a constant-time comparison wherever the comparison
  is on an authorization path.

- SG-27. The commitment is not personal information and nothing is derivable from it: it
  commits to a pseudonym that is itself a keyed HMAC under an owner-held salt, so destroying
  the salt destroys the linkage even for a party holding both the digest and a candidate VIN
  (PS-14). This is the argument that permits the commitment to be anchored at all, and it
  holds only for as long as PS-13 holds.

- SG-28. NF-4 keys revocation state by commitment. The consequence NF-4 states at C-22 is
  restated here because it is an NF-2-shaped trap: **non-membership of the revocation tree is
  not authorization.** A modified grant looks un-revoked precisely because its commitment is
  different, so it must be caught by an issuance check, not by a revocation check.

---

## 13. Verification

### 13.1 The verdict

- VF-1. A `verifier` MUST return a structured verdict of the form
  `{ valid: boolean, reasons: string[] }`, where `valid` is true if and only if `reasons` is
  empty.

- VF-2. A verifier MUST collect **every** failure rather than stopping at the first. NF-5
  asserts *which rule fired*; a verifier returning a single opaque "invalid" is untestable, and
  an untestable rule is an unenforced rule (NF-1 R-4).

- VF-3. A verifier MUST NOT throw on any input. A verifier that throws on malformed input is a
  denial-of-service surface reachable from any untrusted request body (NF-1 L3-9). An
  unforeseen internal error MUST become a reason with code `internal` and MUST make the verdict
  invalid.

- VF-4. A verifier MUST fail closed on missing inputs. With no verifying key available, the
  verdict is invalid with `verifier_key_missing`. There MUST be no path through a verifier that
  returns `valid: true` over an unchecked signature (NF-1 L3-9).

- VF-5. Structural validity MUST be evaluated independently of, and its failure MUST NOT be
  cured by, cryptographic validity. A correctly signed grant naming a forbidden field is
  invalid, and it is invalid on the field ground, not merely on a signature ground (NF-5
  NF5-NT-007).

### 13.2 Evaluation order

- VF-6. A verifier MUST evaluate in this order, and MUST NOT evaluate a later stage on an
  object that failed the shape stage, because reporting "expired" for something that is not a
  grant is noise:

  1. **Shape** — plain object; closed key set; all members present; no holder-mutation member.
  2. **Structure** — schema version; identifier lengths and charsets; pseudonym sub-object;
     field vocabulary, non-transactability and ordering; purpose; counterparty class; key and
     thumbprint shapes; timestamp shape, plausibility, ordering and duration cap; delegation
     depth range; lineage identifier shapes and self-reference; signature shape.
  3. **Temporal** — expiry against `now`; `issued_at` against `now + skew`.
  4. **Binding** — presenter key against `counterparty_key` (CP-5); `revocation_key_id`
     against the caller-supplied operator-held list.
  5. **Revocation-key sanity** — the two grantee-key checks of RK-4, computed from the grant
     alone.
  6. **Lineage** — for a delegated grant, the parent-supplied invariants of DL-11.
  7. **Signature** — Ed25519 over the SG-9 signing input under the expected signer key.
  8. **Revocation state** — only if the caller supplies it. See VF-8.

- VF-7. Cheap structural checks MUST run before any Ed25519 verification, so that malformed
  input is rejected without spending a signature verification.

### 13.3 Verification is not authorization

- VF-8. `valid: true` means the grant is well formed, in vocabulary, in date, correctly bound
  and correctly signed. It does **not** mean access is authorized. Revocation is mutable state
  and lives in NF-4's store; a hash-committed revocation state is a commitment, not the record.

- VF-9. An enforcement point MUST NOT treat a positive verdict as permission to serve data
  without having read current revocation state in the **same request** (NF-1 L3-10, B4).

- VF-10. The boolean revocation channel NF-2 offers a verifier cannot distinguish "checked,
  not revoked" from "not checked" — both present as a grant that verifies. NF-2 states the
  hazard; **NF-4 §1.3 and F-6 close it** by making a verified grant one of four required inputs
  to an authorization predicate. An implementation MUST satisfy NF-4's predicate and MUST NOT
  rely on NF-2's verdict alone.

- VF-11. A verifier that is handed a positive revocation result MUST report it as
  `revoked` and MUST make the verdict invalid, regardless of every other property of the grant.

### 13.4 The reason-code vocabulary

- VF-12. A verifier MUST emit these stable codes. Each reason is the code, a colon, and a
  human-readable detail; a conformance assertion matches on the code, never on the detail.
  Codes MUST NOT be renamed or reused for a different condition, and a verifier MAY add codes
  for local conditions provided it does not reuse a registered one (NF-1 R-5, R-6).

| Code | Condition |
|---|---|
| `shape` | Not a plain object |
| `unknown_field` | A member not in the closed key set (SH-3) |
| `missing_field` | A member of the closed key set absent (SH-2) |
| `transferable_field_present` | A holder-mutation member present (CG-7) |
| `schema_version_unsupported` | `v` is not `nf2-grant/1` |
| `grant_id_malformed` | `grant_id` is not 16 bytes base64url |
| `pseudonym_malformed` | `vehicle_pseudonym` shape, member set, `value`, `epoch` or `audience` invalid |
| `pseudonym_derivation_unsupported` | `derivation` is not `nf2-pseudonym:v1` |
| `pseudonym_audience_mismatch` | Root grant whose audience ≠ `counterparty_class` (PS-9) |
| `fields_invalid` | Field set empty, non-array, non-string member, duplicate, out of vocabulary, or naming a Non-Transactable Class |
| `fields_not_canonical_order` | Field set not sorted by UTF-16 code unit (FV-7) |
| `purpose_unknown` | `purpose` is not a registered DPPA identifier |
| `counterparty_class_unknown` | `counterparty_class` is not a registered class |
| `counterparty_key_malformed` | Not a raw 32-byte Ed25519 public key, base64url |
| `revocation_key_id_malformed` | Not a 32-byte thumbprint, base64url |
| `issued_at_malformed` / `expires_at_malformed` | Not a safe integer |
| `issued_at_implausible` / `expires_at_implausible` | Outside the plausible-time window (TM-7) |
| `expiry_not_after_issue` | `expires_at ≤ issued_at` |
| `duration_exceeds_cap` | Lifetime above 3 888 000 s (TM-3) |
| `delegation_depth_invalid` | Not a safe integer in `[0, MAX_DELEGATION_DEPTH]` |
| `parent_grant_id_malformed` | Not null and not a `grant_id`, or equal to this grant's id |
| `renewal_of_malformed` | Not null and not a `grant_id`, or equal to this grant's id |
| `signature_malformed` | Present but not a 64-byte Ed25519 signature, base64url |
| `expired` | `now ≥ expires_at` |
| `issued_in_future` | `issued_at > now + skew` (TM-9) |
| `counterparty_binding_mismatch` | Presented key ≠ `counterparty_key` (CP-4) |
| `revocation_key_forbidden` | `revocation_key_id` is an operator-held key (RK-5) |
| `revocation_key_held_by_counterparty` | `revocation_key_id` is, or is the thumbprint of, `counterparty_key` (RK-4) |
| `delegation_parent_missing` | Delegated grant presented with no parent (DL-17) |
| `delegation_parent_mismatch` | Supplied parent is malformed, unsigned, unrelated, or supplied for a root grant |
| `delegation_depth_not_decremented` | Child depth ≠ parent depth − 1 (DL-7) |
| `delegation_fields_broadened` | Child field set not a subset of the parent's |
| `delegation_purpose_changed` | Child purpose ≠ parent purpose |
| `delegation_expiry_extends_parent` | Child `expires_at` > parent's |
| `delegation_revocation_key_changed` | Child `revocation_key_id` ≠ parent's (RK-8) |
| `delegation_pseudonym_mismatch` | Child pseudonym ≠ parent pseudonym (DL-12) |
| `signature_missing` | `signature` is null (SH-9) |
| `verifier_key_missing` | No verifying key supplied, or it could not be imported (VF-4) |
| `signature_invalid` | Ed25519 verification failed over the canonical grant |
| `revoked` | The caller-supplied NF-4 revocation state says the grant is revoked |
| `internal` | Verification aborted; fail closed (VF-3) |

- VF-13. These codes populate the NF-5 Verification Reason Code registry (NF-1 §9.2), which is
  First Come First Served and append-only. NF-2 is the document that introduces them and every
  entry MUST record that provenance (NF-1 R-12).

---

## 14. Storage profile

- ST-1. A grant, its pseudonym, its field set, its holder key, its timestamps, its lineage,
  the pseudonym salt, and the owner's key material MUST live in **mutable, deletable storage**
  (NF-1 L3-8, B3). The reference deployment uses D1/SQLite.

- ST-2. The **only** value that MAY cross onto an immutable ledger is the grant commitment
  (SG-23). No payload-shaped member exists on the ledger side, and the constraint is enforced
  by schema rather than by policy.

- ST-3. There MUST be no soft delete. A tombstoned row is a retained row wearing a flag, and
  an erasure regime that leaves the data in place has not erased anything. `DELETE` is a
  first-class compliance primitive in this design, not a maintenance operation.

- ST-4. There MUST be no append-only table, no history table populated by a trigger, and no
  row-copying trigger anywhere in the schema. A history table built by a trigger is an
  immutable ledger built by accident, and it will be discovered during a deletion audit rather
  than during review.

- ST-5. There MUST be no plaintext VIN column. A VIN transits requests; it never rests. A
  blind index — an HMAC of the VIN under an operator-held key — is the conforming way to match
  a presented VIN to an enrolment, and it yields nothing in the other direction.

- ST-6. The stored canonical grant is **authoritative**. Any denormalized column derived from
  it exists for indexing only and MUST NOT be used for a security decision. If a copy and the
  canonical payload disagree — a bad migration, a hand-edited row, a bug — the copy is wrong by
  definition, and code that trusted a denormalized `expires_at` would be honouring a duration
  the owner never signed.

- ST-7. A verifier MUST re-canonicalize and re-check the signature from the stored canonical
  payload on every authorization decision. It MUST NOT cache a verdict without the state that
  verdict was true under, and MUST re-derive on any change to that state (NF-1 L4-1).

- ST-8. There MUST be no `revoked` flag on a grant row. Revocation state lives in its own
  store, so revoking is an insert rather than an update to the grant, which keeps the signed
  payload untouched and makes "was this revoked" a question with one answer in one place.

- ST-9. There MUST be no OEM credential column of any kind — no access token, refresh token,
  password, client secret, cookie or session for a manufacturer's telematics account. Layer 3
  exists so that the accessing party never obtains the owner's credentials, and the broker is
  not exempt from that (NF-1 L2-4, B2). There is no column, so there is no migration that
  quietly starts holding one.

- ST-10. There MUST be no price, amount, currency, invoice, escrow, token, balance or
  settlement column (CG-8; NF-1 L5-2).

- ST-11. There MUST be no geolocation, biometric or in-cabin A/V column at any precision.
  Those classes have no field identifier, so no grant can name them and no row can hold them
  (FV-9, FV-13).

- ST-12. All storage access MUST use parameterized prepared statements. User input MUST NEVER
  be interpolated into SQL (NF-1 I-4).

- ST-13. Type affinity MUST be constrained (SQLite `STRICT`, or the equivalent). Every
  base64url value in this schema is inside a signature or a commitment; a value that changes
  type between write and read changes bytes, and changed bytes mean a signature that no longer
  verifies or a revocation entry that no longer matches.

- ST-14. Erasure MUST cascade from the vehicle enrolment through the salt, the key material,
  the grants, the lineage edges and the revocation records, and MUST destroy the salt (PS-15).
  What survives an erasure is at most a commitment already anchored off-box, which is
  unlinkable to a vehicle or a person once the salt is gone (SG-27).

---

## 15. The agentic three-layer separation (NF-WP-1 §6.4)

### 15.1 Three layers, three different kinds of thing

An owner who wants an automated system to act for them creates a stack of three distinct
participants, and the whole of §6.4 is the insistence that they are not interchangeable:

| Layer | Supplies | Legal status |
|---|---|---|
| **Human owner** (or other legal person) | **Purpose and consent.** The decision about who, what, why, how long. | A legal person. The principal. |
| **Agent-wrapper LLC** — one series per agent, under the Bayern memberless-LLC construction, organized under Wyoming's series-LLC provisions | **Legal personality.** A person that can hold, be bound by, be sued over, and be liable for the grant. | A legal person. The counterparty of record. |
| **AI agent** | **Execution only.** Selecting requests, presenting the grant, consuming the projection. | **None.** Not a person, not a party, not a principal, not an agent in the legal sense. |

- AG-1. The human owner, or another legal person, MUST supply purpose and consent. An
  automated system MUST NOT originate a consent decision, select a DPPA purpose on the owner's
  behalf, or widen a field set.

- AG-2. Legal personality MUST be supplied by a wrapper that is a legal person. In the
  reference construction that is one series of a Wyoming series LLC per agent, so that each
  agent's liability, contracts and grants are segregated from every other agent's.

- AG-3. The AI agent supplies **execution only** and MUST NOT be a party to anything.

### 15.2 The grant is held by the wrapper, never by the agent

- AG-4. `counterparty_key` MUST be a key held by a **legal person**. Where a stack of the
  §15.1 shape is the counterparty, `counterparty_key` is the **wrapper's** key and the wrapper
  is the counterparty of record.

- AG-5. `counterparty_class` MUST be the class the **wrapper** qualifies under, not a class
  invented for automated systems. There is no `ai-agent` counterparty class, and NF-2 MUST NOT
  acquire one: a class exists so the owner can decide about *kinds of counterparty*, and
  "software" is not a kind of counterparty — it is a way a counterparty operates.

- AG-6. **Agents exercise grants; they never originate them.** An automated system MAY
  present a grant, prove possession of the wrapper's key on the wrapper's behalf, and consume
  the resulting projection. It MUST NOT request issuance in its own name, sign a root grant,
  mint a delegated sub-grant in its own name, renew, or revoke.

- AG-7. A grant MUST NOT contain any member identifying an automated system, its model, its
  operator, its runtime, or its instance. There is no such member in the closed key set, and
  SH-5 forecloses adding one. Where a deployment needs to attribute a request to a particular
  automated executor, that attribution lives **outside** the grant, keyed by `grant_id`, in
  mutable storage — and it is the wrapper's record about its own operations, not a term of the
  owner's consent.

- AG-8. Where an automated executor genuinely requires its own key material, the conforming
  encoding is a **delegated sub-grant to another legal person's key** under §11, consuming a
  hop of the delegation budget and inheriting every narrowing invariant. It is not a new class
  of holder, and it is not a second key on one grant.

- AG-9. `MAX_DELEGATION_DEPTH` applies unchanged. An agent stack does not get extra hops.

- AG-10. NF-1's `owner-agent` **role** is a software role that holds the owner's keys. It is
  not an "agent" in the §6.4 sense and confers no legal personality on anything. The
  terminological collision is unfortunate and is recorded here so that a reader does not infer
  from the role name that an automated system may originate consent.

### 15.3 Why the separation is required and not merely tidy

**AI agents have no legal personhood in any U.S. jurisdiction.** Nothing in this
architecture can create it, and a protocol that binds authority to a party with no legal
status has bound it to nothing: there is no one to hold to the purpose limitation, no one to
sue for exceeding it, and no one from whom a regulator can obtain the record.

The doctrinal reason is narrower and sharper than a general appeal to personhood.
Restatement (Third) of Agency §1.01 makes agency a relationship that arises when a principal
**manifests assent** that another act on the principal's behalf and subject to the
principal's control, and the agent **manifests assent or otherwise consents** so to act. The
requirement is mutual. An AI system cannot manifest assent in the legal sense — it has no
volition the law recognizes and no capacity to be bound — so the relationship does not form,
and the "agent" is a tool rather than an agent.

The wrapper is what supplies the missing person. It can manifest assent, it can be bound, it
can be liable, and it can hold a capability. The automated system then operates **the
wrapper's** capability under the wrapper's control, which is the ordinary law of using a tool
and needs no novel doctrine at all.

- AG-11. An implementation MUST NOT represent an automated system as a party to a Consent
  Grant, as a holder of one, as an agent of the owner, or as capable of consenting on behalf
  of anyone.

- AG-12. An implementation MUST be able to name, for every grant it holds or serves, the
  **legal person** that holds it. A grant that cannot be attributed to a legal person MUST NOT
  be issued.

### 15.4 Honest limitation

- AG-13. **Agency law here is unsettled, and NF-2 does not pretend otherwise.** The Bayern
  memberless-LLC wrapper is a *functional* solution, not a *statutory* one: it uses ordinary
  entity law to manufacture a person where the law provides none, and it has not been tested
  against the questions that matter for this use — whether a series is respected as a
  liability boundary across jurisdictions, whether a memberless entity survives challenge, and
  what happens when the automated executor acts outside the wrapper's authority. This carries
  forward NF-WP-1 §13 limitation 3.

- AG-14. AG-1 through AG-12 are protocol requirements and are conformance-testable. AG-13 is a
  legal position and is a **counsel gate**, not a test. An implementation MUST NOT represent
  NF-2 conformance as a determination that its wrapper construction is legally effective (NF-5
  §1.1).

---

## 16. Security considerations

Following the NF-series convention, items are numbered for citation by NF-5. Each states the
threat, the defence, and the residual risk, because a defence stated without its residue is a
claim rather than an analysis.

### SEC-1 — Replay

**Threat.** A grant is captured — from a log, a cache, a backup, an untrusted bearer — and
presented by someone other than the party it was issued to; or a valid presentation is
captured and replayed against a different request.

**Defences.** A grant is not a bearer token. It is bound to `counterparty_key`, and an
enforcement point MUST challenge for possession of the private half in the same session
(CP-4). A stolen grant plus no private key equals nothing, which is the property that makes
E-5 safe. The proof of possession MUST itself be bound to the request by a nonce or channel
binding (CP-6); a nonce store MUST be strongly consistent, because a nonce store with a
read-after-write window is not a nonce store — a replay inside the window simply succeeds.
`expires_at` bounds the window in which any of this matters, and NF-4's staleness bound
bounds it further once revocation has fired.

**Residual risk.** A counterparty holding both a valid grant and its private key, inside the
staleness bound after revocation, is authorized. That window is the bound, and NF-4 §6 exists
to keep it small and disclosed. Compromise of the counterparty's private key is
indistinguishable from the counterparty acting, by construction; the remedy is revocation,
not detection.

### SEC-2 — Grant substitution

**Threat.** An attacker who cannot forge a signature substitutes a *different* validly signed
object — a grant for another vehicle, another purpose, another field set, an older grant, a
grant of another object type entirely — where the verifier expects this one.

**Defences.** Every term the substitution would change is inside the signed bytes: `v`,
`grant_id`, the pseudonym, `fields`, `purpose`, both timestamps, `counterparty_class`,
`counterparty_key`, `revocation_key_id`, `delegation_depth` and both lineage members. The
type binding is `v` itself, so the same bytes cannot be reinterpreted as a Revocation Record
or an NF-3 record (SG-11). Cross-object substitution of digests is blocked by domain
separation: the commitment digest, the revocation-key thumbprint and any NF-4 digest live in
different domains and cannot be confused for one another (RK-2, SG-22). A verifier that is
handed the wrong parent for a delegated grant gets `delegation_parent_mismatch` rather than a
verdict (DL-17).

**Residual risk.** Substitution *within* what the verifier was going to accept anyway — an
older, still-valid grant from the same holder over the same fields — is not a protocol
failure and is not detectable from the object. It is bounded by expiry and by NF-4's issuance
check (SG-28).

### SEC-3 — Pseudonym correlation across counterparties

**Threat.** Two counterparties holding grants over the same vehicle join their datasets on a
shared value and reconstruct a profile neither was granted (NF-WP-1 §12.7).

**Defences, and exactly what each buys.** Salting defeats confirmation of enrolment and
fleet enumeration by a party holding a VIN. Epoch rotation bounds any join in time to one
epoch. Per-audience derivation defeats a **cross-class** join within an epoch. The owner's
public key is deliberately absent, so it cannot be the join key (SH-10); the owner's signing
key is per (vehicle, class) so that it cannot be either (SH-12, SG-21).

**Residual risk, stated precisely because it is easy to overstate the defence.**

1. Two counterparties **in the same class**, in the same epoch, over the same vehicle, hold
   **the same pseudonym value** and can join on it. The audience is the class, not the
   counterparty (PS-10, and Appendix E finding 2).
2. `renewal_of` is a lineage link in the clear. A counterparty that holds both a grant and its
   renewal can link them across an epoch rotation regardless of the fresh pseudonym; the
   holder is also unchanged, so nothing about a renewal is unlinkable *to that holder*. This
   is intended — supersession must be auditable — but it MUST NOT be described as
   unlinkability (Appendix E finding 1).
3. `revocation_key_id` is a long-lived owner-scoped identifier in the clear. See SEC-8.
4. A counterparty can always link its own observations within one epoch, which is inherent in
   receiving a stream at all. Pseudonymization is not anonymization (PS-11).

### SEC-4 — Delegation-depth laundering

**Threat.** A holder synthesizes delegation budget it was never given, producing a chain
longer than the owner authorized and therefore parties the owner never chose and a longer
walk before revocation reaches the last holder.

**Attack surface, enumerated because each has a distinct defence.** Editing
`delegation_depth` on a signed grant (defeated: depth is inside the signed bytes, so the edit
invalidates the signature — DL-8, NF-5 NF5-DD-007). Minting a same-depth child (defeated:
`delegation_depth_not_decremented`, DL-7). Minting from a depth-0 parent (defeated: DL-3).
Requesting a root grant above the bound, or with a coerced or unsafe-integer depth (defeated:
DL-6, SG-7, SG-8). Raising depth at renewal (defeated: TM-14, NF-5 NF5-DD-009). Renewing a
sub-grant to reset it (defeated: TM-17). Recovering depth through an unspecified
"refresh"/"upgrade"/admin route (defeated only by DL-9 plus the declared-surface sweep of
NF-5 NF5-DD-010).

**Residual risk.** DL-9 is asserted over the surface an implementer *declared*. An undeclared
route is outside every check in this section, which is why NF-5 §8.2's manifest exists and why
NF-5 §8.6 states the limitation properly. Fan-out is deliberately unbounded (DL-10), so a
single revocation may have to cut a wide subtree; NF-4 SEC-5 handles the amplification.

### SEC-5 — Canonicalization mismatch

**Threat.** Two parties disagree about the bytes of one grant, or two grants agree on bytes.

**Cost of the first.** One semantic grant with two canonical forms has two commitments. NF-4
keys revocation state by commitment, so a revocation entry filed against the form the owner
saw does not match the form the counterparty presents. This is not a formatting bug; it is a
revocation bypass reachable by anyone who can influence how a grant is serialized.

**Cost of the second.** Forgery: a signature over one object authenticates another.

**Defences.** One canonicalization, RFC 8785, applied to the closed key set with explicit
nulls (SH-2, SH-3) and a canonically ordered field array (FV-7). A canonicalizer that rejects
rather than normalizes (SG-2), refuses negative zero and lone surrogates (SG-5, SG-6),
refuses unsafe integers and coercions (SG-7, SG-8), refuses exotic objects, getters, holes,
symbol keys and cycles (SG-4), and bounds recursion depth (SG-3). One ordering comparator,
exported from one place and shared with NF-3 (FV-8).

**Residual risk.** SG-5 and SG-6 are deliberate deviations from strict RFC 8785. An
implementation using an off-the-shelf strict JCS library will accept inputs NF-2 refuses; it
will not produce different bytes for inputs NF-2 accepts, so signatures still interoperate,
but its refusal surface is smaller and NF-5 NF5-NT-005 will detect the difference. Depth
bounding is a local availability control and is not covered by any signature.

### SEC-6 — Clock skew

**Threat.** A verifier's clock is wrong, or an issuer's clock is wrong, and the disagreement
lengthens or shortens authority. Worse, a millisecond timestamp is supplied where seconds are
expected, turning a 30-day grant into an 80,000-year one while every other check passes.

**Defences.** Timestamps are Unix seconds, safe integers, range-checked against a plausible
window that a millisecond epoch cannot satisfy (TM-7). Skew tolerance is asymmetric and
applies only to `issued_at` (TM-9); a verifier MUST NOT extend a grant's life to accommodate
a slow clock (TM-8). `now` is injectable so the behaviour is testable without the wall clock
(TM-10). The 45-day cap bounds the damage of any clock error that survives all of the above
(TM-3).

**Residual risk.** A verifier whose clock is wrong in the permissive direction has silently
lengthened every grant it evaluates, and nothing inside the object can detect that. This is a
deployment control (TM-11), not a protocol control. The plausible-time window is wide by
design — it exists to catch a unit error of three orders of magnitude, not a clock drift of
minutes.

### SEC-7 — Fail-open by omission

**Threat.** A verifier interface that performs a check only when the caller supplies an
optional input will return a positive verdict to a caller that forgot to supply it. The
failure is invisible: the verdict looks identical to a verdict that passed the check.

**Instances in this design.** Two, and both are the caller's obligation to close: the
presenter key (CP-5) and revocation state (VF-9, VF-10). In the reference implementation both
arrive as optional members of an options object, so omission is reachable by accident rather
than only by deliberately passing a value the caller had to obtain.

**Defences.** CP-5 and VF-9 make supplying them mandatory for an enforcement point. NF-4's
four-part authorization predicate (F-6) makes the revocation half structural rather than
advisory. NF-1 B4 states the design intent: the verifier's interface should make revocation
state a **required** input, so that "I forgot to check" is not reachable by omission.

**Residual risk.** The NF-2 reference interface does not yet meet NF-1 B4's stated bar for
either input; it documents the obligation rather than enforcing it. An implementation SHOULD
make both inputs required parameters of its own enforcement-point wrapper so that the
omission is a compile-time or call-time error rather than a silent policy change. See
Appendix E finding 3.

### SEC-8 — `revocation_key_id` as a cross-class join key

**Threat.** `revocation_key_id` is the one long-lived, owner-scoped identifier NF-2 places in
the clear inside a grant. An owner who reuses one revocation key across counterparty classes
hands two counterparties a stable join key over one vehicle, which voids the per-audience
pseudonym exactly as thoroughly as putting the owner's public key in the grant would have.

**Defence.** RK-6 requires a distinct revocation key per (vehicle, class) lineage. RK-7
allows a broker to detect violations and requires it to report them as findings, while
acknowledging that a broker cannot enforce the requirement on the owner's behalf. NF-4 A-13
forbids disclosing the revocation public key to counterparties.

**Residual risk.** RK-6 is an obligation on the `owner-agent` and is not checkable from a
single grant. An `owner-agent` that ignores it produces conformant-looking grants that leak a
join key, and the only party positioned to notice is the broker — which is precisely the
party the architecture is trying not to have to trust.

### SEC-9 — Unverified ancestry

**Threat.** A verifier establishes that a leaf sub-grant is correctly signed by its parent's
`counterparty_key` and stops there. The parent itself was never authenticated, so the whole
chain rests on an object nobody checked, and the root's owner signature — the only thing
linking the chain to the owner's decision — was never verified.

**Defences.** DL-17 forbids leaf-only verification and requires a parent. DL-18 requires
every link to be verified, and the root against the out-of-band owner key. DL-19 records why
this is a feature: an enforcement point must hold or fetch the whole chain, which is the same
walk revocation makes, so the two cannot drift apart.

**Residual risk.** The reference `verifyGrant()` verifies one link per call and relies on the
caller to iterate to the root; a caller that verifies only the leaf gets a positive verdict
over an unauthenticated ancestry. See Appendix E finding 5. NF-5 NF5-DD-006 asserts the leaf
case; a chain-walk assertion is not yet present in the suite.

### SEC-10 — Commitment ambiguity

**Threat.** A commitment that does not uniquely identify the grant it commits to lets a
revocation entry match a grant the owner never issued, or fail to match one they did.

**Defence.** The commitment covers the signature as well as the payload (SG-24), which is
what binds the issuer given that the signer's key is deliberately absent (SH-10). Unsigned
grants cannot be committed (SG-25). The domain separator prevents confusion with the
revocation-key thumbprint and with any other SHA-256 in the system (SG-22, RK-2).

**Residual risk.** The commitment is only as unambiguous as the canonicalization (SEC-5), and
it is only privacy-preserving for as long as the salt is protected and eventually destroyed
(SG-27, PS-13). An anchored commitment survives erasure by design; its unlinkability after
erasure is an argument about the salt, not about the digest.

### SEC-11 — Algorithm resolution

**Threat.** A verifier is induced to check a signature under an algorithm the attacker chose.

**Defence.** There is no `alg` member and no media-type parameter carrying one (SH-13, E-3).
The suite is pinned by the signed `v`. Algorithm resolution is a property of the *runtime*,
resolved once by probing and cached (SG-15), and never read out of the object under
verification.

**Residual risk.** The dual-name feature detection exists because Cloudflare Workers shipped
Ed25519 under a non-standard name before the WebCrypto Secure Curves draft settled. The probe
is a key generation rather than an import precisely because import is not a reliable
capability test (SG-15). A runtime that resolves neither name MUST fail rather than
substitute; NF-5 §4.3 makes such a run INCONCLUSIVE, which counts as FAIL.

### SEC-12 — Denial of service against the verifier

**Threat.** An untrusted request body reaches the canonicalizer, the JSON parser, the field
validator and the signature verifier.

**Defences.** A verifier MUST NOT throw (VF-3). Canonicalization is depth-bounded (SG-3).
Structural checks run before any Ed25519 verification (VF-7). Vocabulary membership is tested
against a set-like structure that is not a plain object's property table (FV-5). Every
identifier is length- and charset-checked before decoding (§4.3).

**Residual risk.** Cost is bounded per request, not per attacker. Rate limiting is a
deployment control and is outside NF-2 — with the standing caveat from NF-4 SEC-8 that a rate
limiter on the *revocation* path cannot be added without also being able to delay legitimate
revocations.

### SEC-13 — The refusals are structural here, and that is the whole security argument

Refusal 1 appears in NF-2 as an absence: no member of a grant accepts a Vehicle Index, the
pseudonym member has no room for one, and a freshly built grant is re-read to prove the VIN
is not in its bytes (FV-12). Refusal 2 appears as the single permitted ledger artifact
(SG-23) and the mutable-storage requirement (§14). Refusal 3 appears as the absence of any
operator privilege in the schema — no broker key, no Foundation signature, no member the
Foundation can set that changes what an owner authorized — plus the enforceable operator-key
refusal of RK-5.

None of the three is a policy applied to a member that exists. That is the point: a policy
can be waived by a pressured owner, a persuasive counterparty, or an operator under
commercial pressure, and there is no encoding for the waiver.

---

## 17. Privacy considerations

**PRV-1 — Immutability and erasure are irreconcilable, so the object is designed never to be
written.** A standing 45-day Delete Act cadence and CCPA erasure rights cannot be satisfied
on a ledger you cannot delete from (NF-WP-1 §9.5). Only the commitment crosses B3, and the
commitment is unlinkable once the salt is destroyed (SG-27, PS-14).

**PRV-2 — Refusal by schema, not by policy.** The Non-Transactable Classes have no encoding
(FV-9). This is stronger than consent, because consent can be extracted from a party with
poor bargaining position and there is nothing here to extract.

**PRV-3 — Purpose limitation is auditable only if it is singular.** One DPPA purpose per
grant; two purposes are two independently revocable grants (PU-2).

**PRV-4 — The vocabulary is closed so purpose limitation cannot be defeated by naming.** An
open vocabulary with an "other" or free-text identifier is the usual way consent regimes fail
in practice: the scope becomes whatever the requester writes (FV-1).

**PRV-5 — Class, not identity, for counterparties.** The owner's decision is about kinds,
which is the decision they are actually equipped to make (CP-1, and note the sharper point at
CP-3 that the *holder* is nonetheless pinned by key).

**PRV-6 — Inference is a leak path that a field vocabulary cannot close.** Refusing an
identifier does not refuse what can be derived from permitted values. FV-15 states the
concrete open instance — short-window motion aggregates as dead-reckoned trajectory — and does
not claim to have closed it. NF-1 L4-3 requires the analysis at Layer 4.

**PRV-7 — Data minimization is a requirement, not a virtue.** Implementations SHOULD request
the narrowest field set and the shortest lifetime that accomplishes the stated purpose
(TM-4). The ceilings exist to bound failure, not to describe normal practice.

**PRV-8 — Three identifiers in a grant are long-lived, and each is a correlation surface.**
`counterparty_key` (by design — it is the binding), `revocation_key_id` (SEC-8), and
`renewal_of` (SEC-3(2)). `grant_id` and the pseudonym are not, provided PS-8 and SH-6 hold.

**PRV-9 — The salt is the erasure mechanism and MUST be treated as such.** Not escrowed, not
backed up to append-only storage, not derivable from anything on a ledger, and destroyed
rather than flagged (PS-13, PS-15).

---

## 18. Registry considerations

NF-2 owns four registries under the change-control policies of NF-1 §9.2 and §9.4.

| Registry | Contents | Policy | Cardinality in `nf2-grant/1` |
|---|---|---|---|
| NF-2 Data Field Vocabulary | grantable field identifiers, grouped in classes, each tagged with its producing layer | Specification Required + NF-1 §9.4 | 40 |
| NF-2 Non-Transactable Classes | identifiers that MUST NOT have a field id | **CLOSED** (NF-1 R-7) | 18 |
| NF-2 DPPA Purpose Identifiers | one identifier per cited 18 U.S.C. §2721(b) permissible use | Statute-Bound (NF-1 R-8) | 6 |
| NF-2 Counterparty Classes | classes a grant may be issued to | Specification Required | 8 |

- REG-1. Adding a field identifier REQUIRES an identified production interface that actually
  emits it, a provenance layer tag, a written re-identification analysis, and confirmation
  that it is not a Non-Transactable Class under another name (NF-1 R-9). A field admitted
  without a re-identification analysis is how a refused class re-enters through a permitted
  one.

- REG-2. Identifiers MUST NOT be reused or repurposed. Deprecation marks an entry historical;
  it never frees the name (NF-1 R-10).

- REG-3. Removing a field identifier is a **breaking** change and MUST bump the schema version,
  because live grants name it (NF-1 R-11).

- REG-4. Every entry MUST record the document and version that introduced it (NF-1 R-12).

- REG-5. A change to the vocabulary MUST be accompanied by an NF-5 Vector File update, because
  NF5-NT-002 asserts cardinality and set equality against the Vector File. That assertion is
  intentionally brittle: it is what forces a version bump rather than allowing a silent edit
  (NF-5 §5.1, §4.8).

- REG-6. The following changes are **breaking** and MUST bump the schema version from
  `nf2-grant/1`: any change to the top-level key set; any change to the pseudonym derivation,
  including a change to the audience domain (PS-12); any change to a domain-separation string;
  any change to the canonicalization profile including SG-5 and SG-6; any change to the
  signature suite; any change to `MAX_GRANT_DURATION_S` or `MAX_DELEGATION_DEPTH`; and removal
  of any field identifier. A version bump changes `v`, which changes every signature and every
  commitment, which is the correct blast radius for all of these.

- REG-7. The three refusals are not amendable by proposal, vote, or interpretation. Changing
  one requires a superseding white paper and a charter amendment, published, with a version
  bump to NF-1. A pilot, an exception, or a "temporary" carve-out for one member is a violation
  with paperwork (DOCTRINE, "Amendment").

---

## 19. References

### 19.1 Normative

- NF-WP-1, *The Consent-Governed Catallaxy*, Nimbus Foundation, July 2026.
- NF-1, *Architecture Overview and Layer Model*.
- NF-4, *Revocation Semantics, Revocation State and Cascade*.
- NF-5, *Conformance Suite and the Prime-Implementer Tier*.
- RFC 2119, *Key words for use in RFCs to Indicate Requirement Levels*.
- RFC 8174, *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words*.
- RFC 8259, *The JavaScript Object Notation (JSON) Data Interchange Format*.
- RFC 8785, *JSON Canonicalization Scheme (JCS)*.
- RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*.
- RFC 2104, *HMAC: Keyed-Hashing for Message Authentication*.
- FIPS 180-4, *Secure Hash Standard* (SHA-256).
- ISO 3779, *Road vehicles — Vehicle identification number (VIN) — Content and structure*.
- 49 C.F.R. Part 565 (vehicle identification number requirements).
- 18 U.S.C. §2721(b), Driver's Privacy Protection Act permissible uses.
- Cal. Civ. Code §1798.140(ae) (CCPA sensitive personal information).
- Cal. Veh. Code §9951.
- 15 U.S.C. §1 (Sherman Act §1).

### 19.2 Informative

- DOCTRINE.md, Nimbus Foundation charter spine.
- Restatement (Third) of Agency §1.01 (2006).
- Wyoming Limited Liability Company Act (Wyo. Stat. Ann. tit. 17, ch. 29), series provisions.
- S. Bayern, on memberless LLCs as a vehicle for autonomous-system legal personality.
- California Delete Act (45-day deletion-request cadence).
- California Digital Financial Assets Law.
- California SB 95, Ch. 210, Stats. 2023 (enacting UCC Article 12).
- Cal. Ins. Code, Proposition 103; 10 C.C.R. §2632.5.
- C. Miller and C. Valasek, *Remote Exploitation of an Unaltered Passenger Vehicle* (2015).
- S. Curry et al., *Web Hackers vs. the Auto Industry* (2023).
- L. Sweeney; A. Narayanan and V. Shmatikov, re-identification literature (NF-WP-1 §12.7).

---

## Appendix A — The 40 grantable field identifiers

Authoritative machine-readable form: `FIELD_CLASSES` and `FIELDS` in `broker/src/fields.js`.

    build_specification  (layer: vpic, 14)
        body_class            drive_type            engine_configuration
        engine_displacement_l fuel_type_primary     gvwr_class
        make                  model                 model_year
        plant_company_name    plant_country         series
        trim                  vehicle_type

    diagnostics  (layer: layer2, 6)
        dtc_codes             dtc_first_seen_at     freeze_frame
        mil_status            obd_protocol          readiness_monitors

    battery_health  (layer: layer2, 6)
        charge_cycle_count    charge_rate_kw        pack_temperature_c
        state_of_charge_pct   state_of_health_pct   usable_capacity_kwh

    motion_aggregate  (layer: layer2, 6)
        aggregation_window_s  harsh_accel_count     harsh_brake_count
        harsh_corner_count    speed_mean_kph        speed_p95_kph

    usage  (layer: layer2, 4)
        annual_mileage_estimate_km   engine_hours
        odometer_km                  service_due_km

    service_history  (layer: operator, 4)
        last_service_at       recall_completion_status
        repair_order_summaries  service_events

## Appendix B — The 18 Non-Transactable identifiers

These have **no field identifier** in the vocabulary. The list exists solely so NF-5 can
assert their absence; nothing in the protocol consumes it to permit anything (FV-11).

    Positional (FV-13: V1 admits none at any precision)
        coarse_geolocation    geohash    gps_trace    latitude    longitude
        precise_geolocation

    Biometric
        biometric_identifier  driver_face_template   fingerprint   voiceprint

    In-cabin sensory
        driver_monitoring_video   in_cabin_audio   in_cabin_video

    Index and direct identifiers
        raw_vin   owner_address   owner_email   owner_name   owner_phone

## Appendix C — Constants

| Constant | Value | Defined in |
|---|---|---|
| Schema version (`v`) | `nf2-grant/1` | §4.3 |
| Pseudonym derivation tag | `nf2-pseudonym:v1` | PS-1 |
| Commitment domain | `nf2-grant-commitment:v1:` | SG-22 |
| Revocation-key-id domain | `nf2-revocation-key-id:v1:` | RK-1 |
| Maximum grant duration | 3 888 000 s (45 days) | TM-3 |
| Maximum delegation depth | 2 | DL-6 |
| Plausible-time window | `[1 700 000 000, 4 000 000 000]` Unix s | TM-7 |
| Default clock-skew tolerance | 300 s (`issued_at` only) | TM-9 |
| Minimum pseudonym salt entropy | 32 decoded bytes | PS-3 |
| `grant_id` | 16 bytes → 22 base64url chars | §4.3 |
| Pseudonym `value` | 32 bytes → 43 chars | §4.3 |
| `counterparty_key` | 32 bytes → 43 chars | §4.3 |
| `revocation_key_id` | 32 bytes → 43 chars | §4.3 |
| Grant commitment | 32 bytes → 43 chars | SG-22 |
| `signature` | 64 bytes → 86 chars | SG-12 |
| Canonicalization depth ceiling | 64 | SG-3 |
| Top-level members | 14 | SH-1 |

## Appendix D — Requirement index

- Capability semantics and non-transferability: CG-1…CG-8
- Encoding and media type: E-1…E-6
- Schema shape and absences: SH-1…SH-13
- Pseudonym: PS-1…PS-15
- Field vocabulary: FV-1…FV-17
- Purpose: PU-1…PU-7
- Counterparty: CP-1…CP-6
- Time, duration, renewal: TM-1…TM-19
- Revocation key reference: RK-1…RK-8
- Delegation: DL-1…DL-20
- Signature, canonicalization, commitment: SG-1…SG-28
- Verification: VF-1…VF-13
- Storage: ST-1…ST-14
- Agentic separation: AG-1…AG-14
- Security considerations: SEC-1…SEC-13
- Privacy considerations: PRV-1…PRV-9
- Registries: REG-1…REG-7

## Appendix E — Known divergences and unverified claims

Recorded so they are scheduled work rather than later discoveries. Per §1.4, this document
governs and each item below is a defect in the artifact named, not a relaxation of the
requirement.

**Finding 1 — the renewal "unlinkability" claim is wrong as stated.**
`broker/src/nf2-grant.js`, `renewGrant()`, comments that recomputing the pseudonym under a
new epoch makes a renewal "unlinkable to the grant it replaces from the counterparty's side".
It is not: `renewal_of` names the previous `grant_id` in the clear, and `counterparty_key`
and `counterparty_class` are unchanged, so the renewing counterparty links the two trivially.
The correct property — and the one this document states at TM-15 and SEC-3(2) — is that epoch
rotation bounds linkage for parties that do **not** hold both grants, while `renewal_of` is a
deliberate in-the-clear supersession link for the holder and for audit.

**Finding 2 — the per-audience anti-correlation claim is overstated.**
`broker/src/vin.js` (`vehiclePseudonym` doc comment) and NF-1 SEC-3 both say per-audience
derivation defeats joins between "two simultaneous counterparties". Because the audience is
`counterparty_class` rather than the counterparty, two counterparties **in the same class**
over the same vehicle in the same epoch receive an identical pseudonym and can join on it.
This document states the accurate scope at PS-10 and SEC-3(1). NF-1 SEC-3 should be corrected
in the same terms.

**Finding 3 — two fail-open-by-omission inputs in the verifier interface.**
`verifyGrant()` checks counterparty binding only when `opts.presenterKey` is supplied, and
records revocation only when `opts.revoked` is supplied. Omission yields `valid: true`
without either check. NF-1 B4 states that the verifier's interface should make revocation
state a *required* input so that omission is unreachable; the current interface documents the
obligation instead. CP-5, VF-9 and SEC-7 state the caller's duty; the interface has not been
changed to enforce it.

**Finding 4 — renewal does not require a signed predecessor.** `mintDelegatedGrant()`
refuses an unsigned parent explicitly; `renewGrant()` has no equivalent check, so a renewal
can be minted whose `renewal_of` points at an object that was never issued. TM-19 states the
requirement.

**Finding 5 — chain verification is per-link and the walk is the caller's.**
`verifyGrant()` verifies the leaf's signature under the parent's `counterparty_key` and
checks the lineage invariants, but does not itself walk to the root or verify the parent's own
signature. DL-18 states the requirement; SEC-9 states the residual risk. NF-5 asserts the
leaf case (NF5-DD-006) and has no chain-walk assertion.

**Finding 6 — a diagnostic wart in `signGrant()`.** The re-signing guard tests
`grant.signature !== null`, so a grant that is *missing* the `signature` member entirely is
rejected with "grant is already signed". The refusal is correct and fails closed; only the
message is wrong.

**Finding 7 — stale cross-references in sibling documents, reported not corrected.** NF-1
§1.3 lists NF-3 as RESERVED and NF-4 and NF-5 as "not implemented"; all three specifications
and both modules now exist. NF-4 §1.4 states that `broker/src/nf4-revocation.js` does not
exist; it does. NF-3's header states that `broker/src/nf3-resolve.js` is absent and refers to
its own §16; the module exists and that document currently ends at §13.5. NF-4 ends at §10
with a placeholder for the §11 it references. NF-5 ends at §6 while referencing §7 through
§14. None of these affect NF-2's normative content; they affect whether the series can be
read as one document.

**Finding 8 — registry ownership of the reason codes is ambiguous.** NF-1 §9.2 assigns the
Verification Reason Code registry to NF-5, while the codes are defined and emitted by NF-2
(§13.4). VF-13 resolves this by treating NF-2 as the introducing document and NF-5 as the
registry of record, which satisfies NF-1 R-12; NF-1 §9.2 should say so explicitly.

### E.1 What was executed, and what was not

**Executed.** Every constant, cardinality, construction and reason code asserted by this
document was checked against the running modules on Node 24 (`node --test`, no third-party
packages, per NF-1 I-6). Specifically confirmed by execution: the 40/18/6/8/6 registry
cardinalities and the per-class layer tags; the fourteen-member key set in order; all
constants in Appendix C; the PS-1 pseudonym message and the PS-2 key form (and that the
decoded-salt variant produces different output, which is why PS-2 is normative); the RK-1 and
SG-22 digest constructions; the SG-5/SG-6/SG-3 canonicalizer refusals and the SH-2
null-versus-absence byte difference; a full build → sign → verify → commit lifecycle with an
empty reason list; forty-odd negative verification cases covering the §13.4 codes; the
delegation invariants including DL-12/DL-13 pseudonym inheritance and unbounded fan-out; the
renewal invariants; and that `verifyGrant()` throws on nothing.

**Confirmed by execution as defects.** Findings 3, 4 and 6 above were each reproduced:
`verifyGrant()` returns `{ valid: true, reasons: [] }` with both `presenterKey` and `revoked`
omitted; `renewGrant()` accepts an unsigned predecessor and sets `renewal_of` to it; and
`signGrant()` reports "already signed" for a grant missing the `signature` member. Finding 2
was reproduced directly: two derivations differing only in counterparty — same vehicle, same
salt, same epoch, same class — return an identical pseudonym.

**Not executed.** The NF-5 suite itself does not exist (`conformance/tests/` is empty), so no
NF-5 assertion has been run against any implementation, and nothing here constitutes a
conformance verdict. The checks above are this document's own consistency checks against the
reference modules, not the suite. NF-5 §4.6's rule applies by analogy: "could not check" is
not "no finding".

Findings 1, 5, 7 and 8 are established by reading source and specification text rather than by
execution; each concerns a claim, an omission, or a cross-reference rather than a behaviour a
test can exhibit.
