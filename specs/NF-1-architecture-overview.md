# NF-1 — Architecture Overview and Layer Model

    Document:    NF-1
    Title:       Architecture Overview and Layer Model
    Status:      Draft Standard
    Version:     1.0.0-draft
    Date:        2026-07
    Series:      Nimbus Foundation Specifications (NF-1 … NF-5)
    Derives from: NF-WP-1, "The Consent-Governed Catallaxy" (July 2026),
                  §3.1 (layer model), §3.3 (data ceiling), §8.1 (this document),
                  §10 (charter), §14 (stack constraint)
    Supersedes:  no prior NF-series document

## Abstract

NF-1 defines the five-layer reference model of the Internet of Vehicles data
architecture, the ownership and constraint of each layer, the trust boundaries between
them, and the conformance vocabulary used by every document in the NF series. It
establishes the Nimbus Foundation's role: the Foundation **specifies** the Layer 3 and
Layer 4 interfaces and the conformance suite that tests them, **consumes** Layers 1 and
2 read-only, and **gates** Layer 5. NF-1 defines no wire format; formats are defined by
NF-2 (consent grant and field vocabulary) and NF-4 (revocation). NF-1 is the document
that says which questions belong to which layer, and which questions the protocol
refuses to answer at all.

---

## 1. Introduction

### 1.1 Scope

This document is normative for:

- the layer numbering and the definition of each layer (§3);
- which party owns, operates and is accountable for each layer (§3, Appendix A);
- the trust boundaries between layers and what may and may not cross each one (§4);
- the ceiling on what vehicle data is obtainable and therefore representable (§6);
- the Foundation's institutional position and the limits on it (§7);
- the conditions under which Layer 5 may be reconsidered (§8);
- the registries the NF series depends on and their change control (§9).

### 1.2 What this document is not

NF-1 is not a data model, an API description, or a deployment guide. It contains no
field names, no endpoint paths, and no cryptographic constructions. Where a requirement
here can only be satisfied by a format decision, NF-1 states the requirement and names
the document that owns the format.

NF-1 also does not restate the charter. The three refusals are reproduced normatively in
§5 because architecture without them is a different architecture, but their justification
lives in `DOCTRINE.md` and in NF-WP-1 §10.

### 1.3 Document series

    NF-1  Architecture overview and layer model                     (this document)
    NF-2  Consent Grant object and the closed field vocabulary      implemented
    NF-3  RESERVED — index resolution and authorization-endpoint discovery
    NF-4  Revocation records, revocation state and cascade          not implemented
    NF-5  Conformance suite                                         not implemented

An implementation MUST NOT claim conformance to a RESERVED or unpublished document.
Claiming conformance to NF-3 before NF-3 exists is a claim about a specification the
Foundation has not written, which is exactly the failure mode a standards body exists to
prevent.

### 1.4 Layer numbering is closed

The five layers of §3 are the whole model. An implementation MUST NOT introduce a
"Layer 6", MUST NOT renumber, and MUST NOT describe a capability as belonging to a layer
other than the one this document assigns it. Layer numbers are the vocabulary in which
the Layer 5 gate (§8) and the trust boundaries (§4) are stated; a market function
relabelled as "Layer 4 analytics" evades the gate by nomenclature, and nomenclature is
the cheapest attack on a constraint.

---

## 2. Conformance

### 2.1 Requirements notation

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY** and **OPTIONAL** in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
when, they appear in all capitals, as shown here.

Two additional conventions apply across the NF series:

**MUST NOT is not waivable by agreement.** A deployment does not become conformant
because an owner, a counterparty or a regulator consented to the violation. Several NF
requirements exist precisely because they cannot be waived by a pressured or
unsophisticated owner (NF-WP-1 §8.2); a waiver channel would return the decision to the
party least able to make it.

**SHOULD means an implementer who deviates must be able to say why.** NF-5 records
SHOULD deviations as findings, not failures. A deviation with no stated reason is a
finding.

### 2.2 Conformance targets

Conformance is asserted against ROLES, not products. One deployment MAY implement several
roles; when it does, it MUST satisfy each role's requirements independently, and MUST NOT
rely on co-location to satisfy a requirement that assumes separation.

| Role | Definition | Primary layer |
|---|---|---|
| `owner-agent` | Holds the owner's signing key and revocation key. Authorizes and revokes. | 3 |
| `broker` | Resolves the vehicle index, issues scoped grants, holds pseudonym salts and mutable state. | 3 |
| `counterparty` | Presents a grant and proves possession of the bound key. Receives projections. | 3 → 4 |
| `source-adapter` | Consumes a Layer 2 authenticated interface read-only and normalizes to the NF-2 vocabulary. | 2 → 3 |
| `processor` | Builds digital twins and trains models over consented streams. | 4 |
| `verifier` | Evaluates a grant and a revocation state and returns a verdict. | 3 |
| `tester` | Runs NF-5 against another role. | — |

The Nimbus Foundation is **not** a conformance target. It implements no role, holds no
grant, and operates no broker (§5, Refusal 3, and §7).

### 2.3 Terminology

**Vehicle Index** — the VIN, treated as a public name. A well-formed 17-character
identifier under ISO 3779 and, for vehicles manufactured for the North American market,
49 C.F.R. Part 565. The index is public, enumerable, and confers nothing.

**Resolution** — the act of mapping a Vehicle Index to the location at which
authorization may be requested. Resolution returns *where to ask*. It never returns
authorization, a credential, a key, a payload, or a statement about the owner.

**Consent Grant** — a scoped, time-bounded, purpose-limited, owner-revocable,
non-transferable capability object, defined by NF-2. It names a vehicle by pseudonym, not
by index. It is bound to a public key, not to a name.

**Vehicle Pseudonym** — a salted, epoch-rotating, per-audience value standing in for the
Vehicle Index inside a grant. The salt is owner-held, lives only in mutable deletable
storage, and destroying it destroys the linkage.

**Non-Transactable Class** — a category of data for which the protocol defines no field
identifier and therefore cannot encode a grant. See §6.3.

**Authoritative State** — the current revocation state of a grant, held in mutable
storage. A grant that verifies cryptographically is not thereby authorized; see §4.4.

**Projection** — the subset of an upstream payload a counterparty is permitted to
receive, computed as an allowlist from the grant's field set.

**Layer 5 Function** — any function that prices, quotes, bids, matches, settles,
escrows, collateralizes, tokenizes, or transfers a grant or an interest in one. See §8.

**Foundation** — the Nimbus Foundation: a Delaware nonstock nonprofit corporation
electing treatment under IRC §501(c)(6). Its governance model follows the
Linux/Apache pattern (the Linux Foundation is an Oregon-domiciled §501(c)(6)
organization). It is a standards body.

**Implementer** — any party building to the NF series. **Prime Implementer** is a
renewable tier earned by passing NF-5; it is not a preferential licence (§7.3).

---

## 3. The layer model

Five layers, per NF-WP-1 §3.1. Each subsection states what the layer is, who owns it,
what the Foundation does with it, and the normative constraints that bind an NF
implementer at that layer.

### 3.1 Layer 1 — Connectivity substrate

**What.** The physical and link layers that move bytes: C-V2X, cellular, and roadside
infrastructure.

**Ownership.** Mobile network operators, road authorities, and equipment vendors. No NF
role owns Layer 1.

**Foundation's role.** None, beyond depending on it. The Foundation specifies nothing at
Layer 1 and MUST NOT condition conformance on any particular radio, band, or deployment.

**Why nothing is built here.** The architecture rides existing infrastructure because
purpose-built roadside deployment is not a precondition anyone can satisfy on the
Foundation's schedule. Per-device roadside-unit cost is estimated by USDOT in 2025 at
roughly $3,000–$5,000 per device. Even the most aggressive national programme illustrates
the timeline rather than refuting it: China has twenty cities with full-area coverage and
more than 11,000 roadside units, at approximately 4% penetration. An architecture whose
first useful deployment requires new roadside hardware has no first useful deployment.

**Normative constraints.**

- L1-1. An implementation MUST NOT treat link-layer identity, subscriber identity, or
  network position as authorization for anything. Being on the network is not consent.
- L1-2. An implementation MUST NOT require a specific Layer 1 bearer for conformance.
- L1-3. An implementation MUST NOT assume Layer 1 confidentiality. Every NF-defined
  object is designed to be transmissible over an untrusted bearer: a grant is not a
  secret, because it is bound to a key the presenter must prove possession of.

### 3.2 Layer 2 — Authenticated access

**What.** The interfaces through which vehicle data is actually available today: OEM
telematics services, standardized extended-vehicle access (ISO 20078), and physical
diagnostic interfaces.

**Ownership.** Vehicle manufacturers and diagnostic-tool vendors. Not the Foundation, not
the broker, not the owner.

**Foundation's role.** Consume, read-only. The Foundation specifies how a
`source-adapter` normalizes Layer 2 output into the NF-2 vocabulary; it specifies nothing
about Layer 2 itself and asserts no right of access to it.

**Legal frame.** Access is bounded by the Computer Fraud and Abuse Act as narrowed in
*Van Buren v. United States*, 593 U.S. 374 (2021), and by DMCA §1201. Van Buren narrows
the "exceeds authorized access" theory; it does not license access that was never
authorized, and it says nothing about circumvention.

**Normative constraints.**

- L2-1. A `source-adapter` MUST be read-only. It MUST NOT expose, proxy, wrap, or
  construct any actuation, command, remote-control, or write path to a vehicle. There is
  no NF field, grant type, or purpose that authorizes actuation, and there MUST NOT be
  one.
- L2-2. A `source-adapter` MUST NOT circumvent a technological protection measure to
  obtain data (DMCA §1201). If the only route to a field is circumvention, that field is
  unobtainable and §6 applies to it.
- L2-3. Layer 2 access MUST rest on an authorization the owner actually granted to the
  operator of the adapter — an owner-authorized OEM account scope, or the owner's own
  physical diagnostic access. Van Buren does not convert an unauthorized route into an
  authorized one.
- L2-4. Layer 2 **credentials** — OEM OAuth tokens, refresh tokens, session keys,
  diagnostic session material — MUST NOT cross upward to any Layer 3 counterparty, and
  MUST NOT be derivable from any NF-defined object. See §4.3.
- L2-5. A `source-adapter` MUST tag every normalized field with the layer that produced
  it, so the §6 ceiling is machine-readable at request time rather than discovered at
  delivery time.
- L2-6. An implementer MUST NOT represent Layer 2 availability as universal. Field
  availability varies by manufacturer, model year and market, and an implementer SHOULD
  hold a per-field availability finding rather than an assumption.

### 3.3 Layer 3 — Consent layer

**What.** The core build. Layer 3 resolves the Vehicle Index as an index, and issues
scoped, time-bounded, purpose-limited, revocable authorizations over data reachable at
Layer 2. It is the layer at which the owner's decision is expressed and enforced.

**Ownership.** Brokers implement it; owners control it. The Foundation specifies its
interfaces and its conformance suite, and operates none of it.

**Legal frame.** DPPA permissible uses, 18 U.S.C. §2721(b) — a grant cites exactly one.
Cal. Veh. Code §9951. The CCPA, including its sensitive-personal-information category,
Civ. Code §1798.140(ae). The Delete Act's 45-day deletion cadence, which is what pins the
maximum grant lifetime.

**Normative constraints.**

- L3-1. **Resolution returns location, never authorization.** A resolution response MUST
  contain no credential, no key usable to obtain data, no payload, and no assertion about
  the owner or the vehicle beyond the endpoint at which authorization may be requested. A
  resolution response MUST be safe to serve to an anonymous requester, because the input
  to it is public.
- L3-2. **Possession of a Vehicle Index MUST NOT be sufficient input to any authorization
  decision, anywhere, at any layer.** Any code path in which a VIN alone changes an access
  outcome is non-conformant. This is testable: NF-5 asserts it by presenting a valid index
  and nothing else.
- L3-3. A grant MUST be scoped to an enumerated field set drawn from the NF-2 closed
  vocabulary, MUST carry exactly one DPPA purpose, MUST carry a mandatory expiry, and MUST
  be bound to the counterparty's public key rather than to a name. There is no perpetual
  grant and no bearer grant.
- L3-4. A grant MUST be non-transferable. No NF object may encode assignment, sale,
  delegation of holder identity, collateralization, or bearer semantics. Delegation, where
  permitted, mints a *new, narrower, independently revocable* grant signed by the
  delegator; it does not move an existing one.
- L3-5. A grant MUST NOT contain the raw Vehicle Index, nor any value from which the index
  or the owner's identity is derivable without the owner-held salt. An implementation MUST
  verify this property against its own output rather than asserting it.
- L3-6. The owner MUST be able to revoke without the cooperation of the broker or the
  counterparty. An implementation MUST NOT place revocation authority in the hands of the
  broker or the counterparty, and a grant whose revocation key is held by its own
  counterparty is invalid on its face.
- L3-7. Grant lifetime MUST NOT exceed the Delete Act deletion cadence of 45 days. This is
  a ceiling, not a default; an implementation SHOULD issue the shortest grant that does the
  job.
- L3-8. All payload, identifiers, linkage, salts and revocation state MUST live in mutable,
  deletable storage. See §5, Refusal 2.
- L3-9. A `verifier` MUST fail closed and MUST NOT return a positive verdict on an
  unchecked signature. A `verifier` MUST NOT throw on malformed input; a verifier that
  throws is a denial-of-service surface reachable from any untrusted body.
- L3-10. A positive verification verdict MUST NOT be treated as authorization on its own.
  Authorization is a verdict plus current revocation state read in the same request. See
  §4.4.

### 3.4 Layer 4 — Data layer

**What.** Digital twins assembled from consented streams, and federated learning over
them. Partial in V1.

**Ownership.** Processors, under grants. Owners retain control by revocation.

**Foundation's role.** Specify interfaces and conformance. The Foundation does not operate
a twin, hold a corpus, or train a model.

**Normative constraints.**

- L4-1. Every access to a consented stream MUST be authorized at the moment of access.
  A `processor` MUST NOT hold a cached authorization decision without the state it was true
  under, and MUST re-derive on any change to that state.
- L4-2. Projection MUST be an allowlist computed from the grant's field set, never a
  denylist. When an upstream payload gains a field, the failure mode MUST be that the
  counterparty receives less than the grant permits — never that it silently receives data
  nobody consented to.
- L4-3. A twin MUST NOT retain, derive, or reconstruct a Non-Transactable Class (§6.3),
  including by inference across permitted fields. An implementer SHOULD hold a written
  inference analysis for any derived field, because a derivation that reconstructs a
  refused class defeats the schema constraint without ever naming it.
- L4-4. Federated learning MUST NOT be conditioned on payment, token issuance, or any
  economic reward. Aggregation is a Layer 4 function; paying for it is a Layer 5 function
  (§8).
- L4-5. Revocation MUST propagate to Layer 4: a revoked grant MUST cut open streams and
  MUST bar further derivation. An implementer SHOULD state, per model, whether a
  contribution can be withdrawn after aggregation, and MUST NOT represent post-aggregation
  withdrawal as achieved where it is not.
- L4-6. Layer 4 MUST NOT expose a route back down to the vehicle. Data flows up; commands
  do not flow down (L2-1).

### 3.5 Layer 5 — Market layer

**What.** Priced exchange and price discovery over consented data.

**Ownership.** Not the Foundation, ever (§5, Refusal 3). If and when a market exists, a
distinct operator runs it.

**Status.** **DEFERRED AND GATED. OUT OF SCOPE FOR V1.**

**Normative constraints.**

- L5-1. A V1 implementation MUST NOT contain a Layer 5 Function as defined in §2.3. No
  pricing, quoting, bidding, matching, order book, escrow, settlement ledger, token,
  payment rail, or transferability, in any layer, under any name.
- L5-2. No NF object may carry a price, an amount, a currency, a fee, a rate, a bid, or a
  reference to any of them. The absence MUST be structural — there is no field to populate
  — not a policy applied to a field that exists.
- L5-3. The Settlement Credit described in earlier drafts is **cut**, not deferred
  (NF-WP-1 §9.7: a store-of-value instrument raises Digital Financial Assets Law exposure,
  and the associated tangible-net-worth expectation of roughly $100,000 is disqualifying
  for the Foundation's posture). An implementation MUST NOT reintroduce it under another
  name.
- L5-4. When settlement eventually exists it is **fiat**, via a conventional payment
  processor (Stripe). An implementation MUST NOT introduce a protocol-native unit of
  account.
- L5-5. Tiered, pay-to-play validator tokenomics is rejected. Governance Membership is
  non-transferable, one per member, and carries **no economic rights**. An implementation
  MUST NOT make governance weight a function of holdings, spend, or volume.
- L5-6. Layer 5 MUST NOT be reconsidered except through §8.

---

## 4. Trust boundaries

A trust boundary is a place where an assumption stops being safe. Five of them. For each:
what crosses, what MUST NOT cross, and where the constraint is enforced.

### 4.1 B1 — Layer 1 ↔ Layer 2: the authentication boundary

Below it, identity is a bearer artefact: a subscriber identity, a MAC address, a radio
session. Above it, identity is an authenticated session with an accountable party.

- Crosses upward: bytes.
- MUST NOT cross upward: authority. See L1-1.
- Enforcement: Layer 2 authenticates independently of Layer 1. An NF implementer inherits
  this boundary and MUST NOT weaken it by, for example, treating a trusted network segment
  as a substitute for a session.

### 4.2 B2 — Layer 2 ↔ Layer 3: the credential boundary

This is the boundary the doctrine is about. A `source-adapter` holds a real credential —
an owner-authorized OEM scope, or physical diagnostic access. A Layer 3 counterparty holds
a grant. These are different kinds of object and they MUST NOT be interconvertible.

- Crosses upward: normalized field values, tagged with their producing layer (L2-5).
- Crosses downward: read requests only.
- MUST NOT cross upward: credentials, tokens, session keys, or anything from which they can
  be derived (L2-4). A counterparty that can reach the OEM directly has been handed the
  owner's account, and no grant scoping survives that.
- MUST NOT cross downward: commands, writes, actuation, or unlock/start of any kind
  (L2-1, L4-6).
- Enforcement: architectural. The adapter is the only holder of Layer 2 credentials; the
  grant buys a projection of a response, never the credential that produced it.

### 4.3 B3 — Layer 3 ↔ ledger: the immutability boundary

Layer 3 keeps two kinds of state, and the split is the whole of Refusal 2.

- MAY cross onto an immutable ledger: consent-grant hashes, revocation-state commitments,
  integrity commitments. Nothing else.
- MUST NOT cross: personal information, or anything from which personal information can be
  derived — the Vehicle Index, owner identity, pseudonym salts, payload, field values,
  timestamps tied to a natural person, per-vehicle event history, or a persistent
  per-vehicle account identifier.
- Enforcement: schema. A commitment is a fixed-length opaque value; there is no field on
  the ledger side into which a payload fits.
- Why the boundary is one-way and hard: a standing 45-day Delete Act deletion cadence plus
  CCPA erasure rights are irreconcilable with immutability (NF-WP-1 §9.5). You cannot
  delete from an immutable ledger, so the only conformant design never writes it. Note the
  consequence for identifiers as well as payloads: a permanent per-vehicle record on a
  public ledger is undeletable *behavioural metadata* even when it contains no payload at
  all.

### 4.4 B4 — Layer 3 ↔ Layer 4: the authorization boundary

Cryptographic validity and current authorization are different facts, and conflating them
is the most likely way a conformant-looking deployment leaks data.

- Crosses downward into Layer 4: a verdict, plus the revocation state it was evaluated
  against, plus the projection allowlist derived from the grant.
- MUST NOT cross: a verdict alone. A signature proves what the owner authorized at
  issuance; it says nothing about now (L3-10).
- MUST NOT cross upward: payload into commitments (B3), or any Layer 4 derivation that
  reconstructs a refused class (L4-3).
- Enforcement: the verifier's interface makes revocation state a required input from the
  caller, so "I forgot to check" is not reachable by omission — it is reachable only by
  passing a value the caller had to obtain.

### 4.5 B5 — Foundation ↔ implementers and operators: the neutrality boundary

The institutional boundary, and the one with no cryptography behind it. It is enforced by
what the Foundation is chartered to be, and it is the reason Refusal 3 is load-bearing.

- Crosses outward from the Foundation: specifications, test suites, conformance verdicts,
  registry entries, and FRAND terms identical for all implementers.
- MUST NOT cross into the Foundation: consent grants, owner keys, pseudonym salts,
  revocation authority, payload, market operation, listing authority, take rates, or
  preferential access.
- MUST NOT cross outward: preferential terms, private specification, or a conformance
  result that depends on who the implementer is.
- Enforcement: charter, and the absence of any NF role the Foundation occupies (§2.2).
  A body that both writes the standard and runs the exchange has reconstituted the central
  planner it was designed to avoid, and has taken on Sherman Act §1 exposure in the
  bargain. Neutrality is the antitrust and doctrinal firewall (NF-WP-1 §10.2).

---

## 5. The three refusals as architectural invariants

Reproduced here because they are architecture, not policy (NF-WP-1 §10.1). Justification
and the grounding episodes are in `DOCTRINE.md`.

**Refusal 1 — A Vehicle Index MUST NEVER resolve to a credential.** The VIN is a public
index, exactly like a DNS name: resolution returns *where to ask* for authorization, never
authorization itself. Possession of an index MUST confer no authority in any code path
(L3-1, L3-2).

**Refusal 2 — Personal information, and anything from which it can be derived, MUST NEVER
be placed on an immutable ledger.** On-chain content is limited to consent-grant hashes,
revocation-state commitments, and integrity commitments. All payload, identifiers and
linkage live in mutable, deletable storage (B3, L3-8).

**Refusal 3 — The Foundation MUST NEVER operate a market it also governs.** It is a
standards body: not a market operator, not a licensor of preferential access, not a holder
of consent grants (B5, §7).

These are absolute. They are not subject to majority vote, member pressure, commercial
opportunity, or a pilot exception. An implementation that violates one is
non-conformant regardless of every other property it has.

---

## 6. The data ceiling (normative)

NF-WP-1 §3.3 states an honest ceiling on what vehicle data is actually obtainable. NF-1
makes it a normative limit, because an inflated data claim is both a commercial
misrepresentation and an engineering commitment nobody can keep.

### 6.1 The defensible union

The defensible union of obtainable vehicle data is:

1. **telematics** — operational state reported by the vehicle or an attached device;
2. **diagnostics** — trouble codes, readiness and freeze-frame data;
3. **build specification** — what the vehicle was manufactured as;
4. **service history** — what has been done to it, as recorded by a bonded participant.

In the NF-2 vocabulary these map to `battery_health`, `motion_aggregate` and `usage`
(telematics); `diagnostics`; `build_specification`; and `service_history`.

- C-1. Every field in the NF-2 vocabulary MUST fall within the defensible union and MUST
  carry a provenance tag naming the layer that produces it: derivable from the index alone
  via public build data, requiring Layer 2 authenticated access, or supplied by a bonded
  operator.
- C-2. An implementer MUST NOT represent a Layer 2-dependent field as index-derivable. The
  distinction is the difference between a lookup and a relationship with a manufacturer,
  and conflating them is how a data claim becomes undeliverable.
- C-3. A field whose only route is circumvention (L2-2) is unobtainable and MUST NOT be
  offered.

### 6.2 Static manufacturing microproperties are NOT obtainable

Per-unit static manufacturing microproperties — for example the metallurgical composition
of an individual unit's components, per-unit tolerance measurements, or per-unit
material-batch provenance — are **not obtainable** through any interface in this
architecture.

- C-4. An implementer MUST NOT represent such properties as obtainable, present, derivable,
  or forthcoming in any commercial representation: marketing material, data catalogue, field
  list, pitch, prospectus, term sheet, or API documentation.
- C-5. The NF-2 vocabulary MUST NOT contain a field identifier for them, and the registry
  MUST refuse a registration request for one absent a demonstrated production interface
  that emits the value per unit (§9.4).
- C-6. An implementer MUST NOT infer such a property from a fleet-level or model-level
  statistic and present the inference as a unit-level fact. Modelled and measured are
  different claims, and a data market that blurs them is selling something it does not have.

### 6.3 Non-Transactable Classes

Precise geolocation, biometric identifiers, and in-cabin audio and video have **no grant
type at all** (NF-WP-1 §8.2, §12.2). They are not fields with a deny flag; they are absent
from the vocabulary.

- C-7. The protocol MUST NOT be able to encode a grant for a Non-Transactable Class. The
  constraint MUST be structural, because a design constraint beats a policy statement: a
  policy can be waived by a pressured or unsophisticated owner, and there is no encoding
  for the waiver. This aligns with CCPA sensitive personal information, Civ. Code
  §1798.140(ae).
- C-8. **V1 admits no positional field at any precision.** This is deliberate conservatism
  beyond the letter of NF-2, which forbids *precise* geolocation. A coarse-position class is
  defensible in principle, but it needs a documented precision floor, a re-identification
  analysis, and counsel review before it earns an identifier. Until then the honest position
  is that we do not ship it. Non-positional motion data — speed, acceleration events — is not
  geolocation and is admitted.
- C-9. The raw Vehicle Index is itself non-transactable inside a payload. The Delete Act's
  broker disclosures enumerate vehicle identification numbers as a category of personal
  information collected (NF-WP-1 §9.5), so a VIN in a payload does not merely offend
  tidiness — it drags the payload into the regime.

---

## 7. The Foundation's institutional position

### 7.1 Specifies, consumes, gates

- S-1. The Foundation **specifies** the Layer 3 and Layer 4 interfaces and the conformance
  suite that tests them (NF-2 … NF-5). It MUST publish them openly and MUST NOT maintain a
  private variant.
- S-2. The Foundation **consumes** Layers 1 and 2 read-only. It specifies nothing there,
  asserts no right of access, and MUST NOT condition conformance on any Layer 1 or Layer 2
  vendor relationship.
- S-3. The Foundation **gates** Layer 5 (§8). Gating is the authority to say "not yet." It
  is expressly not the authority to operate, license, or take a fee from a market
  (Refusal 3).
- S-4. The Foundation MUST NOT hold a consent grant, an owner key, a pseudonym salt,
  revocation authority, or payload (B5).

### 7.2 Governance

- S-5. The Foundation is a Delaware nonstock nonprofit corporation electing treatment under
  IRC §501(c)(6), following the Linux/Apache model. It is **not** an on-chain token-weighted
  DAO, and MUST NOT become one.
- S-6. Governance Membership MUST be non-transferable, one per member, and MUST carry no
  economic rights. Governance weight MUST NOT be a function of holdings, spend, or volume
  (L5-5).

### 7.3 CarNimbus and the Prime Implementer tier

- S-7. CarNimbus is the **prime implementer**: the first party building to the NF series and
  the reference deployment against which the specifications are exercised.
- S-8. Prime Implementer is a **renewable tier that any implementer can earn** by passing the
  NF-5 conformance suite. It MUST NOT be exclusive, MUST NOT be permanent, and MUST be
  re-earned on the published cadence.
- S-9. CarNimbus is **not a preferential licensee.** Terms are FRAND and identical for all
  implementers (NF-WP-1 §10.3, §9.10). The Foundation MUST NOT grant early access,
  preferential terms, private specification text, or a conformance result that depends on
  who the implementer is.
- S-10. The prime implementer MUST NOT hold a governance position that lets it decide its own
  conformance.

---

## 8. The Layer 5 gate

Layer 5 is deferred, not abandoned. The gate is a document, not a discretion: the
preconditions below are things that either exist in writing or do not.

- G-1. A V1 implementation MUST NOT contain a Layer 5 Function (L5-1).
- G-2. Layer 5 MUST NOT be reconsidered until **all** of the following are held in writing:

  1. **Securities-law clearance** covering every instrument contemplated, including any
     governance or reward unit. Absent this, the token questions are open by default.
  2. **Digital Financial Assets Law determination** — licensure or exemption — for any
     instrument that could be characterized as a store of value, and any escrow or custody
     of value. NF-WP-1 §9.7 records the tangible-net-worth expectation of roughly $100,000
     as disqualifying for the Foundation's posture; that finding is not superseded by a
     later appetite for the feature.
  3. **Money-transmission analysis** for any holding, escrow, or forwarding of funds. Note
     the V1 answer makes this largely moot: settlement is fiat via a conventional processor
     (L5-4).
  4. **Sherman Act §1 clearance** for the market structure, including a structural
     separation opinion confirming that the market operator is a distinct entity from the
     Foundation and that the Foundation takes no fee, listing authority, or preferential
     access from it (Refusal 3).
  5. **Privacy clearance** confirming that pricing introduces no new personal-information
     flow and no new immutable-ledger content (Refusal 2), and addressing whether a price
     attached to consent bears on whether the consent is freely given under the DPPA,
     Cal. Veh. Code §9951 and the CCPA. This question is for counsel; NF-1 does not answer
     it.
  6. **UCC Article 12 analysis** if any controllable electronic record is contemplated.
     California has enacted Article 12 (SB 95, Ch. 210, Stats. 2023), so this is settled
     law in the target jurisdiction, not a forecast.

- G-3. Clearances are **cumulative and non-substitutable.** A favourable opinion on one does
  not soften another, and the absence of any one keeps the gate closed.
- G-4. Two things are **outside the gate** — no clearance revives them, because they are
  charter matters and not legal ones:
  - tiered pay-to-play validator tokenomics (L5-5);
  - economic rights attached to Governance Membership (S-6).
- G-5. Consent Grants MUST remain non-transferable, unpriced and non-collateralizable even
  after the gate opens. A market in access is a different object from a market in grants; the
  gate covers the former and forecloses the latter.
- G-6. Opening the gate MUST be a published amendment to NF-1 with a version bump. It MUST
  NOT happen by implementation, pilot, or interpretation.

---

## 9. Registry considerations

The NF series depends on registries. This section follows the IANA pattern: it states what
the Foundation will request of IANA, what it maintains itself, and the change-control policy
for each. A registry with no stated change control is a registry that gets edited under
pressure.

### 9.1 Media type

The Foundation intends to register one media type for the NF-2 Consent Grant.

    Type name:               application
    Subtype name:            nf2-grant+json
    Required parameters:     none
    Optional parameters:     none
    Encoding considerations: binary; UTF-8, as produced by JSON canonicalization (RFC 8785)
    Security considerations: §10 of this document; NF-2
    Interoperability:        NF-2 defines a closed top-level key set; a member not in that
                             set MUST cause rejection, not tolerance
    Fragment identifiers:    none defined

- R-1. The media type MUST NOT define an `alg` parameter or any other algorithm-negotiation
  parameter. The cryptographic suite is pinned by the grant's in-band, signed version field.
  In-band algorithm negotiation carried outside the signature is the JWT `alg` bug class, and
  a media-type parameter is the same bug at a different layer.
- R-2. The media type MUST NOT define a version parameter. The version is a signed member of
  the object; a transport-level version can disagree with it, and then the question of which
  one governs has no good answer.
- R-3. A new grant schema version MUST use a new subtype (`application/nf2-grantN+json`) or
  rely solely on the in-band signed version — never a parameter.

### 9.2 Foundation-maintained registries

| Registry | Contents | Owner document | Policy (§9.4) |
|---|---|---|---|
| NF-2 Data Field Vocabulary | grantable field identifiers, grouped in classes, each tagged with its producing layer | NF-2 | Specification Required + §9.4 |
| NF-2 Non-Transactable Classes | class identifiers that MUST NOT have a field id | NF-2 | **CLOSED** — see R-7 |
| NF-2 DPPA Purpose Identifiers | one identifier per cited 18 U.S.C. §2721(b) permissible use | NF-2 | Statute-Bound — see R-8 |
| NF-2 Counterparty Classes | classes a grant may be issued to | NF-2 | Specification Required |
| NF-4 Revocation Reason Codes | reasons a revocation record may cite | NF-4 | Specification Required |
| NF-5 Verification Reason Codes | stable failure codes a verifier emits | NF-5 | First Come First Served, append-only |

### 9.3 Reason codes as the conformance surface

- R-4. A `verifier` MUST emit stable machine-readable failure codes, and MUST report every
  failure it found rather than only the first. NF-5 asserts *which rule fired*; a verifier
  that returns a single opaque "invalid" is untestable, and an untestable rule is an
  unenforced rule.
- R-5. Reason codes MUST NOT be renamed or reused. A renamed code silently turns a passing
  conformance assertion into a vacuous one.
- R-6. A verifier MAY add codes for local conditions, and MUST NOT reuse a registered code
  for a different condition.

### 9.4 Change control

- R-7. The Non-Transactable Classes registry is **CLOSED**. The Foundation MUST refuse any
  request to add a field identifier for a registered non-transactable class, and MUST refuse
  any request to remove an entry from it. Removal would be an amendment to Refusal 2's
  reasoning and to §6.3, requiring the process of §8/G-6 — not a registry action. This is
  written down so the refusal survives a change of personnel and a persuasive petitioner.
- R-8. DPPA Purpose Identifiers are **statute-bound**: an identifier exists only where a
  cited permissible use exists in 18 U.S.C. §2721(b). The Foundation MUST NOT mint a purpose
  identifier that has no statutory citation, because the purpose is the whole DPPA compliance
  story and an unmoored purpose is a laundering channel for one.
- R-9. Adding a field identifier REQUIRES: an identified production interface that actually
  emits it (§6.1), a provenance layer tag, a written re-identification analysis, and
  confirmation that it is not a Non-Transactable Class by another name. A field admitted
  without a re-identification analysis is how a refused class re-enters through a permitted
  one.
- R-10. Identifiers MUST NOT be reused or repurposed. Deprecation marks an entry as
  historical; it never frees the name.
- R-11. Removing a field identifier is a **breaking** change and MUST bump the NF-2 schema
  version, because live grants name it.
- R-12. Every registry entry MUST record the document and version that introduced it. A
  registry without provenance cannot be audited against the specification that authorized it.

---

## 10. Security considerations

**SEC-1 — The index is public; the architecture assumes an adversary holds it.** A Vehicle
Index is visible through a windshield, printed on documents, and enumerable. Every NF
security property is stated so that an adversary in possession of an arbitrary number of
valid indices gains nothing. Code that treats an index as a secret is wrong twice: it is
wrong about the fact, and it builds authority on the mistake (L3-2).

**SEC-2 — Grants are not secrets; they are key-bound.** A grant may be stored, logged, and
transmitted over an untrusted bearer, because it authorizes only a presenter who can prove
possession of the bound private key. This is deliberate: designs that depend on grant
confidentiality fail at the first log aggregator. Correspondingly, an implementation MUST
challenge for possession and MUST NOT accept a presented grant as a bearer token.

**SEC-3 — Pseudonym linkability is bounded, not eliminated.** Salting defeats rainbow-table
confirmation of enrolment; epoch rotation bounds cross-time joins; per-audience derivation
defeats joins between two simultaneous counterparties. What remains: a counterparty can
link its own observations within one epoch, which is inherent to receiving a stream at all.
Implementers MUST NOT describe pseudonymization as anonymization.

**SEC-4 — The salt is the erasure mechanism.** Destroying the owner-held salt destroys the
linkage between index and pseudonym. This is what makes erasure real rather than nominal
(NF-WP-1 §9.5), and it is why the salt MUST NOT be derivable from anything committed to an
immutable ledger, MUST NOT be escrowed with a counterparty, and MUST NOT be backed up to
append-only storage.

**SEC-5 — Canonicalization is a security boundary.** Grant integrity depends on one object
producing exactly one byte sequence. Any construction that lets one semantic grant produce
two canonical forms produces two commitments, and NF-4 keys revocation by commitment — so
the second form evades a revocation entry. Implementations MUST reject inputs that
canonicalize ambiguously rather than normalizing them, and MUST bound canonicalization
depth: unbounded nesting is a stack overflow reachable from any untrusted body.

**SEC-6 — Closed key sets are a privilege-escalation defence.** A verifier that ignores an
unrecognized member will accept a grant carrying a term the issuer signed and the verifier
does not enforce. Unknown members MUST cause rejection.

**SEC-7 — No in-band algorithm negotiation.** The suite is pinned by the signed version.
Anything the verifier reads *before* checking the signature, to decide *how* to check the
signature, is attacker-controlled (R-1).

**SEC-8 — Sybil indices.** The index check digit is mandatory for vehicles manufactured for the
North American market (49 C.F.R. §565.15) but is not universally required by ISO 3779, so
structurally valid indices exist that fail it. Sybil-index resistance depends on the check
digit; enrolment of a real vehicle depends on tolerating its absence for some legitimate
vehicles. Implementations MUST report syntax validity and check-digit validity separately and
MUST NOT collapse them into one boolean, and enrolment MUST NOT rest on the index alone —
custody evidence is a separate, non-index input.

**SEC-9 — Revocation is the weakest link, and expiry is its fail-safe.** Revocation depends on
the owner still holding the revocation key and on the revocation store being reachable. When
either fails, the lifetime cap is the *entire* remaining bound on exposure — which is why it
is short, and why L3-7 is a hard ceiling rather than a default (§3.3).

**SEC-10 — Delegation lengthens the revocation path.** Every delegation hop adds a party the
owner never chose and lengthens the chain revocation must walk before the last holder
actually loses access. Depth MUST be bounded, and a delegated grant MUST NOT be verifiable
from its leaf alone.

**SEC-11 — Timestamp units.** A millisecond timestamp where seconds are expected is a
well-formed integer that turns a 30-day grant into an 80,000-year one, and every other
check passes. Implementations MUST range-check timestamps against a plausible window.

**SEC-12 — The credential boundary is the highest-value target.** B2 concentrates real
credentials in the adapter. Compromise there is compromise of the owner's manufacturer
account, which is strictly worse than compromise of any grant. Adapters MUST NOT expose a
credential to a counterparty and MUST NOT hold a credential they do not need.

**SEC-13 — The neutrality boundary has no cryptographic enforcement.** B5 is held by charter
alone. It is therefore the boundary most likely to erode, and the erosion is gradual and
commercially motivated rather than adversarial. §7 and §8/G-6 are the controls; the honest
statement is that they are governance controls, not technical ones.

---

## 11. Privacy considerations

**P1 — Immutability and erasure are irreconcilable, so the design never writes.** A standing
45-day Delete Act deletion cadence and CCPA erasure rights cannot be satisfied on an
immutable ledger. Refusal 2 is the resolution and B3 is its enforcement point.

**P2 — Refusal by schema, not by policy.** The Non-Transactable Classes have no encoding.
This is stronger than consent, because consent can be extracted from a party with poor
bargaining position, and there is nothing here to extract (C-7).

**P3 — Purpose limitation is auditable only if it is singular.** One DPPA purpose per grant.
A multi-purpose grant has a purpose limitation nobody can audit; two purposes are two
independently revocable grants (L3-3).

**P4 — The vocabulary is closed so that purpose limitation cannot be defeated by naming.**
An open vocabulary with an "other" or free-text field is the usual way consent regimes fail
in practice: the scope becomes whatever the requester writes.

**P5 — Class, not identity, for counterparties.** A grant names the kind of counterparty it
is issued to. The owner's decision is about kinds, which is the decision they are actually
equipped to make; and the grant need not be reissued when an insurer changes corporate form.

**P6 — Inference is a leak path.** Refusing a field does not refuse what can be inferred
from permitted fields. L4-3 requires the analysis; NF-1 does not claim the analysis is
complete.

**P7 — Data minimization is a requirement, not a virtue.** Implementations SHOULD request
the narrowest field set and the shortest lifetime that accomplishes the stated purpose. The
ceilings in §3.3 exist to bound failure, not to describe normal practice.

---

## 12. Implementation constraints

NF-WP-1 §14 binds the reference stack, and the constraint is normative for the reference
implementation (it is not a conformance requirement for third parties, whose stacks are
their own). Stated here because it shapes what the specifications can assume.

- I-1. Cloudflare Workers, vanilla HTML/CSS/JS, D1/SQLite, Clerk, Supabase, Inngest, Stripe,
  Twilio. No npm, no build step, no third-party dependencies.
- I-2. Plain ES modules only. No TypeScript, no JSX, no bundler, no transpile. Web-standard
  APIs only.
- I-3. Cryptography via WebCrypto only. Never hand-roll a cipher or a curve. Ed25519 name
  resolution is feature-detected at runtime.
- I-4. D1 via bindings and prepared statements; every query parameterized; user input never
  interpolated into SQL.
- I-5. Consequence for the specifications: NF-2 … NF-5 MUST be implementable with
  web-standard APIs alone. A specification that requires a dependency the reference stack
  cannot install is not implementable in the reference stack, and NF-5 could not test it.
- I-6. The only exception: the conformance suite MAY use Node built-ins (`node:test`,
  `node:assert`). Still no third-party packages.

---

## 13. References

### 13.1 Normative

- NF-WP-1, *The Consent-Governed Catallaxy*, Nimbus Foundation, July 2026.
- RFC 2119, *Key words for use in RFCs to Indicate Requirement Levels*.
- RFC 8174, *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words*.
- RFC 8785, *JSON Canonicalization Scheme (JCS)*.
- ISO 3779, *Road vehicles — Vehicle identification number (VIN) — Content and structure*.
- ISO 20078, *Road vehicles — Extended vehicle (ExVe) web services*.
- 49 C.F.R. Part 565 (vehicle identification number requirements).
- 18 U.S.C. §2721(b), Driver's Privacy Protection Act permissible uses.
- Cal. Civ. Code §1798.140(ae) (CCPA sensitive personal information).
- Cal. Veh. Code §9951.
- 17 U.S.C. §1201 (DMCA anti-circumvention).
- 15 U.S.C. §1 (Sherman Act §1).
- California SB 95, Ch. 210, Stats. 2023 (enacting UCC Article 12).

### 13.2 Informative

- *Van Buren v. United States*, 593 U.S. 374 (2021).
- California Delete Act (deletion-request cadence).
- California Digital Financial Assets Law.
- IRC §501(c)(6).
- USDOT roadside-unit device cost estimate, 2025 (~$3,000–$5,000 per device).

---

## Appendix A — Layer summary

| Layer | Name | Owner | Foundation's role | Hard constraint |
|---|---|---|---|---|
| 1 | Connectivity substrate | Network operators, road authorities | none — depends on it | Network position is never authority (L1-1) |
| 2 | Authenticated access | OEMs, tool vendors | consume read-only | No actuation, no circumvention; credentials never cross up (L2-1, L2-2, L2-4) |
| 3 | Consent layer | Brokers implement, owners control | **specify + conformance** | Index resolves to location, never authority; no PI on-chain (L3-1, L3-2, L3-8) |
| 4 | Data layer | Processors, under grants | **specify + conformance** | Authorize per access; allowlist projection; no economic reward (L4-1, L4-2, L4-4) |
| 5 | Market layer | not the Foundation, ever | **gate only** | Absent from V1 by structure, not policy (L5-1, L5-2) |

## Appendix B — Boundary summary

| ID | Boundary | Must not cross | Enforced by |
|---|---|---|---|
| B1 | L1 ↔ L2 | authority upward | Layer 2 authentication |
| B2 | L2 ↔ L3 | credentials upward; commands downward | architecture — adapter is sole credential holder |
| B3 | L3 ↔ ledger | PI, or anything PI-derivable | schema — only fixed-length commitments exist |
| B4 | L3 ↔ L4 | a verdict without revocation state | verifier interface requires the state as input |
| B5 | Foundation ↔ implementers | grants, keys, market operation, preference | charter; the Foundation occupies no role |

## Appendix C — Requirement index

- Layer requirements: L1-1…L1-3, L2-1…L2-6, L3-1…L3-10, L4-1…L4-6, L5-1…L5-6
- Ceiling: C-1…C-9
- Foundation and separation: S-1…S-10
- Layer 5 gate: G-1…G-6
- Registries: R-1…R-12
- Security considerations: SEC-1…SEC-13
- Implementation: I-1…I-6
