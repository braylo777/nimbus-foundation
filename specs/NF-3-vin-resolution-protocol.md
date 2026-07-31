# NF-3: VIN Resolution Protocol

**Nimbus Foundation Standard NF-3, Version 1**
Status: **Draft standard**, V1 scope
Traces to: NF-WP-1, "The Consent-Governed Catallaxy" (July 2026), §3.1 (Layer 3), §8.3, §9.5, §10.1, §12.2, §12.7, §14
Companion standards: NF-2 (Consent Grant), NF-4 (Revocation state), NF-5 (Conformance)
Reference implementation: `broker/src/nf3-resolve.js` — **ABSENT at the time of writing; see §16**

---

## 1. Introduction

### 1.1 What this protocol is

NF-3 maps a Vehicle Identification Number to the network location of the **consent endpoint**
that is authoritative for that vehicle. That is the whole of it.

The protocol is modelled explicitly and deliberately on the Domain Name System
(Mockapetris, RFC 1034 and RFC 1035, November 1987). The correspondence is not a loose
metaphor; it is the design:

| DNS | NF-3 |
| --- | --- |
| Domain name | VIN (17 characters, ISO 3779) |
| Zone | A prefix of the VIN name space |
| Authoritative name server | Consent authority |
| A / AAAA / SRV record | `nf3-endpoint` record |
| NS + DS record | `nf3-delegation` record |
| DNSKEY record | `nf3-key` record |
| NXDOMAIN + NSEC | `nf3-nx` record (signed prefix range) |
| Recursive resolver | Recursive resolver (§7) |
| TTL, negative TTL | TTL with floors and ceilings (§8) |
| RRSIG, chain of trust | Record signature, chain from trust anchor (§9) |

The analogy carries one property above all others, and it is the reason the analogy was
chosen:

> **Resolving a name to an address does not grant a right to the resource.**

Resolving `example.com` to an IP address confers no login. Resolving a VIN to a consent
endpoint confers no authorization over the vehicle. NF-3 returns **where to ask**. It never
returns **the answer**, and it never returns **the means of asking**.

### 1.2 Why a naming layer exists at all

Without a naming layer, every party wanting to ask an owner for consent must already know
which operator, OEM, or broker holds that owner's consent relationship. That knowledge is a
directory, and whoever holds the only directory holds the market. NF-3 exists so that the
directory is a distributed public naming function rather than a private asset — the same
reason DNS exists rather than HOSTS.TXT.

### 1.3 The three refusals in NF-3 (NF-WP-1 §10.1)

1. **A VIN is never resolved to a credential.** This is NF-3's entire normative core, stated
   as a prohibition in §10 and made conformance-testable in §14. Possession of a VIN, and
   possession of every record NF-3 will ever return for that VIN, confers no authority
   anywhere in any code path.
2. **No personal information reaches an immutable ledger.** NF-3 records are mutable,
   deletable, TTL-bounded, and **MUST NOT** be committed to any ledger (§12.4). The Delete
   Act's broker disclosures expressly enumerate VINs as a category of personal information
   collected (NF-WP-1 §9.5); a VIN-keyed record set on an immutable ledger would be
   irreconcilable with a standing 45-day erasure cadence.
3. **The Foundation never operates what it governs.** The Foundation publishes trust anchors
   and conformance tests as standards artefacts. It **MUST NOT** operate an authoritative or
   recursive resolver for vehicles it does not own, **MUST NOT** condition trust-anchor
   inclusion on commercial terms, and **MUST NOT** be a required participant in any
   resolution (§6.5).

### 1.4 Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described
in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

### 1.5 Scope boundaries

NF-3 specifies naming and nothing else. Out of scope, each with the standard that owns it:

- Issuing, verifying, delegating, or renewing a Consent Grant — **NF-2**.
- Revocation state, cascade, and its commitments — **NF-4**.
- Which fields a given vehicle can actually yield — the endpoint's business, under
  authorization, bounded by the NF-2 closed vocabulary (`broker/src/fields.js`).
- Price, availability, payment, settlement, and any form of exchange — **Layer 5, deferred
  and gated out of V1** (NF-WP-1 §9.7). NF-3 contains no price field and no place to put one.

---

## 2. Terminology

**Name.** A canonical VIN (§3). The unit of query.

**Prefix.** The first *n* characters of a canonical name, 1 ≤ *n* ≤ 17. The unit of zoning.
Unlike DNS, significance runs **left to right**: the World Manufacturer Identifier occupies
characters 1–3 (49 C.F.R. Part 565), so the name space is a prefix tree rooted at the empty
prefix.

**Zone.** A prefix together with the set of names extending it, minus any sub-prefixes
delegated away.

**Consent authority (or "authority").** The entity authoritative for a zone. It answers
"where do you ask about names in this zone." It is **not** necessarily the operator of the
endpoint it names, and it holds no Consent Grants by virtue of being an authority.

**Consent endpoint.** The HTTPS origin at which a requesting party may *ask* for a Consent
Grant under NF-2. NF-3 names it and says nothing else about it.

**Requesting party (or "querier").** Any party performing resolution.

**Resolver.** Software performing the algorithm in §7.1 (iterative) or §7.2 (recursive).

**Stub.** A client that delegates iteration to a recursive resolver.

**Trust anchor.** A locally configured authority identifier and public key from which
validation chains begin (§9.3).

---

## 3. Canonical name form

### 3.1 Normative form

A canonical name is exactly 17 characters from the ISO 3779 character set
`[A-HJ-NPR-Z0-9]` — I, O and Q are excluded to avoid confusion with 1 and 0.

Implementations **MUST** obtain this form via `validateVin()` from `broker/src/vin.js` and
**MUST NOT** reimplement the charset or check-digit logic.

Permitted normalization, and nothing more:

1. Strip leading and trailing whitespace.
2. Upper-case ASCII letters.

### 3.2 Prohibited normalization

A resolver **MUST NOT** perform character substitution of any kind on a name — in
particular it **MUST NOT** map `O`→`0`, `I`→`1`, or `Q`→`0`, and **MUST NOT** attempt
"nearest valid VIN" correction.

The reason is not tidiness. Silent substitution maps a queried name onto a *different
vehicle's* name, and the querier receives a confident, correctly signed answer about a
vehicle it did not ask about. Every downstream authorization then concerns the wrong car.
Transcription error is common in this domain; the correct handling is a local failure, not a
guess.

### 3.3 Check digit

A resolver **MUST** accept a name that is syntactically valid but whose ISO 3779 check digit
does not verify, and **MUST** resolve it normally.

`vin.js` reports syntax validity and check-digit validity separately, and its reasoning
governs here: the check digit is mandatory for vehicles manufactured for the North American
market (49 C.F.R. § 565.15) but is not universally required by ISO 3779, so grey-market and
some non-NA vehicles carry structurally valid VINs that fail it. A resolver that refuses
those names cannot resolve a legally registered vehicle — a defect, not a policy. A resolver
**MAY** report check-digit status to its caller; it **MUST NOT** make resolution conditional
on it.

### 3.4 Malformed names are not resolved

If a name fails syntax validation, the resolver **MUST** fail locally with
`name_malformed` and **MUST NOT** transmit the input to any authority. A malformed string is
not a name, and forwarding it leaks the querier's input — including whatever a
mis-integrated caller passed in place of a VIN — to a third party.

### 3.5 Name ordering

Where an ordering over names or prefixes is required (§5.4 range records, canonical array
ordering), implementations **MUST** use `compareCodeUnits()` from `broker/src/jcs.js`.

One ordering in the system, exported from one place. NF-2 already sorts grant field arrays
with it; a second, subtly different comparator is how a signed range comes to mean different
things to signer and verifier.

---

## 4. Transport and wire encoding

### 4.1 Encoding

All NF-3 messages and records are JSON, canonicalized per RFC 8785 (JCS) using
`canonicalize()` / `canonicalizeToBytes()` from `broker/src/jcs.js`.

JSON-over-HTTPS rather than a DNS-style binary wire format, for three reasons:

1. The signed unit must have exactly one byte representation, and the system already has one
   canonicalizer with a tested rejection surface. Two serializers means two answers to "what
   was signed."
2. The binding stack (NF-WP-1 §14) is Cloudflare Workers with no build step and no
   dependencies. `fetch`, `Request`/`Response`, and `crypto.subtle` are available; a UDP
   wire format is not.
3. Plaintext UDP DNS is the substrate of reflection and amplification attacks and of
   trivially observable queries. Choosing a TLS request/response transport removes the
   amplification vector at the format level rather than mitigating it later (§13.1).

### 4.2 HTTP binding

- A query **MUST** be an HTTP `POST`. Request `Content-Type` and response `Content-Type`
  **MUST** be `application/nf3+json`.
- The name **MUST** appear only in the request body. A resolver **MUST NOT** place a name in
  a request line, path segment, query string, or HTTP header. URLs are logged by
  intermediaries, retained in referrers, and cached by generic HTTP machinery, none of which
  is under the querier's control; a name in a URL is a permanent third-party record of the
  question (§13.3).
- TLS 1.3 or later is **REQUIRED**. A resolver **MUST NOT** fall back to an earlier version,
  to plaintext, or to an unauthenticated transport. No record at all is the correct outcome;
  see §11.5.
- Responses **MUST** carry `Cache-Control: no-store`. NF-3 caching is performed by the NF-3
  resolver against validated records (§8), not by generic HTTP caches keyed on URLs, which
  cannot validate a signature and cannot enforce a TTL floor.
- A resolver **MUST NOT** send or accept cookies, and an authority **MUST NOT** set them.
- An authority **MUST NOT** require an `Authorization` header, API key, account, or contract
  to answer a resolution query. See §6.5 — this is a Refusal-3 constraint, not a courtesy.

### 4.3 Message size and count limits

An implementation **MUST** enforce:

| Limit | Value | Reason |
| --- | --- | --- |
| `MAX_MESSAGE_BYTES` | 65536 | Bounds memory and parse cost from an untrusted peer. |
| `MAX_ANSWER_RECORDS` | 8 | An answer is one endpoint, or a small key set during rollover. A long answer list is either a bug or an attempt to exhaust a verifier. |
| `MAX_REFERRAL_RECORDS` | 4 | A zone cut names one child authority; a handful of resolver locations for it at most. |

Exceeding a limit is a hard failure (`message_oversize`, `answer_count_exceeded`), not a
truncation. Truncating a signed set silently changes what was verified.

### 4.4 Query message

Closed key set. Every key **MUST** be present, with explicit `null` where unused.

```json
{
  "v": "nf3-query/1",
  "name": "1HGCM82633A004352",
  "qtype": "endpoint",
  "nonce": "3q2-7wAAAAAAAAAAAAAAAA",
  "recursion_desired": false,
  "known_authority": null
}
```

| Member | Type | Rules |
| --- | --- | --- |
| `v` | string | `"nf3-query/1"`. Pins the version and the cryptographic suite. |
| `name` | string | Canonical name (§3). |
| `qtype` | string | One of `"endpoint"`, `"delegation"`, `"key"`. Closed set. |
| `nonce` | string | 16 random bytes, base64url (22 chars), from `crypto.getRandomValues`. 128 bits, because the 16-bit DNS transaction ID is the reason off-path poisoning was ever practical (§13.1). |
| `recursion_desired` | boolean | Requests recursive service (§7). An authority **MAY** refuse. |
| `known_authority` | string \| null | The authority id the querier believes is authoritative, from cache. Lets the responder answer `not_authoritative` cheaply. Advisory only; a responder **MUST NOT** vary the *content* of an answer based on it. |

### 4.5 Answer message

```json
{
  "v": "nf3-answer/1",
  "name": "1HGCM82633A004352",
  "qtype": "endpoint",
  "nonce": "3q2-7wAAAAAAAAAAAAAAAA",
  "status": "authoritative",
  "answer": [ { "...": "nf3-endpoint/1 record" } ],
  "referral": [],
  "keys": [ { "...": "nf3-key/1 record" } ],
  "responder": null,
  "generated_at": 1785000000
}
```

| Member | Type | Rules |
| --- | --- | --- |
| `v` | string | `"nf3-answer/1"`. |
| `name` | string | Echo of the queried name. A validator **MUST** compare it byte-for-byte and reject on mismatch. |
| `qtype` | string | Echo. Compared and rejected on mismatch. |
| `nonce` | string | Echo. Compared in constant time where feasible; rejected on mismatch. |
| `status` | string | §4.6. Closed set. |
| `answer` | array | Signed records answering the query. Empty except on `authoritative`. |
| `referral` | array | Signed `nf3-delegation/1` records. Non-empty only on `referral`. |
| `keys` | array | Signed `nf3-key/1` records needed to validate this message's records. Convenience only; a validator **MUST** still confirm each key against the thumbprint committed by the parent delegation. |
| `responder` | string \| null | Opaque identifier of the responding resolver, for operational diagnosis. **Carries no authority.** A validator **MUST NOT** let its value affect validation in any way. |
| `generated_at` | integer | Unix **seconds**. Advisory; the authoritative time bounds are inside each record's signature. |

### 4.6 Status values

| Status | Meaning | Notes |
| --- | --- | --- |
| `authoritative` | The responder is authoritative for `name`; `answer` holds the records. | |
| `referral` | Not authoritative; `referral` holds the zone cut to follow. | |
| `no_authority` | No authority claims `name`. `answer` holds one signed `nf3-nx/1`. | **This is not "the vehicle is not enrolled."** See §5.4 and §12.2. |
| `conflict` | Two or more valid, mutually exclusive chains claim `name`. Fail closed. | §6.4. |
| `not_authoritative` | The `known_authority` hint is stale. Restart from the anchor. | Carries no records. |
| `refused` | Administratively refused (rate limit reached, malformed request). | **MUST NOT** be used to discriminate between queriers (§6.5). |
| `servfail` | Transient failure. | Unsigned; a resolver **MUST NOT** cache it. |

`no_authority`, `conflict` and `not_authoritative` are the only negative statuses that
**MAY** be cached, and only `no_authority` may be cached on the strength of a record (§8.4).

### 4.7 Timestamps

Every integer time in NF-3 is Unix **seconds**. Implementations **MUST** range-check every
timestamp against `MIN_PLAUSIBLE_TIME_S` and `MAX_PLAUSIBLE_TIME_S`, imported from
`broker/src/nf2-grant.js`.

This catches the milliseconds-for-seconds error, which no other check catches: a millisecond
timestamp is a well-formed integer that silently converts a 24-hour TTL ceiling into a
27-year one.

---

## 5. Record types

### 5.1 Rules common to all records

These rules apply to every record type and are load-bearing in the same way NF-2's are.

1. **Closed key set.** Each record type has a fixed top-level key set. Every key **MUST** be
   present. A key that does not apply **MUST** be present with the value `null` and **MUST
   NOT** be omitted. A validator **MUST** reject a record containing an unknown key and
   **MUST** reject a record missing a known key.

   Both halves matter. Unknown keys are rejected because a validator that ignores an
   unrecognized key will happily accept a record carrying something the signer intended and
   the validator does not enforce — which is precisely how a bearer value gets smuggled
   through a naming layer (§10.3). Absent-versus-null is fixed because the two canonicalize
   to different bytes, so permitting both gives one semantic record two signatures and two
   cache identities.

2. **No `alg` member, anywhere.** The signature suite is pinned by `v`, which is inside the
   signed bytes. In-band algorithm negotiation is the JWT `alg` class of bug: a verifier that
   reads the algorithm out of the object it is verifying has already lost.

3. **Signature.** Ed25519 over `canonicalizeToBytes(record)` with `signature` set to `null`
   removed — that is, over the record's JCS canonicalization *sans* the `signature` member,
   exactly as NF-2 defines its signing input. Raw 64 bytes, base64url (86 chars).

4. **Arrays are sorted.** Every array member of a record **MUST** be sorted with
   `compareCodeUnits()` and **MUST** be free of duplicates. JCS treats array order as
   significant; an unsorted set gives one semantic record several distinct signatures.

5. **Keys are 32-byte raw Ed25519 public keys, base64url (43 chars).** Thumbprints are
   32-byte SHA-256 digests, base64url (43 chars), domain-separated per §9.2.

6. **No personal information, ever.** See §12 for the exhaustive prohibition. In particular
   no record contains an owner identity, an owner contact channel, a vehicle attribute, a
   Consent Grant, a grant commitment, a grant count, a counterparty identity, or an NF-2
   `vehicle_pseudonym`.

### 5.2 `nf3-endpoint/1` — where to ask

The A/AAAA/SRV analog: the terminal answer of a successful resolution.

```json
{
  "v": "nf3-endpoint/1",
  "scope": "wmi",
  "prefix": "1HG",
  "authority": "kQ9…43chars",
  "endpoint": "https://consent.example-authority.org/nf2/request",
  "grant_versions": ["nf2-grant/1"],
  "counterparty_classes": ["fleet-operator", "repair-independent"],
  "ttl": 3600,
  "sig_not_before": 1784900000,
  "sig_not_after": 1785400000,
  "signature": "…86chars"
}
```

| Member | Type | Rules |
| --- | --- | --- |
| `v` | string | `"nf3-endpoint/1"`. |
| `scope` | string | `"wmi"` (prefix length exactly 3), `"prefix"` (length 1–16), or `"name"` (length 17). Closed set. Redundant with `prefix.length` **on purpose**: the signer states its intent, so a validator can reject a record whose declared scope and actual prefix disagree rather than inferring which one the signer meant. |
| `prefix` | string | The prefix this record answers for. **MUST** be a prefix of the queried name, and **MUST** be within the signing authority's zone. |
| `authority` | string | Authority id (§9.2) of the signer. |
| `endpoint` | string | Absolute `https://` URL. Scheme **MUST** be `https`. **MUST NOT** contain a query string, fragment, userinfo, or any path segment that varies by name — see §10.4 on capability URLs. |
| `grant_versions` | array | NF-2 schema versions the endpoint speaks, e.g. `["nf2-grant/1"]`. Sorted, non-empty. Lets a querier avoid contacting an endpoint it cannot transact with, without disclosing anything about a vehicle. |
| `counterparty_classes` | array \| null | Counterparty classes (`broker/src/fields.js` `COUNTERPARTY_CLASSES`) the endpoint will *entertain requests from*. **MUST** be `null` when `scope` is `"name"`. |
| `ttl` | integer | Seconds. Clamped per §8.2. Inside the signature — see §8.5. |
| `sig_not_before` / `sig_not_after` | integer | Signature validity window, Unix seconds. §9.5. |
| `signature` | string | §5.1(3). |

**Why `counterparty_classes` is forbidden on a name-scoped record.** On a zone-scoped record
the list describes the *authority's* operational posture — public, institutional, not about
any person. On a single vehicle it describes the *owner's* consent posture, disclosed before
any authorization has been sought or granted. That is an answer that belongs to the consent
layer, where the endpoint can apply purpose limitation and a grant check. Publishing it in
the naming layer answers "would this owner deal with an insurer?" to anyone who can type a
VIN. Design constraint over policy statement, per NF-WP-1 §8.2's method.

**Zone-uniform answers are RECOMMENDED.** An authority **SHOULD** publish `wmi`- or
`prefix`-scoped endpoint records covering its whole zone rather than per-name records. Two
consequences, both significant:

- A positive answer then reveals that *the authority participates*, not that *this owner
  participates*. Per-name records are an enrolment oracle; zone-scoped records are not
  (§13.2). An authority that publishes per-name records **MUST** accept that it is
  publishing that oracle.
- A querier holding a cached zone record can resolve subsequent names in that zone **with no
  query at all**, which is the strongest available defence against traffic analysis: the
  query that is never sent cannot be observed (§13.3).

Whether a given vehicle has anything to grant is then decided at the endpoint, under
authorization. That is the correct place for it, and it is what §1.1 means in practice.

### 5.3 `nf3-delegation/1` — the zone cut

The NS + DS analog. A parent authority delegates a sub-prefix to a child authority and
commits to the child's key.

```json
{
  "v": "nf3-delegation/1",
  "parent_prefix": "1HG",
  "child_prefix": "1HGCM",
  "child_authority": "aB4…43chars",
  "child_key_thumbprint": "zX7…43chars",
  "child_resolvers": ["https://resolver.child-authority.example/nf3"],
  "handoff_key_thumbprint": "pL2…43chars",
  "ttl": 86400,
  "sig_not_before": 1784900000,
  "sig_not_after": 1787320000,
  "signature": "…86chars"
}
```

| Member | Type | Rules |
| --- | --- | --- |
| `parent_prefix` | string | The delegating zone. `""` (empty string) for a root-anchored delegation. |
| `child_prefix` | string | **MUST** be a strict extension of `parent_prefix` (strictly longer, and `parent_prefix` **MUST** be a prefix of it). §6.3. |
| `child_authority` | string | Authority id of the child. |
| `child_key_thumbprint` | string | Thumbprint (§9.2) of the child's signing key. This is the hash link that makes the chain a chain. |
| `child_resolvers` | array | 1 to `MAX_REFERRAL_RECORDS` absolute `https://` URLs. **Authenticated glue** — see below. |
| `handoff_key_thumbprint` | string \| null | Thumbprint of the key permitted to sign an authority hand-off out of this zone (§6.6). |
| `ttl` | integer | Clamped per §8.2. |
| `sig_not_before` / `sig_not_after` | integer | §9.5. |

**Glue is inside the signature, and unauthenticated glue does not exist in NF-3.** In DNS,
the addresses of a child's name servers are additional-section data outside the parent's
signing authority; injecting a forged, out-of-bailiwick glue record is the mechanism the 2008
off-path cache-poisoning technique (Kaminsky) exploited. Here `child_resolvers` is a signed
member of the parent's delegation record. There is no additional section, and a resolver
**MUST NOT** accept a resolver location from anywhere but a validated delegation record.

**`child_authority` and `child_key_thumbprint` are both present** although one implies a
lookup of the other. The thumbprint is the security binding; the authority id is what a
querier compares against `known_authority` and what appears in `conflict` diagnostics. A
validator **MUST** confirm that the key it eventually imports hashes to
`child_key_thumbprint` and that the record it signs carries `authority ===
child_authority`; a mismatch is `authority_id_mismatch`, not something to reconcile.

### 5.4 `nf3-key/1` — the authority's signing key

The DNSKEY analog.

```json
{
  "v": "nf3-key/1",
  "authority": "aB4…43chars",
  "prefix": "1HGCM",
  "public_key": "…43chars",
  "ttl": 86400,
  "sig_not_before": 1784900000,
  "sig_not_after": 1787320000,
  "signature": "…86chars"
}
```

The record is self-signed by `public_key`; that self-signature proves possession, and the
*parent's* `child_key_thumbprint` is what proves authorization. A validator **MUST** check
both, and **MUST** reject a key record that validates only against itself.

**Note a deliberate divergence from NF-2.** NF-2 omits the signer's public key from a grant
on purpose: including the owner's key would let two counterparties holding differently
pseudonymized grants over the same vehicle join their data on the shared key (NF-WP-1 §12.7).
That reasoning **does not apply here and must not be imported here.** An authority is a
public institution, not a person; there is no pseudonym over an authority to un-blind, and no
join to enable. The key must be fetchable or the chain cannot be validated by anyone but its
issuer. Anyone "fixing" `nf3-key` to match NF-2's pattern would break validation to solve a
privacy problem that does not exist at this layer.

### 5.5 `nf3-nx/1` — authenticated non-existence

The NSEC analog, as a signed prefix **range**.

```json
{
  "v": "nf3-nx/1",
  "authority": "aB4…43chars",
  "zone_prefix": "",
  "range_start": "1HF",
  "range_end": "1HH",
  "ttl": 300,
  "sig_not_before": 1784900000,
  "sig_not_after": 1784986400,
  "signature": "…86chars"
}
```

`range_start` and `range_end` bound a half-open interval `[range_start, range_end)` in
`compareCodeUnits()` order, within which the signing authority delegates nothing. A validator
**MUST** confirm that the queried name falls in the interval and that `zone_prefix` is a
prefix of the queried name and within the signer's authority.

**What this record asserts.** "No authority reachable from me claims this name." It asserts
**nothing** about whether a vehicle exists, is registered, is enrolled, or has ever issued a
grant. §12.2 makes that normative, because the natural misreading — treating `no_authority`
as "not enrolled" — converts the naming layer into exactly the enrolment oracle §5.2 was
designed to avoid.

**Ranges, and no hashing.** DNSSEC's authenticated denial of existence originally leaked zone
contents to walking, which is why RFC 5155 introduced hashed (NSEC3) denial. NF-3 uses plain,
unhashed ranges and accepts that the delegation structure is walkable, because **enumeration
resistance is not a goal of this protocol** (§13.2). Ranges are what make offline signing
possible: an authority can pre-sign its whole non-existence structure and never hold an
online signing key, which removes the most attractive key-compromise target in the system.
Paying for enumeration resistance we do not want, with an online signing key we do not want,
would be the wrong trade twice.

### 5.6 Presentation format (non-normative)

For zone files, test vectors and conformance fixtures, a one-record-per-line form is
convenient. It is **non-normative**; signatures are computed over §4.1 JCS bytes only, never
over this text.

```
1HG        ENDPOINT    ttl=3600   auth=kQ9… https://consent.example-authority.org/nf2/request  gv=nf2-grant/1  cc=fleet-operator,repair-independent
""    ->   1HG         DELEGATION ttl=86400 child=aB4… kt=zX7… res=https://resolver.child.example/nf3  hk=pL2…
""         NX          ttl=300    range=[1HF,1HH)
```

---

## 6. Zone delegation

### 6.1 Delegation is a polycentric requirement, not a scaling optimization

In DNS, delegation is primarily an engineering answer to load and administrative locality. In
NF-3 it is a **governance requirement**, and it would be mandatory even if a single server
could serve the entire VIN space from a laptop.

Three reasons, in descending order of force:

1. **A single resolver is a market chokepoint.** Whoever answers every query decides who can
   find whom. That party can throttle, prefer, condition, or price access to the naming
   function — which is licensing preferential access to a market, the third refusal
   (NF-WP-1 §10.1). Delegation is what makes the position unavailable to anyone, including the
   Foundation.
2. **A single resolver sees every query.** The resolution query stream is the surveillance
   product of this system: who asked about which vehicle, when (§13.3). Delegation means no
   party holds the global view, and no party can be compelled to produce one, because it does
   not exist anywhere. This is a structural property, not a policy commitment, and it is the
   only real mitigation NF-3 has for traffic analysis.
3. **A single resolver is a single point of capture and of failure.** Every governance
   pressure — commercial, regulatory, adversarial — concentrates on one operator.

Therefore: an implementation **MUST** support at least two independent trust anchors and
**MUST** be operable with no reference to any Foundation-operated service (§6.5). A resolver
that can only function against one root is not conformant, regardless of whose root it is.

### 6.2 The two delegation axes

**WMI-scoped delegation.** A `child_prefix` of exactly 3 characters. Institutionally natural:
World Manufacturer Identifiers are assigned under 49 C.F.R. Part 565, so the boundary already
exists and already has an accountable holder. An OEM, or its designee, is the obvious
authority for its own WMI.

**Operator-scoped delegation.** A `child_prefix` longer than 3 characters, down to a full
17-character name. This is how an authority that is *not* the manufacturer becomes
authoritative — a fleet operator for the vehicles it operates, a state registry, an
independent broker the owner chose.

Operator-scoped delegation is not a convenience. Without it, the authority for every vehicle
would be the entity that built it, permanently, and the consent endpoint for a car would be
chosen by its manufacturer for the life of the vehicle. That is the OEM telematics
concentration the white paper's Layer-3 design exists to answer (NF-WP-1 §3.1, §3.3); a naming
layer that hard-wires it has defeated the purpose of having a naming layer.

### 6.3 Delegation validity rules

A validator **MUST** reject a delegation record unless all of the following hold:

1. `parent_prefix` is the prefix of the zone whose key signed the record — i.e. the parent
   does not delegate outside its own zone.
2. `child_prefix` is a **strict extension** of `parent_prefix`: strictly longer, and
   `parent_prefix` is a prefix of it. A delegation that does not narrow, or that moves
   laterally, is rejected as `delegation_not_narrowing`. This single rule eliminates referral
   loops without needing loop detection, because every accepted hop strictly decreases the
   remaining name.
3. `child_prefix` is a prefix of the name being resolved — the **bailiwick rule**. A referral
   toward a name the querier did not ask about is `delegation_out_of_bailiwick`. This is the
   rule that closes the out-of-bailiwick injection vector at the format level; combined with
   §5.3's authenticated glue, there is no unsigned, out-of-scope datum in an NF-3 message for
   an attacker to aim at.
4. Its signature validates under the key committed by the *previous* delegation in the chain
   (or by a trust anchor, at the root).
5. Its signature window and TTL are within bounds (§8, §9.5).

Sub-delegation within a single chain resolves by **longest matching `child_prefix`**, because
the longer delegation was authorized by the parent that also authorized the shorter one.
Longest-match precedence applies **only within one chain**, never across chains — see §6.4.

### 6.4 Conflicting chains fail closed

If a resolver finds two or more validating chains from its configured trust anchors that
terminate in different authorities for the same name, it **MUST** return `conflict`, **MUST
NOT** resolve the name, **MUST NOT** cache either answer, and **SHOULD** surface the
conflicting authority ids for operational escalation.

It **MUST NOT** apply a tie-break — not longest prefix, not most recent `sig_not_before`, not
anchor ordering, not first response.

This is deliberate and it is the most consequential normative choice in §6. Any tie-break rule
is an attack: an adversary who can get *one* validating chain published needs only to satisfy
the tie-break to silently capture the endpoint for a name, and the querier sees a
well-formed, correctly signed, entirely wrong answer. A conflict in a naming layer is a real
governance failure — two anchors have made incompatible statements about who speaks for a
vehicle — and the correct behaviour is to make it loudly visible and resolve nothing, not to
smooth it over. Availability is the cost; misdirected consent requests are the alternative.

### 6.5 Resolution is not a gatekeeping function

Normative constraints on every authority and resolver:

- An authority **MUST NOT** require authentication, registration, an account, a contract, or a
  commercial relationship as a condition of answering a resolution query.
- An authority **MUST NOT** return different record content to different queriers for the same
  name and `qtype`. No split horizon. (`not_authoritative` in response to a stale
  `known_authority` hint is not a content difference.)
- An authority **MAY** rate-limit. Limits **MUST** be uniform across queriers and **SHOULD**
  be published. `refused` **MUST NOT** be used to discriminate.
- The Foundation **MUST NOT** operate an authoritative or recursive resolver for names it does
  not itself own vehicles for, **MUST NOT** hold a Consent Grant, **MUST NOT** operate a
  consent endpoint, and **MUST NOT** make trust-anchor publication conditional on any
  commercial term.
- A recursive resolver **MUST NOT** be operated by a party that also operates a consent
  endpoint for names it resolves, unless it resolves only for that party's own vehicles. A
  resolver that both answers "where do you ask" and *is* the place being asked can silently
  point every query at itself, and no validator downstream can tell.

Each of these exists because the naming layer is the natural place to reintroduce the
gatekeeper the architecture is designed not to need. Note the interaction with §13.2: the
tempting defence against VIN-space enumeration — require authentication to resolve — is
prohibited here, and §13.2 explains why that is the right call.

### 6.6 Authority hand-off

An owner's choice of authority must be portable, or operator-scoped delegation (§6.2) is
theoretical. Hand-off proceeds by one of two paths:

**Parent-signed hand-off.** The incumbent authority publishes a delegation record for the
narrower prefix naming the new authority. Ordinary §6.3 mechanics; nothing new.

**Hand-off-key-signed.** Where the incumbent's delegation carried a non-null
`handoff_key_thumbprint`, a delegation record for a narrower prefix **MAY** instead be signed
by the key matching that thumbprint, and a validator **MUST** accept it as if the parent had
signed it. The thumbprint is published by the incumbent in advance, at the time it takes
authority, and commits it to honouring a hand-off it cannot later refuse. Where the key is
owner-held, portability becomes a protocol property.

**The honest limitation.** An incumbent can publish `handoff_key_thumbprint: null` and there
is no cryptographic remedy — the parent controls its own zone by construction, and any scheme
that let a third party override it would be the endpoint-capture attack of §6.4 wearing a
different hat. NF-3 cannot solve authority transfer with cryptography alone. What it can do is
make non-publication **visible and testable**: a conformant authority **MUST** publish a
non-null `handoff_key_thumbprint` on every delegation it issues, so refusal to support
hand-off is a detectable NF-5 conformance failure rather than an invisible business practice.
Enforcement is then certification and law — where a standards body's leverage actually lives,
consistent with the third refusal — not protocol. This residual is documented rather than
papered over.

---

## 7. Resolution algorithm

### 7.1 Iterative resolution (normative)

Given a name *N* and a `qtype`:

1. **Validate the name** (§3). On failure, fail locally with `name_malformed`. Do not
   transmit.
2. **Consult the cache** (§8). Return the most specific unexpired, still-signature-valid
   record whose `prefix` is a prefix of *N*. A cached zone-scoped endpoint record answers for
   every name in the zone with no query — this is the common case and the intended one (§5.2).
3. **Initialize** `matched := ""`, `key := trust anchor key`, `hops := 0`. Where several
   anchors could serve *N*, each is followed independently and §6.4 governs the outcome.
4. **Query** the current authority's resolver, from `child_resolvers` of the delegation that
   produced it (or the anchor's configured location at the root). The query carries a fresh
   128-bit `nonce`.
5. **Validate the envelope** before anything else: `v`, `name`, `qtype` and `nonce` **MUST**
   match what was sent, and message and count limits (§4.3) **MUST** hold. Reject the response
   entirely on any mismatch; do not salvage records from it.
6. **Dispatch on `status`:**
   - `authoritative` — validate every record in `answer` against `key` (§9.4), confirm each
     record's `prefix` is a prefix of *N* and within `matched`'s zone, cache (§8), return.
   - `referral` — select the delegation record with the longest `child_prefix` satisfying
     §6.3. Validate it against `key`. Import the child key, confirming it hashes to
     `child_key_thumbprint`. Set `matched := child_prefix`, `key := child key`,
     `hops := hops + 1`. If `hops > MAX_REFERRAL_HOPS`, fail `referral_limit_exceeded`. Go to
     step 4.
   - `no_authority` — validate the `nf3-nx/1` record, confirm *N* falls in its range, cache
     negatively (§8.4), return.
   - `not_authoritative` — discard any cached authority for *N*, reset to step 3, and count
     the attempt against `hops`. A responder that returns this repeatedly is failing, not
     redirecting.
   - `conflict` — propagate; do not resolve, do not cache.
   - `refused` / `servfail` — retry per §7.3, then fail. Do not cache.
   - Anything else — fail `status_unknown`. Fail closed on an unrecognized status; a resolver
     that ignores what it does not understand will eventually ignore something that mattered.
7. **Never lower validation to make progress.** A resolver **MUST NOT** retry with signature
   validation disabled, with a relaxed bailiwick rule, over a downgraded transport, or against
   a resolver location it did not obtain from a validated delegation. No answer is a correct
   outcome; a weakly validated answer is not.

`MAX_REFERRAL_HOPS` **MUST** be 8 or lower. The realistic chain is root → WMI → operator
prefix → possibly one hand-off, so 8 is generous while bounding an adversarial referral chain
constructed to exhaust a resolver.

### 7.2 Recursive resolution (normative)

A recursive resolver performs §7.1 on behalf of a stub. It is a **performance and privacy
aggregation** function and confers **no authority whatsoever**. Therefore:

- It **MUST** pass through each authority's records byte-for-byte, with signatures intact.
- It **MUST NOT** synthesize a record, re-sign a record, alter a `ttl`, alter a signature
  window, or reorder a record's arrays. Any of these invalidates the signature; a resolver
  that does it and expects clients to cope is asking clients to stop validating.
- It **MUST NOT** omit records needed to validate the chain it returns.
- It **MUST NOT** offer any "validated" or "authentic data" flag, and there is no member in
  §4.5 to carry one. DNS's AD bit invites a stub to trust a resolver's *claim* to have
  validated; NF-3 has no such affordance by construction. `responder` is diagnostic and
  §4.5 requires validators to ignore it for validation purposes.
- It **MUST NOT** return a record it could not itself validate, and **MUST NOT** return a
  partially validated chain with the gap unmarked.

**A validating stub MUST validate the full chain itself.** A non-validating stub is permitted
**only** where both hold: (a) the stub-to-resolver link is mutually authenticated, and (b) the
resolver is operated within the same trust domain as the stub — a fleet's own resolver for its
own vehicles. Even then §6.5's separation rule applies: that resolver **MUST NOT** be
operated by a party that operates consent endpoints for the names it resolves.

Recursion is a genuine privacy trade, and implementers **MUST** understand which way it cuts:
it hides the stub from authoritative servers, and it concentrates the stub's entire query
stream in one log. §13.3 covers the consequences.

### 7.3 Timeouts and retries

- Per-query timeout **SHOULD** be 2–5 seconds; total resolution budget **SHOULD NOT** exceed
  15 seconds.
- On timeout a resolver **MAY** try the next URL in `child_resolvers`, up to
  `MAX_REFERRAL_RECORDS` attempts per hop. Attempts do not increment `hops`.
- Retries **MUST** use a fresh `nonce`. Reusing a nonce across retries gives an off-path
  attacker multiple races against one target value, which is the arithmetic that made DNS
  birthday attacks practical.
- A resolver **MUST NOT** treat repeated failure as a negative answer. Unreachable is not
  non-existent; conflating them lets a denial-of-service attack manufacture a cacheable "no
  authority" (§13.1).

---

## 8. Caching

### 8.1 What is cached

A resolver caches **validated records**, keyed by `(record type, prefix)`. It **MUST NOT**
cache an unvalidated record, an envelope, a `servfail`, a `refused`, or a `conflict`.

A cached zone-scoped `nf3-endpoint/1` answers every name in its zone. This is the design's
main efficiency **and** its main privacy mechanism, in that order of appearance and the reverse
order of importance (§5.2, §13.3).

### 8.2 TTL floors and ceilings

A resolver **MUST** clamp every `ttl` it caches into the range for the record type:

| Record type | Floor | Ceiling |
| --- | --- | --- |
| `nf3-endpoint/1` | 300 s (5 min) | 86400 s (24 h) |
| `nf3-delegation/1` | 3600 s (1 h) | 86400 s (24 h) |
| `nf3-key/1` | 3600 s (1 h) | 86400 s (24 h) |
| `nf3-nx/1` (negative) | 60 s | 900 s (15 min) |

Clamping, not rejection: a TTL outside the range is brought into it. A single mistyped TTL
should not make a vehicle unresolvable, and a resolver that rejects instead of clamping hands
every authority an accidental denial-of-service against its own zone.

**A TTL of 0 clamps to the floor. There is no "do not cache" TTL, and an authority cannot opt
out of caching.**

This inverts the DNS relationship and the inversion is the point. In DNS, TTL principally
serves the *zone operator's* load, so the operator sets it and may set it to zero. In NF-3 the
TTL **floor** serves the *querier's* privacy: every expiry is a query, every query is an
observable event linking a querier to a vehicle at a time (§13.3), and an authority that sets
a very short TTL — or zero — converts resolution into a real-time feed of who is looking at
which vehicle. That feed is worth money and is exactly the surveillance position the
architecture refuses. The floor therefore is not the authority's to waive, and a conformant
resolver enforces it against the authority's stated wishes.

### 8.3 Ceilings, revocation, and erasure

The ceilings are propagation bounds on three different failures, and each fixes a number:

- **Endpoint, 24 h.** The bound on how long a querier keeps sending consent requests to an
  endpoint that has moved or been withdrawn.
- **Delegation and key, 24 h.** The bound on how long a de-certified, compromised, or
  replaced authority keeps receiving queries. This is deliberately *shorter* than common DNS
  NS-record practice: delegation revocation is the security-critical propagation path here, so
  NF-3 trades query volume for revocation speed.
- **All positive records, 24 h ⋘ 45 days.** The Delete Act deletion cadence NF-2 pins its
  grant lifetime to (NF-WP-1 §9.5) is 45 days. The cache ceiling is the upper bound on how
  long a *deleted* NF-3 record can still be served anywhere, so the ceiling must be far
  shorter than the erasure cadence or erasure is nominal. 24 hours against 45 days is a
  comfortable margin, and it is why a ceiling exists at all rather than "as long as the
  signature is valid."

### 8.4 Negative caching, and why its TTL is shorter

A validated `nf3-nx/1` **MAY** be cached for the name and range it covers, subject to the
60 s floor and **900 s ceiling** — far shorter than any positive record. Three reasons:

1. **A cached negative is a denial-of-service with a long tail.** A negative answer denies
   the *owner* the ability to be found and therefore to be asked for consent at all. One
   successful injection cached for 24 hours is a day-long outage on one vehicle's
   participation; cached for 15 minutes it is a nuisance. The asymmetry of consequence between
   a wrong positive (misdirected request, detectable at the endpoint) and a wrong negative
   (silent unreachability, detectable by nobody) justifies the asymmetry of TTL.
2. **Negative answers are the answers most likely to become wrong.** Delegation grows: new
   WMIs are assigned, new authorities are delegated, owners move to new authorities.
   Non-existence is the least stable claim in the system, and staleness in it is
   indistinguishable from a fault.
3. **Negative answers are the cheapest to induce.** An adversary can generate unlimited
   non-existent names at no cost and does not need to guess anything. Cache entries an attacker
   can cause on demand must be short-lived by default; this is the reasoning behind DNS
   negative-caching limits generally (RFC 2308).

A resolver **MUST NOT** synthesize a negative answer from a timeout, a `servfail`, a
`refused`, or a transport failure (§7.3). Unreachable is not non-existent.

### 8.5 The served TTL is the authority's TTL, not the residual

`ttl` is inside the record's signature (§5.2), so it cannot be rewritten. Consequently a
resolver serving a cached record **MUST** serve the record verbatim, including its original
`ttl`, and **MUST NOT** decrement it, substitute the remaining lifetime, or expose
cache-hit status by any other means — no age header, no hit/miss field, no
distinguishable latency signalling where avoidable.

DNS decrements TTLs in flight, and that residual value is precisely what makes **cache
snooping** work: an adversary queries a shared resolver for a VIN and reads the residual TTL to
learn that somebody else asked about that vehicle recently, and roughly when. Over a fleet or a
dealership's resolver that reconstructs service visits, inspections, and sales without ever
seeing a record's contents.

The cost is real and accepted: a downstream cache may hold a record for up to twice its
nominal TTL, bounded absolutely by the signature window (§9.5). A bounded doubling of cache
lifetime is a smaller harm than a working side channel over vehicle events, and unlike the
side channel it is bounded by construction.

---

## 9. Response authentication

### 9.1 Object security, not channel security

TLS is **REQUIRED** (§4.2) and is **not sufficient**. TLS authenticates one hop; resolution is
multi-hop by design — a record travels from an authority through recursive resolvers and caches
to a querier that has no TLS relationship with the authority at all. A cached record served by
a recursive resolver carries no evidence of its origin unless the evidence is *in the record*.

So NF-3 uses both, with distinct jobs:

- **TLS** provides confidentiality against passive observers and removes the plaintext
  transaction an off-path attacker would race (§13.1, §13.3).
- **Record signatures** provide authenticity and integrity end-to-end, through arbitrarily
  many caches, verifiable by any party at any later time.

A validator **MUST NOT** accept a record on the strength of the transport, and **MUST NOT**
accept a record on the assertion of any intermediary (§7.2).

### 9.2 Authority identifiers and thumbprints

An **authority id** and a **key thumbprint** are both 32-byte SHA-256 digests, base64url,
domain-separated:

```
authority id     = SHA-256( "nf3-authority-id:v1:"  || raw_ed25519_public_key )
key thumbprint   = SHA-256( "nf3-key-thumbprint:v1:" || raw_ed25519_public_key )
```

Two distinct domain tags over the same input, deliberately, so an authority id can never be
presented where a thumbprint is expected or vice versa; and both are domain-separated from
NF-2's `nf2-revocation-key-id:v1:` and `nf2-grant-commitment:v1:` so no digest in this system
can be replayed as a digest of another kind. Same construction and same reasoning as
`revocationKeyIdFromPublicKey()` in `nf2-grant.js`.

### 9.3 Trust anchors

A trust anchor is a locally configured `(prefix, authority id, public key)` triple, with
`prefix` normally `""`.

- An implementation **MUST** support **at least two** independently configured anchors and
  **MUST** be fully operable with no Foundation-published anchor present (§6.1, §6.5).
- Anchors **MUST** be configured out of band. A resolver **MUST NOT** learn a new anchor from
  a resolution response, at any status, under any signature. Bootstrapping trust from the thing
  being validated is not validation.
- The Foundation **MAY** publish an anchor set as a standards artefact. It confers no
  operational role and no privilege (§1.3).
- Anchor rollover is an out-of-band configuration change. NF-3 has no in-band anchor update
  mechanism, on purpose: an in-band mechanism is a remote-code-authority channel into every
  resolver in the system.

### 9.4 Record validation (normative order)

For each record, in this order, failing closed at the first failure:

1. **Shape.** Plain object; closed key set complete; no unknown keys; every type correct;
   every base64url field the exact expected byte length; arrays sorted by `compareCodeUnits`
   and duplicate-free (§5.1).
2. **Version.** `v` exactly matches a supported record version. An unsupported version is
   `record_version_unsupported` — never "ignore and continue."
3. **No prohibited content.** §10 and §12 checks. Run **before** signature verification, so a
   correctly signed record carrying a prohibited value is rejected as prohibited rather than
   accepted as authentic. A valid signature over a forbidden field is a signed violation, not
   an authorization.
4. **Timestamps.** `sig_not_before`, `sig_not_after`, `ttl` all within plausible-time range
   (§4.7) and within §9.5 bounds.
5. **Scope.** `prefix` / `child_prefix` / range consistent with the queried name, the declared
   `scope`, and the signing zone (§5.2, §6.3, §5.5).
6. **Chain position.** The signing key is the one committed by the parent delegation's
   `child_key_thumbprint` (or a trust anchor). Recompute the thumbprint; do not trust the
   `authority` member to identify the key.
7. **Signature.** Ed25519 verify over `canonicalizeToBytes(record without signature)`.

Steps 1–6 before 7 is not an optimization. Verifying a signature over a structure you have not
yet constrained tells you only that *somebody* signed *something*; every field that gates
interpretation must already be checked, or the signature is being asked to carry meaning it
does not have.

### 9.5 Signature validity windows, separate from TTL

Every record carries `sig_not_before` and `sig_not_after`. These are **not** the TTL and serve
a different purpose: a TTL is a caching parameter, and the signature window is an assertion
lifetime that no cache can alter because it is inside the signed bytes.

Requirements:

- `sig_not_before < sig_not_after`, both within plausible-time range (§4.7).
- A validator **MUST** reject a record outside its window, and **MUST** apply a clock-skew
  tolerance no greater than `DEFAULT_CLOCK_SKEW_S` (300 s) from `nf2-grant.js`.
- `sig_not_after − sig_not_before` **MUST NOT** exceed: **7 days** for `nf3-endpoint/1`,
  **30 days** for `nf3-delegation/1` and `nf3-key/1`, **24 h** for `nf3-nx/1`.
- The window **MUST** be at least as long as the clamped `ttl`, or the record is unusable for
  its own stated cache lifetime (`sig_window_shorter_than_ttl`).
- **Effective cache lifetime is `min(clamped ttl, sig_not_after − now)`.** A validator **MUST**
  take the minimum and **MUST** reject a record whose window has expired even if its TTL has
  not, and vice versa.

The window ceilings are the bound on **stale-record replay** by a compromised or coerced
intermediary. Such a party cannot forge a record, but it can withhold a new one and keep
re-serving a previously valid one; the signature window is the only thing that stops that from
lasting indefinitely, since TTL is enforced only by the honest cache being attacked. Endpoint
windows are shortest because an endpoint change is what an attacker most wants to suppress.

### 9.6 Key rollover

- An authority **MAY** publish more than one `nf3-key/1` at a time, and a parent **MAY**
  publish more than one delegation record differing only in `child_key_thumbprint`, for the
  overlap period.
- A validator **MUST** accept a record if **any** currently valid chain validates it, and
  **MUST NOT** require a specific key.
- Overlap **SHOULD** exceed the delegation TTL ceiling (24 h) so no cached delegation can
  outlive the key it commits to.
- Algorithm agility is by **version bump only** (`nf3-key/2`, etc.), never by an in-record
  algorithm member (§5.1(2)).

---

## 10. Resolution returns no authorization (normative prohibition)

This section is the reason NF-3 exists in the form it does. It is the first refusal
(NF-WP-1 §10.1) stated as protocol law.

### 10.1 The prohibition

> **A resolver MUST NOT return, and an authority MUST NOT publish, any token, credential,
> session, bearer value, key, secret, or authorization decision, in any record, in any
> envelope member, at any status, under any circumstances.**

> **A querier MUST NOT treat any output of resolution as conferring authority, and MUST NOT
> use any resolution output as an input to an authorization decision other than choosing which
> endpoint to contact.**

The DNS analogy is exact and it is worth being literal about it. Resolving `bank.example` does
not produce a login, a session cookie, or a statement that you may transact. It produces an
address. Everything that decides whether you may act happens afterwards, at the resource, under
its own authentication. NF-3 is that and nothing more: it converts a VIN into an address to ask
at. Authority over vehicle data comes only from an NF-2 Consent Grant, issued by the owner,
scoped, time-bounded, and revocable — and a Consent Grant is not obtainable from a resolver,
because a resolver is not a party to it.

### 10.2 Enumerated prohibited content

Non-exhaustive by intent, exhaustive in effect via §10.3. A record or envelope **MUST NOT**
contain:

- An access token, refresh token, ID token, authorization code, JWT, SAML assertion, or any
  other OAuth 2.0 / OIDC artefact.
- A session identifier, session cookie, `Set-Cookie` value, or continuation handle.
- An API key, client secret, shared secret, HMAC key, symmetric key, or private key of any
  kind.
- A bearer value of any description — anything whose mere possession would let the holder do
  something at the endpoint that a non-holder could not.
- A password, passphrase, PIN, one-time code, or recovery value.
- A client certificate, or any certificate accompanied by key material.
- A pre-signed URL, signed URL, capability URL, magic link, or any URL whose path or query
  encodes authority (§10.4).
- An NF-2 Consent Grant, a grant `signature`, a grant commitment, or an owner signing or
  revocation key.
- An authorization decision, however encoded: `allowed`, `denied`, `permitted_fields`,
  `entitlement`, `access_level`, `tier`, or any boolean or enumeration whose value changes what
  the querier may do rather than where it must ask.
- An owner identity or contact channel (see §12 — that is additionally a personal-information
  violation, and the two prohibitions are independent).

An authority **MUST NOT** publish such a value even signed, and a validator **MUST** reject a
correctly signed record containing one (§9.4 step 3). A signed violation is a violation; the
signature establishes who committed it, not that it is permitted.

### 10.3 The closed key set is the enforcement mechanism

§5.1(1) is what makes §10.2 hold against values nobody has thought of yet. Every record type
and both envelope types have a closed key set, and a validator **MUST** reject any unknown
key. There is no extension point, no `additional`, no `metadata`, no `x-` namespace, and no
free-text member anywhere in NF-3.

This is the same reasoning `GRANT_KEYS` embodies in NF-2, applied to the naming layer. A
prohibition on smuggling authority through resolution is unenforceable if the format has
anywhere to put an unrecognized value, because "extension field" is the exact shape the
violation will take: an authority under commercial pressure to offer "convenient access" adds
one member, cooperating clients read it, validators that ignore unknown keys accept it, and the
naming layer has become a credential service without anyone changing the specification.
Rejecting unknown keys makes that a hard failure at every conformant validator on the first
attempt.

A version bump is the only way to add a member, which puts the question in front of the
standards process — where §10 can be applied to it — rather than in front of one operator's
product decision.

### 10.4 Endpoint URLs are addresses, not capabilities

The `endpoint` member is the likeliest place for authority to leak in disguised as a location.
Normative:

- Scheme **MUST** be `https`.
- **MUST NOT** contain a query string, fragment, or userinfo component.
- **MUST NOT** contain a path segment that varies per name, per querier, or per issuance.
- A validator **MUST** reject an `endpoint` violating any of the above
  (`endpoint_capability_url`).

A per-name or per-querier URL is a bearer capability wearing a URL's clothing: possession of
the string is what gets you served, which is precisely the property §10.1 forbids. It is also
unlogged and unrevocable in practice, and it would recreate the failure mode
`nf2-grant.js` avoids by binding a grant to a *key* rather than a name — a key is a challenge
the presenter answers or does not, while a URL is a secret that leaks into logs, referrers, and
screenshots.

The correct shape is one stable endpoint per zone that authenticates NF-2 grant holders on
their own keys. If two vehicles need different endpoints, that is two records, not two URLs
carrying two secrets.

### 10.5 What the querier must do next

Resolution ends with an address. To obtain data the querier **MUST** then, at the endpoint:

1. Request a Consent Grant under NF-2, or present one it already holds.
2. Authenticate as the grant's `counterparty_key` holder — the grant names a key, so the
   presenter answers a challenge; a stolen grant with no private key is worth nothing.
3. Have the endpoint verify the grant per NF-2 **and** check NF-4 revocation state **in the
   same request**. `verifyGrant()` returning `{ valid: true }` is not an authorization
   decision; `nf2-grant.js` says so at length, and NF-3 repeats it because a resolver-shaped
   integration is exactly where the check gets skipped.

A querier that goes from resolution to data without steps 1–3 has not misused NF-3; it has
failed to use NF-2 at all.

---

## 11. Error handling

### 11.1 Fail closed, everywhere

Every ambiguity resolves to **no answer**. A resolver **MUST NOT** return a partial,
provisional, best-effort, or unvalidated result, and **MUST NOT** annotate a weak result as
usable-with-caution: callers act on results, not on annotations.

### 11.2 Errors are local values, not exceptions

A resolver's entry point **MUST NOT** throw on untrusted input, and **MUST** return a result
object carrying a status and a reason list. A throwing resolver is a denial-of-service surface
reachable from any peer message, and this mirrors `verifyGrant()`, which never throws for the
same reason.

Reasons **MUST** be collected as `code: detail` with the stable codes of §14.2 and **SHOULD**
be reported in full rather than first-failure-only, so a conformance suite and an operator
both see everything wrong at once.

### 11.3 Errors disclose nothing

An error returned to a peer **MUST NOT** include a cached record, a name other than the one
queried, a resolver-internal path, a key, or timing detail that distinguishes cache hit from
miss (§8.5).

### 11.4 A failed resolution is not a negative answer

`servfail`, `refused`, timeout, TLS failure, and `referral_limit_exceeded` **MUST NOT** be
cached and **MUST NOT** be reported to the caller as non-existence (§8.4).

### 11.5 No downgrade, and no answer is a valid outcome

A resolver **MUST NOT**, in response to any failure:

- retry over plaintext or an earlier TLS version;
- retry with signature validation disabled or relaxed;
- accept a record from a resolver location not obtained from a validated delegation;
- accept an expired signature window or an out-of-range TTL "just this once";
- fall back to a hard-coded endpoint, a hint file, a previously seen endpoint outside its cache
  lifetime, or a guess derived from the WMI.

When resolution fails, the querier does not know where to ask, and **the correct behaviour is
to not ask**. Contacting an unvalidated endpoint means transmitting a VIN and a stated purpose
to an unknown party, which is a disclosure, not a retry.

---

## 12. Personal information constraints

### 12.1 The record contains no personal information

Beyond the closed key sets of §5, an authority **MUST NOT** publish and a validator **MUST**
reject any record disclosing:

- an owner's name, address, telephone number, email, or any contact channel;
- a vehicle attribute of any kind — make, model, model year, trim, colour, mileage,
  diagnostics, battery state, or anything else in the NF-2 field vocabulary. NF-3 names a
  vehicle; it does not describe one;
- **any positional value at any precision** — no coordinates, no geohash, no region, no
  garaging location, no home authority-as-location proxy. V1 admits no positional field
  anywhere in the protocol suite (`fields.js`), and the naming layer is not an exception;
- a biometric identifier or any in-cabin audio or video reference;
- an NF-2 `vehicle_pseudonym`, an NF-4 revocation commitment, a grant id, a grant
  commitment, a grant count, or the identity or class of any counterparty holding a grant.

### 12.2 A record asserts nothing about consent

Normative, because the misreading is natural and consequential:

- `authoritative` means "this is where you ask." It does **not** mean the vehicle is enrolled,
  that any grant exists, that the owner will respond, or that anything is available.
- `no_authority` means "no authority reachable from this anchor claims this name." It does
  **not** mean the vehicle does not exist, is not registered, is not enrolled, or has refused.
- A querier **MUST NOT** infer, report, or store an enrolment, consent, or refusal status from
  a resolution result.

Treating `no_authority` as "not enrolled" would turn resolution into a consent oracle answerable
by anyone holding a VIN — reading the owner's participation decision off the naming layer,
before and instead of asking. §5.2's zone-uniform records are the structural defence; this
section is the normative one.

### 12.3 The VIN in transit and in caches

NF-3 necessarily handles the VIN — it is the name. Refusal 2 is preserved by *where* it lives,
which is the same logic NF-2 applies to grant payloads (NF-WP-1 §9.5):

- Queries, answers, and caches are **transient, mutable and deletable**, TTL-bounded by §8.2.
- Cache storage **MUST** be erasable on demand, and cache entries **MUST** expire within the
  §8.2 ceiling — 24 hours, against the Delete Act's 45-day cadence.
- An authority or resolver **MUST NOT** retain a query log associating a name with a querier
  identity beyond an operational minimum, **SHOULD** aggregate rather than retain per-query
  records, and **SHOULD** publish its retention period. The query stream is the sensitive
  artefact here, not the record (§13.3).
- A resolver **MUST NOT** write names to durable analytics, telemetry, or third-party logging.

### 12.4 No NF-3 data on any ledger

An implementation **MUST NOT** commit any NF-3 record, name, query, answer, cache entry, or
digest thereof to an immutable ledger, append-only log, blockchain, or transparency log.

This forecloses a genuinely tempting design. A public append-only log of delegations would
solve §6.4's conflict problem outright by making first-claim objectively determinable. It is
prohibited anyway: such a log is VIN-keyed by construction, VINs are enumerated by the Delete
Act as a category of personal information collected (NF-WP-1 §9.5), and an immutable record
cannot be erased. A protocol that made the conflict question easy at the cost of a permanent,
unerasable public register of every enrolled vehicle would violate the second refusal to fix an
availability edge case. NF-3 fails closed on conflict instead (§6.4), which is the cheaper
loss.

The only ledger interaction anywhere in the suite remains NF-2's grant commitment and NF-4's
revocation-state commitment — digests, not records, and neither keyed by VIN.

---

## 13. Security considerations

### 13.1 Resolver spoofing and cache poisoning

**What the attacker wants.** Not disclosure — see §13.4 — but *misdirection*: get a querier to
send its consent requests, and the VIN and purpose they contain, to an endpoint of the
attacker's choosing; or get a durable negative cached so the vehicle becomes unfindable.

**Off-path blind spoofing.** The classical DNS attack: guess the transaction identifier and
source port, race the legitimate answer, and inject a referral that poisons the cache — the
2008 off-path cache-poisoning technique (Kaminsky) turned this from theory into practice by
combining a birthday race over many concurrent queries with injected out-of-bailiwick glue.
DNS's mitigations were entropy and provenance restriction (RFC 5452). NF-3 closes the vector
four times over, and each layer is independently sufficient against a purely off-path
adversary:

1. **There is no plaintext transaction to race.** TLS 1.3 is required (§4.2); an off-path
   attacker cannot inject into an established TLS session.
2. **128-bit query nonce** (§4.4), against DNS's 16 bits. The birthday arithmetic that made the
   attack economic does not survive the change of scale.
3. **Bailiwick rule and strict narrowing** (§6.3): a referral must be a prefix of the queried
   name and must strictly narrow the match, so there is no lateral or unrelated name to inject
   toward.
4. **Authenticated glue only** (§5.3): resolver locations are signed members of the parent's
   delegation record. NF-3 has no additional section, so the datum Kaminsky's attack injected
   does not exist in this protocol.

**On-path attacker, or a TLS-terminating middlebox.** TLS is defeated by definition here, and
this is why object security is mandatory (§9.1). Record signatures are verified against a key
committed by the parent delegation, chaining to a locally configured anchor, so an on-path
attacker who cannot produce an authority signature can deny service but cannot substitute an
endpoint.

**Compromised recursive resolver.** It cannot forge records. It can (a) deny service, (b)
withhold new records and re-serve previously valid ones, and (c) observe the full query stream
of every stub that uses it. Mitigations: signature-window ceilings bound (b) to 7 days for
endpoint records and are the *only* bound, since TTL is enforced by the cache being attacked
(§9.5); §7.2 forbids any "I validated this" flag, so (a) cannot be dressed up as authority; and
(c) is §13.3.

**Poisoning via conflicting chains.** An attacker who can get one validating chain published —
by compromising a minor authority, or by getting a permissive anchor to delegate — would, under
any tie-break rule, silently capture the endpoint for a name. §6.4's refusal to tie-break
converts that from silent capture into a visible `conflict` and a failed resolution. The cost is
that any authority in a querier's anchor set can *deny* resolution for a name by publishing a
conflicting claim. That is the accepted trade: denial is visible and attributable, capture is
neither.

**Cache snooping.** Addressed in §8.5 — served TTLs are the authority's, never the residual, and
cache-hit status is not exposed.

**Trust-anchor bootstrapping.** No anchor is ever learned in band (§9.3). A resolver that
accepted an anchor from a response would let one compromised answer redefine the whole name
space for that resolver, permanently.

### 13.2 Enumeration of the registered VIN space

**Enumeration resistance is not a goal of this protocol. Stating it plainly matters more than
mitigating it, because attempts to mitigate it do real harm (below).**

The VIN is public. It is visible through a windshield, printed on insurance documents and
titles, published in auction and listing data, and structurally enumerable: the WMI is assigned
and published (49 C.F.R. Part 565), the check digit is computable, and the remaining space is
small enough to walk. `vin.js` states the doctrine and the history — the 2015 Miller–Valasek
Jeep compromise and Curry et al.'s 2023 "Web Hackers vs. the Auto Industry" both turned on a
VIN being treated as a credential, an access-control failure rather than a property of the VIN.
A protocol whose security depended on VIN secrecy would be resting on a secret printed on the
dashboard.

So an adversary can and will enumerate the name space, and NF-3 is designed so that doing so is
**uninteresting**. The actual goal is these four invariants, which **MUST** hold under complete
enumeration of every name:

1. **Enumeration yields no authority.** The full output for every VIN in existence is a set of
   HTTPS URLs. Contacting one without an NF-2 Consent Grant, and without the private key the
   grant names, produces nothing (§10, §13.4).
2. **Enumeration yields no personal information.** No owner identity, no contact channel, no
   vehicle attribute, no position at any precision, no pseudonym, no grant, no grant count, no
   counterparty (§12.1).
3. **Enumeration yields no consent oracle.** With zone-uniform records (§5.2) a positive answer
   reveals that *an authority participates*, not that *an owner does*, and `no_authority` is a
   statement about delegation, not about enrolment (§12.2). This is the one invariant an
   authority can weaken on its own, by publishing per-name records; §5.2 requires it to accept
   that consequence, and `SHOULD` prefer zone scope precisely here.
4. **Enumeration yields no aggregation advantage.** Uniform rate limits are permitted (§6.5) and
   are an availability measure, not a confidentiality one. They may be evaded; nothing above
   depends on them holding.

**Why enumeration defences would be actively harmful.** The obvious mitigations all recreate the
gatekeeper this architecture exists to eliminate:

- *Require authentication to resolve.* Now someone decides who may look up a VIN. That is
  licensing preferential access to a market — the third refusal (NF-WP-1 §10.1) — and it makes
  the resolver a chokepoint with commercial value.
- *Hash the names.* Pointless against a 17-character enumerable space with a public structure,
  and it would break prefix zoning, which is the mechanism of polycentric delegation (§6.1).
- *Hashed authenticated denial (NSEC3-style).* Bought at the price of an online signing key or a
  much more complex offline process, to protect walkability we have already established is not a
  concern. §5.5 declines it and uses plain ranges.
- *Per-querier answers.* Split horizon, prohibited by §6.5 — it is the mechanism by which a
  naming layer discriminates.

The design conclusion is worth stating directly: **make enumeration harmless rather than hard.**
Hardness is a property an adversary erodes; harmlessness is a property of the record format,
and it does not erode.

### 13.3 Traffic analysis of resolution queries

This is NF-3's most serious residual exposure, and the honest position is that it is mitigated
structurally and not eliminated.

**The exposure.** Even with no personal information in any record, the *query stream* is
sensitive. "Who asked about VIN X at time T" reveals vehicle life events with high confidence: a
repair shop resolving a VIN indicates a service visit; an insurer resolving one indicates a
claim or an underwriting decision; a dealer resolving one indicates an appraisal or a resale; a
sudden cluster around one vehicle indicates an incident. None of that is in a record. All of it
is in the metadata, and it is the kind of inference the re-identification literature the white
paper relies on (Sweeney; Narayanan–Shmatikov, NF-WP-1 §12.7) makes routine.

**Mitigations, strongest first:**

1. **The query that is never sent.** Zone-uniform endpoint records (§5.2) plus the TTL floor
   (§8.2) mean a querier resolves most names entirely from cache, emitting no observable event.
   This is the only mitigation that removes the exposure rather than relocating it, which is why
   zone-scoped records are `RECOMMENDED` and why the TTL floor is not the authority's to waive.
2. **Polycentric delegation** (§6.1). No party sees the whole space. An authority sees queries
   for its own zone and nothing else; no party can build the global view, and none can be
   compelled to produce it, because it does not exist. This is the structural mitigation, and it
   is the reason delegation is a requirement rather than an optimization.
3. **Mandatory TLS** (§4.2) plus **no name in any URL, header, or query string** (§4.2). Defeats
   passive network observation and keeps names out of intermediary HTTP logs, referrers, and
   generic caches.
4. **Retention limits** (§12.3). An authority necessarily *sees* its zone's queries; it **MUST
   NOT** retain them as (name, querier) pairs beyond an operational minimum and **SHOULD**
   aggregate. This is a policy control, weaker than the three above, and it is stated as such.
5. **Response padding.** Answer length distinguishes a referral from an endpoint answer from a
   negative answer. Implementations **SHOULD** pad `application/nf3+json` bodies to fixed size
   buckets, following the reasoning of the DNS padding work (RFC 7830, RFC 8467).
6. **Constant-rate resolution.** A querier with a known population — a fleet, a dealer group —
   **SHOULD** resolve its whole roster on a schedule regardless of need, converting an
   event-driven query stream into a constant-rate one. Event timing is the whole signal; a
   constant rate carries none.

**The recursive-resolver trade, stated explicitly.** Recursion (§7.2) hides the stub from
authoritative servers and aggregates many stubs into one query stream — genuine k-anonymity
against the authority. It simultaneously concentrates each stub's *complete* query history in
one operator's log. Neither choice dominates: iterative resolution exposes the querier to every
authority it walks; recursive resolution exposes it completely to one party of its choosing. The
choice belongs to the querier, which is why NF-3 specifies both modes and requires end-to-end
validation in both (§7.2) so the choice is about privacy exposure only and never about trust.
§6.5's separation rule is what stops the recursive resolver from also being the endpoint
operator, which would make the concentrated log maximally valuable to the party holding it.

**What is not mitigated.** An authority sees queries for its own zone; a recursive resolver sees
its stubs' queries. Both are inherent to answering a question for someone. NF-3 bounds *who*
can see *how much*; it cannot make a question unaskable and still answer it.

### 13.4 Compromise of an authority or an endpoint

The worst case is worth naming, because it is the payoff of §10 as a security property rather
than a privacy one.

An attacker with **total control of resolution for a name** — a compromised authority, a stolen
signing key, a coerced operator — can point the endpoint anywhere. What it obtains:

- **Denial.** Consent requests go nowhere useful. Real, and bounded by the 24-hour endpoint TTL
  ceiling and the 7-day signature window once the compromise is corrected (§8.3, §9.5).
- **A phishing surface.** The attacker's endpoint can solicit requests and observe who is asking
  about which vehicle.

What it does **not** obtain: **vehicle data, or any authority over it.** A Consent Grant is
signed by an owner key the authority never holds, is bound to the counterparty's key rather
than to a location, and is verified against revocation state at the endpoint the owner's broker
operates (NF-2, NF-4). A hijacked endpoint has nothing to serve and cannot mint what it lacks.

Full compromise of the naming layer is therefore an **availability and phishing** event, not a
**disclosure** event. That property is a direct consequence of resolution conferring no
authority, and it is the strongest argument for §10 that this specification can make: the
prohibition is not only a privacy doctrine, it is what collapses the blast radius of the
protocol's own worst failure.

### 13.5 Denial of service

- **Amplification and reflection**: absent by construction. Queries are TLS `POST` requests with
  no unauthenticated request/response asymmetry (§4.1).
- **Resource exhaustion**: bounded by `MAX_MESSAGE_BYTES`, `MAX_ANSWER_RECORDS`,
  `MAX_REFERRAL_RECORDS` (§4.3), `MAX_REFERRAL_HOPS` (§7.1), and JCS's own `MAX_DEPTH` of 64
  from `jcs.js`, which bounds a nesting-based stack overflow reachable from any untrusted body.
- **Negative-cache flooding**: bounded by the 900-second negative ceiling (§8.4).
- **Conflict-based denial**: acknowledged in §13.1 as the accepted cost of §6.4.
- **Signature-verification cost**: bounded by the record-count limits. A validator **MUST**
  apply §9.4 steps 1–6 before step 7 so cheap structural checks reject malformed input before
  any Ed25519 verification is attempted.
