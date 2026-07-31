# NF-5 — Conformance Suite and the Prime-Implementer Tier

    Nimbus Foundation Specification NF-5
    Status:      Normative — Standards Track
    Version:     1.0
    Date:        2026-07-29
    Derives from: NF-WP-1, "The Consent-Governed Catallaxy" (July 2026), §8.5, §9.10, §10.1, §10.3
    Depends on:  NF-2 (field vocabulary and Consent Grant), NF-4 (revocation state)
    Layer:       Layer 3 (consent). This document specifies no data path and no market.

## 1. Introduction

NF-WP-1 §10.3 defines a prime-implementer tier. NF-WP-1 §8.5 requires that conformance be
machine-executable. This document is the whole of both: the suite, and the tier that the suite
defines.

The design premise is stated once and governs every clause below. **A tier that a standards
body can award is a tier the standards body can withhold, and the power to withhold is the
lever by which a standards body becomes a market participant.** NF-WP-1 §10.1 Refusal 3 forbids
the Foundation from operating a market it governs. A discretionary certification is such a
market — the good being sold is legitimacy, and the price is compliance with whatever the
certifier wants this quarter. NF-5 therefore removes discretion from the mechanism rather than
promising to exercise it fairly:

- Conformance is a **reproducible test result**, not a decision. Any party can compute it.
- The Foundation does not adjudicate, and is **not** the sole verifier (§9.4).
- The tier **lapses automatically** on defined conditions. There is no revocation power,
  because a revocation power is a grant power wearing a different hat (§9.6).
- The tier confers a **badge and nothing else** — no data, no priority, no influence, no
  price (§10.2).

### 1.1 What this suite is not

It is not a security audit, not a privacy review, not a penetration test, and not a
certification of legal compliance with the DPPA, the CCPA, the Delete Act, Cal. Veh. Code
§9951, the CFAA, or DMCA §1201. It is a battery of assertions over observable behaviour and a
declared implementation surface. §8.6 and §13 state precisely what it cannot establish. An
implementer that passes and then says "certified compliant" has misrepresented the artifact,
and §10.3 makes that a lapse condition.

### 1.2 Reading order

Read `broker/src/fields.js` and `broker/src/vin.js` first: they are the machine-readable form
of the NF-2 vocabulary and the pseudonym construction, and this suite asserts against them.
Read `broker/src/nf2-grant.js` for the reason-code vocabulary that §5–§8 use as the assertion
surface.

## 2. Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14 [RFC2119]
[RFC8174] when, and only when, they appear in all capitals, as shown here.

Two additional terms are defined here because the tier depends on them:

**Mandatory assertion.** An assertion whose Level is MUST. Every mandatory assertion in §5–§8
is a precondition of the Prime tier (§9.3). There is no partial credit and no waiver.

**Vacuous pass.** A verdict of PASS obtained by an implementation that refuses everything, or
that never runs the code under test. Vacuous passes are the characteristic failure of
negative-only test suites, so every assertion group in this document carries positive controls
(§4.7) and a group's verdict is FAIL if its controls fail.

## 3. Terminology

| Term | Definition |
| --- | --- |
| Implementation Under Test (IUT) | The software whose conformance is being determined. |
| Declared Surface | The manifest of §8.2: every source file, route, export, SQL statement, and egress sink the IUT admits to having. |
| Surface Digest | SHA-256 over the Declared Surface manifest in its canonical form (§12.2). |
| Enforcement Point | Any component that decides whether to serve consented data. |
| Issuer | The component that holds the authoritative NF-4 revocation table in D1. |
| Replica | Any cache or derived index of revocation state that an Enforcement Point reads. |
| Revocation View | The (state, `view_ts`) pair an Enforcement Point holds at decision time. |
| `T_stale` | The staleness bound of §7.1. |
| Canary | A unique high-entropy value seeded into a credential store by the harness, used to detect credential egress (§8.4). |
| Vector File | The suite's normative input data (§12.1). Authoritative over the IUT. |
| Suite Version | Semantic version of the vector file plus assertion set, e.g. `NF5/1.0`. |

## 4. Suite architecture

### 4.1 The suite is the definition

The Prime-Implementer tier is defined **entirely** by the outcome of this suite. No other
criterion — not membership, not tenure, not a Foundation review, not commercial relationship,
not implementation language, not hosting provider — bears on it. No criterion may be added
except by a versioned amendment to this document applying prospectively (§14).

Corollary, and it is load-bearing rather than decorative: if an implementation passes every
mandatory assertion, the tier follows **automatically**, and the Foundation has no step to
perform and nothing to approve.

### 4.2 Two profiles

The suite is published in two profiles, and the distinction exists to prevent the reference
implementation from being privileged by the shape of the tests.

**PROTOCOL profile (P).** Assertions expressed over artifacts and observable interfaces only:
Consent Grant JSON documents, published vocabulary documents, HTTP request/response pairs, D1
DDL. A PROTOCOL assertion MUST NOT reference any function name, module path, or internal API.

**MODULE profile (M).** Assertions that import from `broker/src/` and call its exports
directly. These bind implementations that reuse the reference modules, and they catch defects
one layer earlier than the wire.

Requirements:

- The Prime tier MUST be attainable through the PROTOCOL profile alone. An implementation
  written in another language, on another substrate, reusing none of `broker/src/`, MUST be
  able to reach Prime.
- Every mandatory assertion MUST have a PROTOCOL-profile form. MODULE-profile forms are
  additional evidence, never the sole gate.
- A newly proposed assertion that can only be expressed in the MODULE profile MUST be
  rejected, or the protocol MUST be extended until it can be expressed in PROTOCOL form. This
  is a non-discrimination requirement (§11.1), not a matter of taste: a suite that only the
  reference implementation can satisfy is a preferential access regime with a test harness
  bolted to the front of it.

*Rationale for stating this so bluntly.* The spine is a set of JavaScript ES modules. The
cheapest possible suite imports them and asserts on their return values, and that suite would
have made CarNimbus the only possible Prime Implementer while appearing entirely objective.
The split is the fix.

### 4.3 Harness constraints

Per NF-WP-1 §14, the CarNimbus stack admits no npm and no build step. The suite inherits that
constraint with exactly one relaxation, already granted by §14: `node:test` and `node:assert`.

- The harness MUST be plain ES modules (`.js`) with `import`/`export`. No TypeScript, no JSX,
  no bundler, no transpile.
- The harness MUST NOT depend on any third-party package. Web-standard APIs and Node built-ins
  only: `fetch`, `Request`/`Response`, `URL`, `URLPattern`, `crypto.subtle`, `TextEncoder`,
  `btoa`/`atob`, `structuredClone`, `node:test`, `node:assert`.
- All cryptography MUST go through WebCrypto. Ed25519 MUST be obtained by feature-detecting
  `{ name: 'Ed25519' }` and falling back to the legacy Workers name `NODE-ED25519`, as
  `broker/src/nf2-grant.js` does. The harness MUST NOT hand-roll a curve or a cipher.
- Any D1 access in the harness MUST use prepared statements with bound parameters.
- A run that cannot resolve Ed25519 MUST report INCONCLUSIVE for every signature-dependent
  assertion, and INCONCLUSIVE counts as FAIL for tier purposes (§4.6).

### 4.4 Determinism

Two independent implementers must obtain the same verdicts from the same IUT. That requires
the suite to be hermetic:

1. **No network.** The harness MUST NOT make outbound requests other than to the IUT endpoint
   under test. Layer-2 upstreams MUST be stubbed (§7.4, §8.4).
2. **No wall clock in assertions.** Every time-dependent assertion MUST inject time. The
   grant verifier already accepts `opts.now`; the PROTOCOL profile requires the equivalent
   conformance hook (§4.5). `Date.now()` MUST NOT appear in an assertion's decision path.
3. **No unseeded randomness.** Where an assertion needs many inputs, the i-th input MUST be
   derived deterministically as `SHA-256(suite_seed || ':' || assertion_id || ':' || i)`,
   rendered per the assertion. `suite_seed` is a constant in the Vector File. This gives
   fuzz-like coverage with byte-identical reproduction and needs no dependency.
4. **No ordering dependence.** Assertions MUST pass in any execution order and MUST NOT share
   mutable state. A harness MAY run them concurrently.
5. **Fixed vectors.** All VINs, salts, keys, timestamps, and field sets used by an assertion
   MUST come from the Vector File, never from the IUT (§4.8).

### 4.5 The conformance hook, and its cost

Assertions in §7 and §8 require capabilities a production deployment must not have: clock
injection, fault injection, and canary seeding. The IUT MUST therefore expose a conformance
interface, under these constraints:

- **CH-1 (MUST).** The conformance interface MUST live in a module that the production entry
  point does not import, directly or transitively.
- **CH-2 (MUST).** The production bundle's static import graph MUST NOT reach that module. The
  check is decidable because §8.3 forbids dynamic `import()`, `eval`, `new Function`, and
  string-constructed module specifiers on the Declared Surface. Absent that prohibition this
  check would be undecidable; that is why the prohibition exists.
- **CH-3 (MUST).** The conformance build and the production build MUST differ **only** by the
  presence of that module and its registration. The manifest MUST record both digests and the
  file-level diff between them, and the diff MUST be reviewable in full.
- **CH-4 (MUST).** Reaching any conformance-hook route on the production digest MUST return
  404 with no side effect.

*Honest accounting.* CH-1..CH-4 mean the audited build is not byte-identical to the deployed
build. That is a real weakening of the digest argument in §8.2, and no amount of process
removes it. What CH-3 buys is that the delta is enumerated, small, and inspectable rather than
unknown. An implementer who wants to avoid the weakening entirely MAY ship the hook in
production behind an unforgeable authorization and declare it as a route — but then the hook
is production attack surface, which is worse. The trade is stated so it is chosen rather than
stumbled into.

### 4.6 Verdicts

Each assertion yields exactly one of:

| Verdict | Meaning | Counts as |
| --- | --- | --- |
| PASS | The assertion's pass criteria were met in full. | pass |
| FAIL | Any pass criterion was not met. | fail |
| INCONCLUSIVE | The assertion could not be evaluated (missing hook, unresolvable algorithm, IUT unreachable, malformed manifest). | **fail** |
| N/A | The assertion's profile does not apply to this run. Permitted only for MODULE-profile assertions. | neither |

INCONCLUSIVE counts as FAIL for every tier determination. This is the suite's own fail-closed
rule, and it matters because the alternative — treating "could not check" as "no finding" —
makes every mandatory assertion optional for any implementer able to break the harness.

A group verdict is PASS only if every mandatory assertion in it is PASS **and** every positive
control in it is PASS.

### 4.7 Positive controls (vacuity)

Every group MUST contain at least one assertion that requires the IUT to **accept** a
well-formed input or **return** a correct result. These are marked `[control]`. An
implementation that refuses all input, returns 500 unconditionally, or is simply not running
MUST fail its controls and therefore its group.

### 4.8 The Vector File is authoritative

For every assertion, the forbidden list, the expected vocabulary, the bound values, and the
adversarial inputs MUST be read from the suite's Vector File. They MUST NOT be read from the
IUT, from an IUT-served document, or from an IUT-supplied configuration.

*Why this is called out in its own clause.* The obvious way to write §5 is to ask the IUT for
its non-transactable list and check that nothing in it is grantable. An IUT that ships an empty
forbidden list then passes perfectly. The forbidden classes are a property of NF-2, not of the
implementation, and the suite is the only party entitled to state them.

### 4.9 Assertion identifiers

`NF5-<GROUP>-<nnn>`, where GROUP is one of:

| Group | Subject | Section |
| --- | --- | --- |
| `NT` | Non-transactability of the forbidden field classes | §5 |
| `DD` | Delegation-depth enforcement | §6 |
| `RV` | Revocation propagation within the staleness bound | §7 |
| `VC` | Absence of VIN-to-credential resolution | §8 |
| `GC` | Grant core (shape, signature, commitment, non-transferability) | §5.6 |
| `CH` | Conformance hook hygiene | §4.5 |

Identifiers are permanent. A withdrawn assertion's identifier MUST NOT be reused (§14.3).

Each assertion below is specified as: **Profile**, **Level**, **Inputs**, **Procedure**,
**Pass**, **Fail**, **Why**. Two implementers reading Inputs + Procedure + Pass MUST be able to
produce tests that agree on every IUT.

## 5. Group NT — non-transactability of the forbidden field classes

NF-WP-1 §8.2 and §12.2: precise geolocation, biometric identifiers, and in-cabin audio/video
get **no grant type at all**. The protocol cannot encode a grant for them. V1 additionally
admits no positional field at any precision — deliberate conservatism beyond the letter of
NF-2, recorded in `fields.js` with the conditions under which a coarse-position class could
later earn a field id.

What this group tests is therefore not a permission check. It tests that **no encoding exists**.
The distinction is the entire point of the design: a policy statement can be waived by a
pressured or unsophisticated owner, and a missing encoding cannot be waived by anyone.

### 5.1 Published vocabulary

An IUT MUST publish its grantable field vocabulary as a static document so the PROTOCOL profile
can assert on it. The document is `NF2-VOCAB/1`:

```json
{
  "v": "NF2-VOCAB/1",
  "nf2_version": "nf2-grant/1",
  "fields": ["annual_mileage_estimate_km", "body_class", "..."],
  "purposes": ["dppa-2721b-2", "..."],
  "counterparty_classes": ["academic-research", "..."]
}
```

`fields`, `purposes`, and `counterparty_classes` MUST each be sorted by UTF-16 code unit and
free of duplicates — the same comparator the grant uses for its `fields` array, exported from
`jcs.js` as `compareCodeUnits`. The document MUST be retrievable without authentication: a
vocabulary an implementer must ask permission to read is a vocabulary that can differ per
asker, which is preferential access by another name (§11.1).

---

#### NF5-NT-001 — The grantable vocabulary and the forbidden classes are disjoint

**Profile:** P, M · **Level:** MUST

**Inputs:** `V.non_transactable` (the 18 identifiers of the Vector File); the IUT's
`NF2-VOCAB/1` document (P) or the `FIELDS` export (M).

**Procedure:** Compute the set intersection of the IUT's `fields` and `V.non_transactable`.

**Pass:** The intersection is empty.

**Fail:** The intersection is non-empty, or the vocabulary document is unretrievable, malformed,
unsorted, or contains duplicates.

**Why:** The forbidden classes are absent from the vocabulary rather than flagged within it.
`NON_TRANSACTABLE` exists in `fields.js` solely so that this assertion has something to assert
against; nothing in the protocol consumes it to *permit* anything.

---

#### NF5-NT-002 — The vocabulary is exactly the NF-2 vocabulary: no extensions

**Profile:** P, M · **Level:** MUST

**Inputs:** `V.fields` (the 40 identifiers of the Vector File for `nf2-grant/1`); the IUT's
`fields`.

**Procedure:** Assert set equality. Assert that the cardinality is 40.

**Pass:** The two sets are equal and the cardinality matches.

**Fail:** Any element present in one and not the other; any cardinality mismatch.

**Why:** Disjointness alone (NT-001) is satisfied by an IUT that adds `telemetry_blob`,
`raw_sensor_payload`, or `other`. A forbidden class smuggled in under a benign name defeats
§8.2 exactly as thoroughly as naming it outright, and an open vocabulary is the ordinary way
purpose limitation fails in practice — which is why `fields.js` closes it. The cardinality check
is intentionally brittle: a legitimate vocabulary change MUST come with an NF-2 version bump and
a Vector File update, and this assertion is what forces that rather than allowing a silent edit.

---

#### NF5-NT-003 — No field identifier matches the positional or sensory screen

**Profile:** P, M · **Level:** MUST

**Inputs:** The IUT's `fields`; `V.forbidden_id_patterns`, a list of case-insensitive substring
patterns; `V.pattern_exemptions`, a list of `{field, pattern, rationale}` records, empty in
NF5/1.0.

`V.forbidden_id_patterns` for NF5/1.0 (case-insensitive substring match):

```
lat  lon  lng  geo  gps  coord  position  waypoint  route  trace  track  heading  bearing
altitude  address  street  city  zip  postal  cell_id  imsi  imei  msisdn
face  iris  finger  voice  gait  biometric  audio  video  camera  mic  cabin  occupant
vin  ssn  license  plate  passport  dob  birth
```

**Procedure:** For each field identifier and each pattern, test for a match. A match is
permitted only if a matching `{field, pattern}` record exists in `V.pattern_exemptions`.

**Pass:** No unexempted match.

**Fail:** Any unexempted match.

**Why:** NT-001 and NT-002 pin the vocabulary against a known list. This assertion is the
tripwire for the *unknown* list — the field id a future editor adds that is positional or
sensory in substance and was never enumerated as forbidden. It is a heuristic and will produce
a false positive eventually; the exemption record is how a legitimate collision is resolved,
because it forces a named person to write down why `plant_country` is not an address. Editing
the pattern list so that a field passes MUST be treated as an amendment under §14, not a fix.

Verified against the NF5/1.0 vocabulary: no member of the 40 matches any pattern.

---

#### NF5-NT-004 — Every forbidden identifier is refused in every position

**Profile:** P, M · **Level:** MUST

**Inputs:** `V.non_transactable` (18 ids) crossed with positions
`{sole, mixed, duplicated, embedded}`, where for forbidden id `f` and valid ids
`a = odometer_km`, `b = make`:

| Position | Field set submitted |
| --- | --- |
| `sole` | `[f]` |
| `mixed` | `[a, f, b]` |
| `duplicated` | `[f, f]` |
| `embedded` | `[a, b, f]` sorted into canonical order |

72 cases. Each is submitted as a grant-issuance request (P) or a `buildGrant` call (M) with all
other parameters drawn from `V.valid_grant_params`.

**Procedure:** Submit each case. Record the outcome, the error code, and a digest of the IUT's
persistent state before and after (P: via the conformance hook's state-digest route; M: not
applicable).

**Pass, all 72 cases:**
1. No grant object is returned or persisted.
2. The outcome is a refusal: MODULE profile — a thrown error; PROTOCOL profile — HTTP 4xx with
   a JSON body whose `code` is `fields_invalid`.
3. The refusal detail names the offending identifier `f` verbatim.
4. The persistent-state digest is unchanged (P).
5. No commitment is derived, published, or queued for a ledger.

**Fail:** Any case in which a grant is produced; any 2xx; any silently narrowed field set; any
refusal that omits `f`; any state mutation.

**Why:** Criterion 1 is the assertion; criteria 2–3 make the failure diagnosable and give the
suite a stable code to match; criterion 4 exists because a rejection that still writes a row has
created a record of an owner's forbidden-class request, which is itself the collection §8.2
forbids. Criterion 5 blocks the specific defect of validating after committing. Silent narrowing
is a FAIL because a grant that quietly covers less than the owner read is a consent defect, not
a convenience — which is why `validateFieldSet` rejects the whole set rather than filtering it.

---

#### NF5-NT-005 — Confusable and near-miss identifiers are refused

**Profile:** P, M · **Level:** MUST

**Inputs:** For each `f` in `V.non_transactable` and each `g` in the 5-element sample of
`V.fields` fixed in the Vector File, the variant set:

| Variant | Construction |
| --- | --- |
| uppercase | `IN_CABIN_AUDIO` |
| mixed case | `In_Cabin_Audio` |
| leading space | one U+0020 prepended |
| trailing space | one U+0020 appended |
| separator swap | underscores replaced with hyphens |
| NFKD variant | a decomposed combining acute (U+0301) appended |
| homoglyph | Cyrillic small a (U+0430) substituted for the first Latin `a` |
| zero-width | ZWJ (U+200D) inserted at offset 3 |
| tab-suffix | one U+0009 appended |
| lone surrogate | one unpaired high surrogate (U+D800) appended |

**Procedure:** Submit each variant as a sole-element field set. Submit the same variant set built
from the five *valid* identifiers `g`.

**Pass:** Every variant of every `f` **and** every variant of every `g` is refused. Refusals of
`f` variants MAY carry either the non-transactable detail or the not-in-vocabulary detail; both
are `fields_invalid`.

**Fail:** Any variant is accepted. In particular, any accepted variant of a *valid* `g` is a
FAIL.

**Why:** Note carefully what is not asserted. The suite does **not** require the IUT to
*recognise* `IN_CABIN_AUDIO` as the forbidden class — it requires refusal, and refusal as
"unknown identifier" is entirely correct. The danger runs the other way: an IUT that normalises
before comparing can map a confusable *into* a valid identifier, at which point the resulting
grant canonicalises to bytes the owner never saw. That is why the valid-identifier variants are
tested too, and why exact-match comparison against a closed set is the only conforming strategy.
Lone surrogates are included because they have no UTF-8 encoding at all and `jcs.js` refuses
them rather than choosing between the ES6 and ES2019 `JSON.stringify` behaviours; a field set is
inside signed bytes, so a value that canonicalises two ways depending on runtime age is a value
whose signature means two things.

---

#### NF5-NT-006 — Deterministic adversarial identifiers are refused

**Profile:** P, M · **Level:** MUST

**Inputs:** 1024 identifiers generated as the first 16 characters of
`base64url(SHA-256(suite_seed || ":NF5-NT-006:" || i))`, prefixed `f_`, for `i` in `[0, 1024)`;
plus the 64 fixed pathological inputs in `V.pathological_ids` — the empty string, a 4 KiB
string, JSON `null`, integer `0`, boolean `true`, an object, an array, `__proto__`,
`constructor`, `toString`, `prototype`, a 100 000-character string, SQL fragments, path-traversal
forms, and four JSON string-escape edge cases.

**Procedure:** Submit each as a sole-element field set, and each again inside `[make, id_i]`.

**Pass:** All 2176 cases refused, with no unhandled exception, no 5xx, no response exceeding
`V.timeout_ms`, and no state mutation.

**Fail:** Any acceptance; any 5xx; any hang; any stack trace or internal path in a response body.

**Why:** Fail-closed on unknown input is the writing standard, and a closed vocabulary makes it
cheap to verify at scale. `__proto__`, `constructor`, `prototype`, and `toString` are present
because a `Set`-based membership test is safe and an object-literal-keyed one is not. The
generation rule is fully specified so two implementers get byte-identical inputs with no fuzzing
dependency; this is the mechanism of §4.4(3).

---

#### NF5-NT-007 — A valid signature does not rescue a forbidden field

**Profile:** P, M · **Level:** MUST

**Inputs:** A hand-assembled grant bearing all 14 `nf2-grant/1` keys, with
`fields = ["in_cabin_video", "odometer_km"]` in canonical order, genuinely signed with a valid
Ed25519 key over the correct JCS canonicalisation of the payload with `signature` removed.

**Procedure:** Present the grant for verification with the correct verifying key supplied
(`opts.ownerPublicKey` or the PROTOCOL-profile equivalent). Separately, present it as
authorization for a data request.

**Pass:** Verification returns invalid with a reason bearing code `fields_invalid`. The data
request is refused. No data for any field — including the admitted `odometer_km` — is served.

**Fail:** Verification returns valid; or the request is served; or the IUT serves the admitted
subset and drops the forbidden field.

**Why:** The forbidden classes are not a request-time filter that a correctly-signed object can
bypass, and they are not severable. An IUT that serves the admitted subset has treated the grant
as partially honourable, which means a counterparty can obtain the maximum admitted subset by
appending a forbidden field to every request and letting the server sort it out — and it means a
malformed grant has a success path. Structural validity is evaluated independently of, and its
failure is not cured by, cryptographic validity; `verifyGrant` collects every reason precisely so
this ordering is observable.

---

#### NF5-NT-008 — Delegation cannot introduce or broaden toward a forbidden field

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant with `fields = [make, odometer_km]` and
`delegation_depth = 2`. Sub-grant attempts with `fields` of `[precise_geolocation]`,
`[make, in_cabin_audio]`, `[make, dtc_codes]` (admitted id, absent from parent), and `[make]`
`[control]`.

**Procedure:** Attempt each sub-grant. Then hand-assemble a sub-grant with
`fields = [gps_trace, make]`, sign it with the delegator's key, and present it for verification
with the parent supplied.

**Pass:** The first three attempts are refused — the two forbidden ones with `fields_invalid`,
the admitted-but-absent one with a field-broadening refusal. The fourth `[control]` succeeds. The
hand-assembled sub-grant verifies as invalid with `fields_invalid` among the reasons.

**Fail:** Any of the first three succeeds; the control fails; the hand-assembled sub-grant
verifies as valid.

**Why:** Authority strictly decreases along a delegation chain, so no sequence of delegations can
produce access the owner never granted. The forbidden classes are the case where "strictly
decreases" must also mean "cannot be entered from outside", because the delegator signing a
sub-grant is not the owner and has no standing to widen the class of data at issue.

---

#### NF5-NT-009 — Renewal cannot introduce a forbidden field

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant. Renewal attempts with `fields` of `[voiceprint]`,
`[make, owner_email]`, and `[make]` `[control]`.

**Procedure:** Attempt each renewal.

**Pass:** Both forbidden attempts are refused with `fields_invalid`. The control produces a new
grant with a fresh `grant_id`, `renewal_of` set to the previous grant's id, fresh timestamps, and
a fresh signature.

**Fail:** Either forbidden attempt succeeds; the control fails; the control mutates the previous
grant in place; or the control reuses the previous `grant_id`.

**Why:** "Renew" is what an owner clicks without reading, which makes it the highest-value place
to widen a grant. The in-place-mutation clause is a separate criterion because editing
`expires_at` or `fields` under the same `grant_id` yields an object with a different commitment,
and NF-4 keys revocation by commitment — so the edited form would evade a revocation entry filed
against the original.

---

#### NF5-NT-010 — A well-formed grant over admitted fields is accepted `[control]`

**Profile:** P, M · **Level:** MUST

**Inputs:** `V.valid_grant_params`, covering three cases: a `vpic`-only field set, a
`layer2`-only field set, and a mixed set spanning `motion_aggregate` and `usage`.

**Procedure:** Issue, sign, verify with the correct key and a `now` inside the validity window,
derive the commitment, and serve a data request under it (P).

**Pass:** All three issue. All three verify with `valid: true` and an empty reason list. Each
commitment is a 43-character base64url string, and the three differ. The data request is served
for exactly the granted fields and no others.

**Fail:** Any refusal; any non-empty reason list; any two commitments equal; any served field
outside the grant.

**Why:** This is the group's positive control (§4.7). Without it, NT-001 through NT-009 are all
satisfied by an implementation that rejects every input, including one that is not running.

### 5.2 Coverage gap, stated rather than papered over

Group NT establishes that the **protocol cannot encode** a grant for a forbidden class. It does
not and cannot establish that no forbidden data crosses the wire, for one specific reason: a
Consent Grant names field identifiers, and the data plane carries values. NF-WP-1 §8.2's
"anything from which PI can be derived" is a property of values, not of names.

The concrete instance: `motion_aggregate` admits `speed_mean_kph`, `harsh_brake_count`, and
`aggregation_window_s`. At a sufficiently short aggregation window, a sequence of speed and
cornering aggregates is a trajectory in all but name — the derivation is dead reckoning, and the
re-identification concerns the white paper raises at §12.7 apply to it directly. NF5/1.0 asserts
nothing about window floors because no floor is specified anywhere in NF-WP-1, and this document
will not invent an empirical threshold.

This is a **known, unclosed gap**, recorded here so that it is scheduled work rather than a later
discovery. Closing it requires a minimum `aggregation_window_s` and a maximum sample rate per
counterparty class, derived from a documented re-identification analysis, reviewed against the
CCPA sensitive-PI category (Civ. Code §1798.140(ae)), and published in NF-2 or NF-3. Until then
the honest statement of what a Prime badge means with respect to §8.2 is: *the protocol admits no
grant type for the forbidden classes* — not *the implementation cannot leak positional
inference*.

## 6. Group DD — delegation-depth enforcement

`MAX_DELEGATION_DEPTH` is 2. Two hops covers the real relationship — a fleet operator delegating
to the maintenance contractor that turns the wrench — and stops there. Each additional level adds
a party the owner never chose and lengthens the chain revocation must walk before the last holder
actually loses access.

The property under test is: **`delegation_depth` decreases by exactly one at each hop, is bounded
above by 2 at issuance, and can never be increased by any operation or by any party.** There is
no operation that adds depth, and this group's job is to show that no combination of operations
synthesises one.

---

#### NF5-DD-001 — Root issuance is bounded at `MAX_DELEGATION_DEPTH`

**Profile:** P, M · **Level:** MUST

**Inputs:** Root-grant issuance requests with `delegation_depth` in
`{0, 1, 2, 3, 4, 255, 2**31, 2**53, 2**53 + 1, -1, 1.5, "2", null, true, [], {}}`.

**Procedure:** Attempt issuance for each value, all other parameters from
`V.valid_grant_params`.

**Pass:** `0`, `1`, and `2` succeed, each producing a grant whose `delegation_depth` equals the
requested integer exactly. Every other value is refused with code `delegation_depth_invalid`.

**Fail:** Any value above 2 accepted; any negative, non-integer, non-number, or unsafe-integer
value accepted; any accepted value where the resulting grant's `delegation_depth` differs from
the request; any coercion of `"2"` to `2`.

**Why:** `2**53` and `2**53 + 1` are present because both canonicalise to the same JSON number
under IEEE-754 doubles — `jcs.js` documents this and exports `assertSafeInteger` for it. An
implementation that accepted a depth beyond the safe-integer limit would have a value whose
signature authenticates a *different* value, and depth is precisely the kind of
security-relevant integer that comment warns about. String coercion is a FAIL because `"2"` and
`2` canonicalise differently, so the same semantic grant would have two commitments and a
revocation entry against one would miss the other.

---

#### NF5-DD-002 — A depth-0 grant cannot be delegated

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant with `delegation_depth = 0`.

**Procedure:** Attempt to mint a sub-grant from it, with an otherwise entirely valid sub-grant
request — narrower field set, same purpose, earlier expiry, same revocation key id.

**Pass:** Refused. The refusal identifies the parent's zero depth as the cause.

**Fail:** A sub-grant is produced, at any depth, including a sub-grant with
`delegation_depth = 0`.

**Why:** Depth 0 is the owner's decision that this counterparty may not pass the authority on.
The tempting bug is to permit a depth-0 child of a depth-0 parent on the reasoning that it adds
no further delegable authority; it adds a holder the owner never evaluated, which is the thing
being prevented. There is no operation that adds depth, so there is no operation that recovers
from this state.

---

#### NF5-DD-003 — Each hop decrements by exactly one

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant with `delegation_depth = 2`.

**Procedure:** Mint a sub-grant, sign it with the delegator's key, and inspect
`delegation_depth`. Repeat from the sub-grant. Then, for each of the offsets
`{0, -1, +1, +2, -2}` applied to the correct child depth, hand-assemble a child, sign it with
the delegator's key, and verify it with the parent supplied.

**Pass:** The minted chain has depths `2 → 1 → 0`. Of the hand-assembled children, only the one
whose depth equals `parent.delegation_depth - 1` verifies as valid; every other verifies as
invalid with code `delegation_depth_not_decremented`.

**Fail:** Any minted child whose depth is not `parent - 1`; any hand-assembled child at the wrong
depth that verifies as valid; a same-depth child (offset 0) treated as acceptable.

**Why:** Strict decrease is what makes the bound a bound. A same-depth child is the interesting
failure: it looks harmless, and it permits an unbounded chain, which means unbounded parties and
an unbounded revocation walk. Note that the offsets are applied to signed objects: the depth check
is independent of signature validity, so a delegator cannot buy depth with a correct signature.

---

#### NF5-DD-004 — The depth ladder terminates exactly at the bound

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant with `delegation_depth = 2`.

**Procedure:** Mint, sign, and record sub-grants greedily: child of root, grandchild of child,
great-grandchild of grandchild, and so on until an attempt is refused. Count the grants
successfully produced, including the root.

**Pass:** Exactly 3 grants exist — root at depth 2, child at depth 1, grandchild at depth 0. The
fourth attempt is refused, citing the grandchild's zero depth. The refusal occurs at minting; it
is not deferred to verification.

**Fail:** A fourth grant is produced; fewer than 3 are produced; the refusal arrives only at
verification time.

**Why:** This is the assertion that the bound is a bound in practice and not merely in the
validator. Refusal at minting matters because a grant that exists but never verifies is an
artifact in a database, presented to a counterparty as authority, that will be honoured by any
enforcement point with a bug — the failure should occur before the object exists.

---

#### NF5-DD-005 — Breadth is permitted; depth is not `[control]`

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant with `delegation_depth = 2`.

**Procedure:** Mint five sibling sub-grants from the same root, each to a different
`counterparty_key`, each narrower or equal in fields, each expiring no later than the root. Verify
all five with the root supplied as parent.

**Pass:** All five are produced and all five verify as valid. Each has `delegation_depth = 1`,
`parent_grant_id` equal to the root's `grant_id`, and a distinct `grant_id`.

**Fail:** Any sibling refused; any sibling at a depth other than 1; any two siblings sharing a
`grant_id`; any sibling whose creation alters the root.

**Why:** This is the group's positive control, and it also fixes a semantic that would otherwise
be ambiguous to two independent implementers. NF-WP-1 bounds *depth*, not *fan-out*. Breadth is
governed by attributability and cascade instead: every sibling records the same
`parent_grant_id`, so the owner sees the whole subtree and one revocation cuts all of it. An
implementation that limited fan-out would be adding a restriction the standard does not contain,
and an implementation that limited depth by accident of limiting fan-out would pass DD-004
vacuously.

---

#### NF5-DD-006 — A delegated grant cannot be verified from its leaf alone

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed sub-grant at depth 1, and its signed parent.

**Procedure:** Verify the sub-grant (a) with no parent supplied, (b) with a structurally valid
but unrelated grant supplied as parent, (c) with an *unsigned* copy of the true parent, and
(d) with the true signed parent `[control]`.

**Pass:** (a) invalid with `delegation_parent_missing`; (b) invalid with
`delegation_parent_mismatch`; (c) invalid, with the parent's unsigned state cited; (d) valid with
an empty reason list.

**Fail:** Any of (a), (b), or (c) valid; (d) invalid.

**Why:** The expected signer of a sub-grant is the delegator, whose key is
`parent.counterparty_key`. A verifier with no parent has no signer key and therefore cannot have
checked the signature; returning valid in that state is the failure this assertion exists to
catch. The consequence — a chain cannot be verified from its leaf — is a deliberate property, not
a defect: it means an enforcement point must hold or fetch the whole chain, which is the same walk
revocation makes, so the two cannot drift apart.

---

#### NF5-DD-007 — Depth is inside the signed bytes

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant with `delegation_depth = 1`.

**Procedure:** Copy the grant, set `delegation_depth` to 2, leave the signature untouched, and
verify with the correct owner key.

**Pass:** Invalid, with `signature_invalid` among the reasons.

**Fail:** Valid; or invalid on some ground *other than* signature failure while the signature is
reported as verifying.

**Why:** Depth would be worthless as a bound if a holder could edit it. This assertion pins the
mechanism rather than the outcome: the bound is enforced by the signature covering the field, not
by a range check that a downstream component might skip. A verifier that rejects the tampered
grant for the wrong reason is signalling that the depth field is not actually authenticated.

---

#### NF5-DD-008 — Sub-grant narrowing invariants hold on every axis

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant: `fields = [make, odometer_km, dtc_codes]`,
`delegation_depth = 2`, purpose `dppa-2721b-2`, `expires_at = T`, `revocation_key_id = R`,
pseudonym `P` with audience `fleet-operator`.

**Procedure:** For each axis, hand-assemble a child violating exactly that axis, sign it with the
delegator's key, and verify with the parent supplied:

| Case | Violation | Required reason code |
| --- | --- | --- |
| a | `fields` includes `state_of_charge_pct` (absent from parent) | `delegation_fields_broadened` |
| b | `purpose` is `dppa-2721b-6` | `delegation_purpose_changed` |
| c | `expires_at` is `T + 1` | `delegation_expiry_extends_parent` |
| d | `revocation_key_id` is a fresh thumbprint | `delegation_revocation_key_changed` |
| e | `vehicle_pseudonym` recomputed for the child's own audience | `delegation_pseudonym_mismatch` |
| f | `parent_grant_id` equals the child's own `grant_id` | `parent_grant_id_malformed` |
| g | all axes correct `[control]` | none; `valid: true` |

**Pass:** Each of (a)–(f) verifies as invalid with the listed code present. (g) verifies valid
with an empty reason list.

**Fail:** Any of (a)–(f) valid; any missing the listed code; (g) invalid.

**Why:** Depth alone is not the whole cascade invariant, and an implementation that enforced only
depth would satisfy DD-001 through DD-007 while permitting a delegate to repurpose, outlive its
parent, or claim revocation authority. Case (d) is the sharpest: a child bearing its own
revocation key is a child the owner cannot cut without revoking the parent and every sibling.
Case (e) is the least obvious and is a genuine invariant rather than an oversight — the delegator
has no access to the owner's salt and must not receive a fresh pseudonym, because a new pseudonym
mints a linkability domain the owner never authorised. The delegate's ability to correlate is
therefore bounded by the delegator's, which is the correct semantics for a controller/processor
pair.

---

#### NF5-DD-009 — Renewal cannot raise depth

**Profile:** P, M · **Level:** MUST

**Inputs:** A valid signed root grant with `delegation_depth = 0`; a valid signed sub-grant.

**Procedure:** (a) Renew the root requesting `delegation_depth = 1`. (b) Renew the root
requesting `delegation_depth = 0` `[control]`. (c) Attempt to renew the sub-grant.

**Pass:** (a) refused, citing the depth raise. (b) succeeds at depth 0. (c) refused, citing that
a delegated sub-grant is re-minted by its delegator and not renewed.

**Fail:** (a) succeeds; (b) fails; (c) succeeds.

**Why:** Renewal is the second place depth could be synthesised, and (c) closes the standing
question of who may extend a delegate's authority. The answer is the delegator, by minting again
against a live parent — a delegate has no standing to extend its own authority, and a renewal
path open to the delegate would give it exactly that.

---

#### NF5-DD-010 — Depth is not recoverable through any published operation

**Profile:** P · **Level:** MUST

**Inputs:** A valid signed grant at `delegation_depth = 0`; the IUT's full published route list
from its Declared Surface manifest (§8.2).

**Procedure:** For every route in the manifest that accepts a grant or a `grant_id`, submit the
depth-0 grant and inspect every returned grant object in the response for
`delegation_depth > 0`. Include routes not otherwise exercised by this suite.

**Pass:** No route returns any grant object bearing a `delegation_depth` greater than the
submitted grant's, and no route returns a grant whose `parent_grant_id` chain is shorter than the
submitted grant's.

**Fail:** Any route returns a grant with increased depth.

**Why:** DD-001 through DD-009 test the operations this specification knows about. This assertion
tests the operations it does not, over the surface the implementer declared — an "upgrade",
"refresh", "reissue", or admin path that resets depth is exactly the kind of convenience endpoint
that appears later and is never reviewed against this section. It shares the limitation of every
declared-surface check: it covers what was declared. §8.6 states that limitation properly.
