# NF-5 conformance suite

Machine-executable conformance for Nimbus Foundation white paper NF-WP-1, per
`specs/NF-5-conformance-and-prime-implementer.md`.

NF-5 §4.1: the Prime-Implementer tier is defined **entirely** by the outcome of this suite.
Nobody awards it and nobody withholds it — it is a reproducible computation, and this directory
is the computation. There is no `--force`, no waiver flag, no allowlist and no way to mark a red
area as accepted, because NF-5 §2 says there is no partial credit and no waiver, and a runner
with an override switch has quietly re-introduced the discretion NF-5 §1 exists to remove.

**Current verdict: FAIL.** 281 assertions pass, zero fail. The tier is still refused, for the
reasons in [Currently red](#currently-red). That is the suite working, not the suite broken.

---

## Running it

```
node conformance/run.js            # the whole rollup and the verdict
node conformance/run.js --json     # the same, machine-readable
node conformance/static-scan.js    # group VC static half, on its own
node conformance/static-scan.js --json
```

No install step. No `package.json`, no `npm`, no bundler — NF-WP-1 §14 admits none, and NF-5
§4.3 inherits the constraint with exactly one relaxation: `node:test` and `node:assert`, both
Node built-ins. Node 22+ (developed and verified on v24.15.0; `run.js` uses `node:test`'s
programmatic `run()`).

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Every gate passed and no assertion failed. |
| `1` | The verdict is FAIL: a gate failed, an assertion failed, or an area is unevidenced. |
| `2` | Harness error — the suite could not be evaluated. §4.6 makes this count as failure. |

---

## What each area asserts

NF-5 §4.9 declares six assertion groups. `run.js` maps every assertion in `tests/` to the
group(s) it evidences and rolls the result up per group; the mapping is declared in `FILE_MAP`
in `run.js`, not inferred, so a file that appears in `tests/` and is absent from the table is a
harness error rather than a silently uncounted file.

| ID | Area | Spec | Evidenced by | Passing |
| --- | --- | --- | --- | --- |
| `NT` | Non-transactability of the forbidden field classes | §5 | `fields.test.js`, `grant.test.js` (NF5-NT-*) | 42 |
| `DD` | Delegation-depth enforcement | §6 | `grant.test.js` (NF5-DD-*) | 12 |
| `RV` | Revocation propagation within the staleness bound | §7 † | `revocation.test.js` | 41 |
| `VC` | Absence of VIN-to-credential resolution | §8 † | `vin.test.js`, `resolve.test.js`, `grant.test.js` (Refusal 1), `static-scan.js` | 73 |
| `GC` | Grant core — shape, signature, commitment, non-transferability | §5.6 † | `jcs.test.js`, `grant.test.js` (remainder) | 81 |
| `CH` | Conformance-hook hygiene (CH-1..CH-4) | §4.5 | *nothing* | **0** |
| `DA`\* | Delete Act / erasure cadence clocks | not an NF-5 group | `clocks.test.js` | 32 |

† The assertion text for these groups is absent from NF-5 as published in `specs/` — see
[Specification gaps](#specification-gaps).
\* Supplementary: reported, never gated. NF-5 §1.1 disclaims any certification of legal
compliance, so these assertions inform a reader and contribute nothing to the tier.

**NT** — the forbidden classes have *no encoding*, not a permission flag. The grantable
vocabulary is disjoint from the 18 non-transactable identifiers and is closed at exactly 40
members; every forbidden id is refused in every position, in every confusable spelling
(homoglyph, zero-width, NFKD, lone surrogate), under a valid signature, through delegation and
through renewal. A whole field set is refused rather than narrowed, because a grant that quietly
covers less than the owner read is a consent defect.

**DD** — `delegation_depth` decreases by exactly one per hop, is bounded at 2 at issuance, and
is never increased by any operation: not by re-signing, not by forging a parent id, not by
constructing a cycle, not by renewal. Depth lives inside the signed bytes. Breadth is permitted
and depth is not, and the fan-out control proves the bound is not an accident of a fan-out limit.

**RV** — revocation cascades to every transitive descendant, is idempotent, cycle-safe and
monotone; a cached ALLOW is re-derived past the staleness bound and the bound cannot be
configured away; an unreachable store denies; the owner's kill switch is decisive without an
enumeration; the on-chain anchor carries a commitment and nothing else, and no committed artefact
carries a VIN, a pseudonym or free text.

**VC** — Refusal 1. Resolution returns a *location*: `resolve` output is closed against
`NF3_RESULT_KEYS`, carries no token/credential/session/bearer/authorization, does not echo the
VIN, and returns no grant and no decision. The raw VIN never appears in the canonical bytes of a
grant and is not recoverable from a pseudonym. The static scan is the fourth evidence source and
is [heavily caveated](#the-static-scan-is-evidence-not-proof).

**GC** — canonicalisation (RFC 8785) is order-independent, refuses lone surrogates, negative
zero, unsafe integers and type confusion; a grant carries exactly the 14 closed keys; tamper
detection covers every field; the commitment is a domain-separated fixed-length digest; expiry
and skew are injected, never read from the wall clock; a grant is bound to its counterparty and
is not a bearer token.

**CH** — nothing. See below.

---

## How a verdict is reached

**Per assertion.** `PASS`, `FAIL`, or `INCONCLUSIVE`. A skipped or TODO assertion is
INCONCLUSIVE, and NF-5 §4.6 makes INCONCLUSIVE count as FAIL — treating "could not check" as "no
finding" would make every mandatory assertion optional for anyone able to add `{ skip: true }`.

**Per area,** in this order:

1. Zero assertions → `UNEVIDENCED`. **An area with no tests must never read as conformant.**
   This is the specific failure a badge system cannot survive, so it is checked first.
2. Any INCONCLUSIVE → `INCONCLUSIVE`.
3. Any FAIL → `FAIL`.
4. No passing `[control]` assertion → `NO-CONTROL`. NF-5 §4.7: a group evidenced only by
   refusals is satisfied by an implementation that refuses everything, including one that is not
   running.
5. Otherwise → `PASS`.

**Gates.** Seven, all of which must pass for the tier:

| Gate | Requirement |
| --- | --- |
| `§4.3` | Ed25519 resolves via `{name:'Ed25519'}` or the legacy `NODE-ED25519`; otherwise every signature-dependent area is INCONCLUSIVE. |
| `harness` | Every file in `tests/` is declared, every declared file exists, and every assertion attributes to an area. |
| `§4.9` | Every declared NF-5 group has at least one passing assertion. |
| `§4.7` | Every group carries a passing positive control. |
| `§4.6` | Every mandatory assertion is PASS. |
| `§4.2` | Every group has PROTOCOL-profile evidence. MODULE-profile forms are additional evidence, never the sole gate. |
| `VC/static` | The group VC static scan is clean *and* its own self-controls pass. |

**Tier.** `PASS` iff every gate passes. `run.js` exits non-zero if the tier fails **or** any
assertion failed, including in a supplementary area — a failing test run must not exit 0 merely
because the failure was outside a gated group.

---

## Currently red

Three gates fail. None of them is an implementation defect; all three are missing suite or
specification work, and they are listed here rather than suppressed.

### 1. `CH` is UNEVIDENCED (gates §4.9 and §4.7)

NF-5 §4.5 states CH-1..CH-4 as MUST: the conformance interface must live in a module the
production entry point does not import, the production import graph must not reach it, the two
builds must differ only by that module, and any conformance route must 404 on the production
digest. **No conformance-hook module exists in this repository and no assertion tests any of
this.** The runner therefore reports the area as unevidenced rather than omitting it, which is
the whole reason the rollup is per-area instead of a pass count: 281 green assertions say nothing
about a group nobody wrote a test for.

*To close:* ship the conformance-hook module, then add `tests/hook.test.js` asserting (a) the
production entry point's transitive static import graph does not reach it — decidable because
§8.3 forbids dynamic `import()`, `eval` and `new Function`, and `static-scan.js` check `VC-S4`
already verifies their absence — (b) the production/conformance build diff is exactly that
module, and (c) a conformance route returns 404 with no side effect on the production digest.

### 2. No PROTOCOL-profile coverage (gate §4.2)

All seven test files import from an implementation source tree, so every assertion is MODULE
profile. NF-5 §4.2 requires the Prime tier to be attainable through the PROTOCOL profile alone,
and says in terms that MODULE forms are "additional evidence, never the sole gate". As it stands
an implementation written in another language, on another substrate, reusing none of
`broker/src/`, **cannot be assessed by this suite at all** — which §4.2 calls a preferential
access regime with a test harness bolted to the front of it.

*To close:* a PROTOCOL-profile pass driving the Worker over HTTP (`Request`/`Response` against
`broker/src/index.js`'s exported `fetch`, no network per §4.4), asserting on Consent Grant JSON,
the `NF2-VOCAB/1` document, response bodies and reason codes — never on a function name.

### 3. `DA` has no positive control

`clocks.test.js` uses no `[control]` tag. It does contain positive assertions, but the runner
counts tags, not intent. Supplementary, so it gates nothing; recorded so the count is not
mistaken for coverage.

---

## Limitations

### The static scan is evidence, not proof

`static-scan.js` is a syntactic argument over the declared JavaScript surface: export names,
parameter lists, and the top-level keys of returned object literals. It lexes first — comments,
string literals, regex literals and template raw text are blanked before any structural search —
so it does not report `NF3_FORBIDDEN_KEY_NAMES` as the violation it is the guard against, which a
grep does. It runs 15 self-controls on every invocation (synthetic violations each check must
report; real shapes from this codebase each check must not), because a scanner that reports
nothing is otherwise indistinguishable from a scanner that does nothing.

**It still proves nothing.** A real VIN-to-credential path survives it if it is:

- **split across functions** — the scan is intraprocedural, with no dataflow and no call graph.
  A VIN passed to a helper that returns a token is invisible: neither function holds both halves
  of the shape.
- **named innocuously** — every rule is a name rule. Call the token `hint`, `ref`, `blob`,
  `payload` or `x` and the scan is silent. The vocabulary is the suite's guess at what a defect
  would be called.
- **assembled indirectly** — `obj[k] = v`, `Object.assign(out, bag)`, `{ ...credentials }`, or
  JSON built from a template string are not object literals and are not read as keys. A spread is
  recorded as `<spread>` and not resolved.
- **returned through a non-return channel** — a mutated argument, a closure variable, a
  module-level cache, a `Set-Cookie` header, a D1 row or a KV write.
- **keyed off a derived identifier** — the parameter heuristic looks for a VIN-shaped *name*. A
  path taking a pseudonym, a `qname_digest` or an opaque `vehicle_ref` trips nothing.
- **outside the scanned roots** — only `broker/src`, `m0-vin-yield/src`, `m3-drop-compliance/src`,
  only `.js`. SQL in `schema.sql`, vars in `wrangler.toml`, and anything an upstream serves are
  outside the claim. The scan prints its file inventory with SHA-256 digests so the claim's
  boundary is visible rather than assumed.
- **built at runtime** — check `VC-S4` exists because `eval`, `new Function` and dynamic
  `import()` would make everything above unsound. It proves they are absent from the *text*, not
  that the deployed bundle is the text.
- **hidden in an exempt file** — `broker/src/nf2-grant.js` and `broker/src/index.js` are exempt
  from `VC-S6` because NF-2 mints capability objects and the broker verifies operator sessions by
  design. That exemption is a hole, and it is where a real defect would be cheapest to hide.

A lexer is also not a parser: exotic syntax can misalign a body span and drop a function from the
scan silently. **The behavioural evidence for VC is `resolve.test.js` and `vin.test.js`, which
exercise real code paths. The scan's job is the regression nobody wrote a test for — a new
export, on a new route, with a credential-shaped return — and that is the only claim it makes.**

### Specification gaps

NF-5 as published in `specs/` **ends after §6**. Groups `RV` (§7), `VC` (§8) and `GC` (§5.6) are
declared in the §4.9 table and used in §3's terminology, but carry no numbered assertion text.
Their evidence is therefore mapped by *file*, not matched to a published assertion id, so two
implementers can reasonably disagree about what those areas require — precisely what §4.9's
closing sentence requires not to happen. §8.2 (the Declared Surface manifest), §8.6, §11, §12
(the Vector File and Surface Digest), §13 and §14 are likewise absent, which means:

- **NF5-DD-010 cannot be run.** It iterates the IUT's published route list from its Declared
  Surface manifest. No manifest exists.
- **There is no separate Vector File.** §4.8 requires the forbidden list, the vocabulary and the
  adversarial inputs to be stated by the suite and never read from the IUT. They are — each test
  file restates them inline, and the duplication *is* the assertion — but they are not one
  versioned artifact with a Surface Digest, so "the vectors changed" is not currently a
  detectable event.
- **Canary-based credential-egress detection (§8.4) is not implemented**, because the section
  defining it is not present.

### Coverage gap carried over from NF-5 §5.2

Group NT establishes that the **protocol cannot encode** a grant for a forbidden class. It does
not establish that no forbidden data crosses the wire: a grant names field *identifiers* and the
data plane carries *values*. `motion_aggregate` admits `speed_mean_kph`, `harsh_brake_count` and
`aggregation_window_s`; at a short enough window a sequence of those is a trajectory by dead
reckoning. NF5/1.0 asserts nothing about window floors because no floor is specified anywhere in
NF-WP-1, and this suite will not invent an empirical threshold. The honest statement of what a
Prime badge would mean with respect to NF-WP-1 §8.2 is *the protocol admits no grant type for the
forbidden classes* — not *the implementation cannot leak positional inference*.

### Determinism is advised, not gated

NF-5 §4.4(2)–(3) forbid the wall clock and unseeded randomness in an assertion's decision path.
`run.js` counts `Date.now`, `Math.random`, `randomUUID` and `getRandomValues` call sites in code
(not in comments or strings) and prints them. It does not gate on them, because distinguishing a
decision-path read from a clock deliberately broken to prove a module never reads one needs a
dataflow analysis this harness does not have — and `clocks.test.js` does exactly the latter, in
three places. Gating there would fail a file for holding the line harder than the rule requires.

### What this suite is not

Repeating NF-5 §1.1 because it is the sentence most likely to be dropped when the result is
quoted: this is not a security audit, not a privacy review, not a penetration test, and not a
certification of legal compliance with the DPPA, the CCPA, the Delete Act, Cal. Veh. Code §9951,
the CFAA or DMCA §1201. It is a battery of assertions over observable behaviour and a declared
implementation surface. An implementer that passes and then says "certified compliant" has
misrepresented the artifact, and NF-5 §10.3 makes that a lapse condition.
