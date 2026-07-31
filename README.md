# Nimbus Foundation — IoV consent layer

Reference implementation of **NF-WP-1, "The Consent-Governed Catallaxy"** (July 2026).

The thesis is that the binding constraint on the Internet of Vehicles is economic-epistemic
rather than technical: the missing institution is a market in vehicular data with enforceable
property rights, discoverable prices, and low-friction consent. This repository implements the
part of that argument which can be built today — **Layer 3, the consent layer** — and
deliberately does not implement the market layer.

```bash
./verify.sh
```

Every gate that can be checked without a network, in one command and one exit code. To deploy,
follow [RUNBOOK.md](RUNBOOK.md) — ordered, gated, with the two dates that cannot slip. Start at
M0: the VIN-yield study gates everything downstream.

## The three refusals (NF-WP-1 §10.1)

These are absolute, and each is enforced structurally rather than by policy:

1. **Never resolve a VIN to a credential.** The VIN is a public index — a name, exactly like a
   DNS name. Resolution returns *where to ask* for authorization, never authorization itself.
2. **Never place personal information, or anything PI-derivable, on an immutable ledger.**
   On-chain is limited to grant hashes and revocation-state commitments. A standing 45-day
   Delete Act cadence plus CCPA erasure rights are irreconcilable with immutability (§9.5).
3. **Never operate a market the Foundation also governs.** Neutrality is the antitrust and
   doctrinal firewall, not a virtue signal (§10.2).

## Layer model (§3.1)

| Layer | Status here |
| --- | --- |
| 1 — connectivity substrate (C-V2X) | Not built; rides existing infrastructure |
| 2 — authenticated access (OEM telematics, ISO 20078) | Consumed read-only; bounded by CFAA as narrowed by *Van Buren* (2021) and DMCA §1201 |
| 3 — **consent layer** | **The build.** VIN resolved as index; scoped, time-bounded, revocable grants |
| 4 — data layer (digital twins, federated learning) | Partial; token-rewarded ZK rounds removed |
| 5 — market layer (priced exchange) | **Deferred and gated** behind securities, DFAL, Sherman §1 |

## Layout

```
broker/src/fields.js         NF-2 closed field vocabulary, non-transactable classes,
                             DPPA §2721(b) purposes, counterparty classes
broker/src/vin.js            ISO 3779 validation; salted, rotating, per-audience pseudonyms
broker/src/jcs.js            RFC 8785 JSON canonicalization (signature integrity)
broker/src/nf2-grant.js      the Consent Grant: build, sign, verify, delegate, commit
broker/src/nf3-resolve.js    VIN → consent endpoint, DNS-modelled, TTLs and zone delegation
broker/src/nf4-revocation.js owner-key revocation, delegation cascade, staleness bound
broker/schema.sql            D1 DDL — every table mutable and deletable, by design
m0-vin-yield/                the vPIC study that gates everything downstream
m3-drop-compliance/          Delete Act / DROP, hard August 1 2026 deadline
specs/NF-1..NF-5             RFC-level normative specifications
DOCTRINE.md                  the refusals, identifier-not-credential, prime-implementer terms
RUNBOOK.md                   deploy order, gates, and the two dates that cannot slip
verify.sh                    every offline gate in one command and one exit code
conformance/                 NF-5 suite: runner, static scan, tests, published vectors
layer5-deferred/             quarantined prior Solidity — NOT part of V1
_superseded/                 quarantined prior TypeScript broker — NOT part of V1
```

## Stack constraint (binding, §14)

Cloudflare Workers, vanilla JS, D1/SQLite. **No npm, no build step, no TypeScript, no bundler,
no third-party dependencies.** Web-standard APIs only; cryptography via WebCrypto. The single
exception is the conformance suite, which may use `node:test` and `node:assert` — Node built-ins
requiring no install.

## Status

```bash
node conformance/run.js
```

**NF-5 PRIME-IMPLEMENTER TIER: PASS** — 319 assertions, 0 failures, 7/7 gates, all six NF-5
groups plus the supplementary Delete Act area. Verified by direct execution, not by report:

| Group | Assertions | Controls | Profiles |
| --- | --- | --- | --- |
| NT — non-transactability of forbidden field classes | 47 | 11 | MODULE + PROTOCOL |
| DD — delegation-depth enforcement | 17 | 3 | MODULE + PROTOCOL |
| RV — revocation propagation within the staleness bound | 46 | 4 | MODULE + PROTOCOL |
| VC — absence of VIN-to-credential resolution | 78 | 5 | MODULE + PROTOCOL |
| GC — grant core: shape, signature, commitment | 86 | 17 | MODULE + PROTOCOL |
| CH — conformance-hook hygiene | 12 | 3 | PROTOCOL |
| DA — Delete Act cadence clocks (supplementary, never gated) | 33 | 1 | MODULE |

Three properties of the suite are worth more than the totals:

- **Positive controls.** Most assertions here are refusals, and a suite of refusals passes
  unchanged against a module that does nothing. Every group carries at least one `[control]`
  assertion that fails if the machinery stops working, so a green run means the checks ran
  rather than merely not complaining.
- **Two profiles.** MODULE assertions call the reference implementation directly. PROTOCOL
  assertions import none of it: they read committed vectors and re-derive every cryptographic
  claim with a separately written JCS canonicaliser and raw WebCrypto Ed25519. An implementer
  sharing no code with this repository can be assessed by the same suite. Negative vectors are
  produced by tampering with already-signed bytes, so their invalidity is a fact about Ed25519
  rather than an opinion of the generator.
- **The static scan does not overclaim.** `conformance/static-scan.js` searches for
  VIN-to-credential shapes and reports PASS, but it is intraprocedural, has no call graph, and
  matches on names. It is evidence, not proof, and it enumerates what would defeat it.

Regenerate vectors with `node conformance/vectors/generate.js`; run the raw suite with
`node --test conformance/tests/*.test.js`.

**Still not done, and not implied to be:**
- **No hostile reviewer has signed off.** The adversarial doctrine audit and the completeness
  critic have been commissioned but their findings are not yet folded in here. A green suite is
  evidence that the checks ran, not evidence that the right checks exist. The known blind spot
  is documented: a CH-3 assertion in this repo once passed while the manifest falsely claimed
  no conformance hook existed, because it compared the declared hook set against a file set
  derived from that same declaration. It now discovers undeclared hooks instead of trusting
  the manifest — but that class of self-confirming assertion is exactly what an audit is for.
- `broker/src/index.js` is exercised by its author's harness and by the CH import-graph
  assertions, not by end-to-end route tests in the committed suite.
- M2 (dealer-license verification), M4 (prior-art scan, SDOAA notification), M5 (Foundation
  formation) and M6 (agent-wrapper pilot) are organizational milestones with no code here.
- No deployment has happened. Nothing has run against live vPIC or a real DROP endpoint; the
  DROP adapter is an explicit stub pending CPPA's published interface.

## Limitations carried forward from NF-WP-1 §13

These belong to the argument, not to this implementation, and dropping them would be
overclaiming:

1. **The load-bearing data assumption is untested.** Whether a VIN yields the fields the
   architecture assumes is unproven until M0 runs. vPIC yields build and specification data; it
   does **not** yield location, kinematics, live DTCs, battery state, or service history — all of
   which require Layer-2 authenticated access. The negative-finding section is mandatory.
2. **The Node Bond remains exposed** under California's risk-capital test (*Silver Hills*, 1961),
   which is broader than *Howey* and reaches capital placed at risk "even ... where capital is
   placed without expectation of any material benefits." California counsel review is a gate.
3. **Agency law is unsettled.** The Bayern memberless-LLC wrapper is a functional, not statutory,
   solution.
4. **Collective bargaining for data sellers may not survive antitrust scrutiny.** Labor has a
   statutory exemption; data collectives do not.
5. **The insurance wedge is narrow in California** under Proposition 103 and 10 C.C.R. §2632.5,
   in tension with an LA County beachhead. Lead with fleet, repair, municipal and research demand.
6. **Corrected premises:** the Linux Foundation is Oregon-domiciled §501(c)(6), not Delaware;
   California *has* enacted UCC Article 12 (SB 95, Ch. 210, Stats. 2023) and is an early adopter,
   not a holdout; the "$17,680/RSU" figure is a superseded 2014 DSRC number against a 2025 USDOT
   estimate near $3,000–$5,000/device.
7. **Agency guidance is reversible while statute is not.** *Howey* governs with no safe harbor in
   force; CLARITY is not yet law.
8. **No deployment results.** The LAcarGUY pilot has instrumentation targets, not results.

## Design decisions worth challenging

- **V1 admits no positional field at any precision.** NF-2 forbids *precise* geolocation; the
  CCPA test turns on ~1,850 feet. A geohash-5 cell (~4.9 km) would be defensible, but it needs a
  documented precision floor and a re-identification analysis first. This is stricter than the
  paper requires and is easy to loosen.
- **Pseudonyms are per-audience as well as rotating.** NF-2 requires salted and rotating.
  Rotation alone still lets two counterparties holding grants over the same vehicle within one
  epoch join their datasets on the shared pseudonym; audience binding makes that join fail.
- **The owner's public key is deliberately absent from the grant.** Including it would undo the
  per-audience pseudonym — two counterparties could join on the shared owner key instead.
- **Maximum grant duration is 45 days,** pinned to the Delete Act sweep cadence, so no grant
  outlives a full erasure cycle unaffirmed.
