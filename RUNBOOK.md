# Runbook — Nimbus Foundation IoV consent layer

Deployment order, gates, and the two dates that cannot slip. Every command is copy-pasteable.
Nothing here has been run against live Cloudflare, live vPIC, or a live DROP endpoint — the
placeholders are real placeholders.

**Prerequisites:** Node ≥ 20 (Node 24 tested), a Cloudflare account, `wrangler` available via
`npx wrangler` (the *project* takes no npm dependency — `wrangler` is a deploy-time CLI, not a
runtime import, and nothing under `broker/`, `m0-vin-yield/`, `m3-drop-compliance/` or
`conformance/` imports anything outside Node/Web built-ins). `sqlite3` optional, for local
schema checks.

---

## 0. Verify before you touch anything

```bash
./verify.sh
```

Runs the conformance suite, the NF-5 tier verdict, the static scan, a parse check over every
module, all three D1 schemas, and the no-npm/no-build-step constraint. Exit 0 means every gate
that can be checked without a network has passed. **If this is red, stop.**

---

## 1. M0 — the VIN-yield study. This gates everything.

NF-WP-1 §15 rec 1: the cheapest, highest-information action, and the load-bearing data
assumption of the entire architecture is untested until it runs. Do this *before* building on
Layer 3, not after.

```bash
npx wrangler d1 create nf-m0-vin-yield
```

Put the returned `database_id` into `m0-vin-yield/wrangler.toml`, then:

```bash
npx wrangler d1 execute nf-m0-vin-yield --remote --file=m0-vin-yield/schema.sql
```

```bash
cd m0-vin-yield && npx wrangler secret put M0_ADMIN_TOKEN && npx wrangler deploy
```

Run the study against a real VIN sample, then read the report against
`m0-vin-yield/REPORT-TEMPLATE.md`, completing the **mandatory negative-finding section**.

> **GATE M0 → M1.** If any architecturally-assumed field shows **< 80 % VIN-derivable coverage**
> or requires a second source, Layers 3–4 must be re-scoped around Layer-2 authenticated access
> **before** the broker is built. vPIC yields build/specification data. It does **not** yield
> location, kinematics, live DTCs, battery state, or service history — expect those as negative
> findings and size the Layer-2 work accordingly.

`SCHEMA_SQL` in `m0-vin-yield/src/index.js` remains the source of truth for the DDL. After
editing it, regenerate the committed file:

```bash
node --input-type=module -e "import {SCHEMA_SQL} from './m0-vin-yield/src/index.js'; import {writeFileSync} from 'node:fs'; writeFileSync('m0-vin-yield/schema.sql', SCHEMA_SQL.trim()+'\n')"
```

---

## 2. M3 — Delete Act / DROP compliance. Hard date: **August 1, 2026.**

NF-WP-1 §15 rec 2: ship this *before* revenue features. The processing obligation begins
August 1 2026; registration (fee $6,000 for 2026) and the VIN-as-enumerated-PII disclosure are
already required, and missed deadlines run at $200/day. Enforcement is live — the CPPA has
issued repeated registration-failure fines and stood up a Data Broker Enforcement Strike Force.

```bash
npx wrangler d1 create nimbus-drop-compliance
```

Set `database_id` in `m3-drop-compliance/wrangler.toml`, then:

```bash
npx wrangler d1 execute nimbus-drop-compliance --remote --file=m3-drop-compliance/schema.sql
```

```bash
cd m3-drop-compliance && npx wrangler secret put COMPLIANCE_ADMIN_TOKEN && npx wrangler secret put SUBJECT_MATCH_KEY && npx wrangler deploy
```

Both secrets must be ≥ 32 characters. `SUBJECT_MATCH_KEY` keys the subject digests — an unkeyed
digest of a low-entropy identifier is reversible by enumeration, which is the whole reason it is
keyed rather than hashed.

The cron trigger is `17 3 * * *` — daily, deliberately far tighter than the 45-day floor. A
cadence with no margin fails the first time a run errors.

> **The two clocks, both governing** (NF-WP-1 §9.5). Vendor summaries routinely collapse these
> into one "45-day" figure. They are different:
> - access/check DROP **at least every 45 days**
> - report status **within 45 days of retrieval**
> - complete deletions **within 90 days of retrieval**
>
> `m3-drop-compliance/src/clocks.js` tracks them separately and the conformance suite asserts
> they are never conflated.

> **Before launch:** the DROP adapter is a **declared stub**. The real endpoint contract is not
> published in NF-WP-1 and MUST be confirmed against CPPA's published interface. Do not treat
> the stub's shape as verified.

> **Acceptance:** a working 45-day retrieval loop, 90-day completion, and audit-file generation
> demonstrated in staging **by June 2026**. The audit file is produced *before* the status file
> is returned to CalPrivacy — enforced in code, not merely documented.

---

## 3. M1 — the consent broker (Layer 3). Blocked by the M0 gate.

```bash
npx wrangler d1 create nimbus-broker
npx wrangler kv namespace create CACHE
```

Set `database_id` and the KV `id` in `broker/wrangler.toml`, then:

```bash
npx wrangler d1 execute nimbus-broker --remote --file=broker/schema.sql
```

Secrets:

```bash
cd broker && npx wrangler secret put VIN_INDEX_KEY
```

`VIN_INDEX_KEY` is 32 random bytes, base64url:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Then set the Clerk identity vars in `[vars]` (`CLERK_ISSUER`, `CLERK_JWKS_URL`,
`CLERK_AUTHORIZED_PARTIES`) and **`NF3_TRUST_ANCHORS`**.

> **`NF3_TRUST_ANCHORS` is not optional.** With no anchor configured, `resolveVin` refuses every
> resolution with `no_trust_anchor` and `GET /resolve/:vin` is a dead endpoint. It is a JSON
> object mapping zone → signing key; an unsigned resolution answer is a cache-poisoning vector,
> which is why there is no permissive default.

```bash
npx wrangler deploy
```

Routes:

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/grants` | issue a grant (owner-authenticated) |
| GET | `/grants/:id` | status: active / expired / revoked |
| POST | `/grants/:id/verify` | verify a presented grant |
| POST | `/revocations` | owner-signed revocation |
| GET | `/resolve/:vin` | NF-3 resolution — returns a location, never authority |
| GET | `/healthz` | liveness |

Vehicle enrolment is **not** a V1 route: it needs custody evidence, which is a non-index input.
`POST /grants` fails closed with `vehicle_not_enrolled` until that path is designed.

---

## 4. Standing obligations

- **Re-run `./verify.sh` before every deploy.** It is the whole gate.
- **Regenerate vectors after any change to grant or revocation structure:**
  `node conformance/vectors/generate.js`, then re-run `./verify.sh`. Vectors are committed so
  the suite runs offline and so a change to them appears in review.
- **The static scan is evidence, not proof.** It is intraprocedural, has no call graph, and
  matches on names. `conformance/README.md` enumerates what defeats it. A green scan is not a
  substitute for review of any new code that touches resolution or authorization.
- **Never let a VIN reach a log line.** The broker logs route templates, grant ids and
  pseudonyms only. The Delete Act expressly enumerates VINs as collected personal information.
- **Refusal 3 is structural.** If the Foundation is ever asked to operate an exchange it also
  governs, that is a charter violation, not a product decision.

---

## 5. Not built — do not let the repo imply otherwise

| Milestone | Status |
| --- | --- |
| M2 dealer-license verification | Not built. CA DMV Occupational Licensing (Forms OL 12, OL 25, OL 56). **No public API** — scraping or a manual workflow is required. |
| M4 spec publication | NF-1…NF-5 drafted here. Prior-art scan and the **SDOAA DOJ/FTC notification** are not done. De-trebling attaches to the *notifying* SDO, not to participants. |
| M5 Foundation formation | Not started. Delaware nonstock nonprofit, IRC §501(c)(6), Linux-Foundation-style membership classes, patent non-assertion covenant, three refusals in the charter. |
| M6 agent-wrapper pilot | Not started. Wyoming series LLC per agent (Bayern mechanism). Blocked pending California counsel on Node Bond risk-capital structuring if any capital-at-risk instrument attaches. |
| Layer 5 market layer | **Deferred and gated** behind securities, DFAL and Sherman §1 clearance. Out of scope for V1. Prior implementation quarantined in `layer5-deferred/`. |
| Layer 4 federated learning | Design only. Token-rewarded ZK rounds were removed: rewards are economic rights, and Governance Membership carries none. |

**Lead the LA County beachhead with fleet, repair, municipal and research demand — not
insurance.** California's Proposition 103 and 10 C.C.R. § 2632.5 mandate rating-factor order and
constrain usage-based insurance more tightly than most states, so the insurance wedge is
materially narrower there than nationally. Reserve insurance for national expansion.
