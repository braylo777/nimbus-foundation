# NOTICE — read this before relying on anything in this repository

This is a **reference implementation of a specification series, published while the specifications
are still drafts.** It is green on its own conformance suite and has never been deployed. Those two
facts are not the same fact, and this file exists so the gap is visible without reading the source.

## What has actually been verified

`bash verify.sh` → exit 0, six gates. `node conformance/run.js` → **NF-5 PRIME-IMPLEMENTER TIER:
PASS**, 319/319 assertions, 6/6 groups, 7/7 gates. Verified 2026-07-30 on Node v24.15.0 with
`sqlite3` present, offline.

That verdict covers exactly what an offline suite can cover.

## What has NOT been verified

- **No deployment has happened.** Nothing has run against live Cloudflare, live vPIC, or a real DROP
  endpoint. Every `database_id` and KV `id` in every `wrangler.toml` is a placeholder **by design**.
- **The adversarial doctrine audit and the completeness critic never ran.** Both died on a session
  limit. The suite is green, but **no hostile reviewer has gone looking for what the suite does not
  test.** A passing conformance run is not a security review.
- **`broker/src/index.js` has no end-to-end route tests** in the committed suite. It is exercised by
  its author's harness and by import-graph assertions only.
- **The DROP adapter is a declared stub.** The real CPPA interface is not published in NF-WP-1 and
  must be confirmed before it is relied on.
- **M0 has never run.** Until it does, the load-bearing data assumption of the entire architecture is
  untested (NF-WP-1 §13.1) and M1 is not cleared.
- **The static VIN-to-credential scan is evidence, not proof.** It is intraprocedural, has no call
  graph, and matches on names. `conformance/README.md` enumerates what defeats it.

## This publication is not a standards-body notification

The **SDOAA notification to the DOJ and FTC has not been made.** De-trebling under the Standards
Development Organization Advancement Act attaches to the *notifying* SDO — not to participants, and
not to a public repository. Publishing this code creates no such protection and should not be read
as claiming any.

Relatedly: **the Nimbus Foundation does not exist.** Formation (Delaware nonstock nonprofit, IRC
§501(c)(6)) is an unstarted milestone. "Foundation" throughout this repository names an intended
structure, not an incorporated entity, and no entity currently holds the charter described in
`DOCTRINE.md`.

## Legal content is described, not advised

This repository discusses the California Delete Act, CCPA, DPPA, CFAA as narrowed by *Van Buren*,
DMCA §1201, Sherman Act §1, *Howey*, and California's risk-capital test under *Silver Hills*. Those
discussions are engineering rationale for design constraints. **They are not legal advice**, several
of the underlying questions are recorded in NF-WP-1 §13 as genuinely unsettled, and agency guidance
is reversible while statute is not.

## The three refusals are the point

If you fork, implement against, or extend this work, the refusals in `DOCTRINE.md` are not style
preferences — an implementation that violates one is non-conformant regardless of every other
property it has. Refusal 3 in particular has **no cryptographic enforcement**; it is held by charter,
which makes it the one most likely to erode quietly.

## Licence

No licence is declared yet. Absent one, default copyright applies and no permissions are granted.
The intended terms are FRAND and identical for all implementers, per `DOCTRINE.md` — but intent is
not a grant, and this notice is not one either.
