# _superseded — QUARANTINE

**Status: preserved for reference. NOT part of V1. MUST NOT be imported, run, built, or
depended on by any V1 code path.**

## Contents

    offchain-ts-broker/package.json       fastify ^4, jose ^5, viem ^2; tsx, typescript
    offchain-ts-broker/tsconfig.json      TypeScript build config
    offchain-ts-broker/.env.example       RPC URL, contract addresses, JWT secret
    offchain-ts-broker/src/broker.ts      fastify HTTP broker; challenge/response, stream cut
    offchain-ts-broker/src/chain.ts       viem public client, consent/VIN ABIs, revocation watch
    offchain-ts-broker/src/capability.ts  short-lived JWT capability tokens (jose)
    offchain-ts-broker/src/scopes.ts      scope specs and field projections
    offchain-ts-broker/src/source.ts      Layer 2 adapters — OEM HTTP pull, dongle push
    offchain-ts-broker/src/twin.ts        in-vehicle / dongle agent; signs frames, trains locally
    offchain-ts-broker/src/config.ts      env parsing

This was the off-chain consent broker and vehicle twin for the prior Ethereum-L2 design. It
is superseded by NF-WP-1, *The Consent-Governed Catallaxy* (July 2026). The replacement lives
in `broker/src/` as plain ES modules.

---

## Why it is superseded

### 1. It violates the binding stack constraint (NF-WP-1 §14)

Non-negotiable, and sufficient on its own. The reference stack is Cloudflare Workers, vanilla
HTML/CSS/JS, D1/SQLite, Clerk, Supabase, Inngest, Stripe, Twilio — **no npm, no build step, no
third-party dependencies.** This tree is the opposite of all three:

- **Three runtime dependencies**: `fastify` (HTTP server), `jose` (JWT), `viem` (Ethereum RPC).
  Each is a supply-chain surface in a system whose whole argument is that authority must be
  provable, and none of them is available without an install step.
- **TypeScript with a build step** (`tsc`, `tsx`). V1 is plain ES modules with `import`/`export`
  and no transpile.
- **A long-lived Node process** (`fastify`, `watchRevocations` holding a websocket subscription,
  in-memory `Set` of invalidated vehicles). Workers is request-scoped: there is no process to
  hold that state, which is a better fit for the doctrine anyway — see §4 below.
- **`node:crypto`** (`createHash`, `randomBytes`) rather than WebCrypto. V1 is WebCrypto only,
  with Ed25519 feature-detected at runtime.

### 2. It implemented the deferred market layer

`chain.ts` binds `policyOf(... uint128 pricePerDay, uint32 minDays, uint32 maxDays ...)` and
`quote(tokenId, scope, daysRequested)`. The broker's job included quoting and serving priced
subscriptions. That is a Layer 5 Function (NF-1 §2.3, §3.5), out of scope for V1, and gated
behind securities / DFAL / money-transmission / Sherman Act §1 clearance (NF-1 §8). See
`../layer5-deferred/README.md` for the contract side.

### 3. Its authority source is now itself forbidden

The broker derived authorization from public-ledger state: `hasAccess`, `consentEpoch`,
`AccessRevoked` events. Reading revocation state from a chain requires *writing* revocation
state to a chain, which means a permanent per-vehicle record of every grant, transfer and
panic revoke on a public ledger — undeletable behavioural metadata, irreconcilable with the
45-day Delete Act cadence and CCPA erasure (Refusal 2, NF-1 §4.3). The correct answer to "how
do you know it isn't revoked" is a read from mutable, deletable storage, not from an
append-only one.

Related: an on-chain owner address is a persistent global identifier that defeats the
per-audience rotating pseudonym outright (NF-WP-1 §12.7).

### 4. Its scope vocabulary is now non-transactable

`scopes.ts` mirrors `Scopes.sol`, including `LOCATION_COARSE`, `LOCATION_PRECISE` and
`DRIVER_EVENTS`. Precise geolocation, biometrics and in-cabin audio/video now have **no grant
type at all**, and V1 admits **no positional field at any precision** (NF-1 §6.3). There is no
edit that brings this file into line; the vocabulary is a different object now.

---

## What was salvaged conceptually, and where it lives

Four ideas in this tree were right, and each is now enforced somewhere stronger than a broker
comment. Recorded so the reasoning is not re-derived from scratch.

### Authority is external state, re-derived per access — not the token in hand

`broker.ts` re-checked chain state on every stream tick and cut open streams on a revocation
event, regardless of what any presented token said.

**Now:** NF-1 §4.4 (boundary B4) makes this normative and mechanical. A cryptographic
verification verdict is **not** authorization: authorization is a verdict **plus** the current
revocation state, read in the same request (L3-10, L4-1). `verifyGrant` in
`broker/src/nf2-grant.js` deliberately does not know revocation state and takes it as a caller
input, so "I forgot to check" is not reachable by omission — only by passing a value you had
to obtain. The authority *store* moved from a chain to D1, for the reason in §3 above; the
principle is unchanged and now stated as a boundary rather than as diligence.

### Capability tokens are a cache, never a grant

`capability.ts` was explicit and correct: the JWT carried no authority of its own, was a cache
of one authorization answer, stamped with the consent epoch it was true under, expiring in
minutes, and the stream handler re-derived regardless. Binding the epoch meant a revocation
killed outstanding tokens *cryptographically* rather than administratively, surviving a cold
cache or a process restart.

**Now, with the roles inverted.** The NF-2 Consent Grant is the **authority object** — owner-
signed, purpose-limited, expiring, and bound to the counterparty's public key rather than to a
name — and it is emphatically **not** a bearer cache. What survives from `capability.ts` is the
cache discipline: any cached authorization decision MUST carry the state it was true under and
MUST expire (NF-1 §3.4 L4-1). Two honest notes:

- The epoch counter in the old token and the `epoch` in a Vehicle Pseudonym are **not the same
  mechanism.** The pseudonym epoch bounds *linkability*; it is not an authority-invalidation
  counter. A mass-invalidation counter is NF-4's business and is **not built.** Do not read the
  pseudonym epoch as a revocation signal.
- The JWT went with the dependency, and its lesson stayed: NF-2 has **no `alg` field anywhere.**
  The suite is pinned by the signed `v` member. Anything a verifier must read *before* checking
  the signature, in order to decide *how* to check it, is attacker-controlled (NF-1 §9.1 R-1).

### Projection is an allowlist, never a denylist

`scopes.ts` had the best line in the tree: the broker may relay only the fields listed for a
scope, whatever the upstream OEM response happens to contain, so an insurer who bought battery
health gets state of charge and no GPS fix even though the same payload carried one. Failure
mode of a schema change: "buyer sees less than they paid for," never "buyer silently receives
data nobody consented to."

**Now:** promoted from broker policy to protocol structure. `broker/src/fields.js` holds a
**closed** field vocabulary — no "other", no free-text field — and `validateFieldSet` fails
closed on an unknown id rather than silently narrowing the grant, because a grant that quietly
covers less than the owner read is a consent defect, not a convenience. NF-1 §3.4 L4-2 restates
the allowlist rule normatively. The upgrade over `scopes.ts`: the refused classes now have no
identifier at all, so the projection cannot be widened by governance adding a field — there is
nothing to add.

### The credential stays with the adapter; the buyer gets a projection

`source.ts` named the asymmetry precisely: the broker holds the OEM refresh token, that
credential is held in one place, is never derived from anything on chain, and is never exposed
to the buyer — the buyer's grant buys a *projection of the response*, never the credential that
produced it. `assertReadOnlyUpstream` failed closed on any upstream path that looked like
actuation, and no source implementation issued commands.

**Now:** NF-1 §4.2, trust boundary **B2**, the credential boundary. Layer 2 credentials MUST NOT
cross upward and MUST NOT be derivable from any NF object (L2-4); commands MUST NOT cross
downward (L2-1, L4-6); circumvention is out of bounds (DMCA §1201, L2-2); and access must rest
on an authorization the owner actually granted, since *Van Buren v. United States*, 593 U.S. 374
(2021) narrows "exceeds authorized access" without converting an unauthorized route into an
authorized one (L2-3). NF-1 SEC-12 records the consequence the old code implied but did not say:
B2 concentrates real credentials in the adapter, so it is the highest-value target in the system
— compromise there is compromise of the owner's manufacturer account, strictly worse than
compromise of any grant.

### Also noted, not yet rebuilt

`twin.ts` signed telemetry frames on the owner's hardware so the broker could prove provenance
to a buyer **without the broker being trusted to assert it**, while still projecting the frame
down per scope before relaying. That separation — provenance proved by the device, scope
enforced by the broker — is sound and maps onto the integrity commitment, one of the three
things Refusal 2 permits on-chain. It is **not built in V1** and no V1 claim depends on it.

---

## Rules for this directory

- Do **not** `npm install` here, and do not add it to any workspace. The dependency set is the
  violation.
- Do **not** import from `_superseded/` in V1 code, under any flag or conditional.
- Do **not** port a file wholesale. Port the *idea*, and state where it is enforced now — the
  four sections above are the template.
- Do **not** revive the priced-subscription or on-chain-authority paths. See
  `../layer5-deferred/README.md` and NF-1 §8 for what would have to land first.
