# layer5-deferred — QUARANTINE

**Status: preserved for reference. NOT part of V1. MUST NOT be imported, deployed, tested
against, linked from, or built by any V1 code path.**

This directory holds the Ethereum-L2 Solidity suite written against the prior design. That
design has been **superseded** by NF-WP-1, *The Consent-Governed Catallaxy* (July 2026).
Nothing here ships. Nothing here is "pending integration." Each piece is blocked by a
specific constraint in the current charter, and those constraints are listed below next to
the thing they block, so that the block is auditable rather than remembered.

It is kept because the reasoning inside these files is worth reading — several comments
identify real attacks and real design traps — and because a future gated Layer 5 effort
should start from what was already thought through rather than from a blank file. Reading
is the only sanctioned use.

---

## Contents

    foundry.toml, remappings.txt          Foundry build config
    contracts/CatallaxyVIN.sol            ERC-721 vehicle index registry
    contracts/CatallaxyConsent.sol        priced consent market, streamed escrow
    contracts/CatallaxyToken.sol          $CATALLAXY — ERC20 + Permit + Votes, capped supply
    contracts/CatallaxyDAO.sol            OpenZeppelin Governor + Timelock, token-weighted
    contracts/FederatedRounds.sol         ZK-verified federated learning rounds, token rewards
    contracts/lib/Scopes.sol              scope constants (incl. positional scopes — see below)
    contracts/interfaces/*.sol            ICatallaxyVIN, ICatallaxyConsent, IProofVerifier
    test/*.t.sol, test/mocks/             Foundry tests
    script/Deploy.s.sol                   deployment script

---

## Why each piece cannot ship

### 1. `CatallaxyVIN.sol` — ERC-721 vehicle index registry

**Blocked by Refusal 2 (no PI on an immutable ledger) and by NF-1 §4.3 (boundary B3).**

The design was careful in the right places: registration under a *salted* commitment rather
than `keccak256(vin)`, because a bare hash of a public identifier with ~10^8 realistic
entropy is a rainbow-table lookup; and an EIP-712 attestation of custody, because
permissionless self-registration lets whoever reads a VIN off a dashboard mint the consent
rights to someone else's car. Both observations survive and are honoured elsewhere.

The blocker is not the commitment. It is that the contract writes a **permanent per-vehicle
record** to a public ledger: a token id, an owner address, a commitment, a `consentEpoch`
counter and an `epochChangedAt` timestamp, each advancing on transfer and on owner action.
That is undeletable behavioural metadata about a specific vehicle and a specific wallet even
though no payload is stored — enrolment, transfer history, and the timing of every panic
revoke, joinable against the owner address's entire public transaction history. A standing
45-day Delete Act deletion cadence plus CCPA erasure rights cannot be satisfied against it
(NF-WP-1 §9.5). "No PI on chain" excludes the registry entry, not merely the data.

Two further problems, each independently disqualifying:

- **ERC-721 is transferable by construction.** A transferable token over consent rights is a
  transferable consent right. Consent Grants are non-transferable, non-fungible,
  owner-revocable capability objects (NF-1 §3.3 L3-4). A registry whose primary verb is
  `transferFrom` is the wrong object.
- **An on-chain owner address is a persistent global identifier.** It defeats the per-audience
  rotating pseudonym completely: two counterparties holding grants over the same vehicle can
  join on the shared owner address regardless of what the pseudonym does (NF-WP-1 §12.7).

**What replaced it:** the vehicle is named in a grant by a salted, epoch-rotating,
per-audience pseudonym (`broker/src/vin.js`), and enrolment state lives in D1. On-chain
content, if any, is limited to grant hashes, revocation-state commitments and integrity
commitments.

### 2. `CatallaxyConsent.sol` — priced consent market with streamed escrow

**Blocked by the Layer 5 deferral (NF-1 §3.5), and separately by securities / DFAL /
money-transmission / Sherman Act §1 gating (NF-1 §8), and separately by Refusal 3.**

The mechanism was the point of the old design: owners post a per-scope price, buyers purchase
a time-bounded grant, escrow accrues second by second so revocation mid-term robs neither
side, and payouts are pulled rather than pushed so a reverting recipient cannot brick the
subscription path. The streamed-escrow argument for why revocation stays real is genuinely
good, and it is the piece most worth re-reading if the gate ever opens.

It is still four separate walls:

- **Posted prices are price discovery.** That is the definition of a Layer 5 Function, and
  Layer 5 is out of scope for V1 (NF-1 §3.5 L5-1, L5-2).
- **Escrow is custody of value.** It raises California Digital Financial Assets Law exposure
  and money-transmission questions that are unanswered. The Settlement Credit was *cut*, not
  deferred, for the adjacent reason (NF-WP-1 §9.7: store-of-value characterization, and a
  tangible-net-worth expectation of roughly $100,000 that is disqualifying for the
  Foundation's posture).
- **The DAO fee is a take rate on a market the governing body also governs.** Capping it in
  code at 5% mitigates the size of the problem and not the structure of it. Refusal 3 forbids
  the structure.
- **When settlement eventually exists it is fiat**, via a conventional processor (Stripe). A
  protocol-native unit of account is not the direction of travel (NF-1 §3.5 L5-4).

### 3. `CatallaxyToken.sol` — $CATALLAXY (ERC20 + Permit + Votes)

**Blocked by the rejection of tokenomics and by the non-economic-rights Governance
Membership model (NF-1 §3.5 L5-5, §7.2 S-6).**

Supply is capped in code and the mint role is scoped, which addresses dilution but not the
category. The category is the problem: a transferable, mintable ERC20 with `ERC20Votes`
makes **governance weight a function of holdings**, and holdings can be bought. That is
tiered pay-to-play governance, which NF-WP-1 rejects explicitly.

Governance Membership in the current model is non-transferable, one per member, and carries
**no economic rights** — the Linux/Apache pattern (the Linux Foundation is an
Oregon-domiciled §501(c)(6) organization). The Foundation is a Delaware nonstock nonprofit
electing IRC §501(c)(6), not an on-chain token-weighted DAO.

This is the one item on the list that **no legal clearance can revive.** It is a charter
matter, not a securities question (NF-1 §8 G-4).

### 4. `CatallaxyDAO.sol` — OpenZeppelin Governor + Timelock

**Blocked by the same tokenomics rejection (its voting power is the ERC20Votes token), and
independently by Refusal 3.**

The contract's own comment makes the strongest available case for it: deliberately narrow
jurisdiction, no function anywhere by which a majority can price, grant or revoke consent on
a car it does not own, and polycentricity enforced by the absence of the hook rather than by
a norm. That restraint is real and it is preserved in the current design.

It still cannot ship. Its jurisdiction is exactly the union that Refusal 3 forbids one body
from holding: it governs **the scope schemas and their mappings** (standards work) *and* sets
**the market fee** and the venue's parameters (market operation). Splitting standards from
market operation is the whole of Refusal 3, and this contract is the two halves in one
address. Add the token dependency and there is nothing left to salvage structurally.

**What replaced it:** a Delaware nonstock nonprofit with non-transferable membership, and a
published conformance suite instead of on-chain parameter votes.

### 5. `FederatedRounds.sol` — ZK-verified federated rounds with token rewards

**Blocked by the tokenomics rejection (L5-5) and by NF-1 §3.4 L4-4 (no economic reward for
aggregation).**

Federated learning itself is **Layer 4 and survives** — it is in scope, partially built,
and the local-training/only-aggregates-travel property is the right one. What does not
survive is paying for it with a minted token, which turns a Layer 4 aggregation function into
a Layer 5 reward market and reintroduces the token by the back door.

Two further blockers specific to this contract:

- **It writes per-vehicle contribution records and nullifiers on-chain.** Even as commitments,
  a per-round per-vehicle participation trail is undeletable behavioural metadata
  (Refusal 2).
- **It depends on `ICatallaxyVIN` registration and `ICatallaxyConsent` access checks**, so it
  inherits every blocker above.

### 6. `lib/Scopes.sol` — scope constants

**Blocked by the NF-2 closed field vocabulary and the Non-Transactable Classes (NF-1 §6.3).**

Worth calling out separately, because this file is where the old design and the current
charter are most directly opposed. `Scopes.sol` defines `TELEMETRY_LOCATION_COARSE_V1` and
`TELEMETRY_LOCATION_PRECISE_V1`, and prices the latter with the comment that
re-identification risk is high so it should be priced accordingly.

The current position is the opposite one, and deliberately so: precise geolocation,
biometrics and in-cabin audio/video have **no grant type at all**, and V1 admits **no
positional field at any precision**. A design constraint beats a policy statement because it
cannot be waived by a pressured or unsophisticated owner — and "price it accordingly" is
exactly the waiver channel a price creates. Aligns with CCPA sensitive personal information,
Cal. Civ. Code §1798.140(ae).

The one idea here that fully survives: there is **no scope that maps to an actuation or
command endpoint**, and there must never be one (NF-1 §3.2 L2-1).

### 7. `foundry.toml`, `remappings.txt`, tests, deploy script

**Blocked by the binding stack constraint (NF-WP-1 §14).**

Solidity requires a compiler, a toolchain, and third-party dependencies (OpenZeppelin). The
reference stack is Cloudflare Workers, vanilla HTML/CSS/JS, D1/SQLite, with no npm, no build
step, and no third-party dependencies. Even if every doctrinal blocker above were cleared,
none of this is buildable in the sanctioned stack as it stands.

---

## Clearances that must land before any of this is reconsidered

Per NF-1 §8. These are **cumulative and non-substitutable** — a favourable opinion on one
does not soften another, and the absence of any one keeps the gate closed. All must be held
in writing.

1. **Securities-law clearance** covering every instrument contemplated, including any
   governance or reward unit.
2. **California Digital Financial Assets Law determination** — licensure or exemption — for
   any store-of-value instrument and for any escrow or custody of value. NF-WP-1 §9.7's
   finding on the ~$100,000 tangible-net-worth expectation is not superseded by a later
   appetite for the feature.
3. **Money-transmission analysis** for any holding, escrow or forwarding of funds.
4. **Sherman Act §1 clearance** on the market structure, including a structural-separation
   opinion confirming that the market operator is a **distinct entity** from the Foundation
   and that the Foundation takes no fee, listing authority or preferential access from it.
5. **Privacy clearance** confirming that pricing introduces no new personal-information flow
   and no new immutable-ledger content, and addressing whether a price attached to consent
   bears on whether that consent is freely given under the DPPA (18 U.S.C. §2721(b)),
   Cal. Veh. Code §9951 and the CCPA.
6. **UCC Article 12 analysis** if any controllable electronic record is contemplated.
   California has enacted Article 12 (SB 95, Ch. 210, Stats. 2023), so this is settled law in
   the target jurisdiction rather than a forecast.
7. **A Refusal 2-clean ledger design** — one that keeps no PI and nothing PI-derivable
   on-chain, including no permanent per-vehicle or per-owner record. The ERC-721 registry
   here cannot clear this as designed; it would have to be replaced, not amended.
8. **Confirmation that grants remain non-transferable, unpriced and non-collateralizable**
   even after the gate opens. A market in *access* is a different object from a market in
   *grants*; the gate covers the former and forecloses the latter.

**Outside the gate — no clearance revives these**, because they are charter matters:

- tiered pay-to-play validator tokenomics;
- economic rights attached to Governance Membership;
- any Foundation-operated market, fee, or listing authority (Refusal 3).

Opening the gate is a published amendment to NF-1 with a version bump. It does not happen by
implementation, pilot, or interpretation.

---

## Rules for this directory

- Do **not** import from `layer5-deferred/` in any V1 code. There is no conditional, feature
  flag, or "dev only" path that makes it acceptable.
- Do **not** edit these files to bring them closer to compliance. Partially-compliant
  quarantined code invites the argument that it is nearly ready. If a piece becomes
  reconsiderable, it gets rewritten against the specification that admits it.
- Do **not** deploy, verify, or publish addresses for anything here, including on a testnet.
  A deployed contract with these names is a public claim about what the project is.
- Do **not** cite these contracts in any commercial representation. `$CATALLAXY`, the priced
  market, and the Governor DAO are not features of this project and never were, under the
  current charter.
