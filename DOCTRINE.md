# DOCTRINE

The charter spine of the Nimbus Foundation, from NF-WP-1 §10 and §1.4. Short on purpose.
Everything in this file is load-bearing: it is enforced in code, tested by NF-5, and
referenced by NF-1 as architecture rather than policy.

---

## The three refusals (NF-WP-1 §10.1)

These are absolute. Not defaults, not preferences, not subject to a pilot exception, a
majority vote, a member's commercial need, or a regulator's blessing. An implementation
that violates one is non-conformant regardless of every other property it has.

### Refusal 1 — Never resolve a VIN to a credential

The VIN is a **public index** — a name, exactly like a DNS name. Resolution returns
**where to ask** for authorization. It never returns authorization itself, a credential, a
key, a payload, or a statement about the owner.

Possession of a VIN must confer no authority in any code path, anywhere, at any layer. If
a VIN alone changes an access outcome, the system is broken. This is testable, and NF-5
tests it by presenting a valid VIN and nothing else.

### Refusal 2 — Never put personal information on an immutable ledger

On-chain content is limited to three things: consent-grant hashes, revocation-state
commitments, integrity commitments. Nothing else — not payload, not identifiers, not
linkage, not a persistent per-vehicle account record.

The reason is not squeamishness, it is arithmetic. A standing 45-day Delete Act deletion
cadence and CCPA erasure rights cannot be satisfied on a ledger you cannot delete from
(NF-WP-1 §9.5). You do not get to promise erasure and write to an append-only store. So
all payload, identifiers and linkage live in mutable, deletable storage (D1), and the
owner-held pseudonym salt is the erasure mechanism: destroy the salt and the linkage is
gone, not merely marked deleted.

Note the corollary, because it is the one people miss: a permanent per-vehicle *record* on
a public ledger is undeletable behavioural metadata even when it carries no payload at all.
"No PI on chain" excludes the registry entry, not just the data.

### Refusal 3 — Never operate a market we also govern

The Foundation is a standards body. Not a market operator. Not a licensor of preferential
access. Not a holder of consent grants, owner keys, pseudonym salts, or revocation
authority.

---

## Why Refusal 3 is the load-bearing one (NF-WP-1 §10.2)

Refusals 1 and 2 are engineering constraints; you can test for them and you can see them
in a diff. Refusal 3 has no cryptographic enforcement at all. It is held by charter, which
makes it the constraint most likely to erode — and the erosion is commercially motivated
and gradual, not adversarial and sudden. So it needs to be argued, not just asserted.

**Doctrinally:** a body that both sets the standard and runs the exchange has
reconstituted the central planner. It decides what may be traded, on what terms, by whom,
at what price, and who is admitted — which is precisely the calculation the distributed
consent architecture exists to avoid making. A standards body that runs the market it
standardizes is not a market; it is a plan with an order book bolted on.

**Legally:** the same structure is Sherman Act §1 exposure. A standard-setting organization
whose members are competitors, which also operates the venue, sets access terms, and takes
a fee, is doing the thing antitrust law watches standard-setting bodies for. The defence is
not good intentions; it is structural separation.

**Neutrality is therefore the firewall — both antitrust and doctrinal, and it is the same
firewall.** The Foundation specifies interfaces and runs a conformance suite. Somebody else
runs any market. There is no Foundation take rate, no listing authority, no preferential
tier, and no private specification text. The Foundation occupies no role in its own
architecture, which is why it is not a conformance target in NF-1 §2.2.

---

## Identifier, not credential (NF-WP-1 §1.4)

**A VIN is public.** It is visible through a windshield, printed on insurance documents,
carried on title paperwork, and enumerable from build data. Code that treats it as a secret
is wrong twice over: wrong about the fact, and then building authority on the mistake.

Two episodes ground the doctrine. In both, the VIN was being **mistreated as a credential**,
and in both, the failure was an **access-control failure — not a property of the VIN.**

**2015 — Miller and Valasek, Jeep Cherokee.** A remote compromise of an unaltered vehicle
over the cellular network. The researchers used the VIN and location data to *locate* the
target vehicle's IP address; the compromise itself came from the exposed service behind it.
Fiat Chrysler recalled 1.4 million vehicles — the first vehicle recall driven by a
cybersecurity vulnerability. The VIN was an index into a reachable service that should have
demanded authentication and did not.

**2023 — Curry et al., "Web Hackers vs. the Auto Industry."** Across multiple
manufacturers, a VIN alone sufficed to locate, unlock and start vehicles. The mechanisms
were ordinary web bugs: misconfigured SSO, insecure direct object references, mass
assignment. Nothing about the VIN was defeated. The authorization checks were simply
missing, and a public name was accepted where proof of authority was required.

The lesson the industry drew — treat the VIN as sensitive — is the wrong one, and it is
unachievable besides: you cannot make a number secret when it is stamped on the dashboard.
The right lesson is that **authority must be proved, never inferred from a name.** That is
why an NF Consent Grant is bound to a public key and not to a name: a name is an assertion
the presenter makes about themselves, while a key is a challenge the presenter either
answers or does not. A stolen grant plus no private key equals nothing — which is also why
a grant is not a secret and can be logged and shipped over an untrusted bearer.

### What the doctrine is NOT

The doctrine is **not** that the VIN is a "publicly traded index."

The VIN is never traded. It is never priced. It never conveys rights, and there is no
instrument representing it, no market in it, and no token minted against it. Nothing about
a VIN is bought or sold anywhere in this architecture. "Public" means *not secret*; it does
not mean *tradable*, and the two words are not near neighbours.

What is authorized is scoped, time-bounded, purpose-limited access to specific consented
fields — and that authorization is a non-transferable, non-fungible, owner-revocable
capability object. Consent Grants are never traded, never priced, never collateralized.

---

## CarNimbus's status (NF-WP-1 §10.3, §9.10)

**Prime implementer.** CarNimbus is the first party building to the NF series and the
reference deployment against which the specifications are exercised.

**A renewable tier any implementer can earn.** Prime Implementer status is earned by
passing the NF-5 conformance suite, is re-earned on the published cadence, and is not
exclusive. Any implementer who passes holds the same tier.

**Not a preferential licensee.** Terms are FRAND and identical for all implementers. No
early access, no private specification text, no discount, no reserved seat, and no
conformance result that depends on who the implementer is. The prime implementer does not
hold a governance position that lets it decide its own conformance.

The distinction matters because "reference implementation" is the usual vehicle for exactly
the capture Refusal 3 forbids. A standards body whose favoured implementer gets the spec
first has a private market in access to the standard, which is Refusal 3 violated one step
removed.

---

## Where the doctrine is enforced

Doctrine that lives only in a document is a preference. These are the enforcement points.

| Doctrine | Enforced in |
|---|---|
| Refusal 1 — index, never credential | `broker/src/vin.js` (validation and pseudonymization only — nothing here authorizes anything); NF-1 §3.3 L3-1, L3-2 |
| Refusal 1 — no raw VIN in a grant | `broker/src/nf2-grant.js` re-reads its own canonical output to prove the VIN is absent |
| Refusal 2 — mutable storage only | D1 for payload, identifiers, linkage and salts; NF-1 §4.3 (boundary B3) |
| Refusal 2 — commitments only on-chain | `deriveGrantCommitment` in `nf2-grant.js`; fixed-length opaque values, no payload-shaped field exists |
| Refusal 3 — no operator-held revocation | `nf2-grant.js` rejects a grant whose revocation key is the counterparty's, and accepts a list of known operator-held key ids so the refusal is tested, not asserted |
| Refusal 3 — Foundation holds nothing | NF-1 §2.2: the Foundation is not a conformance target |
| No transactable sensitive classes | `broker/src/fields.js` — precise geolocation, biometrics and in-cabin A/V have no field id at all |
| Non-transferable grants | `assertNonTransferable` in `nf2-grant.js`; no holder-mutation field exists in the closed key set |
| No Layer 5 in V1 | absence is structural: no price, amount, currency or fee field exists anywhere; NF-1 §8 holds the gate |

## Amendment

The three refusals are not amendable by proposal, vote, or interpretation. Changing one
requires a superseding white paper and a charter amendment, published, with a version bump
to NF-1. Anything short of that — a pilot, an exception, a "temporary" carve-out for one
member — is a violation with paperwork.
