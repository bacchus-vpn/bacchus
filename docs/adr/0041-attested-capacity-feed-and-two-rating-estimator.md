# 41. Attested-capacity feed and the coordinator's two-rating estimator

- Status: accepted (issue #158; implements the #157 owner decision)
- Date: 2026-07-22

## Context

ADR-0040 (issue #144) built `core/capacity.Estimator` — the ratchet that turns
co-signed usage receipts into a gaming-resistant capacity rating — and proved its bounds
by adversarial simulation. It deliberately shipped **fed by nothing** (design §8.6): the
coordinator held no estimator, `capacity.Usable` (`min(declared, measured)`) had no
production caller, and any gate on `measured` would have pinned every node at `Floor` and
stranded the fleet. Two things had to land together for the estimator to *run*: the feed
that carries samples to it, and the wiring that consumes its output — with tests proving
the landing does not strand anyone.

ADR-0040 also left the **Sybil hole open and priced, not closed**: a co-signed receipt
attests *agreement, not transit*, so an attacker holding a ~4:1 AS supermajority among a
node's attesters can hold a rating it does not honour. Issue #157 set that price, and the
answer (design §8.1.1) is binding on this work, not stylistic: **a node carries two
ratings.** `trusted` is attested only by accounts a real person vouched for and is the one
the coordinator uses; `untrusted` is attested by anyone and may never exceed the
provisional ceiling — so forging the cheap signal buys exactly what silence already buys.

This record captures how that feed and those two ratings are built, and — in
Consequences — what it still does not solve.

## Decision

### 1. The sample: a co-signed receipt plus one client-asserted bit

A capacity sample is an ADR-0021 receipt (which proves a throughput both the exit and the
client co-signed, so neither moved it alone) plus a **`Saturated` bit** — the client's
assertion that it wanted to move more than the link carried (design §5.3). The bit is the
one datum the byte count cannot supply, and the one part of a receipt the exit cannot
verify, so it is **not co-signed**: it is added to `accounting.Receipt` as an additive,
`omitempty` field absent from the signed `canonical()` (an ADR-0021 amendment — see that
record). It is instead bound to the co-signing client by a **separate** signature,
`accounting.SignReport`, over the receipt claim plus the bit, verifiable against the
receipt's client key. This is what stops a node that merely *holds* the receipt from
forging a report or flipping the bit: it does not have the client's private key.

The client detects saturation on its **upload** path only — a tunnel write that blocks
past `satBlockThreshold` (250 ms) means the client had more to send than the link carried.
Download saturation is confounded by remote-server speed (a slow read could be the node
throttling *or* the origin being slow, and blaming the node for the latter would defame
it), so it is left to a follow-up (#160). The bit therefore under-reports, which errs
toward under-rating — the direction the design already prefers (§6.3).

### 2. The feed: `capacity-report`, client → coordinator

A new best-effort message carries `{receipt, reportSig, cred}` from the client to the
coordinator over the same signaling channel `list`/`connect` already use. It is
fire-and-forget and gets no reply — a reply would be an oracle. The coordinator drops any
report whose receipt co-signature (`Receipt.Verify`) or report signature
(`accounting.VerifyReport`) does not check out, or whose attester has no attributable AS.

Samples reach the coordinator **from the client, not the node**: the client has the
correct incentive, and a node cannot suppress a bad sample it does not carry (design
§6.2). The attester AS is derived from the **coordinator-observed** source address of the
report, never a client self-report — the same rule `Entry.Ingress` holds (an observed IP
is trusted, a claimed one is not), because the AS is the unit of Sybil cost.

### 3. Two estimators, never blended (implements #157)

`capacity.NodeRating` holds **two** `Estimator`s with **two** sample streams:

- **`trusted`** — fed only by vouched attesters. Uses the estimator as-is: its ceiling is
  *provisional*, released once `CeilingASes` (3) distinct ASes attest, so vouched
  attestation can earn a rating above `Ceiling` (5 Mbit).
- **`untrusted`** — fed by anyone with a client credential. A new estimator flag,
  `Params.HardCeiling`, makes `Ceiling` a **permanent** clamp: no amount of unvouched
  attestation, from any number of ASes, lifts it past 5 Mbit. The clamp lives *inside* the
  estimator, not in a caller — a clamp in a caller is a clamp someone later removes (§8.1.1
  rule 3).

The combine rule (`NodeRating.Measured`) is the whole of #157:

- **`trusted` decides outright wherever it exists** — no weighted average, no max, no
  tiebreak (rule 2). "Exists" is `Estimator.Informed`: has the trusted stream closed a
  window on real evidence and not since decayed back to `Floor`. An **unfed** trusted
  estimator is not informed and does not decide.
- Otherwise the untrusted rating decides — already clamped to `Ceiling` by its own
  estimator.
- Rule 4 ("a node with `trusted` above the ceiling ignores `untrusted`") falls out of
  rule 2 rather than being a separate branch.

The separation is the security property: two streams cannot be blended, whereas one
estimator with a weight field is one refactor away from a blend (rule 1).

### 4. Vouched-ness rides the credential, and the trusted stream is unfed

Whether an attester is vouched is a **policy** decision made where identity is priced (the
private account/vouch service, productization design §5), which the coordinator **cannot
import**. So vouched-ness rides the admission credential the coordinator already verifies:
a `Vouched` marker on `admission.Credential` (additive, `omitempty`), read by the
coordinator's classifier.

**Nothing in this repo stamps `Vouched`.** `cmd/admission-issue` never sets it, so in this
build **every sample is untrusted and the trusted stream is permanently empty.** That is
the seam, defined and wired, waiting for the account service to issue vouched credentials —
at which point the trusted stream feeds with no coordinator change. This is deliberate and
is called out here so the record is not read as describing a running trusted rating.

### 5. The rating map has its own lifecycle

`capacity.RatingStore` keys ratings by node id in its **own** map, **not** on the registry
entry. The register handler replaces a node's registry struct wholesale every ~10 s; a
rating stored there would be silently reconstructed (reset to `Floor`) on every heartbeat,
and nothing would fail visibly (design §8.6). The store ticks every `Window` (1 min) to
move or decay each rating, and **evicts** a rating idle past `ratingIdleTTL` (48 h, a
couple of decay half-lives — a rating has already decayed to `Floor` and is worthless
before it is evicted; eviction is memory hygiene, not a rating decision).

### 6. `Usable` is applied at the assignment surfaces — with the gate OFF

The coordinator computes `capacity.Usable(declared, measured)` at `list` and `pickRelay`
via `RatingStore.Usable` — the production caller ADR-0040 §8.6 said the contract lacked.
A serve-eligibility floor (`serveFloor`) is wired as a filter at both surfaces, **shipped
at zero (off)**: a `Rate` is always ≥ 0, so it withholds nothing, and the exhausted-quota
check (#143) remains the only thing that withholds a node.

It must stay off. With the trusted stream unfed, every rating clamps to `Ceiling`, so any
floor above zero would reject every **rated** node and strand the fleet (an unrated node
falls back to its `declared` cap, so it is not rejected — immaterial while the floor is
off, but the distinction is the difference between the claim being true and nearly
true). Whether that floor is
raised is #145's policy call — it varies by region, role, and scarcity (§6.5) — and this
lane does not make it. The machinery lands *with* the feed (as §8.6 asks) in the off
position, and `TestFleetSurvivesTheFeedLanding` proves that landing does not strand
anyone; `TestServeFloorGateWouldExcludeIfEnabled` proves the gate is real, not dead code.

### Starting values

The estimator's constants are ADR-0040's, unchanged, and are the ones this record's prose
is pinned against (`core/capacity/estimator.go` `DefaultParams`): `Window` 1 min,
`Quantile` 0.25, `RiseFactor` 1.25, `Ceiling` 5 Mbit, `CeilingASes` 3, `Floor` 256 Kbit,
`HalfLife` 24 h, `MinASes` 2. New here: `satBlockThreshold` 250 ms (upload backpressure)
and `ratingIdleTTL` 48 h (rating eviction) — both starting values, tunable once there is
real data.

## Consequences

**Good.**

- ADR-0040's estimator now *runs*: samples flow client → coordinator, the two ratings are
  maintained per node, and `Usable` has a production caller — without changing which nodes
  are assignable (the fleet-survives test).
- The #157 decision is encoded structurally, not by convention: two estimators, a
  ceiling clamp inside the untrusted one, and a combine that returns `trusted` outright
  where it exists. Each rule is pinned by a test that fails if the rule is removed.
- Forging the cheap (untrusted) signal buys the ceiling and not one bit more — exactly
  what silence already buys — so an honest free-tier-only node is lifted off `Floor` to
  as much as 5 Mbit while a $100/month VPS fleet buys nothing over saying nothing.
- The saturation bit cannot be forged or flipped by the measured node: it is bound to the
  co-signing client by a signature the node cannot produce.

**Bad / open — stated plainly, because this whole lane's value is honesty about it.**

- **The trusted stream is unfed, so today every rating is `≤ Ceiling`.** This is the
  decision working (a purchasable identity buys only the ceiling), not a running trusted
  rating. It also means the coupling it introduces — node ratings above 5 Mbit now depend
  on the vouch trust-graph — is latent until the account service feeds the seam.
- **The Sybil hole is priced, not closed** (ADR-0040, #157). An attacker who obtains
  *vouched* accounts across ~75% of a node's attesting ASes still holds a `trusted` rating
  it does not honour. What changed is the currency — social effort in many networks,
  leaving a revocable trail — not that the hole is shut. The load-bearing defense remains
  the client never trusting the rating (ADR-0028's ladder), which is the standing posture.
- **The AS is a coarse proxy.** With no ASN database wired, `observedAS` masks the observed
  IP to a routing prefix (/24 v4, /48 v6) as a "same-network" stand-in. That is adequate
  for the untrusted stream (which clamps to `Ceiling` regardless of AS count — the proxy
  only affects how readily an honest node *reaches* the ceiling), but the ~4:1 AS bound the
  trusted stream leans on is only as good as the AS mapping, so a **real ASN lookup is
  required before the trusted stream is fed** — the same gate as the unfed seam above.
- **The saturation bit is upload-only and client-asserted** (design §8.2). It under-reports
  (download saturation is unmeasured, #160) and a defaming client can assert it while idle
  — an availability attack on an honest node, bounded because it only lowers a rating, and
  the cheap direction the design accepts (§6.4).
- **Relays still cannot be measured** (design §8.5): receipts are exit-only and
  direct-mode-only, so a relay produces no samples and `measuredUsable` falls back to its
  declared cap. A capacity-aware relay pick (#162) is therefore blocked on relay
  attribution (#159); `pickRelay` stays a random pick among the non-exhausted, as its own
  anti-determinism argument requires.

## Relationship to other work

- **ADR-0021** supplies the receipt; the `Saturated` bit amends it (see that record).
- **ADR-0040** is the estimator and the methodology; this is the feed and the wiring §8.6
  deferred, and the two-rating shape §8.1.1 settled.
- **ADR-0023** admission carries vouched-ness and sets the price of an attesting identity,
  and therefore the depth of the residual Sybil hole.
- **ADR-0028**'s ladder is the client-side safety net that makes the residual survivable —
  a client never has to trust a rating.
- **#145** consumes `Usable` and decides the serve floor this lane ships off; **#159**
  unblocks relay measurement; **#160** hardens the saturation bit.
