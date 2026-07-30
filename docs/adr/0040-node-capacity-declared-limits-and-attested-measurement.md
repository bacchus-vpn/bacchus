# 40. Node capacity: declared limits, and measurement by attested serving

- Status: accepted (issue #143 implemented; issue #144 is a design spike — the
  attested-sample feed follows in child issues)
- Date: 2026-07-15

## Context

A node today registers and the coordinator routes to it without bound. Grepping the
tree for `capacity|bandwidth|quota|throughput` returns exactly one first-party hit: a
comment in `cmd/coordinator/main.go` conceding that a load-aware policy is a follow-up.
There is no speed cap, no quota, and no measurement of either.

The practical consequence is that **a residential volunteer cannot safely
participate** — they have an ISP data cap and an uplink their household also uses, and
no way to say so. That cuts the network off from the node population it most needs:
ordinary residential addresses in and near the censored region, which are exactly the
ones a censor cannot block wholesale.

Two issues, one problem:

- **#143** — what a node is *willing* to serve: a speed cap and a monthly quota, never
  exceeded.
- **#144** — what a node is *able* to serve, so that `usable = min(declared, measured)`
  and a node can neither be over-used nor over-promise.

#144 is labelled `spike` because measurement must be cheap **and** resist gaming: "a
node that is fast to the tester and throttled to real clients has to be caught." It is
the project's one acknowledged engineering unknown.

The full design is [`docs/design/node-capacity.md`](../design/node-capacity.md); this
record captures the decisions, the starting values and why they were chosen, and — in
Consequences — what is **not** solved.

## Decision

### 1. Declared and measured travel by opposite paths, because a self-report is trusted exactly when lying cannot benefit the reporter

This is the spine, and everything else follows from it.

**Declared limits are self-reported and trusted.** A node lying *downward* only reduces
what it is given — the operator's own uplink and ISP bill, their call, and the entire
point of #143. A node lying *upward* is **inert**, because `usable = min(declared,
measured)` and the measured term binds. The only effective direction of the claim is
self-limiting, which is precisely the condition under which a self-report needs no
verification machinery at all.

**Measured capacity is never self-reported.** Lying upward here *works* — it is the
term that would otherwise bind. So there is deliberately **no measured-capacity field
on the register wire in either direction**; it is coordinator-side state derived from
observation.

This is the rule the tree already holds: `coldstart.Entry.Operator` is coordinator-side
truth ("a Sybil operator would fabricate diversity"), and `Entry.Ingress` trusts a
self-reported *port* only because it is paired with a coordinator-*observed* IP. #143
and #144 are the same rule applied to two claims that fall on opposite sides of it.

The halves protect each other, which is why #144 depends on #143 and one PR closes
both: declared can be trusted *because* measured binds an upward lie, and measured can
afford to be conservative *because* declared already bounds it and captures the one
constraint no measurement could ever discover — no probe can read a data cap off a bill.

### 2. #143: declared limits, enforced at BOTH ends

`-max-speed` (aggregate bits/s), `-monthly-quota` (bytes/cycle), `-quota-cycle-day`,
`-quota-state`. All default to unset = unlimited, so the change is opt-in and the
existing datacenter fleet is byte-for-byte unaffected. Both the exit **and relay** roles
are limited: a relay spends its operator's uplink exactly as an exit does, and their
ISP meters it identically.

- **The coordinator stops assigning** — an exhausted node is dropped from `list`,
  refused at `connect`, and skipped by `pickRelay`. This is the *useful* half: a limit
  surfaces as "this node is not offered" rather than "your connection failed."
- **The node enforces locally** — a shared token bucket paces the data path and the
  quota cuts a transfer with `ErrQuotaExhausted`. Both the stream path (`meter`) and
  the datagram path (`meterN`, for ADR-0034's UDP relay) are covered; review caught the
  UDP path bypassing both, which had meant QUIC/HTTP3 and DNS — most traffic — sailing
  past a declared quota in silence. This is the *sound* half **for forwarded traffic**,
  which is the only scope in which it is sound: `transport_reality`'s camouflage splice
  spends the operator's line without reaching either path (design §8.7, #163), so a node
  running `-transport reality` can exceed a declared quota. The
  coordinator learns of exhaustion only on the next 10 s register; a pool has several
  coordinators expiring independently (ADR-0020); and a coordinator may be buggy,
  partitioned, or hostile (#60/#69). **The operator, not the coordinator, pays the
  overage bill**, so the guarantee is enforced by the party bearing the cost. Same shape
  as the kill switch (ADR-0014): the remote hint is a courtesy, the local enforcement is
  the invariant.

Four details that look small and are not:

- **A forwarded byte is charged twice, because the operator's link carries it twice.**
  A forwarder is a middle box: every byte arrives and then leaves, and a residential
  ISP meters both against one cap. `-monthly-quota` is the operator's ISP cap, so
  counting each byte once would let a declared 400GB spend 800GB of a real 400GB cap —
  a 100% overshoot, silently, in exactly the direction that produces the overage bill
  this card exists to prevent. (The decimal-units point below is the same failure at
  7.4%; this one went unstated at 100% until review measured it.)

  **It halves what a declaration serves, and that has to be said in the same breath:**
  the quota is a budget in *metered* bytes, so `400GB` carries roughly **200GB** of user
  traffic. An earlier draft of this bullet cited the operator-facing docs as saying
  "your ISP's data cap" while they in fact said "your ISP's data cap, **or whatever
  slice of it you choose to donate**" — quoting the half that supported the change and
  omitting the half it invalidated, while updating none of them. `cmd/node`'s
  `-monthly-quota` help, `capacity.Limits.MonthlyQuota` and `docs/RUNNING.md` all now
  state the halving explicitly, because an operator who declares the slice they mean to
  donate would otherwise donate half of it and never be told. The case
  this over-counts is a node billed for egress only, as most VPSes are, where the
  operator declares twice what they mean to donate. The asymmetry is deliberate:
  over-counting costs a node that stops early, under-counting costs a volunteer a bill
  they never agreed to, and #143 prefers under-serving every time.

- **The cycle anchors to the operator's BILLING day, not the 1st.** Residential caps
  reset on the day the customer signed up. Anchoring to the 1st would silently overshoot
  the real cap for ~27 of 28 operators — the exact overage bill this card exists to
  prevent. Range 1..28 so the anchor exists in February.
- **Quota state is persisted.** An in-memory counter makes `systemctl restart` mint a
  fresh month; without persistence the feature does not implement its own headline
  requirement. Checkpointed on whichever comes first: `limit/64` bytes (clamped to
  [64 KB, 16 MB]), 30 s, or the instant the quota is spent — that last transition being
  the one whose loss defeats the feature. A crash therefore loses at most ~1.5% of the
  declared quota at any cap size. The byte trigger scales rather than being fixed
  because a smoke test caught a fixed 16 MB trigger meaning a *small* quota was never
  checkpointed at all. A corrupt checkpoint is an error, not a silent reset; so is an
  unreadable one, for the same reason — state we cannot confirm is not a fresh month,
  and starting anyway would bill the operator silently on every restart. A
  **backwards** clock step never resets a cycle: a cycle only ever advances. That has
  to hold on *both* paths, and originally held on only one — `rollover` guarded the
  mid-process step, while `NewQuota` compared cycles for equality and discarded the
  disk on a mismatch. The no-RTC Raspberry Pi this bullet names never reaches
  `rollover`: its clock is already stale when `NewQuota` runs, so it zeroed a spent
  quota and persisted the zero, every reboot. When the disk knows a *later* cycle than
  the clock, the clock is what is wrong; trust the disk.
- **Units are decimal and operator-facing** (`20Mbit`, `400GB`), because that is how an
  ISP states them. Reading `500GB` as binary GiB would overshoot a real cap by 7.4%.

The wire carries `speedCap` and **one bit** of quota state (`ok`/`exhausted`) — not the
byte counts. Matchmaking needs only "may I assign to you", and a per-node monthly usage
curve would hand an untrusted coordinator a linkability signal about a residential
operator's household in exchange for nothing. Both fields ride **every** register,
because the handler replaces its registry entry wholesale.

### 3. #144: there is no tester. Measurement IS serving.

An active speed test fails on four independent grounds, each fatal alone:

1. **The tester is identifiable** and gets whitelisted. Rotating probers does not help:
   an admitted client can enumerate the network's own nodes with `list`.
2. **It measures the wrong path** — capacity is a property of a path, not of a node.
   Fast to a prober in Frankfurt says nothing about a client on a Moscow mobile network.
3. **A bulk flood is self-identifying** by shape, even from an anonymous source.
4. **It burns the very quota #143 exists to protect** — recurring, forever, on every
   node. This one sinks the design even against a wholly honest fleet.

`cmd/capacity-probe -demo` demonstrates (1) physically: two nodes with identical pipes,
one honest, one discriminating in ~15 lines. The probe measures both at the same speed
while one serves real users at 1/32 of it, and cannot tell them apart. (Run it for the
numbers; they are timing-dependent and deliberately not pinned here.)

Stealth is an arms race against an adversary who **owns the endpoint being measured**,
so it cannot be won. We do not enter it. Instead a node's rating is defined by **what
real clients attest it delivered to them**. Every good property follows from that one
choice: it cannot be gamed by recognising the tester (there is none, and every flow is
scored), it measures the right path (it *is* the path), it tracks reality (it *is*
reality), and it is free (those bytes had to flow anyway).

### 4. The observation: a co-signed receipt plus a saturation bit

`core/accounting`'s `Receipt` (ADR-0021) is already "N bytes over interval T",
co-signed by exit and client so neither can move it alone. `N/T` is a throughput
sample; the primitive was already in the tree.

It is missing one bit, and only the client has it: **was I demand-saturated?**
Throughput alone is ambiguous — a low sample cannot distinguish a throttled node from
an idle one. With the bit, `saturated+slow` is evidence and `unsaturated` is discarded.
Most traffic is discarded, and that is correct.

`saturated+slow` deliberately conflates throttling with congestion. We cannot tell a
malicious node from a node whose ISP is having a bad evening, and **we do not need to:
the right action is identical** — route less here. The estimator therefore never has to
attribute blame, only track delivery, which is a far weaker and far more attainable
requirement. It is also what makes "periodic re-tests track reality" fall out for free.

### 5. The estimator is a ratchet over a LOW quantile of one-vote-per-AS

Influence is collapsed twice — median per attester, then **minimum** per AS — so **one
AS is one vote** regardless of how many clients or samples an attacker runs. The AS is
the coordinator-*observed* one. The unit of Sybil cost is an AS.

The per-AS step is a minimum and not a median because a median is *capturable*: an AS
with `n` honest attesters is flipped by `n+1` sybils in that same AS, and `n` is
typically one or two. Review caught that holding a 125 Mbit rating across four honest
ASes each genuinely throttled to 2 Mbit — and falsifying the claim that honest clients
"only have to exist". With a minimum, one honest attester makes its AS vote honestly.

Then a **low** quantile (0.25), which inverts the obvious choice. A peak asks "what is
the best anyone saw?" and is owned by whoever forges the fastest sample. A low quantile
asks "what does a saturated client get at worst?" and is owned by whoever holds the
lower tail — which honest clients occupy **for free, simply by existing**. Holding a
rating requires a ~4:1 AS supermajority, and that ratio gets harder as the node
attracts honest clients.

Stated at its sharpest, the two steps together: **to inflate a rating, every attester
in ~75% of the attesting ASes must be the attacker's; to deflate one, a single attester
in ~25% of them suffices.** That gap is the design's stated preference made concrete —
over-rating hurts users now, under-rating only wastes capacity.

A saturated sample of **zero** throughput counts, and counts as the strongest evidence
of non-delivery. Review caught the first cut discarding it, which was worth ~4800× for
BLACKHOLING strangers rather than throttling them, and which made "every session is
scored" false for the one flow most worth hiding in.

Movement is a ratchet: **multiplicatively capped rise, snap-down on failure.**

> **The rise cap is a security property, not smoothing.** It converts a one-shot lie
> into a sustained, public, self-revealing one. A peak estimator is defeated
> permanently by a single forged sample; a ratchet capped at ×1.25/window needs ~11
> consecutive windows of collusion to reach 10× — and during every one of them the node
> is handed real clients at its rising rating, whose attestations snap it back in one
> window. The attacker cannot both hold a high rating and dodge the traffic it attracts.

Rise-slow/fall-fast is deliberate: over-estimation routes users onto a node that cannot
carry them and they suffer now; under-estimation only wastes capacity and self-corrects.

Ratings are **coordinator-local, never in the signed directory**. A rating is a soft,
revisable judgement from unverifiable inputs; signing it would let a hostile coordinator
mint a tamper-evident lie. Matchmaking is already the thing a coordinator is allowed to
get wrong.

### 6. Starting values, and why

Every value is conservative — each errs toward under-rating (which wastes capacity) over
over-rating (which hurts users). None is a law; this loop has never run against a real
fleet and all of them should move once there is data.

| parameter | value | why this number |
|---|---|---|
| `Window` | 60 s | matches `-acct-interval`'s default, so one receipt is exactly one sample and no re-windowing is needed |
| `Quantile` | **0.25** | the Sybil bound: an attacker needs ~75% of attesting ASes. Lower is safer but under-rates honest nodes harder; 0.25 tolerates a quarter of attesters being bad in either direction |
| `RiseFactor` | **1.25** | ~11 windows (≈11 min) to 10×. Slow enough that collusion must be sustained and public, fast enough that an honest node recovers from congestion in ~12 min (`TestCongestionTracksReality`) |
| `RiseThreshold` | 0.9 | a node delivering at exactly its rating measures slightly under it in any real sampler |
| `FallThreshold` | 0.7 | comfortably below `RiseThreshold` so ordinary jitter cannot flap the rating between rise and fall |
| `MinASes` | 2 | one AS's view of a node is one path's view — not evidence either way |
| `Ceiling` | 5 Mbit | provisional. Usable enough that a new or silent node is not useless; low enough that being wrong about one costs little |
| `CeilingASes` | 3 | the bar to be believed beyond provisional. Small, because the network is small today; this is the value most likely to need raising |
| `Floor` | 256 kbit | non-zero because the ratchet is multiplicative and never leaves zero. Small enough to be a rounding error if wrong |
| `HalfLife` | 24 h | a rating survives a quiet night but not a quiet week; also what makes collusion a recurring cost rather than a purchase |

**`Floor` is not the serve-eligibility floor.** Whether a node rated at 2 Mbit may serve
at all is **#145's** decision, and it is *policy, not a constant* — a 2 Mbit exit is
worthless in Frankfurt and precious in a region where it is the only one, and the answer
changes with how starved the network is. This ADR deliberately does not set it.

### 7. The claims are tests, not prose

The bounds above are quantitative, so each is pinned by an adversarial simulation in
`core/capacity/estimator_test.go` (design note §7.4). If one fails, the design note is
wrong, not the test. This was not ceremony: writing them found a real compounding-decay
bug that cost an idle honest node ~60% of its rating per hour — caught by the
honest-operator test, while every adversarial test passed.

## Consequences

**Good.**

- A residential volunteer can participate today: #143 is live end to end, and their
  declared cap is never exceeded **by forwarded traffic**. That qualifier is load-bearing
  and is not a formality — see Bad/open below.
- The change is inert for the existing fleet — no declared limits means no limiter, no
  quota, no wire fields, and a byte-for-byte identical data path.
- Cheapness and gaming-resistance fall out of the *same* decision (measurement is
  serving), which is the strongest available evidence that the decision is right.
- An honest node is never punished for being idle, and congestion recovery needs no
  extra mechanism.
- The client never has to trust a rating: ADR-0028's ladder already demotes an
  underperforming path on the client's own observation.

**Bad / open — stated plainly, because #144 asked for exactly this.**

- **#143's cap is not honoured by a reality node — the quota's one real hole (#163).**
  `transport_reality`'s camouflage splice (`rawSplice`/`bridge`/`holdAndDrain`,
  ADR-0027/ADR-0032) reverse-proxies unauthenticated probes to the impersonated origin,
  which is what makes the transport survive active probing and is **on by default**. Those
  bytes never reach `meter` or `meterN`, so they are uncounted and unpaced: no handshake
  is required, nothing bounds connections, and the attacker gets **2× amplification**
  (they move N, the volunteer's ISP meters 2N). A saturated 100 Mbit line spends a 400GB
  cap in ~4.4 hours. The payoff is not the bill — it is **eviction**: spend the quota and
  #143 works exactly as designed, the coordinator stops offering the node, and any reality
  node can be removed from the fleet on demand, anonymously, for half what it costs the
  volunteer. Out of #143's lane (`realityTransport` holds no quota handle) and it has a
  real design tension — cutting a splice mid-probe is itself the fingerprint ADR-0027
  exists to avoid — so it is #163, and the argument belongs in ADR-0027's terms. Until
  then the honest statement everywhere is "no *forwarded* traffic exceeds the cap"
  (design §4.2/§8.7).

  > **Update (2026-07-22, #163): closed, up to a bounded overshoot.** The splice now
  > counts every byte against the quota (both crossings for a reverse-proxy leg, one for
  > a drain) and paces it, but it is enforced at splice **admission**, not per byte: a
  > new splice is refused once the cap is spent (drained instead — the same no-instant-
  > close response ADR-0027 already uses for an unreachable origin), while an in-flight
  > one runs to completion rather than being cut mid-response (which would be the
  > fingerprint). So *never exceeded* now holds for a reality node too, up to a **bounded
  > overshoot** — whatever the in-flight splices drain before their timeout — not the
  > unbounded, silent overshoot it had before. A per-source-IP rate gate bounds concurrent
  > amplification and per-IP churn, but — corrected 2026-07-25, #168 — it does **not**
  > raise time-to-exhaust: the splice limiter is aggregate, so one splice saturates the
  > declared speed and `quota / (2 × speedCap)` holds regardless of source-IP count. A
  > single uplink can still spend the cap and get the node evicted; the eviction attack is
  > priced, not closed. The argument is in ADR-0027's terms and the shape is in ADR-0041.
- **The Sybil hole is priced, not closed** (amended 2026-07-17 — #157). A co-signed
  receipt attests *agreement, not transit*: two colluding endpoints can sign "1 Gbit for
  60 s" without moving a byte, so a forged sample costs **nothing** at the margin. An
  attacker holding a ~4:1 AS supermajority among its node's attesters can hold a rating
  it does not honour for strangers, for the price of the identities. §6.4 prices it (one
  AS one vote; ~4:1; ceiling gate; rise cap; decay makes it recurring) but cannot close
  it: the fix is the price of an attesting identity, which is #42/vouch-tier territory,
  and an unforgeable proof of transit to a stranger is an open research problem (Tor has
  fought it for fifteen years across bandwidth authorities, EigenSpeed, PeerFlow,
  FlashFlow).

  **That price is now set, and it is set TWICE — a node carries two estimates.**
  `trusted` is attested only by accounts a real person vouched for, and is the one the
  coordinator uses. `untrusted` is attested by anyone, and **may never exceed the
  provisional ceiling**.

  The split is only safe because of the bound this design already had. `Ceiling`
  (5 Mbit, `CeilingASes`=3) exists to price "decline to be measured": **silence buys the
  ceiling, never more.** Clamping `untrusted` to exactly that line means forging it — a
  few dozen VPS across distinct ASes, ~$100/month — buys *precisely what saying nothing
  already buys*. Lying stops paying, which is §1's spine applied to a range instead of a
  direction. Rising above the ceiling needs `trusted`: real people vouching, in ≥3
  distinct networks, leaving a trail §5's subtree revocation can pull.

  A single vouched-only rating was the first draft of this decision and was rejected for
  a real reason: early on almost every session is free-tier, so almost every node would
  sit at `Floor` (256 Kbit) — not "unrated" but *actively useless*. Two ratings let an
  honest free-tier-only node earn up to 5 Mbit from traffic that actually flowed, while
  buying an attacker nothing.

  **It stays in Bad/open on purpose.** The price of the *expensive* lie went up; the hole
  did not close. An attacker who *can* obtain vouched accounts across ~75% of a node's
  attesting ASes still holds a `trusted` rating they do not honour, and the load-bearing
  defense remains that **the client never has to trust either rating** (ADR-0028's ladder
  demotes an underperforming path regardless of what the coordinator believes). The
  coupling is also real: who may vouch now decides who may rate a node above 5 Mbit.

  Reasoning, the arithmetic, and the rules this imposes on the feed are in design §8.1.1.
  Unblocks #158, which must build **two estimators and never blend them** — an unvouched
  sample is not a weaker sample to down-weight; the moment one can move a number above the
  ceiling, the $100/month attack is back and the vouch requirement was decoration.
- **Deflation is cheap** — inflation needs every attester in ~75% of attesting ASes;
  deflation needs one attester in ~25% of them, and with fewer than 5 attesting ASes a
  single defaming AS owns the rating outright. Accepted: it is an availability attack on
  an honest node, not an integrity attack on the estimate, and cheap deflation is the
  price of erring toward under-rating.
- **The saturation bit is unilateral** — the exit cannot verify "I wanted more", so the
  one bit the methodology rests on is the one part of a sample nothing protects.
- **Relays cannot be measured at all** — ADR-0021's receipts are exit-only and
  direct-mode-only, so a relay produces zero samples. #144's methodology measures
  **exits**; relays get declared limits and sit at the provisional ceiling until a
  correlation id exists on the relay↔exit wire.
- **Capacity is not quality** — 100 Mbit at 500 ms and 5% loss scores perfectly.
- **The estimator is not wired into the coordinator**, on purpose: nothing feeds it yet,
  so any gate on `measured` would pin every node at `Floor` and strand the fleet. The
  registry also replaces node entries wholesale every 10 s, so rating state must live in
  its own map — a decision worth landing *with* the feed and its tests.

  > **Update (2026-07-22, #158): wired.** ADR-0041 lands the attested-sample feed (client
  > → coordinator), a `capacity.RatingStore` holding two ratings per node in its own map
  > with its own eviction, and `Usable` at the assignment surfaces — with the serve floor
  > shipped **off**, exactly because a gate on `measured` would still strand the fleet
  > while the trusted stream is unfed. The two-estimator shape #157 settled is built and
  > tested; the trusted stream stays empty until the account service stamps vouched-ness.
- **Ratings do not survive a coordinator restart.** Nodes re-earn them; acceptable given
  the ~12-window recovery, but it means a coordinator bounce costs the fleet its ratings.
- **A quota cut kills live sessions** rather than letting them drain. Deliberate: "let
  them finish" is an unbounded overshoot, and a cut client re-lands elsewhere via
  ADR-0028's ladder and #2's auto-reconnect.

**Neutral.**

- `golang.org/x/time` becomes a direct dependency (it was already in the module graph
  indirectly) for the token bucket, rather than hand-rolling one. `go mod tidy` also
  corrects `golang.org/x/sys` to direct — it is imported by `core/selection` and the
  file was simply stale.
- `capacity.Usable` is tested but has no production caller until the feed lands, and
  the coordinator records `speedCap` off every register without reading it yet, for the
  same reason.
- `Estimator.Advance` must be ticked once per `Window` by its eventual caller, whether
  or not samples arrived: it is the only thing that applies decay, and `Estimate()`
  reports the value as of the last tick without decaying. An unticked estimator holds
  its rating forever.

**On the process.** Three claims in the first draft of the design note were false in
the code, and all three were universal quantifiers with an exception in them: "the data
path" (UDP was not), "every session is scored" (zero-byte ones were not), "one AS one
vote" (the vote could be captured). Each was found by adversarial review executing the
claim rather than reading it. For a deliverable whose value is honesty about its own
limits, that is the failure mode to watch: a sentence that sounds like a summary but is
actually a claim. Design note §7.6 records them rather than quietly correcting them.

## Relationship

- **#145 [B3] serve floor** consumes `min(declared, measured)` and decides eligibility.
  Deliberately not set here: floors are policy, varying by region, role, and scarcity.
- **ADR-0021** supplies the measurement primitive; the `saturated` bit will amend it.
- **ADR-0023 / #42 admission** sets the price of an attesting identity and therefore the
  depth of the Sybil hole. **Capacity measurement is only as sound as admission is
  expensive.**
- **ADR-0028 transport pool** is the client-side safety net that makes the residual hole
  survivable: a client demotes an underperforming path on its own observation regardless
  of what the coordinator believes.
- **ADR-0033 relay selection** is where a capacity-aware pick lands. It must stay
  **filter-then-random** — sorting by rating would rebuild the deterministic winner
  `pickRelay`'s doc comment exists to prevent, and hand it to whichever relay advertised
  the most attractive number.
- **ADR-0014 kill switch** is the precedent for enforcing locally at the party that bears
  the cost.
- The **earn/payout plane** (private repo) is the eventual consumer, and the reason the
  over-promising and Sybil adversaries have a profit motive at all. Measurement must be
  settled before payout, or the payout pays for claims.

## Amendment (2026-07-30, issue #49) — declared configuration is disclosed; observed usage is not

§2 closes by saying the wire carries `speedCap` and **one bit** of quota state, "not the
byte counts". That sentence was written to refuse one specific thing and was read as
refusing a broader class, so it is worth stating the rule it was reaching for, with the
reason, rather than leaving the next person to infer it from a single example.

**The rule.** A node's DECLARED CONFIGURATION may ride the register wire. Its OBSERVED
USAGE may not.

### 1. Why the line falls there

The refusal in §2 is about a *per-node monthly usage curve* — a series showing how much
a node moved and when. That is a measurement **of a household**: when its operator is
awake, when they are on holiday, when their teenager started streaming. Against a
coordinator assumed hostile (ADR-0020, #60/#69) it is a linkability signal about a
residential operator that buys matchmaking nothing, and refusing it costs nothing,
which is why §2 refuses it and why this amendment does not disturb that.

A **declared cap** is a different kind of claim. It is a constant the operator typed
into a config file — the slice of their line they chose to donate. It says nothing
about what they did, only about what they are willing to do. An operator could publish
it on a forum without disclosing anything about their household, and nothing about it
changes as the month is spent. The identical argument already licenses `SpeedCap`,
which has ridden this wire since #143 without anyone treating it as a usage disclosure,
and `-monthly-quota` is the same sentence in a different unit.

That is the whole distinction, and it survives the obvious objection: a declared cap
plus the exhausted bit does leak *something* — roughly when a node crossed its own
line, once a cycle. That was already true from the bit alone, which §2 accepted. A
constant does not make a series.

### 2. What ships (#49)

- The register wire gains `declaredQuotaBytes`: the operator's configured
  `-monthly-quota`, in **bytes**. Read once from config, never from the live counter,
  so a usage series is off this wire by construction rather than by care.
- Both the exit and relay roles send it, for §2's reason — a relay spends its
  operator's uplink exactly as an exit does.
- The coordinator records it on the registry entry beside `speedCap` and compares it
  against the signed policy's `serve_floor.min_declared_quota_bytes` in the
  serve-eligibility gate (`servingCheck`), alongside the version fence and the
  measured-throughput floor. Those three conditions are exactly the three fields of the
  policy's `ServeFloor`, and they now live in one place.
- It is **absent-optional**: a node predating #49 sends nothing and is treated exactly
  as it is today.

**Trusted for SpeedCap's reason, and no further.** The claim only ever binds downward:
under-declaring fails the floor and lies a node out of traffic, and over-declaring buys
nothing, because the node's own quota accounting still stops it at the real cap and
reports that through the exhausted bit. There is no version of lying about this number
that wins the liar traffic to carry.

**The unit split is deliberate and is carried in the field names.** `speedCap` is a
RATE in bits/s; `declaredQuotaBytes` is a VOLUME in bytes. The two are never
interconvertible and never compared, so both names state their unit rather than relying
on a reader's memory — the same split `capacity.Rate`/`capacity.Bytes` and the policy's
own `min_measured_bps`/`min_declared_quota_bytes` already make, and for the same reason:
a number an operator transcribes off their ISP paperwork without a factor-of-8
conversion is one they cannot get wrong by a factor of 8.

### 3. The consequence that needed deciding: an absent declaration is admitted

`min_declared_quota_bytes` has been in the signed policy since #15 — parsed, validated,
and **read by nothing**, because there was no byte-valued input to compare it against.
So a policy already in the wild may set it: the project's own frozen fixture bundle
sets 100 GB. Every node predating #49 declares nothing.

Had an absent declaration been treated as a failing one, turning on this reader would
have fenced the **entire existing fleet** out of the serve pool on a single coordinator
restart, against a floor nobody knowingly enabled. That is the fleet-stranding failure
design §8.6 is written against, so absent means "as today", exactly as an absent
`speedCap` or `quotaState` does.

**The cost, stated rather than buried:** for now the floor is skippable by declaring
nothing. A node that states no commitment is admitted while one that honestly states a
small commitment is refused, which is backwards for something meant to be a Sybil-cost
lever.

**What closes it is already in the same gate.** Once `min_serving_version` is raised
past the first release that sends `declaredQuotaBytes`, "declares nothing" stops being
reachable for any node that clears the version fence. The two policy conditions compose
into a migration — raise the quota floor now, raise the version floor once the fleet has
rolled — and no step strands anyone. **No code changes when that happens**, which is the
point of recording it here rather than filing it.

### 4. What this does NOT authorise

The byte counts stay off the wire. So does anything from which a series could be
reconstructed: periodic remaining-quota reports, a percentage-consumed field, a
"bytes since last register" delta. Each of those is the usage curve §2 refused,
arriving in instalments. The exhausted **bit** remains the whole of what this
coordinator learns about consumption, and the next request for "just the byte counts"
should be read against §1 above rather than against #49 as a precedent.
