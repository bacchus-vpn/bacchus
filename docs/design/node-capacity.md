# Node capacity — declared limits and measurement

- Status: **design spike (issues #143, #144; this document + [ADR-0040](../adr/0040-node-capacity-declared-limits-and-attested-measurement.md); the attested-sample feed follows in child issues)**
- Date: 2026-07-15
- Track: control plane (R2)
- Companion decision record: [ADR-0040](../adr/0040-node-capacity-declared-limits-and-attested-measurement.md)
- Builds on: [ADR-0021](../adr/0021-co-signed-usage-receipts-stub.md) (co-signed usage
  receipts — reused here as the measurement primitive),
  [ADR-0023](../adr/0023-cryptographic-node-admission.md) (node/client admission — the
  Sybil cost floor), [ADR-0033](../adr/0033-prefer-peer-relays-over-turn-for-the-data-plane.md)
  (relay selection — where a capacity-aware pick lands),
  [ADR-0037](../adr/0037-mesh-walk-recovery-via-signed-peer-exchange.md) /
  [ADR-0038](../adr/0038-configurable-multi-hop-relay-chaining.md) (the signed directory
  and its self-report/observed-truth split).

> This is a **design spike**. Issue #144 is labelled `spike` because the measurement
> problem is the project's one acknowledged engineering unknown, and it asks for the
> *methodology* to be settled before the serve floor (#145) and assignment build on it.
> What this document fixes is the shape of the mechanism and the argument for why it
> resists gaming — **including, in §8, the hole it does not close.** §9 hands the
> remaining build to child issues.
>
> Two things are built now rather than deferred, because the methodology is not
> credible without them: the **estimator itself** (`core/capacity`), whose
> gaming-resistance claims are pinned by adversarial simulation tests rather than by
> assertion (§7.4), and a **capacity probe** ([`cmd/capacity-probe`](../../cmd/capacity-probe/README.md))
> which exists chiefly to demonstrate, physically, *why an active probe cannot be
> trusted* (§6.1). Issue #143 is not a spike and is built in full.

---

## 1. Problem statement

Two issues, one problem, which is why they share a lane.

**#143 — what a node is *willing* to serve.** A residential volunteer has an ISP
with a monthly data cap and an uplink they also use for their own life. Today Bacchus
has no way for them to say so: a node registers and the coordinator routes to it
without bound. Grepping the tree for `capacity|bandwidth|quota|throughput` returns
exactly one first-party hit — a comment at `cmd/coordinator/main.go` conceding that
"a load-aware policy (fewest live sessions) is still a follow-up." There is no speed
cap, no quota, no accounting of either. **The practical consequence is that a
residential volunteer cannot safely participate at all**, which cuts the network off
from the node population it most needs: ordinary residential IPs in and near the
censored region, which are exactly the addresses a censor cannot block wholesale.

**#144 — what a node is *able* to serve.** Willingness alone is not enough, because a
declaration is a claim. A node that declares 1 Gbit on a 10 Mbit line would be handed
traffic it cannot carry, and every client routed there suffers. So the system needs a
second number, obtained by observation rather than by assertion:

> **usable = min(declared, measured)**

With both, a node can neither be **over-used** (its declared cap binds) nor
**over-promise** (the measured cap binds). Neither number is sufficient alone, and
each one is what makes the other safe — §3 is that argument.

**Why #144 is hard.** Measurement must be *cheap* and must *resist gaming*: a node
that is fast to the tester and throttled to real clients has to be caught. That
sentence is the whole spike. §2 is the threat model, §4–§5 are the two observations
that make it tractable, §6 is the methodology, §7 is the resistance argument, and §8
is the part of the problem that remains open.

---

## 2. Threat model

The standing adversaries from [threat-model.md](threat-model.md) that this design
must answer, plus the one this design introduces.

**A2.1 — The over-promising operator.** Runs a node, declares or demonstrates more
capacity than it has. Motive is not always fraud: it is often just an operator who
does not know their own upload speed. But the malicious form matters, because in the
eventual earn/payout model (private repo, `§5 vouch trust-tiers`) capacity is
compensated, and because **traffic concentration is itself an attack** — a
censor-run node that attracts a disproportionate share of sessions gets a
disproportionate view of who is connecting, even though the payload stays opaque
(ADR-0009). Attracting traffic cheaply is a goal worth paying for.

**A2.2 — The discriminating operator (the one #144 names).** Serves the measurement
fast and real clients slow. This is A2.1 with a detection-evasion strategy, and it is
the adversary that kills every naive design in §6.1.

**A2.3 — The Sybil operator.** Runs both a node *and* the clients that attest to it.
Admission credentials (#42/ADR-0023) put a price on identities but do not make them
unforgeable-in-quantity; the price is set outside this lane. This is the adversary
that §8.1 does not defeat.

**A2.4 — The defaming client.** Reports a healthy node as slow, to push traffic away
from it (towards nodes the attacker prefers, or simply to degrade the network).
Symmetric to A2.3 and cheaper.

**A2.5 — The hostile coordinator.** The standing assumption (ADR-0020, #60/#69): the
coordinator is not trusted with client safety, only with matchmaking. Capacity is
matchmaking, so a hostile coordinator can already mis-assign traffic and this design
does not change that. It must, however, not *add* a way for the coordinator to prove
false statements to a client — which is why measured capacity stays out of the signed
directory (§6.5).

Out of scope: a network adversary between node and client. TSPU-style throttling of a
node's uplink is indistinguishable — deliberately, see §5.3 — from the node throttling
itself, and the correct response is identical.

---

## 3. The trust asymmetry (the spine of the design)

The two numbers have **opposite trust properties**, and everything else follows from
noticing that.

**Declared is safe to self-report.** A node says "cap me at 20 Mbit, stop at 400 GB
this month." Can it profit by lying?

- *Lying downward* (declaring less than it has) only reduces what it is given. That
  is not an attack; it is the operator exercising the right the card exists to grant.
  Their uplink, their ISP bill.
- *Lying upward* (declaring 1 Gbit on a 10 Mbit line) is **inert**, because
  `usable = min(declared, measured)` and the measured term binds. The lie buys
  nothing.

So a declared limit is a claim whose only *effective* direction is self-limiting.
That is precisely the condition under which a self-report can be trusted, and it
means declared limits can ride the register wire as-is, with no verification
machinery at all.

**Measured is unsafe to self-report.** A node says "I benchmarked at 500 Mbit." Lying
upward *works*: it directly increases assignment. There is no `min()` on the other
side to bind it — it *is* the other side. A self-reported measurement is not a
measurement; it is a wish.

This mirrors the posture the repo already holds, and holds explicitly. From
`core/coldstart/snapshot.go`, on why the operator tag is coordinator-side truth:

> The coordinator sets this from its own operator registry, never from a node's
> self-report … a Sybil operator would fabricate diversity in a signed tag.

and on `Entry.Ingress`, which trusts a self-reported *port* but pairs it with the
coordinator-*observed* IP, "so a relay cannot claim an ingress in an AS it does not
occupy." The rule underneath both, stated generally:

> **A self-report is trusted exactly when lying cannot benefit the reporter.**

Declared passes. Measured fails. Therefore:

| | #143 declared | #144 measured |
|---|---|---|
| Travels on | the register wire, self-reported | **never the wire** — coordinator-side state |
| Trusted because | lying is self-limiting or inert | *not* trusted; derived from observation |
| Enforced by | the node itself (§4.4), coordinator stops assigning | the coordinator's estimator (§6) |
| Bounded above by | nothing — it is the operator's choice | `declared`, and the provisional ceiling |

**The two halves protect each other.** Declared can be trusted *because* measured
binds an upward lie; measured can afford to be conservative and slow-moving
*because* declared already bounds it from the other side and captures the operator's
real constraint (which no measurement could ever discover — no probe can detect an
ISP contract). Neither works alone. This is why #144 `Depends on: B1`, and why one PR
closes both.

---

## 4. #143 — declared limits

The straightforward half. Recorded here because §6 leans on it.

### 4.1 What is declared

- **Speed cap** — bits/second the node is willing to carry, aggregate across all its
  sessions. Parsed from human units (`20Mbit`, `1.5Gbit`), because the operator's ISP
  states it in those units and a config in bits/s invites a factor-of-eight mistake.
- **Monthly quota** — bytes/cycle (`400GB`), the operator's own ISP data cap. Counted
  as the ISP counts it: **a forwarded byte costs two**, because a forwarder is a middle
  box and every byte it handles both arrives and leaves. A residential cap meters both
  directions against one number, so charging once would let a declared 400GB spend
  800GB of a real 400GB cap — the overage bill this card exists to prevent, at 100%,
  silently. See `capacity.LinkCrossings`. The node this over-charges is one billed for
  egress only, as most VPSes are; there the operator declares twice what they mean to
  give. That asymmetry is chosen: over-charging costs a node that stops early,
  under-charging costs a volunteer money they never agreed to spend.
- **Cycle anchor** — the day of month the quota resets. **Not the 1st.** Residential
  ISP caps reset on the *billing* day, which is when the customer signed up. Anchoring
  to the 1st would silently overshoot the real cap for ~29 of 30 possible customers,
  which is the exact failure #143 exists to prevent. A one-field detail that decides
  whether the feature is usable by its target population. A cycle **only ever
  advances**, on both paths that can move it: `rollover` ignores a backwards step
  mid-process, and `NewQuota` trusts the disk over a boot clock that reads earlier than
  the checkpoint it just loaded (a Pi with no RTC boots stale, and `NewQuota` runs
  before NTP lands — §7.6).

All three default to unset = unlimited, so a datacenter node (the current fleet) is
byte-for-byte unaffected and the feature is opt-in.

### 4.2 Where it is enforced — both ends, and why both

The card says the coordinator "routes until the quota is hit, then stops assigning."
That is necessary but **not sufficient for the word *never***:

> **Scope of *never*, stated before the argument that earns it.** What follows holds
> for every byte this node **forwards**. It does **not** hold for the reality
> transport's camouflage splice, which spends the operator's line without passing
> through the meter at all — **§8.7**, and the one place a declared quota can still be
> exceeded today. Read every *never* in this section as *no forwarded traffic*.

- The **coordinator stops assigning** — drops the node from `list` and makes it
  unpickable in `pickRelay`. This is the *useful* half: it prevents clients being
  matched to a node that will refuse them, so the quota shows up as "this node is not
  offered," not as "this node fails your connection."
- The **node enforces locally** — a token-bucket rate limiter on the data plane and a
  hard stop when the quota is exhausted. This is the *sound* half. The coordinator
  learns of quota exhaustion only on the next 10s register; a pool has several
  coordinators (ADR-0020) that expire independently; a coordinator may be buggy,
  partitioned, or hostile (A2.5). **The operator, not the coordinator, pays the
  overage bill**, so the guarantee has to be enforced by the party that bears the
  cost. The coordinator's stop-assigning is an optimisation; the node's local stop is
  the guarantee.

This is the same shape as the kill switch (ADR-0014): the party that suffers the
failure enforces the invariant locally, and the remote hint is a courtesy.

### 4.3 Quota state must be persistent

An in-memory counter resets on restart, and "never exceeded" would then be defeated
by `systemctl restart`. Quota is checkpointed to disk (`-quota-state`), so a crash
loop cannot mint fresh quota. Persistence is not a nicety here; without it the
feature does not implement its own headline requirement.

### 4.4 On the wire

Two additive, `omitempty` fields on `register`, matching the `IngressPort` precedent
(#124) exactly — including the requirement that they ride **every** register, since
the coordinator's handler replaces the registry struct wholesale every 10s:

- `speedCap` — declared bits/s (0 = unlimited).
- `quotaState` — `"ok"` or `"exhausted"`. **Not the byte counts.** A node's remaining
  quota is a private operational fact about its owner's household; the coordinator
  needs exactly one bit — *may I assign to you* — and giving it a byte-accurate
  monthly usage curve per residential node is a linkability gift to a hostile
  coordinator (A2.5) for no matchmaking benefit. Minimum disclosure, not because it
  is cheap, but because the extra disclosure buys nothing.

---

## 5. #144 — what can actually be observed

Before proposing a methodology, two facts constrain every possible one.

### 5.1 The coordinator cannot see bytes. Only the client and the exit can.

By deliberate design: the client↔exit channel is end-to-end Noise (ADR-0009), and a
relay is a blind ciphertext splice (ADR-0033). The coordinator sees registers,
connects, and sessions — **no data plane at all**. So the coordinator can never
measure anything directly, and any capacity number it holds is necessarily *reported*
by someone. The question is only *whom* to believe, and §3 already answered that a
node reporting on itself is not it.

Three candidate reporters:

| Reporter | Incentive | Alone, can it lie? |
|---|---|---|
| the node | wants a high rating | yes, freely — this is §3's "wish" |
| the client | suffers from a slow node — **correct incentive** | yes: unilateral, so defamable (A2.4) |
| **client + exit, co-signed** | must agree | **no** — neither alone can move the number |

### 5.2 ADR-0021's receipt is already the primitive

`core/accounting` exists, from #20, and produces exactly this:

```go
type Receipt struct {
    SessionID   string
    Seq         uint64
    IntervalSec uint32   // T
    Bytes       uint64   // N
    ExitID      string
    ExitSig     []byte   // exit proposes
    ClientSig   []byte   // client co-signs
    // ...
}
```

The exit proposes "N bytes over T seconds", the client checks it against its own
count and co-signs; `Reconcile` requires an exact match, so a disagreement yields no
receipt rather than a wrong one. It was built for accounting. But **N/T is
throughput**, and the co-signature makes it a throughput sample that required the
consent of two parties. The measurement primitive was already in the tree; #144 does
not need to invent one, it needs to notice this one and add one bit to it (§5.3).

What a co-signature does and does not prove is exactly §8.1, and is worth stating
early: it proves **agreement between two keys**. It does not prove **service to a
stranger**.

### 5.3 The ambiguity at the heart of it

Observed throughput is not capacity. It is:

```
observed = min(capacity, willingness, client demand, path bottleneck elsewhere)
```

From bytes alone:

- A **low** sample is **ambiguous**. Throttled? Or the client just didn't ask for
  more? A node serving two hundred idle mail clients is indistinguishable from a node
  strangling two hundred desperate ones. Identical byte counts.
- A **high** sample is **unambiguous**. If the bytes really transited, the node
  demonstrably *can* do at least that. Capacity is a lower bound you can only prove by
  exceeding it.

This kills both obvious estimators at once, and the trap is that each looks
reasonable until you notice the other:

- **Mean or median throughput** is confounded by demand. It measures how busy a
  node's users were, not what the node can do. Honest idle nodes look broken.
- **Peak throughput** dodges the demand confound — a maximum is exactly "the most
  this node has been seen to do". But it is a maximum *over attacker-influenceable
  samples*, so one forged high sample moves it arbitrarily far, permanently. It is
  precisely the estimator A2.3 would choose for us.

So we need one bit that bytes do not carry, and **only the client has it**: *was I
demand-saturated?* Did I have more to send or receive than the link delivered,
continuously, for this interval? A client draining a 2 GB download at 1 Mbit **knows**
it wanted more. A client checking mail knows it didn't. With that bit:

| | fast | slow (including **zero**) |
|---|---|---|
| **saturated** | capacity evidence → may raise | **not delivering** → lower |
| **unsaturated** | no information → **discard** | no information → **discard** |

"Including zero" is doing real work in that header. A saturated sample of *zero*
throughput is not a missing measurement — it is a client that wanted bytes and got
none, i.e. the strongest evidence available that a node is not delivering. The first
cut of the estimator dropped zero-throughput samples as meaningless, which handed a
node a **~4800× advantage for BLACKHOLING strangers rather than throttling them**:
blackholed clients produced no samples at all, so the votes were the colluders' alone.
Serving nothing must never score better than serving almost nothing
(`TestBlackholedClientsCountAgainstTheNode`).

Three consequences worth being explicit about:

1. **Most samples are discarded, and that is correct.** Most real traffic is
   unsaturated and simply carries no capacity information. Discarding it is not lost
   signal; it is refusing to read signal into noise. It is also most of why this is
   cheap (§7.5).
2. **`saturated + slow` conflates throttling with congestion — deliberately.** We
   cannot tell a malicious node from a node whose ISP is having a bad evening, and we
   do not need to: **the correct action is identical.** Stop routing here. The
   estimator never needs to attribute blame, only to track delivery, which is a much
   weaker and much more attainable requirement. Note this is also what makes the
   "periodic re-tests track reality (congestion; an operator who started gaming at
   home)" requirement fall out for free — both are just the rating following
   observation.
3. **The saturation bit is client-asserted and the exit cannot verify it** — it is the
   one part of a receipt that is not co-signed in any meaningful sense. That is a real
   weakness, and it is §8.2.

And it resolves the peak-vs-mean trap, in the direction that is not obvious. Once
samples are filtered to *saturated only*, the demand confound is gone — so a **low**
sample is no longer ambiguous, it is evidence ("this node did not deliver to a client
that wanted more"). We are therefore free to select a **low quantile**, and that
choice is what makes §6.4's Sybil bound possible: a peak is owned by whoever forges
the fastest sample, whereas a low quantile is owned by whoever holds the whole *lower
tail* — which honest clients occupy for free, simply by existing. **The conservative
statistic and the attack-resistant statistic turn out to be the same one.** §6.3.

---

## 6. Methodology

### 6.1 First, what is rejected: there is no tester

The instinctive design is a prober — the coordinator, or a dedicated fleet — that
speed-tests each node periodically. **It fails, and it fails four independent times.**
Each of these alone is fatal; listing all four matters, because the first is the one
people try to patch and the other three survive the patch:

1. **The tester is identifiable, and identity is enough.** A prober has an address.
   The node whitelists it (A2.2). Rotating the prober fleet does not help: an admitted
   client can call `list` and *enumerate the network's own address space*, and any
   prober that is not a Bacchus node still has to come from somewhere, in bulk, on a
   schedule. Being fast to a known address is cheap; being fast to everyone is the
   thing we actually want to buy.
2. **It measures the wrong path.** Capacity is not a scalar property of a node — it is
   a property of a *path*. Fast to a prober in Frankfurt says nothing about a client
   on a Moscow mobile network, which is the path we care about and the one no prober
   occupies.
3. **The traffic is shaped differently.** A speed test is a bulk unidirectional flood
   of a fixed duration. Real sessions are not. Even from a perfectly anonymous source,
   a flood is recognisable *as a flood* — so "hide the tester" does not help; the test
   is self-identifying by its shape.
4. **It burns the very quota #143 exists to protect.** The periodic re-test is
   recurring cost on both ends, forever. Spending a residential volunteer's 400 GB cap
   on proving to us that they have a 400 GB cap is self-defeating: the naive design
   consumes the resource it is measuring. This one is not a security argument at all,
   and it is the one that would sink the design even against a wholly honest fleet.

The conclusion is stronger than "make the tester stealthy." **Any distinguishable
measurement event is a gameable one**, and stealth is an arms race against an
adversary who owns the endpoint being measured and can therefore always win it. So do
not enter the race. **There is no tester.** Instead:

> **Measurement *is* serving.** The node's rating is defined by what it delivers to
> real clients, under real load, on real paths. There is no separate thing to be fast
> at.

Every good property below is a corollary of that one sentence: it is un-gameable
because there is nothing to detect, it measures the right path because it *is* the
path, it tracks reality because it *is* reality, and it is free because those bytes
had to flow anyway.

### 6.2 The observation

A capacity sample is a **co-signed receipt (ADR-0021) plus a client-asserted
saturation bit**:

```
Sample{ throughput: N/T, saturated: bool, attester: clientKey, attesterAS: <coordinator-observed> }
```

- `throughput` — from the receipt. Neither party can move it alone (§5.2).
- `saturated` — client-asserted (§5.3, weakness in §8.2). Requires one additive field
  on `Receipt` → an ADR-0021 amendment, tracked as a child issue (§9).
- `attester` — the client's accounting key. Identifies *who* attested, so a single
  attester's contribution can be capped (§6.4).
- `attesterAS` — derived from the client's **coordinator-observed** source address at
  connect, never a self-report. This follows `Entry.Ingress`'s rule exactly: the
  coordinator cannot see a TCP listener but it *can* see a source IP, so the parts it
  can observe are the parts it trusts.

Samples reach the coordinator from the **client**, not the node. The client has the
correct incentive (§5.1) and, critically, a node cannot *suppress* a bad sample it
does not carry. A node can still refuse to propose receipts at all — that is
§8.3.

### 6.3 The estimator: a ratchet, not a peak

The estimate is **not "the fastest we ever saw."** It is:

> *the load level at which this node has repeatedly been observed to deliver.*

And what it estimates is deliberately **the rate a saturated session gets from this
node** — not the node's aggregate capacity. That is a load-aware choice, and it is the
same trick as §5.3's: a node with eight busy clients legitimately gives each less, and
a node that is throttling gives each less, and *the right action is identical* (route
less here). Aggregate willingness is the declared cap's job (§4), enforced by the
node. So the estimator never has to distinguish busy from malicious, which is a far
weaker requirement than it first appears to need.

Per scoring window, over the saturated samples only (`core/capacity.Estimator.Advance`):

```
votes    := one value per AS   (§6.4: median per attester, then median per AS)
observed := quantile(votes, 0.25)          // LOW, not high — §6.4

if observed >= rise_threshold * estimate:      // meeting its current rating
    estimate = min(estimate * rise_factor,     // ratchet up, slowly
                   ceiling)
else if observed < fall_threshold * estimate:  // failing to deliver
    estimate = max(observed, floor)            // snap down to reality
```

(`declared` is not a term here: the estimator is a pure function of observation, and
`min(declared, measured)` is applied by the consumer — `capacity.Usable`. Keeping the
declaration out of the measurement is what stops the two from quietly justifying each
other.)

Plus decay: an estimate with no saturated attestation for a half-life drifts back
down. A rating is a statement about the recent past, and it has to expire, or a node
that was fast in March holds a rating in July.

**Why a ratchet rather than simply taking the observed peak?** This is the crux of the
gaming resistance, and it is worth being precise, because "use a peak" is the obvious
move and it is wrong for a non-obvious reason.

A peak estimator can be moved arbitrarily far by **one** good sample. If an attacker
can manufacture one sample (§8.1 says they can), a peak estimator is defeated in one
shot, permanently, for the price of a single forged interval.

A ratchet capped at `×rise_factor` per window cannot be moved more than
`rise_factor` per window **no matter what samples arrive**. Reaching 10× takes
`log(10)/log(1.25) ≈ 11` consecutive windows of sustained collusion. And here is the
part that matters: **during every one of those windows, the node is being assigned
real clients at its rising rating** — and those real clients generate their own
saturated samples, which snap it straight back down (fast, asymmetrically). The
attacker cannot both hold a high rating and avoid serving the traffic that rating
attracts.

> **The ratchet converts a one-shot lie into a sustained, expensive, self-revealing
> one.** A liar must keep lying, in public, forever, while the truth accumulates
> against it — and the moment it stops paying, decay takes the rating back.

The rate limit is therefore **a security property, not smoothing.** That is the single
most important design decision in this document, and the one most likely to be
"optimised" away later by someone who reads it as a filter. It is not a filter.

**Rise slow, fall fast** is deliberate asymmetry. The two errors are not symmetric:
over-estimation routes clients to a node that cannot carry them (users suffer,
immediately); under-estimation merely wastes capacity (nobody suffers, and it
self-corrects on the next saturated window). Conservative in the direction that hurts.

### 6.4 One AS, one vote — and why the quantile is low

A quantile over *raw samples* is trivially stuffed: submit ten thousand samples from
one colluding client and every percentile is yours. So influence is collapsed twice
before anything is measured:

1. **per attester** → the median of its samples. One client is one number, whether it
   submitted one sample or ten thousand.
2. **per AS** → the **minimum** over that AS's attesters. **One AS, one vote**, whether
   the attacker rented one VPS in it or a hundred. The AS is the coordinator-*observed*
   one (§6.2), so this cap cannot be evaded by claiming otherwise.

The unit of Sybil cost is therefore **an AS** — not a sample, not a client.

Step 2 is a **minimum and not a median**, and the difference is the whole point of the
step. A median is *capturable*: an AS with `n` honest attesters is flipped by `n+1`
sybils **in that same AS**, and `n` is typically one or two — so a handful of
residential-proxy addresses takes an AS the attacker never had to occupy. That was a
real bug in the first cut of this design, worth a 125 Mbit rating across four honest
ASes each genuinely throttled to 2 Mbit, and it silently falsified this section's own
headline claim. With a minimum, one honest throttled attester makes its AS vote
honestly no matter how many sybils crowd in beside it. Pinned by
`TestSybilCannotCaptureAnHonestAS`.

Then take a **low** quantile (0.25) over those votes. This is the single most
important parameter in the design, and it inverts the obvious choice for a reason
worth stating precisely.

A **high** quantile or a peak asks "what is the best anyone saw?", which is a question
the attacker answers by forging one fast sample. A **low** quantile asks "what does a
saturated client typically get *at worst*?" — and to hold an estimate `E`, the
attacker must make a fraction `(1 − 0.25)` of **all attesting ASes** report `≥ E`.

The consequence is the good one:

> **Honest clients do not have to out-shout the attacker. They only have to exist.**
> Each honest AS that is throttled adds a value to the lower tail, and the quantile
> reads from the lower tail. The attacker must *displace* them, not merely outnumber
> them by a little.

Concretely, with the estimate at rank `floor(0.25·(n−1))` and honest ASes occupying
the lowest ranks, the attacker wins only when it outnumbers honest attesting ASes
roughly **4:1** — and that ratio must be sustained as the node attracts more honest
clients. `TestASSupermajorityRequiredToHoldRating` walks the exact boundary
(1 honest vs 3 sybil ASes: honest wins; 1 vs 4: attacker wins; 2 vs 6: honest wins;
2 vs 7: attacker wins).

Combining the two steps gives the bound in its sharpest form:

> **To inflate a rating, EVERY attester in ~75% of the attesting ASes must be the
> attacker's** (one honest attester anywhere in an AS is enough to make it vote
> honestly). **To deflate one, ONE attester in ~25% of them suffices.**

That asymmetry is not an accident to be corrected — it is the design's stated
preference, made concrete. The expensive direction is over-rating, which hurts users
now; the cheap direction is under-rating, which only wastes capacity. §8.2 is the
honest accounting of what the cheap direction costs us.

The price of the conservative choice is real and accepted: a node with a few genuinely
bad clients is under-rated. That errs toward under-use, which wastes capacity, rather
than toward over-use, which hurts users.

Finally, the **provisional ceiling**: an estimate may not exceed it until `k` distinct
ASes have attested in a window. That answers cold start (§8.3) and prices silence.

None of this *closes* §8.1. All of it converts "free" into "priced," which is the most
this layer can honestly do; the price itself is set by admission (#42), not here.

### 6.5 Where the number lives, and where it must not

`measured` is **coordinator-local state, not directory content.** It is:

- held per-node beside `lastSeen`, under the same mutex;
- applied at the two assignment surfaces — `list` (exit enumeration) and `pickRelay`;
- **never** placed in the signed `coldstart.Snapshot`.

That last point is deliberate and follows the snapshot's own reasoning. The signed
directory is what a client trusts *when it cannot reach a coordinator* and is the
artifact a hostile coordinator (A2.5) would most like to make authoritative claims in.
A capacity rating is a *soft, local, revisable* judgement derived from unverifiable
inputs; signing it would let a hostile coordinator mint a tamper-evident lie and hand
it to a client with no way to check. Ratings are matchmaking hints, and matchmaking is
already the thing the coordinator is allowed to get wrong.

**Also: this is not the serve floor.** Whether a node is *eligible* to serve at a given
rating is #145's decision, and it is **policy, not a constant** — it varies by region
(a 2 Mbit exit is worthless in Frankfurt and precious in a region where it is the only
one), by role, and by how starved the network currently is. This lane deliberately does
not set it, and the floors it does carry (`provisional ceiling`, `floor`) are estimator
mechanics, not eligibility.

---

## 7. Gaming-resistance argument

The claim to defend, from #144 verbatim: *"a node that is fast to the tester and
throttled to real clients has to be caught."*

### 7.1 The attack does not exist in this design

The attack requires a **tester** to be fast to, and a **non-tester** to be slow to. It
presupposes that the node can partition its flows into "scored" and "unscored."

Here **every session is scored, by construction** — the score *is* the co-signed
record of what was delivered. There is no unscored flow to hide in, because there is no
scored flow to detect. The node cannot be "fast to the tester" because there is no
tester; it can only be fast, or not.

That "every" has to be *literally* true or the argument collapses, and it very nearly
was not: dropping zero-throughput samples would have left exactly one unscored flow —
the blackholed one — and it would have been the most attractive one to hide in (§5.3).
An argument that rests on a universal quantifier is only as good as the code's
willingness to honour it, which is why that case is now pinned by a test rather than
by this paragraph.

So the strategy "look fast, be slow" has no referent: **the looking is the being.**
Consider what a node maximising its rating must do: deliver high throughput to
saturated clients, repeatedly, across distinct attesters and ASes, sustained over many
windows, or the ratchet decays it. That is not an approximation of running a good exit
node. **It is the definition of one.** The attack collapses into honest behaviour —
which is the only kind of gaming resistance that survives contact with an adversary
who owns the thing being measured.

### 7.2 Each adversary, against the mechanism

**A2.1 over-promising** — dead by `min(declared, measured)` and §3. Declaring 1 Gbit on
a 10 Mbit line yields a 10 Mbit rating, because the measured term is not a declaration.

**A2.2 discriminating** — dead by §7.1, *provided* the node cannot identify which
clients are attesting. Every client attests, so it cannot. Note what the node *can*
still identify: its own Sybils. That is the escape hatch, and it is §8.1 — this
argument does not survive it, and I am not claiming it does.

**A2.4 defaming client** — bounded, but **cheaper than A2.3, and that is a direct
consequence of the low quantile rather than an oversight**. See §8.2: the same
statistic that makes inflation need ~75% of ASes makes deflation need only ~25%. It
remains an *availability* attack on an honest node rather than an *integrity* attack
on the estimate — it can only ever lower a rating — and lowering is the direction the
design deliberately makes cheap, because over-rating hurts users now while under-rating
only wastes capacity.

**A2.5 hostile coordinator** — unchanged. It could already mis-assign; ratings do not
give it a new capability, and §6.5 keeps ratings out of the signed artifact so it
cannot mint a *provable* lie.

**A2.3 Sybil** — **not defeated.** §8.1.

### 7.3 Why the honest-node story still works

A gaming-resistant metric that punishes honest nodes is not a solution. Check the
mechanism against the volunteer it exists to serve:

- Their node is mostly unsaturated → most samples discarded → **rating unaffected by
  being idle.** An unused node is not a slow node, and the estimator does not confuse
  them.
- When a real client does saturate it, that window ratchets it up.
- Their evening congestion → `saturated + slow` → rating drops → less traffic while
  the family is streaming → recovers overnight. **This is the feature working**, and it
  is exactly the "track reality" requirement, achieved with no extra mechanism.
- They never have to run a benchmark, and no probe eats their quota.

### 7.4 The argument is tested, not asserted

Every claim above is quantitative, so each is pinned by an adversarial simulation in
`core/capacity/estimator_test.go` rather than by prose. If one of those tests fails,
**this document is wrong, not the test**:

| test | claim it pins |
|---|---|
| `TestRatchetBoundsSybilGain` | an attacker forging *every* sample cannot exceed `floor·rise_factor^windows`; and 10× costs 11 windows, not 1 |
| `TestASSupermajorityRequiredToHoldRating` | the ~4:1 AS bound, walked at its exact boundary (1v3 honest wins, 1v4 attacker wins, 2v6 honest, 2v7 attacker) |
| `TestSybilCannotCaptureAnHonestAS` | sybils outnumbering an AS's honest attesters cannot take its vote (§6.4's per-AS minimum) |
| `TestBlackholedClientsCountAgainstTheNode` | serving **nothing** never scores better than serving almost nothing (§5.3) |
| `TestASStuffingBuysNothing` | 100 attesters in one AS weigh exactly as much as one |
| `TestVolumeStuffingBuysNothing` | 10 000 samples from one attester weigh exactly as much as one |
| `TestHonestClientsSnapBackInflatedRating` | the asymmetry, measured: **27 windows to inflate, 1 window to collapse** — both pinned exactly |
| `TestUnsaturatedSamplesAreIgnored` / `TestIdleNodeKeepsItsRating` | an idle node is not a slow node |
| `TestCongestionTracksReality` | congestion drops the rating and recovery re-earns it in exactly 12 windows |
| `TestProvisionalCeilingHoldsUntilEnoughASes` | 100 windows of narrow attestation buys the ceiling and not one bit more |
| `TestSeedIsClampedToTheCeiling` | an untrusted probe result cannot buy a rating |
| `TestDecayExpiresStaleRating` / `TestDecayIsIndependentOfAdvanceFrequency` | a rating that stops being re-earned goes away, at a rate set by elapsed silence and not by the caller's tick rate |

A design note that argues a bound and a test that measures it are different artifacts,
and the second is the one that survives someone refactoring the first.

**This was not ceremony.** Writing the simulations found a real bug in the first cut:
decay was applied by scaling the *current* estimate by
`0.5^(elapsed-since-last-informative-window)` on every idle window, which compounds to
`0.5^(Σ elapsed)` — quadratic, not exponential. An idle node lost ~60% of its rating in
one hour against a 24-hour half-life, and the loss depended on how often anyone called
`Advance`, which is not a property a rating may have.

Note **which** test caught it: the honest-operator one (`TestIdleNodeKeepsItsRating`).
Every adversarial test passed, because over-decaying a node looks like caution. It
would have quietly driven off the residential volunteers this whole lane exists to
recruit. Pinned now by `TestDecayIsIndependentOfAdvanceFrequency`.

### 7.6 What review found, and the pattern it exposed

Three claims in an earlier draft of *this document* were false in the code, and they
are recorded here rather than quietly corrected, because the pattern is the useful
part:

| the document said | the code did | now |
|---|---|---|
| "**the data path** is metered" (§4.2) | UDP bypassed the quota *and* the cap entirely — so QUIC/HTTP3, DNS and torrents, i.e. most traffic, sailed past a declared quota in silence | `meterN` on the datagram path; `TestUDPRelayIsMetered` |
| "**every session is scored**" (§7.1) | zero-throughput samples were dropped, so blackholing beat throttling ~4800× | zeroes are kept (§5.3); `TestBlackholedClientsCountAgainstTheNode` |
| "**one AS, one vote**" (§6.4) | the vote was a median, so 2 sybils captured an honest AS — "honest clients only have to exist" was false | per-AS minimum; `TestSybilCannotCaptureAnHonestAS` |

**Every one is a universal quantifier that was not universal.** "The data path" had an
exception, "every session" had an exception, "one vote" did not say *whose*. Each
sounded like a summary and was actually a claim — and a claim with an exception in it
is how a design note becomes a lie without anyone lying.

For a deliverable whose whole value is honesty about what it does not solve, that is
the failure mode to watch for. The practical lesson: when this document says *every*,
*all*, or *the*, there should be a test named after the sentence. The table in §7.4 is
that, and §8 is what is left once the quantifiers are made true.

#### A second round found three more, and the first one is the interesting one

| the document said | the code did | now |
|---|---|---|
| "**the data path** is metered" (§4.2) — *again* | the probe echo (`handleProbeStream`) bypassed the quota *and* the cap: 1 MB per stream, unbounded streams per session, free to anyone who can complete a handshake | `e.meter` on the echo; `TestProbeEchoIsMetered` |
| "a cycle **only ever advances**" (§4.1) | true in `rollover`, false in `NewQuota`, which compared cycles for *equality* and discarded the disk on a mismatch — so the no-RTC Pi this document names by name zeroed a spent quota at boot and persisted the zero, every reboot | `NewQuota` trusts the later cycle; `TestStaleClockAtBootDoesNotResetTheQuota` |
| "**your ISP's data cap**" (§4.1, and the flag help) | the quota counted each forwarded byte once; the operator's link carries it twice, so a declared 400GB spent 800GB of a real 400GB cap | `capacity.LinkCrossings`; `TestQuotaMeterChargesBothLinkCrossings` |

**The first row is the lesson, not the bug.** The round above audited `exitTerminate`'s
early returns, found the UDP one, fixed it — and left the branch immediately beside it
untouched. The audit was of a *sentence*, and it stopped when it found *an* exception
instead of enumerating *the* exceptions. So the rule now has its carve-outs **enumerated** in
the code (see `meter`'s doc: `handleAcctStream`, `exitHandshake`, and — the one that
matters — the reality splice of §8.7), because a rule whose exceptions are written down
can be checked, and a rule that merely sounds true cannot. Note the enumeration started
at one and is now at three: each round of review found another. Treat "all of them" here
as "all of them we have found", which is the only version that has survived contact.

The second row is the same shape one level up: the guard existed, was correct, was
well-documented, and described a scenario **it could not reach**. `rollover` cannot
see a clock that was already wrong before the process started. A comment naming a
failure is not a test covering it.

The third row is worth weighing against §4.1's care over decimal-vs-binary units: that
paragraph exists to avoid a 7.4% overshoot, and sat above a 100% one for the whole
first draft. Nobody had to be careless — the byte really was metered exactly once, and
"exactly once" was simply the wrong number.

### 7.5 Cheapness

The requirement was "cheap," and the answer is stronger than cheap:

> **In steady state there is no measurement traffic at all.** The mechanism counts
> bytes that were already flowing, for traffic that had to be served anyway.

The only new cost is one sample report per session per window (a few hundred bytes/
minute/session, riding the existing accounting receipt path), and the one-off install
probe (§6.1's rejection means it is a *seed*, not a recurring test). Compare with the
periodic active re-test the naive design needs, forever, on every node, in both
directions.

**Cheapness and gaming-resistance here have the same root cause** — measurement is
serving — which is the strongest evidence available that the design's core choice is
the right one. Designs where the security property and the efficiency property fall out
of a single decision are usually correct; designs where they trade off usually mean the
decision has not been found yet.

---

## 8. What this does NOT solve (honest limits)

Issue #144 asked for the residual to be stated plainly if it could not be closed. It
cannot. This section is the deliverable, not an appendix.

### 8.1 **The Sybil hole — the real one, and it is open**

**The attack.** An operator runs a node *and* the clients that attest to it. Its
clients are admitted (it paid for credentials) and sit in diverse ASes (it rented
VPS). They "saturate" the node and co-sign fast receipts. The receipts are
**cryptographically perfect** — genuinely co-signed, genuinely reconciled, genuinely
valid. The node holds a high rating and throttles every stranger.

**Why co-signing does not help.** It proves *two keys agreed*. Both keys are the
attacker's. The primitive is doing exactly what it was designed to do — stop
*unilateral* inflation (§5.2) — and this attack simply is not unilateral.

**And it is worse than it first looks, which is the part worth being exact about.** A
co-signed receipt attests **agreement, not transit**. Two colluding endpoints can sign
"1 Gbit for 60 s" *without moving a single byte*. So the attacker does **not** pay for
bandwidth, does not need the pipe it claims, and does not even need to own a fast
line. The marginal cost of a forged sample is **zero**; the only real cost is
acquiring the identities in the first place.

An earlier draft of this note claimed the bytes must be real and therefore that the
attacker "genuinely has the pipe". **That was wrong**, and the error mattered: it
inflates the apparent cost floor by pricing in bandwidth the attacker never buys. It
is recorded here rather than quietly deleted, because a design note that overstates
its own defences is the specific failure #144 warns against.

**Why §7.1's argument does not reach it.** §7.1 rests on the node being unable to
identify which flows are scored. Against a Sybil that is false: the node knows its own
clients. It serves them at line rate (or claims to, having moved nothing) and everyone
else at 1 Mbit.

**What §6.4 buys** — a cost floor, not a fix:

- the unit of cost is an **AS**, not a client or a sample, so volume is worthless;
- the attacker must control roughly **4:1** of the ASes attesting to its node, and
  that ratio must hold as the node attracts honest clients — a node that succeeds at
  attracting traffic becomes *harder* to hold, not easier;
- `k` distinct ASes are needed even to pass the **provisional ceiling** at all;
- the rise cap means a big lie takes **many windows**, in public;
- and decay makes the collusion **recurring** — the attacker pays every window,
  forever, or the rating evaporates.

**What remains.** An attacker who holds a ~4:1 AS supermajority among its node's
attesters, and sustains it, can hold a rating it does not honour for strangers, for
about the price of the identities. **That is not closed, and I do not see how to close
it inside this lane.**

**Why it is not closable here.** The attack is not a flaw in the estimator; it is the
*price of an identity* being too low. That price is set by the client-admission and
vouch-tier system (#42/ADR-0023, and `§5 vouch trust-tiers` in the private
productization design), not by anything `core/capacity` can compute. Any estimator
that accepts attestations from purchasable identities inherits this hole; the only
real fixes are (a) making attesting identities expensive or socially-vouched, which
is #42's job, or (b) an unforgeable proof of *transit to a stranger*, which is an open
research problem — Tor has fought this exact fight for fifteen years across bandwidth
authorities, EigenSpeed, PeerFlow, and FlashFlow without a clean answer, and this
project should not pretend to one in a Size-L card.

**What makes it survivable in the meantime**, and why this is worth landing anyway:
the attacker's gain is *bounded and priced* rather than free and unbounded; the
honest-node path is unaffected; and the failure mode is over-assignment to one node,
which the client's own transport pool already routes around (ADR-0028's ladder demotes
a path that underperforms, regardless of what the coordinator thinks of it). **The
client does not have to trust the rating** — which is the standing posture for
everything the coordinator says.

#### 8.1.1 The price, decided: two ratings (owner, 2026-07-17 — #157)

The question this section left open was narrow: *what does an attesting client identity
cost, and is it vouched?* The answer is option (a) from the two named above — (b), an
unforgeable proof of transit to a stranger, remains an open research problem and this
project is not going to solve it in passing — but it is applied **twice**, not once:

> **A node carries TWO estimates. `trusted` is attested only by accounts a real person
> vouched for, and is the one the coordinator uses. `untrusted` is attested by anyone,
> and may never exceed the provisional ceiling.**

##### Why two, and why the ceiling is the whole design

A single vouched-only rating would be sound and would starve the honest majority: early
on almost every session is free-tier, so almost every node would sit at `Floor`
(256 Kbit) — not "unrated", *actively useless*. A single anyone-can-vote rating is worth
nothing, because forging it costs ~$100/month of VPS across a few dozen ASes.

Splitting them is only safe because of a bound this design **already has**. `Ceiling`
(5 Mbit, rising past it needs `CeilingASes` = 3 distinct ASes) exists to price §8.3's
"decline to be measured" strategy, and its rule is: **silence buys the ceiling, never
more.** Capping `untrusted` at exactly that line makes the arithmetic work out:

| what an attacker does | what it costs | what it buys |
|---|---|---|
| stays silent | nothing | the ceiling (5 Mbit) |
| forges `untrusted` across many ASes | ~$100/month of VPS | the ceiling (5 Mbit) |
| forges `trusted` across ≥3 ASes | real people, vouching, in many networks | the real rating |

**Forging the cheap signal buys nothing over saying nothing.** That is not a coincidence
to be grateful for; it is the §1 spine holding — *a self-report is trusted exactly when
lying cannot benefit the reporter* — applied to a range rather than a direction. Below
the ceiling, lying gains you what silence already gave you. Above it, lying pays, so the
signal there must be expensive to forge.

Meanwhile the honest node with only free-tier users is lifted from 256 Kbit to as much as
5 Mbit: usable, bounded, and earned by traffic that actually flowed.

##### The rules this imposes on the feed (#158)

- **`trusted` decides.** Where it exists it is the rating, full stop. `untrusted` is not
  a tiebreaker, not a prior, and not a blend — no weighted average of the two, ever. The
  moment an unvouched sample can move a number above the ceiling, the $100/month attack is
  back and the vouch requirement was decoration.
- **`untrusted` is clamped to `Ceiling`, in the estimator, not by convention.** A clamp
  that lives in a caller is a clamp someone removes.
- **Two separate estimators, two separate sample streams.** Not one estimator with a
  weight field. The separation is the security property; a shared accumulator is one
  refactor away from a blend.
- **A node with `trusted` above the ceiling ignores `untrusted` entirely.** It has better
  evidence; the worse evidence must not drag it.

##### What this still does not do

**It raises the price of the expensive lie; it does not close the hole.** An attacker who
*can* obtain vouched accounts across ~75% of a node's attesting ASes still holds a
`trusted` rating they do not honour. What changed is the currency: social effort, in many
networks, leaving a trail that implicates the voucher and that §5's subtree revocation
exists to pull — instead of a credit card. Anyone reading this as "solved" has misread it.

And **the client still does not have to trust either rating**, which remains the
load-bearing defense: ADR-0028's ladder demotes a path that underperforms regardless of
what the coordinator believes about it.

**It also couples node rating to the trust graph.** A change to who may vouch is now also
a change to who may rate nodes above 5 Mbit. Deliberate, but real, and #158 should not
quietly widen it.

### 8.2 The saturation bit is unilateral — and deflation is cheap

Two weaknesses that compound, so they are stated together.

**The bit is not co-signed.** The exit co-signs the byte count; it has no way to verify
"I wanted more." So the one bit that disambiguates §5.3 — the bit the entire
methodology rests on — is the one part of a sample nothing protects. A defaming client
(A2.4) can assert `saturated` while idle and report a low rate it never actually
suffered.

**And §6.4's statistics make that cheap — twice over.** Both choices are asymmetric,
and both asymmetries run the same way.

*The quantile.* The estimate sits at rank `floor(q·(n−1))`, so it tolerates only
`floor(q·(n−1))` adversarial ASes *in the lower tail*:

| attesting ASes | defaming ASes tolerated |
|---|---|
| < 5 | **0** — one defaming AS owns the rating outright |
| 5–8 | 1 |
| 9–12 | 2 |

*The per-AS minimum.* One defaming attester captures its whole AS's vote, since the
minimum takes it. (A median would have required a majority within that AS — but a
median is capturable in the *other* direction, which is strictly worse; see §6.4.)

Together: **every attester in ~75% of ASes to inflate, one attester in ~25% of them to
deflate.** Inflation is expensive and deflation is cheap, and on a node with few honest
attesters, deflation is nearly free.

**Why this is accepted rather than fixed.** It is the trade the design makes on
purpose. The two errors are not equal: over-rating routes real users onto a node that
cannot carry them and they suffer immediately, while under-rating wastes capacity and
hurts nobody. Given a statistic that must be wrong in one direction, being wrong toward
*under*-rating is the correct choice, and cheap deflation is the price of that. It is
also self-limiting in a way inflation is not — a defamer can push traffic away from a
node but cannot attract traffic to its own, which is the thing A2.1/A2.3 actually want.

Bounded further by: it costs an admission credential per AS; it dilutes as the node
attracts honest attesters; and a partial hardening exists — the exit could co-sign an
*observed backlog* proxy (its own send-queue depth toward that client), which is not
the same claim but correlates with it. → child issue (§9.4), not v1.

Bounded by §6.4's per-attester cap and by direction (it only lowers). Accepted for
now: it is an availability attack on an honest node, not an integrity attack on the
estimate, and it costs a credential. A partial hardening exists — the exit could
co-sign an *observed backlog* proxy (its own send-queue depth toward that client),
which is not the same claim but correlates — and is a child issue, not v1.

### 8.3 A node can decline to be measured

Refuse to propose receipts and you produce no samples. Absence is ambiguous (dead
node? honest node with idle users? node hiding?), so it cannot be read as guilt
directly. The design's answer is structural rather than punitive: **an unmeasured node
never rises above the provisional ceiling** (§6.4). Silence buys the ceiling, never
more. Whether the ceiling is *also* the serve floor — i.e. whether an unmeasured node
serves at all — is exactly #145's policy call, and deliberately not made here.

### 8.4 Capacity is not quality

A node can deliver 100 Mbit with 500 ms of added latency and 5% loss and score
perfectly. Throughput is one axis. Latency, jitter, and loss are a different metric —
and arguably the one users *feel* — but they are not what this card measures and
folding them in would conflate two decisions. → child issue, and a natural companion
to #145's floor, which will want both.

### 8.5 **Relays cannot be measured at all today**

The sharpest scope limit, and it falls straight out of ADR-0021's stated limitations
rather than from anything this design chose:

- receipts are **exit-only** — only `RoleExit` derives an accounting identity; relays
  have none;
- receipts are **direct-mode only** — a relay-forwarded flow reaches the exit as a
  bare spliced TCP stream with no session id, so nothing keys a counter (this is
  ADR-0021's known gap, not a new one);
- so a relay produces **zero** samples.

**Therefore #144's methodology measures *exits* today.** Relays get declared limits
(#143, which needs no measurement) and are pinned at the provisional ceiling by §8.3
until relay measurement exists. Closing it needs a correlation id on the relay↔exit
wire so relayed bytes can be attributed — a protocol change, out of this lane's scope
and a sibling of the same gap #56 hit. → child issue.

Note the interaction with `pickRelay`'s anti-determinism argument
(`cmd/coordinator/main.go`): that comment argues at length that relay selection must
**not** become a deterministic best-first pick, because a relay controlling its own
heartbeat cadence would make itself the perpetual choice and concentrate metadata.
A capacity-aware relay pick must therefore *filter* (exclude quota-exhausted and
below-rating relays) and then **still choose randomly among survivors** — never sort by
rating and take the best. This lane preserves that property; a later load-aware policy
must too.

### 8.6 The estimator is not wired into the coordinator yet, on purpose

The plainest statement of what did and did not land, because it would otherwise be
easy to read this document as describing a running system:

- **#143 is live end to end.** Declared limits ride the register wire, the coordinator
  drops exhausted nodes from `list`/`connect`/`pickRelay`, and the node enforces its
  own cap and quota on the data path. A residential volunteer can use it today.
- **#144's estimator is a tested library, fed by nothing.** `core/capacity.Estimator`
  is complete and its bounds are pinned (§7.4), but the coordinator does not hold one.

That is deliberate, for two reasons:

1. **Nothing feeds it.** The attested-sample path (client → coordinator) is §9.1, and
   it is gated on the §8.1 owner decision. With no feed, every node's rating would sit
   at `Floor` forever — so any filter on `measured` would strand the entire fleet. A
   gate wired to a number that is always the floor is not a partial feature; it is a
   loaded footgun.
2. **The registry replaces entries wholesale.** The coordinator's `register` handler
   does `exits[m.ID] = &exitNode{...}` every 10 s. An estimator stored on the node
   struct would be silently reconstructed on every heartbeat, resetting every rating
   forever, and nothing would fail visibly. Coordinator-side rating state must live in
   its own map with its own lifecycle — which is a decision worth landing *with* the
   feed and its tests, not ahead of them.

So `capacity.Usable` (the `min(declared, measured)` contract) exists and is tested but
has no production caller yet. It is the seam §9.1 plugs into.

> **Landed (2026-07-22, #158, [ADR-0041](../adr/0041-attested-capacity-feed-and-two-rating-estimator.md)).**
> §9.1 plugged in: the coordinator holds a `capacity.RatingStore` (its own map, its own
> eviction), the client → coordinator feed moves samples into it, and `Usable` is computed
> at `list`/`pickRelay`. The serve floor is wired but **off**, precisely for the reason
> this section gives — with the trusted stream unfed every rating clamps to the ceiling, so
> a gate on `measured` would still strand the fleet — proven by `TestFleetSurvivesTheFeedLanding`.

### 8.7 A reality node's camouflage splice is unmetered — the quota's one real hole

**#143's cap is not "never exceeded" on a node running `-transport reality`.** It is
never exceeded *by forwarded traffic*, which is a different sentence and the only one
this lane can honestly write today.

`core/transport_reality.go`'s anti-probing paths — `rawSplice`, `bridge`,
`holdAndDrain` (ADR-0027/ADR-0032, issue #62) — reverse-proxy an unauthenticated
connection to the impersonated origin so a censor's prober sees that origin's real
certificate chain instead of a Bacchus node. That is exactly what makes the transport
survive active probing, and it is not optional: `-reality-probe-origin` defaults to
the SNI host on `:443`, so it is **on by default** for a reality node.

`rawSplice` and `bridge` reverse-proxy, so their bytes cross the operator's line
**twice** like any other forwarded byte; `holdAndDrain` discards, so its bytes cross
once. All of them are metered **not at all**. Compare what they bypass:

| | probe echo (fixed, §7.6) | reality splice (open) |
|---|---|---|
| needs a completed handshake | yes (Noise_NK) | **no.** A ClientHello that fails to parse still routes to the unauthenticated path — a bare connect that sends *nothing* gets spliced |
| bounded per connection | 1 MB | `realityProbeTimeout` = 30s of whatever fits |
| bounded per session | no | **no session exists to bound** |
| counted against the quota | now yes | **no** |

So the smaller hole is the one this lane found and closed, and the larger one is the
one it did not.

**The threat is an attacker, and it is worth stating precisely, because the first
version of this section got it wrong in a way that flattered it.** That version claimed
internet-wide `:443` scanners would exhaust the cap on their own — "no adversary
required, the ordinary weather on port 443". That is false by about four orders of
magnitude. A scanner sends a ClientHello and reads the certificate chain: **5–10 KB**,
not 375 MB. At a generous 10⁴ probes/day that is ~3–5 GB/cycle — around **1%** of a
400GB cap. Background noise, not a bill.

The real finding is sharper than the invented one:

- **2× amplification, for free.** The attacker pushes or pulls N bytes; the volunteer's
  ISP meters 2N. The attacker pays retail for their half; the volunteer pays their cap
  for both.
- **No handshake, no identity, no session.** Nothing to authenticate, rate-limit per
  peer, or attribute afterwards. This is the cheapest possible way to spend someone
  else's quota.
- **The payoff is eviction, not the bill.** Once `-monthly-quota` is spent the
  coordinator stops offering the node — that is #143 working exactly as designed. An
  attacker who can spend a volunteer's quota can therefore **remove any reality node
  from the fleet**, on demand, for half the bandwidth it costs the volunteer. Against a
  censorship-resistant network that is not an billing nuisance; it is a targeted,
  anonymous, cheap way to take exits offline — and the more successfully #143 recruits
  residential volunteers, the more nodes it applies to.
- **A saturated 100 Mbit line spends a 400GB cap in about 4.4 hours** (400e9 ÷ 25e6
  bytes/s). That is the number that matters, and it needs one attacker with a
  respectable uplink, not five hundred of anything.

**Why it is not fixed here.** `realityTransport` holds no quota or limiter handle —
only `onEvent` and `onUnderlayDial` — so metering it means new plumbing through the
transport, which is another lane's surface and another lane's review. Tracked as
**#163**; the fix is not conceptually hard, it is simply not this PR's — and it has a
real design tension to settle first (cutting a splice mid-probe is itself the
fingerprint ADR-0027 exists to avoid), which belongs in ADR-0027's terms, not #143's.

> **Landed (2026-07-22, #163, [ADR-0027 update](../adr/0027-reality-active-probing-response.md) / [ADR-0041](../adr/0041-attested-capacity-feed-and-two-rating-estimator.md)).**
> `realityTransport` was given a metering handle (`realitySpliceLimits`, sharing the
> engine's quota and limiter). The splice now **counts** every byte against the quota —
> both link crossings for a `rawSplice`/`bridge` leg, one for a `holdAndDrain` — and
> **paces** it, but never cuts an in-flight splice: exhaustion is enforced at *admission*
> (a new splice is refused and drained instead, the same no-instant-close fallback used
> for an unreachable origin), which resolves the design tension exactly as ADR-0027's
> terms require. A per-source-IP rate gate plus a global concurrency cap bounds how many
> amplifying legs run at once, the per-IP connection churn a flood costs, and the gate's
> own memory.
>
> **Corrected 2026-07-25 (issue #168): that gate does _not_ raise time-to-exhaust**, and
> the first version of this block implied it did ("blunts the eviction attack"). The
> splice limiter is **aggregate and shared** with the forwarder's, so a single active
> reverse-proxy splice already saturates the entire declared speed; and the per-IP rate
> (1/sec, against a 30 s splice lifetime) trivially keeps one splice alive continuously.
> Time-to-exhaust therefore stays `quota / (2 × speedCap)` — **the same formula this
> section computes above** (`400e9 ÷ 25e6`) for the *unmetered* case — **independent of
> how many source addresses the volume comes from**. One machine can still spend an
> honest node's whole cycle quota and get the node evicted.
>
> What #163 did buy is intact and is the part worth stating: *never exceeded* now holds
> for a reality node up to a bounded in-flight overshoot, because the spend is **bounded
> by the declared cap and accounted for** instead of running at line rate unmetered. The
> residual — the eviction attack is *priced, not closed*, and a **single** uplink suffices
> rather than a botnet; an exhausted node holds rather than proxying — is in the ADR-0027
> update.

**Why it is written down here anyway.** §4.2/§4.3 argue at length that the coordinator
half is "necessary but not sufficient for the word *never*", and then earn *never* with
node-side enforcement. That argument is sound and its conclusion, stated without this
caveat, was false: the config the project *recommends* for censorship resistance is the
config in which a declared quota can be exceeded. A design note whose value is honesty
about what it does not solve does not get to leave that in the reader's blind spot
because the code lives in a neighbouring file.

---

## 9. Deferred → child issues (filed)

1. **Attested-sample feed (client → coordinator), and the coordinator-side estimator** —
   **#158, LANDED ([ADR-0041](../adr/0041-attested-capacity-feed-and-two-rating-estimator.md)).**
   The `capacity-report` message, the `saturated` bit on `Receipt` (an ADR-0021
   amendment), coordinator-side verification, the per-node estimator map with its own
   lifecycle (§8.6), and `Usable` applied at the assignment surfaces. This is the piece
   that makes #144 *run* rather than merely be settled. It builds **two** estimators, not
   one: `trusted` (vouched attesters, decides) and `untrusted` (anyone, clamped to
   `Ceiling` inside the estimator). Never blended, never weighted — see §8.1.1's rules,
   which are load-bearing rather than stylistic. As built, the trusted stream is
   **permanently empty** (nothing stamps vouched-ness yet), the AS is a coarse
   observed-IP-prefix proxy pending a real ASN lookup, and the serve floor ships **off**
   so the feed landing does not strand the fleet — all stated in ADR-0041.
2. ~~**Sybil cost floor for attesters**~~ — **#157, DECIDED (owner, 2026-07-17).**
   **Two ratings: `trusted` is attested only by vouched accounts and is the one the
   coordinator uses; `untrusted` is attested by anyone and may never exceed the
   provisional ceiling** — so forging it buys exactly what silence already buys, while an
   honest free-tier-only node still gets lifted off `Floor`. Reasoning, the arithmetic,
   the rules it imposes on (1), and what it does *not* close are in §8.1.1. Spans
   #42/ADR-0023 and `§5 vouch trust-tiers` in the private productization design.
3. **Relay measurement** (§8.5) — **#159**. A correlation id on the relay↔exit wire so relayed
   bytes are attributable; unblocks measuring the relay tier at all.
4. **Exit-observed backlog proxy** (§8.2) — **#160**, to partially harden the unilateral
   saturation bit against a defamer.
5. **Quality metrics** (§8.4) — **#161** — latency/jitter/loss, a companion to #145's floor, which
   will want both axes.
6. **Capacity-aware relay pick** — **#162**: filter-then-random in `pickRelay`, preserving the
   anti-determinism argument (§8.5). Blocked on (3): filtering relays by a rating no
   relay can earn would strand the tier.

---

## 10. Relationship to other work

- **#145 [B3] serve floor** consumes `min(declared, measured)` and decides eligibility.
  This lane deliberately does not set it (§6.5): floors are policy, varying by region,
  role, and scarcity.
- **#42 / ADR-0023 admission** sets the price of an attesting identity, and therefore
  the depth of §8.1. Capacity measurement is only as sound as admission is expensive.
- **ADR-0021 accounting** supplies the primitive; the `saturated` bit amends it (§9.1).
- **ADR-0028 transport pool** is the client-side safety net: its ladder demotes an
  underperforming path on the client's own observation, so a client never has to trust a
  rating. This is what makes §8.1 survivable rather than fatal.
- **ADR-0033 relay selection** is where a capacity-aware pick lands, subject to §8.5's
  anti-determinism constraint.
- The **earn/payout plane** (private repo) is the eventual consumer, and the reason
  A2.1/A2.3 have a profit motive at all. Measurement must be settled before payout, or
  the payout is paying for claims.
