# 48. Tier limits are resolved from the signed policy: the coordinator enforces priority and endpoint quality, the exit shapes to the speed cap, and the exit is never shown the credential

Date: 2026-07-29

Status: Accepted

Implements issue #58 (the public half of `bacchus-payment#6` `[B5]`). Consumes
ADR-0043's issue #67 amendment; applies ADR-0006 decision 5; extends ADR-0040 and
ADR-0041; constrained by ADR-0042 and ADR-0035.

## Context

ADR-0043's #67 amendment reversed where tier limits live. The signed policy carries
them — `speed_cap_bps`, `priority`, `endpoint_quality` per `(trust, plan)` row — and
the admission credential carries only the pair that indexes them. The producer side
shipped in `bacchus-payment#6`: an issued credential now carries `trust` and `plan`
and carries no numbers. `core/policy` has parsed and validated the `tiers` table
since ADR-0043 and nothing has read it.

This is the consumer side. It answers three questions the amendment deliberately left
open: which party enforces which number, what the exit is told in order to enforce
its one, and what happens when the lookup fails.

## Decision

### 1. The credential grows `Trust` and `Plan`, in that order, immediately after `Vouched`

`core/admission.Credential` gains two `omitempty` strings. Both are stamped by the
account service and by nothing in this repository — `cmd/admission-issue` does not set
them, pinned by `TestIssueStampsNoTierKey`, because a public issuer that could grant
paid standing is a public issuer that can grant paid standing.

**Declaration order is the contract.** `encoding/json` marshals struct fields in
declaration order and the marshaled form is the signed body, so two independent
implementations of one signed format must declare the same fields in the same order.
`bacchus-payment/internal/admission.Credential` declares `Vouched`, `Trust`, `Plan`;
this repository now matches it exactly.

Both are additive: a credential naming no tier marshals to the bytes it would have
before #58, so an operator-issued credential is unchanged and an older verifier reads
the same body it always did.

#### How this was proven, and what the proof does not cover

`bacchus-payment` cannot import `bacchus` — private to public, separate modules
(ADR-0002) — so the two implementations share no code and "tests pass in both repos"
establishes nothing about interop. The arbiter is the frozen vectors the private repo
mints. All **20** checks were run through *this* repository's verifier from a
throwaway module with a `replace` directive at this worktree, and the harness was
deleted afterwards rather than landing in either repo:

- **2 positive vectors** — accepted, and `trust`/`plan`/`vouched` parsed to the frozen
  expectations;
- **16 negative vectors** — refused, each with the sentinel its `expect_error` names,
  including the two this change makes newly relevant (`plan` and `vouched` forged onto
  an honest credential after signing);
- **2 order round-trips** — each frozen body re-marshalled through this repo's
  `Credential` and required back byte-for-byte.

The third group exists because the first two cannot see field order at all:
verification checks the signature over the bytes **as received** and then unmarshals,
and unmarshalling is order-independent, so a swapped declaration passes every positive
vector there is. Order governs the **minting** direction. Swapping `Trust` and `Plan`
was confirmed to leave all 18 accept/refuse checks green and to fail the round trip for
the vector carrying both keys — which is the only reason to believe the round-trip check
is doing any work. (The free-tier vector still passed under the swap, because a body
carrying `trust` and no `plan` has no order to get wrong. Two keys are needed to observe
the property at all, which is worth knowing before anyone prunes a fixture.)

### 2. The coordinator enforces `priority` and `endpoint_quality`; the exit shapes to `speed_cap_bps`

Both coordinator-side numbers are applied inside `exitAssignable`, which is the single
definition of "assignable" shared by the country list and the assignment. That
function becomes per-client as a result, and it has to: an aggregate computed under
different limits than the connect will enforce would make `Available` promise what
`connect` then refuses, which is the invariant the function exists for.

- **`endpoint_quality`** is a floor on an exit's coordinator-observed endpoint class.
- **`priority`** scales the fullness floor: `minShare / max(1, priority)`. As an exit
  fills it stops accepting the lowest-priority sessions first and keeps accepting the
  highest, which is what "scheduling weight under congestion" means when the only
  scheduling decision this coordinator makes is whether to assign at all. Priority 0 —
  an unset field — takes the network floor unchanged: a tier earns relief by being
  named in a signed row, never by omission.

Neither reaches the octave banding. Turning priority into a **sort** would rebuild the
deterministic best-node pick ADR-0033 forbids and ADR-0042 §3 keeps out, and would do
it with a number a paying client could then observe.

The posture is the serve floor's (#15): a number read from a document verified against
the policy root, applied to a quantity the coordinator observed itself, with no
constant default anywhere. A coordinator that could fall back to a constant would have
authored policy.

#### Both are live machinery over unfed inputs, and say so

`minShare` ships at zero and must (ADR-0042), so priority changes nothing for anyone
today — zero divided by any priority is zero. `TestPriorityIsInertAtTheShippedMinShare`
pins that; `TestPriorityAdmitsWhereALowerTierIsRefused` flips `minShare` to prove the
mechanism is real, exactly as `TestServeFloorGateWouldExcludeIfEnabled` flips
`serveFloor`.

The endpoint-class oracle (`exitClass`) ships **nil**, and an exit with no known class
is **not** withheld. That looks like a hole and is the opposite. An endpoint class is a
quality judgement — latency, jitter, loss, the feed issue #21 describes — and
ADR-0040 §8.4 is explicit that capacity is not quality, so deriving a class from
measured throughput would be inventing the number rather than reading it. A *declared*
class is worse: ADR-0040 accepts a self-reported speed cap because that claim only ever
binds downward, while a self-reported endpoint class binds **upward** — it is a claim
to be assigned premium sessions, which is precisely what a node profits from inflating.

So there is no honest class source yet, and treating "no class" as class 0 would be
catastrophic rather than merely strict: the frozen policy fixtures **both** repositories
test against carry `endpoint_quality` 1, 2 and 3 on **every** row, so the first
realistic policy anyone signed would refuse every connect in the fleet. An unclassified
endpoint is not a bad endpoint, exactly as design §5.3's unmeasured node is not a slow
node. `TestEndpointQualityFloorDoesNotFenceAnUnclassifiedExit` is the guard.

### 3. Fail directions: three states, three answers

ADR-0043 fails **closed** and ADR-0045 fails **open**, on the same sheddability test,
and both are right about their own gate. Neither is a template. These were decided
separately:

| State | Answer | Why |
| --- | --- | --- |
| **No policy configured** | Assign **unshaped**, exactly as today | `-policy-root-pubkey` has always been opt-in. A deployment that never adopted signed policy has not opted out of tier limits; it has not opted into the mechanism that carries them. Refusing would turn signed policy into a hard requirement to boot, as a side effect of this change. |
| **Policy held, pair unknown** | **Refuse, loudly**, naming the pair | ADR-0006 decision 5, now load-bearing. |
| **Policy held, admission disabled** | Assign **unshaped**, warned at startup | There is no credential on an open network, so there is no pair. That is *no key*, not an unknown one. |

A fourth state — policy configured, none currently held — cannot produce an assignment
at all: `policyAllowsAssignment` already refuses every connect while it holds
(ADR-0043 §3). It is handled anyway and refused, because the **country list** does not
go through that gate and must not answer with an availability figure computed under
limits it could not resolve.

#### Why the unknown pair is refused and not defaulted

A zero `TierLimit` reads as **uncapped** on two of its three fields. A permissive
fallback would hand full speed and unrestricted endpoint access to precisely the
credential nobody signed a row for, and it would open at the moment someone ships a
plan and forgets to re-sign the policy — a failure that looks like success. A
restrictive fallback is refused for the mirror reason: it would enforce a number
appearing nowhere in the signed document, so an operator debugging it would be hunting
a value that does not exist. Both substitutions are refused; the pair is named instead,
in the log for the operator and in the refusal reason for the client.

Concretely, this is the case an operator actually hits. **Every credential minted
before #58 carries an empty `Trust`**, and the policy's rows are keyed by a closed
vocabulary with no empty member (`policy.Trust.valid`), so no signable policy can admit
them. Turning policy on ahead of re-issuing the fleet's credentials refuses every
connect, by design. "Sign the policy first, then ship the plan" now includes "and
re-issue before you enable". `TestPreTierCredentialIsRefusedNotDefaulted` pins it,
because that is exactly the pressure under which someone adds a "just for old
credentials" fallback row and reopens the hole.

#### Why the third state is not refused

Refusing would stop a coordinator that works today over a feature it is not configured
for — the undiagnosable outage the restrictive fallback is refused to avoid. But a hole
that is silent where it opens has to be loud somewhere, so `warnTierEnforcementIsOff`
announces it at startup, beside the warning `main()` already prints for admission being
off at all.

### 4. The exit is given a number, never the credential

The coordinator resolves `(trust, plan)` and sends the resulting `speed_cap_bps` on the
assignment as `sessionCapBps`. The exit does not fetch its own policy, and **the client
does not present its admission credential to the exit**.

**The reason is a privacy property, not a layering convenience.** A credential's
`Serial` is a stable per-device identifier that outlives any one session, and the exit
is the single party that sees the user's actual traffic. Re-presenting a credential to
it would hand it a join key for linking one user's sessions to each other — the exact
correlation ADR-0042 removed the exit pin to deny and ADR-0035 keeps the relay tag
opaque to deny. A number links nothing.

**The cost, plainly: a hostile coordinator can hand out an uncapped session.** It can
send a large `sessionCapBps`, or none, and the exit will honour it. That is a
**revenue-integrity** failure and not the linkability failure ADR-0020 is about — the
coordinator is already assumed hostile for linkability and already learns which country
a client connects to, and this adds nothing to what it could correlate. It is bounded
from above by the node's own declared aggregate cap (ADR-0040), which the node enforces
locally through `e.limiter` and no coordinator can raise. So the worst a hostile
coordinator achieves is giving away capacity its operator already agreed to carry.

The alternative — the exit verifying the credential and resolving the tier itself —
buys revenue integrity at the price of the linkability property, and this project
spends money to protect linkability rather than the reverse.

At the exit the cap becomes a per-session `capacity.Limiter` wrapped inside the node's
own aggregate one: accounting counts what the session *moved*, the session limiter what
the tier is *entitled to*, and `meter` what the operator is *willing to carry*. Three
questions about the same bytes. `capacity.NewLimiter(0)` is nil and `LimitReads` is
nil-safe, so "no cap" needs no branch anywhere.

### 5. Per-session shaping covers the direct data plane only

`sessionCapBps` rides only assignments an **exit** receives — a direct connect or a
relay-mode TURN fallback, which the exit correctly cannot tell apart (`old #97`). It is
absent from:

- **A peer-relay assign**, which goes to the *relay* (it carries `ExitAddr`). A relay
  splices ciphertext and terminates nothing, so it could not shape the session; and the
  exit on the far side is reached through `serveExit`'s bare TCP listener with
  `exitTerminate("", nil, c)` — no session id, so nothing to key a limiter by. A
  peer-relayed session is therefore **unshaped by tier**. Stamping a cap on that assign
  would hand a forwarder a tier signal about a client it is only splicing, in exchange
  for no enforcement at all.
- **A chained (onion) connect**, for the reason `exitID` is empty there: the client
  assembled its own path and this coordinator does not know the terminating exit
  (ADR-0042 §9).
- **The UDP relay path** (`exitTerminateUDP`), which hand-rolls a datagram loop and
  paces through `meterN`/`WaitN` rather than an `io.Reader`, so there is no reader for
  the session limiter to wrap.

The first is not closed here and closing it is a separate decision: giving the exit an
identity for a relayed session is exactly what would reopen §4's linkability question,
and the splice is transparent by design (`TestPeerRelaySplicePreservesE2E`, ADR-0033).
Filed as **#74**. The node's own declared cap and quota still pace every one of these
paths; what is missing is the per-tier limit.

> **The first bullet was closed by the amendment (issue #74) at the end of this
> document, and its reasoning above is superseded.** "A relay could not shape the
> session" is false: a relay terminates nothing but forwards every byte, so it can
> pace them. A peer-relayed session is now shaped **at the relay**, and the exit is
> told nothing — which is why §4's linkability property is untouched rather than
> traded away. The second bullet (a chained connect) is **still open**, for the
> different reason it gives.

## Consequences

- **Nothing changes for a deployment that has not adopted signed policy.** No policy
  configured means no tier applies, the assign is byte-identical to a pre-#58 one, and
  the session log line is unchanged.
- **Adopting signed policy now requires re-issued credentials first.** Enabling
  `-policy-root-pubkey` against a fleet holding pre-#58 credentials refuses every
  connect with `unknown-tier`.
- **The country list is now per-tier in its `Available` figure** and refuses outright
  when the tier cannot be resolved; a client rotates to another pool member (ADR-0020).
  `Exits` stays tier-independent, deliberately — it is the network's shape, and making
  it per-tier would turn the list into an oracle for how many premium exits a country
  holds.
- **A tier-driven refusal reports `country-busy`, not a distinct reason.** A distinct
  one would let a client count the exits above and below its own class, one connect at
  a time — the per-tier network map `old #146` removed the exit list to prevent.
- **`admit` now returns the verified credential.** Re-verifying to read a field the
  gate already parsed would spend a second ed25519 verification per connect and leave
  two call sites that could disagree about which credential they read.
- **The session log gains the cap and never the tier.** A log line naming a client's
  plan would turn an operator's log into an account-linkability record keyed by source
  address — the same property §4 spends the revenue-integrity residual to protect.
- **Peer-relayed and UDP-relayed sessions are not tier-shaped** (§5). A client that
  wants more than its tier can ask for relay mode or drive UDP and get the node's
  aggregate cap instead of its own. #74 covers the relay half; the UDP half needs
  `core/udprelay.go`, outside this change's file ownership, and is noted on the same
  issue.

  > **Superseded for the relay path — see the amendment (issue #74) at the end of this
  > document.** A relay-mode client is now shaped at the relay. What remains unshaped
  > is a **chained** connect, for its own separate reason (ADR-0042 §9).
- **`min_declared_quota_bytes` is still enforced by nothing**, for the reason
  ADR-0043's #15 amendment gives.

## Alternatives considered

- **Exit verifies the credential and resolves the tier itself.** Removes the hostile-
  coordinator residual entirely. Rejected: it hands the one party that sees the user's
  traffic a stable per-device identifier, which is the correlation §4 exists to deny.
- **Derive the endpoint class from measured capacity.** Available today and would make
  the floor bite immediately. Rejected: ADR-0040 §8.4 — capacity is not quality; it
  would rank a fast, lossy node above a clean one, and it is inventing the number
  rather than reading it.
- **Let a node declare its endpoint class on register.** Rejected: the self-report
  binds upward, which is the direction ADR-0040's whole argument for trusting
  `-max-speed` does not cover.
- **Treat an unclassified exit as class 0.** Rejected: with no class feed and fixtures
  carrying `endpoint_quality` ≥ 1 on every row, the first realistic signed policy would
  refuse every connect in the fleet.
- **Priority as a sort over candidates rather than a fullness floor.** Rejected:
  rebuilds the deterministic best-node pick ADR-0033 forbids.
- **A permissive fallback row for an unknown pair.** Rejected — see §3; this is
  ADR-0006 decision 5 and it is the whole reason the amendment could have become a hole
  instead of an outage.

---

## Amendment (issue #74, 2026-07-30): a peer-relayed session is shaped at the RELAY

§5 listed three paths per-session shaping did not reach, and argued the first was hard
to close. That argument contained a false premise, and this amendment records the
correction rather than quietly overwriting it.

### What §5 got wrong

§5 said a relay "could not shape the session" because it "splices ciphertext and
terminates nothing". Terminating nothing is true; being unable to shape does not follow
from it. **A relay forwards every byte of the session, so it can pace them.** Pacing
needs custody of the bytes, not comprehension of them.

Having framed the problem as *"what identifies a relayed session to its exit"*, §5 then
found — correctly — that every answer to that question reopens §4. The mistake was the
framing: the exit is not the only party on the path.

### The decision

`sessionCapBps` now rides the **peer-relay assign** as well, and the relay applies it in
`relayPipe`, wrapped inside the node's own aggregate limiter exactly as the exit's TCP
path composes them (§4). Three edits, no new wire field — `SessionCapBps` has existed on
both wire copies since #58 and was simply never set on this path:

1. `cmd/coordinator/main.go` stamps `sessionCap` on the peer-relay assign.
2. `core/forwarder.go`'s `handlerFor` builds `sessionPace(m)` in its `ExitAddr` branch.
3. `relayPipe` wraps both copies with it.

### Why this costs neither property §5 was protecting

- **§4's linkability property is untouched, because the exit is not involved.** No
  session identity, no token, no credential reaches it. The exit still receives
  `exitTerminate("", nil, c)` through its bare TCP listener and still knows nothing about
  the session — which is the option §5 rejected, and it stays rejected. Shaping moved to
  a party that already had custody instead of granting knowledge to one that did not.
- **ADR-0033's transparency is intact.** The limiter wraps the *copies*; the relay learns
  how fast to move bytes it still cannot read. No destination, no plaintext, no preamble.
  `TestPeerRelaySplicePreservesE2E` is the regression barrier and stays green, with a nil
  limiter so the splice under test is byte-for-byte what it was.
- **The disclosure to the relay is a number it could already derive.** It is measuring
  the throughput it forwards; being told the cap reveals a coarse bucket it could observe
  empirically. That is materially smaller than the credential-to-exit design §4 rejected,
  which would have handed over a stable per-device identifier.

The residual is unchanged in kind and now applies to one more party: a hostile
coordinator can send a large cap or none, and the forwarder honours it. That is still a
revenue-integrity failure rather than a linkability one, still bounded above by the
node's own declared aggregate cap (ADR-0040), which no coordinator can raise.

### What does NOT close: a chained connect

**A chained (onion) connect still carries no cap, and this is a different gap with a
different reason** — not a leftover of the one above. The client assembled the path and
this coordinator does not know where it terminates (ADR-0042 §9), so there is no session
for it to account for; `sessionCap` is zeroed for `chained` before any assign is built.

The distinction matters because the two gaps would be closed by different things. The
relay gap was about *which party can enforce*, and is closed. The chained gap is about
*what the coordinator knows*, and closing it is a question for ADR-0042 §9's own terms,
not this record's. `TestChainedPeerRelayAssignCarriesNoSessionCap` pins it so a later
change that caps every relay assign uniformly fails rather than silently deciding it.

So §5's list goes from three unshaped paths to one, and that one is named rather than
implied. A reader should not come away thinking every path is now shaped.

### Testing

Mutation-checked, the bar #58 set:

| Mutation | Test that fails |
| --- | --- |
| drop `SessionCapBps` from the peer-relay assign | `TestPeerRelayAssignCarriesTheSessionCap` (`cmd/coordinator`) |
| drop the `if chained { sessionCap = 0 }` guard | `TestChainedPeerRelayAssignCarriesNoSessionCap` |
| drop `sessionPace` from `handlerFor`'s `ExitAddr` branch | `TestPeerRelaySpliceShapesToTheTierCap` (`core`) |
| drop `pace.LimitReads` from `relayPipe`'s copies | `TestPeerRelaySpliceShapesToTheTierCap` |

`TestPeerRelaySpliceShapesToTheTierCap` drives `handlerFor` rather than `relayPipe`
directly, so it covers the production wiring end to end and either mutation reddens it.
`TestUncappedPeerRelaySpliceIsNotShaped` is its control, and also guards the chained and
unpoliced-coordinator cases, where the assign carries no cap and the splice must run
unshaped.

**One test was inverted rather than added**, and that is the honest record of this
change: `TestPeerRelayAssignCarriesNoSessionCap` asserted §5's original decision and is
now `TestPeerRelayAssignCarriesTheSessionCap`, asserting the opposite.
