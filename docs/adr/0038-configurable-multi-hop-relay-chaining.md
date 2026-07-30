# 38. Configurable multi-hop relay chaining (client-assembled onion)

- Status: accepted (design spike — issue #76; implementation follows in child issues)
- Date: 2026-07-11

## Context

The relay tier is single-hop (ADR-0033): when a client cannot reach its exit
directly, the coordinator picks one relay, tells it the exit's address
(`assign{ExitAddr}`), and the relay blind-splices ciphertext (`core/forwarder.go`
`relayPipe`). That one relay sees **both** endpoints at the Bacchus layer — the
client's source address (it is the transport peer) and the exit's address (the
coordinator named it) — though never the content or internet destination, which live
inside the client↔exit Noise_NK channel (ADR-0009).

Issue #76 asks for a **configurable number of relay hops** so a user can route the
relayed data plane through a chain `R₁ → … → Rₙ` where no single relay sees both the
client and the exit, while keeping the client↔exit end-to-end guarantees (#60/#69)
exactly as they are — and with a default that is byte-for-byte today's single hop, so
the feature is a strict superset with zero regression when unset.

The full design is [`docs/design/relay-chaining.md`](../design/relay-chaining.md);
this record captures the decisions and their justification against the standing
threat model (a possibly-hostile coordinator, ADR-0020/#60; untrusted relays).

## Decision

Adopt **client-assembled, onion-layered relay chains**, engaged only at hop count
`≥ 2`, built from primitives already in the tree.

1. **The construction is nested Noise_NK — no new protocol.** A chain is the existing
   client↔exit handshake (`core/e2e.go`) run once per hop. The client telescopes
   layers (Tor-style): Noise_NK to `R₁` carrying the encrypted address of `R₂`, then
   through it Noise_NK to `R₂` carrying `R₃`, … then to the exit carrying the real
   destination. Each relay is the exit's existing `exitTerminate` behaviour pointed at
   the next Bacchus node: Noise_NK responder with its own key, read the encrypted
   next-hop address, dial, splice raw. `core/e2e.go`'s `noiseConn` already re-delimits
   frames over an opaque byte stream, so `noiseConn`s stack directly.

2. **The client assembles the chain; the coordinator never picks the path
   (defends the hostile coordinator).** The client selects all hops and the exit from
   the coordinator-**signed**, pool-cross-checkable directory
   (`core/coldstart.Snapshot`) and names each hop's successor only *inside* the onion.
   The coordinator keeps its two existing, already-untrusted jobs: serve the signed
   directory (tamper-evident) and broker the **first hop only** (client↔R₁ rendezvous,
   which it already sees in single-hop mode). It learns nothing of `R₂…Rₙ` or the exit.
   A coordinator therefore cannot force a colluding/deanonymizing path (it does not
   choose the hops), cannot MITM a hop (each is Noise_NK-authenticated to a directory
   key it does not hold), and cannot MITM the exit (admission-verified E2E, below).
   Coordinator-assembly is rejected: a hostile coordinator would pick an all-colluding
   chain every connect and the client could not tell.

3. **End-to-end exit admission survives the chain by construction.** The innermost
   layer is the unchanged `clientHandshake`/`exitHandshake`; the exit presents its
   `AdmissionCred` in msg2 and the client's `verifyExit` predicate (#60/#69) aborts
   before sending the target if it is unauthorized. Every relay only splices
   ciphertext, so this exchange is bit-identical whether it crossed 0, 1, or n hops —
   the same transparency argument ADR-0033 proved for one hop, extended to any depth.
   Additionally each *relay* hop is authenticated by the client to its directory key
   (stronger than the single-hop blind splice); per-hop relay-role admission
   credentials are an optional follow-up (shipped — see the issue #26 amendment at
   the end of this file).

4. **Hop count is one knob, default 1 == today (strict superset).** `Config.RelayHops`
   / `-relay-hops` (and the ADR-0036 "route through N nodes" GUI control), default `1`,
   hard-capped at `RelayHopsMax` (proposed 4). At `1` the onion path is **not engaged**
   — the coordinator's existing `pickRelay` + `relayPipe` blind splice runs unchanged,
   so an unset knob is exactly the shipped behaviour. The onion is strictly the `n ≥ 2`
   opt-in. (n=1 stays on the old path deliberately: a 1-hop onion buys no anonymity —
   one relay sees both endpoints regardless — while adding a handshake, so it is not
   worth diverging from the proven path.)

5. **Composition.** The chain lives inside the ADR-0028 selection ladder's `ModeRelay`
   tier (tier order unchanged; depth is engine config, not a per-`Candidate` field) and
   is a strict generalization of ADR-0033's peer relay. It is orthogonal to the
   underlay: the **first** hop rides the ladder's chosen reality/webrtc transport with
   coordinator rendezvous and TURN as its ICE fallback (ADR-0033), while hops
   `R₁→…→exit` are outbound TCP dials to node ingresses. Intermediate hops must be
   publicly reachable (Tor-like); NAT'd residential nodes serve as the first hop
   (hole-punched) or the exit, not as middle hops — hole-punched middle hops would
   re-leak the path to a coordinator and are deferred.

6. **Bounds.** Chain length is capped (`RelayHopsMax`) and client-clamped (a
   coordinator cannot inject hops it never sees). Forwarding is 1:1 with no
   amplification vector; the cost is `n×` volunteer bandwidth per unit of user traffic,
   borne by the mesh, which is why depth is opt-in. Relays forward **only to a known
   Bacchus node** from their cached signed directory (preserving the relay/exit safety
   line — a relay never becomes an open internet proxy) and rate-limit per previous hop
   and in aggregate. Sybil correlation (controlling first + last hop) is bounded by
   AS/operator/vouch-subtree-diverse hop selection and the §5.4 vouch/tenure ladder.

## Consequences

- A user can opt into a relayed path where no single relay links them to their exit,
  reusing the Noise_NK handshake, the transparent splice, the signed directory, and the
  reselect/failover machinery already in the tree — the design is a composition of
  shipped primitives, not a new stack. Default-1 means existing users are unaffected.
- #60/#69 exit-admission verification is unaffected at any depth — proven by
  construction (onion layers sit outside the E2E channel) and to be pinned by an
  n-hop analogue of `TestPeerRelaySplicePreservesE2E`.
- **Honest limits.** No defence against a global passive traffic-correlation adversary
  (the standing limit of low-latency onion routing — Tor shares it). The first hop
  still sees the client's address; the coordinator still sees client↔R₁ — both
  unchanged from single-hop. At the default depth a single relay still sees both
  endpoints; that is today's behaviour, opted out of only at `n ≥ 2`.
- **Dependency.** Client-side hop selection needs each relay's forwarding ingress
  address + operator tag in the signed snapshot — the courier-address advertisement
  ADR-0037 deferred. **This directory seam is now implemented (issue #124 — see the
  Amendment below);** the client-side selection/dialing that consumes it (§2/§4) stays
  deferred, so until those land, intermediate hops are directory-/operator-anchored.
- **A feasibility probe ships with this spike** ([`cmd/relaychain-probe`](../../cmd/relaychain-probe/README.md)):
  a dependency-free, in-process demonstrator that telescopes real `flynn/noise` layers
  and asserts the peel property (each relay learns only its neighbours; the innermost
  target + admission credential survive; a substituted hop key fails its handshake). It
  imports no `core/` package and wires nothing into production.
- **Deferred to child issues** (enumerated in the design doc §9): relay onion-forward
  handler + ingress; client telescoping dialer; directory ingress/AS metadata (gates
  selection); AS-diverse hop selection; the hop-count knob + GUI; chain liveness +
  rebuild; relay-side DoS controls; optional per-hop relay admission creds; and the
  deferred NAT-traversed middle hop. This PR is **Part of #76** and does not close it.

## Amendment (issue #124, 2026-07-11): relay ingress + operator advertised; AS-tag advisory-only

The directory seam §6 and the Dependency consequence named — "each relay's forwarding
ingress address + operator tag in the signed snapshot" — is now implemented on the
production/directory side. This is the **ungated foundation** of the epic (§9 item 3):
§1 (relay onion-forward handler) and §2/§4 (client selection + telescoping dial) build on
it; it wires none of them.

**What landed.** `core/coldstart.Entry` gains two additive, `omitempty` fields, both
inside the ed25519-signed snapshot body, and the coordinator populates them in
`buildSnapshot`:

- `Ingress` — the TCP address a client's onion layer dials to use the node as an
  intermediate hop, distinct from `Addr` (a relay's coordinator-observed UDP *signaling*
  address, a NAT-punched hole, not a forward-dial target). The coordinator composes it as
  the **observed source IP** of the relay's register joined to the relay's **self-reported
  listener port**. Only the port is a node self-report; the host is never the node's to
  assert, so a relay cannot advertise an ingress in an AS it does not occupy. A relay that
  reports no port advertises no ingress and is, by `Entry.RelayEligible`, simply not a hop.
- `Operator` — the coordinator-known operator / vouch-subtree tag for operator-diversity
  hop selection (§6). It is **coordinator-side truth** (loaded from the operator's
  `-operators` assignment file), never a node self-report — a node cannot be trusted to
  state its own operator, or a Sybil would fabricate diversity. Empty when unassigned
  (fail-open, like admission #42): hops are then merely unlabeled.

Signing covers both fields end-to-end (a tampered ingress or operator tag fails snapshot
verification), the addition is backward-compatible both ways (a pre-#124 snapshot verifies
under the new parser and vice-versa — no version bump), and a mesh-walk courier (#31)
forwards the fields verbatim without being able to strip or forge them.

**No AS field is carried — the honest limit on §6/§7 anti-Sybil.** The spike's §6
listed "AS/operator/vouch-subtree-diverse hop selection." Of these, **AS is deliberately
NOT put in the signed directory at all.** A self-reported — or even coordinator-asserted —
AS number cannot be trusted for network diversity: a hostile coordinator or Sybil operator
would fabricate AS diversity in a signed tag, and the client cannot verify it. Such a field
would have **no trustworthy consumer**, because real AS-diversity is enforced in §4 by
deriving each hop's AS from its **observed IP** against an independent public routing table,
client-side, never from this snapshot. If any AS hint is ever carried here for coordinator
bookkeeping, it must be documented — in code and here — as **advisory only, never a client
diversity input.** The operator/vouch tag *is* legitimately signed (operator identity is
not IP-derivable), but it too is an advisory anti-Sybil signal anchored in coordinator
bookkeeping; the load-bearing network-diversity anchor for §4 is the IP-derived AS, not any
tag in this directory.

**Still deferred (unchanged):** the relay onion-forward handler + ingress listener (§1);
client hop selection, diversity, and the telescoping dialer (§2/§4); everything else in the
§9 list. This change stays inside `core/coldstart` + `cmd/coordinator`; it is **Part of #76**
and does not close it.

## Amendment (issue #142, 2026-07-25): the onion is implemented — and the chain starts one hop later than the spike assumed

> **Partly superseded — read the 2026-07-27 amendment at the end of this file before
> acting on anything here.** The mechanism described below (the client naming its
> first peeling hop in `connect{exitId}`) no longer exists: ADR-0042 removed that
> field's client direction. Three claims in this section are also corrected there —
> "the coordinator never learns your real exit" was false on every connect, "operator
> diversity is enforced" described nothing at depth 2, and the both-endpoints
> guarantee needs a proviso about the assigned relay. What this section says about
> the onion construction, per-hop authentication, and E2E survival of #60/#69 is
> unaffected and stands.

The construction this record accepted is now built and wired: `core/relaychain.go`
(client chain assembly + telescoping dial), the `hop:` branch of `exitTerminate`
(the peel), a relay onion ingress in `Start`, and `Config.RelayHops` /
`-relay-hops`, default `1`. Decisions 1, 3, 4, 5 and 6 landed as written. **Decision
2 landed with a materially different mechanism**, described below, which is why this
amendment exists rather than a note that the work shipped.

### The spike's first hop could not be built, and did not need to be

§4.1 assumed the coordinator-assigned relay `R₁` **peels** the outermost layer.
Implementation showed it cannot, for a reason the spike missed: Noise_NK
authenticates the responder by a static key the **initiator supplies up front**, and
the client never learns the assigned relay's key. The coordinator names that relay to
the client only through `wire.RelayTag`, which #56/ADR-0035 deliberately defines as
opaque and non-routable. Making `R₁` peelable therefore needs the coordinator to
publish the assigned relay's identity — a coordinator protocol change this issue was
scoped to avoid, and one that would hand a hostile coordinator a new lever.

**What shipped instead.** Exit ids already *are* X25519 public keys (#12/#60), and
the client already chooses which exit the coordinator pairs it with. So the client
names its **first peeling hop** in `connect{ExitID}`. The assigned relay
blind-splices to that node exactly as ADR-0033 ships today — `relayPipe`,
`handlerFor`, and `serveExit` are **not modified at all** — and the onion begins at
the node it was spliced to. The real exit is named only inside the onion.

So for `RelayHops = n` the path is one coordinator-assigned blind relay plus `n-1`
client-chosen peeling hops:

```
client → R₁ (blind splice, coordinator-assigned) → H₁ → … → Hₙ₋₁ → exit
```

`n` still counts the nodes between client and exit, so the property this ADR was
accepted for — at `n ≥ 2` no single node in the path sees both endpoints — holds
exactly as stated, and `n = 1` is still literally today's code path.

### This makes decision 2 *stronger* than the spike claimed, and one §4.2 sentence was wrong

§4.2 asserted the coordinator "learns **nothing** about `R₂…Rₙ` or the exit." Under
the spike's own mechanism that was **false**: the client would still have sent
`connect{ExitID: <real exit>}`, so the coordinator would have learned the exit on
every connect, exactly as it does at n=1. The shipped mechanism makes the sentence
true — the coordinator is told the first peeling hop and never sees the real exit.
The claim is retained because what ships now supports it, not because it was right.

**What the coordinator still sees, stated exactly:** that this client asked to
connect to node H₁ and was assigned relay R₁. It cannot tell a chained connect from
an ordinary one, does not choose H₂…Hₙ₋₁ or the exit, and cannot MITM any of them.

### Fail closed — the rule that governs every failure in the feature

Every way of failing to build the requested chain **fails the path**. None falls back
to a shorter one. A user who asked for a path no single relay can link, and silently
received a linkable one, is worse off than one who received an error, because they
would act on an assurance they no longer hold. Concretely, these all fail the
candidate and let selection move on: no signed directory; a directory with too few
distinct hops for the requested depth; an exit the directory has no address for; and
a coordinator that answered with the **TURN fallback** instead of a peer relay (on
that disposition the client is wired straight to H₁, which would then see the
client's own address *and* the real exit — precisely the linkage being bought away).

### Two safety lines the implementation had to add

- **A relay is not an exit.** A forwarding relay runs the same accept loop an exit
  does, so `exitTerminate`'s internet-egress paths are now gated on actually holding
  the exit role. Without it a relay would dial any `host:port` a client named. The
  gate also refuses a **hostile coordinator** that assigns a relay-only node a direct
  session — it cannot conscript a residential volunteer into egressing under their
  own ip.
- **A relay is not an open proxy.** A hop's next-hop address is attacker-chosen
  (completing the handshake needs only the hop's public key, which is public), so a
  forward is admitted only to an address named in the node's **signed** directory,
  and a node with no directory forwards nothing. `RelayIngress` without
  `RelayDirectory` is a construction error, not a listener that rejects everything.

### Other implementation facts worth recording

- **A relay that serves as a hop gets an X25519 identity**, derived exactly as an
  exit's is, because the client authenticates each hop against the key the signed
  directory publishes for it. Relays that serve no ingress keep their opaque random
  id, so no existing relay's identity moves.
- **The relay's ingress port is self-reported on register** (`wire.IngressPort`,
  consumed by the already-merged #124/#126 coordinator side). Only the port is a
  self-report; the coordinator joins it to the source ip it observes.
- **Operator diversity is enforced; AS diversity is not.** Hop selection spreads
  hops across the signed `Entry.Operator` tag and falls back to allowing a repeat
  only when the directory cannot supply enough distinct operators. The IP-derived AS
  diversity this ADR's #124 amendment calls the load-bearing anchor is **not
  implemented** and remains a child issue.
- **Chaining covers every client data path** — SOCKS CONNECT, UDP ASSOCIATE, and the
  pool's sustained-flow probe — through one seam (`dialE2E`), so no traffic class
  silently takes a shorter path than the user configured.
- **Direct-tier paths are untouched**, per decision 4: hop count applies only once
  the ladder reaches the relay tier.

### Still deferred

Per-hop relay-role admission credentials (§4.3); IP-derived AS diversity; relay-side
DoS controls; in-place directory refresh (a restart currently adopts a new one —
**shipped by the issue #27 amendment at the end of this file**); chain-aware
liveness beyond the existing stall detection; and NAT-traversed middle hops. This
change is **Part of #76** and does not close it.

## Relationship

Extends ADR-0033 (single hop is n=1) and ADR-0028 (the `ModeRelay` tier); preserves
ADR-0009 and ADR-0026/#69 through the chain; selects from ADR-0037's signed snapshot;
reuses ADR-0030/#96/#105 for failover.

## Amendment (issue #142, 2026-07-27): rebuilt on the ADR-0042 wire, and three claims corrected

The #142 amendment above records a mechanism that no longer exists, and three
statements in it — two of them repeated in user-facing flag help — were false as
written. This amendment supersedes it on those points. Everything it says about the
onion construction itself, the per-hop authentication, and the E2E survival of
#60/#69 stands unchanged and is unaffected by any of this.

### The client no longer names its hop in `connect{exitId}`

ADR-0042 removed the client's ability to name an exit at all: `connect{exitId}` is
the coordinator's answer, never the client's request. That deleted the mechanism the
#142 amendment describes. It also anticipated the replacement — §9 of that record
reserved a `firstHop` request field for this work and committed three things about it
before this code existed.

What ships now, matching those commitments exactly:

- **The client names its head in `connect{firstHop}`.** The coordinator pairs it with
  that node instead of choosing an exit, and `resolveFirstHop` consults no country, no
  ranking and no exclusion — the client is not asking it to choose.
- **The session records `exitID = ""`.** The coordinator does not know where a chained
  path terminates, and recording the head there would charge a hop with a terminator's
  load in the §3 ranking whose only discriminating term is the session count. A
  chained session is invisible to exit ranking rather than misattributed.
- **`connect{country}` is omitted on a chained request.** It means the terminating
  exit's country and nothing else, and a chaining client resolves its own exit, so the
  coordinator has no use for it — and not sending it keeps the user's egress
  jurisdiction off the wire.
- **Exit discovery is the signed coldstart snapshot.** `core/` reads exits out of it
  now (`relayDirectory.exitsIn`), filtered by the user's country, one chosen at random
  per connect. Random rather than best: a deterministic rule would give every client
  running this build the same answer for a given country and directory, which is both
  a fingerprint and a load magnet no coordinator could move.

A named refusal (`no-such-hop`) is added for a head this coordinator does not have
registered, which is the actionable case — it means the client's cached directory has
drifted and should be refreshed.

### Correction 1 — "the coordinator never learns your real exit" was false on every connect

The #142 amendment claims the shipped mechanism made §4.2's sentence true.
`cmd/node`'s `-relay-hops` help asserted the same thing to users. Both were wrong,
for a reason neither noticed: `reconnectModes` returns `[direct, relay]`, `chainFor`
returns no plan for a direct attempt, and the helper that produced the id to pair on
returned the **real exit** when there was no plan. So a client configured for three
hops put `connect{exitId: <real exit>, mode: "direct"}` on the wire — three times,
against UDP loss — before any chained attempt happened, and the coordinator logged
it against the client's source address.

Two changes make the claim true rather than restating it:

- **There is no exit id on the connect wire in any mode.** ADR-0042 removed the
  field's client direction outright, and `firstHopID` on an absent plan returns the
  empty string rather than falling back to an exit id. A method with no exit id to
  leak cannot leak one; the previous shape kept the most sensitive value in the design
  one nil-check away from the wire.
- **A chaining client is not offered the direct tier at all**, on either ladder. This
  is not about the leak — it survives the leak's removal. A direct path carries no
  chain, so taking one is a silent downgrade, and it was the *first* thing tried.

The cost is real and is now stated in the help text and the design doc: a chaining
client is slower and less available, because the tier that works when no relay is
free is gone.

### Correction 2 — "operator diversity is enforced" described nothing at depth 2

The sentence "Operator diversity is enforced; AS diversity is not" was true only in
the sense that code ran. `buildSnapshot` stamped `Entry.Operator` on **relay** entries
only, and a chain's head must be exit-role — it is reached by being named to the
coordinator — so the head always carried an empty tag, which is neither recorded as
used nor collided against. At depth 2 the head is the only peeling hop, so the control
did literally nothing at the depth most clients will run.

Exits now carry their operator tag; the `operators` map was never role-scoped, so this
reads a value that was already loaded. The claim is still narrower than "enforced" and
is now written that way in `selectHops` and in the design doc's §0.5 table: it
constrains a pair, so it starts to bite at depth 3, and `operators[id]` is empty for
every node absent from a curated operators file, so on an uncurated deployment it is
**inert**. Refusing to build chains on an uncurated network was considered and
rejected as the worse trade; saying so plainly is the correction.

### Correction 3 — "at n ≥ 2 no single node sees both endpoints" needs a proviso

`R₁` is coordinator-chosen and the client never learns its identity, so nothing
stopped `R₁` from also being one of the client's own peeling hops. `R₁` sees the
client; the last hop sees the exit; one node in both roles is one node holding both
ends, at any depth.

This is not only a hostile-coordinator concern. `pickRelay` excludes the node it
paired — the head — but not the client's later hops, which it cannot see. So an
**honest** coordinator can produce the collision by accident at depth 3 and above.

`verifyChainDisjoint` closes the accident. `wire.RelayTag` is a published function of
the relay's id, so the client recomputes it for every hop it selected and fails the
path on a match. The derivation is duplicated in `core` rather than imported (the two
binaries deliberately do not import each other) and both copies are pinned to the same
known-answer vectors, because a drift would silently stop the check from ever matching
rather than fail anything.

It does **not** close the attack. A coordinator that wants the collision reports a tag
that does not match the relay it wired, and no client-side signal contradicts it.
Against a coordinator actively colluding with a node in the path, this ADR's
unlinkability property does not hold at any depth. That is now stated in the design
doc's §7 and filed as issue #190 rather than claimed away.

### Smaller corrections

- **`firstHop` is honoured only on a relay-mode connect** (`hop-needs-relay-mode`).
  The client half already worked this way — `chainFor` builds a plan for no other
  mode — but the coordinator inferred "chained" from the field's presence alone, so
  the wire accepted `{mode:"direct", firstHop:X}` and paired the client straight to
  the node it named. That is exact-exit pinning (#146, ADR-0042 §2) reconstructed
  through the field ADR-0042 §9 opened, reachable by any modified client. It is now
  refused before anything is paired, for `direct` and for an absent mode alike — the
  latter because the handler's dispatch treats an unset mode as relay, so a guard
  written against the literal `"direct"` would leave the field open to a client that
  simply omits it. What this does **not** close, and ADR-0042 §9 now states rather
  than argues away: a client may ask for relay mode, name a node, and terminate there
  instead of peeling. No coordinator can detect that without reading the onion it
  exists not to read.
- **A depth above `RelayHopsMax` is refused at construction**, not clamped with a
  logged notice. Clamping is the silent downgrade the fail-closed rule forbids
  everywhere else in this feature: an operator who asked for 6 and was given 4 without
  an error has a weaker path than they requested. The ceiling is now checked in exactly
  one place.
- **`RelayIngress` requires a persistent `ExitKeyHex`.** A forwarding hop's node id is
  the key clients authenticate it against, published in a directory clients cache, so
  deriving it from a fresh keypair each start made the node unreachable as a hop until
  a new snapshot propagated — intermittently broken rather than visibly misconfigured.
  `-exit-key`'s help was scoped to exits, so a relay-only operator had no reason to set
  it; both the refusal and the help text are fixed.
- **A hop refuses to dial itself.** Its own addresses are in the directory it checks
  targets against, so a self-target passed the allow-list and the node spliced to
  itself, peeling and forwarding again — one attacker socket becoming two at every
  pass. The check is against the node's own **directory** entry, not its local
  listener: a hop binds a wildcard or an OS-assigned port while upstreams dial the
  address the coordinator observed, so a guard written against the listener would pass
  every real self-dial. This is the cheap half of #25 and does not bound a ring of
  nodes pointed at each other. (Superseded on that last point by the issue #25
  amendment at the end of this file, which bounds the ring without a hop counter.)
- **"At depth 1 every code path in this file is unreachable" was false.**
  `setupRelayChaining`, `loadRelayDirectory` and `relayForward` all run at depth 1, and
  `relayForward` is an intermediate hop's entire hot path. The claim is about the
  client's dial path, and is now written that way.

### On the test suite, because the corrections above were not found by it

A mutation audit found that five independent edits switching chaining **off** in
production left the whole suite green. The cause was structural rather than a set of
gaps: every onion test called `dialChain` directly with a hand-built `chainPlan`, on
an `Engine` literal whose `RelayHops` was zero — so `chaining()` was false on the very
engines used to prove chaining worked, and nothing reached the selection, wrapping or
wire code at all.

The fix is an acceptance test built the other way round: through `New()` with
`RelayHops` set, driving traffic in through the SOCKS listener `Connect` bound, with
only the coordinator and the peer relay's transport faked. A second suite drives the
real coordinator handler, because the client half had been tested against a fake
coordinator and the coordinator half against nothing — so a build that ignored
`firstHop` entirely passed the repository. 19 mutations now run with no survivors.

## Amendment (issue #11, 2026-07-28): the ingress port is range-checked, and the operator tag's trust bound stated

Two hardening items the independent review of #124 (PR #126, §9 item 3) raised and
recorded as non-blocking. Neither is a correctness fix; the load-bearing
network-diversity anchor is unchanged and remains the client-side IP-derived AS of §4.

**The self-reported `IngressPort` is range-checked at register.** Only the *port* of a
relay's forwarding ingress comes from the node — `buildSnapshot` supplies the host from
the address the coordinator observed, which is what lets §4 trust an IP-derived AS — and
nothing checked that the port was a port. A relay reporting `70000`, or a negative
number, was advertised in the **signed** directory as `observedIP:70000`: an address no
client can dial. A port outside `1..65535` is now ignored at register, so such a relay
advertises no ingress and is, by `Entry.RelayEligible`, simply not a hop.

Ignoring the port rather than refusing the register is deliberate. The relay is otherwise
perfectly serviceable — it can still splice, still act as a mesh-walk courier, still
carry a country — and only its relay-*eligibility* depends on a usable port. Refusing the
whole registration over one malformed advisory field would cost the network a working
node to punish a mistake that only harms the node making it.

It is worth doing at all, given the relay only harms itself and §4 rejects the address on
dial, because the signed snapshot is the artifact this project asks clients to trust.
Publishing an entry the coordinator could see was undialable at register time spends a
client's hop-selection attempt and its dial timeout on a node that was never going to
answer.

**The operator tag is trustworthy only as far as node-id authentication is.** §6/§7 and
the #124 amendment above establish that `Operator` is coordinator-side truth rather than
a node self-report, and that is true and it is the reason the tag is worth signing at
all. It is not the whole bound, and the missing half is worth stating plainly: the tag is
keyed by the node id (`operators[m.ID]`), and the node id is **self-asserted at
register**. With admission (#42) disabled — which is fail-open, and the default — a node
can register under an arbitrary id and inherit whatever operator assignment that id
carries in the coordinator's file. The tag therefore says "the operator's file assigns
this *id* to that subtree", not "this *node* belongs to that operator", and those two
statements come apart exactly when ids are not authenticated.

That stays within the advisory-only model §6 already declares, and it does not change
what the tag is used for. What it changes is how much weight the sentence "operator
identity is not IP-derivable, so it is legitimately signed" can carry: signing binds the
tag to the coordinator's assertion, and the coordinator's assertion is bounded by
whatever authenticates the id it is keyed on. **The real diversity anchor for §4 is the
IP-derived AS, not this tag** — an observed address cannot be re-registered under
somebody else's name — and enabling admission (#42) is what raises the operator tag from
advisory to something a hostile node cannot simply claim.

Part of #76; closes neither it nor #124.

## Amendment (issue #27, 2026-07-28): in-place directory refresh

The "Still deferred" list above named this the neighbourhood of §9 item 6; it turned
out to be its own, smaller, independent change. §9 item 6 (chain liveness + rebuild)
is about a hop *dying mid-session*; this is about the directory a client selects hops
*from*, or a relay admits forwards against, going stale while the process keeps
running — the rough edge §10.5 of the design doc named plainly: "restart to adopt a
fresh snapshot."

**What shipped.** `Config.RelayDirectoryPath` (core, `cmd/node`'s `-relay-directory`
help text, and the Windows client's Settings "Relay hops" directory field, issue #28)
names a file `reloadRelayDirLoop` re-reads on an interval (`core/relaychain.go`),
started from `Start` exactly where `reloadCRLLoop` (issue #90) is — the client-side
CRL-reload shape this record already cites as precedent, applied to the directory
instead of the revocation bundle, and the same `atomic.Pointer`-swap shape
`cmd/coordinator`'s `reloadRevocationsLoop` uses for its revocation list. A reload
runs the fresh bytes through the *identical* `loadRelayDirectory` call construction
uses — same signature verification under `RelayDirectoryKey`/`MeshPubKey`, same
expiry check, same "a node id that is not a key cannot be authenticated as a hop"
filtering — so a reload can only ever produce a directory exactly as strict as a
fresh `New()` would, never a looser one. `RelayDirectory` itself (the inline bytes)
must still be set and still gates construction exactly as before; the path only says
where a *later* copy comes from.

**Fail-closed, unchanged.** A reload that cannot read the file, cannot verify it, or
finds it itself expired is logged and the *previous* directory keeps being enforced
— never a partial one, never nothing. This is the same posture `reloadCRLLoop`
already established and this file's own doc comment calls "the single most important
behavioural property in this file": a hop that quietly started admitting forwards to
`nil`, or a client that quietly stopped chaining, on a transient misread (an operator
mid-write) or a late re-sign, would be a worse failure than the staleness this issue
fixes. `core/relaychain_reload_test.go` pins this per failure mode (unreadable,
unverifiable, expired) and the pickup and Start-wiring paths; every one of those five
tests was mutation-checked by hand against the shipped code — the specific mutation
each catches, and its result, is recorded in the PR that shipped this amendment.

**The mesh-walk courier was considered as the refresh source, and rejected.** The
design doc's Dependency consequence and this record's §9 both point at "the
mesh-walk courier the node may already run" as a plausible source of a live
directory. It does not fit this seam, for two independent reasons:

1. **Courier-serving is a `cmd/node`-only concern.** A node opts into serving its
   cached snapshot to recovering peers via `-courier-listen`/`startCourier`
   (`cmd/node/main.go`); `core` itself never runs a courier, so `core.Engine` has
   nothing to read a live snapshot out of even when the process it's embedded in
   happens to also be running one.
2. **Mesh-walk *recovery* (the client half `core` does own — `MeshPeers`/`MeshProof`,
   `Engine.NeedsRecovery`) is a one-shot, fail-cold escape hatch for "every
   coordinator is unreachable," not a standing cache of a live directory.** It exists
   to answer a different question — can this client reach *any* rendezvous point at
   all — and is wired through the connect path (`core/pool.go`'s dead-pool handling),
   which this change does not touch. Sourcing directory freshness from it would
   couple two failure domains that are orthogonal in practice: a coordinator can be
   perfectly reachable for years while a relay directory quietly ages past its
   validity window, and conversely a client recovering from a dead coordinator pool
   has nothing to say about whether its *chaining* directory is fresh.

   A plain re-read of the same signed-snapshot source construction already trusts —
   with no new failure coupling, no dependency on whether this node also runs
   mesh-walk recovery, and reusing `loadRelayDirectory` verbatim — is simpler and
   strictly no less safe. If a future change wants push-based freshness (the courier
   or coordinator notifying a node rather than a poll), it can still layer on top of
   `reloadRelayDir`'s verify-and-swap without revisiting this decision.

**What this did not need to touch, and what it did.** The chain-building and
onion-forwarding logic in `core/relaychain.go` is unchanged — `loadRelayDirectory`,
`selectHops`, `dialChain`, `relayForward` read exactly the fields they always did.
What changed is how `Engine` *holds* the directory: `relayDir` became
`atomic.Pointer[relayDirectory]` instead of a plain `*relayDirectory` (`core/
engine.go`), so a reload can swap in a freshly verified directory without a lock and
without a reader ever observing a torn or partially-updated one — every
`*relayDirectory` a `Load()` can return is itself immutable, exactly as it was before
this issue, so the only new invariant is that *which* immutable directory `Load()`
returns can now change between two calls in the same process's lifetime, and a chain
build loads it once and threads that single snapshot through its own call rather than
re-reading `Load()` per field.

**Still deferred:** chain liveness + rebuild (§9 item 6); IP-derived AS diversity;
relay-side DoS controls; per-hop relay admission credentials; NAT-traversed
intermediate hops; coordinator-independent relay identity (#190). This change is
**Part of #76** and does not close it.

## Amendment (issue #25, 2026-07-29): forwarding is bounded per previous hop and in aggregate; no hop counter

§6 committed relays to "rate-limit per previous hop and in aggregate". #142 shipped
the forwarding path without it. `relayForward` metered forwarded bytes against the
operator's declared limits (ADR-0040) and refused to dial itself, and that was the
whole of its self-defence: **one neighbour could hold an unbounded number of
forwarded circuits open on any node in the mesh**, and nothing bounded a cycle of
nodes pointed at each other. This lands the caps §6 named, and records two decisions
the issue text left open.

**What landed** (`core/relaychain.go`, `core/engine.go`, `cmd/node`):

- **A per-previous-hop and an aggregate cap on concurrent forwarded circuits**
  (`forwardLimits`), defaulting to 32 and 256. Zero means the default, never
  unlimited — forwarding is already opt-in behind `RelayIngress`, and an operator
  who threw that switch did not thereby ask to be unbounded. A per-peer value above
  the aggregate is clamped to it, since otherwise the aggregate always binds first
  and the per-peer cap is silently inert.
- **A circuit over either cap is refused, never queued.** Queueing converts an
  occupancy bound into a latency bound and leaves the node holding exactly the state
  the cap exists to deny it.
- **An optional per-previous-hop byte pace** (`-relay-forward-peer-rate`, off by
  default). Bytes are *paced*, not dropped — the split is deliberate and is the same
  rule applied to two different resources. A circuit is admission: you either take
  the state or you do not. A byte is throughput: cutting a splice mid-copy destroys a
  circuit already admitted and paid for, to save bandwidth pacing reclaims anyway
  (ADR-0027 makes the same call for the reality splice). Aggregate forwarding
  bandwidth was already bounded by ADR-0040; this divides that budget between
  neighbours, which is the part §6 asked for and #142 did not have.

### Why the previous hop, and what that key cannot do

It is the only key available: an intermediate hop cannot see the client — that is the
point of the onion — so it cannot meter the party actually responsible for a circuit.
§6 already said this; the consequence is worth stating rather than discovering.

**A hop's budget is shared by everything arriving through the same neighbour.** An
attacker routing through a busy honest hop spends that hop's budget and degrades the
honest circuits behind it. What the key does buy is **containment**: that attacker
cannot spend any other neighbour's budget, and cannot take the node, because the
per-peer ceiling is a fraction of the aggregate. Bounding the blast radius to one
neighbour is the most this key can do, and it is worth having. It is not the same
thing as fairness between clients, and nothing here should be read as claiming it.

### One §6 sentence was too strong

§6 says "Forwarding is 1:1 with no amplification vector", and the issue text repeated
it. That is true of **bytes** and false of **occupancy** the moment a cycle exists.
A→B→C→A is 1:1 on every link and still turns one attacker socket into a slot on every
node of the ring, once per lap, for as many laps as the attacker builds. The
self-dial guard #142 added closed the degenerate one-node case and said so; the
general case is what this amendment closes.

### The ring: bounded by the caps, and no hop counter added

The obvious fix is a hop counter — a TTL each node decrements and refuses at zero.
**Rejected**, and the reasoning matters more than the conclusion because the
alternative is not obviously wrong.

A hop counter in the onion layer does not work at all: each hop shares a key with the
client and nobody else, so the field would be *written by the client*, and an attacker
building a ring writes 1 every time. Making it unforgeable means each hop decrements
and re-seals it — and a hop can only re-seal what it can read. **Unforgeable and
non-leaking are mutually exclusive here.** The workable shape is therefore a
*cleartext* TTL outside the encryption, rewritten hop by hop, clamped on receipt so an
attacker cannot start it high. That would bound the ring. It was rejected on cost:

1. **The caps already bound the ring, by the specific mechanism the counter was
   wanted for.** Every revisit to a node in a cycle arrives from the *same*
   predecessor — its ring-predecessor — so every lap past the first draws on one
   per-previous-hop budget and the ring runs out of it. Measured, not assumed:
   `TestRingOfForwardingNodesTerminates` builds three real forwarding nodes in a cycle
   and it dies at depth 10 with a per-peer cap of 3. A cycle of *m* nodes at per-peer
   cap *P* terminates around *mP* layers, and every slot it took came out of a
   per-peer bucket, so it starved no other neighbour on the way.
2. **There is no autonomous spin to stop.** The chain does not self-extend: each lap
   costs the attacker another full Noise_NK handshake driven through the whole chain
   built so far, so the attacker's cost per lap grows with depth while the mesh's
   stays flat. "A loop consuming a slot on every node indefinitely" describes the
   occupancy, not a runaway process — nothing continues once the attacker stops
   paying.
3. **The aggregate cap is the ceiling regardless of topology.** Mesh-wide forwarded
   occupancy is at most the sum of every node's aggregate cap. A cycle cannot exceed
   that; it can only fill it in a particular shape. A hop counter does not lower that
   number by one circuit.
4. **The counter costs a property this design spends its whole complexity budget
   on.** Today an intermediate hop knows it is not first (it was reached by a plain
   dial to its ingress, not the coordinator-brokered rendezvous of §5) and not the
   exit (its target carries `hop:`). It does *not* know how many hops precede it, or
   whether the node it dials is the exit or one more relay. A readable depth, against
   a published `RelayHopsMax`, converts that into position: at depth 3 the middle hop
   learns the address it is dialing **is the exit**. Handing one node the exit's
   identity for a flow whose predecessor it also knows is precisely the linkage §2
   and Correction 3 deny. As cleartext between hops it is worse than a leak to the
   hop — it is a position fingerprint for any passive observer of a single inter-hop
   link, which does not exist today.

So: the bound is **occupancy, taken where the resource is spent**, and the onion
keeps its property that a hop knows its two neighbours and nothing else.

**What would reopen this.** Argument 2 is the load-bearing one. If a change ever made
a cycle cheap to sustain without per-lap attacker cost — a hop that re-dials on its
own, or server-side chain extension arriving with NAT-traversed middle hops (§9 item
9) — the ring stops being attacker-paced and this decision should be taken again.

### The failure mode: a refusal is fail-closed *and* legible

Refusing a forward fails the client's chain build. That half was already settled by
this ADR's fail-closed rule — the path fails and selection moves on, never a silent
fall back to a shorter chain — and nothing here changes it.

**The sheddability test both ADR-0043 and ADR-0045 apply lands clearly on "shed".** A
saturated hop is the most sheddable failure in the system: the client picked it at
random out of a directory of many and can pick another immediately, which is the same
structural reason ADR-0043 fails closed (a pool with rotation) rather than a template
borrowed from it. ADR-0045's opposite answer turns on a condition no client can
rotate away from, which is not this.

But that test answers *whether to refuse*, not *whether the refusal is legible*, and
here the second question has teeth the other two never had. A refused coordinator and
a crashed coordinator both mean "rotate", so ADR-0043/0045 never needed the
distinction. A refused hop and a **dead** hop do not mean the same thing: a dead hop
should be dropped from the client's candidates, a full one is a good hop worth coming
back to. Before this they were the same handshake failure on the next layer.

**So a hop that declines says so, on its own Noise channel to the client.** The
channel already exists and needs no new field: the telescoped construction negotiates
layer *i* end-to-end between the client and hop *i*, so a hop can seal a statement the
client alone can read. It is authenticated (only the holder of the key the client
picked from the **signed** directory can produce it), confidential to every other hop,
and — the property that decided the shape — it carries **no new information to
anyone**. It travels client↔hop on a channel that already exists. That is exactly why
it is a message and not a field: a field in the onion layer is read by every hop, this
is read by one endpoint.

Two consequences worth recording:

- **Every deliberate refusal carries it**, including the older self-target,
  not-in-mesh and forwarding-disabled cases. The signal means "a hop decided", so its
  absence has to mean "no hop decided". Signalling only the new refusals would leave
  silence ambiguous and the client no better off.
- **It reports a reason token, never a number.** `node-busy` discloses one coarse bit
  of load to a party that already holds a circuit's worth of evidence; occupancy
  counts would be a load oracle anyone could poll to map the mesh's spare capacity. A
  hostile hop can of course claim to be busy — but it can already refuse by simply not
  forwarding, and this signal only ever lowers a client's opinion of a hop, never
  raises it, so there is nothing to gain by lying.

Operator side, the refusals are edge-triggered: the first refusal of a saturation
episode is logged and the episode's total is logged when it ends. Logging every
refusal would hand an attacker a log amplifier at a rate they choose, on a node that
is already declining work.

**Still deferred:** chain liveness + rebuild (§9 item 6); IP-derived AS diversity;
per-hop relay admission credentials; NAT-traversed intermediate hops;
coordinator-independent relay identity (#190). This change is **Part of #76** and does
not close it.

## Amendment (issue #26, 2026-07-29): per-hop relay-role admission credential verification

Decision 3's "per-hop relay-role admission credentials are an optional follow-up" —
repeated as still-deferred in every amendment above — now ships. `dialChain` no
longer passes `nil` as the verify func for a hop layer; each hop's admission
credential is checked exactly as an exit's already was, extending hostile-node
rejection (#60/#69) from the exit to every intermediate hop. The ordering property
this ADR already relies on — layers verified outermost-first, so a bad hop fails
before the client tunnels anything through it — holds unchanged: the check runs as
part of completing that hop's own `clientHandshake`, the same call that already
authenticates its key, so it inherits the ordering for free rather than needing new
sequencing.

**A second, independent anchor — not the exit anchor reused.** `Config.RelayAdmissionPubKey`
is a new client-side field, separate from `AdmissionPubKey`. ADR-0047 §7/§9's
Consequences section noted that the client's existing exit anchor, built via
`admission.NewVerifier` (which scopes one key to *every* role), would already answer a
`RoleRelay` question for free if simply pointed at it — "if a client ever needs a
separate relay anchor, that is a `NewAuthoritySetVerifier` call and nothing else on
the path moves." This shipped the separate anchor rather than the free reuse, and the
reason is the fail-open decision below: reusing the exit anchor would mean every
existing client that had only ever configured `AdmissionPubKey` for exit verification
starts verifying hops too, the moment it upgrades — against relays that, before this
issue, were never asked to present a `RoleRelay`-authorized credential at all. That is
exactly the silent, retroactive tightening the two named sub-decisions below rule out.

**Fail-open posture: the relay anchor is its own gate, independent of the exit
anchor.** No `RelayAdmissionPubKey` configured means hops are not verified
(fail-open), matching the #42/#60 posture — but the gate is `RelayAdmissionPubKey`
specifically, never `AdmissionPubKey`'s mere presence. A client with an exit anchor
and no relay anchor therefore sees no change at all: it neither starts failing
chains against hops that predate this feature, nor stops checking anything it was
checking (the exit check is a completely separate code path, untouched). Per-hop
verification only turns on when an operator opts into the new anchor deliberately.

**A hop whose credential fails verification fails the WHOLE chain — fail-closed, not
de-selection.** The issue named both options. De-selecting just the bad hop and
retrying with another was set aside: it needs candidate-exclusion state that lives in
hop *selection*, above `dialChain`, which this change does not touch or extend.
Fail-closed needs nothing new — the verify callback's error surfaces through the
exact path a substituted hop's failed Noise handshake already takes, since both are
just `clientHandshake` returning a non-nil error — and it matches this ADR's own
"Fail closed — the rule that governs every failure in the feature" section above.
Revocation is checked against the same oracle the exit anchor's CRL builds
(`Config.AdmissionCRL`/`AdmissionCRLPath`) rather than a second `RelayAdmissionCRL`:
ADR-0047 already established that one revocation list covers every authority because
a serial names a credential, not an issuer, and nothing about a second anchor changes
that.

**One behavioral asymmetry from its sibling anchor, worth stating plainly.**
`AdmissionPubKey` is validated once, eagerly, in `New()`, before the engine exists —
a malformed value is a construction error. `RelayAdmissionPubKey` is validated
lazily: `dialChain` reads it directly off `Config` and builds the (small, cheap)
per-hop verifier itself, once per chain dial, rather than `New()` building it once
and caching it on an `Engine` field the way it does for the exit anchor. A malformed
value is still a hard failure — the chain fails rather than silently trusting every
hop — but it surfaces from the first chain dial that needs it, not from `New()`.
This is a narrower construction-time guarantee than every other admission-related
field in `Config` carries, traded to keep this change entirely inside
`core/relaychain.go`, `core/exit_admission.go`, and the `Config` struct itself,
touching nothing in `Engine`'s construction path. Revisiting it — eager construction
and validation alongside the exit anchor's — is a reasonable follow-up and does not
require reopening any decision recorded above.

Still deferred: chain liveness + rebuild (§9 item 6); IP-derived AS diversity;
NAT-traversed intermediate hops; coordinator-independent relay identity (#190). This
change is **Part of #76** and does not close it.

## Amendment (issue #24, 2026-07-30): chain liveness — a dead hop is discarded and the chain rebuilt

§9 item 6, named as still-deferred in every amendment above and described at the head of
the issue #27 amendment as "a hop *dying mid-session*", now ships. This is the last of
this record's implementation children.

No new decision is taken here, which is why this is an amendment and not ADR-0049.
Decision 5 already settled the policy — "a broken circuit is discarded, not spliced" —
and §9 item 6 already named the shape: client-side detection, a full rebuild, bounded
retry. What follows is that decision built, plus four sub-decisions the issue text left
open, each of which is a consequence of a decision already recorded above rather than a
replacement for one.

### What was actually broken, which is not what "detected only as a stall" suggests

The pre-#24 story was that a dead hop surfaced as an end-to-end stall and recovered
through the ADR-0028 sustained-flow probe or the ADR-0030 reconnect. Only the first half
was true. Neither mechanism could fire:

- **ADR-0030's `reconnectLoop` and ADR-0028's `maintainPath` both wait on
  `sess.Closed()`, and the session does not close.** A chained session terminates at the
  chain's HEAD (`connect{firstHop}`); a hop dying *behind* the head leaves the
  client↔head transport perfectly healthy. So the failover machinery never woke up.
- **The sustained-flow probe runs at selection time only.** It proves a chain carried
  bytes when the pool committed to it, and says nothing about the chain an hour later.

What actually happened was worse than a stall: the plan was fixed on the session for its
lifetime, and a chain is telescoped per STREAM (`dialE2E`), so every subsequent SOCKS
connection re-dialed the same dead hop and failed identically, indefinitely, over a
session nothing had any reason to drop. The coordinator could not help, exactly as the
issue says: `reselectDeadRelays` (#96/#105) only ever covers the assigned blind relay,
and by construction the coordinator does not know which nodes are in the chain past the
first.

### 1. Detection is per layer, inside `dialChain`, and it names the hop

`dialChain` now arms a per-layer guard (`stallGuard`, budget `chainLayerTimeout`) and
returns a `*chainDialError` carrying which hop to hold responsible and why
(`hopDead`/`hopStalled`/`hopRefused`/`hopRejected`).

The bound is needed for one specific failure and not for the obvious one. A hop that is
simply *gone* was already bounded: the hop before it gives up its own forward dial after
`forwardDialTimeout` and drops the circuit. The unbounded case is a hop that **accepts
the TCP connection and then answers nothing** — a wedged process, an ingress port since
taken over by something that is not a Bacchus node, a middlebox that completes
handshakes it does not carry. Then the upstream dial succeeds, the splice stands, and
the client's layer handshake blocks on a read that never returns: `clientHandshake` and
`noiseConn` carry no deadline, and the callers disagreed about imposing one (the pool's
`validateSession` did; `handleSocksConnect` bounded only `OpenStream`; so did
`core/udprelay.go`'s ASSOCIATE path).

Per layer rather than one budget for the whole dial, because each layer waits on exactly
one thing — the hop before it completing one outbound dial — so an overrun is
attributable. One shared budget is not: a legitimately slow early layer would spend it
and get a healthy later hop blamed and cooled, which is precisely the misattribution a
cooling memory must not accumulate. The cost is that the worst case multiplies by depth;
that is bounded, every caller's own deadline still cuts it shorter, and the alternative
buys a smaller number by cooling the wrong nodes.

Attribution rule, stated because it is a judgement and not a lookup: **the suspect is the
hop whose own layer did not complete.** Every hop before it demonstrably carried its
layer to completion, so it is alive. The one exception is a sealed refusal (issue #25),
which identifies its author explicitly and is therefore attributed to the *previous* hop
— the one that decided — and not to the layer that was in flight when it arrived.

### 2. The rebuild lives where streams are opened, because §5 leaves it nowhere else

`dialChainedStream` (`core/relaychain.go`) opens the stream, telescopes over it, and on a
liveness failure cools the suspect, builds a **fresh** chain, installs it on the session,
and retries over a **new** stream. `handleSocksConnect` and the pool's `validateSession`
now reach the exit through it. It also applies the caller's context to the handshake and
not merely to `OpenStream` — which is what `validateSession` already arranged with a
watchdog of its own, and which `handleSocksConnect` lacked; on an unchained path that is
the caller's existing 15s budget covering the handshake it was always meant to cover, not
a new bound and not a shorter one.

That placement is forced by decision 5, not chosen for convenience. Repairing in place —
splicing a replacement hop onto the layers already standing — would have to re-key every
downstream layer and would tell the surviving hops which of their successors died. So the
circuit is discarded whole; the outermost handshake is spent, therefore the stream it was
spent on is spent too, and a rebuild needs a new one. `dialE2E` is handed a stream and
cannot make another, so the retry cannot live there.

**Reusing the head is not in-place repair.** A rebuild keeps `hops[0]` and re-chooses
everything behind it, including the terminating exit. The head is not the client's to
re-choose: the coordinator paired the session to that node and layer 1's Noise_NK runs
against its static key, so a re-headed plan would hand layer 1 a key nobody in the path
holds and every stream would fail authentication — a worse outcome than the dead hop.
Nothing of the broken circuit survives; the head being the same NODE is a selection
outcome the session forces, and the ADR-0038 §5 property (no re-keying, no leak of which
hop died) holds unchanged.

**A dead HEAD escalates instead of rebuilding.** Rebuilding behind it cannot move off it,
so the client cools it and drops the session, which hands the problem to the machinery
that *can* replace a head: `reconnectLoop` / `maintainPath` re-run `chainFor`, and the
cooled head is now avoided. This is the client's own version of the coordinator's #96
relay-dead nudge, for the one node the coordinator cannot nudge about.

### 3. Failed hops sink into a parallel cooling memory, not a widened `candCooling`

The issue asked for failed hops to go into "the existing cooling/health memory". That
memory (`markCandidateCooling`/`candidateCooling`, `core/pool.go`) is keyed by
`selection.Candidate` — a transport, a country and a mode — and cannot hold a hop. This
ships `markHopCooling`/`hopCooling`, a parallel map in the same style, for three reasons
rather than as a shortcut:

1. **Different keys.** Widening one map to hold both means `map[any]time.Time`, which
   accepts anything and loses the compile-time guarantee that only candidates reach the
   candidate memory.
2. **Different meanings.** A cooling *candidate* is sunk to the back of its tier and
   still raced; a cooling *hop* is skipped when the directory can spare it, because a
   chain either contains a node or it does not — there is no back of the tier for a hop.
3. **Different lifetimes, for reasons specific to each.** `candCooldown` (30s) waits out
   a censor's interference; `hopCooldown` (5 min) waits out a volunteer machine
   restarting, saturating, or drifting off the directory.

What the two share is the shape, and that is kept: an expiring mark under its own lock,
read through a predicate the selector calls, never a removal. The expiry is load-bearing
— a hop that refused because it was full (§6) is a perfectly good hop to come back to.

**Avoidance is a preference, not a filter, and that is not a breach of the fail-closed
rule.** If every alternative is cooling, selection falls back to reusing one and says so.
The fail-closed rule forbids silently handing the user a *weaker* path than they
configured — a shorter chain, an unchained path, a clamped depth. A chain of the full
requested depth with full diversity that happens to include a node which failed a minute
ago is exactly as strong as the one they asked for; it is only less likely to work.
Refusing would turn one hop's bad minute into a client that cannot connect.

A rebuilt chain goes through `buildChainHeaded` like any other, so it is reported by the
same `hopDiversity.degraded()` notice (#23/#52): a rebuild is not a way to obtain a chain
that skipped the diversity report and reads as healthy.

### 4. An admission rejection is NOT routed around — #26's decision is not reversed

`chainDialError.recoverable()` excludes `hopRejected`. Issue #26 decided that a hop whose
admission credential fails verification fails the whole chain — "fail-closed, not
de-selection" — and set the alternative aside because it needed candidate-exclusion state
in hop selection that did not exist. This issue builds that state, and deliberately does
not use it for that.

The line is worth stating on its own merits rather than as deference. A liveness failure
means the hop did not answer, and rebuilding is recovery. A verification failure means the
hop *did* answer and the client's own anchor refused it; rebuilding around that would walk
the client hop by hop through the directory looking for one whose credential passes,
turning a hard refusal into a search and handing whoever controls the directory
`chainRebuildMax` attempts per stream. The node is still cooled — declining to rebuild
*now* and preferring somebody else *next time* are separable, and only the first is #26's
decision.

### Bounds, and what stops the spin

`chainRebuildMax` (2) caps rebuilds per data-path dial. The case it exists for is not a
directory too short to build a chain — `errChainTooShort` already refuses that
synchronously — but a directory with just enough hops to build a chain and not enough to
build a *different* one: there every rebuild legitimately succeeds and every dial over it
legitimately fails, and nothing but a ceiling ends it. Two, for the same reason
`countryAttempts` is two: each attempt spends a full telescoping dial serially inside one
caller, and beyond that the cross-candidate failover is what should be doing the work.
The give-up is logged, because "rebuilt twice and still failed" and "failed" are different
operational stories and only the first says the directory cannot route around its own
failures.

A second, non-counting bound: a rebuild is only possible while the head is still a node the
signed directory names (`errChainNoPinnedHead`). A reload (#27) that dropped it leaves
nothing to pin, and inventing a different head is the authentication failure described
above.

Concurrent streams that fail together produce **one** rebuild, not one each:
`chainedSession.plan` became an `atomic.Pointer` (the same hot-swap shape `relayDir`
already uses) and the install is a compare-and-swap, so the first dial to finish installs
its chain and the rest dial over that one instead of discarding their own work.

### Honest limit: one client data path does not retry — **closed by the #82 amendment below**

`core/udprelay.go`'s UDP ASSOCIATE path calls `dialE2E` directly, so it gets the per-layer
stall bound and the attribution — both of which live inside `dialChain` — and it picks up
a chain rebuilt by any other path, since it reads `planOf(sess)` per associate. It does
not itself open a second stream and retry. That is a file another lane owned in the wave
this shipped in, not a design position; moving it onto `dialChainedStream` is a one-line
change and the natural follow-up. Until then a UDP association is the one path where a hop
dying is observed but costs that one association.

> This paragraph as first written also credited the path with **the cooling**, which was
> not true: cooling is applied by `dialChainedStream`, never by `dialChain`. Corrected in
> place rather than left standing, since it understated the gap it exists to disclose; the
> #82 amendment records what the check found.

**Still deferred:** IP-derived AS diversity; NAT-traversed intermediate hops (§9 item 9, a
tracked non-goal — #30); coordinator-independent relay identity (#190). §9's
implementation list is otherwise complete. This change is **Part of #76**; it closes #24
and does not close #76 itself.

## Amendment (issue #82, 2026-07-30): the UDP data path retries too, and the gap was one behaviour wider than disclosed

The limit the #24 amendment disclosed above is closed. `core/udprelay.go`'s
`serveSOCKSUDPAssociate` now opens its end-to-end channel through `dialChainedStream`
instead of calling `OpenStream` + `dialE2E` itself, so all three client data paths — SOCKS
CONNECT, UDP ASSOCIATE, and the pool's sustained-flow probe — reach the exit through the
seam that can rebuild. No new decision: decision 5 and §9 item 6 already settled both the
policy and the shape, and this is the last call site moved onto them.

### What the old call site actually inherited, which is less than was written down

The #24 amendment credited the direct-`dialE2E` path with the stall bound, the attribution
**and the cooling**. Checking the call sites rather than the prose: `markHopCooling` has
exactly one production caller, `dialChainedStream` (`core/relaychain.go`), and `dialChain`
neither calls it nor calls `recoveryFor`. So the split ran:

| Behaviour | Lives in | The old UDP path had it |
|---|---|---|
| Per-layer stall bound (`stallGuard`) | `dialChain` | yes |
| Fault attribution (`chainDialError.suspect`) | `dialChain` | yes — as a value in the returned error |
| Cooling the suspect (`markHopCooling`) | `dialChainedStream` | **no** |
| Dead-head escalation (`chainRepath`) | `dialChainedStream` | **no** |
| Rebuild + retry on a fresh stream | `dialChainedStream` | **no** |
| Picking up another path's rebuilt chain | `planOf(sess)`, read per associate | yes |

The correction matters in one direction only, and it is the unflattering one: the path was
computing an attribution and discarding it. A UDP association that met a dead hop named the
right node in an event message and cooled nothing, so the *next* association was free to
select that same node — the failure did not merely cost one association, it failed to teach
the client anything. "Observed and remembered" was half right; only the observing happened.

Recorded rather than quietly fixed because the same sentence had been carried into the
issue text, and the ADR is where a reader would check it.

### Why the retry could not have lived at the old call site

Unchanged from decision 5, and restated because it is what makes this a move rather than a
copy. A broken circuit is discarded, not spliced, so the outermost handshake is spent and
the stream it was spent on is spent with it. A caller that is *handed* a stream cannot make
another; `dialChainedStream` owns the session and can. That is the whole reason the retry
is a property of the caller rather than of `dialE2E` — and the whole reason moving one call
site is enough to get it.

One consequence carried over with the move: the association's existing 15s budget now
bounds the handshake and any rebuild attempts under it, not merely `OpenStream`. That is
the same widening `handleSocksConnect` took in #24 — the caller's own deadline applied to
the work it was always meant to cover, not a new number.

### On the Consequences list's "one seam"

The Consequences list above says chaining covers every client data path "through one seam
(`dialE2E`)". Since #24 that seam is two-part and the sentence names the inner half:
`dialChainedStream` owns the stream and the recovery, `dialE2E` owns the telescoping, and
what a data path must reach for is the outer one. Left as written — it was true when
written and the distinction is what these two amendments are for.

### Verification

A UDP associate over a depth-3 chain whose middle hop is killed **before** the association
is opened now comes up, carries datagrams, and leaves the dead hop cooled and out of the
rebuilt chain — the ordering matters, since it makes the flow the first thing to meet the
dead hop rather than an inheritor of somebody else's rebuild. Its negative half is asserted
too: a healthy chain opens exactly one stream, keeps the plan it started with, and cools
nobody, so the test cannot be satisfied by a path that rebuilds unconditionally. Both drive
the shipped SOCKS5 entry point over the real forwarding mesh
(`TestUDPAssociateRebuildsAroundADeadChainHop`,
`TestUDPAssociateOverAHealthyChainDialsOnceAndRebuildsNothing`).
