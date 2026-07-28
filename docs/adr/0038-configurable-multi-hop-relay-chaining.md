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
   credentials are an optional follow-up.

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
DoS controls; in-place directory refresh (a restart currently adopts a new one);
chain-aware liveness beyond the existing stall detection; and NAT-traversed middle
hops. This change is **Part of #76** and does not close it.

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
  every real self-dial. This is the cheap half of #174 and does not bound a ring of
  nodes pointed at each other.
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
