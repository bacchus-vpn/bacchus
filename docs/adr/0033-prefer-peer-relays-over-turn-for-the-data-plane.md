# 33. Prefer peer relays over TURN for the data plane

- Status: accepted
- Date: 2026-07-09

## Context

A client that cannot hole-punch a direct path to its exit needs a relayed one.
The system has two mechanisms that can relay, at two different layers, and until
now it leaned on the wrong one by default:

- **A Bacchus peer relay** (application layer). A node registered as `relay`
  is assigned a session carrying the exit's advertised TCP address; it accepts
  the client's transport session and blind-splices ciphertext to that address
  (`core/forwarder.go`'s `relayPipe`). It never sees the destination or content —
  the client's end-to-end Noise_NK channel to the exit passes through untouched
  (ADR-0009). This is the `mode:"relay"` matchmaking path and the "route through
  nodes" tier of the selection ladder (ADR-0028, tier 3).

- **The coordinator's TURN** (transport layer). The WebRTC transport is
  configured with the coordinator's STUN/TURN server and
  `ICETransportPolicyAll`, so a `mode:"direct"` candidate that fails to
  hole-punch *silently* falls back to relaying its DTLS through TURN. In
  practice this made TURN the de-facto relay the pool leaned on: a direct
  candidate "succeeded" over TURN before the ladder ever reached the peer-relay
  tier, and the peer-relay tier itself only did anything if a `relay` node
  happened to be registered — otherwise `pickRelay()` returned nil and the
  matchmaker replied `error`, with no fallback at all.

TURN relaying every blocked user's traffic through the coordinator concentrates
bandwidth and trust on the one enumerable chokepoint the whole design works to
avoid (ADR-0006, ADR-0020). Issue #17 asks to invert the preference: route a
relayed data plane through a Bacchus **node** peer, and keep TURN only as the
last-ditch fallback when no peer relay is available.

The invariant that makes this safe was already true by construction and had to
stay true: the relay is **transparent**. Because the destination and the exit's
admission credential live *inside* the Noise_NK channel (`core/e2e.go`), a relay
only ever forwards ciphertext, so end-to-end exit-admission verification
(#60/#69) authenticates the *exit*, not the relay, no matter how many hops it
crossed.

## Decision

Make the coordinator the matchmaker for relay preference, and keep the
transparent splice unchanged. Surface area: `core/engine.go`,
`core/forwarder.go`, `cmd/coordinator`, `cmd/node` (plus a small
`core/client.go` event so the client reports which path it got).

- **Peer relay preferred (`cmd/coordinator`).** A `connect{mode:"relay"}` first
  tries `pickRelay(exitID)`: a live relay node that is **not** the exit itself
  (a node registered as both must never be told to relay to its own ingress — a
  pointless loopback that would also collapse the "relay is a distinct peer"
  property). When one is found, the coordinator assigns it the splice
  (`assign{ExitAddr}`) and tags the client's reply `relay:"peer"` — unchanged
  data-plane behaviour, now explicit and preferred. Among the live relays (last
  seen within half the prune TTL) it picks one at random, so no relay can make
  itself the perpetual choice by heartbeat timing — see the consequences.

- **TURN fallback (`cmd/coordinator`).** When no peer relay is available, instead
  of failing the coordinator wires the client straight to the exit — the
  direct-assignment shape (`assign` with no `ExitAddr`) — and tags the reply
  `relay:"turn"`. The client's transport dials the exit directly; ICE uses a
  TURN relay candidate only if a direct hole-punch fails. So TURN becomes the
  reserved last resort a relay-mode request degrades to, not the default, and a
  relay-mode client with no relay node available now *connects* where before it
  got an error.

- **Disposition on the wire (`core/engine.go`).** A `relay` field on the
  `session` reply carries `relayPeer` / `relayTURN`. It is informational: the
  exit terminates the same end-to-end channel in both cases, so the disposition
  is transport plumbing, not a change to who the client authenticates. The
  client surfaces it as an accurate connected-via line; a coordinator predating
  #17 sends no field and the client behaves exactly as before (fail-open,
  backward compatible).

- **Capability advertisement (`cmd/node`).** A node advertises relay capability
  by registering `role:relay` — no new flag; the coordinator now prefers it as a
  data-plane peer over its own TURN.

- **Transparent splice unchanged (`core/forwarder.go`).** `relayPipe` is
  documented as the peer-relay splice but its behaviour is untouched: it adds no
  preamble, reads nothing from the stream, and forwards ciphertext both ways.
  `TestPeerRelaySplicePreservesE2E` drives the *actual* `relayPipe` (dialing a
  real exit TCP ingress, not a hand-rolled `io.Copy`) and proves the end-to-end
  channel — target, payload, and the exit's admission credential — terminates at
  the exit through the hop; `TestPeerRelaySpliceRejectsUnauthorizedExitE2E`
  proves the hop does not weaken #60/#69, rejecting an exit whose credential the
  client's anchor refuses.

## Consequences

- A relayed data plane now prefers a Bacchus peer relay and reserves TURN for
  the fallback, moving relay bandwidth off the coordinator when the network has
  relay nodes to carry it. A relay-mode client with no relay available still
  connects (via TURN) instead of erroring.
- #60/#69 exit-admission verification is unaffected — proven end-to-end through
  the real splice — validating ADR-0009 once more: the relay change needed no
  change to `core/e2e.go`.
- Accepted limits and named follow-ups:
  - **Relay-side accounting is deferred (the #17-scoped gap).** A peer-relay
    splice carries no session id — `relayPipe` reaches the exit through its bare
    TCP ingress with nothing to key accounting state by (see
    `core/accounting.go`, `handlerFor`) — so co-signed usage receipts (ADR-0021)
    still cover direct-mode sessions only. Threading a session id through the
    splice so relayed traffic can be metered/attributed is a **follow-up issue**,
    not solved here.
  - **The direct tier can still silently TURN-relay.** #17 makes the *relay-mode*
    path prefer a peer relay, but a `mode:"direct"` candidate that cannot
    hole-punch still falls back to TURN inside ICE (`ICETransportPolicyAll`),
    so TURN is not yet fully demoted to "only when explicitly chosen".
    Separating "direct hole-punch" from "direct via TURN" needs per-attempt ICE
    policy control in the WebRTC transport (host+srflx only on the direct tier,
    relay candidates reserved for the fallback) — a transport-layer follow-up,
    deliberately out of this issue's surface.
  - **`pickRelay` is random among live relays, not load-aware.** It picks (via
    Go's randomized map iteration) among relays last seen within half the prune
    TTL, rather than the most recently seen. This is deliberate: a deterministic
    freshest-first pick would let a relay that controls its own heartbeat cadence
    make itself the perpetual choice — handed every relay-mode client, so
    concentrating the source address + timing metadata a relay can observe (the
    payload stays end-to-end opaque) — and would defeat the client's cross-
    coordinator failover, since every coordinator would keep returning the same
    relay even after it died, black-holing relay-mode connects until it prunes.
    Random selection spreads sessions, re-rolls on retry, and denies a hostile
    relay a fixed target. It is still not *load*-aware: a round-robin or
    fewest-live-sessions policy is a follow-up once the relay tier is actually
    populated (only one relay node exists today, issue #5).
  - **Single hop only.** This is one relay between client and exit. Configurable
    multi-hop / relay chaining is separate future work (issue #76, ADR-0028).
  - **Tested with fake peers.** Coordinator preference/fallback/exclusion is
    proven by driving `handle()` with fake UDP peers (`cmd/coordinator`), and the
    transparency invariant by the real splice over `net.Pipe`/loopback TCP
    (`core`). The `-race` detector is unavailable locally (needs cgo), matching
    prior batches; the change adds no new shared-state concurrency
    (`handle()` is mutex-guarded and single-threaded per call).

## Amendment (issue #96): reselect a dead peer relay mid-session

The decision above covers relay selection at **connect** time. It left a gap for a
relay that dies *after* it is assigned: `pickRelay` runs once, and the coordinator
then only relayed signaling for that session, never re-checking the relay carrying
it. A relay that stopped heartbeating mid-session was noticed only by the client's
own transport teardown (auto-reconnect, ADR-0030) — fast when the relay resets the
splice, but a multi-minute TCP timeout when it black-holes (host powered off,
network-partitioned) without a reset. The coordinator, which sees the relay stop
heartbeating within a window, did nothing about the sessions riding it.

Issue #96 closes that with a coordinator-side **in-session liveness** check — the
counterpart to connect-time `pickRelay` — and a client re-establish nudge:

- **Sweep on a timer (`cmd/coordinator`).** `reselectLoop` runs `prune` +
  `reselectDeadRelays` every `reselectInterval` (one heartbeat window, 10s — the
  forwarder re-announce cadence), independent of incoming packets so it fires on an
  otherwise-idle coordinator too. A session records the `relayID` actually carrying
  it (peer-relay path only; direct and TURN-fallback sessions carry none and are
  skipped).

- **One definition of "dead."** `reselectDeadRelays` treats a session's relay as
  dead once it has gone stale past `ttl/2` — the *same* freshness bound `pickRelay`
  uses to judge a relay unpickable. That coherence is deliberate: a relay the sweep
  declares dead is exactly one `pickRelay` would already refuse to hand out, so
  reselection excluding the dead relay falls out for free (below), and the `ttl/2`
  bound tolerates a single lost heartbeat where a one-missed-beat bound would
  false-trigger and churn a healthy path.

- **Reselect-or-TURN via re-establish, not a re-wire.** On a dead relay the
  coordinator sends the client a `reselect` push (just the session id) and drops the
  now-defunct session so the nudge fires once. The client re-drives
  `connect{mode:relay}`, and the existing matchmaker does the reselection: `pickRelay`
  skips the dead relay by that same staleness and returns a fresh live relay (the
  dead one excluded), or `nil` and the client degrades to the TURN fallback. Reusing
  the connect path — rather than having the coordinator re-wire the session in place
  and the client adopt it — keeps the reselection logic in one tested place and the
  client change to a minimal signal.

- **Minimal client signal (`core/engine.go`, `core/client.go`, flagged).** A new
  `reselect` wire type (reusing the existing `session` field, no new wire field) is
  dispatched in `readLoop` to `onRelayReselect`, which closes the active
  single-transport session so the reconnect driver (ADR-0030) re-establishes. The
  nudge is **scoped to the live session id** (`rcSid`): a relay dying cleanly usually
  breaks the client's transport first, so a nudge for the session it already left
  must be ignored, not tear down the healthy path it moved to. A pooled client
  (ADR-0028) has no single-transport reconnect session and its own failover, so the
  nudge no-ops for it.

- **Best-effort, degrades to ADR-0030.** The push is one UDP datagram; a lost one is
  not fatal — the client's own transport teardown drives the same reconnect. #96 only
  *bounds* recovery to a heartbeat window instead of a TCP timeout in the black-hole
  case that ADR-0030 alone recovers from slowly.

The transparency invariant is untouched: `reselectDeadRelays` never reads the splice
and the re-established path runs the same end-to-end Noise_NK handshake through a
fresh relay, so #60/#69 exit-admission verification authenticates the exit exactly as
before — no change to `core/e2e.go` or `core/forwarder.go`. Selection, the sweep, the
reselect-or-TURN re-establish, and the client nudge's id-scoping are proven by driving
`reselectDeadRelays()` + the follow-on connect with fake UDP peers (`cmd/coordinator`)
and `onRelayReselect` with a fake session (`core`); as in the parent decision `-race`
is unavailable locally, and the sweep adds no new shared state — it takes the same
registry mutex `handle()` does, matching the existing background snapshot/secrets
loops.

Follow-ups this does **not** take on: load-aware `pickRelay` (still random among
live, as above) and relay-side accounting (still direct-mode only) remain open from
the parent decision.

### Correction (issue #105): the sweep must outlive the session's first `sessionTTL`

The amendment above overclaimed. Its "bounds recovery to a heartbeat window" held
only for a session's first `sessionTTL` (2 min). `reselectDeadRelays` can act only on
sessions still in the `sessions` map, but `prune` reaps a session once its `lastSeen`
is older than `sessionTTL`, and a session's `lastSeen` is bumped **only** by
setup-time signaling (`offer`/`answer`/`candidate`). A healthy peer-relay session
sees no coordinator signaling after setup — the data plane flows client↔relay↔exit
directly, and a relay `heartbeat` refreshes the relay *node*, not the sessions riding
it — so its entry was reaped ~2 min after connect while the data plane was still up.
From then on the sweep was blind to the relay dying, and recovery fell back to the
client's own multi-minute transport teardown (ADR-0030) — exactly the slow path the
amendment claimed to eliminate, for all but the first two minutes of a session.

The fix ties a peer-relay session's liveness to its **relay**, not to signaling
silence:

- **`prune` exempts peer-relay sessions** (`relayID != ""`) from the `sessionTTL`
  reaping. `reselectDeadRelays` becomes their sole reaper — it drops a session when
  the relay carrying it goes stale, which is the correct liveness signal. (Exempting,
  rather than bumping `lastSeen` on each sweep, is deliberate: `prune` runs *before*
  `reselectDeadRelays` in `reselectLoop`, so a bump could still lose to `prune` on the
  sweep a session first crosses `sessionTTL`.) Direct and TURN-fallback sessions
  (`relayID == ""`) keep reaping on signaling silence exactly as before.

- **Liveness is per-incarnation.** `reselectDeadRelays` now also requires the live
  relay's address to still match the session's `peer`: a relay that restarts under the
  same admission-bound id but a new socket is a different incarnation than the one the
  splice was built on, so a fresh `lastSeen` alone must not mask it (the client is
  nudged onto the new incarnation instead).

With this, a relay that dies minutes into a long session is caught within one sweep
(`reselectInterval`, 10s) for the session's whole life, so the amendment's claim now
holds in full. Proven by a test that ages a peer-relay session past `sessionTTL` and
shows it survives a full `prune`+`reselect` sweep while its relay is alive, then is
nudged and reaped when the relay dies late; a test that `prune` still reaps a silent
direct session; and a test for the same-id-restart reap.

**Residual (honest):** the coordinator has no client-side liveness signal — the data
plane never touches it — so a peer-relay session that has fallen out of use lingers
until its relay dies, rather than being reaped ~2 min after it fell idle. That covers
not just a client that vanished but any client that re-established onto a fresh session
while the old relay stayed up — auto-reconnect (ADR-0030), pool failover (ADR-0028), or
an app restart — orphaning the old entry. The leaked entry is tiny and bounded by relay
lifetime (a relay restart under a new address, or its going stale, reaps every session
keyed on it in one sweep). If coordinator session-map growth ever becomes a concern, a
proper client-liveness signal (periodic client keepalive, or relay-reported
active-session lists) is the fix — filed as a follow-up on #105.

## Amendment (issue #97): a TURN fallback is the DIRECT disposition, not a relay

The #93 review of this decision flagged that the client mishandled the
`relay:"turn"` disposition. When no peer relay is available the coordinator wires
the client straight to the exit (the direct-assignment shape) and tags the reply
`relay:"turn"` — but the client, seeing only that it had *requested* `mode:"relay"`,
treated the result as a relayed path: it surfaced `EventConnected "connected via
RELAY"` and skipped `startAccounting`. Both are wrong. A TURN fallback is a **direct
client↔exit data plane**: the exit terminates the session and holds a session id,
and ICE relays through TURN only if a direct hole-punch fails — exactly as a
`mode:"direct"` connect does (which can itself silently TURN-relay at the ICE layer,
see this ADR's consequences). The only genuinely relayed disposition is
`relay:"peer"`.

The fix aligns the client with what the exit already does, and is deliberately
**client-side only**:

- **Telemetry + accounting follow the disposition, not the requested mode
  (`core/client.go`).** `connectVia` now treats a `relay:"turn"` result exactly like
  a `mode:"direct"` one: it emits `connected DIRECT to exit` and calls
  `startAccounting`. `relay:"peer"` keeps the `via RELAY` line and stays unaccounted.
  The relay disposition is threaded up from `awaitSession` through `attemptWith`/
  `attempt` so `connectVia` can branch on it (previously it was consumed only for an
  info line). The reconnect `mode` stays `relay` for a TURN fallback — the user still
  wants a relayed path, and a peer relay may appear on a later attempt — so *mode*
  drives reconnect while *disposition* drives telemetry+accounting; the two are
  independent by design.

- **Why accounting a TURN fallback is correct, not a drift (ADR-0021).** ADR-0021
  scopes accounting to "direct-mode sessions only," and the review read the exit's
  counter for a TURN fallback as a drift from that. The real criterion ADR-0021 rests
  on is *"is there a session id to attribute bytes to?"* — relay mode was excluded
  because a peer-relay splice reaches the exit through its bare TCP ingress with **no
  session id** (`serveExit` passes `sid==""`). A TURN fallback is the opposite: it is
  a direct-shaped assign **with** a session id, so it is attributable, and metering
  it is correct direct-mode accounting, not a drift. The client cosigning (above) is
  what makes the exit's counter *used* rather than orphaned — the actual resolution
  of the review's "counter no client cosigns" point.

- **The exit cannot, and must not, distinguish TURN fallback from direct
  (`core/forwarder.go`).** A `mode:"direct"` connect and a TURN fallback arrive at the
  exit as the identical `assign` (no `exitAddr`); only the *client* gets the
  `relay:"turn"` tag. So there is no exit-side behavioural change to make: the exit
  meters any `sid`-bearing session as direct-mode, which is correct precisely because
  both are genuinely direct exit↔client data planes. Suppressing the counter for a
  TURN fallback on the exit is both impossible — it cannot tell them apart without a
  new wire field this issue does not add — and undesirable — the exit really did serve
  those bytes directly. `handlerFor`/`exitTerminate` comments now state this
  explicitly; `startAccounting`'s "direct-mode only" doc is unchanged and correct (a
  TURN fallback *is* a direct-mode session for accounting).

- **`relayPipe` surfaces a dial-to-exit failure (`core/forwarder.go`).** A peer relay
  that cannot reach its assigned exit previously swallowed the dial error. It now
  `emit(EventError)` — a relay operator needs the signal (exit down, stale advertised
  address, partitioned relay→exit leg). It names only the exit address the relay
  already dials (the splice carries no session id or destination), and the client is
  unaffected end-to-end: its transport to the relay simply carries nothing, so it
  times out and reconnects (ADR-0030) or is nudged onto another relay (#96).

- **Wire-contract drift guard.** The `relayPeer`/`relayTURN` literals are duplicated
  in `core/engine.go` and `cmd/coordinator/main.go` (the coordinator binary does not
  import core, ADR-0016). A `TestRelayDispositionWireContract` in each package now
  pins the exact bytes, so neither copy can drift without a test failing.

Consequences: telemetry now names the path a relay-mode client actually got, and a
TURN-fallback session is metered like the direct session it is; nothing changes for
`relay:"peer"` (still `via RELAY`, still unaccounted — the one relayed case ADR-0021
cannot attribute). The transparency invariant and the exit's E2E termination are
untouched. Proven by driving the real connect ladder over a fake transport (a TURN
fallback reports DIRECT and starts a counter; a peer relay reports RELAY and does
not) and a `relayPipe` dial-failure test; the relay-side accounting gap for a genuine
`relay:"peer"` splice remains open from the parent decision.
