# 31. First-class session and peer expiry

- Status: accepted
- Date: 2026-07-05

## Context

A session that ends cleanly is cleaned up: the transport fires `Session.Closed()`,
and `trackSession`'s watcher drops the signaler, releases accounting state, and
deletes the entry from `Engine.sessions`. But a *silent* disappearance — a peer
that vanishes with no teardown (a killed client, a dropped network, a NAT
rebinding) — fires nothing. Over a long-lived or connectionless transport the
local end can stay "up" indefinitely: on Reality (TCP :443) a peer that never
sends a FIN leaves the socket open until OS keepalive hours later; the forwarder's
`AcceptStream` loop blocks forever and the session sits in the map, pinning its
goroutines and file descriptors.

This is the class of bug behind the earlier "12s disconnect": liveness was left
implicit, so a half-open session was indistinguishable from a live-but-quiet one,
and the only expiry that existed was too crude. ADR-0030 handled the *client*
re-establishing when its path drops and explicitly deferred the server side — "the
exit/relay dropping its half of a dead session is issue #3" — to here. Milestone
M4 is where expiry stops being incidental and becomes a first-class, tested
behavior on both the node and the coordinator.

Two layers leak on a silent vanish:

- **The engine (exit/relay).** `Engine.sessions` only shrinks on `Closed()`.
  Nothing measures inactivity; nothing closes an idle session.
- **The coordinator.** Relays and exits already expire on `lastSeen` + a 35 s
  `ttl` (they re-register every 10 s), swept lazily on every packet and every 10 s
  snapshot refresh. But *sessions* — the signaling rendezvous entries — expired on
  a flat `created` + 2 min, independent of activity. A client never heartbeats, so
  its only footprint is its session entry, and a fixed-age cap neither tracks a
  live handshake nor promptly reaps a vanished one.

## Decision

Expiry is activity-based at both layers: a peer is live exactly as long as
*something is moving*, and is reaped a bounded time after it goes quiet.

### Engine: an idle-session reaper (`core/engine.go`, `core/forwarder.go`)

- **Per-session activity.** `Engine.sessions` now holds `*trackedSession{sess,
  reap, lastNano}` (was a bare `Session`). `lastNano` is the unix-nano time of the
  last observed activity, written and read atomically. `reap` marks a session the
  reaper may close — **forwarder (exit/relay) sessions set it true; a client's own
  session sets it false**, so the reaper never tears down the tunnel the client's
  reconnect driver (ADR-0030) owns.

- **Activity is bytes, not new streams.** Each accepted forwarder stream is wrapped
  (`activityStream`) so every read or write refreshes `lastNano`, and a new stream
  refreshes it too. Reaping on new-stream events alone would close a session
  carrying one long-lived, busy stream (a large download) that opens nothing new;
  "idle" therefore means "no bytes in either direction", which is the property that
  actually distinguishes a dead peer from a quiet one.

- **The reaper.** A `reapLoop` — started only for a forwarder role — scans every
  `reapInterval` (30 s) and closes any `reap` session whose `lastNano` is older
  than `idleTTL` (5 min). Closing cascades through the existing `trackSession`
  watcher, which frees the entry, so the reaper needs no teardown path of its own.
  Dead sessions are collected under `sessMu` and closed outside it, because `Close`
  wakes the watcher, which takes `sessMu` to delete — closing under the lock could
  deadlock.

- **5 minutes, deliberately generous.** The "12s disconnect" lesson is that
  *over-aggressive* expiry is itself the bug: a live-but-quiet session (an idle SSH
  session, a paused download) must survive. 5 min of total silence clears any real
  idle gap while still bounding a half-open leak to `idleTTL` + one scan.
  `idleTTL`/`reapInterval` are fields, not constants, so a test can shrink them.

- **A session-count metric.** `Engine.SessionCount()` exposes the live-session
  cardinality — a number only, no session ids, peers, or destinations — safe to
  surface operationally and the anchor for the soak test's baseline assertion.

### Coordinator: sessions expire on signaling activity (`cmd/coordinator/main.go`)

Session rendezvous entries now carry `lastSeen`, set at `connect` and refreshed on
every `offer`/`answer`/`candidate` relayed for them, and `prune` drops them on
`now - lastSeen > sessionTTL` (a named 2-min idle window) rather than on creation
age. A live handshake or trickle-ICE exchange keeps its entry; a vanished client's
entry — which never sees another frame — is reaped once quiet. Relay/exit expiry
(`lastSeen` + `ttl`) is unchanged; the sweep still runs lazily on every packet and
every 10 s snapshot refresh, so expiry holds even with no traffic.

### Also folded in: a startup session leak (#85)

Separate from expiry but the same lifecycle theme: in the non-pooled `Connect`, if
`serveReconnectSocks` fails to bind, the just-established session was
returned-around without being closed. It now `Close()`s the session before the
error return. Committed separately within this change.

## Consequences

- A peer that vanishes silently is now reclaimed on both sides within a bounded
  time — the #3 acceptance — with no protocol change: the reaper reacts to local
  inactivity, and the coordinator to signaling silence.
- Expiry is tested as a guarantee, not assumed. Unit tests pin the reaper predicate
  (reap-eligible **and** idle, client sessions spared) and the coordinator
  prune/refresh; soak tests run many connect/disconnect and half-open cycles and
  assert the session map **and** goroutine count return to baseline (the FD leak
  follows the goroutine/session leak — closing frees both).
- Accepted limits and named follow-ups:
  - **Idle is measured locally, at the byte layer.** A session moving bytes is
    never reaped, but the reaper cannot distinguish an application-level stall from
    a healthy idle connection — by design, a 5-min silence is treated as reapable.
    Transports that expose their own liveness (WebRTC consent freshness, a future
    Reality keepalive) will still fire `Closed()` faster; the reaper is the backstop
    for those that do not.
  - **The reaper is forwarder-only.** A client's single session is owned by its
    reconnect loop (ADR-0030); unifying client and forwarder lifecycle under one
    manager is possible later but unneeded for v1.
  - **The coordinator session sweep is lazy, not a dedicated timer.** It runs on
    packet arrival and the 10 s snapshot refresh, so worst-case reap latency is
    `sessionTTL` + one refresh interval — acceptable for tiny rendezvous entries; a
    dedicated ticker is a later option if the entry cost ever matters.
  - **`sessionTTL` is intentionally conservative (2 min).** It outlasts any
    realistic handshake/trickle-ICE sequence so a slow negotiation is never torn
    down; the cost is a vanished client's rendezvous entry lingering up to that
    long, which is bounded and cheap.
