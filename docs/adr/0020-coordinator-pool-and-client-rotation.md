# 20. Coordinator pool + client rotation

- Status: accepted
- Date: 2026-07-03

## Context

A single coordinator IP is a single enumerable, blockable point — ADR-0006
already named "many coordinators + rotation + client fallback" as the product
answer to that risk, tracked separately (issue #6). This ADR is that decision.

A pool needs two things: (1) relay/exit nodes discoverable no matter which pool
member a client happens to reach, and (2) a client that doesn't stall when the
member it tries first is blocked.

The straightforward way to get (1) is a **replicated directory**: coordinators
gossip registrations to each other. That is real distributed-systems surface
(consistency, partition handling, a new inter-coordinator protocol) for a
directory that is small, ephemeral (35s heartbeat TTL,
[cmd/coordinator/main.go](../../cmd/coordinator/main.go)), and cheap to rebuild.

## Decision

**No coordinator-to-coordinator replication.** The coordinator binary is
unchanged. Instead the pool lives entirely in the node engine
([core/coordpool.go](../../core/coordpool.go)), asymmetrically by role:

- **Forwarder nodes (relay/exit) register with every member of their configured
  pool**, concurrently, over one UDP link per member, re-announcing well within
  the coordinator's heartbeat TTL. Each coordinator's directory is then
  populated directly by the nodes themselves — the "shared directory" the issue
  asked for falls out of that, with no new server-side protocol.
- **The client rotates.** It shuffles its pool, tries the healthiest-first
  ordering, and on a member that is unhealthy or in cooldown sinks it to the end
  of the order rather than dropping it (a member that recovers keeps getting
  retried; see `rankCoordinators` in
  [core/coordpool.go](../../core/coordpool.go)). Health memory is **in-process
  only** — a member that fails an attempt is deprioritized for 30s
  (`coordCooldown`), not persisted. Deliberately minimal: no state file, no DB,
  matching the project's "own Go binaries, no infra" stage.
- **Each session's signaling is bound to the member that owns it.** A client
  binds its rotation choice; a forwarder binds the member that sent the
  `assign`. Offers/answers/candidates then flow back over that one link. Each
  member also has its own inbox, so a slow member can never leak a reply into
  another member's client attempt.
- **The client contacts only what it uses.** A forwarder must greet every member
  (it registers with all), but a client greets and queries members lazily, one
  per rotation step — it never fans the whole pool out at startup, so a hostile
  network sees only the members the client actually needed, not its entire
  fallback set.
- **Rotation assumes a member can be poisoned, not just blocked**
  ([core/client.go](../../core/client.go)). The client rotates on *any* connect
  failure — silent, refused, or a transport that failed after the member paired
  it — trying each member once. A poisoned coordinator can hand back a dead or
  hostile relay (`pickRelay` in
  [cmd/coordinator/main.go](../../cmd/coordinator/main.go)), so a fresh relay
  assignment from the next member is worth trying. The one thing it does not
  repeat is the **direct** attempt: that is a P2P hole-punch to the
  client-chosen exit, independent of which coordinator brokered it, so it runs
  once and later members try relay only. Only a *silent* member is additionally
  marked unhealthy (deprioritized for the cooldown); a member that answered but
  couldn't get the client connected is still considered reachable.
  - Finer dedup — skipping a member that re-suggests the *same* already-failed
    relay — isn't possible client-side today: the coordinator sends the relay
    identity only to the relay (`assign`), never to the client (which gets just
    a session id), and this ADR leaves the coordinator unchanged. Tracked as a
    follow-up.
- `-coordinators` replaces `-coordinator` everywhere — the node flag
  (comma-separated), the Windows client config (`coordinators` JSON array), and
  the systemd env files (`COORDINATORS`). Config-driven, no hardcoded host.

## Consequences

- No inter-coordinator trust or gossip protocol to design, run, or secure.
- A forwarder's registration traffic scales with pool size (one register +
  heartbeat stream per member) — fine at pool sizes in the low single digits;
  would need revisiting well before pools grew large.
- The rendezvous chokepoint from ADR-0006 is now a *set* of chokepoints — one
  blocked member no longer stalls a client, as long as one member is reachable
  (covered end-to-end by `TestClientRotation_DiscoversViaHealthyMember` in
  [core/coordpool_integration_test.go](../../core/coordpool_integration_test.go)).
- The Windows full-device tunnel now excludes **every** pool member from its
  route (not just one coordinator), so the client can rotate to any member
  without the kill-switch cutting off its signaling.
- Out of scope, tracked separately: how a *fresh* client with no prior config
  learns its first pool at all (issue #18, cold-start bootstrap — this ADR
  assumes the pool is already known to the node).
