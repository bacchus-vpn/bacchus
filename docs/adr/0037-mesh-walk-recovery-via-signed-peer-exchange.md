# 37. Mesh-walk recovery via signed peer-exchange

- Status: accepted
- Date: 2026-07-11

## Context

Design doc [§4.3](../design/rendezvous-cold-start.md) calls for a **warm
re-bootstrap**: once a client has *ever* connected, if every coordinator it knows
goes unreachable, it must not fail cold. It should ask any node it has met — even a
plain relay — for a current, coordinator-signed snapshot and walk the mesh until it
finds a live rendezvous point. This *complements* the cold-start bootstrap (issue
#18, ADR-0013): cold-start gets a brand-new client its first contact; mesh-walk
recovers a client that had contact and lost it.

The design also says (§4.3, §8) this is the **coordinator pool (issue #6)
generalized** — #6 rotates among a configured set of coordinators, mesh-walk lets
*any* node hand you a fresh signed snapshot — and the two should share one
mechanism: the signed snapshot `core/coldstart.Snapshot`, already minted and served
by the coordinator (ADR-0013/0017). This ADR builds that shared courier on `main`'s
`core/coldstart`; it does **not** depend on the unmerged coordinator-pool-rotation
work (that seam is noted as a follow-up, not pulled in).

## Decision

1. **Courier model — dispense, never author.** A relay/exit node caches the last
   coordinator-signed snapshot it received (`coldstart.SnapshotCache`, opaque signed
   bytes held in an atomic pointer, copied on store and load) and serves those exact
   bytes to a recovering client (`coldstart.ServeCourier`). It re-signs nothing and
   needs no key. The recovering client re-verifies every reply with the existing
   `coldstart.Verify` against the coordinator's public key, so a hostile courier can
   only serve a stale-but-genuine snapshot or nothing — **never a forged directory.**
   This closes the poisoning vector the design names.

2. **Proof-of-prior-contact gate (anti-probe).** A mesh-walk request is a STUN
   Binding Request carrying a new comprehension-optional `PROOF` attribute
   (`0xC002`): a snapshot the coordinator once signed. The courier attaches its
   cached snapshot only when `coldstart.VerifySigned` accepts that proof; any other
   request — a prober with no prior snapshot — gets exactly the plain Binding Success
   Response a public STUN server sends (design principle #4). This both preserves
   anti-probe against a censor port-scanning for couriers **and** enforces the
   design's "recovery needs ≥1 prior contact" precondition *in the protocol itself*.

3. **Asymmetric freshness check.** The courier verifies the requester's proof with
   `VerifySigned` — signature only, **expiry ignored** — because a recovering
   client's cached snapshot is legitimately stale (that staleness is *why* it is
   recovering); provenance, not freshness, is what the gate tests. The client
   verifies the *reply* with `Verify` — signature **and** expiry — because a
   directory it is about to reconnect through must be live, not a courier's expired
   leftovers.

4. **Reuse the STUN blend and the bootstrap primitives.** `ServeCourier` /
   `FetchSnapshot` reuse the same RFC 5389 framing, `FINGERPRINT` construction, and
   `SNAPSHOT` (`0xC001`) response attribute as the cold-start bootstrap, so a
   mesh-walk exchange is shape-identical to an ICE check carrying one
   comprehension-optional attribute. A courier feeds its own cache by fetching from
   its coordinator with `coldstart.Bootstrap` under an operator-issued invite — no
   new coordinator-to-node path is required. `cmd/coordinator -print-bootstrap-pubkey`
   exports the snapshot-signing public key so couriers and clients can be provisioned
   to verify.

5. **Client trigger + walk.** `establish` now distinguishes *every coordinator
   silent* (network-unreachable) from *answered-but-could-not-pair*, returning the
   sentinel `core.ErrNoCoordinatorReachable` for the former. `Engine.MeshWalk` walks
   the configured peer couriers, returns the first verified fresh snapshot, and the
   node binary's recovery loop (`bacchus-node -mesh-peers`) adopts its coordinator
   entries, re-caches the fresher snapshot as the next proof, and reconnects —
   bounded, so a client never spins forever chasing a dead directory.

## Consequences

- A client that loses all coordinators recovers through any peer courier instead of
  failing cold, and the courier cannot poison what it serves — the two properties
  the design asked for. Exercised end-to-end over real loopback UDP in
  `core/coldstart/courier_test.go`, `core/meshwalk_test.go`, and
  `cmd/node/courier_test.go` (forged/altered/expired snapshots rejected; the
  proof gate proven non-vacuous; an all-silent connect surfaces the sentinel; the
  courier binary fetches, caches, and serves a real snapshot).
- **Replay is not prevented.** A censor that captures a client's mesh-walk request
  can replay its proof to a courier — but the proof is a coordinator-signed snapshot
  (not secret) and the reply is the same signed directory, so replay reveals only
  what the proof-holder already had. The gate raises the bar above an unauthenticated
  port scan, not to per-request authentication; a nonce/challenge would add a round
  trip and is a possible follow-up.
- **Courier address auto-advertisement is deferred.** A node's courier address is
  not yet carried in the coordinator's signed directory — that needs the
  node→coordinator register seam in `core/engine.go`, out of this change's scope — so
  couriers are operator-configured today (`-mesh-peers` / a cached snapshot's
  entries). Follow-up: have a node advertise its courier address on register and the
  coordinator stamp it into snapshots, so a recovering client's cached snapshot names
  the couriers directly.
- **Trust of which peers a client accepts from is by signature only.** Sybil/trust
  gating beyond signature verification is the unbuilt vouch system (design §5.4) and
  explicitly out of scope; today any peer serving a validly-signed, unexpired
  snapshot is accepted. Safe in the curated private-seed phase (§5.8), to be
  tightened before the public front door.
- **Recovery rebuilds the engine.** The node binary reconnects by rebuilding the
  engine against the rediscovered coordinators; for a combined client+forwarder node
  that means a brief re-registration blip (acceptable — the coordinators were
  unreachable anyway), and an exit without a persistent `-exit-key` regenerates its
  identity on rebuild exactly as it would on any restart.
- **One mechanism with issue #6.** The coordinator-pool rotation work can consume
  courier snapshots through the same `coldstart.Snapshot` + `SnapshotCache`; this ADR
  deliberately builds on `main` and leaves that integration as a follow-up rather
  than coupling to the unmerged branch.
- `-race` is not runnable in the local toolchain (no cgo); `SnapshotCache` is
  race-free by construction (atomic pointer, copy on both store and load), matching
  the coordinator's existing atomic snapshot handling.

## Update (2026-07-12) — recovery past the first-connect boundary (issue #115)

This ADR's decision #5 wired the client trigger only into `establish` — the
first-connect path. A client that had connected and then lost every coordinator
*mid-session*, or a client on the transport-pool path (issue #15), still failed cold:
the pooled path never surfaced `ErrNoCoordinatorReachable`, and the single-transport
auto-reconnect loop (ADR-0030) retried the same dead coordinators forever without ever
asking a peer. Issue #115 extends recovery to both boundaries and enforces one coupling
the original left to cadence. The design is unchanged — recovery still rebuilds the
engine against a coordinator-signed directory a courier hands over — so this is an
extension of the trigger surface, not a new mechanism.

- **Mid-session trigger, single-transport.** `reconnect` now counts consecutive
  all-silent passes and, after `meshRecoveryAfter` of them, calls the shared
  `Engine.tryMeshRecovery`. On a walk that yields coordinators **different** from the
  current (dead) set it stashes them, closes `NeedsRecovery`, and returns the internal
  `errRecovering` so `reconnectLoop` stops; the node binary's supervisor loop selects
  on `NeedsRecovery` alongside `Done`, reads `RecoveredDirectory`, stops the engine,
  and rebuilds against the rediscovered coordinators (same rebuild as first connect).
- **ADR-0030 is preserved, deliberately.** The escalation *only* stops the retry loop
  when it has a concrete, genuinely-different live directory to rebuild against
  (`sameCoordSet` guards the no-improvement case). A walk that finds nothing, or one
  that merely re-lists the same unreachable coordinators, leaves the loop retrying
  exactly as before — so a transient coordinator outage still self-heals in place,
  cheaply, without tearing the engine down. Recovery is an *addition* to retry-forever,
  never a downgrade of it to a give-up.
- **Pooled path.** `ListExits` now wraps `ErrNoCoordinatorReachable` on all-silent;
  `poolExits`/`selectPath`/`connectPooled` propagate it (distinguishing it from
  "answered but no exits", and from a force-major latch, which still takes precedence).
  So a pooled client surfaces the sentinel at first connect (the supervisor's existing
  recovery engages) and `maintainPath` escalates to `tryMeshRecovery` on a mid-session
  all-silent reselection before giving up. A pinned exit no longer masks all-silent:
  pairing needs a coordinator, so the sentinel — not a doomed pin — is the right answer.
- **Courier serves only unexpired snapshots.** `courierRefresh` (30 s) sits well inside
  the snapshot TTL (~5 min) *while a courier's coordinator is up*; if that coordinator
  is unreachable past the TTL the cache ages out. `handleCourierRequest` now runs the
  cached snapshot through `Verify` (signature **and** freshness) before attaching it,
  withholding an expired one and answering as a plain STUN endpoint instead — the same
  check `FetchSnapshot` already applies to the reply, now honored symmetrically on the
  serve side so a courier never hands out what a client would only reject.
- **No strand, no double-connect (the #105 review lesson).** An engine runs exactly one
  failover loop (single-transport *or* pool, never both). That loop stops itself before
  the supervisor rebuilds, and the supervisor stops the old engine (freeing the SOCKS
  listener and draining goroutines) before building the new one — so nothing races the
  rebuild for the listener. The client's own session is never reap-eligible, so the
  idle reaper is unaffected; a relay-death nudge (issue #96) drives the same reconnect
  path, which now escalates to mesh-walk if the coordinators are gone too. A
  supervisor-observable test asserts the reconnect loop makes no further establish
  attempts once recovery is signalled.
- Recovery config (`MeshPeers`/`MeshProof`/`MeshPubKey`) is plumbed through `Config`;
  the proof evolves across rebuilds (each fresher snapshot becomes the next proof).
  All three unset leaves recovery off — a client fails cold / keeps retrying exactly as
  before, so the change is inert for anyone not opting in.
- Exercised over real loopback UDP against live `ServeCourier` couriers, mirroring the
  existing mesh-walk tests: mid-session all-silent fires a walk on both paths; the
  pooled connect surfaces the sentinel; a no-improvement directory does *not* rebuild;
  and a courier withholds an expired snapshot. Each new guard was reverted to confirm
  the matching test fails without it. `-race` remains unavailable locally (no cgo); the
  new handoff state is race-free by construction (write-once mesh config, `recoverOnce`
  close of `recoverCh`, `recoverMu` around the stashed directory).

## Amendment (2026-07-11): supervisor-level coverage, a partial-config diagnostic, and a Stop() session leak found along the way (#121)

Follow-ups from the independent review of #115/#119, both fail-safe as shipped and
neither blocking (no MAJORs) — plus one unplanned fix the first item's test forced to
the surface.

- **The `cmd/node` supervisor glue now has direct coverage.** The engine-side contract
  (mid-session `NeedsRecovery` firing) was covered above; the `runNode` loop that
  consumes it — `Stop` the dead engine, read `RecoveredDirectory`, rebuild `core.New`
  against the rediscovered coordinators, reconnect — was not, the same pre-existing gap
  as the first-connect rebuild loop. `cmd/node/midsession_recovery_test.go` drives it
  for real: a real client connects through a real (wire-compatible fake) coordinator to
  a real exit over real WebRTC, proven by a SOCKS5 CONNECT + echo round trip; the
  coordinator then goes silent and the exit dies, forcing a genuine session drop; the
  engine's own reconnect loop retries (three real all-silent passes, matching
  `meshRecoveryAfter`'s production default) until its own mesh-walk recovers a fresh
  directory from a real courier and closes `NeedsRecovery` — never touched directly.
  `runNode`'s branch is then proven to `Stop` the dead engine and rebuild against the
  rediscovered coordinator by a second SOCKS5 CONNECT + echo round trip succeeding on
  the *same* `cfg.SocksAddr`. cmd/node has no access to core's white-box test seams
  (`fakeTransport`, `establishFn`, …), so this is necessarily a real, slower test
  (~90s+ floor from core's fixed, unexported reconnect/mesh-walk timeouts, which
  cmd/node cannot shorten from outside the package) — skipped under `-short`, matching
  `core/dtls_fingerprint_test.go`'s existing convention for real-WebRTC tests.
- **Partial mesh-recovery config is now observable.** A direct `core.Config` caller
  (unlike `cmd/node`'s `loadMeshRecovery`, which fails fast on a half-configured flag
  set) that sets only some of `MeshPeers`/`MeshProof`/`MeshPubKey` — or a wrong-size
  `MeshPubKey` — got recovery silently disabled with no signal at all. `New` now emits
  a one-time `EventInfo` diagnostic naming the gap when the config is partial
  (`meshRecoveryPartial`, called once from `newEngine`). The fail-safe itself is
  unchanged: `meshRecoveryConfigured` still requires the full combination, so a partial
  config still disables recovery exactly as before — this only makes the gap
  observable.
- **Found and fixed: `Engine.Stop()` could leak a tracked session's transport past
  return.** Building the supervisor-level test above — the first to call `Stop` on an
  engine holding a *real*, live forwarder session under real network timing, rather
  than an in-memory `fakeSession` — surfaced a pre-existing race between `Stop`'s own
  "collect `e.sessions`, close each one" loop and `trackSession`'s per-session watcher
  goroutine, which reacts to the very same `close(e.stop)` Stop starts with. If the
  watcher wins the race, it deletes its session from `e.sessions` before Stop's loop
  ever reads the map — Stop's snapshot never contains it, so Stop never calls `Close`
  on it, and the session's transport (an entire WebRTC `PeerConnection`'s goroutines,
  in the case that surfaced this) leaks indefinitely; the peer on the other end never
  observes a disconnect either, since the connection was never actually torn down.
  Sibling of #24/#27 (the original in-process-embedding session-leak fixes) — same
  hazard, a different code path. Fixed in `core/engine.go`'s `trackSession`: the
  watcher's `<-e.stop` case now calls `s.Close()` itself before deleting, so the
  session is torn down regardless of which side wins the race; `Close` is already
  documented idempotent, so this is safe whichever side gets there first.
  `TestStopClosesSessionRaceLoses` (`core/engine_test.go`) pins it deterministically —
  it forces the exact losing case (removing the session from `e.sessions` before
  calling `Stop`, so Stop's own loop provably cannot see it) rather than relying on
  timing, and was reverted to confirm it fails without the fix.

## Update (2026-07-11) — Windows client adoption (issue #122)

The #115 update above wired the supervisor-rebuild consumption pattern into
`cmd/node`'s `runNode` (`courier.go`) only; the Windows tray client
(`clients/windows`) runs its own `eng.Connect` + tunnel-bring-up flow
(`main.go`'s `connect()`) and never read `Engine.NeedsRecovery`/
`RecoveredDirectory`, so mid-session recovery was `core`/`cmd/node`-only.
Issue #122 closes that gap, mirroring the shape issue #116 already used to
bring this client up to the node's CRL posture (`docs/design/node-admission.md`):

- `connect()` now names its `core.Config` literal (`engCfg`) instead of
  inlining it into `core.New`, and — once `eng.Connect` succeeds — starts
  `watchMeshRecovery(ctx, eng, engCfg, lbl)` in the background for the rest
  of the session. It selects on `eng.NeedsRecovery()` alongside `eng.Done()`,
  exactly like `runNode`'s loop: on a recovery signal it reads
  `RecoveredDirectory`, stops the old engine (freeing the SOCKS listener
  before the rebuild needs it, same ordering `runNode` and the "no strand, no
  double-connect" note above require), and rebuilds via a new
  `rebuildRecoveryConfig` helper that replaces only `Coordinators`/
  `MeshProof` on `engCfg` — every other setting (`ExitID`, the transport
  pool, admission, `OnUnderlayDial`, the event sink) carries forward
  unchanged, so a recovery cannot silently widen or narrow anything the user
  configured. A concurrent user-initiated disconnect is detected the same
  way the rest of `main.go` already does (`engine == eng` under the
  package's `mu`), so a mid-flight rebuild never "helpfully" reconnects
  someone who just disconnected.
- Windows still has no settings surface for `MeshPeers`/`MeshProof`/
  `MeshPubKey` — out of this issue's scope — so `engCfg` never sets them and
  `meshRecoveryConfigured()` stays false: `NeedsRecovery()` can never close,
  and `watchMeshRecovery`'s loop sits on a channel that never fires, exactly
  as if it weren't wired in. It does not touch, and cannot regress, the
  ADR-0030 auto-reconnect loop already living inside `core.Engine`, which
  keeps retrying a dropped path on its own regardless of whether this
  watcher exists.
- The genuinely bug-prone surface — silently dropping a field across a
  rebuild (e.g. losing `AdmissionCRLPath` and reverting a session to
  fail-open revocation checking after a recovery) — is covered by a pure,
  unit-tested `rebuildRecoveryConfig` (`clients/windows/main_test.go`); the
  surrounding stop/rebuild/swap sequencing is thin orchestration mirroring
  `runNode`'s already-reviewed shape and, since the trigger cannot fire yet
  on this client, has no live path to exercise via an automated test beyond
  that. See the PR for the full reasoning.

## Amendment (issue #5, 2026-07-28): "answered but unroutable" is no longer a mesh-walk trigger

The trigger for warm recovery is that **every coordinator is silent**: rendezvous itself
is unreachable, so a live coordinator has to be rediscovered through a peer. That is the
right condition, and one case was reaching it that is not it.

A coordinator that is up and answering in a shape this build cannot route produces the
same non-event as silence at every leg that waits for a reply — nothing usable arrives,
the deadline expires, the member reads as blocked. `readLoop` already noticed and said so
(`noteUnroutable`, added when a protocol change shipped that no client could speak), but
it was a **log line only**: the control flow was unchanged, so `ListCountries` still
returned `ErrNoCoordinatorReachable`, `silentStreak` still climbed, and after
`meshRecoveryAfter` passes the supervisor rebuilt the engine against a rediscovered
coordinator — while the configured one was healthy throughout.

Walking the mesh cannot help there, and that is the point rather than an inefficiency.
Mesh-walk rediscovers coordinator **addresses**. An unroutable reply means the address is
fine and the **protocol** is not, so the fresh directory names coordinators that answer
identically — the engine is torn down and rebuilt to arrive back where it started. A
version problem and a reachability problem want different recovery, and they were
indistinguishable at the point that decides.

`coordLink` now counts every reply it could not route (separately from the memo that
bounds *logging* — a member whose second unroutable reply went unlogged has still
answered), and both client legs sample it around their wait. The result is
`ErrCoordinatorUnroutable`, which is deliberately **not** wrapped around the all-silent
sentinel, so nothing keys mesh-walk off it.

Both legs, not only the one #5 traced. The country list is where the chain to harm runs —
after #146 every connect with no configured country takes it — but the connect leg has the
identical hole, and a client with `Geo` set skips the list entirely. Fixing one would have
left the configured client with exactly the original bug.

The version fence could not have caught this either, which is why the diagnosis has to
come from the drop site: `observeNetworkVersion` runs only for `session`/`countries`/
`error`, so a reply this build cannot route never reaches the force-major check.

**What does not change:** genuine silence still returns `ErrNoCoordinatorReachable` and
still triggers recovery, and a run of all-silent passes still escalates exactly as this
record describes. The existing all-silent tests are what pin that, and a mutation that
reports every failure as unroutable kills them.
