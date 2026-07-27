# 30. Auto-reconnect and relay failover on the single-transport path

- Status: accepted
- Date: 2026-07-05

## Context

The default client path — one `Config.Transport`, no `TransportPool` — brought a
session up once and never watched it again. `Connect` captured the session, ran
SOCKS over it, and returned; if the path then dropped (data-channel/ICE teardown,
the peer going away, a network change), the SOCKS listener kept accepting but
every `OpenStream` on the dead session failed. The tunnel was silently down with
no recovery and no signal — the user had to reconnect by hand.

ADR-0028 gave the *pooled* path (`Config.TransportPool`) failover across
transports and exits: `maintainPath` watches the committed session, re-races the
ladder on a drop, and swaps the new session under a bind-once listener. But the
pool is opt-in; the single-transport default — what v1 ships on — had none of it.

Issue #2 is the narrower, always-on case the pool does not cover: re-establish
*within the current transport*, to the one configured exit. The candidates are not
other transports — they are the two ways to reach that exit, `direct` (a P2P
hole-punch) and `relay` (routed through nodes), across the coordinator pool
(ADR-0020). This is deliberately not transport failover (that is #15/ADR-0028, and
issue #79 is fixing the pooled path in parallel) and not server-side session
reaping (the exit/relay dropping its half of a dead session is issue #3).

## Decision

The single-transport `Connect` keeps its coordinator-rotation semantics but, once
a path is up, hands it to a **reconnect driver** and returns. The driver lives in
`core/client.go`; it shares no mutable state with `core/pool.go`, so the two
failover mechanisms (which are mutually exclusive at run time) stay independent.

- **Establish is one reusable pass.** `establish(ctx, prefer)` rotates the
  coordinator pool and, per member, attempts the candidate modes in preference
  order, returning the first path that comes up (a `connPath{session, counter,
  mode}`). `prefer` names the mode to try first: `""` is the initial
  direct-then-relay order; a reconnect passes the just-dropped mode so the current
  path is retried before failing over. `direct` is coordinator-independent (a P2P
  hole-punch), so it is offered once per pass; `relay` is retried on each member
  because its assignment varies per coordinator. This is the old `Connect` loop,
  refactored so the driver and the initial connect share it.

- **The driver (`reconnectLoop`)** watches the live session's `Closed()` and, on a
  drop, re-establishes — retrying the dropped mode first, then failing over to the
  other candidate — and swaps the fresh session under the SOCKS listener with no
  rebind (`serveReconnectSocks` binds once and reads the active session at accept
  time, mirroring `bindPoolSocks`). It is `wg`-tracked and exits on `Stop`/ctx.

- **Two capped backoff clocks, so it never busy-loops.** `reconnect` spaces
  *failed* establish passes with exponential backoff (base 500 ms, doubling,
  capped at 15 s). A separate *flap guard* handles the connect-then-drop-at-once
  case the pool damps for free via its sustained-flow probe (this path has no
  probe): a session that held for `reconnectHealthy` (5 s) is a genuine one-off
  drop and is retried fast, while one that dies immediately grows a capped wait, so
  a rapid connect/drop cycle cannot spin.

- **Retry until recovered, not a fixed budget.** With `reconnectMaxAttempts == 0`
  (the default) the driver retries until the path returns or the engine stops —
  resilience over self-limiting, matching the M4 milestone intent and standard VPN
  behavior. "Bounded recovery time" still holds: a returning exit is picked up
  within one capped interval, and a `Stop` during a backoff wait interrupts it at
  once (no shutdown-time leak). A positive budget (used by tests) makes it give up
  and surface a terminal error instead.

- **Every transition is a `core` event**, on the same channel the Windows client
  already consumes: `EventError` on the drop and on abandonment (the client
  surfaces it live), `EventInfo` for retry/flap progress, `EventConnected` on
  recovery. No new event kind was needed.

- **Testable through a seam.** `establishFn` (default `establish`) is the
  single-transport analog of the pool's `dialFn`: unit tests drive backoff and
  failover deterministically with fake sessions and no network, and a loopback
  smoke test runs the real `Connect`/`establish`/coordinator-pairing path with a
  fake transport whose sessions it kills mid-flight.

## Consequences

- The default single-transport client now self-heals when its path drops — the #2
  acceptance — automatically, within a bounded time, with no user action and no
  SOCKS rebind, and narrates each state transition to the UI.
- The refactor left the coordinator-rotation and force-major (#36) behavior of the
  initial connect unchanged; `establish` is the old loop, and the existing
  rotation tests still pass.
- Accepted limits and named follow-ups:
  - **Real-transport teardown is confirmed only on real infra.** The unit and
    loopback tests use fake sessions / a fake transport, because there is no
    in-process real WebRTC/Reality client↔exit harness. The reconnect logic is
    transport-agnostic (it reacts to `Session.Closed()`), so this exercises exactly
    the engine behavior #2 owns; how promptly a live WebRTC data-channel or Reality
    TCP conn reports its own teardown is a transport property, validated on the
    running stack (a loopback deployment + a real client), not here.
  - **The race detector could not run locally** (no cgo/C toolchain on the dev
    box); concurrency is guarded by `rcMu` and a write-once `exitPub`, and the
    timing tests were stress-run. CI with `-race` is the backstop.
  - **This is the non-pooled path only.** A client with `TransportPool` set uses
    the pool's own failover (ADR-0028); the two never run together. Unifying them
    behind one connection manager is possible later but not needed for v1.
  - **Server-side reaping is separate (#3).** This is the client re-establishing;
    the exit/relay expiring its half of the dropped session is that issue.
  - **A permanently-gone exit means the client retries forever** at the capped
    interval (by design). A future client UI could surface a persistent
    "reconnecting…" state so the user can choose a different exit.
