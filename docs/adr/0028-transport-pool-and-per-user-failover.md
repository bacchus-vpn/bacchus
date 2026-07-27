# 28. Transport/exit selection is a validated priority ladder with per-network learning

- Status: accepted
- Date: 2026-07-04

## Context

ADR-0008 made `Transport` an interface and named the endgame: resistance is the
*union* of many partial transports, chosen per user. ADR-0024 added `reality`
(TCP :443) as a second axis to WebRTC's UDP/DTLS. We now have two transports that
fail on different axes but no client logic to choose between them —
`Config.Transport` picks exactly one, set ahead of time, blind to whether it
actually works from this user's network.

Russian blocking is per-operator, regionally fragmented, and time-varying (see
the field notes on issue #15). So the choice cannot be static or global: the
client must carry several candidate paths and discover which one works *here,
now*. Three traps make a naïve racer fail:

1. **"Connected" ≠ "working".** A soft-block completes the handshake, then wedges
   the flow around 16 KB / ~25 packets (the destination-freeze). Handshake
   success is not evidence of a usable path.
2. **Racing is noisy.** Firing every axis at every endpoint at once looks
   anomalous and burns endpoints to active probing.
3. **The answer is per-network and worth remembering.** Re-racing on every
   connect wastes latency and probe budget when last time's winner still works.

The owner also specified the *order* of the search: stay on the fast path (the
primary transport to the lowest-ping exit in the user's chosen geo), exhaust
exits before changing protocol, and change protocol before routing through nodes.

## Decision

A candidate path is `{transport, exit, mode}` (`core/selection.Candidate`; mode
is direct hole-punch or relayed through nodes). Selection is a **priority
ladder**, not a flat race, built by the pure `core/selection` package and driven
by `core/pool.go`:

- **The ladder (`selection.Ladder`)**, highest priority first:
  0. the **learned winner** for this network+geo, if any and not itself cooling;
  1. **primary transport**, every in-geo exit by ping (fastest first), direct;
  2. **alternate transports**, same exits, direct;
  3. **relay** ("route through nodes"), primary transport — the last resort.

  Exits outside the user's chosen geo are filtered out; within a tier, a
  recently failed candidate sinks to the back but is still tried; the result is
  de-duplicated keeping highest priority.

- **Staggered racing (`raceLadder`)** walks the ladder happy-eyeballs style:
  start the top candidate, and every ~800 ms — or immediately on a failure —
  start the next, at most two in flight. The first candidate to return a
  *validated* session wins; the losers are cancelled and any session they raced
  to completion is closed. The common case touches one path; the rest never
  start (trap #2).

- **Sustained-flow validation (`validateSession` + `core/pool_probe.go`)** is
  what "validated" means (trap #1). After the transport dials and the client
  completes Noise_NK to the exit, it pushes ~32 KB to a reserved echo target and
  reads it back; only a path that returns all of it — past the freeze threshold —
  wins. This reuses the accounting-sentinel seam (a reserved `.invalid` target
  the exit branches on *after* the identical handshake), so `core/e2e.go` is
  unchanged, the probe rides inside the same encryption as real traffic, and it
  is reachable only after transport setup + exit authentication — the same
  admission/anti-probe gates (#42/#60/#62) as any real connection, no new
  external surface. The round-trip it measures **is** the ping that ranks exits,
  so validation and ranking are one mechanism.

- **Per-network learning (`core/selection.Store`)** remembers each validated
  winner on the device, keyed to the network and geo, and tries it first next
  time (Tier 0). It persists to a single JSON file (`SelectionDir`), holds
  nothing user-identifying, expires after a TTL, and is cleared by
  `Engine.ResetSelection()` — the user's reset control. `NetworkKey()` supplies
  the per-network fingerprint: a hashed digest of the machine's masked local
  subnets + interface names (no host IP or MAC stored), stable while attached and
  distinct across most networks; offline it degrades to one `"default"` bucket.

- **Failover (`maintainPath`)** binds the local SOCKS listener once and swaps the
  active session underneath it: when the committed path drops, the candidate is
  marked cooling and the ladder is re-run (with a bounded backoff retry, so a
  transient blip does not permanently end failover), reconnecting to a
  *different* candidate with no rebind.

- **Opt-in, backward-compatible.** `Config.TransportPool` (a preference-ordered
  list; `[0]` is primary) turns the pool on; empty preserves the exact pre-pool
  single-transport `Connect`. The pool composes with — does not replace — the
  coordinator rotation (ADR-0020), which still runs underneath each candidate's
  pairing.

## Consequences

- The client now finds a working path automatically when some candidates are
  blocked, and reconnects to a different one when the active path is blocked —
  the #15 acceptance — with the user's real traffic never committed to a path
  that failed sustained-flow validation.
- Selection policy (ordering, learning, TTL) lives in a pure, dependency-free
  package tested without a network; the engine layer holds only the I/O.
- Adding this required no change above the `Transport` interface and no
  coordinator or `core/e2e.go` change, validating ADR-0008 and ADR-0009 again.
- Accepted limits and named follow-ups:
  - **Exit selection is machinery-complete but not yet *real*:** only one exit
    exists (issue #5). Ranking-by-ping and "other exits in the same geo" are
    exercised by tests with fake multi-exit sets and degrade cleanly to one exit
    until #5 lands.
  - **The node tier is today's relay mode.** Configurable multi-hop / node count
    is a follow-up (needs a relay-chaining protocol), as is user-editable ladder
    ordering and manual server-IP entry — all surfaced through a future client UI.
  - **`NetworkKey()` is a hashed subnet+interface fingerprint** — portable and
    non-identifying, but two networks sharing the same private subnet and adapter
    collide into one bucket (harmless: a mis-keyed winner just fails validation).
    Breaking that collision needs the default-gateway MAC (platform-specific ARP)
    and is the hardening follow-up (#77); see `docs/design/transport-pool.md`.

    > **Update (2026-07-11):** closed for Windows by issue #77. `NetworkKey()`
    > now mixes in a fingerprint of the default gateway's MAC (resolved via
    > `SendARP`, hashed into the digest — no raw MAC stored) where a cheap
    > platform lookup exists (`core/selection/network_windows.go`; other
    > platforms return "" and keep the exact prior digest, so nothing is
    > invalidated). Two cafés on the same subnet behind different access points
    > now key differently. See the amendment below.
  - **Probe bandwidth.** ~32 KB per validated candidate is a real cost on metered
    mobile; the size is a single constant, tunable down as field data arrives.
  - **Accounting (ADR-0021) is not wired into pooled sessions** yet; the pool
    passes a nil counter. Attributing pooled/relayed sessions is future work.
  - **The pool's own exit fetch (`poolExits`) didn't defer to the force-major
    version cutover (ADR-0029/#36).** A `ListExits` failure fell straight
    through to the pinned exit (when configured) regardless of *why* it
    failed, so a pinned pooled client could keep connecting on a network its
    build could no longer speak to at all, and an unpinned one saw a generic
    "no exits" error instead of the actionable one.

    > **Update (2026-07-05):** closed by issue #79. `poolExits` now withholds
    > the pinned exit once `updateRequired()` is latched, and `selectPath`
    > checks the same latch both before and after the exits fetch — the fetch
    > itself is usually what first observes the mismatch, since a coordinator's
    > reply is inspected as it arrives, before the caller sees the result.
    > `connectPooled` now aborts with the same actionable error the non-pooled
    > `Connect` loop already surfaced, pinned exit or not — no new error path,
    > just correct use of the existing engine-wide latch. Folded in alongside:
    > `connectPooled` now closes the committed session and clears the active
    > path if `bindPoolSocks` fails after a path was already selected, instead
    > of leaking the session and leaving stale active-path state.

## Amendment (2026-07-11): late underlay exclusion (#109) and gateway-hardened NetworkKey (#77)

### Late underlay-address exclusion — reality in the full-device pool (#109)

The Windows full-device client (#75, ADR-0036) shipped its pool restricted to
`webrtc` only. A full-device tunnel makes every destination egress through the
tunnel and, under the kill-switch, blocks everything not on a tiny allowlist —
so a transport's own underlay connection must be *excluded* from that tunnel
(a host route via the physical gateway) and *allow-listed*, or it loops into
the tunnel it is carrying (and is Blocked once the kill-switch arms). WebRTC
gets this for free: `ForceRelay` pins every candidate to the one configured TURN
server, a fixed, known-ahead-of-time address already in the exclusion set.
Reality can't be pinned — its exit dial address arrives only in the per-session
coordinator answer, at `Dial` time — so there was nothing to exclude in advance,
and shipping it would have reopened the very leak `webrtc`-only avoided.

The fix is a **pre-underlay-dial callback**, `Config.OnUnderlayDial(addr)`, that
a transport invokes the instant it has learned the physical address it is about
to connect to but **before** it opens that connection
(`core/transport_reality.go`'s `dialInner`, just before `DialContext`). The
full-device client wires it to a `poolExcluder` (`clients/windows/poolroutes.go`)
that installs the host-route exclusion and, under the kill-switch, the allowlist
entry, and returns only once the address is tunnel-safe. Because it fires on the
dial path — **not** after the pool commits a winner — it is correct for a
mid-session failover by construction: `maintainPath` re-dials a different exit
while the split-default route is already live, and that re-dial excludes its own
new address as it dials it, so the "route flip races the real address" window
never opens. A post-commit notification would not do this: at commit the
underlay is already dialled, so during a failover it would already have looped.

Details that make it leak-safe rather than merely working:

- **Fail-safe under every partial failure.** A missing route loops the dial into
  the tunnel; a missing allowlist entry lets the armed kill-switch Block it.
  Both *fail closed* — the path breaks, nothing egresses in the clear — so the
  callback only has to install both before returning, in any order. If it can't
  (e.g. a hostname answer that won't resolve under an already-armed kill-switch),
  the dial still proceeds and simply fails into the tunnel; it never leaks.
- **Bring-up vs. failover.** The initial pooled `Connect` dials reality before
  the tunnel exists, so the excluder only *records* those addresses; `startTunnel`
  installs their routes before the split-default flips and folds them into the
  initial kill-switch allowlist. After bring-up the excluder installs live.
- **Arm/reserve atomicity.** The reserve path and the kill-switch arm share one
  lock across their whole critical section, mirroring the #73 arm/learn fix, so
  an address reserved in the window around arming is either in the initial
  allowlist snapshot or live-refreshed after — never neither.
- **Gate.** `sanitizePoolOrder` stops stripping `reality` *because* `connect()`
  always wires `OnUnderlayDial`; a transport the client couldn't make tunnel-safe
  this way would stay out of `allowedPoolTransports`. `ForceRelay`/WebRTC's
  existing exclusion model is unchanged.

`OnUnderlayDial` is appended last to `Config` (a stable seam for parallel
callers) and is client-role only; the reality responder side never sets it.

### Gateway-hardened `NetworkKey()` (#77)

`NetworkKey()` now mixes the default gateway's MAC into its digest where a cheap
platform lookup exists — Windows via `GetAdaptersAddresses` + `SendARP`
(`core/selection/network_windows.go`), hashed in, no raw MAC stored. That breaks
the accepted same-subnet collision (two cafés both on `192.168.1.0/24` behind
different access points now key differently). It is strictly additive: platforms
without the lookup, and any connect where no gateway resolves, return `""` and
reproduce the exact pre-#77 subnet+interface digest, so no learned bucket is
invalidated and there is never a regression. See `docs/design/transport-pool.md`
for the updated trade-off table.

## Amendment (2026-07-11): pool full-device leak-safety hardening (#117)

Non-blocking follow-ups from the #109/#77 review, all fail-closed before this
change (no user-IP leak in any of the four) — this is hardening, not a bug fix.

- **Stale gateway on a live install.** `poolExcluder.gw` (`clients/windows/
  poolroutes.go`) was captured once, in `goLive`, and reused for every
  subsequent live-install exclusion route for the rest of the session. A
  physical-network change mid-session (the laptop roams to a new Wi-Fi
  network) left it stale, so a failover's reality dial would route its
  exclusion via a gateway that no longer exists — failing that dial into the
  tunnel (fail-closed) rather than merely failing to exclude it, until the next
  full reconnect. `reserve()`'s live-install path now re-resolves the gateway
  fresh (an injected `gatewayFn`, mirroring `excludeFn`/`allowFn`'s existing
  testability seam) immediately before installing, falling back to the
  last-known value only if the re-resolve itself fails. `goLive`'s own initial
  batch install is unaffected — its `gw` parameter is already fresh, resolved
  by `startTunnel` moments before calling it.

  This is unrelated to `core/selection.NetworkKey()` / `gatewayFingerprint()`
  (the #77 mechanism just above): that function has no cache at all — it
  re-resolves the gateway fingerprint on every call — so there was nothing to
  fix there. The two mechanisms only share the word "gateway"; one keys the
  learned-path store, the other excludes a route, and they don't interact.

  Deliberately **not** addressed here: the control-plane exclusion routes
  (coordinator/STUN/TURN) installed once at the top of `startTunnel`, before
  `poolExcluder` existed, have the same "captured once, never re-derived"
  shape and go stale under the identical network change. This is a
  pre-existing limitation predating #109, inherited rather than introduced by
  it — fixing it would mean a live network-change-triggered re-plumb of
  `startTunnel`'s whole bring-up sequence, a bigger and riskier change than
  this hardening pass owns. Acknowledged, not solved: a moved laptop still
  needs a full reconnect to pick up a new physical gateway for the
  control-plane exclusions specifically.

- **IPv6 exit address not excluded.** `resolveExclusions` (`routes.go`) only
  ever resolved IPv4 addresses, so a reality exit advertising an IPv6 literal
  would resolve to no exclusion at all. Safe today only because physical IPv6
  is disabled on the adapter for as long as the tunnel is up
  (`disablePhysicalIPv6`) — an unexcluded IPv6 dial has nothing to route over
  regardless, and fails closed rather than leaking. `reserve()` now also
  resolves IPv6 addresses (`resolveExclusionsV6`) and installs a `/128`
  host-route exclusion via the interface's IPv6 default gateway
  (`addExclusionRoutesV6`, `gatewayInfo.nextHopV6`, best-effort — many
  networks and most of the tunnel's lifetime have no IPv6 default route at
  all, in which case this is a no-op, unchanged from before). Defense in depth
  against that posture ever changing, not a currently reachable leak. Caught
  in the same pass: `hostOf` mis-parsed a bracketed IPv6 `host:port`
  (`"[2001:db8::1]:443"`) — its "does this look like a `scheme:host:port`"
  heuristic counted the address's own colons and sliced into it before
  `net.SplitHostPort` ever saw it. Fixed alongside, since the IPv6 exclusion
  path depends on parsing that shape correctly; `ensureCIDR` (used by the
  shared, family-agnostic `removeRoutes` as well as both `addExclusionRoutes*`
  installers) now appends `/128` rather than `/32` for a bare IPv6 literal.

- **`reserve()` held its lock across the route/allowlist shell-outs.** The
  whole call — recording the address *and* the PowerShell-backed
  `excludeFn`/`allowFn` calls — ran under one `sync.Mutex` acquisition, so a
  slow shell-out could momentarily stall a concurrent `reserve()` (a
  different failover) or the `reserved()` snapshot `startTunnel`'s failure
  cleanup and `tunnel.Close()` both take. Narrowed to match the #73 precedent
  (`splittunnel.go`'s `learn()`): the lock now covers only the *recording* —
  marking an address seen and snapshotting the gateway/armed/closed state
  needed to install it — never the shell-outs themselves.

- **Orphaned-route race the lock-narrowing above reopens.** With the whole
  call under one lock, `startTunnel`'s failure cleanup (or `tunnel.Close()`)
  could never observe a route recorded without also seeing it installed, since
  both are provably atomic with respect to it. Narrowing the lock breaks that:
  a concurrent `reserve()` could have already recorded an address (so a
  `reserved()` snapshot includes it) but not yet finished its unlocked
  install, or the reverse — recorded and installing while teardown's snapshot
  runs just before the recording completes. Either way, cleanup's one-shot
  `removeRoutes(reserved())` can land before the install actually happens,
  leaving a route nothing is tracking (harmless — a `/32`/`/128` to the exit's
  own address via the gateway, no user-IP exposure — but orphaned). Closed
  with a `closed` flag: `poolExcluder.disable()`, called by both teardown
  paths immediately before they take that snapshot, and `reserve()` checks it
  again right after each install — landing after teardown's snapshot now
  self-reaps instead of leaking the route indefinitely.

**Tests (non-vacuous, revert-watch-fail-restore per each item):**
`TestPoolExcluderReserveRefreshesGatewayOnLiveInstall` +
`TestPoolExcluderReserveFallsBackToLastGatewayOnRefreshError`,
`TestPoolExcluderReservesIPv6Address` (+ `resolveExclusionsV6`/`isIPv6Literal`/
`hostOf`/`ensureCIDR` unit tests, `routes_test.go`),
`TestPoolExcluderDoesNotHoldLockAcrossExcludeFn` (a blocked `excludeFn` must
not stall a concurrent `reserved()` call — proven via timeout against the
reverted, whole-call-locked shape), `TestPoolExcluderSelfReapsRouteInstalledAfterDisable`
(all `clients/windows/poolroutes_test.go`). The existing `poolroutes_test.go`
suite and `core/selection`'s hardcoded-digest test (`fa7d497429cba980`, #77)
are unmodified and stay green — this pass touches neither
`core/selection/network_windows.go` nor the digest it pins.

See `docs/design/node-admission.md`'s client-CRL-adoption note (issue #116, a
related client-hardening change landing alongside this one).

## Amendment (2026-07-11): post-#117 follow-ups (#123b, #123c)

Two non-blocking, fail-closed-before-and-after follow-ups from the #117
review, both `clients/windows/poolroutes.go`.

- **Allowlist entry for a route already known to be reaped (#123b).** The
  #117 self-reap above ran `excludeFn`, then unconditionally `if armed {
  allowFn }`, and only *then* checked `closed` to decide whether to reap the
  route. An install racing past `disable()`'s teardown snapshot got its route
  reaped but had already installed a live kill-switch allow rule for the
  same address — harmless for leak-safety (it is only ever an *Allow*, for
  the exit's own address, under a kill-switch that is about to come down
  anyway), but a duplicate-`DisplayName` `Bacchus-Allow-Remotes` firewall
  rule left for the *next* teardown's group sweep to find, since `allowFn`
  had no self-reap of its own the way the route did. `reserve()`'s loop now
  computes the post-`excludeFn` `closed` read once and uses it for both
  decisions: closed reaps the route and skips the allowlist call entirely;
  not-closed installs the allowlist entry as before. Same check, same
  timing, just also gating the call that used to run unconditionally.

- **Gateway shell-out on the dial path (#123c).** #117 made `reserve()`'s
  live-install path re-resolve the physical gateway *synchronously*, on
  every call, immediately before installing — correct (a stale gateway
  routes a failover's exclusion via a next-hop that may no longer exist
  after the machine roams to a new network), but it put a PowerShell spawn
  (`defaultGateway`, two `Get-NetRoute` cmdlets in one script) on the
  critical path of every first dial to a new exit address. `gatewayFn` is no
  longer called from `reserve()` at all: a live install now triggers
  `triggerGatewayRefresh`, a deduplicated one-shot background re-resolve
  (`gwRefreshing` guards against a burst of new addresses spawning one
  PowerShell process each), and reads whatever `p.gw` that background call —
  or `goLive`'s initial seed — most recently wrote. `reserve()` itself never
  waits on it.

  This intentionally trades #117's "always fresh, synchronously, on every
  live install" for "fresh as of the most recent reserve() call before this
  one": at most one live install immediately after a physical-network change
  can still route via the gateway that was current a moment ago. That one
  dial fails exactly like any other missed exclusion (fail-closed — see
  `reserve()`'s doc comment — never a leak), and the pool's own failover
  retries moments later, by which point the background refresh has landed.
  What #117 actually protected against — a gateway captured once at
  `goLive` and never revisited for the rest of the session — is unchanged:
  every live install still triggers a refresh.

  `TestPoolExcluderReserveRefreshesGatewayOnLiveInstall` and
  `TestPoolExcluderReserveFallsBackToLastGatewayOnRefreshError` (named in
  the Tests list above) pinned the synchronous contract this change
  intentionally replaces and are superseded by
  `TestPoolExcluderReserveDoesNotBlockOnGatewayRefresh`,
  `TestPoolExcluderBackgroundRefreshUpdatesGatewayForNextInstall`, and
  `TestPoolExcluderBackgroundRefreshFailureKeepsLastKnownGateway` below.

**Tests (non-vacuous, revert-watch-fail-restore per each item, all
`clients/windows/poolroutes_test.go`):**
`TestPoolExcluderSkipsAllowlistForInstallReapedAfterDisable` (#123b — reverting
the gate back to an unconditional `if armed` before the `closed` check makes
this observe an allow call for a reaped route);
`TestPoolExcluderReserveDoesNotBlockOnGatewayRefresh` (#123c off-dial-path
proof — a slow `gatewayFn` must not stall `reserve()`'s return, reverted by
inlining the refresh instead of backgrounding it);
`TestPoolExcluderBackgroundRefreshUpdatesGatewayForNextInstall` and
`TestPoolExcluderBackgroundRefreshFailureKeepsLastKnownGateway` (#123c
eventual-freshness and fallback proofs — both fail with "background gateway
refresh was never attempted" if `triggerGatewayRefresh` is reverted to a
no-op); `TestPoolExcluderTriggerGatewayRefreshDedupsConcurrentCalls`
(reverted to a no-op, fails on the same "never attempted" check rather than
hanging — the dedup itself has no separate revert target, since removing the
`gwRefreshing` guard is what the other three tests already force to exist).
The rest of the existing `poolroutes_test.go` suite (arm atomicity, dedup,
IPv6, the lock-narrowing and self-reap proofs) is unmodified and stays green.
