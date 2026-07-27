# Bacchus — Windows Client UI

Minimal system-tray app that makes the client clickable. Runs the `core` engine
in-process (client role), lists the **countries** the coordinator will assign an
exit in, lets you pick one, and routes the **whole device** through the tunnel
via a wintun TUN adapter — not just the browser.

> v0 — rebuilt properly later (code-signing).

**New here?** Start with [Working on this client](#working-on-this-client) at
the bottom: what to install, what you can and cannot verify on a dev machine,
and which of the guarantees below are enforced by code versus upheld only by
convention.

## You pick a country; the coordinator picks the exit

This is the single most important thing to understand about the client, because
it shapes the tray, the settings window and the wire.

A client **cannot name an exit**. It names a country, and the coordinator
chooses which exit inside that country to assign (issue #146,
[ADR-0042](../../docs/adr/0042-country-only-exit-assignment.md)). The exit's
identity comes back on the session reply, and it is load-bearing rather than
informational: an exit's id *is* its Noise static public key
([ADR-0009](../../docs/adr/0009-noise-nk-client-exit-e2e.md)), so a session reply
that omits it is unusable and is treated as a refusal.

Two consequences worth internalising:

- `core.Config.ExitID` is **accepted and ignored**. `core.New` emits a loud
  error event when a client sets it. This client therefore never sets it — see
  `clientEngineConfig` in `main.go`, which says so at length because an earlier
  version set it and justified doing so with a claim about `core` that was not
  true.
- The coordinator may legitimately assign a **different exit inside the same
  country** on every reconnect. Nothing in the client should treat "the exit"
  as stable for the life of a session.

## What it does
- Tray menu: **status · selected country · Refresh countries · country list ·
  Connect · Disconnect · Connection settings… · Show invite QR… · Quit**.
- **Refresh countries** → starts a throwaway client-role engine, asks the
  coordinator which countries it will assign in, tears the engine down;
  populates the menu. A country with exits but none currently assignable is
  shown as **busy** rather than hidden, so a full country is labelled instead of
  silently vanishing (issue #147).
- **Connect** → builds a `core.Engine` for the picked country (forced through
  the TURN relay — see "Why TURN-only" below) and starts it in-process;
  drives UI state from `core.Event`s. Once the tunnel's SOCKS5 server is up,
  brings up a wintun adapter + userspace netstack (`tun2socks.go`) and
  reroutes the device's default route through it (`routes.go`), excluding the
  coordinator/STUN/TURN endpoints so the tunnel's own signalling doesn't loop
  into itself. Disables IPv6 on the physical adapter for the duration, then
  arms the **fail-closed kill-switch** (`killswitch.go`).
- **Disconnect / Quit** → lifts the kill-switch, tears the tunnel down
  (restores routing + IPv6), cancels the engine's context, and stops it.

### Kill-switch (fail-closed)
While connected, the machine's outbound default action is flipped to **Block**
with a narrow allowlist, so **nothing egresses in the clear even if the tunnel
— or this whole process — dies.** This matters because a killed process's
wintun adapter is auto-removed and its routes vanish, which would otherwise
resurface the physical default route and leak your real IP at the exact moment
you think you're protected. Only an OS-level firewall filter survives our
death, so that is what enforces it.

The allowlist permits only: the tunnel adapter itself, the control-plane
endpoints (coordinator/STUN/TURN), the configured `bypass` destinations
(kept current for the life of the session — see Split tunnelling below),
loopback, and DHCP. There is deliberately **no plaintext-DNS allowance** — DNS
goes over TCP through the tunnel, so the lockdown can't leak a lookup. The
status line shows **Protected** / **Blocked — tunnel down** / **Disconnected**.

Because it's fail-closed, a hard crash while connected leaves you **offline
until recovered** (this is the correct behaviour for a kill-switch — no leak).
Recovery is automatic: relaunching `bacchus.exe` detects the leftover lockdown
(the prior firewall state is stashed in a marker rule so it survives the
crash) and restores normal networking on startup. Set `"disableKillSwitch":
true` in config to opt out (accepts plaintext fallback — not recommended).

### Why TURN-only
Full-device routing needs to know, up front, which address to exclude from
the tunnel's route so the tunnel's own traffic doesn't loop into itself. A
direct P2P path's address is only known after ICE completes — too late, and
racy. So this path always sets `ForceRelay: true`, which pins the session to
the (statically configured, known-in-advance) TURN server. The "direct"
optimization is only used by the plain `cmd/node` CLI and the (now-removed)
browser-PAC v0 flow.

### Connection settings (issue #75)
Tray → **Connection settings…** opens a window over the transport pool /
per-user failover core already implements (ADR-0028): a geo picker
(`core.Config.Geo`), a reorderable transport ladder, a relay-hop count, and a
**Reset learned paths** button (`core.Engine.ResetSelection()`). Design in
[docs/design/client-connection-ui.md](../../docs/design/client-connection-ui.md)
and [ADR-0036](../../docs/adr/0036-windows-client-connection-strategy-and-invite-qr-ui.md);
how reality's underlay is kept leak-safe here in
[ADR-0028's #109 amendment](../../docs/adr/0028-transport-pool-and-per-user-failover.md).

**Live country switching (issue #137).** Picking a different country from the
tray switches to it live if a session is already connected — no manual
Disconnect/Connect. The switch rebuilds only the engine: the wintun adapter,
the routes and the kill-switch stay exactly as they were, **armed throughout**.
That is safe rather than merely convenient, because `tun2socks` dials the fixed
local SOCKS address per flow instead of holding a connection to it, so the
tunnel layer never has to know which exit is underneath it. A flow arriving in
the gap between the old engine stopping and the new one listening simply fails
to dial — the same fail-closed `Blocked` any other transient drop produces,
never a leak to the physical interface.

The switch carries the whole connection strategy across: the transport ladder,
the selection directory and the learned-path store all apply to the new country
exactly as they did to the old one. **`Geo` is what makes a switch a switch** —
`selection.Ladder` filters candidates to the chosen country (`inScope`) before
racing them, and the learned-path store is keyed on `(network, geo)`, so a
winner remembered for one country is invisible to a lookup for another.

A burst of clicks collapses to the last selection rather than stacking one
reconnect per click. The debounce mailbox deliberately carries **no value** —
it is a bare "the selection changed, catch up" wakeup, and the switch reads the
picker itself — so the tray's checkmark and the country the session actually
switches to cannot disagree.

A click only switches live once a session is fully up. During
`Connecting…`/`Bringing up tunnel…` there is no tunnel to switch underneath
yet, so the click just updates the selection and the connect in progress
finishes on the country it started with — pick again once it is `Protected`. If
the switch fails once it has torn the old session down — nothing assignable in
the new country, or the new engine will not start — the session ends rather than
silently falling back to the country you just deselected: the status and
`bacchus.log` both carry the reason, and the kill-switch means "no session" reads
as `Blocked`, never as a leak.

One case is different and better: if the switch is rejected *before* anything is
torn down — a bad mesh-recovery setting, which is checked while building the new
config — you stay connected on the country you were already on. The tray shows
`Country switch failed: …`, but that line is not written to `bacchus.log` and the
next engine event overwrites it, since the session is still live and still
emitting. If you clicked a country and nothing appeared to happen, that is this
case; check the Settings dialog.

**Two controls, one country.** The settings window's geo box and the tray picker
both feed `core.Config.Geo`. They are not independent inputs: the saved geo is
the *persisted preference* and seeds the picker at startup, the picker is the
authority from then on, and saving a new geo re-seeds the picker (and switches a
live session, exactly as a tray click would). One of them silently losing is the
failure this arrangement exists to prevent.

- **Automatic path selection** (checkbox) turns the pool on/off. Off
  reproduces the exact pre-#75 behavior: a single transport into the
  coordinator-assigned exit in your chosen country.
- **Transport ladder** lists every transport core knows (`webrtc`, `reality`)
  and both are usable here. `reality`'s exit address is learned only once a
  session is dialing (via coordinator signaling), so it can't be pre-excluded
  the way the known TURN server is; instead it's excluded from the tunnel's
  route (and allow-listed under the kill-switch) on the dial path, just before
  the underlay connects, via `Config.OnUnderlayDial` (issue #109 — see
  `poolroutes.go` and "Why TURN-only" above). That holds on a mid-session
  failover too: a re-dial to a different exit excludes its own new address as
  it dials it.
- **Relay hops** is a disabled placeholder — this client has no way to configure
  a hop count yet (issue #137's follow-up). Multi-hop chaining itself is a `core`
  feature with its own design (issue #142, ADR-0038); the gap is the GUI wiring,
  not the transport.

### Invite QR (issue #32)
Tray → **Show invite QR…** turns an already-issued `bacchus1:…` coldstart
invite string (minted out of band by an operator running
`cmd/coldstart-issue` — this client never mints one itself) into a scannable
QR code, so it can be handed to a new user in person instead of copy-pasted.
Paste the string, click **Generate QR**, and either point a phone camera at
the screen or share the rendered image directly. Client-side generation and
display only — nothing is sent over the network, and scanning/decoding a QR
back into an invite (the other half of "cold-start by scanning") is not part
of this client; see the design doc for scope.

### DNS
DNS gets its own special case rather than the general UDP path below: the
netstack intercepts every outbound UDP/53 packet regardless of which resolver
the OS was pointed at, and re-resolves it via DNS-over-TCP through the same
SOCKS tunnel against `dns` in config (default `1.1.1.1:53`).

**Why `1.1.1.1` is a sound default even though Cloudflare is blocked in Russia.**
The client never sends a packet to that address. `handleDNSUDP` calls
`resolveDNSOverTCP`, which calls `dialSOCKS(socksAddr, dnsUpstream)` — the
resolver is a *destination inside the tunnel*, dialled by the exit from the
exit's own vantage. What leaves the client's network interface is the tunnel's
underlay traffic to the coordinator/TURN/reality endpoint, never anything
addressed to `1.1.1.1`. Blocking at the client's ISP therefore cannot touch it.

Two things make that argument hold rather than merely sound plausible, and both
are worth re-checking if this path is ever changed:

1. **The DNS path has no bypass branch.** `handleTCP` and `handleGeneralUDP`
   both consult `policy.direct(dst)` and will dial straight out for a
   split-tunnel destination. `handleDNSUDP` does not — `policy` is passed to it
   only so answers can be *observed* for domain-bypass learning, never to route
   the query. So DNS is unconditionally tunnelled, including for a domain on
   your `bypass` list. (A consequence worth knowing: bypassing a domain sends
   its *traffic* direct but still resolves its *name* through the exit.)
2. **It fails closed.** If the SOCKS dial fails, `handleDNSUDP` drops the query
   and loops; there is no plaintext-DNS fallback, and the kill-switch
   deliberately carries no plaintext-DNS allowance either.

This reasoning covers the tunnelled path only. Before Connect and after
Disconnect the OS uses whatever resolver it is configured with — `dns` in this
config is queried *only* through the tunnel, and is not a system-wide setting.

### General UDP (QUIC, VoIP, games, ...)
Every other UDP flow (i.e. not DNS) is proxied through the tunnel too, via a
genuine SOCKS5 UDP ASSOCIATE against the same local SOCKS server CONNECT
uses (ADR-0034) — so QUIC/HTTP3, voice/video calls, and games work while
connected instead of only falling back to whatever TCP path they have (most
browsers retry HTTP/3 over TCP automatically; plenty of UDP-only apps don't).
Split tunnelling applies the same way it does to TCP: a `bypass` destination
dials directly, everything else goes through the tunnel.

Each flow is tracked by its 5-tuple and torn down after 45 seconds with no
traffic either way, mirroring how a NAT table ages out an idle mapping. The
hard invariant, matching the kill-switch's fail-closed posture: if the
tunnel can't be reached for a flow, its datagrams are dropped — never sent to
the real destination in the clear, and never a fallback to a direct dial for
something split tunnelling said should be tunnelled.

### Split tunnelling
`bypass` (config) lists destinations — IPs, CIDRs, and/or domains — that
should egress the physical interface instead of the tunnel, e.g. RU
banking/gov/streaming sites that geo-block or degrade a foreign exit IP.
`bypassMode` picks which way round: `"exclude"` (default) tunnels everything
*except* `bypass`; `"include"` tunnels *only* `bypass` and sends everything
else direct.

One hazard this design exists specifically to avoid: the tunnel's route is a
split-*default* (`0.0.0.0/1` + `128.0.0.0/1`, see Config below), which beats
the real default for any address without a more specific route pointing
elsewhere. A "direct" dial for a destination with no such route would just
get routed straight back into the tunnel adapter and loop — the same reason
the control-plane endpoints already carry their own exclusion routes. The two
modes take opposite approaches to avoiding it:

- **`exclude`** captures everything into the tunnel (the split-default route)
  and carves `bypass` back out: IPs/CIDRs get an exclusion route (via the real
  gateway) as soon as the tunnel comes up, and domains are matched against
  every query the DNS interceptor already sees — the first time one resolves,
  its address is excluded live, before the answer goes back to whatever asked
  for it, so it's covered before any follow-up connection can race the route
  being installed. A CDN-backed domain's address can change mid-session; each
  newly-seen address is picked up the same way, and the kill-switch allowlist
  (below) is refreshed right along with it, so a bypass destination doesn't
  silently stop working under lockdown just because it re-resolved after
  connect.
- **`include`** never installs the split-default at all — the real default
  route stays authoritative for everything, so "direct" traffic (everything
  outside `bypass`) needs no route changes and never touches the tunnel
  adapter. `bypass` itself is what needs a route in this mode: an *inclusion*
  route pulling it *into* the tunnel adapter, the mirror image of `exclude`'s
  exclusion routes, installed the same way (IPs/CIDRs at connect, domains
  seeded once via a normal, un-tunnelled resolution). Its live-tracking is
  weaker than `exclude`'s, though: because only already-included destinations'
  traffic ever reaches the netstack, a `bypass` domain resolving to a new
  address mid-session isn't observed the way it is in `exclude` mode — that
  one connection keeps going through whatever route it had from connect,
  which may by then be stale. Fails toward that connection going direct
  rather than tunnelled, not toward a leak, but it's a real gap versus
  `exclude` mode.

Whichever mode, the shipped `config.example.json` seeds `bypass` with a
handful of well-known RU sites — treat it as a starting point, not a complete
list.

**Kill-switch note for `include` mode:** the kill-switch (below) allow-lists
the control-plane endpoints and `bypass` itself, same as in `exclude` mode —
but it has no notion of "`include` mode's direct traffic was never supposed to
be protected." So arming it blocks (never leaks) that direct traffic for as
long as it's connected, which may be surprising if you expected `include` mode
to leave non-listed traffic untouched. Set `"disableKillSwitch": true` if this
isn't what you want; there's no partial-lockdown option yet.

## Config
Endpoints and TURN credentials load at runtime — **nothing is compiled in**.
Copy `config.example.json` to `bacchus.config.json` (next to `bacchus.exe`) or to
`%APPDATA%\Bacchus\config.json`, and fill in your coordinator/STUN/TURN + TURN
password. `coordinators` is a JSON array — list one or more coordinator
endpoints and the client rotates across them, surviving one being blocked
(issue #6). `bacchus.config.json` is gitignored — never commit it.

## Build (on the Windows dev machine)
```
go build -ldflags "-H=windowsgui" -o bacchus.exe ./clients/windows
```
(`-H=windowsgui` hides the app's own console.)

Build **from** `clients/windows` (or otherwise put the output next to this
directory's files) so `bacchus.exe.manifest` lands beside `bacchus.exe`.
Windows loads a same-named `.manifest` file next to an exe automatically, no
embedding step needed — this one declares the Common Controls v6 dependency
the "Connection settings"/"Invite QR" windows require (`lxn/walk`). Without
it, opening either window fails outright (`TTM_ADDTOOL failed` /
`CreateWindowEx` — Windows falls back to the legacy v5 controls, whose
`TOOLINFO` layout doesn't match). Confirmed by manual testing, not just
documentation — see ADR-0036.

### wintun runtime dependency (fetch separately — not vendored)
The client loads **`wintun.dll`** at runtime (via `golang.zx2c4.com/wintun`) to
create the TUN adapter; it must sit next to `bacchus.exe` (or on the DLL search
path). It is deliberately **not** committed to this repo: `wintun.dll` is
proprietary (© WireGuard LLC, "licensed, not sold" — see its own `LICENSE.txt`),
so it does not belong in an AGPL source tree, and wintun's own guidance is to
distribute the binary "as downloaded from wintun.net", not a rebuilt or
in-repo copy.

Fetch it once from **https://www.wintun.net/builds/** (use the release matching
`golang.zx2c4.com/wintun` in `go.mod` — 0.14.1 at time of writing), unzip, and
copy `wintun/bin/<arch>/wintun.dll` next to `bacchus.exe` for your target arch
(`amd64` for a normal 64-bit build). The staging dir `clients/windows/wintun/`
is git-ignored for exactly this — drop the download there and it can't be
committed by accident. In any release bundle, ship `wintun.dll` **and its
`LICENSE.txt`** alongside the exe.

## Run
- **Run `bacchus.exe` as Administrator.** Creating the wintun adapter and
  changing routes both require it — Connect fails with a clear error
  otherwise, it does not silently fall back to unprotected.
- Put **`bacchus.config.json`** alongside `bacchus.exe` (see Config above). No
  `node.exe` needed — the engine runs in the tray process.
- Make sure the coordinator + STUN/TURN + at least one exit are up.
- Double-click `bacchus.exe` → tray icon → **Refresh countries** → pick one →
  **Connect**. (A country shown as `busy` has exits but none assignable right
  now; picking it will be refused rather than silently substituted.)
- Verify: with Connect showing "Protected", `curl.exe https://ifconfig.me` (no
  `--socks5-hostname` needed — it's not just a browser proxy anymore) should
  show the exit's IP, and a packet capture on the physical adapter should show
  no plaintext DNS. For general UDP (ADR-0034), an HTTP/3-capable client
  (e.g. `curl.exe --http3 https://cloudflare-quic.com`) should also succeed
  through the tunnel rather than falling back to TCP. Kill-switch check: kill
  the tunnel mid-session (stop the exit, or pull the network) — traffic
  should **stop**, not fall back to your real IP, and the status should read
  "Blocked".

## Diagnostics
The tray status line shows live state (`Protected`, `Blocked — tunnel down`,
`Connecting…`, `Error: ...`), but it's ephemeral — the next event overwrites
it. Every event, including ones the tray never shows live (individual ICE
state transitions, session ids), is also appended to a plain-text log at
`%APPDATA%\Bacchus\bacchus.log` (or next to `bacchus.exe` if `%APPDATA%`
isn't set), so a bug report has the full sequence to paste rather than
whatever happened to be on screen. This is necessary, not just convenient:
`bacchus.exe` is built with `-H=windowsgui` (no console), so anything printed
to stdout/stderr — including `core`'s own default logging — is never visible
anywhere. The tray status line and this file are the only two places this
client's diagnostics ever surface.

The log records connection lifecycle events only (connect/disconnect
attempts, session ids, ICE state, dial/handshake error reasons) — never the
sites or content you access through the tunnel, which stay inside the
end-to-end encrypted channel (`core/e2e.go`, ADR-0009) and never reach this
event system at all.

**Address redaction.** There are exactly two writers into `bacchus.log` —
`logEvent` (engine events) and `logLine` (client-side diagnostics) — and both
redact at the point of write, so every IP literal becomes `<ip>` regardless of
which call site produced it. That placement is deliberate: `core` puts real
addresses into event messages as a matter of course (a skipped coordinator, a
mesh peer, a `reality` dial error), and under censorship "the coordinator I
could not reach" is exactly the address a user should not be pasting into a bug
report. Redacting at the writer rather than per-call-site is what stops a future
event source from silently reintroducing the leak.

`runPS` additionally passes its command and output through `routes.go`'s
`logSafe`, which also cuts to the first line and catches the partial dotted-quad
a PowerShell hard wrap leaves behind mid-token — neither of which is an IP
literal that redaction alone can see.

**Redaction recognises IP literals only — never hostnames.** This is the limit
that matters most, so read it before treating the log as safe to share. If your
`coordinators`, `stun` or `turn` entries are DNS names rather than literals —
which `config.example.json` shows as the normal form — then a failure logs them
in the clear:

```
[error] skipping coordinator "rv1.example.org:8080": i/o timeout
[error] core: no usable coordinator in pool [rv1.example.org:8080 rv2.example.org:8080]
[error] dial tcp exit-nl-03.example.org:443: i/o timeout
```

The second of those names the whole pool at once, at exactly the moment a client
is failing under censorship. A hostname identifies a node more precisely than any
address would, so **if you configure by name, treat `bacchus.log` as naming your
infrastructure** and redact it yourself before sharing. Redacting hostnames at the
writer is tracked as follow-up work; today the guarantee is about literals.

Three further residues are known and deliberate, all of them narrow:

- a **one-octet tail** (`…203`), indistinguishable from an interface index or a
  route metric;
- a **wrapped IPv6 literal**, which truncates into a shape no rule can separate
  from ordinary colon-separated command text;
- an **IPv6 zone id** (`fe80::1%eth0` → `<ip>%eth0`).

Those three are fragments and cannot name a node. The hostname case above can, and
is the one to check before pasting a log anywhere. The live tray status is *not*
redacted: it is ephemeral, never written to disk, and keeps full diagnostic value
for the running session.

## Known limits (v0)
- General UDP forwarding (see above) assumes one destination per flow for its
  whole lifetime — this client only ever needs that, since it opens one SOCKS
  UDP ASSOCIATE per captured 5-tuple, but it means the local SOCKS server
  isn't a fully spec-complete RFC 1928 UDP ASSOCIATE implementation (no
  multi-destination multiplexing on one association). Not relevant unless
  something other than this client ever talks to that local SOCKS server.
- IPv6 is blocked (adapter binding disabled), not tunnelled.
- Split tunnelling is **destination-based only** — by IP/CIDR/domain
  (`bypass`), not by process/app. Per-app split tunnelling is a separate,
  harder problem (Windows has no `addAllowedApplication`-style API) and isn't
  planned for v1.
- A bypass domain resolved via the OS's *own* DNS cache from before connect
  (rather than a fresh query the interceptor observes) won't be recognized
  until something actually re-queries it — the safe direction to fail (that
  traffic tunnels instead of going direct), just not the intended one.
- `bypassMode: "include"` doesn't live-track a `bypass` domain's mid-session IP
  rotation the way `"exclude"` mode does — only already-included traffic
  reaches the interceptor at all (see Split tunnelling above), so a CDN
  rebalancing after connect isn't observed. Fails toward that connection going
  direct, not toward a leak. Also: the kill-switch has no notion of `"include"`
  mode's direct traffic being something that was never meant to be protected,
  so arming it blocks that traffic (rather than leaving it alone) for as long
  as it's connected.
- A hard crash leaves the tunnel adapter/routes and the IPv6-disabled binding
  behind; these are cleaned up on next launch alongside the kill-switch
  recovery. To clear manually: `Enable-NetAdapterBinding -ComponentID
  ms_tcpip6`, `Set-NetFirewallProfile -All -DefaultOutboundAction Allow`,
  `Remove-NetFirewallRule -Group BacchusKillSwitch`.
- Not code-signed (SmartScreen will warn). Auto-reconnect *is* implemented, in
  `core` rather than here (ADR-0030, `reconnectLoop`) — an earlier version of
  this line said otherwise and was wrong.

## Working on this client

Everything below is for someone who has just cloned the repo.

### Prerequisites

| What | Why |
|---|---|
| **Go ≥ the `go` directive in `go.mod`** (1.26.4 at time of writing) | The whole repo is one Go module. Nothing else is needed to `build`, `vet` or `test` this package. |
| **Windows** | This package is `//go:build windows` in every file. It does not cross-compile meaningfully, and `go test ./clients/windows/...` on another OS builds nothing and reports success — a green run on Linux means *no tests ran*. |
| **`wintun.dll`**, fetched separately | Only needed to actually *run* the client. See below. Tests do not need it: they never create a TUN adapter. |
| **Administrator**, only to run | Creating the adapter and editing routes require it. Not needed to build or test. |
| **A C toolchain** — optional, and see the `-race` note | Not needed for anything in this package. It *is* needed for `clients/fyne`. |

### Build, vet, test

```bash
go build ./clients/windows && go vet ./clients/windows/... && gofmt -l clients && go test -count=1 -timeout 20m ./clients/windows/...
```

That is exactly what CI runs. Notes on each:

- **`gofmt -l clients`** must print nothing. It is a CI gate, not a suggestion.
- **`-timeout 20m`** is not optional. Several tests drive real WebRTC handshakes
  on `core`'s own fixed timeouts and run ~90–120s each; the default 600s
  per-binary limit is close enough to the total that a slow runner would turn
  into a panic-on-timeout that reads like a product bug.
- **No `-short`.** The slow supervisor and integration tests are gated behind
  `testing.Short()` precisely so a local `go test -short` is a fast inner loop
  while CI still covers them. Adding `-short` to the CI step would silently stop
  covering the tests most worth having.

For the fast inner loop while iterating:

```bash
go test -count=1 -short -timeout 5m ./clients/windows/...
```

### `-race` is not available here, and would not have helped

`go test -race` requires cgo, and cgo on Windows requires a C toolchain (mingw-w64)
that a stock Go install does not provide. Without one, `-race` fails to build; it
is not a flag anyone can simply add.

More importantly, **do not treat `-race` as the safety net for this package.**
The three most serious bugs found in review here were all *check-then-act* races:
every individual access to `engine`/`engineCancel`/`activeTunnel`/`liveCountry`
was correctly mutex-guarded, and what was missing was atomicity *across* two of
them. No data-race detector models that. The countermeasure that does work is
structural — one function (`adoptEngine`) does the re-check and the assignment in
a single critical section, and every write to the session globals goes through
it — plus tests that **pin** the interleaving through the `newCoreEngine` seam
rather than firing a goroutine and hoping. See `switchcountry_test.go`.

### How the tests are organised

| File | What it covers |
|---|---|
| `main_test.go`, `routes_test.go`, `splittunnel_test.go`, … | Pure helpers. Fast, no network. |
| `midsession_recovery_test.go` | Supervisor-level mesh-walk recovery against a **hand-rolled fake coordinator** on real loopback UDP, with real client and exit engines. Also holds the shared harness (fake coordinator, test exits, SOCKS echo, connection-state helpers). |
| `switchcountry_test.go` | Live country switching, including two pinned concurrent-disconnect races. |
| `coordinator_integration_test.go` | The **real `cmd/coordinator` binary** as a subprocess, with this package's own engine composition. |

That last one exists because of a specific failure: the fake in
`midsession_recovery_test.go` was forked from `cmd/node`'s before country-only
assignment and answered a wire no coordinator had spoken since. Every test here
passed, and no client built from this package could have connected to a real
coordinator. **A fake on both sides of a protocol tests the fakes.** If you
change anything about what the client sends, the integration test is the one
that will tell you the truth.

### Where the logs are, and how to read them

`%APPDATA%\Bacchus\bacchus.log` (or next to `bacchus.exe` when `%APPDATA%` is
unset). Append-only, plain text, no rotation. Lines look like:

```
2026/07/27 21:31:45 [error] skipping coordinator "<ip>:51820": blocked
2026/07/27 21:31:45 bringing up tunnel, excluding <ip>:51820
```

`[kind]` is the `core.Event` kind (`info`, `error`, `ice`, `session`,
`connected`); unprefixed lines are client-side diagnostics from `logLine`.
Addresses are `<ip>` by design — see Diagnostics above. **Tests must not write
here**: use `redirectEventLogForTest(t)`, and call it *before*
`resetConnectionState(t)` so the LIFO cleanup order keeps the teardown contained
too.

### What "Protected" actually guarantees

`Protected — <country>` means all of: a `core.Engine` is live and its SOCKS5
server is bound; the wintun adapter exists with the split-default route
installed; and, unless `disableKillSwitch` is set, the OS firewall's default
outbound action is **Block** with the narrow allowlist armed.

It does **not** mean the coordinator assigned you an exit that is physically in
that country — it means it assigned one it *labels* as being there. With no
GeoIP database configured, a coordinator falls back to each node's self-reported
country tag (issue #136).

The failure this word is guarded against is showing `Protected` while the tunnel
is down — [ADR-0039](../../docs/adr/0039-fyne-cross-platform-client-skeleton.md)'s
belief-safety failure, where "the tunnel came up… 100% of traffic went out in the
clear". That is why the supervisor tests assert on the *status string* directly
rather than inferring it from engine state, and why they assert on the **wrong**
state (engine live, tunnel gone, status lying, SOCKS still bound) rather than on
eventual convergence — a test that only checks "everything ends up torn down"
passes whether or not the guard exists.

### Enforced by code vs. upheld by convention

Reviews here have repeatedly turned up comments asserting properties the code did
not have. Trust this table over any comment, and the code over this table.

**Enforced — a violation fails to build, or fails a test that exists:**

- Every write that *publishes* a session — `connect`, `switchCountry`,
  `watchMeshRecovery` — goes through `adoptEngine`, which re-checks ownership and
  assigns in one critical section. All three concurrent-disconnect tests fail if
  it is bypassed. Two writes deliberately do not go through it and are not
  covered by that claim: `disconnect()` clears all four globals directly, and
  `connect()` assigns `activeTunnel` inside its own checking critical section.
  Both are correct; neither is publishing a replacement engine, which is the only
  thing `adoptEngine` exists to serialise.
- The client never sets `core.Config.ExitID`. Asserted directly, and the
  real-coordinator test fails if it is set to a literal. Note the assertion does
  not catch `ExitID: snap.ExitID`, since no fixture populates the dead config
  field — see the "assumed" list.
- Both writers into `bacchus.log` redact **IP literals**. Asserted by reading the
  real log file back. Hostnames are not redacted — see "Address redaction".
- `socksAddr` is a package constant used identically by `connect`,
  `switchCountry` and `startTunnel`, so the address the new engine binds is
  always the one `tun2socks` dials.
- DNS is unconditionally tunnelled — there is no `policy.direct` branch on that
  path.
- `gofmt`, `go vet`, and the full test suite are CI gates.

**Convention only — nothing will stop you:**

- *Fail-closed on every new error path.* The existing paths are fail-closed and
  tested, but nothing forces a newly added one to be.
- *The event log records lifecycle events only, never traffic content.* True
  today because nothing passes traffic to `logEvent`; no mechanism enforces it.
- *Reserved (RFC 5737/3849) addresses in examples and fixtures.* A convention,
  and one this package broke in ~70 places until it was swept.
- *Comments describing `core`'s behaviour.* `core` is a separate package with no
  compile-time link to what a comment here claims about it. Two review blockers
  were comments that confidently described a `core` behaviour that did not
  exist. **Go read `core` before believing one.**
- *Tests staying off the developer's real machine state* (the event log, the
  `HKCU\...\Run` key, the routing table). Helpers exist for each; using them is
  up to you.
