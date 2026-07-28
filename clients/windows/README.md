# Bacchus — Windows Client UI

Minimal system-tray app that makes the client clickable. Runs the `core` engine
in-process (client role), lists the countries the coordinator can assign exits
in, lets you pick one, and routes the **whole device** through the tunnel via
a wintun TUN adapter — not just the browser.

> v0 — rebuilt properly later (code-signing).

## What it does
- Tray menu: **status · selected country · Refresh countries · country list ·
  Connect · Disconnect · Connection settings… · Show invite QR… · Quit**.
- **Refresh countries** → starts a throwaway client-role engine, asks the
  coordinator for its country list, tears the engine down; populates the menu.
- **Connect** → builds a `core.Engine` with the picked country (the
  coordinator assigns the exit inside it — issue #146; forced through the
  TURN relay, see "Why TURN-only" below) and starts it in-process;
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
per-user failover core already implements (ADR-0028): a legacy (disabled)
manual exit-ID pin, a reorderable transport ladder, a relay-hop count with
its own directory (issue #28), and a **Reset learned paths** button
(`core.Engine.ResetSelection()`). Design in
[docs/design/client-connection-ui.md](../../docs/design/client-connection-ui.md)
and [ADR-0036](../../docs/adr/0036-windows-client-connection-strategy-and-invite-qr-ui.md);
how reality's underlay is kept leak-safe here in
[ADR-0028's #109 amendment](../../docs/adr/0028-transport-pool-and-per-user-failover.md).

- **Automatic path selection** (checkbox) turns the pool on/off. Off
  reproduces the exact pre-#75 behavior: a single transport, the tray-picked
  country only.
- **Country precedence (issue #6):** the tray's country picker is the *only*
  control that decides which country you exit in — it's what `connect()`
  puts in `core.Config.Geo`. A "preferred geo" control briefly lived here in
  Settings too; it wrote to the saved config and was read by nothing, so it
  was removed rather than wired up. There is exactly one country selector.
- **Manual exit ID** is legacy and disabled: naming a specific exit was
  removed for everyone (issue #146, ADR-0042) — the coordinator picks the
  exit inside the country you choose. A value carried over from an older
  config is shown, greyed out, and has no effect; `connect()` logs why.
- **Transport ladder** lists every transport core knows (`webrtc`, `reality`)
  and both are usable here. `reality`'s exit address is learned only once a
  session is dialing (via coordinator signaling), so it can't be pre-excluded
  the way the known TURN server is; instead it's excluded from the tunnel's
  route (and allow-listed under the kill-switch) on the dial path, just before
  the underlay connects, via `Config.OnUnderlayDial` (issue #109 — see
  `poolroutes.go` and "Why TURN-only" above). That holds on a mid-session
  failover too: a re-dial to a different exit excludes its own new address as
  it dials it.
- **Relay hops** (issue #28) routes your relayed traffic through more than
  one node so no single one links you to your exit (issue #76/#142,
  ADR-0038) — at the cost of a round trip of latency and more volunteer
  bandwidth spent per hop. 1 (the default) is unchanged from before this
  control existed. 2 or more needs a relay directory file (a signed
  snapshot, e.g. from `cmd/coldstart-bootstrap -cache` — ask your operator)
  and its public key, both entered here; the client re-reads the file at
  every connect. Chaining is fail-closed: a chain that can't meet your hop
  count fails the connection outright rather than silently dropping to fewer
  hops, and the status line says so distinctly from an ordinary connection
  error. Once connected, the status line and log show the hop count next to
  the country, so you can confirm it took effect.

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
SOCKS tunnel against `dns` in config (default `1.1.1.1:53`). That resolver is
only ever reached from the exit's network, never directly from the client, so
it doesn't matter that Cloudflare is blocked inside Russia.

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
- Double-click `bacchus.exe` → tray icon → **Refresh countries** → pick one → **Connect**.
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
- No reconnect logic (issue #2); not code-signed (SmartScreen will warn).
