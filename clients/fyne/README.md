# Bacchus — cross-platform client (Fyne)

All-Go, cross-platform client shell (issues #148/#149, ADR-0039): a Fyne UI calling
the `core` engine **in-process** — no FFI bridge, one language, one binary per
platform, **no bundled webview** (Fyne renders its own widgets — the smallest attack
surface a security tool can have).

> **What this client protects depends on the platform you run it on.**
> On **Windows** (bacchus#59) and **Linux** (bacchus#37) it routes the whole device —
> TUN adapter, route table, fail-closed kill-switch, split tunnelling, DNS capture —
> through one shared implementation in `clients/internal/enforcement`.
> On **macOS** it does none of that and is a SOCKS5 proxy only; that is `[E9]`
> (bacchus#36), deferred past 1.0.
>
> The app tells you which one you are getting rather than making you read this:
> the headline says **Protected** where the device is really routed and **Proxy
> ready** where it is not. Still missing everywhere: a country picker (bacchus#16).
>
> **This is the only desktop client.** `clients/windows` was retired in bacchus#138
> once its three gates closed — enforcement folded behind one interface (bacchus#59),
> the OS-level guarantees confirmed on hardware (bacchus#88), and this client built
> for Windows by CI and driven through the full enforcement lifecycle on real
> hardware (bacchus#115). See ADR-0039.

## What it does
A single window: a full-width color band showing one of four states —
**Disconnected / Connecting… / Protected (or Proxy ready) / Blocked** — in plain
language (Russian or English, following the OS locale; see i18n below), plus one
button that's always "the one thing you can do right now" (Connect, wait, or
Disconnect).

**Connect** names nothing: not an exit, and not a country. Naming an exit is not a
thing any client can do — country-only assignment (issue #146, ADR-0042) removed it
from the wire, so a client asks for a *place* and the coordinator picks the exit
inside it. The country, by contrast, is a choice this client *could* make and
doesn't: it leaves `core.Config.Geo` unset, which makes `core` resolve the country
list itself and take the first country the coordinator reports as **assignable** —
not merely the first one listed, since a country whose exits are all busy or
withheld is skipped, and "every country is busy" is a named error rather than a
silent pick. `core` announces the choice on the detail line (`no country
configured — using NL`). There is no picker yet; that is `bacchus-vpn/bacchus#16`
`[E3]` in the current tracker.

Everything below that (dialing the coordinator, the transport handshake, tearing a
session down) is exactly `core.Engine`'s ordinary client-role lifecycle — `core.New`
→ `Start` → `Connect` → `Stop`, with no list call of its own, because `Connect`
resolves the country internally. (`core.Engine` does expose `ListCountries`, and a
client with a picker would call it to populate one; this client has no reason to.)
The lifecycle is driven by `internal/appstate.Controller` and rendered by
`main.go`/`ui.go` — see `internal/appstate`'s package doc for the exact threading
contract between the two.

### Connection states (issue #149)
| State | Meaning | Driven by |
|---|---|---|
| Disconnected | No tunnel. Not protected. | Initial state; after Disconnect or a failed connect attempt |
| Connecting… | Resolving a country and negotiating a session. | Set the moment Connect is pressed |
| Protected | **Windows and Linux.** A session is up and this device's traffic is routed through it: TUN device, routes, kill-switch. On Linux this additionally requires `bacchus-netd` to be installed and reachable. | `core.Engine.Connect` succeeded *and* `enforcement.Enforcer.Start` succeeded |
| Proxy ready | **macOS.** A session is up and the SOCKS5 proxy is listening on `127.0.0.1:1080`. **Not** device-wide protection — see below. | `core.Engine.Connect` returned successfully, with no enforcement backend on this platform |
| Blocked | The session was up and the live path just died. | A transport-level ICE disconnect/failed/closed while the session was up — the same signal the retired Windows tray client used for this state (see ADR-0039) |

`Blocked` is named after the kill-switch's fail-closed posture (ADR-0014). On
Windows an armed kill-switch really is holding the machine closed at that point
(unless you turned it off in Settings); on the other platforms the state reflects
a transport drop and nothing more. The banner deliberately does not claim
"nothing is leaking" either way, because the kill-switch is a setting you can
disable and the banner does not know which you chose.

### What the headline means — read this before trusting it
There are two different promises here and the app shows you which one applies.

**Windows — "Protected".** The whole device is routed: a wintun adapter, a
split-default route, the coordinator/STUN/TURN endpoints excluded so the tunnel's
own signalling survives, split tunnelling honoured, and a fail-closed kill-switch
armed by default. This is the enforcement code the retired Windows tray client
shipped, moved behind one interface by bacchus#59 rather than reimplemented.

All of that needs Administrator, and the binary **asks Windows for it itself**: it
carries an application manifest requesting `requireAdministrator`, so launching it
raises a UAC prompt rather than starting unelevated and failing at the first route
call (bacchus#136). Unsigned, that prompt says "Publisher: Unknown" — signing is
bacchus#38 and deferred to the end of 1.0. If you decline the prompt the app does
not start at all, which is the honest outcome: it could not have protected anything.

If enforcement still cannot be brought up — with elevation arranged, the usual
remaining cause is a missing or wrong-architecture **`wintun.dll`** (see below) —
the connect **fails** and tells you which of the two it was. It does not
quietly fall back to leaving you with a working proxy: you asked to be protected,
and a green banner over traffic that is still in the clear is the exact failure
ADR-0039 exists to prevent.

**Linux — "Protected", but only with the helper installed (#37, ADR-0049).**
Device-wide routing on Linux needs `CAP_NET_ADMIN`, and this GUI deliberately
runs with none: a process that links a GL stack, an X11/Wayland client and a font
renderer has no business rewriting the route table. The privileged half lives in
a separate helper, `bacchus-netd`, reached over a peer-credential-gated unix
socket — see
[deploy/README.md](../../deploy/README.md#the-one-unit-that-is-not-a-server-unit-bacchus-netd-issue-37)
to install it.

If that helper is missing or unreachable, **the connect fails and says so**. It
does not quietly leave you with a working proxy under a green banner; that is the
same failure the paragraph above describes, and a missing helper is the most
likely way to meet it on Linux.

One caveat is real and is stated in the Settings window next to the field it
affects: Linux cannot yet capture DNS queries that `systemd-resolved` sends to
`127.0.0.53`. That address is loopback, the kernel consults the `local` routing
table first, and no route can override `127.0.0.0/8`. With the kill-switch armed
those queries are dropped; with it off they leave in the clear. Tracked as
bacchus#104.

**macOS — "Proxy ready".** No OS-level routing: no TUN device, no route
table changes, no system proxy configuration. The tunnel is exposed as a **SOCKS5
proxy on `127.0.0.1:1080`** and that is the whole interface between it and your
traffic — an application is protected if, and only if, you have pointed it at that
proxy. Everything else on the machine is exactly as unprotected as before you
pressed Connect.

Point your browser (or whatever you want protected) at SOCKS5 `127.0.0.1:1080`. The
port is fixed rather than OS-assigned precisely so it can be pointed at; it listens on
loopback only, so nothing off the machine can reach it. The number is a package
constant (`appstate.SocksAddr`).

### i18n (Russian-first)
UI strings go through Fyne's `lang` package (`lang.L("English string")`); the English
literal is simultaneously the lookup key and the fallback. `translations/state.ru.json`
carries a Russian translation for every `lang.L`-wrapped string in this skeleton —
that is, every state name, description and button — picked up automatically when the
OS locale is Russian (`lang`'s own locale detection; no in-app language switcher
exists or is needed). Adding a language is adding one more
`translations/<name>.<tag>.json` file; nothing else changes.

The **secondary detail line is not translated**, and deliberately so for now: it is a
passthrough for errors and progress messages originating in `core` (English, and
frankly jargon — "direct failed → trying relay…", "path unstable (UDP) — waiting 5s
before retry"). Translating it means either translating core's message strings or
giving core typed events the UI can render itself; both are real work and neither
belongs in a skeleton. The headline state — the part a user has to understand — is
fully translated, and it never depends on the detail line.

## Config
Nothing is compiled into the binary. Copy
`bacchus-fyne.config.example.json` to `bacchus-fyne.config.json` (next to the built
binary) or to this OS's per-user config directory (`%AppData%\Bacchus\fyne-client.json`
on Windows, `~/.config/Bacchus/fyne-client.json` on Linux), and fill in your
coordinator/STUN/TURN + TURN password. `coordinators` is a JSON array; the client
rotates across them (issue #6). This file is gitignored — never commit it. A missing
file isn't an error at startup; pressing Connect with nothing configured surfaces a
plain-language explanation instead of hanging.

**An unedited template counts as nothing configured.** The example's placeholder hosts
(`COORDINATOR_HOST`, `COORDINATOR_HOST_2`) are treated as absent rather than as
addresses, so a fresh install that has not been filled in gets that same explanation
instead of a DNS failure against a name that resolves nowhere. This matters because
both seeded templates a user actually receives carry those placeholders — the Windows
bundle ships the example beside the exe, and `deploy/install.sh` copies it verbatim on
Linux. The match is exact and only on the host, so a real deployment is never refused
for a hostname that merely resembles one.

**`coordinators`, `stun` and `turn` are the one group Settings cannot set** — there
is no widget for any of them, deliberately (ADR-0039 separates operator config from
user preference). So the Connect refusal names this file by its full path and says
that outright, rather than sending you to a window with no such field (bacchus#134).
It names the file to *edit* when one is already there — `deploy/install.sh` seeds
one on Linux and the Windows release bundle is to place one beside the exe
(bacchus#136) — and the file to *create* when there is not. An entry that is blank
(`"coordinators": [""]`) counts as no coordinator and gets the same message, rather
than reaching the dialer as an address.

**Which of the two the client reads, and which it writes, are different questions**
(issue #118). It **reads** the exe-adjacent file first and the per-user one second, so
a portable install — binary and config together on a USB stick — wins over anything
already in the user's config directory. It **writes** to the per-user file: a Settings
save normally goes straight back to whichever file was loaded, and when nothing was
loaded at all the new file is created under the per-user directory (`Bacchus/` included,
mode 0700), not beside the binary. Beside the binary is wrong for anything installed
system-wide — `deploy/install.sh` puts the GUI in `/usr/local/bin`, which the desktop
user cannot write, so the first Save used to fail on permissions. An existing
exe-adjacent config still keeps the save, because that is the file the client would go
on reading.

`admissionPubKey` / `admissionCrlPath` are optional and mirror `core.Config`'s
fields of the same name. Both empty means the client verifies no
exit credential and checks no revocation — fail-open, matching a coordinator with
admission disabled. Set `admissionPubKey` to your admission authority's ed25519 public
key (64 hex chars) to turn on ADR-0026/#60's end-to-end check that the exit you were
matched with is actually admission-authorized; add `admissionCrlPath`, pointing at a
signed CRL file (#69, hot-reloaded), to reject exits revoked before their credential
expires. A CRL path without a public key is a startup error, not a silent no-op.
Since #93 both are settable in Settings too — the config file is still read, so an
operator scripting a deployment need not open a dialog.

## Settings (`old #152`, then #93)

The `File` menu's `Settings…` opens one window over every field below, all persisted
to the same config file `LoadConfig` read at startup (or, on a fresh install with no
config file yet, to this OS's per-user config directory — see Config above):

| Field | Config key | Live today? |
|---|---|---|
| Split-tunnel bypass list (one IP/CIDR/domain per line) | `bypass` | **Windows and Linux** — see below |
| Split-tunnel mode (`exclude` or `include`) | `bypassMode` | **Windows and Linux** — see below |
| Kill-switch, **default on** | `disableKillSwitch` (inverted) | **Windows and Linux** — see below |
| DNS upstream (`host:port`) | `dns` | **Windows**; **partly on Linux** — see below |
| Connect automatically when Bacchus starts | `autoConnect` | **Yes** |
| Start Bacchus when you log in | `launchOnBoot` | **Yes** |
| Automatically find the best path + transport try-order | `transportPool` | **Yes** |
| Relay hops | `relayHops` | **Yes** |
| Relay directory file and its public key | `relayDirectoryPath`, `relayDirectoryKey` | **Yes** |
| Admission authority public key | `admissionPubKey` | **Yes** |
| Revocation list file | `admissionCrlPath` | **Yes** |
| Carry other people's traffic as a relay | `volunteerRelay` | Linux and macOS — see below |
| Let other people's traffic reach the internet through your connection | `volunteerExit` | Linux and macOS — see below |
| Your address for exiting, and your exit identity key | `volunteerAdvertise`, `volunteerExitKey` | Linux and macOS — see below |

The lower five arrived with #93 and carry no platform caveat: they are `core` config,
enforced by `core`, and so mean the same thing on every platform this client runs on.
Before #93 they were unreachable here — the replacement client could not configure
them while the client it replaced could. See ADR-0039's
configuration-parity bar, which that issue added precisely because the original
eight-point bar was entirely about enforcement and so could be met in full with this
gap wide open.

**Relay hops is the one with a sharp edge.** `1` (the default) is a single relay,
which sees both you and your exit. `2` or more builds a chain so no single node links
you to your exit — and chaining is deliberately **fail-closed**: if a chain that deep
cannot be built from your directory, the connection *fails* rather than quietly using
fewer hops. When that happens the client says so specifically ("no path met your
relay-hops setting: …") rather than reporting a generic connection error, because
retrying into the same directory retries into the same wall. `2`+ requires both the
relay directory file and its public key; Settings refuses to save without them rather
than letting the failure surface at connect time.

The transport try-order is only offered for transports this client can make
tunnel-safe. A transport named in a hand-edited config that is not on that list is
dropped rather than shown — what the window displays is what it will save.

**Split-tunnel, kill-switch, and DNS are enforced on Windows and Linux, and
saved-but-inert on macOS.** They are passed straight into `enforcement.Policy`
and honoured by the same portable code on both enforcing platforms — the bypass
list carves destinations out of the tunnel (or, in `include` mode, is the only
thing pulled into it), the kill-switch arms a fail-closed OS lockdown
(`NetSecurity` on Windows, nftables on Linux), and DNS is the upstream queried
over DNS-over-TCP through the tunnel. On macOS there is still no TUN device, no
route table change and no OS firewall for them to act on, so they are saved and
nothing more (`[E9]` bacchus#36).

Two Linux qualifications, both stated in the window itself rather than only here:
enforcement requires `bacchus-netd` (above), and the DNS field does not cover
`systemd-resolved`'s own lookups (bacchus#104). The window's notice would
otherwise claim all three settings "change what leaves it", which for DNS on
Linux is more than is true — and claiming more than is enforced is the same
class of failure as claiming less.

On macOS, turning the kill-switch checkbox off remains safe for the same
reason turning it on does nothing: neither changes what leaves the machine. On
Windows and Linux, turning it off genuinely disables the lockdown.

Auto-connect and launch-on-boot are fully functional everywhere: the
former calls `Controller.Connect` once at startup instead of waiting for the button;
the latter registers this binary with the OS's native per-user autostart mechanism
(a `Run` registry value on Windows, an XDG `~/.config/autostart/*.desktop` file on
Linux) and is reconciled — not merely read — against the saved config at every
startup, so deleting the autostart entry by hand or moving the binary is corrected
automatically rather than silently drifting from what Settings says is on. macOS has
neither implementation yet (nobody has built or verified a launchd `LaunchAgent` for
this client) — checking the box there surfaces an explicit
`launch-on-boot is not supported on this platform yet` error rather than silently
doing nothing, which is the one thing worse than an honest error.

### Volunteering your connection (#12)

The last three rows point the other way from everything above them: at what this
client *gives* the network rather than what it takes. `bacchus-node` got the same
switch as `-volunteer-relay` / `-volunteer-exit`; see
[docs/RUNNING.md](../../docs/RUNNING.md) for the node side.

On a build that routes the whole device these are live only where enforcement can
carve the served roles' own egress back out of the tunnel — Linux, as of
bacchus#109. Where it cannot, the controls are disabled with the reason on them
rather than accepting a choice that would fail at connect. See "Volunteering is
refused on Windows" under the honesty list below.

**Relay and exit are two separate checkboxes, and neither one turns on the other.**
Both off by default. The two costs are not comparable:

- **Relay** carries other people's traffic **encrypted and blind-forwarded**. It never
  learns the destination and never sees plaintext. What it costs you is **bandwidth**,
  and it does not make you an exit.
- **Exit** egresses other people's traffic **under your own IP and jurisdiction**. Your
  address is what every site they reach records, and abuse reports, provider notices
  and legal process arrive at **you**. What it costs you is **legal exposure**.

There is deliberately no single control spanning both: one checkbox covering them
would let somebody who meant to donate bandwidth accept liability they never read
about. The exit's disclosure is printed next to the exit's own checkbox rather than in
this file, because a cost you have to go looking for is one nobody read.

Only the exit choice asks for anything else — the address relays dial to reach you
(`volunteerAdvertise`, your public address with that port forwarded to this machine)
and a permanent identity key (`volunteerExitKey`, which **Generate** produces so you
are not sent to a terminal for `openssl rand -hex 32`). The relay choice needs neither:
behind a home NAT a relay serves as a client's *first hop*, reached the way the client
itself is. Asking a bandwidth-only donor for an exit's setup would put the exit's cost
back on somebody who declined it.

The advertised address is checked by class, not dialled — a node cannot usefully test
its own public reachability from behind its own NAT, since hairpinning makes a self-dial
answer yes where the internet answers no. A wildcard, loopback or link-local address is
**refused** (nothing off this machine can ever dial it, so registering one is an exit
that serves nobody and says nothing about it). Private space, carrier-grade NAT
(`100.64.0.0/10`) and a name instead of an address **warn and save**, because a LAN, a
lab or a tunnelled uplink advertises private space correctly. Behind carrier-grade NAT
there is no port for you to forward at all, so an exit will not work there — relay does.

**These are the one group that is available on Linux and macOS but refused on
Windows**, which is the inverse of split-tunnel/kill-switch/DNS above, and it is not an
oversight. Where this client routes the whole device it installs the OS default route
into its own TUN and arms a fail-closed lockdown behind a small allowlist — and a
relay or exit role in that same process has its forwarding caught by exactly that
route. Other people's traffic would leave through *your own* Bacchus connection and
egress at the upstream exit's address rather than yours, making the disclosure on the
exit checkbox false in the direction that matters; and an advertised exit would be
unreachable anyway, because the reply to an inbound dial follows the default route into
the TUN. So the section is disabled there, with that reason on screen, instead of
accepting a choice that would quietly mean something else. Teaching enforcement to
carve the served roles' own egress out of the tunnel it installs is the work that would
lift this, and it belongs in `clients/internal/enforcement`.

The refusal is not only a disabled checkbox: `PlanVolunteer` re-checks it in
`Controller.connectAsync` too, so a hand-edited config file cannot reach `core` through
a dialog it never opened — the same double-check `transportPool` gets.

## Build

This client needs a **C toolchain** — Fyne's desktop driver renders through OpenGL
via cgo bindings (`go-gl/gl`, `go-gl/glfw`). It is the only package in the repo that
does; everything under `cmd/` builds with `CGO_ENABLED=0`.

- **Linux**: `gcc` + X11/Wayland + OpenGL dev headers. On Debian/Ubuntu:
  ```
  sudo apt-get install gcc libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev wayland-protocols
  ```
- **Windows**: a mingw-w64 GCC (e.g. MSYS2's `mingw-w64-x86_64-gcc`), on `PATH` as
  `gcc`.

```
# The release this binary will report, from VERSION at the root of the repo.
stamp="-X github.com/bacchus-vpn/bacchus/core/version.current=$(cat VERSION)"

go build -ldflags "$stamp" -o bacchus-fyne ./clients/fyne          # native
GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  go build -ldflags "-H=windowsgui $stamp" -o bacchus-fyne.exe ./clients/fyne   # cross-compile from Linux
```

**The stamp is not decoration** (bacchus#128). `VERSION` is the single source of truth
for the release every binary reports, and the same `-X` is applied by CI and by
`deploy/install.sh`. A build with no `-X` still works and is a supported development
build — but it reports the release `0.0.0` and prints one loud
line at startup saying it was not stamped, because a development build passing for a
release build is what feeds a wrong number to the client's own force-major/skip-minor
check and to the coordinator's build-skew warning. See
[docs/RUNNING.md](../../docs/RUNNING.md#the-release-version-comes-from-version-issue-128).

### The Windows application manifest (elevation)

Two files in this directory exist only for Windows builds:

| File | What it is |
|---|---|
| `bacchus-fyne.manifest` | The manifest itself — reviewable XML. It requests `requestedExecutionLevel level="requireAdministrator"` and nothing else. |
| `rsrc_windows_amd64.syso` | That manifest compiled into a COFF resource object. `go build` links any `*.syso` in the package directory whose name matches the target, so a `windows/amd64` build carries the manifest **inside the exe** with no extra step, and a Linux or macOS build ignores the file entirely. |

Embedded rather than shipped beside the exe as `bacchus-fyne.exe.manifest`, so it
travels with the binary through any channel in
[docs/distribution.md](../../docs/distribution.md) — a sidecar manifest that got
separated from its exe would silently stop asking for elevation.

**Regenerate the `.syso` whenever you edit the manifest**, with
[`rsrc`](https://github.com/akavel/rsrc):

```
go run github.com/akavel/rsrc@v0.10.2 \
  -manifest bacchus-fyne.manifest -arch amd64 -o rsrc_windows_amd64.syso
```

Forgetting is caught: `manifest_test.go` walks the resource directory in the
committed object and fails if the manifest embedded in it is not byte-for-byte the
`.manifest` beside it, or if it is not under `RT_MANIFEST`/id 1 where Windows looks.
It runs on every platform, because the `.syso` is committed data and a check only
the Windows job runs is one a Linux contributor never sees fail.

Only `amd64` is committed, which is the only Windows architecture anything here
builds. A `windows/arm64` build would link no `.syso` at all and would therefore
launch unelevated — generate one with `-arch arm64` first; the drift test covers
whatever `.syso` files are present.

One cost, and it is only a local-development one: the `.syso` is linked into
whatever the Go linker builds from this package, **including the test binary**. Go
runs tests through `CreateProcess`, which does not elevate — it fails with "the
requested operation requires elevation" — so on a Windows machine with UAC on,
`go test ./clients/fyne` needs an elevated shell. `go test ./clients/fyne/internal/...`
does not, and neither does anything on Linux. CI is unaffected: the GitHub-hosted
Windows images run as administrator with UAC disabled.

Two things this manifest deliberately does *not* declare, both in its own comment:
Common Controls v6 (the retired tray client needed it for `lxn/walk`; Fyne draws its
own widgets and links no comctl32) and DPI awareness (Fyne's GLFW driver sets that
through the API, and a manifest declaration would override it).

### wintun runtime dependency, Windows only (fetch separately — not vendored)

**A Windows build that compiles will still not connect without this.** The client
loads **`wintun.dll`** at runtime (via `golang.zx2c4.com/wintun`) to create the TUN
adapter, and it must sit next to `bacchus-fyne.exe` or in `System32` — those are the
only two places it is searched for (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR` plus
`LOAD_LIBRARY_SEARCH_SYSTEM32`), so anywhere else on `PATH` will not do.

Without it, bring-up fails with `create wintun adapter`, and the message now names
**which** of the two causes it was: a DLL that could not be loaded, or a process
that is not elevated. It used to name only elevation, for both (bacchus#135), which
sent whoever had the other problem in the wrong direction. A wrong-**architecture**
`wintun.dll` reads as the DLL case too, which is worth knowing because the download
below carries one per arch and they all have the same file name.

It is deliberately **not** committed to this repo: `wintun.dll` is proprietary
(© WireGuard LLC, "licensed, not sold" — see its own `LICENSE.txt`), so it does not
belong in an AGPL source tree, and wintun's own guidance is to distribute the binary
"as downloaded from wintun.net", not a rebuilt or in-repo copy.

Fetch it once from **https://www.wintun.net/builds/** (use the release matching
`golang.zx2c4.com/wintun` in `go.mod` — 0.14.1 at time of writing), unzip, and copy
`wintun/bin/<arch>/wintun.dll` next to the exe for your target arch (`amd64` for a
normal 64-bit build). The staging dir `clients/fyne/wintun/` is git-ignored for
exactly this — drop the download there and it cannot be committed by accident. In
any release bundle, ship `wintun.dll` **and its `LICENSE.txt`** alongside the exe.

CI does not do this: `windows-fyne-client` builds and smoke-launches the binary but
never brings a tunnel up, so the artifact it uploads is an exe with no DLL beside it.
That is what bacchus#136 is about — there is no Windows install path that places
either one.

Both the native Linux build and the mingw-cross-compiled Windows build were run (not
just compiled) as part of proving this seam — see ADR-0039. Both are now proven on
every push. CI's `linux-client` job installs the same package list above, builds,
`go vet`/`go test`, then launches the binary under `xvfb-run` and confirms it is
still alive five seconds later. `windows-fyne-client` does the equivalent on a
Windows runner: locate a mingw-w64 gcc, refuse to run at `CGO_ENABLED=0`, vet, build
with `-H=windowsgui` and the release stamp above, check the output is a real PE image
of plausible size, test,
smoke-launch against the real Windows session, and upload the exe as an artifact
(bacchus#115). A third job, `windows-enforcement`, vets and tests
`clients/internal/...` on Windows without any toolchain — the shared enforcement
layer, whose Windows half compiles on no other runner. It is kept separate because it
runs in about a minute against `windows-fyne-client`'s eight, nearly all of which is
cgo compiling `go-gl/glfw`. See `.github/workflows/ci.yml`.

## Known limits
- No country picker (#150; `bacchus-vpn/bacchus#16` `[E3]` in the current tracker).
- **Carries no device traffic on macOS.** No TUN, no route flip, no system proxy —
  only apps you point at SOCKS5 `127.0.0.1:1080` go through the tunnel, and it is the
  one thing to read before trusting the banner there. Windows routes the device
  (bacchus#59) and so does Linux (bacchus#37); macOS is `[E9]` (bacchus#36), deferred
  past 1.0.
- **Linux routing needs `bacchus-netd` installed**, and the connect fails without
  it rather than degrading to a proxy. See the Linux paragraph under "What the
  headline means".
- **Linux DNS is incomplete**: `systemd-resolved`'s own lookups to `127.0.0.53`
  are not captured (bacchus#104). The Settings window says so next to the field.
- Settings (`old #152`) for split-tunnel/kill-switch/DNS enforce nothing on macOS —
  same root cause as the first point. Live on Windows and Linux. See Settings above.
- **Volunteering is refused on Windows, and available on Linux.** Serving and
  device-wide routing cannot share a process unless the served roles' own egress is
  carved back out of the tunnel, which Linux does as of bacchus#109 (ADR-0053) and
  Windows cannot: Windows selects a route by destination and has no source-based
  rule layer, so a served socket bound to the physical adapter's address still goes
  into the tunnel. The gate is what the platform can DO
  (`Enforcer.ServesWhileRouted`), not whether it routes the device, so a Windows
  user still gets `ErrVolunteerWhileRouted` and disabled controls. To donate
  capacity from Windows, run `cmd/node` with `-volunteer-relay` /
  `-volunteer-exit` instead — see
  [docs/RUNNING.md](../../docs/RUNNING.md#volunteering-your-connection-issue-12).
- **What volunteering on Linux widens.** While either opt-in is on, the kill-switch
  gains one allowance that is a SOURCE rather than a destination: traffic this
  machine sent as itself may leave, which for an exit is necessarily the whole
  internet. It is scoped to the volunteering user's uid and to this machine's own
  address, so another user's processes and every ordinary unbound socket — the
  volunteer's own browsing included — still go through the tunnel. It is dropped
  the moment the session ends, including a crash, where the lockdown itself is
  deliberately held. ADR-0053 §4 states the residue this leaves.
- `Blocked` makes no claim about leakage on any platform. On Windows an armed
  kill-switch is holding the machine closed; the banner still does not say so,
  because the kill-switch is a setting you can turn off and the banner does not
  know which you chose.
- Connect always takes the first country the coordinator reports as assignable, and
  the coordinator picks the exit inside it. Nothing here chooses a jurisdiction, so
  a user who needs a specific one cannot express that yet — see "What it does" above.
- Exit admission (ADR-0026/#60) and CRL revocation (#69) are **off unless configured**
  — set `admissionPubKey` (and optionally `admissionCrlPath`) in Settings or the config
  file. Left
  unset, core fails open and the client accepts any exit it can complete a handshake
  with, which is the pre-#60 behaviour and matches a coordinator with admission
  disabled. If you run an admission authority, set it: it is the client's only
  end-to-end check against a coordinator handing out an exit it controls.
- **Split tunnelling is destination-based only** — by IP/CIDR/domain (`bypass`), never
  by process or application. Per-app split tunnelling is a separate and harder problem
  (Windows has no `addAllowedApplication`-style API) and ADR-0025 ruled it out of scope
  for 1.0 in its Consequences.
- **A bypass domain the OS resolved from its own cache before you connected** is not
  recognised until something re-queries it, because the interceptor never observes that
  lookup. It fails in the safe direction — that traffic tunnels instead of going direct
  — just not the intended one.
- **`bypassMode: "include"` does not live-track a domain's mid-session IP rotation** the
  way `"exclude"` does: only already-included traffic reaches the interceptor at all, so
  a CDN rebalancing after connect is not observed. Fails toward that connection going
  direct rather than toward a leak. Separately, the kill-switch has no notion of
  include-mode's direct traffic being something that was never meant to be protected, so
  arming it blocks that traffic rather than leaving it alone.
- **IPv6 is blocked while the tunnel is up, not tunnelled** — the physical adapter's
  IPv6 binding is disabled for the session's lifetime.
- **A hard crash leaves the tunnel adapter, its routes and the IPv6 binding behind.**
  They are cleaned up on the next launch, alongside kill-switch recovery — verified on
  hardware in bacchus#115. To clear them by hand on Windows without relaunching:
  ```
  Enable-NetAdapterBinding -Name * -ComponentID ms_tcpip6
  Set-NetFirewallProfile -All -DefaultOutboundAction Allow
  Remove-NetFirewallRule -Group BacchusKillSwitch
  ```
- **On Windows there is no installer.** `deploy/install.sh` covers Linux only;
  bacchus#136 is the card for the release bundle that replaces it, and the bundle is
  not built yet. The client's own half of it is: the exe asks Windows for elevation
  itself, it prefers a config placed beside it over the per-user one, and both
  first-run failures name what is wrong and where (bacchus#134, bacchus#135). A
  **bare exe with nothing beside it still cannot connect** — it needs `wintun.dll`
  and a config file, and until the bundle ships both are placed by hand.
- Requires a C toolchain to build (see Build above).
