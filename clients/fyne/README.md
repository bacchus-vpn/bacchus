# Bacchus — cross-platform client (Fyne)

All-Go, cross-platform client shell (issues #148/#149, ADR-0039): a Fyne UI calling
the `core` engine **in-process** — no FFI bridge, one language, one binary per
platform, **no bundled webview** (Fyne renders its own widgets — the smallest attack
surface a security tool can have).

> **What this client protects depends on the platform you run it on.**
> On **Windows** it routes the whole device — TUN adapter, route table,
> fail-closed kill-switch, split tunnelling — through the same enforcement code
> `clients/windows` ships (`clients/internal/enforcement`, bacchus#59).
> On **Linux and macOS** it does none of that yet and is a SOCKS5 proxy only;
> those are `[E10]` (bacchus#37) and `[E9]` (bacchus#36).
>
> The app tells you which one you are getting rather than making you read this:
> the headline says **Protected** where the device is really routed and **Proxy
> ready** where it is not. Still missing everywhere: a country picker (bacchus#16).
> `clients/windows` remains maintained and shipping until the owner takes the
> retirement decision ADR-0039's 2026-07-30 amendment describes.

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
| Blocked | The session was up and the live path just died. | A transport-level ICE disconnect/failed/closed while the session was up — the same signal `clients/windows`'s tray status line already uses for this state (see ADR-0039) |

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
armed by default. This is the same code `clients/windows` has shipped for as long
as it has existed, not a reimplementation.

If that enforcement cannot be brought up — most commonly **because the app is not
running as Administrator** — the connect **fails** and tells you why. It does not
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
loopback only, so nothing off the machine can reach it. `clients/windows` uses the
same number.

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
Same idea as `clients/windows`: nothing is compiled in. Copy
`bacchus-fyne.config.example.json` to `bacchus-fyne.config.json` (next to the built
binary) or to this OS's per-user config directory (`%AppData%\Bacchus\fyne-client.json`
on Windows, `~/.config/Bacchus/fyne-client.json` on Linux), and fill in your
coordinator/STUN/TURN + TURN password. `coordinators` is a JSON array; the client
rotates across them (issue #6). This file is gitignored — never commit it. A missing
file isn't an error at startup; pressing Connect with nothing configured surfaces a
plain-language explanation instead of hanging.

`admissionPubKey` / `admissionCrlPath` are optional and mirror `clients/windows`'s
fields of the same name (and `core.Config`'s). Both empty means the client verifies no
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
Before #93 they were unreachable here — the client replacing `clients/windows` could
not configure them while the client being replaced could. See ADR-0039's
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

This is the first client in the repo that needs a **C toolchain** — Fyne's desktop
driver renders through OpenGL via cgo bindings (`go-gl/gl`, `go-gl/glfw`).
`clients/windows` (`lxn/walk`, `getlantern/systray`) is pure Go/syscall and is
unaffected; this requirement is new to `clients/fyne` only.

- **Linux**: `gcc` + X11/Wayland + OpenGL dev headers. On Debian/Ubuntu:
  ```
  sudo apt-get install gcc libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev wayland-protocols
  ```
- **Windows**: a mingw-w64 GCC (e.g. MSYS2's `mingw-w64-x86_64-gcc`), on `PATH` as
  `gcc`.

```
go build -o bacchus-fyne ./clients/fyne          # native
GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  go build -ldflags "-H=windowsgui" -o bacchus-fyne.exe ./clients/fyne   # cross-compile from Linux
```

Both the native Linux build and the mingw-cross-compiled Windows build were run (not
just compiled) as part of proving this seam — see ADR-0039. The Linux build (issue
#153) is now also proven on every push: CI's `linux-client` job installs the same
package list above, builds, `go vet`/`go test`, then launches the binary under
`xvfb-run` and confirms it is still alive five seconds later — see
`.github/workflows/ci.yml`. Windows CI (`windows-client`) builds `clients/windows`
and additionally vets and runs the tests for `clients/internal/...` — the shared
enforcement layer, whose Windows half compiles on no other runner. It does not
launch a GUI binary, matching `clients/windows`'s own job.

## Known limits
- No country picker (#150; `bacchus-vpn/bacchus#16` `[E3]` in the current tracker).
- **Carries no device traffic on macOS.** No TUN, no route flip, no system proxy —
  only apps you point at SOCKS5 `127.0.0.1:1080` go through the tunnel. This is now
  the last platform gap against `clients/windows`, and it is the one to read before
  trusting the banner there. Windows routes the device (bacchus#59) and so does
  Linux (bacchus#37); macOS is `[E9]` (bacchus#36).
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
- Requires a C toolchain to build (new; see Build above).
