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
| Protected | **Windows only.** A session is up and this device's traffic is routed through it: TUN adapter, routes, kill-switch. | `core.Engine.Connect` succeeded *and* `enforcement.Enforcer.Start` succeeded |
| Proxy ready | **Linux/macOS.** A session is up and the SOCKS5 proxy is listening on `127.0.0.1:1080`. **Not** device-wide protection — see below. | `core.Engine.Connect` returned successfully, with no enforcement backend on this platform |
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

**Linux/macOS — "Proxy ready".** No OS-level routing: no TUN device, no route
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
| Split-tunnel bypass list (one IP/CIDR/domain per line) | `bypass` | **Windows only** — see below |
| Split-tunnel mode (`exclude` or `include`) | `bypassMode` | **Windows only** — see below |
| Kill-switch, **default on** | `disableKillSwitch` (inverted) | **Windows only** — see below |
| DNS upstream (`host:port`) | `dns` | **Windows only** — see below |
| Connect automatically when Bacchus starts | `autoConnect` | **Yes** |
| Start Bacchus when you log in | `launchOnBoot` | **Yes** |
| Automatically find the best path + transport try-order | `transportPool` | **Yes** |
| Relay hops | `relayHops` | **Yes** |
| Relay directory file and its public key | `relayDirectoryPath`, `relayDirectoryKey` | **Yes** |
| Admission authority public key | `admissionPubKey` | **Yes** |
| Revocation list file | `admissionCrlPath` | **Yes** |

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

**Split-tunnel, kill-switch, and DNS are enforced on Windows and saved-but-inert
elsewhere.** On Windows they are passed straight into `enforcement.Policy` and
honoured by the same code `clients/windows` uses — the bypass list carves
destinations out of the tunnel (or, in `include` mode, is the only thing pulled
into it), the kill-switch arms a fail-closed OS firewall lockdown, and DNS is the
upstream queried over DNS-over-TCP through the tunnel. On Linux and macOS there is
still no TUN device, no route table change and no OS firewall for them to act on,
so they are saved and nothing more, exactly as before (`[E10]` bacchus#37, `[E9]`
bacchus#36).

On those platforms, turning the kill-switch checkbox off remains safe for the same
reason turning it on does nothing: neither changes what leaves the machine. On
Windows, turning it off genuinely disables the lockdown.

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
- **Carries no device traffic on Linux or macOS.** No TUN, no route flip, no system
  proxy — only apps you point at SOCKS5 `127.0.0.1:1080` go through the tunnel.
  This is the biggest remaining gap between those platforms and `clients/windows`,
  and it is the one to read before trusting the banner. Windows does route the
  device (bacchus#59); Linux is `[E10]` (bacchus#37) and macOS `[E9]` (bacchus#36).
- Settings (`old #152`) for split-tunnel/kill-switch/DNS enforce nothing on Linux/macOS —
  same root cause as the point above. Live on Windows. See Settings above.
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
