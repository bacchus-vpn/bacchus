# Bacchus — cross-platform client (Fyne)

All-Go, cross-platform client shell (issues #148/#149, ADR-0039): a Fyne UI calling
the `core` engine **in-process** — no FFI bridge, one language, one binary per
platform, **no bundled webview** (Fyne renders its own widgets — the smallest attack
surface a security tool can have).

> Skeleton — this is the app shell, the connection-state indicator, and a settings
> window, not the full client. See ADR-0039's Scope section (and its 2026-07-22
> amendment) for what's deliberately not here yet: a country/exit picker, and any
> OS-level enforcement of split-tunnel/kill-switch/DNS or this client's own
> kill-switch. `clients/windows` remains the full-featured client until those land
> here.

## What it does
A single window: a full-width color band showing one of four states —
**Disconnected / Connecting… / Proxy ready / Blocked** — in plain language (Russian or
English, following the OS locale; see i18n below), plus one button that's always
"the one thing you can do right now" (Connect, wait, or Disconnect).

**Connect** names no exit and no country: country-only assignment (issue #146,
[ADR-0042](../../docs/adr/0042-country-only-exit-assignment.md)) means the
coordinator picks the exit, and leaving `Geo` unset lets `core` take the first
country the coordinator reports as assignable. The country picker that would let
a user choose is issue #150, still open. Everything below that (dialing the
coordinator, the transport handshake, tearing a session down) is exactly
`core.Engine`'s ordinary client-role lifecycle (`core.New` → `Start` → `Connect`
→ `Stop`), driven by `internal/appstate.Controller` and rendered by
`main.go`/`ui.go` — see `internal/appstate`'s package doc for the exact threading
contract between the two.

### Connection states (issue #149)
| State | Meaning | Driven by |
|---|---|---|
| Disconnected | No tunnel. Not protected. | Initial state; after Disconnect or a failed connect attempt |
| Connecting… | Resolving a country and negotiating a session. | Set the moment Connect is pressed |
| Proxy ready | A session is up and the SOCKS5 proxy is listening on `127.0.0.1:1080`. **Not** device-wide protection — see below. | `core.Engine.Connect` returned successfully |
| Blocked | The proxy was ready and the live path just died. | A transport-level ICE disconnect/failed/closed while the session was up — the same signal `clients/windows`'s tray status line already uses for this state (see ADR-0039) |

`Blocked` is named after the kill-switch's fail-closed posture (ADR-0014), but this
client does not yet enforce an OS-level kill-switch of its own — that's a separate,
platform-specific card. The state reflects a real transport drop, not a firewall
check.

### What "Proxy ready" means — read this before trusting the banner
This client does **no OS-level routing**: no TUN device, no route table changes, no
system proxy configuration. It brings up the tunnel and exposes it as a **SOCKS5 proxy
on `127.0.0.1:1080`**, and that is the whole interface between the tunnel and your
traffic. So the headline says **Proxy ready**, not "Protected", and that wording is deliberate:
the tunnel is up and the proxy is listening, and an application is protected if, and
only if, you have pointed it at that proxy. Anything
else on the machine is unaffected and unprotected, exactly as before you pressed
Connect.

Point your browser (or whatever you want protected) at SOCKS5 `127.0.0.1:1080`. The
port is fixed rather than OS-assigned precisely so it can be pointed at; it listens on
loopback only, so nothing off the machine can reach it. `clients/windows` uses the same
number and additionally routes the whole device through it via tun2socks — that
device-wide step is what this client does not have yet.

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

## Settings (issue #152)

The `File` menu's `Settings…` opens one window over six fields, all persisted to the
same config file `LoadConfig` read at startup (or, on a fresh install with no config
file yet, to this OS's per-user config directory — see Config above):

| Field | Config key | Live today? |
|---|---|---|
| Split-tunnel bypass list (one IP/CIDR/domain per line) | `bypass` | No — see below |
| Split-tunnel mode (`exclude` or `include`) | `bypassMode` | No — see below |
| Kill-switch, **default on** | `disableKillSwitch` (inverted) | No — see below |
| DNS upstream (`host:port`) | `dns` | No — see below |
| Connect automatically when Bacchus starts | `autoConnect` | **Yes** |
| Start Bacchus when you log in | `launchOnBoot` | **Yes** |

**Split-tunnel, kill-switch, and DNS are saved but not enforced.** The window says so
in its own body text. This client has no TUN device (see "What 'Proxy ready' means"
above); there is no route table and no OS firewall for these settings to act on yet.
They exist now so the config format doesn't have to change again when a TUN device
lands (`clients/windows`'s `tunnel.go`/`splittunnel.go`/`killswitch.go` are the
implementations to port). Turning the kill-switch checkbox off is safe to do today for
exactly the same reason turning it on does nothing: neither changes what leaves the
machine.

Auto-connect and launch-on-boot need no TUN device and are fully functional: the
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
`.github/workflows/ci.yml`. Windows CI (`windows-client`) currently builds only, not
run, matching `clients/windows`'s own CI job.

## Known limits (skeleton)
- No country/exit picker (#150).
- **Carries no device traffic on its own.** No TUN, no route flip, no system proxy —
  only apps you point at SOCKS5 `127.0.0.1:1080` go through the tunnel. See "What
  'Proxy ready' means" above; this is the biggest gap between this client and
  `clients/windows`, and it is the one to read before trusting the banner.
- Settings (#152) exist for split-tunnel/kill-switch/DNS but enforce nothing yet —
  same root cause as the point above (no TUN device). See Settings above.
- No kill-switch enforcement in this client yet — see the Connection states table
  above. Nothing here prevents a leak; `Blocked` reports that the path died, and does
  not claim anything about what is or is not leaving the machine.
- Connect names no country, so `core` takes the first assignable one the
  coordinator reports. A user cannot choose where they egress (#150).
- Exit admission (ADR-0026/#60) and CRL revocation (#69) are **off unless configured**
  — set `admissionPubKey` (and optionally `admissionCrlPath`) in the config file. Left
  unset, core fails open and the client accepts any exit it can complete a handshake
  with, which is the pre-#60 behaviour and matches a coordinator with admission
  disabled. If you run an admission authority, set it: it is the client's only
  end-to-end check against a coordinator handing out an exit it controls.
- Requires a C toolchain to build (new; see Build above).

## Working on this client

Everything below is for someone who has just cloned the repo.

### Prerequisites

| What | Why |
|---|---|
| **Go ≥ the `go` directive in `go.mod`** (1.26.4 at time of writing) | One Go module for the whole repo. |
| **A C toolchain** | Required, not optional — see Build above. Without one, `go build ./clients/fyne` fails with `build constraints exclude all Go files in …/go-gl/gl`, which is cgo being disabled rather than a missing source file. That error message is confusing enough to have cost people an afternoon; it means "install gcc". |
| **A display** to run it | Or `xvfb-run` on Linux. See the verification recipe below. |

### The package split, and why it matters for testing

```
clients/fyne/
├── main.go, ui.go, settings.go, theme.go   ← Fyne. Needs cgo. Cannot be unit-tested here.
└── internal/appstate/                      ← Fyne-FREE. Pure Go. Fully testable.
```

`internal/appstate` holds the connection state machine, the config format, the
autostart reconciliation, and the `core.Engine` lifecycle. It imports **no Fyne
package at all**, which is the whole point: it builds and tests without a C
toolchain, so the logic worth testing is testable on any machine, and CI can
cover it even where a GUI cannot run.

```bash
go test -count=1 ./clients/fyne/internal/appstate/...   # works anywhere, no cgo
go build ./clients/fyne                                 # needs the C toolchain
```

If you are adding behaviour, put it in `internal/appstate` and let `main.go`/
`ui.go` render it. Logic that drifts up into the Fyne layer becomes untestable
without a display, which in practice means untested.

### Verifying a GUI change without a desktop

The technique used to prove this seam (ADR-0039) and reused since: build inside
the project's Docker buildenv, run under `Xvfb`, and screenshot. That covers
"does it start and render" — which is the failure mode that matters for a
skeleton — without needing a desktop session or a signed build. CI's
`linux-client` job does the same thing minus the screenshot: it launches the
binary under `xvfb-run` and confirms it is still alive five seconds later.

**On this dev machine `clients/fyne` cannot be built at all** (no C toolchain),
so changes here are verified through `internal/appstate`'s tests plus CI. Anyone
claiming to have verified a Fyne-layer change should say which of those two they
actually ran.

### Enforced by code vs. upheld by convention

Trust this table over any comment, and the code over this table.

**Enforced — a violation fails to build, or fails a test that exists:**

- `internal/appstate` imports no Fyne package. A violation breaks the cgo-free
  build immediately.
- Launch-on-boot is *reconciled* against the saved config at every startup, not
  merely read, so an entry deleted out of band is corrected. Tested against a
  redirected registry key / XDG directory, never the developer's real one.
- The settings window states, in its own body text, that split-tunnel,
  kill-switch and DNS are saved but not enforced. That label is asserted.
- `go vet`, `go test ./clients/fyne/internal/appstate/...`, and a real
  `xvfb-run` launch are CI gates.

**Convention only — nothing will stop you:**

- *The state banner never over-claims.* `Proxy ready` deliberately does not say
  "protected", because this client routes no device traffic. Nothing enforces
  that a future state string stays as careful; it is the single most important
  convention in this package.
- *Settings that do nothing say so.* Same class of promise, same lack of
  enforcement.
- *Reserved (RFC 5737/3849) addresses in examples and fixtures.*
- *Parity with `clients/windows`.* The two clients share `core` and nothing
  else. A fix in one does not propagate; several have had to be made twice.
