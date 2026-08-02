# 39. Cross-platform client: all-Go Fyne UI calling core in-process, no webview

- Status: accepted
- Date: 2026-07-15

## Context

`clients/windows` (ADR-0036) is a Win32 tray app: `getlantern/systray` for the menu,
`lxn/walk` for the two dialogs, both pure-Go/syscall, no cgo. It is Windows-only —
ADR-0005 committed the mobile story to gomobile binding `core` from Kotlin/Swift, but
nothing has built that bridge or an equivalent desktop story for Linux, and `bind/`
(the planned gomobile facade) is still a placeholder (`bind/doc.go`).

Issues #148/#149 asked for a real cross-platform client — Windows, Linux, and later
Android/iOS from one codebase — starting with the two things every later card
depends on: an app shell, and the single most important pixel in it (Protected /
Connecting / Blocked / Disconnected, unmistakable at a glance for a non-technical,
possibly stressed user in a censored country).

Three shapes for "one UI, many platforms" were on the table:

1. **Flutter (Dart) + `core` behind gomobile/cgo FFI.** Best-in-class mobile+desktop
   widget story, but every call from Dart into Go crosses an FFI boundary that has to
   marshal `core`'s types (events, config, errors) by hand, and it adds a second
   language and toolchain (Dart/Flutter SDK) alongside Go's. Rejected: bridge
   maintenance cost, and a second runtime is a second thing to audit for a security
   tool.
2. **Electron/Tauri-style: a webview UI (HTML/CSS/JS) talking to `core` over local
   IPC.** Familiar web tooling, but a bundled webview is a large, frequently-patched
   attack surface (a full browser engine) sitting in front of a tool whose entire job
   is defeating a hostile network adversary — the opposite of what this product
   should add. Rejected on that principle alone, independent of IPC-design cost.
3. **Native per-platform UI (Win32/lxn/walk, GTK, AppKit/Swift, Android/Kotlin), each
   calling `core` through its own binding.** Multiplies UI code and binding surfaces
   by platform count forever; defeats the point of a shared core (ADR-0002/0003's
   single-module ethos).
4. **Fyne: a pure-Go, immediate-widget toolkit that runs on Windows/Linux/macOS/
   Android/iOS from the same source, in the same process and binary as `core`.**

All-Go Fyne (option 4) was the direction chosen before this branch (tracked as
"already decided" in #148); this ADR records that decision and the seam it depends
on, having now proven it rather than assumed it — it does not relitigate 1–3.

## The seam: why in-process embedding was expected to work, and how it was checked

`core.Engine` (`core/engine.go`, `core/doc.go`) was already designed to be embedded,
not to own `main()`: `New`/`Start` do no blocking network I/O beyond validation and a
non-blocking dial, `Start` returns once setup is launched (goroutines do the rest),
`Stop` is idempotent and safe to call concurrently, and every status update crosses
the boundary through one callback, `Config.OnEvent`, invoked from whichever internal
goroutine observed it (a coordinator read loop, the reconnect driver, …) — never from
the caller's own stack. `clients/windows` already proved this shape works for a GUI:
`getlantern/systray` runs its own event loop, and `lxn/walk`'s single-OS-thread
affinity requirement is solved with one persistent worker goroutine plus a work queue
(`runOnUIThread`, ADR-0036).

Fyne has the mobile-toolkit-shaped version of the same requirement: all widget
mutation must happen on Fyne's own driver goroutine, and it ships the answer as
library API — `fyne.Do`/`fyne.DoAndWait` (since Fyne 2.6), which marshal a function
onto that goroutine from any other one. The pairing is: `core.Config.OnEvent` fires
on an arbitrary engine goroutine → the callback wraps its body in `fyne.Do` → Fyne
runs it on its own thread next. `clients/fyne/internal/appstate.Controller` is that
callback's home; it holds no Fyne import at all, so it is the whole seam minus the
toolkit, and is what got exercised directly rather than assumed:

- `TestController_RealLoopback` (`clients/fyne/internal/appstate/controller_test.go`)
  builds a real exit-role `core.Engine` and drives a real client-role one through
  `Controller` — exactly the calls `ui.go` makes — against a from-scratch, ~120-line
  fake coordinator (`fakecoordinator_test.go`) speaking the same UDP JSON protocol
  `cmd/coordinator` does (duplicated locally; the two binaries share no wire-format
  package today, so this mirrors `cmd/coordinator/main.go`'s own independent copy of
  `core`'s `wire` shape). No transport is faked — real WebRTC completes over
  loopback, reaches `Protected`, and killing the exit mid-session is observed as a
  genuine ICE disconnect that `Controller` maps to `Blocked`, not merely the
  synthetic string fed to the unit test. Total run time: under a second.
- `TestController_NoCoordinators` covers the far more common real-world case — no
  reachable coordinator — resolving cleanly back to `Disconnected` with an actionable
  detail line instead of hanging in `Connecting`.

Conclusion: **core does not fight a GUI event loop.** No restructuring of `core/`
was needed or attempted.

## What the spike also surfaced: a new build prerequisite

Fyne's desktop driver renders through OpenGL via `go-gl/gl` + `go-gl/glfw`, both cgo
bindings. `clients/windows` added zero cgo to this repo (systray and walk are both
syscall-based); this client is the first to require a C toolchain, and this dev
environment had none (`CGO_ENABLED=0` by default, no `gcc` on `PATH`) — confirmed
empirically, not assumed:

```
$ go build .
...github.com/go-gl/gl/v2.1/gl: build constraints exclude all Go files...
$ CGO_ENABLED=1 go build .
cgo: C compiler "gcc" not found: exec: "gcc": executable file not found in %PATH%
```

Rather than install a compiler on the dev host, both platforms were built and
**run** (not just cross-compiled) in a disposable Docker Linux container: natively
for Linux under Xvfb (a real GL context via software rendering, screenshotted to
confirm actual rendering — the screenshots were verification artifacts and were not
committed or attached, since a rendered-window capture is worth nothing to a reader
who cannot reproduce it and is a standing risk to capture something it should not), and
cross-compiled to Windows via `gcc-mingw-w64-x86-64`, then executed directly on the
Windows host to confirm the cross-compiled binary is genuine, running Windows code,
not merely "didn't fail to compile." Both platforms therefore have direct evidence,
per the lane's own requirement that a cross-platform claim compiled on only one
platform is not evidence.

Consequence: building this client now requires, in addition to `go build`:
`mingw-w64` (Windows) or `gcc` + X11/Wayland + OpenGL dev headers (Linux) — see
`clients/fyne/README.md`. `clients/windows` is unaffected; it remains cgo-free.

## Decision

- **`clients/fyne`** is the new cross-platform client: one Go binary per platform,
  Fyne UI calling `core.Engine` in-process, no FFI layer, no webview.
- **`clients/fyne/internal/appstate`** holds every piece of logic that does not
  touch Fyne — the `ConnState` model, the pure `StateFor`/`DetailFor` transition
  functions (typed equivalents of `clients/windows`'s `eventStatus`, issue #149),
  `Controller` (owns the `core.Engine` lifecycle), and config loading. This is a
  structural split motivated by something concrete rather than speculative: on a
  host with no cgo toolchain, `go vet`/`go test` still run instantly against this
  package with zero Docker/GUI dependency, and both `TestController_RealLoopback`
  and the state-transition table tests do exactly that. Only the outer package
  (`main.go`, `ui.go`, `theme.go`) imports `fyne.*` and needs the toolchain above.
- **Connection-state UI (#149)**: `ConnState` has four values — `Disconnected`,
  `Connecting`, `Protected`, `Blocked` — rendered as one full-width color band
  (`ui.go`'s `stateIndicator`) with a plain-language headline and one-sentence
  description, never protocol jargon. `Blocked` is named for the kill-switch's
  fail-closed posture (ADR-0014) and reuses exactly the signal
  `clients/windows`'s `eventStatus` already uses for the same state — a transport
  drop (ICE disconnected/failed/closed) observed while previously `Protected` — not
  a firewall check. **This client enforces no OS-level kill-switch of its own yet**;
  that is a separate, platform-specific card, out of scope here (see Scope below).
  Every other transition is driven directly by `Controller`'s own call sequence
  around `Start`/`Connect`/`Stop`, matching `clients/windows`'s `connect()`/
  `disconnect()` — only the Protected↔Blocked edge has no corresponding blocking
  call, hence it alone is event-driven.
- **Theme**: `calmTheme` (`theme.go`) wraps `theme.DefaultTheme()` and overrides
  colors only (icons/fonts/sizes fall through unchanged), reusing Fyne's own
  semantic names (`ColorNamePrimary/Success/Warning/Error/Disabled`) rather than
  inventing app-specific ones — the same palette drives ordinary widgets and the
  state indicator, so they can't disagree about what "safe" looks like.
- **i18n**: Fyne's `lang` package (`lang.L("English string")`, since 2.5), backed by
  an embedded `translations/` directory. Russian-first per #148: every `lang.L`-wrapped
  string in this skeleton — the state names, their descriptions, and the buttons — has
  a `translations/state.ru.json` entry; English is the in-code fallback (`lang.L`'s key
  doubles as its own fallback), so no other language needs a stub file to work, it just
  falls back. The secondary **detail line is not wrapped and not translated**: it is a
  passthrough for `core`'s own English (and jargon-heavy) error and progress strings,
  and translating it needs either core's messages localized or core emitting typed
  events the UI renders itself. Both are real work and out of scope here; the headline
  state, which is the part a user must understand, does not depend on it.
- **Connect auto-selects the first advertised exit** (mirroring `clients/windows`'s
  own default before a user picks). This skeleton has no picker: #150 needs
  country-only assignment (#146), which does not exist yet. Intentional scope, not
  a placeholder — see Scope.

## Scope

In: app shell, theme, i18n scaffolding, the four-state connection indicator wired to
a real (if auto-selecting) connect/disconnect flow, and the tunnel exposed as a SOCKS5
proxy on a fixed loopback port.

**Out, and the one that matters: this client does not carry device traffic.** No TUN,
no route table changes, no system proxy configuration. It offers SOCKS5 on
`127.0.0.1:1080` and protects exactly what is pointed at it; everything else on the
machine is untouched. `clients/windows` closes this gap with tun2socks (ADR-0014's
kill-switch sits on top of that), and porting it is a later card.

This deserves its own paragraph because getting it wrong is not a missing feature, it
is a **lie to a user in a censored country**. The first cut of this client asked core
for an OS-assigned ephemeral SOCKS port (`127.0.0.1:0`) — and core exposes no accessor
for the bound address, so nothing could ever find it. The tunnel came up, the engine
was healthy, the state machine correctly reached Protected, the UI displayed "your
connection is private and secure", and 100% of the user's traffic went out in the
clear, on the only path the app had. The state was true; the sentence about it was not.
Hence: a fixed port (so the tunnel is reachable at all), copy that says what is and is
not covered, and `TestProtectedMeansTrafficActuallyFlows`, which round-trips a real
byte through a real exit rather than asking the state machine how it feels.

And the headline reads **"Proxy ready"**, not "Protected" — which is the second half of
the same lesson. Rewriting the *description* to scope the claim left the claim itself
untouched: 28px bold on a success-green band, with the qualifier at 14px underneath. By
this app's own standard — a stressed user must know their safety state *at a glance* —
a true footnote does not repair a false headline; the colour and the type size win. The
state is still named `Protected` internally, because that is the posture it will have
once tun2socks lands (ADR-0014's kill-switch sits on top of that); the word the user
reads is what changed, and it earns the stronger one back when the app can carry it.

Also out, deliberately: a country/exit picker (#150, blocked on #146), a settings
window (#152), split-tunnel, and any OS-level kill-switch enforcement for this client.
`Blocked` is named for the posture that enforcement will have; today it reports a
transport drop and makes no claim about what is leaving the machine, because it has no
way to know. None of these are implied to be hard — `clients/windows` has working
implementations to port — they are simply the next cards, not this one.

Exit admission (ADR-0026/#60) and CRL revocation (#69) ARE in scope, as config
passthrough: `appstate.Config` carries `admissionPubKey`/`admissionCrlPath` through to
`core.Config`, mirroring `clients/windows`. They are optional and fail-open when unset,
matching core and the coordinator — but they had to exist, because "no field for it" is
not a scope decision, it is an unreachable security check.

## Consequences

- A C toolchain is now a build prerequisite for *this* client (not `clients/windows`,
  not `core`, not any `cmd/*` binary) — documented in `clients/fyne/README.md`.
- The `appstate`/outer-package split is a pattern later client cards should keep:
  logic that can be tested without a GUI toolchain, should be.
- `bind/` (gomobile) remains unaddressed — Android/iOS builds of this same Fyne
  source are future work, not attempted here; Fyne's mobile packaging path (`fyne
  package -os android`) is a different mechanism than gomobile binding and this ADR
  does not evaluate it.
- The next client cards (#150, #152, and eventually a kill-switch for this client)
  build on `clients/fyne/internal/appstate.Controller` rather than growing `main.go`
  directly, keeping the Fyne-free/Fyne-touching boundary intact.

## Amendment (2026-07-22): Settings window (#152) and continuous Linux build verification (#153)

Two corrections to the original text above, which listed a settings window as
deliberately out of scope and Linux as proven only by the one-time spike this ADR
records.

**Settings (#152).** The Scope section's "also out, deliberately" list named "a
settings window (#152)"; the Consequences section listed #152 among "the next client
cards." Both are now stale. `settings.go` adds one window — split-tunnel bypass list,
split-tunnel mode, kill-switch, DNS upstream, auto-connect, launch-on-boot — reached
from a new `File` menu rather than competing with the single Connect/Disconnect
button, matching this ADR's existing "the one thing you can do right now" framing for
that button. It follows the split this ADR already committed to: the new fields live
on `appstate.Config` and are read/written by `appstate.LoadConfig`/`SaveConfig`
(extended, not replaced) and a new `appstate.SetLaunchOnBoot` (per-OS: a Windows
registry Run key, an XDG autostart `.desktop` file on Linux); `settings.go` itself
holds only widget wiring, no logic of its own to unit-test. i18n follows the same
`lang.L` + `translations/<prefix>.ru.json` convention as the original skeleton
(`translations/settings.ru.json`).

Split-tunnel, kill-switch, and DNS are **config surface only, same as before** — this
client still has no TUN device, so nothing enforces them yet. This is exactly the
"Proxy ready" vs. "Protected" distinction the Scope section already draws at length,
and it was not going to be reintroduced by a different door: the settings window says
so in its own body text, not only in a doc a user will never open. Auto-connect and
launch-on-boot are the two fields that do not wait on a TUN device and are fully live
today. `Blocked`'s meaning, and everything else in the Scope section on what this
client does and does not carry, is unchanged.

**Linux build (#153).** The "new build prerequisite" section above proved the Linux
build by hand, once, in a disposable container, and deliberately did not commit its
verification screenshot ("worth nothing to a reader who cannot reproduce it"). A
`linux-client` job in `.github/workflows/ci.yml` now runs that same proof — install
the package list this ADR already recorded, `go vet`/`go build`/`go test`, then launch
the built binary under `xvfb-run` and confirm it is still running five seconds later
— on every push, rather than resting on a one-time record. This does not change the
decision: Linux was already the second of the two platforms this ADR evaluates, and
was already run, not just cross-compiled. It closes the gap between "proven once" and
"proven continuously," the same gap #131 (elsewhere in this PR) closed for
`cmd/node`'s mesh-recovery test. Mobile remains future work per the Consequences
section above and is untouched by this amendment.

## Amendment (2026-07-28): does Fyne replace `clients/windows`, or do both ship? (#35)

**This section is evidence, a proposed seam, and a recommendation — not a decision.**
`clients/fyne/README.md` already says "`clients/windows` remains the full-featured
client until those land here" (that line is the README's, not this ADR's own prose —
checked directly rather than assumed, since no such sentence appears earlier in this
file). It is still true today. Whether it stays true is #35's question, and it is the
owner's call, not this lane's. What follows is what #35 asked this lane to produce
before the desktop trio (`[E9]` macOS #36, `[E10]` Linux #37) is built: a written
parity bar, an enforcement seam, and a recommendation for where #16 `[E3]` gets built.
Nothing below retires `clients/windows`, and nothing below should be read as though it
already has.

### The six files, individually, on `2a8a1fe`

`clients/windows` owns the entire OS enforcement layer in six files, 1,969 lines.
Read file by file rather than taken from this ADR's earlier prose, they split cleanly
into two groups — and the split is the single most important fact for costing either
option, because "port six files" is not six roughly-equal units of work: only two of
them, 652 of the 1,969 lines (33%), are the genuinely hard part; the other four,
1,317 lines (67%), are portable unchanged or need only re-pointing:

| File | Lines | OS-coupling |
|---|---|---|
| `splittunnel.go` | 361 | **None.** `bypassPolicy` has no PowerShell/OS call of its own — its own file doc says so. Pure `net.IPNet` matching, DNS-packet parsing, and locking; OS side effects are injected via `onLearn`, which `tunnel.go` wires. Portable unchanged. |
| `poolroutes.go` | 304 | **Isolated to four fields.** `poolExcluder`'s locking/dedup/self-reap state machine (hardened across issues #109/#117/#123b/#123c) is plain Go; the only OS-facing surface is `excludeFn`/`allowFn`/`gatewayFn`/`removeFn`, injected functions `newPoolExcluder` wires to `routes.go`/`killswitch.go`. The struct and its methods port unchanged; only the wiring changes per platform. |
| `tun2socks.go` | 338 | **Minimal.** Bridges a `tun.Device` (wireguard-go's `golang.zx2c4.com/wireguard/tun` — already cross-platform: Windows/Linux/macOS implementations upstream) to gVisor's pure-Go userspace netstack, then to the existing local SOCKS5 server via standard `net`/SOCKS5 calls. No direct Windows API use. |
| `tunnel.go` | 314 | **Orchestration only.** The bring-up/teardown sequencing (exclude control-plane endpoints → seed bypass domains → create TUN → split-default or inclusion routes → arm kill-switch, each step's rollback deferred in reverse) is portable logic — but it currently calls `routes.go`/`killswitch.go` functions directly by name, not through an injected seam the way `poolroutes.go` already does. Needs re-pointing at the interface below, not a rewrite. |
| `routes.go` | 414 | **Total.** Every function shells out to PowerShell's `NetTCPIP` cmdlets (`Get-NetRoute`, `New-NetRoute`, `Remove-NetRoute`, `New-NetIPAddress`, `Disable/Enable-NetAdapterBinding`). No portable equivalent exists in this codebase. |
| `killswitch.go` | 238 | **Total.** Every function shells out to PowerShell's `NetSecurity` cmdlets (`New/Remove-NetFirewallRule`, `Set/Get-NetFirewallProfile`). No portable equivalent exists in this codebase. |

`routes.go` + `killswitch.go` — 652 lines — is the number Option 1 actually turns on,
and it is not a port: Linux has no `NetTCPIP`/`NetSecurity` equivalent (routing is
netlink or `ip route`; the firewall side is nftables or iptables) and neither does
macOS (a BSD routing socket or `route`/`networksetup`; the firewall side is
`pf`/`pfctl`) — each is a from-scratch implementation against an unrelated OS API,
**twice** (once per platform), against a spec that today exists only as these two
Windows files' behavior.

That figure understates the real cost, not overstates it. `routes.go` and
`killswitch.go` are exactly the two files whose comments document the most hardening
history in this package — issues #64, #73, #109, #117, #123b, #123c are all races or
leaks found and closed *after* the original implementation shipped, in this exact
code. A port that reproduces the current behavior without reproducing that hardening
reopens those races on two more platforms. "Behind an interface" is necessary and, per
the table above, cheaper than it looks for four of the six files — it is not sufficient
to make the remaining 652 lines routine.

### Written parity bar

If Option 1 ("Fyne everywhere") is the direction chosen, `clients/windows` retires
only once a platform's `enforcement.Enforcer` (below) clears all of the following —
not "compiles," not "connects," but every guarantee `clients/windows` ships today:

1. **Full-device routing, both split-tunnel modes.** Exclude mode (default: capture
   everything, carve the bypass set back out) and include mode (issue #64: capture
   nothing by default, pull the bypass/include set in) both work, including the
   live DNS-driven learning path for bypass domains (`splittunnel.go`'s
   `observeDNS`/`learn`) — this one ports unchanged, so parity here is "wired
   correctly," not "reimplemented correctly."
2. **Fail-closed kill-switch**, default-deny plus a narrow allowlist (tunnel adapter,
   control-plane endpoints, configured bypass set, loopback, DHCP — no plaintext-DNS
   allowance), that survives a killed process: an OS-level filter, not
   process-lifetime state.
3. **Crash recovery.** A lockdown left behind by a killed prior session is detected
   and lifted on next launch (`recoverKillSwitch`'s equivalent) — without this, a
   crash leaves the user silently offline with no explanation and no recourse short of
   knowing to reach for whatever this platform's equivalent of Windows' firewall
   rules is.
4. **Live kill-switch allowlist refresh** when a bypass domain resolves mid-session
   (`refreshKillSwitchAllowIP`'s equivalent) — without it, a bypass destination works
   until the kill-switch arms and then silently stops, which is a functional
   regression wearing a security feature's clothes.
5. **Pool-underlay exclusion on the dial path**, wired to the transport pool's
   underlay-dial hook (`ReserveUnderlay` below), preserving the specific ordering
   issues #109/#117/#123b/#123c fixed: an address excluded *before* the dial that
   uses it, never after, and never orphaned if bring-up fails mid-flight.
6. **IPv6 handled**, not merely unmentioned: either blocked at the same point
   `disablePhysicalIPv6` blocks it, or an equivalent stated leak analysis for why not.
7. **Elevated execution is real and documented** for the platform: what this
   client requires (Administrator on Windows; likely `CAP_NET_ADMIN`/`CAP_NET_RAW`
   or root on Linux; admin on macOS) and what happens when it's missing — silently
   degrading to unprotected is the one failure mode this whole bar exists to rule out.
8. **A traffic-level test, not just a state-level one, proves it**: this ADR's own
   Scope section already recorded what happens without one —
   `TestProtectedMeansTrafficActuallyFlows` exists because the state machine reached
   `Protected` while 100% of traffic left in the clear, and every build-time check
   stayed green through it. A platform clears this bar only once it has that test's
   equivalent: a real byte round-tripped through a real exit over the *enforced* path,
   plus a leak check with the kill-switch armed and the tunnel process killed out from
   under it.

> **These eight are the ENFORCEMENT axis, and that is all they are.** Items 9–12
> (the 2026-07-30 `#93` amendment) are the configuration axis, added after all eight
> here were met in full while `clients/fyne` still could not configure six of the
> `core.Config` fields the walk client exposed. Read both lists, or repeat that.

Until a platform clears all eight, `clients/windows` is that platform's answer, full
stop — a partial `Enforcer` shipped as if it were parity is this ADR's Scope-section
lie ("the state was true; the sentence about it was not") wearing a new platform.
**If Option 2 or 3 is chosen instead, this bar is simply never applied** — clients/windows
keeps shipping on Windows indefinitely and nothing above is a gate on anything. Which
of those is true is exactly what #35 asks the owner to decide; this bar answers "what
would parity even mean," not "should we pursue it."

### The enforcement seam

`clients/internal/enforcement` (new: `enforcement.go`, `enforcement_linux.go`,
`enforcement_darwin.go`, and matching `_test.go` files) names the seam without
implementing it. Its `Enforcer.Start(policy Policy, socksAddr string) (Session, error)`
is the single entry point a platform implementation provides; `Session.ReserveUnderlay`
and `Session.Close` are the only two calls a running session needs from the outside —
sized from the table above: `Policy` is shaped by what `splittunnel.go`/`tunnel.go`
already treat as pure configuration (bypass list/mode, DNS upstream, kill-switch
on/off, the control-plane endpoints an implementation must keep excluded), and
`ReserveUnderlay` exists specifically so a port of `poolroutes.go`'s hardening has
somewhere to attach (parity item 5 above) rather than being quietly dropped.

Two things this seam is not: it is not a rewrite of `routes.go`/`killswitch.go`
(New returns `NotImplementedError` on every platform today — no enforcement logic
exists behind it, on any OS, after this PR), and it does not touch `clients/windows`
at all. `clients/windows` already has a complete, working implementation of this
shape; folding it in behind this interface — if Option 1 is chosen — is that
option's own cost (parity item table, `routes.go`/`killswitch.go` row) and its own
card, not a side effect of naming the seam. That is also why there is no
`enforcement_windows.go` here: writing one now would either duplicate
`clients/windows`'s working code behind a second interface nothing calls yet, or
silently assert that Fyne needs its own Windows enforcement at all — which is exactly
the question this amendment defers. Only `[E9]`/`[E10]`'s two platforms get a stub,
because those are the only two this decision actually blocks (`clients/windows`'s
Windows enforcement is not blocked on anything; it already ships).

This shape is not invented for this PR. Two precedents for it already exist in this
repo, independently, before this decision was ever raised:

- **`poolExcluder`'s own injected functions** (`excludeFn`/`allowFn`/`gatewayFn`/
  `removeFn`, `poolroutes.go`) are the same idea — OS-facing primitives passed in
  rather than called by name — applied to one narrow piece of `clients/windows`
  itself. `enforcement.Enforcer` generalizes exactly that pattern to the whole
  routing/kill-switch surface, rather than inventing a new one.
- **`appstate`'s `autostart_linux.go`/`autostart_windows.go`/`autostart_other.go`**
  (`SetLaunchOnBoot(enabled bool) error`, one capability, one function per platform,
  the unimplemented case a named error rather than a silent no-op) is the pattern
  `enforcement_linux.go`/`enforcement_darwin.go`/`NotImplementedError` follow directly.
  The one deliberate difference: `NotImplementedError` is a typed struct carrying
  `GOOS` and the specific tracking issue, because there are two distinct unimplemented
  platforms here with two different owning cards, not one `_other.go` catch-all —
  collapsing `[E9]` and `[E10]` into one generic "unsupported" would lose exactly the
  information (which issue, which platform) a caller most needs from this error.

A proposal that invented a third pattern beside these two would be the worse proposal;
this one doesn't.

### Where #16 `[E3]` gets built

**Recommendation: Fyne, not `clients/windows`.** Reasoning, not a ruling:

- `clients/windows` already has *a* country picker (`main.go`: `countryItem`,
  `exitSlots`, `selectExit`, `listCountries`, `refreshExits` — real code, not a gap),
  but it is a `systray.MenuItem` list — one text line per country, busy expressed as a
  `" — busy"` label suffix, no ping at all. #16 asks for pings and a busy *bar* per
  country. Even today, on Windows, #16 is not fully satisfied — the tray-menu-item
  toolkit has no natural home for a numeric ping and a bar widget the way a real list
  widget does. `clients/fyne` has no picker at all yet (`main.go`'s own comment: "Still
  no country picker (#150, blocked on #146)"), but building #16 there is building it
  once, in a toolkit built for the widget shape #16 actually asks for, not rebuilding
  it in a toolkit that would need stretching to do it and already shipped a lesser
  version.
- The data source is not the throwaway part either way: `core.Engine.ListCountries` is
  already toolkit-agnostic and already proven from two callers' worth of evidence —
  `clients/windows/main.go`'s `listCountries()` calls it today, and a Fyne picker would
  call the identical method. Nothing about #16 requires deciding #35 first *technically*
  — only the UI glue is at stake, per the issue.
- Under every branch of #35, a Fyne-first #16 is the better bet: if Option 1 wins,
  it's immediately the Windows picker too — zero throwaway. If Option 2 or 3 wins,
  Windows keeps its existing (lesser but shipped) picker as-is, and a nicer
  ping-plus-busy-bar version for Windows specifically becomes its own later card if
  the owner wants it — not a blocker for #16 landing on the platforms that have
  nothing today. A walk-first #16, by contrast, is thrown away outright under Option 1,
  and is redundant work under Option 2/3 unless the owner separately wants the
  enhanced UX on Windows specifically — walk-first loses on strictly more branches
  than Fyne-first does.
- This does not require #35 to resolve first. It only requires accepting that
  `clients/fyne` is getting a country picker regardless of what happens to
  `clients/windows` — which is already true under every option on the table.

## Amendment (2026-07-29): #35 is ruled — Fyne everywhere, `clients/windows` retires at parity

The amendment above set out the evidence, the parity bar and the seam, and explicitly
declined to choose. This is the choice.

### Decision

**Option 1. `clients/fyne` becomes the client on all three desktop platforms.
`clients/windows` is retired — not now, but once Fyne clears the eight-point parity
bar above on Windows.** Owner, 2026-07-29: *"We finish fyne, drop the old one when we
will have all functionality in the new one."*

Three consequences follow immediately, and they are the whole reason #35 blocked
three cards:

1. **The eight-point parity bar above is now binding, not hypothetical.** Every "if
   Option 1 is chosen" in it reads as "is". A platform ships enforcement when it
   clears all eight; `clients/windows` is retired when *Windows* clears all eight.
   The bar's own closing sentence — that a partial `Enforcer` shipped as parity is
   this ADR's Scope-section lie wearing a new platform — is now a rule rather than a
   caution.
2. **`clients/internal/enforcement` is the architecture, not a proposal.** `[E9]`
   (#36) and `[E10]` (#37) implement `Enforcer` for their platforms. They are two
   backends behind one interface, not two clients.
3. **#16 `[E3]` is built in Fyne.** The recommendation above becomes the instruction;
   under this option a Fyne picker is immediately the Windows picker too, so there is
   no throwaway.

### What "drop the old one" does *not* mean

`clients/windows` is not deprecated today and does not stop being maintained today.
It is the only thing on any platform that actually routes a device, and it stays the
answer on Windows until the bar is cleared. Retirement is an event with a written
trigger, and the trigger is the bar — not a date, not "when Fyne feels ready", and
not the first release in which Fyne can connect.

That distinction is the one this decision is most likely to lose. "Fyne everywhere"
read as "stop working on the walk client" would leave every platform with a client
that routes nothing, which is strictly worse than the position this ADR started in.

### The work this creates, and where it is tracked

Choosing Option 1 turns the 652 lines the amendment above identified —
`routes.go` + `killswitch.go` — into three separate implementations against three
unrelated OS APIs, plus the fold of the existing Windows implementation behind the
seam. That is the honest price of one codebase, it was measured before the choice was
made, and it does not become cheaper for having been chosen.

Specifically not carded by this amendment, because each belongs to its own card:

- **Windows:** fold `clients/windows`'s working enforcement behind `Enforcer`. This
  is the cheapest of the three — the implementation exists and is hardened — but it
  is also the one that gates retirement, since the bar is cleared on Windows first or
  it is never cleared anywhere.
- **`[E10]` #37 (Linux):** netlink or `ip route`, nftables or iptables.
- **`[E9]` #36 (macOS):** a BSD routing socket or `route`/`networksetup`, `pf`/`pfctl`.

Each carries parity item 8 — a traffic-level test, not a state-level one — as an
acceptance criterion rather than a nice-to-have. The four portable files
(`splittunnel.go`, `poolroutes.go`, `tun2socks.go`, `tunnel.go`; 1,317 of the 1,969
lines) move once, not three times, and the hardening history recorded in the
amendment above is what a port has to preserve, not merely the behaviour.

### Consequences

- **#35 closes.** It asked for a decision, a parity bar, a seam and a home for #16;
  all four now exist.
- **`[E9]`, `[E10]` and #16 unblock.** They were blocked on this and nothing else.
- **`clients/fyne/README.md`'s line — "`clients/windows` remains the full-featured
  client until those land here" — becomes accurate rather than provisional.** It was
  describing a temporary state nobody had committed to; it now describes a committed
  plan with a written end condition.
- **Two Windows clients exist for a while, deliberately.** That is the cost of
  retiring one safely rather than switching over and discovering the bar was not met.

## Amendment (2026-07-30): Windows has cleared the parity bar (#59)

The amendment above made the eight-point bar binding and named the fold of
`clients/windows`'s enforcement behind `Enforcer` as the card that gates
retirement — "the bar is cleared on Windows first or it is never cleared
anywhere." #59 is that card, and this section is its record.

**Windows meets all eight items in code, with one caveat that belongs in the
first paragraph rather than a footnote: two of the guarantees are OS
behaviours that no Go test can assert, and they were not confirmed on an
elevated Windows machine as part of this work.** See "what these tests do not
cover" below — it is the section that decides whether the trigger has really
fired, and the honest answer is "everything that can be automated, yes; the
hardware run, not yet".

That framing is the point of writing this down at all. The bar's own trigger
clause is that retirement is "an event with a written trigger", so a record
that says "all eight met" and nothing else would leave the owner taking a
retirement decision on this document's assurance rather than on evidence. Each
item below therefore says what satisfies it, where, and — where it matters —
what it does *not* cover.

### What was actually built

`clients/internal/enforcement` went from a named seam with no implementation
to the single implementation both desktop clients use. The 2026-07-28 costing
held up: the four portable files moved once and needed no logic changes,
`tunnel.go` needed re-pointing rather than rewriting, and `routes.go` +
`killswitch.go` moved behind the seam near-verbatim as `winOS` methods.

Three things the costing did not name, found while doing it:

- **`udprelay.go` (290 lines) had to move too.** It is not in the six-file
  table, but `tun2socks.go` depends on it for the entire general-UDP path
  (issue #41). The table's 1,969 lines were the enforcement layer as ADR-0036
  drew it; the actual portable unit is 2,259.
- **Two more pieces turned out to be portable**, and moving them was worth
  more than leaving them: the address handling (`addrs.go` — `hostOf`'s
  bracketed-IPv6 case, `ensureCIDR`'s `/128`, the IPv4/IPv6 split of issue
  #117) and the log redaction (`redact.go`, issue #140). Both are pure Go,
  both are obligations every platform has, and both were fixes made once after
  the original shipped — exactly the class the amendment above warns a port
  re-derives badly. `routes.go`'s Windows-total row is 414 lines; the part
  that is genuinely PowerShell is smaller than that.
- **`Enforcer` needed two methods the seam did not name**, both because a
  parity item cannot be met without them. `Recover()` is item 3: the bar says
  a crashed session's lockdown is lifted "on next launch", and `Start` runs on
  next *connect*, which is too late for a user who is already offline and does
  not know why. `ReserveUnderlay(addr)` is item 5: the pool dials its first
  reality underlay inside `core`'s `Connect`, before the tunnel exists and so
  before there is a `Session` to hand it to — wiring `OnUnderlayDial` to a
  `Session` would silently drop precisely the address issue #109 exists to
  catch.

`clients/windows` calls this package now too. There is one implementation with
two callers, not two implementations — which is what makes "the walk client
stays maintained" cost nothing and mean something: a fix to either client's
routing is a fix to both.

### The eight items

1. **Full-device routing, both split-tunnel modes.** Exclude mode installs the
   split-default and carves the bypass set back out; include mode installs no
   split-default at all and routes the include set into the adapter
   (`TestIncludeModeNeverInstallsASplitDefault` asserts the absence, which is
   the actual content of issue #64). The DNS-driven learning path ports
   unchanged, as predicted, and `TestObserveDNSLearnsBypassDomainAnswers` and
   the rest of `splittunnel_test.go` came with it. Bypass-goes-direct is also
   proven at traffic level
   (`TestEnforcedPathSendsBypassDestinationsDirect`), not only by asking
   `bypassPolicy` what it thinks.
2. **Fail-closed kill-switch.** `enableKillSwitch` unchanged: default-deny
   plus tunnel adapter, control plane, bypass set, loopback and DHCP, no
   plaintext-DNS allowance. `TestEnableKillSwitchAllowsBeforeItBlocks` pins
   that every allow rule exists before the default flips to Block, and
   `TestEnableKillSwitchLeavesNothingHalfArmed` that a failure part-way
   removes the group rather than leaving the machine locked down with a
   partial allowlist. `TestBringUpArmsTheKillSwitchLast` pins it as the final
   step of bring-up. It is an OS-level filter, so it survives the process —
   see "what these tests do not cover" below.
3. **Crash recovery.** `recoverKillSwitch` unchanged, now reachable through
   `Enforcer.Recover()` and called at launch by both clients.
   `TestRecoverKillSwitchRestoresACrashedSession` checks the exact prior
   per-profile state is restored from the marker rule's Description, and
   `TestRecoverKillSwitchIsANoopWithoutAMarker` that a clean launch touches
   the firewall not at all — restoring "Allow" unconditionally would silently
   undo an outbound-block policy an administrator set themselves.
4. **Live kill-switch allowlist refresh.** `refreshKillSwitchAllowIP`
   unchanged. `TestRefreshKillSwitchAllowIPAddsToTheLiveRule` checks the
   existing addresses survive the remove-and-recreate (NetSecurity has no
   in-place edit) and that the removal precedes the recreation;
   `TestRefreshKillSwitchAllowIPIsANoopWhenUnarmed` that an unarmed session
   does not leave an allow rule behind.
5. **Pool-underlay exclusion on the dial path.** `poolExcluder` moved with its
   state machine and all fourteen of its tests intact — the #109/#117/#123b/
   #123c orderings are asserted by exactly the code that asserted them before.
   Only its wiring changed: the four injected primitives now come from
   `osNet`. The ordering constraint the issue singles out is covered from both
   ends: `TestReserveBeforeStartSurvivesIntoBringUp` for the pre-tunnel dial
   (the one a `Session`-only hook would have dropped),
   `TestReserveAfterStartInstallsLive` for failover, and
   `TestFailedBringUpOrphansNothing` for "never orphaned if bring-up fails
   mid-flight" — every route installed comes back out, IPv6 is re-enabled, the
   device is closed, and the kill-switch is never left armed over a tunnel
   that failed to come up.
6. **IPv6 handled.** `disablePhysicalIPv6` blocks it on the physical adapter
   for the tunnel's lifetime, the netstack has no IPv6 route as a second line,
   and `resolveExclusionsV6`/`addExclusionRoutesV6` handle an IPv6 reality
   exit address as defense in depth. Unchanged from what shipped;
   `TestFailedBringUpOrphansNothing` additionally pins that a failed bring-up
   never leaves IPv6 disabled with nothing owning its restoration.
7. **Elevated execution is real and documented.** Administrator, for TUN
   creation and every routing/firewall cmdlet; `createTUN`'s error names it,
   because unelevated is overwhelmingly the reason this fails in the field.
   The part that needed building was the *consequence*: `clients/fyne` now
   aborts the whole connect when enforcement fails rather than leaving the
   engine up as a working SOCKS proxy. That fallback is the friendlier
   outcome and it is exactly the failure this bar exists to rule out — a green
   banner over a proxy the user never configured is this ADR's Scope-section
   lie in its original form. `Controller.DeviceEnforced` is what the UI asks,
   so the headline reads "Protected" only where a device really is routed and
   stays "Proxy ready" on the platforms that still route nothing.
8. **A traffic-level test, not a state-level one.** `traffic_test.go`. A byte
   enters at the TUN device as a real IP packet from a real TCP stack that
   knows nothing about Bacchus, and has to come back having been to a real
   exit: real gVisor netstack, real split-tunnel decision, real SOCKS5, real
   `core.Engine` on both ends, real transport handshake, real egress
   (`TestEnforcedPathCarriesRealTraffic`). The leak half is
   `TestEnforcedPathDropsRatherThanLeakingWhenTheTunnelDies`: with the tunnel
   gone, a destination the policy routes through it must be dropped, never
   re-dialled on the physical interface because that path still works — and
   the assertion is against a listener that records arrivals, so the failure
   being ruled out is "the byte arrives anyway, by another route" rather than
   "an error was returned". Item 1's control test doubles as this one's
   sensitivity control: a leak check whose listener is unreachable passes
   forever, including on the day the code starts leaking.

### What these tests do not cover, and how that half was checked

The TUN device in the traffic test is in-memory (`memtun_test.go`). That is
what lets it run unelevated, on every push, on both CI runners — but it means
these tests prove everything from the IP packet inward and nothing about
whether the OS hands the device those packets in the first place. That is the
route table's job, it lives behind PowerShell, and it needs Administrator.

Likewise, the kill-switch tests drive the real cmdlet sequence through an
injected runner and assert ordering. They cannot prove Windows *honours* those
cmdlets — that a `DefaultOutboundAction Block` really does keep blocking after
this process is killed. That is an OS guarantee, and asserting it in Go would
only be asserting that we called the right function.

**Neither of those was verified on hardware as part of #59, and this section
will not pretend otherwise.** The work was done on a Linux host with no
elevated Windows machine attached; every test above was run, and nothing
beyond them was.

That gap is narrower than it looks, and it is worth being precise about why,
because the answer is not "trust us":

- The PowerShell layer is **unchanged code**. `routes.go` and `killswitch.go`
  moved behind the seam as `winOS` methods; the cmdlet strings, their
  arguments, their error handling and their ordering are the same ones
  `clients/windows` has been shipping to real users since ADR-0036, through
  six rounds of hardening. What #59 changed is who calls them, and that is
  precisely the part the tests above do cover.
- What is genuinely new and unproven on hardware is therefore not "does
  `New-NetRoute` work" but "does this package call it in the same order the
  old code did" — which `tunnel_test.go` asserts directly, against the same
  sequence, on every push.

Still, "the same code, called the same way" is an argument, not a run, and the
two guarantees at the top of this section are the two a user's safety actually
rests on. **The bar is met to the limit of what can be automated; the
on-hardware confirmation is outstanding.** Whoever takes the retirement
decision should do that run first — bring the tunnel up elevated, confirm
`Get-NetRoute` shows the split-default and the control-plane exclusions,
confirm real device traffic egresses via the exit, kill the process outright,
confirm the machine is still fail-closed, and confirm the next launch
recovers. Retiring `clients/windows` on the strength of this document alone
would be taking the one step this ADR has twice now written down as the thing
not to do.

### Consequences

- **Retirement is now a decision the owner can take, once the hardware run
  above is done.** The code half of the trigger has fired; the on-hardware
  half is the outstanding piece, and it is small and well-specified rather
  than open-ended. This amendment does not retire `clients/windows`, and #59
  explicitly did not: that is a separate call, and until it is taken, the walk
  client stays maintained and shipping. It is now maintained on top of the
  same enforcement code as Fyne, so "both ship for a while" costs one
  implementation rather than two.
- **`clients/fyne` carries device traffic on Windows.** The Scope section's
  "**Out, and the one that matters: this client does not carry device
  traffic**" is now false on one platform and still true on the other two. So
  is the sentence about the settings window's split-tunnel/kill-switch/DNS
  fields being "config surface only": on Windows they are live.
- **`[E9]` (#36) and `[E10]` (#37) got smaller.** They implement `osNet`, not
  `Enforcer` — around a dozen primitives — and inherit the orchestration, the
  underlay-exclusion state machine, the split-tunnel logic, the netstack
  bridge, the address handling and the redaction. `tunnel_test.go` runs
  against any `osNet`, so the ordering guarantees they have to satisfy are
  executable rather than prose. What does not get smaller is the part the
  2026-07-28 amendment already said was the real cost: nftables/iptables and
  `pf` are still from-scratch implementations against unrelated OS APIs, and
  each still carries item 8 as an acceptance criterion.
- **CI covers this code for the first time.** `clients/internal/...` was
  vetted and tested by no job — the server job excluded `./clients/...`,
  linux-client runs only `./clients/fyne/...`, and windows-client built a
  single package. Both now vet and test it, which is what makes the eight
  items above a standing claim rather than a one-time one.

## Amendment (2026-07-30): the parity bar had only one axis (#93)

The bar above has eight items. Every one of them is about **enforcement**:
routing, kill-switch, crash recovery, live allowlist refresh, pool-underlay
exclusion, IPv6, elevated execution, and a traffic-level test. #59 met all
eight, honestly and completely, and this document said so.

It was still possible, at that moment, for `clients/fyne` to be unable to
configure half of what `core` supports — and it was. Six `core.Config` fields
the walk client exposed could not be reached from the client replacing it:
`RelayHops`, `RelayDirectoryPath`, `RelayDirectoryKey`, `TransportPool` had no
field in `appstate.Config` at all, and `AdmissionPubKey` / `AdmissionCRLPath`
were read from the config file with no way to set them.

**The bar did not omit an item. It never covered this axis.** That is the
finding, and it is worth more than the six fields, which are only its symptom.
A bar with the word "parity" in its name was read — by this document, by #35's
ruling, and by #59's implementation — as *the* definition of parity, so a gap
lying entirely outside its axis could survive a decision, an ADR and an
implementation without any of the three being wrong on its own terms. Nothing
was skipped; the question was never asked.

Two things follow, and only the first is about `clients/fyne`.

### Configuration-parity bar

Alongside the eight enforcement items, `clients/windows` retires only once:

9. **Every `core.Config` field either client can set, the surviving client can
   set** — or the field is recorded here as deliberately dropped, with the
   reason. The comparison is between what each settings dialog actually
   *writes*, not what either README says it offers; #93's table was built that
   way and found six fields precisely because it was.
10. **A field that no longer does anything is deleted, not ported.** The walk
    client offered a disabled exit-ID pin with a label explaining that it did
    nothing — `core` emits *"Config.ExitID is set but has NO EFFECT"* for a
    value that reaches it (ADR-0042, `old #146`). #93 deleted the control.
    Carrying it across by pattern-matching would have been the easier move and
    would have reproduced a dead control in a new client. The persisted field
    stays: an old settings file still carries one, and connecting logging that
    the saved pin is ignored beats a dialog silently rewriting the file.
11. **Configuration is verified where it can be asserted.** Validation and
    normalization live in `internal/appstate`, which needs no GUI toolchain to
    test, and the widget layer is wiring over it — the split this ADR already
    draws for `Controller`, applied to settings. A rule enforced only inside an
    `OnSubmit` closure is a rule no test can reach.
12. **A UI string with no translation fails a build.** Fyne's `lang.L` falls
    back to the key itself, so a missing translation renders as English and
    passes every other check — including, before #93, every check in this
    repo. `clients/fyne/translations_test.go` walks the package's own AST for
    `lang.L` keys and fails on any the catalogue is missing. This is the one
    item on either bar whose failure mode is invisible rather than loud, which
    is exactly why it needs a test rather than a review habit.

Items 9–12 are gates on retirement in the same way items 1–8 are. #93 satisfies
9, 10, 11 and 12 for Windows and Linux; nothing here is platform-specific, so
`[E9]`/`[E10]` inherit them satisfied rather than owing them.

### What #93 also surfaced, and did not leave alone

Wiring `TransportPool` made a latent divergence load-bearing. `clients/windows`
sets `core.Config.ForceRelay`; `clients/fyne` did not. That is the mechanism
pinning every WebRTC candidate to the configured TURN server — an address
`enforcement.Policy` already excludes — and it is *why* webrtc qualifies for
the pool's allow-list at all. reality qualifies by the other route, the late
`OnUnderlayDial` exclusion, which this client has wired since #59.

Unset, a WebRTC underlay on the one platform where this client enforces
follows the split-default back into the tunnel it is carrying: a loop, and a
Block once the kill-switch arms. Not a plaintext leak — the failure is that it
stops working, not that it escapes — but it was a real defect in the #59 fold
that no item on the eight-point bar asks about, and it went unnoticed for the
same structural reason as the six fields: item 5 asks whether the
underlay-exclusion *hook* is wired, which it was.

`Controller` now sets `ForceRelay` whenever an `Enforcer` exists, and only
then. `clients/windows` sets it unconditionally, which is right for a client
that always routes the device; this one is proxy-only where there is no
`Enforcer`, has no tunnel to loop into, and forcing every session through TURN
there would spend an operator's relay bandwidth and a round trip to fix a
problem that platform does not have.

### Consequences

- **The bar is now two bars, and the second one is the general lesson.** A
  parity bar states what was compared; anything outside it is not "met", it is
  unexamined. Item 9's rule — compare what the code *writes*, not what the
  docs claim — is the part that generalizes past this client pair.
- **#88 (retire `clients/windows`) gained four gate items.** It was already
  blocked on the hardware run for items 2 and 3; it is now also blocked on
  9–12, which #93 satisfies. Recorded before retirement rather than after, so
  these controls do not leave with the client that used to be their only home.
- **`docs/design/relay-chaining.md` §9 row 5 is closed.** It named the
  `RelayHops` remainder and said nothing on the board tracked it. #93 did, and
  the row now says so.
- **This amendment is the second time this ADR has recorded a true statement
  that was not the whole truth** — the Scope section's original form was the
  first. Both were accurate about what had been checked, and both let a reader
  conclude something broader. That pattern, not either instance, is the thing
  to watch for in the next bar this project writes.

## Amendment (2026-07-31): Linux clears the bar, with one item qualified (#37)

`[E10]` (bacchus#37) shipped the Linux `Enforcer`, against the privilege model
ADR-0049 decided. Recorded item by item, because this bar's whole point is that a
partial `Enforcer` shipped as if it were parity is this record's Scope-section lie
wearing a new platform.

| # | Item | Linux |
|---|---|---|
| 1 | Split tunnelling *wired correctly*, not reimplemented | Yes — `splittunnel.go` is inherited unchanged; only three route methods are new |
| 2 | Kill-switch is an OS-level filter that survives a killed process | Yes — nftables state in the kernel, asserted surviving the client being killed |
| 3 | A stale lockdown is detected and lifted on next launch | Yes — the helper reaps its own table by name, no heuristic needed |
| 4 | Late-learned bypass addresses fold into the live allowlist | Yes — and with **no** fails-closed window, unlike Windows (ADR-0049 §8) |
| 5 | Underlay exclusions installed before the dial, never orphaned | Yes — `poolroutes.go` inherited; ordering unchanged |
| 6 | IPv6 on the physical adapter is closed for the tunnel's lifetime | Yes — and restored to its *captured prior value*, not a hardcoded 0 |
| 7 | Elevated execution is real, documented, and fails loudly when missing | Yes — `bacchus-netd`, documented in `deploy/README.md` and `docs/RUNNING.md`; a missing helper **fails the connect** |
| 8 | A traffic-level test, not a state-level one | Yes, and further than Windows reaches — see below |

**Item 8 is cleared more strongly here than on Windows, and item 7's DNS half is
not cleared at all.** Both deserve saying plainly.

Item 8: a user namespace plus a network namespace gives CI a real kernel, so the
Linux tests assert what `traffic_test.go` explicitly cannot — that the *kernel
actually delivers* a packet into the tunnel device given the routes installed,
and that an armed kill-switch actually stops one leaving. `traffic_test.go`'s own
file doc names that gap ("Not covered: whether the OS actually hands this device
the packets in the first place"). On Windows it is still open, as #88.

The qualification: **Linux does not capture DNS queries `systemd-resolved` sends
to `127.0.0.53`**. That is loopback, the kernel consults the `local` table before
any route Bacchus installs, and closing it needs a new `osNet` method — a
three-platform interface change, tracked as bacchus#104. It does not fail any of
the eight items as written, because none of them names DNS; it is recorded here
anyway, because a bar read as "all eight, therefore done" would otherwise cover
a real hole. The Settings window states it next to the field rather than leaving
the reader to find this table.

- **`clients/windows`'s retirement (#88) is unaffected.** It was blocked on a
  hardware run for items 2 and 3 on *Windows*; nothing here touches that.
- **The same honesty gap applies to Linux.** A namespace is a synthetic network:
  no real `systemd-resolved`, no NetworkManager, no physical adapter. Passing
  these tests means the mechanism is right, not that a desktop is covered. That
  run has not been done, and this amendment does not claim it has.
- **Volunteering is now refused on Linux.** `ErrVolunteerWhileRouted` refuses to
  serve from a build that routes the device, and `DeviceEnforced()` is a property
  of the platform. bacchus#101 is the fix for the stored-opt-in trap this creates
  on upgrade; `cmd/node` remains the way to donate capacity from a Linux machine.

## Amendment (2026-08-02): the hardware run happened — on `clients/windows` (#88)

The 2026-07-30 amendment above, recording #59, says of the two OS-level guarantees
no Go test can assert:

> **Neither of those was verified on hardware as part of #59, and this section
> will not pretend otherwise.**

That was true, and it stayed true for three days. #88 is the run it asked for, done
on 2026-08-02 on real Windows hardware with Administrator rights, and **both
guarantees are now observed.** The sentence above is left where it is rather than
rewritten, because it is still an accurate statement about #59 — what changed is
not that it was wrong but that it has been overtaken, and a reader should be able
to see both.

### What the run establishes

Six checks, all passing, mapped onto the bar rather than left as a list — the point
of the run is which items it moves:

| #88 checked | Bar item | What it turns from argument into observation |
|---|---|---|
| The tunnel comes up elevated | 7 | Elevated execution is real, not just documented |
| `Get-NetRoute` shows the split-default | 1 | `0.0.0.0/1` and `128.0.0.0/1` both present on the Bacchus adapter, both with `NextHop` = `tunIP` (`enforcement/tunnel.go`'s `10.66.0.2`) |
| …and the control-plane exclusions | 1, 5 | The coordinator's `/32` resolves via the **physical** gateway, outside the tunnel it is building — the exclusion is real, not merely installed |
| Real device traffic egresses via the exit | 8 | The one this ADR could not reach. `traffic_test.go` proves everything from the IP packet inward; whether Windows *hands the device those packets* was open, and an egress-address check answers it from outside the process entirely |
| Kill the process outright; still fail-closed | 2 | `Stop-Process -Force`, no cleanup path taken, `DefaultOutboundAction` still `Block` on all three profiles, and the same request fails. The kill-switch is an OS filter, observed rather than reasoned about |
| Next launch recovers | 3 | A stale lockdown is detected and lifted, and the machine is genuinely back on its own path |

Rows 2 and 4 are one guarantee in two halves and only the pair is evidence: **routes
existing is state; traffic arriving at the exit is proof.** The #59 amendment made
exactly this distinction to explain what its tests could not reach, and it is the
distinction the run was designed around.

One thing the run deliberately did not re-test: the unelevated refusal. That path is
already asserted by `routes_windows.go`'s own error handling, and re-confirming it by
hand would have added a screenshot, not a fact.

### The qualifier, which belongs in this section and not a footnote

**The run used `clients/windows`.** It had to: `clients/fyne` needs a mingw-w64
toolchain to produce a Windows binary, the run had none, and no current binary existed
to reach for — because, as #115 then established, **no CI job had ever built
`clients/fyne` for Windows.**

The precise version of that, since this document's whole subject is the difference
between "not checked" and "not checkable": the "new build prerequisite" section above
records a Windows binary of this client being cross-compiled with mingw and *executed
on a Windows host* as part of the original spike. So the target was known to build —
on 2026-07-15, before #59 folded the enforcement layer in, before #93 wired six more
config fields through it, and before everything since. It was proven once and then
watched by nothing, which is the same gap the #153 amendment closed for Linux and the
same distinction it drew: proven once is not proven continuously.

What follows from that, precisely:

- **The two guarantees hold for either caller.** They are properties of Windows and of
  `clients/internal/enforcement`, and since #59 there is one implementation of that
  package with two callers. The run drove the same `Enforcer`, the same `osNet` and the
  same PowerShell layer `clients/fyne` drives.
- **What is not established is that `clients/fyne` itself brings that package up
  correctly on Windows** — a different claim, about a different binary, and one that
  could not be tested at all while nothing compiled it for the platform.

Writing this section as "Windows is verified" without that sentence would reproduce, in
a new place, the exact pattern the #93 amendment named as this document's recurring
failure: a true statement that is not the whole truth, which lets a reader conclude
something broader than what was checked. The run is real; the binary it used is the one
being retired, not the one replacing it.

### The generalizable lesson from the run itself

Recovery — bar item 3 — cannot be tested with the client reconnected. The first attempt
left it connected, which re-arms the kill-switch and produces `DefaultOutboundAction
Block` for an entirely legitimate reason, indistinguishable from a failed recovery if
the firewall state is all you look at. **Relaunch and leave it disconnected, and use the
egress address as the discriminator, not the firewall state.**

That is not a Windows fact. `[E10]` (#37) and `[E9]` (#36) each carry the same item
against nftables and NetworkExtension respectively, and the same trap: an armed filter
looks identical whether it was left behind or just re-armed. Recorded here rather than
in the issue, so the next platform's run inherits it.

### Consequences

- **The #59 amendment's Consequences bullet — retirement is a decision the owner can
  take "once the hardware run above is done" — has had its condition met.** It is not
  the last one. The #93 amendment added items 9–12 (satisfied), and #115 adds a gate
  that did not exist when either was written: `clients/fyne` must be built for Windows,
  and then brought up on it, before the client being retired stops being the only
  Windows client anyone has ever run.
- **The #37 amendment's line that the OS-delivery gap is "still open, as #88" on
  Windows is superseded.** Linux reached that assertion through a real kernel in a
  network namespace; Windows now reaches it through a real machine. Both are outside
  the process, which is the property that matters; neither is a Go test, which is the
  point.
- **The build half of #115 is now covered.** `.github/workflows/ci.yml` grows a
  `windows-fyne-client` job that installs the mingw-w64 toolchain
  `clients/fyne/README.md` documents, vets, builds the shipping `-H=windowsgui` binary
  and runs the tests — the same "proven once versus proven continuously" move the #153
  amendment made for Linux, applied to the platform that had no proof at all. The
  hardware pass with that binary is #115's second item and is not this.
- **`clients/windows` is still not retired, and this amendment does not retire it.**
  That has been the standing position through four amendments and it has not moved:
  retirement is an event with a written trigger, the trigger is the bar, and the bar
  now has one item outstanding that is about the surviving client rather than the
  departing one.
