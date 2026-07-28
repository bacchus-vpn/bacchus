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
