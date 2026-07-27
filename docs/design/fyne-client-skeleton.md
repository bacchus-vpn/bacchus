# Fyne client skeleton: the in-process spike, in detail (issues #148/#149)

The decision and rationale live in
[ADR-0039](../adr/0039-cross-platform-fyne-client-in-process-core.md). This note
covers the parts an ADR shouldn't carry: how the spike was actually run, the one
environment gotcha it took a few tries to pin down, and the file layout.

## Files

| File | Contents |
|---|---|
| `internal/appstate/state.go` | `ConnState` + the pure `StateFor`/`DetailFor` transition functions (issue #149's typed equivalent of `clients/windows`'s `eventStatus`). No Fyne import. |
| `internal/appstate/controller.go` | `Controller`: owns the `core.Engine` lifecycle (`Connect`/`Disconnect`), republishes state via `OnState`/`OnDetail`. No Fyne import. |
| `internal/appstate/config.go` | JSON config load, mirrors `clients/windows/config.go` trimmed to what this skeleton needs. |
| `internal/appstate/fakecoordinator_test.go` | ~100-line stand-in for `cmd/coordinator`'s wire protocol, test-only. |
| `internal/appstate/controller_test.go`, `state_test.go` | The tests below. |
| `theme.go` | `calmTheme`, overriding only `Color()` on top of `theme.DefaultTheme()`. |
| `ui.go` | `stateIndicator` (the headline color band) + localized copy per state. |
| `main.go` | App/window setup, translation loading, wiring `Controller` callbacks through `fyne.Do`. |

Every pure decision (`StateFor`, `DetailFor`, config load/save) lives in
`internal/appstate`, which has zero Fyne import — see "Why a separate package"
below. The Fyne-touching glue (`main.go`/`ui.go`/`theme.go`) is thin and not unit
tested beyond compiling; its job is wiring, not decisions.

## Why a separate package, not just files in `clients/fyne`

Discovered empirically, not planned up front: this dev environment has no C
compiler, and Fyne's desktop driver needs one (cgo, via `go-gl`). That means
`go build`/`go vet`/`go test` on anything importing `fyne.io/fyne/v2/app` fails on
this host with

```
imports github.com/go-gl/gl/v2.1/gl: build constraints exclude all Go files...
```

*before* CGO_ENABLED=1 is even set — and with it set, `gcc` isn't found either. A
package boundary was drawn at exactly the Fyne import: everything that could
plausibly be tested without a display (the state machine, the controller, config)
went into `internal/appstate`, which has no Fyne import and therefore builds/tests
with the plain host toolchain, no Docker, no cgo, no GUI:

```
$ go test ./clients/fyne/internal/appstate/...
ok  	github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate	1.98s
```

That included `TestController_RealLoopback` — a real client-role `core.Engine`,
driven by `Controller` exactly as `main.go` drives it, against a real exit-role
`core.Engine`, rendezvoused through `fakecoordinator_test.go` over loopback UDP.
Real WebRTC, not a fake transport: it reaches `Protected` and, when the exit is
killed mid-session, observes a genuine ICE disconnect map to `Blocked` — in under a
second, no Docker involved.

## Proving the GUI layer itself: Docker + Xvfb, not "it compiled"

The one thing that categorically needs a display is confirming Fyne actually
renders — and the lane's own instructions are explicit that a claim compiled on
only one platform isn't evidence of running on it. Neither platform was assumed:

**Build environment** (a disposable local image, built ad hoc and not committed — it
is reproduced in full here so it needs nothing else to be rebuilt from):
```
FROM golang:1.26-trixie
RUN apt-get install -y gcc libgl1-mesa-dev xorg-dev \
      libwayland-dev libxkbcommon-dev wayland-protocols \
      gcc-mingw-w64-x86-64 xvfb imagemagick
```

**Gotcha worth recording**: the first pass installed `gcc`, `libgl1-mesa-dev`, and
`xorg-dev` (X11) but not the Wayland dev headers, and the build failed on
```
./glfw/src/wl_platform.h:27:10: fatal error: wayland-client-core.h: No such file or directory
```
— `go-gl/glfw` v3.4 builds both X11 *and* Wayland backends unconditionally on
Linux, so X11 headers alone aren't enough. Adding `libwayland-dev`/
`libxkbcommon-dev`/`wayland-protocols` fixed it — confirmed by installing them in
isolation and locating `wayland-client-core.h` under `/usr/include` before
re-running the real build. (A second, unrelated wrinkle: a `docker build` that
only changed a `RUN` line's package list once reused a stale cached layer that
silently lacked the new packages, invisible until the container was inspected
directly with `dpkg -l`; `--no-cache` resolved it. Root cause not pinned down
further since it didn't recur — noted in case it does.)

**Linux: build and run natively, screenshot to prove it**, no cross-compilation
involved for this half:
```
go build -o bacchus-fyne .
Xvfb :99 -screen 0 1024x768x24 &
DISPLAY=:99 ./bacchus-fyne &
sleep 3 && import -window root screenshot.png   # imagemagick
```
This renders through Mesa's software GL (`llvmpipe`) under Xvfb's virtual
framebuffer — a real GL context and a real Fyne paint pass, just no physical GPU
needed. The captured PNG showed the app's actual widget content, not a blank or
error window.

**Windows: cross-compile from the same Linux container, then run natively on the
real Windows host** — proving the cross-compiled binary is genuine Windows code,
not just "didn't fail to compile":
```
GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  go build -ldflags "-H=windowsgui" -o bacchus-fyne.exe .
```
The resulting `.exe` was copied to the Windows host and launched directly (no
Windows-side compiler needed at all — confirmed separately that this host has
none: `CGO_ENABLED=1 go build` fails with `cgo: C compiler "gcc" not found`). A
screenshot of the running window confirmed real rendering, not just a clean
process start.

## Threading contract, precisely

Three goroutines invoke `OnState`/`OnDetail`, and the enumeration has to be complete
or the contract below means nothing. `Controller.Connect`/`Disconnect` each spawn
their own; the third — and the busiest — is **whichever engine goroutine calls
`onEvent`**, which for the ICE transitions that drive `Blocked`/`Protected` is a
callback goroutine **pion owns** (`core/transport_webrtc.go` registers
`pc.OnICEConnectionStateChange`, and `core/engine.go`'s `emit` calls `OnEvent`
synchronously, inline, on it). Notably `Engine.Stop`'s `wg.Wait()` does not track
pion's goroutines, so an event can still land after Stop returns.

What holds across all three: `OnState`/`OnDetail` are never called synchronously from
the caller's own stack — including the immediate `Connecting` transition (the
re-entrancy guard that rejects a double-click runs synchronously, but never itself
calls `OnState`).

**A state announcement is made with `c.mu` held**, by `publishLocked`, which is what
makes the state change and its announcement one atomic step. Without that they are
ordered against nothing, and two goroutines can set A then B while announcing B then
A — stranding the UI on a stale state that no later event will correct. That is not a
theoretical concern here: it is exactly the pion-goroutine-versus-Disconnect race
above, and the state it strands on is `Protected`. The detail line is deliberately
published outside the lock: it is cosmetic and makes no safety claim.

`main.go` wires both callbacks through `fyne.Do` (never
`fyne.DoAndWait`, which can deadlock if it's ever invoked from Fyne's own UI
goroutine). Given the "never from the caller's stack" contract, `fyne.Do` is
always called from a goroutine that is provably not Fyne's UI goroutine, so this
can't arise in practice — but keeping the contract exact, rather than "usually
true," is what makes that safe to rely on instead of merely observed.
