# Windows client: connection settings + invite QR (issues #75, #32)

The decision and rationale live in
[ADR-0036](../adr/0036-windows-client-connection-strategy-and-invite-qr-ui.md).
This note covers implementation detail the ADR shouldn't carry: the widget
layout, the two `lxn/walk` runtime failures this branch found and fixed (with
the full diagnostic trail, since both are the kind of thing that's expensive
to rediscover), and the safe/unsafe transport-pool table.

## Files

| File | Contents |
|---|---|
| `settings.go` | Pure helpers (`geoOptions`, `sanitizePoolOrder`, `moveLadderItem`, `effectiveExitID`, `ladderDisplayOrder`) + the "Connection settings" `walk.Dialog`. |
| `invite.go` | Pure helpers (`canonicalizeInvite`, `inviteQRImage`, `decodePNG`) + the "Invite QR" `walk.Dialog`. |
| `main.go` | `runOnUIThread`/`uiWorkerLoop` (the persistent UI thread, below), two new tray items, `connect()`'s pool/pin wiring, `currentExitLabel`/`refreshSelectedExitLabel`. |
| `config.go` | New `Config` fields (`Geo`, `ExitID`, `TransportPool`) + `saveConfig` (this client's first config *writer* — previously JSON-file-edit-by-hand only). |
| `bacchus.exe.manifest` | Common Controls v6 manifest — see below. Required, not cosmetic. |

Every pure helper is table-driven tested (`settings_test.go`, `invite_test.go`,
`config_test.go`) per this package's established convention (`main_test.go`'s
`eventStatus`, `splittunnel_test.go`'s `newBypassPolicy`, etc.): the
`walk`-calling glue is thin and untested; the decisions it makes are pure
functions and are.

## Two `lxn/walk` failures found only by running it

Both of these compiled cleanly, vetted cleanly, and looked correct against
`lxn/walk`'s actual pinned source (`v0.0.0-20210112085537-c389da54e794`) —
neither was visible without actually creating the windows. This is the
concrete reason this branch's manual-smoke step used a real, if throwaway,
Win32 window-creation harness instead of stopping at unit tests.

### 1. Missing manifest → every widget fails

Symptom: the very first widget in the very first dialog failed —

```
settings dialog Create: TTM_ADDTOOL failed
```

`lxn/walk`'s `WidgetBase.init` unconditionally creates a shared tooltip and
calls `TTM_ADDTOOL` for *every* widget, regardless of whether `ToolTipText`
is set (`tooltip.go`). `TTM_ADDTOOL` fills a `win.TOOLINFO` struct whose
`CbSize` field must match a size the loaded `comctl32.dll` recognizes. With
no manifest, Windows loads the legacy v5 common controls (the process-wide
default absent an explicit opt-in); `lxn/walk`'s compiled-in `TOOLINFO`
layout doesn't match v5's expectations, so the message is rejected outright.

Fix: `bacchus.exe.manifest`, a `<dependency>` on
`Microsoft.Windows.Common-Controls` version `6.0.0.0`, next to `bacchus.exe`.
Windows probes for a same-named external manifest automatically — no
embedding tool, no build step, just a file that has to ship alongside the
exe (see main.go's package doc and README.md's Build section). Confirmed:
building the standalone test binary with the manifest present next to it
turned the failure into a pass; without it, deterministic every time.

### 2. A second dialog, from a second thread, fails `CreateWindowEx`

With the manifest fixed, each dialog worked *individually*. The original
design gave each dialog open its own fresh `runtime.LockOSThread()`'d
goroutine (walk's windows are thread-bound, so *some* locking is required —
see below). Under that design, opening the settings window and then the
invite window in the same run failed the second one:

```
invite dialog Create: CreateWindowEx
```

with no Win32 error code attached (`win.GetLastError()` read back
`ERROR_SUCCESS`) — a `NULL` `HWND` with no diagnosable cause from the error
text alone, which is why this needed isolation by experiment rather than by
reading the message.

Isolated via a throwaway probe harness (three variants, each removing one
variable):

| Variant | Result |
|---|---|
| Same dialog shape, called 3× in a row, same goroutine | ✅ pass |
| Two *different* dialog shapes, same goroutine | ✅ pass |
| Same trivial dialog shape, two separate `go test` test functions (→ two separate locked goroutines/threads) | ❌ 2nd fails |
| A single persistent locked goroutine, fed both dialog-open requests over a channel with a realistic (200–300ms) gap between them | ✅ pass |

This isolates the variable cleanly: not dialog shape, not timing, not the
manifest — specifically, *a second top-level `walk.Dialog` created from a
different `LockOSThread`'d thread than the first one*. `lxn/walk`'s
`window.go` confirms why: its one-time setup (`InitCommonControlsEx`, the
shared dialog window class, the default `WndProc` callback) runs inside an
`atomic.CompareAndSwapUint32(&initedWalk, 0, 1)` guard — global, fires
exactly once per process, on whichever thread happens to create the first
walk window. It calls `runtime.LockOSThread()` itself at that point, but
that only pins *that* thread for *that* goroutine; it does nothing for a
second goroutine that separately locks a *different* OS thread later. Some
part of what that one-time setup wires up (most likely the shared dialog
window class's association with the thread that registered it, though this
wasn't traced past the point of confirming the fix) doesn't carry over.

Fix: **one persistent, lazily started, `LockOSThread`'d worker goroutine**
for the whole process's lifetime, not one thread per dialog (`main.go`):

```go
var (
    uiWork     = make(chan func())
    uiWorkOnce sync.Once
)

func runOnUIThread(fn func()) {
    uiWorkOnce.Do(func() { go uiWorkerLoop() })
    uiWork <- fn
}

func uiWorkerLoop() {
    runtime.LockOSThread()
    for fn := range uiWork {
        fn()
    }
}
```

A tray click does `go runOnUIThread(openSettingsDialog)` — the `go` keeps the
tray's own dispatch loop unblocked; `runOnUIThread`'s channel send blocks the
throwaway calling goroutine (harmless — it exists only to make this one call)
until the worker is free, which is also the desired behavior: only one
settings/invite window's Win32 calls should ever be in flight at a time.
Verified against the *actual* `runOnUIThread`/`uiWorkerLoop` (not just the
probe pattern): three dialog-shaped windows, dispatched sequentially with
realistic gaps, all succeed.

## Transport-ladder safety (ADR-0036's core claim, worked example)

The tunnel must make each candidate's underlay address reachable outside itself
(an exclusion route, plus a kill-switch allowlist entry) before that underlay is
dialled. A transport is usable in this client's pool when it can guarantee that.

| Transport | How its underlay address is made tunnel-safe | Usable in this client's pool? |
|---|---|---|
| `webrtc` | Ahead of time — `Config.ForceRelay: true` pins every candidate to the configured, already-excluded `TURNURL`, regardless of `selection.Candidate.Mode` (`transport_webrtc.go`: `ForceRelay` sets `webrtc.ICETransportPolicyRelay` at the ICE-agent level, independent of the pool's own direct/relay pairing choice). | Yes |
| `reality` | Late but pre-dial — the exit's dial address arrives only in the `Dial`-time signaling answer (`transport_reality.go`'s `Dial`/`answer`), so it is surfaced via `Config.OnUnderlayDial` and excluded on the dial path, before the underlay connection opens (issue #109; `poolroutes.go`, ADR-0028's amendment). | Yes — the `OnUnderlayDial` handler is the structural gate |

**Update (#109):** reality was originally webrtc-only-excluded here because its
address couldn't be excluded in advance. That gap is closed: `connect()` wires
`Config.OnUnderlayDial` to a `poolExcluder` (`poolroutes.go`) that excludes and
allow-lists the reality underlay *before* it is dialled — on bring-up and, by
firing on the dial path rather than after the pool commits, on a mid-session
failover too. `allowedPoolTransports` now includes `reality` precisely because
that handler is always present; a transport the client couldn't make tunnel-safe
this way would still be filtered out.

`sanitizePoolOrder` runs in two places: when the settings window saves
(`settings.go`), and again in `connect()` (`main.go`) immediately before
building `core.Config`. It now keeps both `webrtc` and `reality`, still dropping
only genuinely unknown or duplicate entries, so a hand-edited
`bacchus.config.json` ladder is normalized the same way the UI's is.

## Manual smoke test performed

`clients/windows`'s own convention (`main_test.go` et al.) is that
OS/UI-integration glue is verified manually, not left as an automated test —
this branch followed that: a throwaway test file built both dialogs' full
widget trees (not simplified stand-ins) through the real `runOnUIThread`
worker, sequentially with a realistic gap, exercised the same imperative
calls the real Save/Generate handlers make (`ListBox.SetModel`,
`ComboBox.SetCurrentIndex`, `canonicalizeInvite` → `inviteQRImage` →
`walk.NewBitmapFromImage` → `ImageView.SetImage`) against the live HWNDs, and
was deleted once it passed. `go build`/`go vet`/`gofmt`/`go test ./...` are
clean; the throwaway harness is not part of the committed diff.
