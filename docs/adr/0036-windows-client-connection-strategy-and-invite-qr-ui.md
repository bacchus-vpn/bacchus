# 36. Windows client gets a real GUI (lxn/walk) for connection-strategy settings and invite QR display

- Status: accepted
- Date: 2026-07-10

## Context

Two client-side follow-ups had been waiting on `clients/windows` gaining any
UI beyond a systray menu:

- **#75** (follow-up to #15/ADR-0028): core's transport pool exposes a real
  config surface — `Config.Geo`, `Config.ExitID`, `Config.TransportPool`,
  `Config.SelectionDir`, `Engine.ResetSelection()` — with zero callers. The
  ask was to surface it: a geo picker, a manual exit pin, transport-ladder
  reordering, a node-count control, a reset button.
- **#32**: `cmd/coldstart-issue` prints a `bacchus1:…` invite string an
  operator hands a new user out of band; turning that string into a
  scannable QR image was flagged as "a small, separable UI task" in
  `docs/design/bootstrap-protocol.md`.

Both need real widgets — text input, a reorderable list, an image. `clients/
windows` had none of that: `getlantern/systray` (its only UI dependency) is
menu-only, no forms, no images. Every prior client feature (exit picking,
split-tunnel config, kill-switch) either used the tray menu directly or was
JSON-file-configured with no in-app editor — the README says as much ("v0 —
rebuilt properly later (real settings UI...)").

Three ways to get a real window, weighed against this client's specifics —
it already runs elevated (Administrator, for the TUN adapter and routes) and
owns a fail-closed kill-switch:

1. **A cgo webview** (the pattern `getlantern/systray`'s own examples use):
   HTML/CSS/JS in an embedded native control. Rejected — it would be this
   repo's first-ever cgo dependency, meaning every future build of the
   Windows client needs a C toolchain, not just `go build`, complicating the
   eventual code-signed release pipeline the README already flags as v0 debt.
2. **A local HTTP server + the default browser**: stdlib-only, trivial image
   embedding, easy to unit-test. Rejected for *this* client specifically —
   binding a local listener from an always-elevated, firewall-controlling
   process is a new attack-surface category worth not taking on lightly, even
   with 127.0.0.1-only binding and a per-launch token. (Nothing here rules
   this pattern out for a *different*, non-elevated Bacchus surface later.)
3. **`lxn/walk`**: a pure-Go (no cgo, syscall-based) native Win32 GUI
   toolkit, via its `declarative` sub-package. No new listening socket. Its
   one real cost, weighed explicitly: the repo's `go.sum` already carried a
   dangling, never-fetched reference to it from January 2021, and `go get
   github.com/lxn/walk@latest` resolves to that exact five-and-a-half-year-old
   commit — there is no evidence of an actively maintained upstream. Chosen
   anyway: it compiles and vets clean against this repo's toolchain (go1.26.4),
   it's MIT/BSD-family licensed (compatible with this repo's AGPL-3.0), and
   for a client that must not grow a new local-network attack surface, a
   stale-but-functional native dependency was judged the better trade.

Two problems in `lxn/walk` itself surfaced only once dialogs were actually
built and *run* — not from reading its source or docs — which is the reason
this branch's PR includes a manual smoke-testing step, not just unit tests
(see docs/design/client-connection-ui.md for the full diagnostic trail):

- **A missing manifest breaks every widget.** The very first widget created
  in the very first dialog failed with `TTM_ADDTOOL failed`. Root cause:
  `lxn/walk` requires a Common Controls v6 manifest; without one, Windows
  loads the legacy v5 controls, whose `TOOLINFO` struct size doesn't match
  what walk's compiled-in `win.TOOLINFO` expects, and `TTM_ADDTOOL` rejects
  the mismatched `cbSize`. This is a known, documented `lxn/walk` requirement
  (confirmed against upstream issue reports), not a bug introduced here — but
  nothing in this client's existing build process ever needed a manifest
  before (`systray` doesn't touch themed common controls), so it was an easy
  gap to miss.
- **A second dialog, from a second thread, silently fails.** With the
  manifest fixed, each dialog worked *individually* — but the second one,
  created from its *own* freshly `LockOSThread`'d goroutine (the original
  design: one disposable thread per dialog open), failed `CreateWindowEx`
  outright. Manually probed and isolated (not guessed): identical dialog code
  succeeds every time when reused repeatedly on the *same* locked thread, and
  fails the moment a *second*, independently locked thread tries — regardless
  of whether the two dialogs are the same shape or different ones. `lxn/walk`
  only fully initializes its shared internal state (the dialog window class,
  common-controls setup) for the first thread that ever creates a walk window
  in the process. A per-dialog-thread design would have shipped working for
  exactly one dialog per app run and then silently broken on the second —
  every subsequent tray click on either new menu item, for the rest of that
  session.

## Decision

- **`clients/windows` adopts `lxn/walk` + `lxn/walk/declarative`** as its GUI
  toolkit for both features, plus `github.com/skip2/go-qrcode` (MIT, the most
  widely used pure-Go QR encoder) for #32. `bacchus.exe.manifest` ships in
  `clients/windows/`, next to the source — Windows loads a same-named
  `<exe>.manifest` automatically with no embedding/build-tool step, so
  building the existing way (`go build -o bacchus.exe .` from this directory)
  is sufficient.
- **Every walk window in this client is created on one persistent,
  lazily-started, OS-thread-locked worker goroutine** (`runOnUIThread` /
  `uiWorkerLoop`, `main.go`), never a fresh thread per dialog open. A tray
  click dispatches `go runOnUIThread(openXDialog)`; the worker itself is
  started once and serializes every dialog-open request onto the single
  thread walk actually works from.
- **#75's transport ladder is functionally restricted to `webrtc`** for this
  client. `reality` is still shown in the UI (so a user's preferred order is
  captured and ready), but `sanitizePoolOrder` strips it before it ever
  reaches `core.Config.TransportPool` — both when the settings window saves
  and again in `connect()`, so a hand-edited config can't smuggle it in
  either. Reason: `tunnel.go`'s route-exclusion (and therefore the
  kill-switch's leak protection) requires every session to transit a *known,
  fixed* address decided *before* the route flip. WebRTC gets this for free —
  `Config.ForceRelay: true` (already set, for the pre-existing single-
  transport path's identical reason) pins every WebRTC candidate's ICE policy
  to relay-only, so it always transits the one known TURN server regardless
  of which `selection.Candidate.Mode` the pool's ladder picks. `reality` has
  no equivalent: the exit's dial address is learned only at `Dial` time, over
  per-session coordinator signaling (`core/transport_reality.go`), so there is
  nothing fixed to pre-exclude. This is a real, pre-existing gap between the
  transport pool (core, #15/ADR-0028) and the full-device tunnel (client) —
  it was simply never reachable before, since no prior UI could turn the pool
  on for this client. Flagged as a follow-up (#109) rather than solved here:
  fixing it needs the pool to expose a live "this candidate just became
  active, here is its address" hook `tunnel.go` could act on, which is a
  core+client cross-cutting change beyond a `clients/windows`-only branch.

  > **Update (2026-07-11):** resolved by #109. The hook shipped as
  > `Config.OnUnderlayDial`, fired by the reality transport on the dial path
  > (before the underlay connection opens) rather than after the pool commits —
  > which is what also makes a mid-session failover leak-safe. `reality` is now
  > in `allowedPoolTransports`, so `sanitizePoolOrder` no longer strips it. See
  > ADR-0028's #109 amendment and `docs/design/client-connection-ui.md`.
  >
  > **Update (2026-07-11):** hardened further by #117 (stale gateway on a live
  > install, IPv6 exit exclusion, a lock narrowed across shell-outs plus the
  > orphaned-route self-reap that narrowing needed) — all fail-closed before
  > and after, non-blocking follow-ups from this review rather than a fix to
  > this ADR's decision. Full detail in ADR-0028's #117 amendment, not
  > repeated here since none of it changes this client's UI or its
  > `allowedPoolTransports` gate.
- **A manual exit-ID pin turns the pool off** for that connect, rather than
  restricting pool selection to one exit. `core/pool.go`'s `poolExits` only
  falls back to `Config.ExitID` when the coordinator is unreachable — with a
  reachable coordinator and the pool on, a pin would be silently overridden
  by the pool's normal cross-exit selection. Turning the pool off is what
  actually makes the pin deterministic.
- **"Manual exit-IP entry" is a manual exit-*ID* pin**, using the same
  pubkey-hex id the tray picker already resolves through the coordinator's
  directory — not a raw `host:port` dial. Core has no such dial path (exits
  are only ever resolved by id, through the coordinator, never by a client-
  supplied address), and building one would mean bypassing the coordinator's
  admission/directory model from a `clients/windows`-only branch. **Node
  count** is likewise a disabled placeholder: no hop-count concept exists
  anywhere in core yet (`selection.Candidate.Mode` is a direct/relay binary,
  not a count), pending #76.
- **#32 is display-only for an already-minted invite.** The window takes a
  pasted `bacchus1:…` string, round-trips it through `coldstart.DecodeInvite`
  → `coldstart.EncodeInvite` to validate and canonicalize it (rejecting
  garbage and catching copy-paste whitespace), and renders the canonical
  string as a QR code. Minting a *new* invite needs `cmd/coldstart-issue`'s
  coordinator-filesystem access, which this client will never have; scanning
  a QR back into an invite (the bootstrap side) is a separate concern, out of
  scope here per the task that opened this branch.

## Consequences

- Both #75 and #32 are closed: a user can drive geo/manual-pin/ladder-order/
  reset without editing JSON by hand, and hand a QR code to a new user in
  person instead of a copy-pasted string.
- `clients/windows` has a real GUI toolkit for the first time, decided
  deliberately rather than defaulted into — future client UI work (the
  README's other v0 TODOs) has a established pattern to extend rather than a
  fresh toolkit decision to make.
- Accepted limits and named follow-ups:
  - **`lxn/walk` is unmaintained upstream.** Functional and now proven
    correct on this repo's toolchain + this manifest + the single-worker-
    thread pattern, but a future Windows/comctl32 change could reintroduce a
    variant of either bug this ADR documents with no upstream fix to pull.
    Revisit if that happens; the localhost-HTTP option (rejected above on
    attack-surface grounds, not capability) remains the fallback.
  - **The pool is `webrtc`-only for this client** until tunnel.go can learn a
    winning candidate's address late and exclude it dynamically — tracked as
    #109. Until then, `reality` stays visible-but-inert in the ladder UI.
  - **No raw-IP manual dial and no node-count**, both because the backing
    core API doesn't exist yet (the latter tracked as #76). Both are
    documented in-UI (a tooltip and a disabled label, respectively) rather
    than silently omitted.
  - **QR size is unbounded by this UI.** A v3 invite (issue #69's CRL
    attached) can be large; `qrcode.Encode` is left to return its own error
    for anything past what a QR code can represent rather than this window
    pre-validating a size budget. Not observed in practice (CRLs are meant to
    be short — see `core/admission.CRL`), flagged rather than solved.

## Amendment (issues #6, #28, 2026-07-28): node-count wired; the geo picker removed

Two changes to the "Connection settings" window this ADR designed, from a followup
review of the leftover surfaces country-only exit assignment (issue #146, predating
this ADR) left behind. Neither reopens the toolkit or transport-pool decisions above.

**Node count (issue #28).** §"Consequences" above named this a disabled placeholder
because "no hop-count concept exists anywhere in core yet." It does now — issue #142
shipped `Config.RelayHops`/`RelayHopsMax` — so the `NumberEdit` this ADR's PR left at
a fixed `1` with a `-issue #76` tooltip is real: `MinValue`/`MaxValue` span
`[1, core.RelayHopsMax]`, and saving it validates (`validateRelayChainConfig`, the
same shape as `validateAdmissionConfig`, issue #130's precedent) that 2+ hops carries
a relay directory file and its verification key, both new fields on the same window
— chaining needs a directory to select hops from (docs/design/relay-chaining.md §10.1),
so the control cannot be offered without one. `connect()` reads the file fresh at
every connect and, since issue #27, keeps it fresh for the rest of a long session by
also passing `RelayDirectoryPath` through — see that issue's ADR-0038 amendment. The
trade is stated in-window rather than left implicit: more hops is harder to link but
slower and costs more volunteer bandwidth, and — because chaining is deliberately
fail-closed (core/relaychain.go's file doc) — a chain that cannot be built fails the
connection outright, which `eventStatus` (`main.go`) now says in those words rather
than folding it into a generic `"Error: ..."` line indistinguishable from a transient
one (issue #28's own text: a user who retries into the same directory gap deserves to
know retrying won't help).

**The geo picker is gone, not merely left inert (issue #6).** This ADR's own PR added
a "Preferred geo" `ComboBox` to the same "Exit selection" group as the manual exit-ID
pin. It was never wired to anything `connect()` reads — `Config.Geo` (core) is set
from the tray's country picker alone (`currentCountryLabel`), a fact unrelated to
this ADR's decisions and predating them slightly (the tray picker is older). Rather
than retrofit a precedence rule between two controls that name the same thing, the
Settings copy was removed: `geoOptions`/`geoAny` (this window's own helpers) are gone,
`clients/windows/config.go`'s `Config` carries no `Geo` field, and the tray is
documented as the sole selector (`clients/windows/README.md`'s "Connection settings"
section). The manual exit-ID `LineEdit` alongside it stays, but disabled and
relabeled: naming a specific exit was removed for everyone by #146, `connect()` has
logged and ignored a saved pin since, and a live-but-inert text box next to a
newly-live hop-count control would read as "this one still does something."
