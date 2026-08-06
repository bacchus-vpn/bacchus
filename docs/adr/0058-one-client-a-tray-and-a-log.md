# 58. One client per machine, a tray to live in, and a log that reaches the disk

- Status: accepted (issues #185, #186, #187)
- Date: 2026-08-06

## Context

Three defects were found on a Windows hardware pass on 2026-08-05, while running
`#144`. They edit one file between them and share one subject: **the client as a
process somebody has to live with**, rather than as a screen.

None of them is visible to any test in this repository, and none of them is a
regression. Every one has been true since `clients/fyne` became the shipping
client.

**`#185` — nothing declares a single instance.** Three clients were running
simultaneously before anybody noticed. That is unsafe rather than untidy:
`enableKillSwitch` opens with `recoverKillSwitch`, whose job is to clear a stale
lockdown left by a crash. It cannot tell a crash from a peer. A second client
starting finds the first's marker, restores `DefaultOutboundAction=Allow` on all
three profiles and runs `Remove-NetFirewallRule -Group "BacchusKillSwitch"` —
taking the first client's allow rules with it — and then arms its own. When the
first client disconnects it reads whatever marker is present, which is now the
second's, restores `Allow`, and removes the group again. The second client is
left connected, routed, saying **Protected**, with the profiles at `Allow` and no
allow rules: precisely the state the kill-switch exists to make impossible. The
installer had the same hole from the other side — no `AppMutex`, so the
uninstaller ran straight through a running client and left the install directory
holding a locked exe.

**`#186` — closing the window disconnects the VPN.** There is no tray, so there
is no way to get the client off the screen while staying protected. `launchOnBoot`
ships and is implemented on Windows, so the intended flow is a client that starts
at every login, connects, and then puts a window on screen the user cannot dismiss
without dropping their tunnel. The capability was not missing but LOST: the
retired `clients/windows` had a tray, deleted in `d26a772`, and
`enforcement/routes_windows.go` still reasoned about it in a live comment.

**`#187` — a Windows user cannot produce a log at all.** `ctrl.Logf = log.Printf`
writes to `os.Stderr`; the shipping binary is linked `-H=windowsgui`, which gets
no console, so `os.Stderr` has no destination and every line is discarded.
`main.go` already documented this trap and routed exactly one message — the
config-parse error — around it. Nothing generalised it. Meanwhile the enforcement
package takes careful trouble to redact infrastructure addresses out of lines that
went nowhere, justified in its own comment by a `bacchus.log` that had not existed
since `#138`.

## Decision

### 1. One client per machine, arbitrated by a kernel-released primitive

`clients/fyne/internal/singleinstance` claims the machine before anything is armed
and before a window exists. Windows: named mutexes, `Global\BacchusVpnClient` with
`BacchusVpnClient` as the fallback where the global namespace is refused. Linux: an
exclusive non-blocking `flock` on `<config dir>/Bacchus/client.lock`.

Both primitives are released by the kernel when the process dies, by any route.
That is the property being bought, not a detail. `#115` established that this
software really does reach the killed-client state, and a guard that outlived the
process would turn a recoverable machine into one where Bacchus can never be
started again, recoverable only by deleting a file nobody has been told about.

`deploy/windows/bacchus.iss` declares both names in `AppMutex`, so Setup and
Uninstall refuse while a client is running.

### 2. Ownership checks in the kill-switch are NOT added

`disableKillSwitch` and `removeKillSwitchRules` delete by group, so they cannot
delete only their own rules. `#185` asks whether they should learn to — for
instance by putting an owner PID in the marker.

**Ruled: no, and the mutex is the whole answer.** Two reasons, and the second is
the one that settles it:

- The loss does not happen at `disableKillSwitch`. It happens at
  `recoverKillSwitch`, when the second client starts, *before* it has any rules
  to own. An ownership check on teardown would leave the second client's arming
  step still tearing down the first's.
- An ownership check would make `recoverKillSwitch` refuse to clear a marker
  belonging to a PID it does not recognise — which is exactly the crashed-client
  case that function exists for, since a crashed client's PID is gone. Making it
  stricter breaks the recovery it was written to perform.

The single-instance guard removes the situation instead of surviving it. It is
also the only mechanism that helps the installer, which is the other half of the
same card.

### 3. `CloseApplications=no` in the installer

Inno's default uses the Restart Manager, whose graceful close is a window-close
message. Since decision 4 that message HIDES this client rather than exiting it,
so the graceful path always fails and Inno falls back to terminating the process —
which is `#115`'s stranded machine, kill-switch armed with nothing left to lift it.

The refusal has to come from `AppMutex`, which asks the user to close the client
themselves and so routes them through the client's own Quit: the one path that
disarms the machine before the process goes away.

### 4. X hides, Quit disconnects — and Quit waits

The tray carries the current state (a disabled readout, first), Connect/Disconnect,
Show Bacchus, and Quit. `SetCloseIntercept` hides the window, saying once per run
that Bacchus is still running. Quit is the only gesture that ends the session, and
the File menu carries the same action.

The ordering `ctrl.Disconnect()` then `w.Close()` is kept in spirit and **fixed in
fact**. `Controller.Disconnect` spawns a goroutine and returns immediately, so the
old pairing was never the ordering guarantee `#186` describes it as: `w.Close()`
took the last window down, the driver exited the process, and whether the
kill-switch had been lifted first was a race. `Controller.DisconnectAndWait` is the
synchronous form, and quit runs it on a goroutine of its own — hide, then tear down
and wait, then exit.

Both menus declare their Quit item with `IsQuit`, because Fyne appends one of its
own to any menu that lacks it and the item it appends calls the driver's Quit
directly, skipping the teardown entirely.

### 5. Where there is no tray, the close button does not change

Fyne gives no answer here: `SetSystemTrayMenu` returns nothing, and on Linux
`fyne.io/systray` fails soft through a missing bus, a missing watcher and a missing
host alike. So `clients/fyne/internal/tray` asks the session bus directly, for the
same `org.kde.StatusNotifierWatcher` the tray itself registers with, and treats
every error and every timeout as no.

Where the answer is no, closing the window keeps its pre-`#186` behaviour. Hiding
a window into a machine that cannot show an icon would leave a running, connected,
kill-switched client with no surface at all — reachable only through the process
list, where killing it is `#115` again.

Guessing from `XDG_CURRENT_DESKTOP` was rejected: it is wrong for every user who
has added or removed a tray extension, and both directions of wrong are bad.

### 6. The log file is on by default, capped, and deletable

`clients/fyne/internal/clientlog` writes `bacchus.log` in the client's existing
per-user directory — `%APPDATA%\Bacchus\` and the XDG equivalent — installed as
`log.SetOutput`, capped at 256 KiB with one previous generation, with a Settings
control that turns it off **and deletes both files**.

On by default because the two failures it exists for (`#183`, `#137`) are silent:
the user does not know anything is wrong until connecting stops working, which is
exactly too late to have enabled logging. An opt-in log is a log that is off during
every failure it was built for. The forensic cost is answered by the cap, by the
redaction below, and by the off-and-delete control.

`log.SetOutput` rather than a sink handed to each writer, because two of the four
writers cannot be handed one: Fyne's own `fyne.LogError` and `fyne.io/systray`'s
tray errors go to the package logger, and those are precisely the ones that report
a tray failing to appear.

The XDG state directory is the more correct home for a log and was passed over. It
would be a third directory for a client that already keeps its config and its
device identity in one, and it would survive an uninstall that removes the other
two. Being deleted with everything else is worth more here than being filed
correctly.

### 7. The off-switch is a marker file, not a config key

`<config dir>/Bacchus/logging-off`. Its presence means off, so a machine that has
never been told anything logs.

A config key would make the log's existence depend on the file whose parse failure
is one of the things the log is for: an unparseable config leaves
`appstate.Config` at its zero value, so `"keepLog": true` would read as false at
exactly the launch where somebody needs it. Fyne's own preferences store was also
rejected — it lives outside `%APPDATA%\Bacchus`, so the uninstaller would leave it
behind, and this client should not create a new trace outside the directory it
already offers to remove.

The switch acts immediately rather than on Save, because turning it off deletes a
file, and a destructive action queued behind a button the user may never press —
on a window they may close with Cancel — is not the control they asked for.

### 8. The redaction bar, decided per writer, applied at the sink

Every line goes through `enforcement.RedactAddresses` (the existing `redactIPs`,
exported for this) and then through a home-directory substitution, at the sink,
whoever wrote it. Deciding it per writer and applying it per writer is how a writer
added next year ships without it.

The writers, enumerated, and what each may put in the file:

| Writer | What it writes | Bar |
| --- | --- | --- |
| `clients/fyne/main.go` | translations, config parse, country save, launch-on-boot | Go `os` errors quote paths; no config VALUES are logged |
| `appstate.Controller.logf` | country refresh, volunteer findings, enrollment outcomes, renewal outcomes | outcomes only — never a claim code, credential or device key |
| `clients/internal/enforcement` (via `Policy.Logf`) | bring-up/teardown progress, failing OS commands | already redacted at source, first line only; see `runPS` |
| `core/accountclient` (via `Config.Logf`) | its own diagnostics | its doc forbids claim codes, credentials, recovery tokens and device public keys |
| `fyne` / `fyne.io/systray` | `fyne.LogError`, tray registration failures | third-party; covered only by the sink, which is why the sink is where the bar lives |

Two findings from doing that enumeration are recorded because they change what the
file can be expected to contain:

- **`core`'s engine lines do not reach it.** `core/engine.go`'s `emit` falls back
  to `log.Println` only when `Config.OnEvent` is nil, and every `core.Config` this
  client constructs sets `OnEvent` — `Controller.connectAsync` and
  `FetchCountries` both. Core's events reach the state indicator and the detail
  line. The one exception is `version.Current`'s unstamped warning, which is a
  plain `log.Print` and now lands in the file, where it is useful.
- **`core/accountclient` has a `Logf` and no call sites.** The field is wired and
  documented and nothing ever calls `c.logf`. Nothing is lost today; it is listed
  above because the bar has to be decided before the first line is written, not
  after.

The home-directory substitution is new and belongs to the sink rather than to any
writer: every writer can emit a path, because Go's `os` errors quote the path they
failed on, and on both 1.0 platforms a per-user path contains the account name.
`C:\Users\<name>\...` in a file somebody is about to email to support is an
identifier they did not choose to send.

The **returned** error from `runPS` stays full and unredacted, and that exemption
was re-checked rather than carried over. It reaches exactly one place:
`Controller.abort` wraps it into a `Detail`, which `OnDetail` puts on the main
window's detail line. Nothing on that path writes it to the log.

## Consequences

- Two clients cannot be armed at once, and the uninstaller notices a running one.
  Upgrading now requires quitting the client first, which is correct — a running
  exe cannot be replaced — and is stated by Inno's own message.
- Closing the window leaves the tunnel up. That is a behaviour change users will
  meet without being told, which is what the once-per-run notice is for.
- A user who has never opened a terminal can find and send a log, and what is in
  it was decided per writer rather than inherited.
- `enforcement/routes_windows.go` and `addrs_test.go` describe things that exist
  again. Their `bacchus.log` premise was true, then was not, and is now.
- **Not verified on hardware.** The mutex, the `AppMutex` interlock, the tray and
  the log path are reasoned from the Windows API, Inno's documentation and Fyne's
  source. The name drift between the client and the installer is asserted by a
  test; the rest is on the hardware list.
- macOS is a stub in both new platform packages: no guard, no tray. Both are
  documented as stubs that stop being adequate the day `[E9]` gives it an
  `Enforcer`, because the failure otherwise is silent — everything compiles,
  everything runs, and two clients quietly share a lockdown.
