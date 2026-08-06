// One Bacchus client per machine (bacchus#185).
//
// Nothing declared a single instance, and on a Windows hardware pass three
// clients ran at once before anybody noticed. That is not untidy, it is unsafe:
// the kill-switch bookkeeping is machine-wide and has no ownership check, so the
// FIRST client to disconnect disarms the SECOND client's kill-switch while it is
// still connected and still reporting Protected — profiles back at
// DefaultOutboundAction=Allow with no allow rules, which is precisely the state
// the kill-switch exists to make impossible.
//
// The fix is arbitration, not ownership tracking. See ADR-0058 for why:
// enforcement's disableKillSwitch and removeKillSwitchRules delete
// Remove-NetFirewallRule -Group "BacchusKillSwitch", which cannot delete only
// its own rules, and teaching them to would not help — the loss happens at
// recoverKillSwitch, before the second client has any rules to own.
//
// # What "held" means
//
// Both implementations use a primitive the KERNEL releases when the process
// dies, and that is the load-bearing property rather than a detail:
//
//   - Windows: a named mutex. The handle is closed by the OS on process exit,
//     however the process ended.
//   - Linux: an exclusive flock on a lock file. The lock goes with the open
//     file description, which the kernel closes on exit.
//
// A PID file would have neither property, and this client's most likely
// abnormal exit is exactly the one a PID file handles worst — bacchus#115
// established that a KILLED client leaves the firewall holding a block, so the
// next launch is the one that has to clean up. A guard that refused to start
// after a crash would turn a recoverable state into an unrecoverable one.
//
// # The installer half
//
// deploy/windows/bacchus.iss declares AppMutex over the same names. Until it
// did, the uninstaller ran straight through a running client and left the
// install directory holding a locked exe. The names must be identical in both
// places and there is nothing in either file that would notice if they drifted,
// so deploy/windows/appmutex_test.go asserts it — the .iss is not Go, is not
// compiled by anything on Linux, and is exactly the kind of file where a
// rename lands on one side only.
package singleinstance

import "errors"

// ErrAlreadyRunning is Acquire's refusal: another Bacchus client already holds
// the machine. It is not an error condition to be logged and stepped over — the
// caller must not go on to arm anything.
var ErrAlreadyRunning = errors.New("Bacchus is already running on this computer")

const (
	// GlobalMutexName is the Windows name in the global kernel namespace, so
	// the guard spans terminal-server sessions. That matters here rather than
	// being thoroughness: the kill-switch is
	// Set-NetFirewallProfile -All -DefaultOutboundAction Block, which is
	// machine-wide, so two clients under two logged-in accounts collide exactly
	// as two under one do. A session-scoped guard would leave the worst version
	// of #185 — two different people, neither able to see the other's client —
	// completely unguarded.
	GlobalMutexName = `Global\BacchusVpnClient`

	// SessionMutexName is the fallback. Creating a name in Global\ needs
	// SeCreateGlobalPrivilege, which this client holds because its manifest
	// requires administrator — but "the guard could not be created" must not be
	// the reason a VPN client refuses to start, so a failure there falls back to
	// the session namespace and covers the ordinary single-account machine.
	//
	// Both are created, and bacchus.iss names both, so the installer finds
	// whichever one exists.
	SessionMutexName = `BacchusVpnClient`

	// LockFileName is the Linux lock, kept in the same per-user directory as
	// the config, the device identity and the log. Per-user rather than
	// per-machine is the honest scope there: ADR-0049 puts Linux enforcement
	// behind a root helper with its own arbitration, and whether two clients
	// under two accounts can both drive that helper is bacchus#185's explicitly
	// unanswered question rather than something to guess at here.
	LockFileName = "client.lock"
)

// Acquire claims this machine's single client slot, returning a release
// function to be deferred for the life of the process.
//
// dir is the per-user directory the client keeps its files in
// (clientlog.DefaultDir); it is used only by the implementations that need a
// path, and may be empty.
//
// Three outcomes, and the caller must tell them apart:
//
//   - nil error: this process holds the slot.
//   - ErrAlreadyRunning: another client holds it. Say so and exit; do NOT
//     connect, and do not arm anything.
//   - any other error: the guard could not be established, so whether another
//     client is running is UNKNOWN. See main.go for what it does with that.
func Acquire(dir string) (release func(), err error) {
	return acquire(dir)
}
