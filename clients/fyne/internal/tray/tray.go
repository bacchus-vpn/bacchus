// Whether this machine can show a system tray icon (bacchus#186).
//
// The client needs this answer BEFORE it decides what the window's close button
// does, and Fyne cannot supply it. desktop.App.SetSystemTrayMenu returns
// nothing, and on Linux fyne.io/systray fails soft all the way down: a missing
// session bus, a bus with no StatusNotifierWatcher on it, and a watcher with no
// host attached all produce a log line and a running program with no icon
// anywhere. There is no error to check and no callback that says "no".
//
// That matters because the wrong answer is not cosmetic. Hiding the window on
// close, on a machine with no tray, leaves a running client with no surface at
// all: the tunnel is up, the kill-switch is armed, and the only way to reach it
// is the process list — where killing it is exactly bacchus#115's stranded
// machine, firewall still holding the block. So the close gesture is decided by
// this package, and where the answer is "no" the client keeps the behaviour it
// has always had (disconnect and exit) rather than hiding into nothing.
//
// # Why the Linux answer is a bus query and not a guess
//
// The StatusNotifierItem host is the thing that actually draws the icon, and it
// is optional: KDE, XFCE and Cinnamon ship one, and a stock GNOME session has
// none unless an extension provides it. Guessing from XDG_CURRENT_DESKTOP would
// be wrong for every user who installed or removed such an extension, and both
// directions of wrong are bad — a false yes hides the window into nothing, a
// false no keeps #186 unfixed for somebody whose desktop is fine.
//
// The query asked here is the same one fyne.io/systray's own registration makes
// (org.kde.StatusNotifierWatcher at /StatusNotifierWatcher), so this reports on
// the mechanism that will actually be used rather than on a proxy for it.
package tray

// Available reports whether a system tray icon put on this machine will be
// visible to the user.
//
// It is a snapshot, not a subscription: a panel that dies after this returns
// takes the icon with it and nothing here notices. That residual case is why
// the client's File menu keeps a Quit item and why the tray is never the only
// way to reach a hidden window — see clients/fyne/tray.go.
//
// Never blocks for long: every implementation that can block is bounded by
// ProbeTimeout, and a probe that times out answers no.
func Available() bool {
	return available()
}
