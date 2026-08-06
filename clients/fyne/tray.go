// The system tray, and what the window's close button now means (bacchus#186).
//
// Before this, closing the window disconnected the VPN and exited. There was no
// tray, so there was no way to get the client off the screen while staying
// protected — and `launchOnBoot` ships and works on Windows, so the intended
// flow was a client that starts at every login, connects, and then puts a
// window on screen the user cannot dismiss without dropping their tunnel. A
// feature that exists to make the client unobtrusive guaranteed the opposite.
//
// The capability was not missing, it was LOST: the retired clients/windows had
// a tray (bacchus#138 deleted it), and enforcement/routes_windows.go still
// reasons about it in a live comment. This is that surface back, on both 1.0
// platforms rather than only one.
//
// # X hides, Quit disconnects
//
// The disconnect did not move off the close button because it was wrong — it
// moved because "close a window" is the wrong gesture to hang it on. The
// teardown itself is load-bearing and is kept, in the same order, on the QUIT
// path: bacchus#115 established that a client which goes away without lifting
// the kill-switch leaves the machine with the firewall holding a block and
// nothing left to lift it.
//
// What DID change about the teardown is that it is now waited for. See
// appstate.Controller.DisconnectAndWait: the old `ctrl.Disconnect(); w.Close()`
// pairing looked like an ordering guarantee and was a race, because Disconnect
// spawns a goroutine and returns immediately while w.Close() takes the last
// window down and exits the process.
//
// # Where there is no tray
//
// internal/tray answers that before any of this is built, and where the answer
// is no the close button keeps its pre-#186 behaviour. Hiding a window into a
// machine that cannot show an icon would leave a running client with no surface
// at all — tunnel up, kill-switch armed, reachable only through the process
// list, where killing it is exactly #115's stranded machine.
//
// Belt and braces on top of that: the File menu carries its own Quit, wired to
// the same action as the tray's, so the window is never the only way to end the
// session even on a machine where the tray was there at startup and its panel
// has since died.
package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// appIconSVG is the client's icon: the window's on Linux, and the tray's on
// both platforms.
//
// It is a source literal rather than a file because it has exactly one consumer
// and adding an embedded asset directory for 300 bytes of path data buys
// nothing. Fyne rasterises it to a PNG for the tray on every platform except
// macOS (gLDriver.SetSystemTrayIcon), so the SVG is the only form needed.
//
// The colour is the theme's primary in its dark-variant tone, which is the one
// of the two that stays legible against both a light and a dark notification
// area — a tray icon is drawn on the panel's background, not the app's, and the
// client cannot know which that is. Without an icon set at all, Fyne falls back
// to theme.BrokenImageIcon: a broken-image glyph, permanently, in the tray of a
// security tool.
const appIconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` +
	`<path fill="#5fa8c7" d="M12 1.5 3.5 4.6v6.7c0 5.2 3.6 10 8.5 11.2 4.9-1.2 8.5-6 8.5-11.2V4.6L12 1.5z"/>` +
	`<path fill="#ffffff" d="m10.6 15.4-3.2-3.2 1.4-1.4 1.8 1.8 4.6-4.6 1.4 1.4-6 6z"/>` +
	`</svg>`

// appIcon is what a.SetIcon and the tray are given.
func appIcon() fyne.Resource {
	return fyne.NewStaticResource("bacchus.svg", []byte(appIconSVG))
}

// trayMenu is the tray's menu and the handful of items whose text changes.
//
// The state item is the reason the tray is worth having at all rather than just
// a way to hide a window: it makes the main window genuinely optional, because
// the one thing a user opens this app to find out — am I protected — is legible
// without opening it.
type trayMenu struct {
	menu   *fyne.Menu
	state  *fyne.MenuItem
	action *fyne.MenuItem
	ctrl   *appstate.Controller

	// refresh pushes the mutated items back to the OS. Injected so the menu's
	// behaviour can be driven in a test without a system tray: fyne.Menu.Refresh
	// reaches through CurrentApp() to a driver that has one.
	refresh func()
}

// newTrayMenu builds the menu. show raises the main window; quit is the real
// exit, shared with the File menu's own Quit item.
//
// The state item is Disabled, which in a tray menu is how "this is a readout,
// not a control" is said. It is deliberately first: a tray menu is read
// top-down and the answer belongs above the actions, not under them.
func newTrayMenu(ctrl *appstate.Controller, show, quit func()) *trayMenu {
	t := &trayMenu{
		state:  &fyne.MenuItem{Label: stateHeadline(appstate.Disconnected, false), Disabled: true},
		action: fyne.NewMenuItem(lang.L("Connect"), ctrl.Connect),
		ctrl:   ctrl,
	}
	showItem := fyne.NewMenuItem(lang.L("Show Bacchus"), show)
	// IsQuit, and with an Action of our own. Both halves matter: Fyne APPENDS a
	// Quit item to any tray menu whose last entry is not one (see
	// addMissingQuitForMenu), and the item it appends calls the driver's Quit
	// directly — exiting the process with the tunnel up and the kill-switch
	// armed. Claiming the slot is what stops that.
	quitItem := &fyne.MenuItem{Label: lang.L("Quit"), Action: quit, IsQuit: true}

	t.menu = fyne.NewMenu(appName,
		t.state,
		fyne.NewMenuItemSeparator(),
		t.action,
		showItem,
		fyne.NewMenuItemSeparator(),
		quitItem,
	)
	t.refresh = t.menu.Refresh
	return t
}

// update repaints the menu for state s. Must be called from the Fyne UI
// goroutine — main.go's OnState callback already is, via fyne.Do.
//
// The action item mirrors applyButtonState's rule exactly rather than having
// its own: "the one thing you can do right now", never two competing controls.
// A tray offering Connect while the window's button says Disconnect would be
// the same app disagreeing with itself about whether the user is protected,
// which is the failure ui.go's whole doc is about.
func (t *trayMenu) update(s appstate.ConnState, enforced bool) {
	t.state.Label = stateHeadline(s, enforced)
	switch s {
	case appstate.Connecting:
		t.action.Label = lang.L("Connecting…")
		t.action.Action = nil
		t.action.Disabled = true
	case appstate.Protected, appstate.Blocked:
		t.action.Label = lang.L("Disconnect")
		t.action.Action = t.ctrl.Disconnect
		t.action.Disabled = false
	default:
		t.action.Label = lang.L("Connect")
		t.action.Action = t.ctrl.Connect
		t.action.Disabled = false
	}
	if t.refresh != nil {
		t.refresh()
	}
}

// showTrayNotice is the once-per-run explanation of what the close button now
// does, shown BEFORE the window goes away.
//
// A user who closes a window and finds the process still running goes looking
// for a leak, and after the hide there is no surface left to tell them
// anything. So it is said while there is still a window to say it in.
//
// Built out of widget rather than through fyne.io/fyne/v2/dialog on purpose:
// that package pulls a file-browser dependency this module does not otherwise
// carry, for one information box. It is also deliberately NOT an OS
// notification — Fyne's SendNotification on Windows writes a temporary
// PowerShell script and runs it without CREATE_NO_WINDOW, so a client built
// -H=windowsgui would flash a console window and leave a script in %TEMP%,
// which is a poor trade for a sentence in a product whose users care what it
// leaves behind.
func showTrayNotice(w fyne.Window) {
	message := widget.NewLabel(lang.L("Closing this window leaves Bacchus running in the notification area, so your connection stays up. To disconnect and quit, use Quit in the tray menu or in the File menu."))
	message.Wrapping = fyne.TextWrapWord

	var pop *widget.PopUp
	ok := widget.NewButton(lang.L("OK"), func() {
		pop.Hide()
		w.Hide()
	})
	body := container.NewBorder(nil, ok, nil, nil, message)
	// A definite width, because a wrapping Label's minimum size is one long
	// line: without this the popup is as wide as the sentence and runs off the
	// screen.
	pop = widget.NewModalPopUp(container.NewGridWrap(fyne.NewSize(340, 140), body), w.Canvas())
	pop.Show()
}

// quitAction is what Quit means, from the tray or from the File menu.
//
// The order is the whole content of this function, and it is the half of
// bacchus#186 that has to be right or the card makes things worse:
//
//  1. hide, synchronously. The user asked to quit, and a window sitting there
//     for the length of a teardown looks like the click did nothing.
//  2. disconnect, on a goroutine, and WAIT for it. This is the step the old
//     close button appeared to take and did not: Controller.Disconnect returns
//     immediately, so `ctrl.Disconnect(); w.Close()` raced the process exit
//     against the kill-switch being lifted. Losing that race is bacchus#115's
//     stranded machine.
//  3. exit, only then.
//
// The goroutine is not tidiness either. The teardown takes as long as an engine
// stop takes and publishes state changes that land back on the UI goroutine, so
// running it there would block the thread it is handing work to.
//
// disconnect and exit are functions rather than a Controller and an App so that
// the ordering above is assertable without a window system — see tray_test.go.
// main.go is where they are bound, and where exit carries the fyne.Do that
// touching the app from a goroutine requires.
func quitAction(disconnect, hide, exit func()) func() {
	return func() {
		hide()
		go func() {
			disconnect()
			exit()
		}()
	}
}
