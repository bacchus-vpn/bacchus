// The tray surface and the quit ordering (bacchus#186).
//
// ADR-0039's split puts logic in internal/appstate, where a unit test can reach
// it without a GUI toolchain. What is here is what genuinely lives in this
// package: the SHAPE of a *fyne.Menu (plain structs, no display needed) and the
// order quitAction does three things in. Both are one line away from being
// wrong in ways that produce no error anywhere.
package main

import (
	"sync"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// newTestTray builds a tray menu against Fyne's software driver, so
// fyne.Menu.Refresh — which reaches through CurrentApp() — has something to
// talk to.
func newTestTray(t *testing.T) (*trayMenu, *appstate.Controller, *int, *int) {
	t.Helper()
	test.NewApp()
	t.Cleanup(func() { test.NewApp() })

	shows, quits := 0, 0
	ctrl := appstate.NewController(appstate.Config{})
	return newTrayMenu(ctrl, func() { shows++ }, func() { quits++ }), ctrl, &shows, &quits
}

// TestTrayQuitClaimsTheQuitSlot is the assertion that keeps Fyne from wiring
// the exit itself.
//
// glfw's addMissingQuitForMenu appends its own Quit item to any tray menu whose
// LAST entry is not one, and the item it appends calls the driver's Quit
// directly — taking the process down with the tunnel up, the routes in place
// and the kill-switch armed, which is bacchus#115's stranded machine arriving
// through a menu nobody wrote.
//
// Mutation check: drop IsQuit from the item in newTrayMenu, or move it out of
// last place, and this goes red.
func TestTrayQuitClaimsTheQuitSlot(t *testing.T) {
	tr, _, _, quits := newTestTray(t)

	last := tr.menu.Items[len(tr.menu.Items)-1]
	if !last.IsQuit {
		t.Fatal("the last tray item is not IsQuit, so Fyne will append a Quit of its own that skips the teardown")
	}
	if last.Action == nil {
		t.Fatal("the tray's Quit has no action, so Fyne fills it in with the driver's own — which does not disconnect")
	}
	last.Action()
	if *quits != 1 {
		t.Errorf("the tray's Quit ran the client's quit %d times, want 1", *quits)
	}
}

// TestTrayShowIsReachable covers the escape hatch. Once closing hides the
// window, this menu item is how it comes back.
func TestTrayShowIsReachable(t *testing.T) {
	tr, _, shows, _ := newTestTray(t)

	var found *fyne.MenuItem
	for _, i := range tr.menu.Items {
		if i.Label == "Show Bacchus" {
			found = i
		}
	}
	if found == nil {
		t.Fatal("the tray has no way to bring the window back")
	}
	if found.Disabled {
		t.Error("the show item is disabled")
	}
	found.Action()
	if *shows != 1 {
		t.Errorf("the show item raised the window %d times, want 1", *shows)
	}
}

// TestTrayStateMirrorsTheButton is the consistency rule.
//
// A tray offering Connect while the window's button says Disconnect is the same
// app disagreeing with itself about whether the user is protected, in the one
// product where believing a false answer is the risk. The two are asserted
// against each other rather than against literals, so they cannot drift apart
// by either side being changed.
//
// Mutation check: change any branch of trayMenu.update and this names the state
// whose two surfaces stopped agreeing.
func TestTrayStateMirrorsTheButton(t *testing.T) {
	tr, ctrl, _, _ := newTestTray(t)
	button := widget.NewButton("", nil)

	for _, s := range []appstate.ConnState{
		appstate.Disconnected,
		appstate.Connecting,
		appstate.Protected,
		appstate.Blocked,
	} {
		applyButtonState(button, ctrl, s)
		tr.update(s, false)

		if tr.action.Label != button.Text {
			t.Errorf("state %v: tray action says %q, button says %q", s, tr.action.Label, button.Text)
		}
		if tr.action.Disabled != button.Disabled() {
			t.Errorf("state %v: tray action disabled=%v, button disabled=%v", s, tr.action.Disabled, button.Disabled())
		}
		if want := stateHeadline(s, false); tr.state.Label != want {
			t.Errorf("state %v: tray readout says %q, the window's headline says %q", s, tr.state.Label, want)
		}
		if !tr.state.Disabled {
			t.Errorf("state %v: the tray's state readout is clickable — it is a readout, not a control", s)
		}
	}
}

// TestTrayRefreshesAfterEveryUpdate: a mutated *fyne.MenuItem is invisible to
// the OS until the menu is pushed back to it, so a state change that skipped
// the refresh would leave a tray permanently reading whatever it read at
// startup — the failure being fixed here, wearing a new hat.
func TestTrayRefreshesAfterEveryUpdate(t *testing.T) {
	tr, _, _, _ := newTestTray(t)
	refreshes := 0
	tr.refresh = func() { refreshes++ }

	tr.update(appstate.Protected, true)
	tr.update(appstate.Disconnected, true)
	if refreshes != 2 {
		t.Errorf("the menu was pushed to the OS %d times over 2 updates", refreshes)
	}
}

// TestQuitOrdering is bacchus#186's load-bearing half.
//
// The window has to go away first (or the click looks inert), the teardown has
// to COMPLETE before the exit (or the process can die mid-disconnect, which
// `ctrl.Disconnect(); w.Close()` left entirely to chance), and the exit has to
// happen at all (or Quit hangs the app with no window).
//
// Mutation check: swap the two calls inside the goroutine, or move disconnect
// out of it and drop the wait, and this names the step that ran out of order.
func TestQuitOrdering(t *testing.T) {
	var (
		mu    sync.Mutex
		order []string
	)
	note := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	done := make(chan struct{})
	quit := quitAction(
		func() { note("disconnect") },
		func() { note("hide") },
		func() { note("exit"); close(done) },
	)
	quit()
	<-done

	mu.Lock()
	defer mu.Unlock()
	want := []string{"hide", "disconnect", "exit"}
	if len(order) != len(want) {
		t.Fatalf("quit ran %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("quit ran %v, want %v", order, want)
		}
	}
}

// TestQuitDoesNotBlockTheCaller: the quit action is invoked from the Fyne UI
// goroutine (a menu action, a close intercept), and the teardown it waits for
// publishes state changes back to that same goroutine. Running the wait inline
// would be a client that appears to freeze on Quit, and on the platforms where
// enforcement has real work to undo it would freeze for as long as that takes.
func TestQuitDoesNotBlockTheCaller(t *testing.T) {
	release := make(chan struct{})
	finished := make(chan struct{})
	quit := quitAction(
		func() { <-release },
		func() {},
		func() { close(finished) },
	)

	quit() // must return while disconnect is still blocked
	select {
	case <-finished:
		t.Fatal("exit ran before the teardown was released")
	default:
	}
	close(release)
	<-finished
}
