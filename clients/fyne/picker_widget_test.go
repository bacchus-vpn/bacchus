// The picker as a live widget, driven through Fyne's own software test driver.
//
// picker_test.go covers the rendering decisions as pure functions, which is
// where ADR-0039 says the logic belongs. What it cannot reach is the two
// behaviours that only exist once there is a real widget.List underneath:
//
//   - widget.List.Select fires OnSelected, so re-applying the picker's own
//     selection after every refresh looks exactly like the user re-choosing.
//     Unguarded, that writes the config file once per refresh — silently, and
//     forever, since the app refreshes at launch and after every settings save.
//   - a choice made while a session is up must be refused rather than queued,
//     and the refusal is a callback that must NOT have run.
//
// Both are one boolean away from being wrong and neither is visible to a test
// of the pure functions, so they are driven here instead.
package main

import (
	"errors"
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
	"github.com/bacchus-vpn/bacchus/core"
)

// newTestPicker builds a picker against Fyne's software driver, recording every
// choice that reached the persistence callback.
func newTestPicker(t *testing.T, chosen string) (*countryPicker, *[]string, *int) {
	t.Helper()
	test.NewApp()
	// Reset the global app afterwards so the next test starts from a clean one.
	t.Cleanup(func() { test.NewApp() })

	var chose []string
	refreshes := 0
	p := newCountryPicker(chosen,
		func() { refreshes++ },
		func(code string) error { chose = append(chose, code); return nil },
	)
	return p, &chose, &refreshes
}

// TestPickerDoesNotRewriteTheConfigOnEveryRefresh is the re-entrancy guard.
//
// Mutation check: delete the `applying` guard in applySelection (or the check at
// the top of OnSelected) and this goes red with one recorded choice per refresh.
func TestPickerDoesNotRewriteTheConfigOnEveryRefresh(t *testing.T) {
	p, chose, _ := newTestPicker(t, "DE")

	for i := 0; i < 3; i++ {
		p.update(offered(
			core.CountryInfo{Country: "DE", Exits: 2, Available: 1},
			core.CountryInfo{Country: "NL", Exits: 1, Available: 0, Busy: true},
		))
	}
	if len(*chose) != 0 {
		t.Fatalf("a refresh wrote the config %d time(s) (%v) — the picker re-selecting its own row is not the user choosing", len(*chose), *chose)
	}
	if p.chosen != "DE" {
		t.Fatalf("chosen = %q after three refreshes, want DE", p.chosen)
	}
}

// TestPickerRecordsARealChoice is the other side of the same guard: with it in
// place, an actual selection must still get through.
func TestPickerRecordsARealChoice(t *testing.T) {
	p, chose, _ := newTestPicker(t, appstate.CountryAutomatic)
	p.update(offered(core.CountryInfo{Country: "DE", Exits: 2, Available: 2}))

	// Row 0 is Automatic, row 1 is DE.
	p.list.Select(1)
	if len(*chose) != 1 || (*chose)[0] != "DE" {
		t.Fatalf("choices = %v, want exactly one DE", *chose)
	}
	if p.chosen != "DE" {
		t.Fatalf("chosen = %q, want DE", p.chosen)
	}

	// And back to Automatic, which is a choice like any other.
	p.list.Select(0)
	if len(*chose) != 2 || (*chose)[1] != appstate.CountryAutomatic {
		t.Fatalf("choices = %v, want a second entry clearing the country", *chose)
	}
}

// TestPickerIsInertWhileConnected is the rule that keeps the heading from lying.
// core settles the country once per session, so a change accepted here would
// show one country while traffic left through another.
//
// Mutation check: drop the state check at the top of choose and this records a
// choice the running session will not honour.
func TestPickerIsInertWhileConnected(t *testing.T) {
	for _, state := range []appstate.ConnState{appstate.Connecting, appstate.Protected, appstate.Blocked} {
		p, chose, _ := newTestPicker(t, "DE")
		p.update(offered(
			core.CountryInfo{Country: "DE", Exits: 2, Available: 2},
			core.CountryInfo{Country: "NL", Exits: 2, Available: 2},
		))
		p.setConnState(state)

		p.list.Select(2) // NL
		if len(*chose) != 0 {
			t.Errorf("state %v: the picker accepted %v while a session was up", state, *chose)
		}
		if p.chosen != "DE" {
			t.Errorf("state %v: chosen moved to %q under a live session", state, p.chosen)
		}
		if p.status.Text == "" {
			t.Errorf("state %v: the picker refused the change and said nothing about why", state)
		}
	}
}

// TestPickerAcceptsChoicesAgainAfterDisconnect closes the obvious way to get the
// rule above wrong: latching.
func TestPickerAcceptsChoicesAgainAfterDisconnect(t *testing.T) {
	p, chose, _ := newTestPicker(t, "DE")
	p.update(offered(
		core.CountryInfo{Country: "DE", Exits: 2, Available: 2},
		core.CountryInfo{Country: "NL", Exits: 2, Available: 2},
	))
	p.setConnState(appstate.Protected)
	p.list.Select(2)
	p.setConnState(appstate.Disconnected)
	p.list.Select(2)

	if len(*chose) != 1 || (*chose)[0] != "NL" {
		t.Fatalf("choices = %v, want one NL once disconnected", *chose)
	}
}

// TestPickerShowsAFailedSaveAndKeepsTheChoice: the selection applies to this
// session either way, and a user who is not told will find it reverted at the
// next launch with no explanation.
func TestPickerShowsAFailedSaveAndKeepsTheChoice(t *testing.T) {
	test.NewApp()
	t.Cleanup(func() { test.NewApp() })
	p := newCountryPicker(appstate.CountryAutomatic, func() {},
		func(string) error { return errors.New("permission denied") })
	p.update(offered(core.CountryInfo{Country: "DE", Exits: 1, Available: 1}))

	p.list.Select(1)
	if p.chosen != "DE" {
		t.Fatalf("chosen = %q; a save that failed must not undo the choice for this session", p.chosen)
	}
	if p.status.Text == "" {
		t.Fatal("a save failure was swallowed")
	}
}

// TestPickerRefreshButtonIsWired is a small thing that is entirely invisible
// until somebody presses it: with no auto-refresh, this button is the only way a
// user updates the list.
func TestPickerRefreshButtonIsWired(t *testing.T) {
	p, _, refreshes := newTestPicker(t, appstate.CountryAutomatic)
	test.Tap(p.refresh)
	if *refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1", *refreshes)
	}

	// And it is the only thing stopping a user leaning on it from starting one
	// list engine per press: the Controller orders concurrent refreshes rather
	// than refusing them, so the button has to refuse instead.
	p.update(appstate.CountryListState{Loading: true})
	test.Tap(p.refresh)
	test.Tap(p.refresh)
	if *refreshes != 1 {
		t.Fatalf("refreshes = %d after two presses during a refresh, want 1", *refreshes)
	}
	p.update(offered(core.CountryInfo{Country: "DE", Exits: 1, Available: 1}))
	test.Tap(p.refresh)
	if *refreshes != 2 {
		t.Fatalf("refreshes = %d once the refresh finished, want 2 — the button latched off", *refreshes)
	}
}
