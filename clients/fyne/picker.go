// The country picker (issue #16) — the main window's centre, and the last v1
// client feature. A list of countries, each either free or busy; pick one and
// Connect. It is the only place in this app where the product's actual promise
// (you choose the jurisdiction you appear from) is expressed at all.
//
// # What it deliberately does not show
//
// No latency. core.CountryInfo carries PingMs, the coordinator never feeds it,
// and there is no honest client-side source — see
// internal/appstate/countries.go's package doc and ADR-0055 for what each
// candidate source costs. A blank is better than a plausible wrong number, which
// is the same call cmd/coordinator already made on its own side of the wire.
//
// No exit, no coordinator, no SOCKS. Those words appear nowhere a user can read
// them here, on purpose: this client speaks in countries, and everything below
// that is machinery a person choosing where to appear from should never have to
// learn. The one existing exception (the proxy address in the Proxy-ready
// description) is there because it is an instruction without which the tunnel is
// unusable at all — see ui.go.
//
// # What it does not compete with
//
// The state indicator above it is "the single most important widget in the app"
// (ui.go), and this must stay quieter than it: no colour band, no bar, no
// progress animation. A busy country is greyed (widget.LowImportance, which is
// theme.ColorNameDisabled, the same grey the Disconnected band uses) and says so
// in a word. The list is a list.
package main

import (
	"errors"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
	"github.com/bacchus-vpn/bacchus/core"
)

// countryRow is one line of the picker. The zero-code row is "Automatic", which
// is not a country and is not a fallback either — it is the choice to let the
// coordinator's first assignable country be used, exactly what this client did
// before it had a picker (see appstate.CountryAutomatic).
type countryRow struct {
	code   string
	label  string
	busy   bool
	absent bool // the chosen country, which the current list does not offer
}

// countryPicker owns the picker's widgets and the state needed to render them.
// Everything here runs on the Fyne UI goroutine — the callbacks that drive it
// come through fyne.Do in main.go, exactly like the state indicator's — so
// nothing needs a lock of its own.
type countryPicker struct {
	content fyne.CanvasObject

	list    *widget.List
	heading *widget.Label
	status  *widget.Label
	refresh *widget.Button

	rows   []countryRow
	chosen string // canonical code, or appstate.CountryAutomatic
	state  appstate.CountryListState
	conn   appstate.ConnState

	// applying suppresses OnSelected while the picker re-applies its own
	// selection after a rebuild. widget.List.Select fires the callback, so
	// without this every refresh would look like the user re-choosing — which
	// would write the config file once per refresh.
	applying bool

	// onChoose persists the choice and tells the Controller. It returns an error
	// when the choice could not be written to disk, which is shown rather than
	// swallowed: the selection is live for this session either way, and a user
	// who is not told will find it reverted at the next launch with no
	// explanation.
	onChoose func(code string) error

	// saveErr is the last failed save, cleared by the next successful choice or
	// the next refresh. Held rather than written straight to the status label so
	// a refresh landing a moment later cannot silently wipe it.
	saveErr error
}

func newCountryPicker(chosen string, onRefresh func(), onChoose func(string) error) *countryPicker {
	p := &countryPicker{
		chosen:   appstate.NormalizeCountry(chosen),
		onChoose: onChoose,
	}

	p.heading = widget.NewLabel("")
	p.heading.TextStyle = fyne.TextStyle{Bold: true}

	p.status = widget.NewLabel("")
	p.status.Wrapping = fyne.TextWrapWord

	p.list = widget.NewList(
		func() int { return len(p.rows) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, o fyne.CanvasObject) {
			if id < 0 || id >= len(p.rows) {
				return
			}
			row := p.rows[id]
			lbl := o.(*widget.Label)
			lbl.SetText(row.label)
			// Greyed rather than hidden or unselectable. Hidden would make a
			// country a user is looking for simply vanish, and unselectable would
			// take away their ability to insist on a jurisdiction and be told the
			// honest reason it did not work — which is the one thing core's
			// pickCountry refuses to trade away.
			if row.busy || row.absent {
				lbl.Importance = widget.LowImportance
			} else {
				lbl.Importance = widget.MediumImportance
			}
			lbl.Refresh()
		},
	)
	p.list.OnSelected = func(id widget.ListItemID) {
		if p.applying || id < 0 || id >= len(p.rows) {
			return
		}
		p.choose(p.rows[id].code)
	}

	// The only way the list is ever updated while the window is open. There is
	// no timer: a polled country list would mean a fixed-interval request to the
	// coordinator from every idle client, which is a load question and a
	// traffic-shape question, and this lane answers neither.
	p.refresh = widget.NewButton(lang.L("Refresh"), onRefresh)

	p.content = container.NewBorder(
		p.heading,
		container.NewVBox(p.status, p.refresh),
		nil, nil,
		p.list,
	)
	p.rebuild()
	return p
}

// choose applies the user's selection: record it, persist it, and repaint.
//
// A choice made while a session is up is REFUSED rather than queued. core
// settles the country once per engine (resolveCountry) so that a reconnect can
// never move a user to a different jurisdiction mid-session; a picker that
// accepted a change here would show one country while the traffic left through
// another, which is this app's worst failure in miniature. Saying "disconnect
// first" is the honest version and needs no state to get wrong.
func (p *countryPicker) choose(code string) {
	if p.conn != appstate.Disconnected {
		p.applySelection()
		p.status.SetText(lang.L("Disconnect first, then choose where to connect."))
		return
	}
	p.chosen = appstate.NormalizeCountry(code)
	p.saveErr = p.onChoose(p.chosen)
	p.rebuild()
}

// update repaints the picker for a fresh country list.
func (p *countryPicker) update(s appstate.CountryListState) {
	p.state = s
	if !s.Loading {
		p.saveErr = nil
	}
	p.rebuild()
}

// setConnState tells the picker whether choosing is currently allowed. It is
// driven from the same OnState callback the indicator is, so the two can never
// disagree about which state the app is in.
func (p *countryPicker) setConnState(s appstate.ConnState) {
	p.conn = s
	p.rebuild()
}

// rebuild recomputes the rows, the heading and the status line from the current
// list, choice and connection state, then re-applies the selection.
func (p *countryPicker) rebuild() {
	p.rows = buildCountryRows(p.state, p.chosen)
	p.heading.SetText(fmt.Sprintf(lang.L("Country: %s"), p.chosenLabel()))
	p.status.SetText(p.statusText())
	// The Controller orders concurrent refreshes rather than refusing them, so
	// this is what stops a user leaning on the button from starting one list
	// engine per press. It is also the honest feedback for a press that landed.
	if p.state.Loading {
		p.refresh.Disable()
	} else {
		p.refresh.Enable()
	}
	p.list.Refresh()
	p.applySelection()
}

// chosenLabel is the current choice as a user reads it in the heading.
func (p *countryPicker) chosenLabel() string {
	if p.chosen == appstate.CountryAutomatic {
		return lang.L("Automatic")
	}
	return p.chosen
}

// applySelection puts the highlight back on the chosen row without letting the
// List's own callback read it as a fresh choice.
func (p *countryPicker) applySelection() {
	p.applying = true
	defer func() { p.applying = false }()
	for i, row := range p.rows {
		if row.code == p.chosen {
			p.list.Select(i)
			return
		}
	}
	p.list.UnselectAll()
}

// statusText is the one sentence under the list. Ordered by what the user can
// act on: a setup step first, then what the app is doing, then what went wrong,
// then what is true of their own current choice.
func (p *countryPicker) statusText() string {
	if p.saveErr != nil {
		// Two sentences rather than one, because the two causes have different
		// fixes and only one of them is worth showing an OS error for. An
		// unreadable settings file is already named on the detail line and the
		// user's next step is to fix that file; a write that failed needs its
		// own errno, appended after a translated prefix exactly as settings.go's
		// own save failure does.
		if errors.Is(p.saveErr, errCountryConfigUnreadable) {
			return lang.L("Your choice applies now, but it could not be saved: the settings file could not be read.")
		}
		return lang.L("Your choice applies now, but it could not be saved:") + " " + p.saveErr.Error()
	}
	switch {
	case p.state.Loading:
		return lang.L("Looking for countries…")
	case p.state.Unconfigured:
		// Deliberately short, and it does not repeat the fix: pressing Connect
		// already names the file, the path and the key to put an address in
		// (appstate's noCoordinatorsError), and two half-instructions in
		// different words is worse than one complete one.
		return lang.L("Bacchus has no address to ask for a country list yet — press Connect to see what is missing.")
	case p.state.Err != nil:
		// The error itself goes to the log, not here. core's list errors name
		// coordinators and protocol dialects; what a user can do about any of
		// them is the same one thing.
		return lang.L("Could not reach Bacchus to get the country list. Check your internet connection, then press Refresh.")
	case p.state.Fetched && len(p.state.Countries) == 0:
		return lang.L("No countries are available right now. Press Refresh to try again.")
	}
	// Ordinary case: say something only when the user's own choice is one they
	// should know is in trouble BEFORE they press Connect. This is the whole
	// point of showing busy — the connect will be refused rather than quietly
	// sent somewhere else, so the warning has to arrive before the click.
	if p.chosen == appstate.CountryAutomatic || len(p.state.Countries) == 0 {
		return ""
	}
	switch appstate.StatusOf(p.chosen, p.state.Countries) {
	case appstate.CountryBusy:
		return fmt.Sprintf(lang.L("%s is busy right now, so connecting there will probably be refused. You can still try, or choose somewhere else."), p.chosen)
	case appstate.CountryNotOffered:
		return fmt.Sprintf(lang.L("%s is not on the list right now, so connecting there will probably be refused. You can still try, or choose somewhere else."), p.chosen)
	}
	return ""
}

// buildCountryRows turns a country list and the current choice into the rows the
// list renders. Automatic is always first; the chosen country is always present
// even when the coordinator did not offer it, so a user can always see and
// re-select their own choice — including with no list at all, which is what an
// unreachable coordinator leaves behind.
//
// Split out from the widget so it can be tested without a display driver, the
// same split ADR-0039 draws between this package and internal/appstate.
func buildCountryRows(s appstate.CountryListState, chosen string) []countryRow {
	rows := []countryRow{{
		code:  appstate.CountryAutomatic,
		label: lang.L("Automatic — Bacchus chooses for you"),
	}}
	found := chosen == appstate.CountryAutomatic
	for _, c := range s.Countries {
		code := appstate.NormalizeCountry(c.Country)
		if code == "" {
			// A country tag the coordinator sent that is not a country code.
			// Dropped rather than shown: it can never be connected to (core
			// canonicalizes it to nothing at the other end too), so a row for it
			// would be a choice that always fails.
			continue
		}
		if code == chosen {
			found = true
		}
		rows = append(rows, countryRow{code: code, label: countryRowLabel(c), busy: !c.Assignable()})
	}
	if !found {
		label := chosen
		if s.Fetched && len(s.Countries) > 0 {
			label = chosen + "  —  " + lang.L("not on the list")
		}
		rows = append(rows, countryRow{code: chosen, label: label, absent: true})
	}
	return rows
}

// countryRowLabel is one country's line: the code, and how full it is.
//
// The counts are the "busy bar" issue #16 asked for, in the one form that
// survives ruling A. They are also the whole of what the wire carries about a
// country's shape (ADR-0042 §9 removed the per-exit list precisely so a client
// gets counts and nothing more), so this renders it and stops.
//
// No noun after the numbers, and that is deliberate rather than terse: Russian
// agrees a noun with the number in front of it (1 сервер / 2 сервера / 5
// серверов), so any noun here would need three forms and lang.L has one. A
// sentence that is right in every language beats one that is wrong in the
// language this client is mainly for.
func countryRowLabel(c core.CountryInfo) string {
	if !c.Assignable() {
		return appstate.NormalizeCountry(c.Country) + "  —  " + lang.L("busy")
	}
	return appstate.NormalizeCountry(c.Country) + "  —  " + fmt.Sprintf(lang.L("%d of %d free"), c.Available, c.Exits)
}
