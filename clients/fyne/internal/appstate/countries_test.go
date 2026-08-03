package appstate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

// TestValidateCountry pins the one rule that decides what reaches
// core.Config.Geo. The case that matters is the last group: a value that is not
// a country code must be REFUSED, never quietly read as "automatic", because
// automatic connects the user somewhere while their config file names a country
// they think they are in.
func TestValidateCountry(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: CountryAutomatic},
		{in: "   ", want: CountryAutomatic},
		{in: "DE", want: "DE"},
		{in: "de", want: "DE"},
		{in: " nl ", want: "NL"},
		{in: "Germany", wantErr: true},
		{in: "D", wantErr: true},
		{in: "DEU", wantErr: true},
		{in: "D1", wantErr: true},
	} {
		got, err := ValidateCountry(tc.in)
		if tc.wantErr {
			if !errors.Is(err, ErrCountryConfig) {
				t.Errorf("ValidateCountry(%q) = (%q, %v), want ErrCountryConfig — a value that is not a country code must be refused, not defaulted to automatic", tc.in, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ValidateCountry(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}
}

// TestStatusOf covers the three answers the picker renders differently, and the
// one that is easy to get wrong: a country absent from the list is NOT busy. The
// two send a user to different next steps, and the wire draws the same
// distinction for the same reason.
func TestStatusOf(t *testing.T) {
	list := []core.CountryInfo{
		{Country: "DE", Exits: 3, Available: 2},
		{Country: "NL", Exits: 2, Available: 0, Busy: true},
		// A country the coordinator reports with capacity but has flagged busy:
		// Busy is carried rather than derived (core.CountryInfo.Assignable), so
		// the flag wins and this client must not second-guess it from the counts.
		{Country: "FR", Exits: 4, Available: 2, Busy: true},
	}
	for _, tc := range []struct {
		code string
		want CountryStatus
	}{
		{"DE", CountryAvailable},
		{"de", CountryAvailable},
		{"NL", CountryBusy},
		{"FR", CountryBusy},
		{"US", CountryNotOffered},
		{"", CountryNotOffered},
		{"Germany", CountryNotOffered},
	} {
		if got := StatusOf(tc.code, list); got != tc.want {
			t.Errorf("StatusOf(%q) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

// TestPingIsNeverReadFromTheWire is ruling A as a test rather than a comment.
//
// PingMs is an unfed seam on both sides and always 0; the risk is not that this
// client renders a wrong number today but that somebody later feeds the field
// from a client-side source (this device's own session history, or a probe of
// the signed directory's exits) because the struct offers it and nothing says
// no. This is the "no" — see countries.go's package doc and ADR-0055 for what
// each of those sources costs.
func TestPingIsNeverReadFromTheWire(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	got, err := FetchCountries(context.Background(), Config{Coordinators: []string{coord.addr()}}, nil)
	if err != nil {
		t.Fatalf("FetchCountries: %v", err)
	}
	for _, c := range got {
		if c.PingMs != 0 {
			t.Fatalf("country %s arrived with PingMs %d: the coordinator does not feed this field, so a non-zero value means something invented one", c.Country, c.PingMs)
		}
	}
}

// TestFetchCountriesAgainstARealEngine is the picker's own acceptance test: the
// list a user chooses from comes from a real core.Engine doing a real list
// handshake against a coordinator, with no session and nothing bound.
//
// It also covers the shape decision this lane had to make (ADR-0055): the
// throwaway engine must be able to answer this question with no Connect in
// front of it, which is precisely what ListCountries' "requires a started
// engine" made non-obvious.
func TestFetchCountriesAgainstARealEngine(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	cfg := Config{Coordinators: []string{coord.addr()}}

	got, err := FetchCountries(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("FetchCountries: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d countries, want the one the exit registered in: %+v", len(got), got)
	}
	if NormalizeCountry(got[0].Country) != "ZZ" {
		t.Fatalf("country = %q, want the registered exit's", got[0].Country)
	}
	if !got[0].Assignable() {
		t.Fatalf("%+v is not assignable, but the exit is up and free", got[0])
	}
	if StatusOf("zz", got) != CountryAvailable {
		t.Fatal("StatusOf disagrees with Assignable about the same country")
	}

	// The same country, full. Both halves have to move together — a list that
	// says available while the connect refuses is the failure the picker exists
	// to prevent, and it is what this asserts the fake cannot do either.
	coord.setBusy(true)
	got, err = FetchCountries(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("FetchCountries (busy): %v", err)
	}
	if len(got) != 1 || got[0].Assignable() || !got[0].Busy {
		t.Fatalf("busy country came back as %+v, want Busy with nothing available", got)
	}
	if StatusOf("ZZ", got) != CountryBusy {
		t.Fatal("a full country did not read as busy")
	}
}

// TestFetchCountriesWithNothingConfigured is the fresh install: no coordinator,
// so there is nobody to ask. It must fail with this client's own actionable
// message rather than core's construction error, exactly as Connect does — the
// picker is now the first thing a fresh user touches, so it is the first place
// that message has to be right.
func TestFetchCountriesWithNothingConfigured(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{Coordinators: []string{"", "  "}},
		{Coordinators: []string{"COORDINATOR_HOST:8080"}}, // the shipped template, unedited
	} {
		_, err := FetchCountries(context.Background(), cfg, nil)
		if err == nil {
			t.Fatalf("FetchCountries(%+v) succeeded with nothing to ask", cfg.Coordinators)
		}
		if err.Error() != noCoordinatorsError().Error() {
			t.Fatalf("FetchCountries(%+v) = %v, want this client's own no-coordinators message", cfg.Coordinators, err)
		}
	}
}

// TestFetchCountriesWhenNobodyAnswers is the censored user's ordinary Tuesday:
// the coordinator is configured and unreachable. The refresh must fail in
// bounded time and hand back core's sentinel, not hang — the app has to stay
// usable, and Connect (which has its own recovery) must remain pressable.
func TestFetchCountriesWhenNobodyAnswers(t *testing.T) {
	// Port 9 is discard; nothing answers a UDP datagram there.
	cfg := Config{Coordinators: []string{"127.0.0.1:9"}}
	start := time.Now()
	_, err := FetchCountries(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("FetchCountries succeeded against a coordinator that does not exist")
	}
	if !errors.Is(err, core.ErrNoCoordinatorReachable) {
		t.Fatalf("err = %v, want ErrNoCoordinatorReachable — the picker's failure has to stay distinguishable from a coordinator that answered", err)
	}
	if elapsed := time.Since(start); elapsed > CountryListTimeout+5*time.Second {
		t.Fatalf("took %s: a silent coordinator must not hold the picker open indefinitely", elapsed)
	}
}

// TestRefreshCountriesPublishesLoadingThenTheList drives the Controller seam the
// UI actually binds to.
func TestRefreshCountriesPublishesLoadingThenTheList(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	c := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}})
	states := make(chan CountryListState, 8)
	c.OnCountries = func(s CountryListState) { states <- s }

	c.RefreshCountries()
	first := waitForCountries(t, states, 2*time.Second)
	if !first.Loading {
		t.Fatal("the first publication was not Loading: a refresh that says nothing while it runs looks like a dead button")
	}
	final := waitForCountries(t, states, 20*time.Second)
	if final.Loading || final.Err != nil {
		t.Fatalf("final = %+v, want a finished refresh with no error", final)
	}
	if len(final.Countries) != 1 {
		t.Fatalf("final list = %+v, want the one registered country", final.Countries)
	}
	if got := c.Countries(); len(got.Countries) != 1 {
		t.Fatalf("Countries() = %+v, want the same list the callback got", got)
	}
}

// TestRefreshCountriesKeepsTheLastListWhenARefreshFails is the honest-degrade
// rule. A coordinator that has gone away does not make the countries it named a
// minute ago stop existing, and emptying the picker would take the user's
// ability to choose away at the exact moment the app can least explain itself.
//
// Mutation check: assign the (empty) result unconditionally in RefreshCountries
// and this goes red.
func TestRefreshCountriesKeepsTheLastListWhenARefreshFails(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	c := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}})
	states := make(chan CountryListState, 8)
	c.OnCountries = func(s CountryListState) { states <- s }

	c.RefreshCountries()
	waitForCountries(t, states, 2*time.Second) // Loading
	good := waitForCountries(t, states, 20*time.Second)
	if len(good.Countries) != 1 {
		t.Fatalf("first refresh = %+v, want one country", good)
	}

	// Point the same Controller at a coordinator that does not answer, the way
	// the Settings window would, and refresh into the void. SetConfig publishes
	// once itself (it clears the spinner for any refresh it just invalidated —
	// see TestSetConfigDoesNotStrandTheSpinner), so that is consumed first.
	c.SetConfig(Config{Coordinators: []string{"127.0.0.1:9"}})
	if s := waitForCountries(t, states, 2*time.Second); s.Loading {
		t.Fatalf("SetConfig published %+v, want the spinner cleared", s)
	}
	c.RefreshCountries()
	waitForCountries(t, states, 2*time.Second) // Loading
	failed := waitForCountries(t, states, CountryListTimeout+10*time.Second)
	if failed.Err == nil {
		t.Fatal("a refresh against a dead coordinator reported no error")
	}
	if len(failed.Countries) != 1 {
		t.Fatalf("the previous list was dropped on failure (%+v): the user is left unable to choose for a reason that has nothing to do with the countries", failed.Countries)
	}
}

// TestSetConfigDoesNotStrandTheSpinner is the deadlock a generation counter
// invites and does not by itself prevent.
//
// A settings save invalidates a refresh in flight, so that refresh discards its
// own result — including the Loading flag it set. If nothing else clears it the
// picker sits on "Looking for countries…" over a refresh nobody will ever
// publish, and the Refresh button (disabled while Loading) can never get it out.
//
// Mutation check: drop the Loading clear from SetConfig and this hangs waiting
// for the publication that says the spinner stopped.
func TestSetConfigDoesNotStrandTheSpinner(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	// Start against a coordinator that will never answer, so the first refresh
	// is still in flight when the config changes under it.
	c := newProxyOnlyController(Config{Coordinators: []string{"127.0.0.1:9"}})
	states := make(chan CountryListState, 8)
	c.OnCountries = func(s CountryListState) { states <- s }

	c.RefreshCountries()
	if s := waitForCountries(t, states, 2*time.Second); !s.Loading {
		t.Fatalf("first publication = %+v, want Loading", s)
	}

	c.SetConfig(Config{Coordinators: []string{coord.addr()}})
	if s := waitForCountries(t, states, 2*time.Second); s.Loading {
		t.Fatal("a settings save left the picker loading over a refresh whose answer it has already decided to discard")
	}

	// And the picker still works afterwards.
	c.RefreshCountries()
	if s := waitForCountries(t, states, 2*time.Second); !s.Loading {
		t.Fatalf("second refresh did not start: %+v", s)
	}
	final := waitForCountries(t, states, 20*time.Second)
	if final.Loading || final.Err != nil || len(final.Countries) != 1 {
		t.Fatalf("second refresh = %+v, want the new pool's one country", final)
	}
}

// TestSetConfigKeepsTheChosenCountry is the two-writers rule. The Settings
// window and the picker both persist the same file; Settings has no country
// widget, so a save from a window opened before the user picked must not carry
// the country back to what it was when that window opened.
func TestSetConfigKeepsTheChosenCountry(t *testing.T) {
	c := newProxyOnlyController(Config{Coordinators: []string{"127.0.0.1:9"}, Country: "NL"})
	c.SetCountry("de")
	if got := c.Country(); got != "DE" {
		t.Fatalf("Country() = %q after SetCountry(\"de\"), want the canonical form", got)
	}
	// A settings save carrying the stale country it was seeded with.
	c.SetConfig(Config{Coordinators: []string{"127.0.0.1:10"}, Country: "NL", DNS: "9.9.9.9:53"})
	if got := c.Country(); got != "DE" {
		t.Fatalf("Country() = %q after a settings save, want DE — the picker's choice was overwritten by a window that cannot even set it", got)
	}
	if c.cfg.DNS != "9.9.9.9:53" {
		t.Fatal("SetConfig dropped the settings it does carry")
	}
}

// TestSetCountryClearsBackToAutomatic covers the row that is not a country.
func TestSetCountryClearsBackToAutomatic(t *testing.T) {
	c := newProxyOnlyController(Config{Country: "DE"})
	c.SetCountry(CountryAutomatic)
	if got := c.Country(); got != CountryAutomatic {
		t.Fatalf("Country() = %q, want automatic", got)
	}
}

// TestConnectUsesTheChosenCountry is the end-to-end proof that the picker's
// choice reaches the wire: the client asks for the country it was given, a
// coordinator that has an exit there pairs it, and the session comes up.
func TestConnectUsesTheChosenCountry(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	ctrl := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}, Country: "zz"})
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 20*time.Second); s != Protected {
		t.Fatalf("state = %v, want Protected (details: %v)", s, rec.detailsSnapshot())
	}
	ctrl.Disconnect()
	rec.next(t, 5*time.Second)
}

// TestConnectIntoAnUnknownCountryIsRefusedInPlainLanguage is the whole point of
// the wire naming its two refusals, carried through to what a user reads.
//
// It also pins state.go's coupling to core's refusal sentence. countryRefusal
// matches on text core owns; nothing but a real refusal, from a real engine,
// through a real coordinator can tell us that match still holds. A reword in
// core lands here as a failure instead of silently reverting the detail line to
// a line of protocol vocabulary in English.
func TestConnectIntoAnUnknownCountryIsRefusedInPlainLanguage(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	// The exit registered in ZZ; ask for somewhere else entirely.
	ctrl := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}, Country: "DE"})
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 30*time.Second); s != Disconnected {
		t.Fatalf("state = %v, want Disconnected (details: %v)", s, rec.detailsSnapshot())
	}
	d, ok := rec.findKind(DetailNoSuchCountry)
	if !ok {
		t.Fatalf("no DetailNoSuchCountry was published; details were %v", rec.detailsSnapshot())
	}
	if d.Country != "DE" {
		t.Fatalf("refusal named country %q, want DE — the user has to be told which country was refused", d.Country)
	}
	if strings.Contains(d.Text, "exit") || strings.Contains(d.Text, "coordinator") {
		t.Fatalf("refusal text %q relays core's vocabulary; issue #16 requires this client to speak in countries", d.Text)
	}
}

// TestConnectIntoABusyCountryIsRefusedRatherThanSubstituted is the rule this
// lane must not undo, stated as a test.
//
// core's pickCountry uses a configured country VERBATIM even when the list says
// it is busy, deliberately: substituting a working country would egress the user
// somewhere they did not choose. So a busy choice must produce a REFUSAL naming
// that country — never a quiet connection somewhere else — and the refusal must
// be the busy one, which tells the user to wait or choose again, not the
// wrong-code one.
//
// Mutation check: make connectAsync fall back to CountryAutomatic when the
// chosen country is busy and this goes green on the wrong outcome — it reaches
// Protected, which is the failure the whole rule exists to prevent.
func TestConnectIntoABusyCountryIsRefusedRatherThanSubstituted(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	coord.setBusy(true)
	ctrl := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}, Country: "zz"})
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 30*time.Second); s != Disconnected {
		t.Fatalf("state = %v, want Disconnected — a busy country must be refused, never swapped for a working one (details: %v)", s, rec.detailsSnapshot())
	}
	d, ok := rec.findKind(DetailCountryBusy)
	if !ok {
		t.Fatalf("no DetailCountryBusy was published; details were %v", rec.detailsSnapshot())
	}
	if d.Country != "zz" && d.Country != "ZZ" {
		t.Fatalf("busy refusal named %q, want the country that was asked for", d.Country)
	}
}

// TestConnectRefusesAConfiguredCountryThatIsNotOne is the hand-edited config
// file. It never reaches the wire: the client says which value it could not read
// and stops, rather than treating it as "no preference" and connecting the user
// somewhere while their file still names a country.
func TestConnectRefusesAConfiguredCountryThatIsNotOne(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	ctrl := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}, Country: " Germany "})
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 5*time.Second); s != Disconnected {
		t.Fatalf("state = %v, want Disconnected", s)
	}
	d, ok := rec.findKind(DetailCountryConfig)
	if !ok {
		t.Fatalf("no DetailCountryConfig was published; details were %v", rec.detailsSnapshot())
	}
	if d.Country != "Germany" {
		t.Fatalf("the refusal named %q, want the offending value trimmed but otherwise verbatim — the user has to recognise what they typed", d.Country)
	}
}

// TestConnectWithNoCountryIsUnchanged is the regression guard on today's
// behaviour: a client that has chosen nothing still connects, with core
// resolving the country exactly as it did before this client had a picker.
func TestConnectWithNoCountryIsUnchanged(t *testing.T) {
	coord, _ := startLoopbackExit(t)
	ctrl := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}}) // no Country
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 20*time.Second); s != Protected {
		t.Fatalf("state = %v, want Protected (details: %v)", s, rec.detailsSnapshot())
	}
	ctrl.Disconnect()
	rec.next(t, 5*time.Second)
}

// TestTheShippedTemplateAsksForNoCountry checks the file both installers seed
// (deploy/install.sh and deploy/windows/build-bundle.ps1 copy it verbatim).
//
// The template is the one config most users will ever have, and a country in it
// would be used VERBATIM by core — so a template shipping, say, "NL" would put
// every fresh user in the Netherlands and refuse them outright the day it filled
// up, with nothing on screen explaining why the app picked a country they never
// chose. Empty is the only correct value here, and it is worth a test because
// "just add a sensible default" is such a natural-looking edit.
func TestTheShippedTemplateAsksForNoCountry(t *testing.T) {
	const example = "../../bacchus-fyne.config.example.json"
	b, err := os.ReadFile(example)
	if err != nil {
		t.Fatalf("read %s: %v", example, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse %s: %v", example, err)
	}
	if !strings.Contains(string(b), `"country"`) {
		t.Errorf("%s has no \"country\" key: a user hand-editing the template has no idea the setting exists", example)
	}
	got, err := ValidateCountry(cfg.Country)
	if err != nil {
		t.Fatalf("%s ships country %q, which this client refuses to connect with: %v", example, cfg.Country, err)
	}
	if got != CountryAutomatic {
		t.Errorf("%s ships country %q; the template must ask for none, or every fresh install is pinned to one jurisdiction nobody chose", example, cfg.Country)
	}
}

// waitForCountries takes the next picker publication or fails the test.
func waitForCountries(t *testing.T, ch <-chan CountryListState, timeout time.Duration) CountryListState {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for a country-list publication", timeout)
		return CountryListState{}
	}
}
