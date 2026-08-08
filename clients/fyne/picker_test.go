// The picker's rendering decisions (issue #16). They live in this package
// rather than internal/appstate for one reason — they call lang.L, which is a
// Fyne import — so they are written as pure functions over a
// appstate.CountryListState and tested here without building a widget or a
// display driver. That keeps ADR-0039's split intact: everything a wrong answer
// would break is still reachable from `go test`.
//
// lang.L with no catalogue loaded returns the key, so what these assert is the
// English text. That is deliberate: the Russian is asserted for PRESENCE by
// translations_test.go, and asserting a translation's wording in a Go test would
// be asserting a review question.
package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
	"github.com/bacchus-vpn/bacchus/core"
)

func offered(countries ...core.CountryInfo) appstate.CountryListState {
	return appstate.CountryListState{Countries: countries, Fetched: true}
}

// TestBuildCountryRowsAlwaysOffersAutomatic pins the row that is not a country.
// Automatic is what this client did before it had a picker and it has to stay
// reachable: a user who picked DE last week and is travelling must be able to
// get back to "just connect me".
func TestBuildCountryRowsAlwaysOffersAutomatic(t *testing.T) {
	for _, s := range []appstate.CountryListState{
		{},
		offered(),
		offered(core.CountryInfo{Country: "DE", Exits: 1, Available: 1}),
	} {
		rows := buildCountryRows(s, appstate.CountryAutomatic)
		if len(rows) == 0 || rows[0].code != appstate.CountryAutomatic {
			t.Fatalf("rows = %+v, want Automatic first", rows)
		}
	}
}

// TestBuildCountryRowsKeepsTheChosenCountryVisible is the honest-degrade rule at
// row level. A user whose choice is not in the current list — because the
// coordinator is unreachable, or because that country's exits went away — must
// still see and be able to re-select their own choice. Dropping the row would
// silently move the selection to something else, which is the substitution this
// whole feature exists to refuse.
func TestBuildCountryRowsKeepsTheChosenCountryVisible(t *testing.T) {
	// No list at all: the row carries the code and no verdict, because with
	// nothing fetched we do not know one.
	rows := buildCountryRows(appstate.CountryListState{}, "DE")
	last := rows[len(rows)-1]
	if last.code != "DE" {
		t.Fatalf("rows = %+v, want a row for the chosen country", rows)
	}
	if last.label != "DE" {
		t.Fatalf("label = %q, want the bare code: nothing has been fetched, so there is no verdict to give", last.label)
	}

	// A list that was fetched and does not contain it: now there IS a verdict.
	rows = buildCountryRows(offered(core.CountryInfo{Country: "NL", Exits: 1, Available: 1}), "DE")
	last = rows[len(rows)-1]
	if last.code != "DE" || !last.absent {
		t.Fatalf("rows = %+v, want the chosen country marked absent", rows)
	}
	if !strings.Contains(last.label, "DE") || last.label == "DE" {
		t.Fatalf("label = %q, want the code and a reason it is greyed", last.label)
	}

	// And it must not be duplicated when the list DOES contain it.
	rows = buildCountryRows(offered(core.CountryInfo{Country: "DE", Exits: 1, Available: 1}), "DE")
	seen := 0
	for _, r := range rows {
		if r.code == "DE" {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("rows = %+v, want exactly one DE row", rows)
	}
}

// TestBuildCountryRowsGreysBusy is issue #16's "a full country is greyed out as
// busy", and the half of it that matters: greyed, not gone. A country the user
// is looking for must not vanish, and it must stay selectable so they can insist
// and get the honest refusal instead of a silent redirection.
func TestBuildCountryRowsGreysBusy(t *testing.T) {
	rows := buildCountryRows(offered(
		core.CountryInfo{Country: "DE", Exits: 3, Available: 2},
		core.CountryInfo{Country: "NL", Exits: 2, Available: 0, Busy: true},
	), appstate.CountryAutomatic)
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want Automatic plus both countries", rows)
	}
	if rows[1].busy {
		t.Errorf("DE is greyed but has capacity: %+v", rows[1])
	}
	if !rows[2].busy {
		t.Errorf("NL is full and is not greyed: %+v", rows[2])
	}
	if rows[2].code != "NL" {
		t.Errorf("a busy country must stay selectable, so it keeps its code: %+v", rows[2])
	}
}

// TestBuildCountryRowsDropsUncodedCountries covers a coordinator sending a tag
// that is not a country code. It cannot be connected to — core canonicalizes it
// to nothing at the other end too — so a row for it would be a choice that
// always fails.
func TestBuildCountryRowsDropsUncodedCountries(t *testing.T) {
	rows := buildCountryRows(offered(
		core.CountryInfo{Country: "Germany", Exits: 1, Available: 1},
		core.CountryInfo{Country: "de", Exits: 1, Available: 1},
	), appstate.CountryAutomatic)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want Automatic plus the one usable country", rows)
	}
	if rows[1].code != "DE" {
		t.Fatalf("row = %+v, want the canonicalized code", rows[1])
	}
}

// TestCountryRowLabel is the one place a user reads how full a country is.
func TestCountryRowLabel(t *testing.T) {
	free := countryRowLabel(core.CountryInfo{Country: "de", Exits: 5, Available: 3})
	if !strings.Contains(free, "DE") || !strings.Contains(free, "3") || !strings.Contains(free, "5") {
		t.Fatalf("label = %q, want the canonical code and both counts", free)
	}
	busy := countryRowLabel(core.CountryInfo{Country: "NL", Exits: 2, Available: 0, Busy: true})
	if !strings.Contains(busy, "NL") || !strings.Contains(busy, "busy") {
		t.Fatalf("label = %q, want the code and the word busy", busy)
	}
	if strings.Contains(busy, "0") {
		t.Fatalf("label = %q: a full country is a word, not an arithmetic problem", busy)
	}
	// Ruling A, at the surface it would have appeared on: no latency, ever.
	for _, l := range []string{free, busy} {
		for _, banned := range []string{"ms", "ping", "latency"} {
			if strings.Contains(strings.ToLower(l), banned) {
				t.Errorf("label %q mentions %q — the 1.0 picker is country + busy, and PingMs has no honest source (ADR-0055)", l, banned)
			}
		}
	}
}

// TestPickerVocabulary is issue #16's own bar, as a test: "The user picks a
// country and sees fast / busy — never 'exit', 'coordinator' or 'SOCKS'." Every
// sentence this file can put on screen is checked, because the words leak in
// from core's own error text more easily than from anything written here.
func TestPickerVocabulary(t *testing.T) {
	var texts []string
	texts = append(texts,
		countryRowLabel(core.CountryInfo{Country: "DE", Exits: 5, Available: 3}),
		countryRowLabel(core.CountryInfo{Country: "NL", Exits: 2, Available: 0, Busy: true}),
	)
	for _, r := range buildCountryRows(offered(core.CountryInfo{Country: "DE", Exits: 1, Available: 1}), "NL") {
		texts = append(texts, r.label)
	}
	for _, p := range []*countryPicker{
		{state: appstate.CountryListState{Loading: true}},
		{state: appstate.CountryListState{Unconfigured: true, Fetched: true}},
		{state: appstate.CountryListState{Err: errors.New("core: no coordinator answered the country list"), Fetched: true}},
		{state: offered()},
		{state: offered(core.CountryInfo{Country: "NL", Exits: 1, Available: 0, Busy: true}), chosen: "NL"},
		{state: offered(core.CountryInfo{Country: "DE", Exits: 1, Available: 1}), chosen: "NL"},
		{saveErr: errCountryConfigUnreadable},
	} {
		texts = append(texts, p.statusText())
	}
	texts = append(texts,
		detailText(appstate.Detail{Kind: appstate.DetailCountryBusy, Country: "NL"}),
		detailText(appstate.Detail{Kind: appstate.DetailNoSuchCountry, Country: "NL"}),
		detailText(appstate.Detail{Kind: appstate.DetailCountryConfig, Country: "Germany"}),
	)
	for _, s := range texts {
		low := strings.ToLower(s)
		for _, banned := range []string{"exit", "coordinator", "socks", "proxy", "tunnel"} {
			if strings.Contains(low, banned) {
				t.Errorf("%q says %q: the picker speaks in countries (issue #16)", s, banned)
			}
		}
	}
}

// TestStatusTextOrdering pins which sentence wins when several are true at once.
// The order is what the user can act on, and the case that matters is the last:
// a busy or missing CHOICE has to be said before the click, because after the
// click it is a refusal, and core will not substitute its way out of it.
func TestStatusTextOrdering(t *testing.T) {
	busyList := offered(core.CountryInfo{Country: "NL", Exits: 2, Available: 0, Busy: true})

	// A failed save outranks everything: it is the only one that is about
	// something the user just did.
	p := &countryPicker{state: busyList, chosen: "NL", saveErr: errors.New("permission denied")}
	if !strings.Contains(p.statusText(), "permission denied") {
		t.Errorf("a failed save was hidden behind another message: %q", p.statusText())
	}

	// Loading outranks a stale verdict about the list underneath it.
	p = &countryPicker{state: appstate.CountryListState{Loading: true, Fetched: true, Countries: busyList.Countries}, chosen: "NL"}
	if !strings.Contains(p.statusText(), "Looking") {
		t.Errorf("a refresh in flight did not say so: %q", p.statusText())
	}

	// The busy warning, which is the whole point of showing busy at all.
	p = &countryPicker{state: busyList, chosen: "NL"}
	if !strings.Contains(p.statusText(), "NL") || !strings.Contains(p.statusText(), "busy") {
		t.Errorf("a chosen country that is full did not warn before the click: %q", p.statusText())
	}

	// A chosen country the list does not offer reads differently from a busy
	// one, matching the two refusals the wire draws.
	p = &countryPicker{state: offered(core.CountryInfo{Country: "DE", Exits: 1, Available: 1}), chosen: "NL"}
	if !strings.Contains(p.statusText(), "not on the list") {
		t.Errorf("a chosen country nobody offers was reported as busy or not at all: %q", p.statusText())
	}

	// Automatic never warns: there is no choice of the user's to be in trouble.
	p = &countryPicker{state: busyList, chosen: appstate.CountryAutomatic}
	if got := p.statusText(); got != "" {
		t.Errorf("statusText = %q for Automatic, want nothing to say", got)
	}

	// An untouched picker says nothing either — "we have not asked" must not
	// read as "we asked and there is nothing".
	p = &countryPicker{}
	if got := p.statusText(); got != "" {
		t.Errorf("statusText = %q before any refresh, want nothing", got)
	}
	p = &countryPicker{state: offered()}
	if got := p.statusText(); got == "" {
		t.Error("a finished refresh that found no countries said nothing at all")
	}
}

// TestDetailTextNamesTheCountry is the half of the two refusals that makes them
// actionable: the sentence has to say WHICH country was refused, or a user with
// a list in front of them cannot tell what to change.
func TestDetailTextNamesTheCountry(t *testing.T) {
	for _, kind := range []appstate.DetailKind{
		appstate.DetailCountryBusy,
		appstate.DetailNoSuchCountry,
		appstate.DetailCountryConfig,
	} {
		got := detailText(appstate.Detail{Kind: kind, Country: "NL", Text: "core's own sentence"})
		if !strings.Contains(got, "NL") {
			t.Errorf("kind %d rendered %q without naming the country", kind, got)
		}
		if strings.Contains(got, "core's own sentence") {
			t.Errorf("kind %d relayed core's text instead of its own: %q", kind, got)
		}
	}
	// Anything else is relayed untouched: core's errors are not fixed sentences,
	// and replacing them with a generic translated one would throw away the only
	// diagnostic the user has.
	verbatim := "listen tcp 127.0.0.1:1080: bind: address already in use"
	if got := detailText(appstate.Detail{Text: verbatim}); got != verbatim {
		t.Errorf("detailText(%q) = %q, want it relayed unchanged", verbatim, got)
	}
}

// TestRenewalDetailsAreRenderedHereNotRelayed is bacchus#171's first part.
//
// Every rung of the renewal ladder is a fixed sentence this app wrote, so every
// rung has to be rendered here — through lang.L, where TestEveryUIStringIsTranslated's
// AST walk can see it — rather than relayed from appstate as English. A kind
// with no case falls through to Detail.Text, which compiles, passes every other
// check, and hands a Russian-speaking user an English warning at the one moment
// they have something to act on. This is the check that fails instead.
func TestRenewalDetailsAreRenderedHereNotRelayed(t *testing.T) {
	const fallback = "the English copy appstate always fills in"
	for _, kind := range []appstate.DetailKind{
		appstate.DetailRenewalFailing,
		appstate.DetailRenewalUrgent,
		appstate.DetailRenewalExpired,
		appstate.DetailRenewalUnknownExpiry,
		appstate.DetailSubscriptionExpired,
		appstate.DetailDeviceRevoked,
		appstate.DetailRenewalRecovered,
	} {
		got := detailText(appstate.Detail{Kind: kind, Text: fallback, Remaining: 30 * time.Minute})
		if got == fallback {
			t.Errorf("kind %d fell through to Detail.Text; it needs a lang.L case in detailText", kind)
		}
		if got == "" {
			t.Errorf("kind %d rendered nothing", kind)
		}
	}

	// The urgent rung is the only one carrying a number, and it has to say it:
	// "runs out soon" without a quantity is a warning a user cannot plan around.
	urgent := detailText(appstate.Detail{Kind: appstate.DetailRenewalUrgent, Remaining: 30 * time.Minute})
	if !strings.Contains(urgent, "30") {
		t.Errorf("the urgent renewal sentence does not say how long is left: %q", urgent)
	}
	// And the phrase itself goes through lang.L rather than arriving pre-rendered
	// from appstate, so it is translated with the sentence around it.
	for d, want := range map[time.Duration]string{
		5 * time.Hour:    "5 hours",
		90 * time.Minute: "an hour",
		45 * time.Minute: "45 minutes",
		30 * time.Second: "a moment",
	} {
		if got := roughRemainingText(d); got != want {
			t.Errorf("roughRemainingText(%v) = %q, want %q", d, got, want)
		}
	}
}

// TestEnrollmentDetailsAreRenderedHereNotRelayed is bacchus#181, and it is
// TestRenewalDetailsAreRenderedHereNotRelayed's check applied to the two
// sentences bacchus#171 named and did not widen to.
//
// Both are fixed sentences this app wrote, so both have to be rendered here
// through lang.L rather than relayed from appstate as English. A kind with no
// case falls through to Detail.Text, which compiles and passes every other
// check while handing a Russian-speaking user an English line — and for the
// second of these that line is what they read when enrollment could not reach
// the account service, at a moment they have something to act on.
func TestEnrollmentDetailsAreRenderedHereNotRelayed(t *testing.T) {
	const fallback = "the English copy appstate always fills in"
	for _, kind := range []appstate.DetailKind{
		appstate.DetailEnrolled,
		appstate.DetailEnrollUnreachable,
	} {
		got := detailText(appstate.Detail{Kind: kind, Text: fallback})
		if got == fallback {
			t.Errorf("kind %d fell through to Detail.Text; it needs a lang.L case in detailText", kind)
		}
		if got == "" {
			t.Errorf("kind %d rendered nothing", kind)
		}
	}

	// And the two are distinct sentences rather than one kind doing both jobs:
	// "registered" and "could not register" are opposite outcomes and the
	// unreachable one is the only one a user can act on.
	enrolled := detailText(appstate.Detail{Kind: appstate.DetailEnrolled})
	unreachable := detailText(appstate.Detail{Kind: appstate.DetailEnrollUnreachable})
	if enrolled == unreachable {
		t.Errorf("both enrollment kinds render the same sentence: %q", enrolled)
	}
}
