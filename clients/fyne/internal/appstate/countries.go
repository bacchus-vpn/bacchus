// The country picker's model (issue #16): which countries the coordinator will
// assign exits in, which one this client has chosen, and what to say when the
// answer is "none of them". Fyne-free like the rest of this package (ADR-0039's
// split), so every decision below is unit-testable and the outer package is left
// rendering what it is told.
//
// # Why listing needs an engine of its own
//
// core.Engine.ListCountries requires the client role AND a started engine, and
// this client builds an engine only at connect time (Controller.connectAsync).
// A picker needs the list BEFORE the connect, so FetchCountries stands up a
// throwaway client-role engine that does the list handshake and nothing else —
// no SOCKS listener, no session, no serve roles. That is the shape cmd/node's
// -list uses (cmd/node/main.go) and the shape the retired Windows tray client's
// own picker used, so it is the third instance of one pattern rather than a new
// one; ADR-0055 records why the two alternatives (holding a long-lived engine
// open, or teaching Connect to publish the list it already fetches) were not
// taken.
//
// # Why no latency
//
// core.CountryInfo carries PingMs and this package never reads it. That is a
// ruling, not an omission: the field is an unfed seam on BOTH sides (see
// cmd/coordinator's countryInfo.PingMs, which says the same thing), and every
// source a client could feed it from costs more than a number is worth —
// a file on disk recording which countries this person has connected to is a
// device-seizure artifact in the countries this client is built for; an
// in-memory-only figure is present for one row and absent for the rest, which is
// useless for choosing between them; and probing the signed directory's exits
// builds a network map on the client and generates traffic to every exit, which
// is the thing ADR-0042 §9 exists to prevent. The wire field stays so a client
// can render it the day an aggregated client-reporting path exists (issue filed
// alongside this one); until then the picker is country + busy, which is
// complete on its own. See ADR-0055.
package appstate

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/geoip"
)

// CountryAutomatic is the absence of a choice, and it is the default. It maps to
// an unset core.Config.Geo, which makes core resolve the country itself and take
// the first assignable one the coordinator offers (core's pickCountry) — exactly
// what this client did before it had a picker at all. Spelled as a named constant
// because "" means two different things in this file otherwise: "the user chose
// automatic" and "we have not looked yet".
const CountryAutomatic = ""

// CountryListTimeout is how long one refresh waits for a coordinator to answer.
// It matches core's own default listTimeout: the engine splits this across the
// coordinator pool (perLinkBudget), so a pool whose first member is blocked still
// gets to the second inside one refresh.
const CountryListTimeout = 8 * time.Second

// ErrCountryConfig is the refusal for a configured country that is not a country
// code. Its text is the English fallback only — the message a user actually reads
// is rendered by the UI layer from DetailCountryConfig, which can name the
// offending value in the user's own language.
//
// It exists because the alternative is silence. A hand-edited `"country":
// "Germany"` canonicalizes to nothing, and a client that treated nothing as
// CountryAutomatic would connect the user somewhere they did not ask for while
// their config file still said otherwise. That is the same failure core's
// pickCountry refuses to commit at the other end of the wire, and it is refused
// here too, one round trip earlier and naming the value.
var ErrCountryConfig = errors.New("that is not a two-letter country code — pick a country in the main window, or use a code like DE")

// NormalizeCountry canonicalizes a country tag the way every other tag in the
// system is canonicalized (geoip.Canonical): exactly two ASCII letters, upper
// case, and "" for anything else. Used on what the coordinator sends as well as
// on what the config file holds, so the picker's rows, the persisted choice and
// core.Config.Geo cannot disagree about case or whitespace.
func NormalizeCountry(raw string) string { return geoip.Canonical(raw) }

// ValidateCountry turns Config.Country into the value that reaches
// core.Config.Geo. Blank (any amount of whitespace) is CountryAutomatic and is
// not an error; anything else must canonicalize, or the connect is refused with
// ErrCountryConfig rather than quietly becoming automatic. Returns the
// canonicalized code so the caller sends what was validated.
func ValidateCountry(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return CountryAutomatic, nil
	}
	cc := NormalizeCountry(raw)
	if cc == "" {
		return "", ErrCountryConfig
	}
	return cc, nil
}

// CountryStatus is what the list says about one country. It is deliberately
// three-valued: "the coordinator did not mention it" is not the same answer as
// "it is full", and the two send a user to different next steps (change the
// code versus wait or choose elsewhere) — which is the same distinction the wire
// draws between no-such-country and country-busy.
type CountryStatus int

const (
	// CountryNotOffered: this country is absent from the list. Only meaningful
	// against a list that was actually fetched — check the list is non-empty
	// first, or a coordinator that could not be reached reads as every country
	// having vanished.
	CountryNotOffered CountryStatus = iota
	// CountryAvailable: the coordinator would assign an exit here right now.
	CountryAvailable
	// CountryBusy: the country is known and nothing in it is assignable —
	// everything there is at capacity, out of quota, or withheld from this
	// client's tier. Named by the coordinator rather than derived, so two
	// clients cannot derive it differently (core.CountryInfo.Busy).
	CountryBusy
)

// StatusOf reports what list says about code. code is canonicalized first, so a
// stale hand-edited "de" still matches the "DE" the coordinator sent.
//
// It is what puts busy in front of the user BEFORE the click. Nothing here
// substitutes: a busy country stays selectable and stays selected, because
// swapping it for a working one would egress the user somewhere they did not
// choose, which core's pickCountry refuses for the same reason at the other end.
// The picker's whole job is to make the refusal predictable, never to avoid it.
func StatusOf(code string, list []core.CountryInfo) CountryStatus {
	cc := NormalizeCountry(code)
	if cc == "" {
		return CountryNotOffered
	}
	for _, c := range list {
		if NormalizeCountry(c.Country) != cc {
			continue
		}
		if c.Assignable() {
			return CountryAvailable
		}
		return CountryBusy
	}
	return CountryNotOffered
}

// CountryListState is the whole of what the picker renders, published through
// Controller.OnCountries. The four cases are separate fields rather than one
// error because each needs different words and only one of them is the user's to
// fix: nothing configured is a setup step, a failed refresh is a network
// condition, an empty list is a network with no exits in it, and a populated list
// is the ordinary case.
type CountryListState struct {
	// Loading is a refresh in flight. Published on its own so the picker can say
	// so instead of showing a stale list as though it were current.
	Loading bool

	// Countries is the last list a coordinator successfully answered with, in the
	// coordinator's own order (alphabetical, and stable across refreshes — see
	// cmd/coordinator's countrySnapshot). It is KEPT across a failed refresh: a
	// list from thirty seconds ago is a far better basis for choosing than an
	// empty box, and Err says the figures may have moved.
	Countries []core.CountryInfo

	// Err is why the last refresh failed, or nil. Carried for the log rather than
	// for the screen — core's list errors name coordinators and protocol
	// dialects, and the picker says one calm sentence instead.
	Err error

	// Unconfigured is "there is no coordinator address to ask", which is not a
	// failure to report as one: it is a fresh install that has not been pointed
	// at a network yet, and pressing Connect already explains exactly what to do
	// about it (noCoordinatorsError).
	Unconfigured bool

	// Fetched is whether any refresh has finished yet. It separates "we have not
	// asked" from "we asked and there is nothing", which look identical in
	// Countries and need opposite words on screen — the first is a picker that
	// has not started, the second is a network with no exits in it.
	Fetched bool
}

// FetchCountries asks a coordinator which countries it will assign exits in,
// through a throwaway client-role engine that is stopped before this returns.
//
// The engine is deliberately minimal: coordinators, the client role, and the
// admission anchor — nothing else. No SocksAddr (nothing binds; core only listens
// inside Connect), no serve roles (a list must never be the thing that turns
// somebody into a relay), no transport pool and no relay chaining (neither
// changes the answer to "which countries exist", and both cost setup for a
// question that is one request and one reply).
//
// The admission fields ARE passed, and that is a judgement rather than
// symmetry: they verify exits, which a list does not do, but core validates them
// at construction — so passing them means a malformed anchor fails the picker in
// the same breath it would fail the connect, instead of leaving a user with a
// populated list and an unexplained refusal the moment they use it.
//
// logf, when non-nil, receives the engine's own diagnostics. They do not go to
// the detail line: that line is one calm sentence about the connection the user
// is waiting on, and "skipping coordinator %q" is neither.
func FetchCountries(ctx context.Context, cfg Config, logf func(string, ...any)) ([]core.CountryInfo, error) {
	if !hasCoordinator(cfg.Coordinators) {
		return nil, noCoordinatorsError()
	}
	eng, err := core.New(core.Config{
		Coordinators:     cfg.Coordinators,
		Roles:            []string{core.RoleClient},
		AdmissionPubKey:  cfg.AdmissionPubKey,
		AdmissionCRLPath: cfg.AdmissionCRLPath,
		OnEvent: func(ev core.Event) {
			if logf != nil {
				logf("countries: [%s] %s", ev.Kind, ev.Message)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	if err := eng.Start(ctx); err != nil {
		return nil, err
	}
	// Stopped on every path out of here, success included. A list engine that
	// outlived its request would hold a UDP socket per coordinator open for the
	// life of the app, and a refresh button would leak one set per press.
	defer eng.Stop()
	return eng.ListCountries(ctx, CountryListTimeout)
}
