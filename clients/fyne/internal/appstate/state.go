// Package appstate is the connection-state model and engine controller (issues
// #148/#149), kept deliberately free of any Fyne import. That split is what
// lets this package's tests run as plain `go test`, with no GUI toolchain
// (glfw/OpenGL need cgo - see the ADR) - only the outer main package touches
// fyne.* and needs that toolchain to build.
//
// ConnState is the single most important pixel in the app: a non-technical,
// possibly stressed user in a censored country must know their safety state
// at a glance, in plain language. Exactly one state is shown at a time; the
// outer ui.go binds it to a big icon+color+text indicator, never a jargon
// status line.
package appstate

import (
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

// ConnState is the headline connection state. The zero value (Disconnected) is
// what the app starts and ends in.
type ConnState int

const (
	// Disconnected: no tunnel, nothing protected. Also where the app lands
	// after the user disconnects or a connect attempt fails outright.
	Disconnected ConnState = iota
	// Connecting: a connect attempt is in flight (dialing the coordinator,
	// negotiating the transport). Entered the moment the user presses Connect.
	Connecting
	// Protected: a session is up and traffic is flowing through it.
	Protected
	// Blocked: was Protected, and the live path just died. Named for the
	// kill-switch's fail-closed posture (ADR-0014): this app has no OS-level
	// enforcement of its own yet (out of scope for this skeleton - see the
	// ADR), but the *signal* is the same one the Windows tray client already
	// uses for the identical state (main.go's eventStatus) - a transport-level
	// drop while previously protected, not a firewall check.
	Blocked
)

// StateFor computes the next headline state given the state just prior and one
// core.Event. Every other transition (Disconnected->Connecting->Protected, or
// back to Disconnected on a failed attempt) is driven directly by
// Controller's own call sequence around Start/Connect/Stop, exactly as the
// Windows tray client's connect()/disconnect() drive its status line - those
// transitions have a corresponding blocking call that succeeds or fails right
// there. The one transition with no such call is a live path dying (or
// recovering) underneath an already-established session, which is only
// observable from the ICE event stream, so that is all this function
// handles. Mirrors eventStatus's ICE branch (the retired Windows client's main.go)
// exactly, typed as a state instead of a status string.
func StateFor(cur ConnState, ev core.Event) ConnState {
	if ev.Kind != core.EventICE || (cur != Protected && cur != Blocked) {
		return cur
	}
	switch {
	case strings.Contains(ev.Message, ": disconnected"), strings.Contains(ev.Message, ": failed"), strings.Contains(ev.Message, ": closed"):
		return Blocked
	case strings.Contains(ev.Message, ": connected"), strings.Contains(ev.Message, ": completed"):
		return Protected
	}
	return cur
}

// DetailKind classifies a detail-line message so the layer that owns the
// user's language can render it there.
//
// It exists because this package cannot import Fyne (see the package doc) and so
// cannot call lang.L, while every sentence a user reads has to be translatable —
// clients/fyne/translations_test.go fails the build over exactly that, and its
// reasoning applies with more force here than to a settings label: this line is
// what a user reads when a connect did not happen. Passing a rendered English
// string out and translating it back by matching on its own text would make the
// English copy a key nobody can see is one; passing a kind and its one variable
// part lets the outer package write a literal lang.L call the AST walk can find.
//
// Text is filled in on every kind, so a caller that does not translate (the
// tests, and anything reading this as a log) still gets the whole sentence.
type DetailKind int

const (
	// DetailVerbatim: Text is the message, as it stands. Everything core emits
	// arrives this way — an engine error is not a fixed sentence and has no
	// translation to look up.
	DetailVerbatim DetailKind = iota
	// DetailCountryBusy: the coordinator refused the connect because every exit
	// in the requested country is at capacity, out of quota, or withheld from
	// this client's tier (the wire's country-busy). Country names it.
	DetailCountryBusy
	// DetailNoSuchCountry: the coordinator knows no exit in the requested
	// country at all (the wire's no-such-country). Country names it.
	DetailNoSuchCountry
	// DetailCountryConfig: the configured country is not a country code, so this
	// client refused the connect before sending it (ValidateCountry). Country
	// carries the offending value verbatim, which is the whole point of showing
	// it — the user has to recognise what they typed.
	DetailCountryConfig

	// The renewal ladder (bacchus#171). These seven are the sentences
	// recordRenewalFailure and recordRenewalSuccess put on the detail line, and
	// they had no kinds until now — so the one class of message a user reads
	// while everything still looks fine went out through DetailVerbatim, the
	// path meant for core's own error text. That path exists because core's
	// errors are not fixed sentences and have no translation to look up; these
	// ARE fixed sentences this client wrote, and rendering them as though they
	// were not is what left a Russian-speaking user reading English at the one
	// moment they have something to act on.
	//
	// One kind per rung rather than one kind for "renewal": the ladder escalates
	// on the CLOCK (ADR-0056 §6), each rung is a different sentence, and a UI
	// that wanted to raise a badge on the urgent ones needs to be able to tell
	// them apart without parsing prose.

	// DetailRenewalFailing: a renewal failed while the stored credential still
	// has comfortable life left. Nothing is wrong yet and the sentence says so —
	// this is the rung that exists so the later ones are not the first news.
	DetailRenewalFailing
	// DetailRenewalUrgent: a renewal failed with the credential close enough to
	// expiry that the user has something to do about it and a shrinking window
	// to do it in. Remaining carries how long is left.
	DetailRenewalUrgent
	// DetailRenewalExpired: the credential has run out and could not be
	// refreshed. Connecting is refused from here until renewal works.
	DetailRenewalExpired
	// DetailRenewalUnknownExpiry: a renewal failed and the stored credential's
	// own claimed expiry could not be read, so no rung of the clock ladder can be
	// chosen honestly. Said plainly rather than guessed at.
	DetailRenewalUnknownExpiry
	// DetailSubscriptionExpired: the account service refused the renewal because
	// the subscription has lapsed. Ignores the clock — no amount of waiting fixes
	// it — and is therefore said immediately whatever the remaining life is.
	DetailSubscriptionExpired
	// DetailDeviceRevoked: the account service refused the renewal because this
	// device's access was withdrawn. The clock is ignored for the same reason.
	DetailDeviceRevoked
	// DetailRenewalRecovered: a renewal succeeded after one had failed. Published
	// only when there was a failure to clear — announcing every success would
	// make the line flicker with news that nothing is wrong, which is how a line
	// that also carries real warnings stops being read.
	DetailRenewalRecovered

	// Enrollment (bacchus#181). The two sentences enrollIfNeeded puts on the
	// detail line went out as DetailVerbatim for the same reason the renewal
	// ladder did — nobody had given them kinds — and bacchus#171 moved the ladder
	// without widening to them. They are the same case: fixed sentences this
	// client wrote, not core diagnostics, so the verbatim path is the wrong one.

	// DetailEnrolled: this device just completed enrollment and now holds a
	// device credential. A fixed sentence this client wrote, not core
	// diagnostics, so it is a kind rather than DetailVerbatim (bacchus#171's
	// rule, bacchus#181).
	DetailEnrolled
	// DetailEnrollUnreachable: enrollment could not reach the account service, so
	// the connect proceeds on whatever this device already holds. The one of the
	// two that matters — it is what a user sees at a moment they have something
	// to act on.
	DetailEnrollUnreachable
)

// Detail is one detail-line message: what to say, and enough structure for the
// UI to say it in the user's own language.
type Detail struct {
	Kind DetailKind
	// Text is the English rendering, always set.
	Text string
	// Country is the country tag the message is about, for the three country
	// kinds. Empty otherwise.
	Country string
	// Remaining is how much life the stored device credential has left, for
	// DetailRenewalUrgent — the one renewal rung whose sentence carries a
	// number. Zero for every other kind.
	//
	// It is a Duration rather than a rendered phrase because the phrase is a UI
	// string like any other: handing the outer package "3 hours" would put an
	// English fragment inside a translated sentence, which is the exact failure
	// this whole type exists to prevent. Text still carries the English rendering
	// for a caller that does not translate.
	Remaining time.Duration
}

// relayChainFailedPrefix mirrors the retired Windows client's main.go's constant of the
// same name: core's one genuinely diagnostic signal for a relay chain that
// failed to build (docs/design/relay-chaining.md §10.4; core/relaychain.go's
// file doc — chaining is fail-closed, never silently downgraded to fewer
// hops).
//
// This used to say that nothing in this client could produce the message,
// because there was no Settings UI for RelayHops/RelayDirectory (issue #28
// wired the walk client only) — it was written against the day one arrived.
// Issue #93 is that day: the hop count is settable here now, so a user who
// raises it past what their directory can satisfy reaches this branch, and
// what they are told is that their relay-hops setting is why, rather than a
// generic connection error they would retry into the same directory gap.
const relayChainFailedPrefix = "[relay] chain not built: "

// deviceRenewFailedPrefix is core's own event for a renewal that did not work
// (core/devicecred_connect.go's maybeRenewDeviceCred). It is recognised here in
// order to be SUPPRESSED, which is the opposite of what the two prefixes above
// are for, and the reason is that this client has already said something better
// about the same outcome by the time core says this.
//
// The ordering is worth stating because it is what makes the suppression
// necessary rather than tidy. core calls Config.DeviceRenew; the closure this
// client wires publishes its own escalating sentence from the failure; the
// closure returns the error; and only THEN does core emit this event. So the
// last thing to reach the detail line was core's diagnostic — "device
// credential: renewal failed, will retry at the next check: accountclient:
// /v1/credential: HTTP 403" — landing on top of the one calm sentence written
// for exactly this moment, with a subscription warning replaced by an HTTP
// status.
//
// ADR-0056 §6 refused to PRODUCE the warning by matching on core's text, and
// that refusal stands: the warning is produced from the closure's own return
// value and does not depend on this constant at all. What this does is drop a
// duplicate. If the prefix ever drifts, the duplicate comes back — visibly, in
// English, the way it looked before — rather than the warning going missing,
// and controller_test.go drives a real core.Engine through a failing renewal so
// a reword in core goes red here instead of quietly reverting a user-facing
// sentence to protocol vocabulary.
const deviceRenewFailedPrefix = "device credential: renewal failed"

// DetailFor decides whether ev should update the small secondary detail line
// beneath the headline state, and with what text. Mirrors eventStatus's own
// show/suppress rules (the retired Windows client's main.go): an error
// surfaces; info narrates the connect attempt and only matters pre-protected;
// ICE detail is redundant with the headline state itself once protected, so it
// is never separately shown. EventSession/EventConnected are plumbing, logged
// elsewhere, never surfaced here.
//
// This used to justify surfacing every error with "no client-role error source
// fires once a session is protected". That was true when it was written and is
// not true now: deviceRenewLoop (bacchus#163) runs on a ticker for the life of
// the engine and can fail at any point, mid-session included — which is
// precisely the case the renewal warning exists for, since at the moment it
// happens nothing is wrong and the user's window to act is closing. A false
// claim beside a switch on error sources is the kind of thing the next person
// adding a case trusts, so it is replaced rather than repaired: an error
// surfaces because an error is what the user needs to see, whatever the
// headline state says, and the one error source that DOES fire mid-session is
// handled explicitly below rather than by an assumption that it cannot.
func DetailFor(ev core.Event, cur ConnState) (d Detail, show bool) {
	switch ev.Kind {
	case core.EventError:
		if strings.HasPrefix(ev.Message, deviceRenewFailedPrefix) {
			return Detail{}, false
		}
		if reason, ok := strings.CutPrefix(ev.Message, relayChainFailedPrefix); ok {
			// Left verbatim, unlike the two country refusals below: the half of
			// this sentence that carries the information is core's own reason
			// string, which has no translation either way, so giving the prefix a
			// kind would translate the frame around an untranslated middle.
			return Detail{Text: "Not connected — no path met your relay-hops setting: " + reason}, true
		}
		if d, ok := countryRefusal(ev.Message); ok {
			return d, true
		}
		return Detail{Text: ev.Message}, true
	case core.EventInfo:
		if cur == Protected {
			return Detail{}, false
		}
		return Detail{Text: ev.Message}, true
	default:
		return Detail{}, false
	}
}

// coordinatorRefusedPrefix is how core reports a coordinator declining to pair
// (core/client.go's attemptWith): "coordinator refused to pair in NL:
// country-busy (…)". The country and the machine-readable reason are both in
// there, and the wire draws the country-busy / no-such-country distinction
// specifically so a client can act on it — but core hands it over as one
// sentence, so recognising it here is the only way it reaches a user as anything
// other than a line of protocol vocabulary containing the word "exit".
//
// This is a coupling to another package's message text, and it is the same
// coupling relayChainFailedPrefix above already is. It is paid for the same way:
// asserted rather than assumed. controller_test.go drives a real core.Engine
// against a coordinator that refuses, and fails if what lands on the detail line
// is not the plain-language sentence — so a reword in core goes red here instead
// of silently reverting a user-facing message to protocol jargon.
//
// It fails in the safe direction if it ever does drift: an unrecognised message
// falls through to DetailVerbatim, which is exactly what this client showed
// before the picker existed.
const coordinatorRefusedPrefix = "coordinator refused to pair in "

// countryRefusal classifies core's refusal sentence into the two refusals the
// wire names. Anything else — an unrecognised reason, a coordinator that sent a
// bare error — is not classified, so it reaches the user verbatim rather than
// being flattened into one of these two and telling them the wrong thing to do.
func countryRefusal(msg string) (Detail, bool) {
	rest, ok := strings.CutPrefix(msg, coordinatorRefusedPrefix)
	if !ok {
		return Detail{}, false
	}
	country, reason, ok := strings.Cut(rest, ": ")
	if !ok || country == "" {
		return Detail{}, false
	}
	switch {
	case strings.HasPrefix(reason, "country-busy"):
		return Detail{
			Kind:    DetailCountryBusy,
			Country: country,
			Text:    country + " is busy right now — everything there is full. Choose another country, or try again in a moment.",
		}, true
	case strings.HasPrefix(reason, "no-such-country"):
		return Detail{
			Kind:    DetailNoSuchCountry,
			Country: country,
			Text:    "Bacchus has nothing in " + country + " to connect you through. Choose another country from the list.",
		}, true
	}
	return Detail{}, false
}
