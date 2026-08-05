package appstate

import (
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core"
)

func TestStateFor(t *testing.T) {
	cases := []struct {
		name string
		cur  ConnState
		ev   core.Event
		want ConnState
	}{
		{
			name: "ice noise before protected is ignored",
			cur:  Connecting,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: disconnected"},
			want: Connecting,
		},
		{
			name: "ice noise while disconnected is ignored",
			cur:  Disconnected,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: connected"},
			want: Disconnected,
		},
		{
			name: "protected + disconnected reads as blocked",
			cur:  Protected,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: disconnected"},
			want: Blocked,
		},
		{
			name: "protected + failed reads as blocked",
			cur:  Protected,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: failed"},
			want: Blocked,
		},
		{
			name: "protected + closed reads as blocked",
			cur:  Protected,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: closed"},
			want: Blocked,
		},
		{
			name: "blocked + connected recovers to protected",
			cur:  Blocked,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: connected"},
			want: Protected,
		},
		{
			name: "blocked + completed recovers to protected",
			cur:  Blocked,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: completed"},
			want: Protected,
		},
		{
			name: "protected + unrelated ice message is unchanged",
			cur:  Protected,
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: checking"},
			want: Protected,
		},
		{
			name: "non-ice event never changes state",
			cur:  Protected,
			ev:   core.Event{Kind: core.EventError, Message: "peer1 ICE: disconnected"},
			want: Protected,
		},
		{
			name: "info event never changes state",
			cur:  Connecting,
			ev:   core.Event{Kind: core.EventInfo, Message: "direct failed -> trying relay"},
			want: Connecting,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StateFor(tc.cur, tc.ev); got != tc.want {
				t.Fatalf("StateFor(%v, %+v) = %v, want %v", tc.cur, tc.ev, got, tc.want)
			}
		})
	}
}

func TestDetailFor(t *testing.T) {
	cases := []struct {
		name        string
		ev          core.Event
		cur         ConnState
		wantText    string
		wantShow    bool
		wantKind    DetailKind
		wantCountry string
	}{
		{
			name:     "error always shows, even while protected",
			ev:       core.Event{Kind: core.EventError, Message: "coordinator rejected handshake"},
			cur:      Protected,
			wantText: "coordinator rejected handshake",
			wantShow: true,
		},
		{
			name:     "info shows pre-protected",
			ev:       core.Event{Kind: core.EventInfo, Message: "direct failed -> trying relay"},
			cur:      Connecting,
			wantText: "direct failed -> trying relay",
			wantShow: true,
		},
		{
			name:     "relay chain-not-built reads distinctly from a generic error (issue #28)",
			ev:       core.Event{Kind: core.EventError, Message: "[relay] chain not built: core: not enough distinct relay hops in the directory for the requested chain depth: need 2, found 1"},
			cur:      Connecting,
			wantText: "Not connected — no path met your relay-hops setting: core: not enough distinct relay hops in the directory for the requested chain depth: need 2, found 1",
			wantShow: true,
		},
		{
			name: "info is suppressed once protected",
			ev:   core.Event{Kind: core.EventInfo, Message: "direct failed -> trying relay"},
			cur:  Protected,
		},
		{
			name: "ice detail is never shown directly (it drives the headline state instead)",
			ev:   core.Event{Kind: core.EventICE, Message: "peer1 ICE: disconnected"},
			cur:  Protected,
		},
		{
			name: "session/connected plumbing is never shown",
			ev:   core.Event{Kind: core.EventConnected, Message: "connected via direct"},
			cur:  Connecting,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, show := DetailFor(tc.ev, tc.cur)
			if show != tc.wantShow || (show && d.Text != tc.wantText) {
				t.Fatalf("DetailFor(%+v, %v) = (%q, %v), want (%q, %v)", tc.ev, tc.cur, d.Text, show, tc.wantText, tc.wantShow)
			}
			if show && d.Kind != tc.wantKind {
				t.Fatalf("DetailFor(%+v, %v) classified as kind %d, want %d — the kind is what decides whether the UI can say this in the user's own language", tc.ev, tc.cur, d.Kind, tc.wantKind)
			}
			if show && d.Country != tc.wantCountry {
				t.Fatalf("DetailFor(%+v, %v) named country %q, want %q", tc.ev, tc.cur, d.Country, tc.wantCountry)
			}
		})
	}
}

// TestDetailForCountryRefusals is the country half of DetailFor, kept separate
// because its stake is different: these are the only two refusals the wire names
// deliberately (cmd/coordinator's assignRefusal), and the reason it names them
// is so a client can tell a user which of the two happened. Relaying core's own
// sentence would put the words "exit" and "quota" in front of somebody whose
// entire vocabulary for this product is "countries", and would do it in English.
//
// Mutation check: change either prefix match in countryRefusal and the matching
// case falls through to DetailVerbatim, which this names.
func TestDetailForCountryRefusals(t *testing.T) {
	cases := []struct {
		name        string
		msg         string
		wantKind    DetailKind
		wantCountry string
		wantSubstr  string
	}{
		{
			name:        "country-busy is classified and names the country",
			msg:         "coordinator refused to pair in NL: country-busy (every exit there is at capacity or out of quota — try again shortly, or choose another country)",
			wantKind:    DetailCountryBusy,
			wantCountry: "NL",
			wantSubstr:  "NL",
		},
		{
			name:        "no-such-country is classified distinctly",
			msg:         "coordinator refused to pair in ZZ: no-such-country (this coordinator knows no exit in that country — check the country code)",
			wantKind:    DetailNoSuchCountry,
			wantCountry: "ZZ",
			wantSubstr:  "ZZ",
		},
		{
			name:     "a refusal reason this client does not know stays verbatim",
			msg:      "coordinator refused to pair in DE: connect-needs-nonce (this coordinator requires a per-connect idempotency key…)",
			wantKind: DetailVerbatim,
			// Not flattened into one of the two above: telling a user to choose
			// another country when the problem is a client bug sends them round a
			// loop that cannot end.
			wantSubstr: "connect-needs-nonce",
		},
		{
			name:       "an unrelated error is untouched",
			msg:        "listen tcp 127.0.0.1:1080: bind: address already in use",
			wantKind:   DetailVerbatim,
			wantSubstr: "address already in use",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, show := DetailFor(core.Event{Kind: core.EventError, Message: tc.msg}, Connecting)
			if !show {
				t.Fatal("an error was suppressed: every error surfaces, protected or not")
			}
			if d.Kind != tc.wantKind {
				t.Fatalf("kind = %d, want %d (text %q)", d.Kind, tc.wantKind, d.Text)
			}
			if d.Country != tc.wantCountry {
				t.Fatalf("country = %q, want %q", d.Country, tc.wantCountry)
			}
			if !strings.Contains(d.Text, tc.wantSubstr) {
				t.Fatalf("text %q does not contain %q", d.Text, tc.wantSubstr)
			}
			if tc.wantKind != DetailVerbatim && strings.Contains(d.Text, "exit") {
				t.Errorf("text %q says \"exit\": issue #16 requires this client to speak in countries, and core's own refusal text is exactly what it must not relay", d.Text)
			}
		})
	}
}

// TestDetailForDropsCoresRenewalDiagnostic is bacchus#171's second part, and the
// defect the false comment above DetailFor was hiding.
//
// deviceRenewLoop fires on a ticker for the life of the engine, so a renewal
// error reaches DetailFor mid-session — the case the old comment said could not
// happen. When it does, this client has ALREADY published its own escalating
// sentence from the closure's return value, and core's event arrives afterwards
// carrying the transport's diagnostic. Surfacing it replaces a subscription
// warning with an HTTP status, on the one line the user reads.
//
// Mutation check: delete the deviceRenewFailedPrefix branch in DetailFor and
// this names the protocol string the user would have been left looking at.
func TestDetailForDropsCoresRenewalDiagnostic(t *testing.T) {
	// The message core actually emits (core/devicecred_connect.go's
	// maybeRenewDeviceCred); TestRenewalFailureEventTextIsPinned in that package
	// holds the other end, so a reword there goes red there.
	const fromCore = "device credential: renewal failed, will retry at the next check: accountclient: /v1/credential: HTTP 403"

	for _, state := range []ConnState{Connecting, Protected, Blocked, Disconnected} {
		if d, show := DetailFor(core.Event{Kind: core.EventError, Message: fromCore}, state); show {
			t.Fatalf("core's renewal diagnostic surfaced in state %d as %q, overwriting the sentence this client already showed", state, d.Text)
		}
	}

	// Only that one. Every other error still surfaces, whatever the headline
	// state says — including while protected, which is what the comment above
	// DetailFor now says outright instead of assuming it cannot happen.
	other := "device credential: renewed but could not persist the fresh credential: disk full"
	if _, show := DetailFor(core.Event{Kind: core.EventError, Message: other}, Protected); !show {
		t.Fatalf("a different device-credential error was suppressed too: %q", other)
	}
}
