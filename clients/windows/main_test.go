//go:build windows

package main

import (
	"reflect"
	"testing"

	"github.com/bacchus-vpn/bacchus/core"
)

func TestEventStatus(t *testing.T) {
	cases := []struct {
		name      string
		ev        core.Event
		lbl       string
		protected bool
		wantText  string
		wantShow  bool
	}{
		{
			name:      "error always shows, even while protected",
			ev:        core.Event{Kind: core.EventError, Message: "coordinator rejected handshake: peer protocol version 2 is newer than 1"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Error: coordinator rejected handshake: peer protocol version 2 is newer than 1",
			wantShow:  true,
		},
		{
			name:      "error shows pre-protected too",
			ev:        core.Event{Kind: core.EventError, Message: "[direct] dial: timeout"},
			protected: false,
			wantText:  "Error: [direct] dial: timeout",
			wantShow:  true,
		},
		{
			// core/relaychain.go's file doc: chaining is fail-closed and this
			// is docs/design/relay-chaining.md §10.4's one genuinely
			// diagnostic signal — a user who asked for 2+ hops and gets a
			// generic "Error: ..." here will retry into the same directory
			// gap (issue #28). It must read differently from an ordinary
			// transient dial failure, both pre- and post-protected (a
			// chained attempt that never builds never reaches protected, but
			// eventStatus must not accidentally gate this on that).
			name:      "relay chain-not-built reads distinctly from a generic error (issue #28)",
			ev:        core.Event{Kind: core.EventError, Message: "[relay] chain not built: core: not enough distinct relay hops in the directory for the requested chain depth: need 2, found 1"},
			protected: false,
			wantText:  "Not connected — no path met your relay-hops setting: core: not enough distinct relay hops in the directory for the requested chain depth: need 2, found 1",
			wantShow:  true,
		},
		{
			name:      "info shows pre-protected",
			ev:        core.Event{Kind: core.EventInfo, Message: "direct failed -> trying relay…"},
			protected: false,
			wantText:  "direct failed -> trying relay…",
			wantShow:  true,
		},
		{
			name:      "info is suppressed once protected",
			ev:        core.Event{Kind: core.EventInfo, Message: "direct failed -> trying relay…"},
			protected: true,
			wantShow:  false,
		},
		{
			name:      "ice is suppressed before protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: connected"},
			protected: false,
			wantShow:  false,
		},
		{
			name:      "ice disconnected reads as blocked once protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: disconnected"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Blocked — tunnel down (us exit1)",
			wantShow:  true,
		},
		{
			name:      "ice failed reads as blocked once protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: failed"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Blocked — tunnel down (us exit1)",
			wantShow:  true,
		},
		{
			name:      "ice closed reads as blocked once protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: closed"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Blocked — tunnel down (us exit1)",
			wantShow:  true,
		},
		{
			name:      "ice connected reads as protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: connected"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Protected — us exit1",
			wantShow:  true,
		},
		{
			name:      "ice completed reads as protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: completed"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Protected — us exit1",
			wantShow:  true,
		},
		{
			name:      "ice with an unrecognized state is ignored",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: checking"},
			protected: true,
			wantShow:  false,
		},
		{
			name:      "session is never shown live",
			ev:        core.Event{Kind: core.EventSession, Message: "[direct] session: abc123"},
			protected: false,
			wantShow:  false,
		},
		{
			name:      "connected is never shown live (connect() already narrates it)",
			ev:        core.Event{Kind: core.EventConnected, Message: "connected DIRECT to exit"},
			protected: false,
			wantShow:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotText, gotShow := eventStatus(tc.ev, tc.lbl, tc.protected)
			if gotShow != tc.wantShow {
				t.Fatalf("show = %v, want %v", gotShow, tc.wantShow)
			}
			if gotShow && gotText != tc.wantText {
				t.Fatalf("text = %q, want %q", gotText, tc.wantText)
			}
		})
	}
}

// TestRebuildRecoveryConfigReplacesOnlyCoordinatorsAndProof is the
// config-carrying-forward proof for issue #122's mid-session mesh-walk
// recovery: a rebuild must adopt the freshly rediscovered coordinators and
// proof but leave every other connect-time setting — ExitID, the transport
// pool, admission, OnUnderlayDial, … — exactly as connect() built it.
// Reverting rebuildRecoveryConfig to (say) also reset ExitID or drop
// AdmissionCRLPath would silently disable exit pinning or revocation
// checking on every mid-session recovery; this test catches that class of
// mistake without needing a running engine.
func TestRebuildRecoveryConfigReplacesOnlyCoordinatorsAndProof(t *testing.T) {
	base := core.Config{
		Coordinators:     []string{"203.0.113.1:51820"},
		Roles:            []string{core.RoleClient},
		SocksAddr:        "127.0.0.1:1080",
		ExitID:           "deadbeef",
		Geo:              "de",
		TransportPool:    []string{"reality", "webrtc"},
		SelectionDir:     `C:\selection`,
		STUNURL:          "stun:203.0.113.2:3478",
		TURNURL:          "turn:203.0.113.3:3478",
		TURNUser:         "u",
		TURNPass:         "p",
		ForceRelay:       true,
		AdmissionPubKey:  "abcd",
		AdmissionCRLPath: `C:\crl.bin`,
		MeshPeers:        []string{"198.51.100.9:3478"},
		MeshProof:        []byte("old-proof"),
	}
	dialCount := 0
	base.OnUnderlayDial = func(string) { dialCount++ }

	fresh := []string{"192.0.2.1:51820", "192.0.2.2:51820"}
	freshProof := []byte("new-proof")
	got := rebuildRecoveryConfig(base, fresh, freshProof)

	if !reflect.DeepEqual(got.Coordinators, fresh) {
		t.Fatalf("Coordinators = %v, want %v", got.Coordinators, fresh)
	}
	if !reflect.DeepEqual(got.MeshProof, freshProof) {
		t.Fatalf("MeshProof = %v, want %v", got.MeshProof, freshProof)
	}

	got.OnUnderlayDial("1.2.3.4") // proves the func value itself survived, not just its zero-ness
	if dialCount != 1 {
		t.Fatalf("OnUnderlayDial was not preserved across the rebuild")
	}

	// Blanket-check everything else: neutralize the func field (DeepEqual on a
	// non-nil func is always false, even for the identical value) and the two
	// fields already proven above, then the rest must be byte-for-byte
	// unchanged from base.
	got.OnUnderlayDial, base.OnUnderlayDial = nil, nil
	got.Coordinators, got.MeshProof = base.Coordinators, base.MeshProof
	if !reflect.DeepEqual(got, base) {
		t.Fatalf("rebuildRecoveryConfig altered a field it must preserve:\n got  = %+v\n want = %+v", got, base)
	}
}
