package appstate

import (
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
		name     string
		ev       core.Event
		cur      ConnState
		wantText string
		wantShow bool
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
			text, show := DetailFor(tc.ev, tc.cur)
			if show != tc.wantShow || (show && text != tc.wantText) {
				t.Fatalf("DetailFor(%+v, %v) = (%q, %v), want (%q, %v)", tc.ev, tc.cur, text, show, tc.wantText, tc.wantShow)
			}
		})
	}
}
