package main

import (
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// TestProtectedSaysTheLocalNetworkIsGone is bacchus#257, and it is the whole of
// the fix that a test can hold: the block itself is kept (ADR-0073), so what has
// to be true is that the client SAYS it, at the moment it becomes true, and does
// not say it when it is false.
//
// Measured on hardware, connected, with the kill-switch armed: the router's own
// page and a LAN host were both refused. The allowlist is the tunnel adapter,
// the control plane, loopback and DHCP — no RFC1918 range anywhere — so every
// LAN destination falls to the default Block. Nothing in the UI said so, nothing
// in docs/ said so, and the only visible change was this band turning green.
//
// The predictable outcome of that silence is a user concluding the VPN broke
// their network and turning off the kill-switch, which is the one setting that
// must not be turned off for a bad reason.
//
// Mutation check: drop the lanBlocked branch and this names the sentence that
// went missing.
func TestProtectedSaysTheLocalNetworkIsGone(t *testing.T) {
	got := stateDescription(appstate.Protected, true, true)
	for _, want := range []string{"local network", "printers", "router"} {
		if !strings.Contains(strings.ToLower(got), want) {
			t.Errorf("the Protected line %q does not mention %q — the first thing a real user notices is undisclosed", got, want)
		}
	}
}

// TestTheLocalNetworkNoticeIsOnlyShownWhenItIsTrue is the other half, and it
// matters as much. The LAN is blocked by the FIREWALL, not by the routing: a
// directly connected subnet is an on-link route that the split-default
// (0.0.0.0/1 + 128.0.0.0/1) never overrides. So with the kill-switch off the LAN
// keeps working, and claiming otherwise would be this app's characteristic
// defect running backwards — a warning nobody can act on, attached to a session
// where the thing warned about is not happening.
//
// A proxy-only build makes no claim about the device at all, so it says neither.
func TestTheLocalNetworkNoticeIsOnlyShownWhenItIsTrue(t *testing.T) {
	for _, tc := range []struct {
		name              string
		enforced, blocked bool
	}{
		{"routed, kill-switch off", true, false},
		{"proxy-only", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stateDescription(appstate.Protected, tc.enforced, tc.blocked)
			if strings.Contains(strings.ToLower(got), "local network") {
				t.Errorf("%q claims the local network is unreachable when it is not", got)
			}
		})
	}
}

// TestTheOtherStatesAreUnchanged pins that the new parameter changed nothing
// else. Three of these four sentences are the ones ADR-0039 and bacchus#59
// argued over word by word, and a refactor is exactly how one of them quietly
// starts overclaiming again.
func TestTheOtherStatesAreUnchanged(t *testing.T) {
	cases := []struct {
		state appstate.ConnState
		want  string
	}{
		{appstate.Disconnected, "You're not protected right now."},
		{appstate.Connecting, "Finding the safest way to connect…"},
		{appstate.Blocked, "The connection dropped — trying to reconnect…"},
	}
	for _, c := range cases {
		for _, blocked := range []bool{false, true} {
			if got := stateDescription(c.state, true, blocked); got != c.want {
				t.Errorf("stateDescription(%v, true, %v) = %q, want %q", c.state, blocked, got, c.want)
			}
		}
	}
	if got, want := stateDescription(appstate.Protected, false, true),
		"Apps set to use the proxy at 127.0.0.1:1080 are protected. Other apps are not."; got != want {
		t.Errorf("the proxy-only Protected line = %q, want %q", got, want)
	}
}
