//go:build linux

package appstate

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/clients/internal/enforcement"
)

// TestEachHelperFailureKeepsItsOwnSentence pins the reason
// ErrHelperUnreachable, ErrHelperBusy and ErrHelperVersion are three values
// instead of one: the user's next action differs for each. Install the helper.
// Close the other Bacchus. The two binaries disagree and one of them has to
// change. A controller that flattened them into "could not route this device"
// would leave a user staring at a failure with nothing to do about it, and
// ErrHelperUnreachable's own doc promises the opposite — "clients/fyne shows
// the user a different sentence for it".
//
// It promises that without clients/fyne branching on the value anywhere, which
// is worth being explicit about: nothing outside clients/internal/enforcement
// mentions these errors at all. The distinct sentences exist ONLY because
// startEnforcement wraps with %w and abort hands err.Error() straight to the
// detail line. Both halves are one edit away from being untrue — %w to %v, or
// a tidy-looking generic message — and neither edit fails any other test.
//
// This file is Linux-tagged because the three values are (enforcement_linux.go
// is //go:build linux), and appstate itself still builds for windows and darwin.
//
// Driven through startEnforcement and abort rather than a full connect: that
// pair IS the shaping-and-delivery path for this branch, three more ICE
// negotiations would not make the string any more real, and
// TestEnforcementFailureAbortsTheConnect already proves a live connect delivers
// Start's error to exactly this line.
func TestEachHelperFailureKeepsItsOwnSentence(t *testing.T) {
	cases := []struct {
		name     string
		sentinel error
		// from is the error as the Linux Enforcer actually returns it —
		// translateRefusal wraps the sentinel with the helper's own message
		// (enforcement_linux.go), so this is the shape the controller meets
		// rather than a bare sentinel it never sees.
		from error
	}{
		{"unreachable", enforcement.ErrHelperUnreachable, enforcement.ErrHelperUnreachable},
		{"busy", enforcement.ErrHelperBusy, fmt.Errorf("%w: enforcement is already held", enforcement.ErrHelperBusy)},
		{"version", enforcement.ErrHelperVersion, fmt.Errorf("%w: helper speaks v2, client speaks v1", enforcement.ErrHelperVersion)},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enf := &fakeEnforcer{startErrs: []error{tc.from}}
			c := newEnforcedController(Config{Coordinators: []string{"127.0.0.1:9"}}, enf)
			var details []string
			c.OnState = func(ConnState) {}
			c.OnDetail = func(s string) { details = append(details, s) }

			_, err := c.startEnforcement(false)
			if err == nil {
				t.Fatal("startEnforcement returned no error for a helper that refused")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("errors.Is(%v, %v) is false: the controller's wrap dropped the sentinel, so nothing above this seam can ever tell one helper failure from another", err, tc.sentinel)
			}

			// The real failure sequence: connectAsync hands exactly this error
			// to abort, which puts it on screen before the state lands.
			c.mu.Lock()
			c.gen, c.state = 1, Connecting
			c.mu.Unlock()
			c.abort(1, err)

			if len(details) != 1 {
				t.Fatalf("the user was given %d detail lines, want 1: %v", len(details), details)
			}
			got := details[0]
			if !strings.Contains(got, "could not route this device") || !strings.Contains(got, tc.sentinel.Error()) {
				t.Errorf("detail line = %q\nwant it to name BOTH the failure (%q) and what the user can do about it (%q)",
					got, "could not route this device", tc.sentinel.Error())
			}
			if prev, dup := seen[got]; dup {
				t.Errorf("%s and %s produce the identical sentence %q: the two need different actions from the user and are indistinguishable on screen", prev, tc.name, got)
			}
			seen[got] = tc.name
		})
	}
	if len(seen) != len(cases) {
		t.Fatalf("%d distinct sentences for %d distinct helper failures", len(seen), len(cases))
	}
}
