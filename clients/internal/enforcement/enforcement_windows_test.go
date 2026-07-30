//go:build windows

package enforcement

import "testing"

// TestReserveBeforeStartSurvivesIntoBringUp is issue #109's ordering at the
// Enforcer level, and the reason ReserveUnderlay is on Enforcer and not only
// on Session.
//
// The transport pool dials its first reality underlay inside core's Connect,
// which happens BEFORE enforcement starts — so at that moment there is no
// Session to hand the address to. If the Enforcer dropped it, or handed the
// session a fresh excluder that never saw it, that first underlay would never
// be excluded and the connection carrying the whole tunnel would loop into
// the tunnel (or, once armed, be blocked by its own kill-switch).
func TestReserveBeforeStartSurvivesIntoBringUp(t *testing.T) {
	f := newFakeOS()
	e := newWindowsEnforcerWith(f)

	e.ReserveUnderlay("198.51.100.7:443") // the pre-tunnel dial

	sess, err := e.Start(testPolicy(false, BypassModeExclude, nil), reserveLoopbackAddr(t))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(sess.Close)

	if indexOf(f.seq(), "exclude 198.51.100.7") < 0 {
		t.Fatalf("an underlay reserved before Start was never excluded during bring-up (issue #109)\nsequence: %v", f.seq())
	}
}

// TestReserveAfterStartInstallsLive is the failover half: an address dialled
// mid-session must be excluded on the dial path, not recorded for a bring-up
// that already happened.
func TestReserveAfterStartInstallsLive(t *testing.T) {
	f := newFakeOS()
	e := newWindowsEnforcerWith(f)

	sess, err := e.Start(testPolicy(false, BypassModeExclude, nil), reserveLoopbackAddr(t))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(sess.Close)

	// Both entry points reach the same excluder — a caller holding only the
	// Session and a caller still wired to the Enforcer must not diverge.
	e.ReserveUnderlay("198.51.100.8:443")
	sess.ReserveUnderlay("198.51.100.9:443")

	for _, ip := range []string{"198.51.100.8", "198.51.100.9"} {
		if indexOf(f.seq(), "exclude "+ip) < 0 {
			t.Errorf("a mid-session underlay dial to %s was not excluded live\nsequence: %v", ip, f.seq())
		}
	}
}

// TestSessionCloseIsIdempotent guards a double Close. tunnel.Close is not
// idempotent on its own: run twice it re-removes routes and re-lifts a
// kill-switch — which, if a NEWER session has armed one in between, disarms
// the live session's lockdown. Disconnect paths are reached from a UI button
// and from a failed connect's unwind, so twice is reachable.
func TestSessionCloseIsIdempotent(t *testing.T) {
	f := newFakeOS()
	e := newWindowsEnforcerWith(f)

	sess, err := e.Start(testPolicy(true, BypassModeExclude, nil), reserveLoopbackAddr(t))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sess.Close()

	f.mu.Lock()
	f.ops = nil
	f.mu.Unlock()

	sess.Close() // the second one must do nothing at all

	if ops := f.seq(); len(ops) != 0 {
		t.Errorf("a second Close touched the OS again: %v", ops)
	}
}

// TestReconnectGetsAFreshExcluder: the addresses of the last session are gone
// with its routes, so carrying them into the next connect would put stale
// entries in that session's kill-switch allowlist and its teardown.
func TestReconnectGetsAFreshExcluder(t *testing.T) {
	f := newFakeOS()
	e := newWindowsEnforcerWith(f)

	e.ReserveUnderlay("198.51.100.7:443")
	first, err := e.Start(testPolicy(false, BypassModeExclude, nil), reserveLoopbackAddr(t))
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	first.Close()

	f.dev = newMemTun() // the first session closed the old one
	f.mu.Lock()
	f.ops = nil
	f.mu.Unlock()

	second, err := e.Start(testPolicy(false, BypassModeExclude, nil), reserveLoopbackAddr(t))
	if err != nil {
		t.Fatalf("second Start: %v", err)
	}
	t.Cleanup(second.Close)

	if indexOf(f.seq(), "exclude 198.51.100.7") >= 0 {
		t.Errorf("the second session re-excluded the first session's underlay address\nsequence: %v", f.seq())
	}
}

// TestRecoverRunsBeforeAnyConnect is parity item 3's shape at this level:
// Recover must work on a freshly constructed Enforcer, with no Start ever
// having happened, because that is exactly the situation after a crash.
func TestRecoverRunsBeforeAnyConnect(t *testing.T) {
	f := newFakeOS()
	e := newWindowsEnforcerWith(f)

	e.Recover()

	if indexOf(f.seq(), "recoverKillSwitch") < 0 {
		t.Errorf("Recover did nothing on a fresh Enforcer, so a lockdown left by a killed session survives launch\nsequence: %v", f.seq())
	}
}
