package enforcement

import (
	"errors"
	"strings"
	"testing"
)

// servingPolicy is testPolicy with the serve-while-routed carve-out asked for.
func servingPolicy(killSwitch bool) Policy {
	p := testPolicy(killSwitch, BypassModeExclude, nil)
	p.ServeEgress = true
	return p
}

// TestServedEgressIsCarvedOutAfterTheRouteAndBeforeTheLockdown pins both ends
// of where the carve-out sits in bring-up, and each end is a different failure.
//
// Before the split-default route, it would be an exception to a route that does
// not exist yet — a rule overriding nothing. After the kill-switch, the
// allowance would have to be added to an already-armed lockdown, and the
// platform builds it into the arming transaction (see the helper's refusal in
// handleAllowServedEgress), so there would be an instant where this machine is
// serving and its own kill-switch is dropping what it serves.
func TestServedEgressIsCarvedOutAfterTheRouteAndBeforeTheLockdown(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, servingPolicy(true))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	t.Cleanup(tn.Close)

	ops := f.seq()
	mustBefore(t, ops, "splitDefault", "allowServedEgress",
		"a carve-out installed before the tunnel's own route is an exception to nothing")
	mustBefore(t, ops, "allowServedEgress", "enableKillSwitch",
		"the served allowance is built into the arming transaction, so the carve-out has to exist before the lockdown is armed")

	if tn.servedSource != servedSource {
		t.Errorf("tunnel kept servedSource %q, want %q — core binds what this reports", tn.servedSource, servedSource)
	}
}

// TestKillSwitchStaysTheLastCallEvenWhenServing guards the invariant
// tunnel_test.go already pins for the non-serving path. It is repeated here
// rather than assumed because the carve-out is the first thing ever inserted
// between captureDNS and the arming, and "last" is what makes the machine
// never briefly routed-but-unlocked.
func TestKillSwitchStaysTheLastCallEvenWhenServing(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, servingPolicy(true))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	t.Cleanup(tn.Close)

	ops := f.seq()
	if last := ops[len(ops)-1]; !strings.HasPrefix(last, "enableKillSwitch") {
		t.Errorf("bring-up ended with %q, want enableKillSwitch: sequence %v", last, ops)
	}
}

// TestNotServingNeverAsksForACarveOut is the default path, and the reason it
// gets its own test is that the carve-out widens what the machine may do. A
// session that never opted into serving must not acquire it, or every ordinary
// user gets an exception to their own kill-switch for a feature they did not
// turn on.
func TestNotServingNeverAsksForACarveOut(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, testPolicy(true, BypassModeExclude, nil))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	t.Cleanup(tn.Close)

	if i := indexOf(f.seq(), "allowServedEgress"); i >= 0 {
		t.Errorf("a non-serving session asked for a served-egress carve-out: %v", f.seq())
	}
	if tn.servedSource != "" {
		t.Errorf("servedSource = %q on a non-serving session, want empty", tn.servedSource)
	}
}

// TestACarveOutThatFailsAbortsTheConnect is the fail-closed posture, and it is
// the opposite of what every other route mutator in bring-up does.
//
// A missing exclusion route fails safe — the dial loops into the tunnel or is
// blocked. A missing carve-out does not: the served traffic still flows, out
// through the tunnel, under the upstream exit's address, while the settings
// window's disclosure says it left under this machine's. There is no degraded
// mode that is honest, so bring-up unwinds.
func TestACarveOutThatFailsAbortsTheConnect(t *testing.T) {
	f := newFakeOS()
	boom := errors.New("no routable address on the physical interface")
	f.fail["allowServedEgress"] = boom

	tn, err := startForTest(t, f, servingPolicy(true))
	if err == nil {
		tn.Close()
		t.Fatal("startTunnel succeeded with no carve-out. The session would serve other people's traffic through the tunnel while claiming it left under this machine's address")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap the platform's own failure", err)
	}
	if i := indexOf(f.seq(), "enableKillSwitch"); i >= 0 {
		t.Errorf("the kill-switch was armed after the carve-out failed: %v", f.seq())
	}
}

// TestAFailedBringUpGivesTheCarveOutBack covers the unwind path. A carve-out
// left behind by a bring-up that then failed is an exception to a lockdown that
// was never armed and a route past a tunnel that does not exist — pure residue,
// and residue that widens what the machine may do.
func TestAFailedBringUpGivesTheCarveOutBack(t *testing.T) {
	f := newFakeOS()
	f.fail["enableKillSwitch"] = errors.New("nftables refused")

	if tn, err := startForTest(t, f, servingPolicy(true)); err == nil {
		tn.Close()
		t.Fatal("startTunnel succeeded with a failed kill-switch")
	}
	ops := f.seq()
	if indexOf(ops, "allowServedEgress") < 0 {
		t.Fatalf("the carve-out never happened, so this test proves nothing: %v", ops)
	}
	if indexOf(ops, "revokeServedEgress") < 0 {
		t.Errorf("a failed bring-up left the carve-out installed: %v", ops)
	}
}

// TestCloseRevokesTheCarveOutBeforeLiftingTheLockdown pins the teardown order.
//
// Either order restores the machine — once the lockdown is gone everything is
// permitted anyway — but this one makes a stronger sentence true: the carve-out
// never outlives the lockdown it was an exception to. The crash path in
// bacchus-netd follows the same rule for a reason that is not cosmetic there
// (it holds the lockdown and drops the carve-out), so having both obey it means
// there is one rule to check rather than two orders to reason about.
func TestCloseRevokesTheCarveOutBeforeLiftingTheLockdown(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, servingPolicy(true))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	tn.Close()

	ops := f.seq()
	mustBefore(t, ops, "revokeServedEgress", "disableKillSwitch",
		"the carve-out must never outlive the lockdown it was an exception to")
}

// TestCloseWithoutServingDoesNotRevoke keeps teardown quiet on the default
// path: a session that never carved anything out has nothing to give back, and
// a spurious revoke would delete a rule belonging to nobody.
func TestCloseWithoutServingDoesNotRevoke(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, testPolicy(true, BypassModeExclude, nil))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	tn.Close()

	if i := indexOf(f.seq(), "revokeServedEgress"); i >= 0 {
		t.Errorf("a non-serving session revoked a carve-out it never had: %v", f.seq())
	}
}
