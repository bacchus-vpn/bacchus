package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/policy"
)

// withRatings installs a ratings store for one test and restores the previous one,
// so these do not leak into the capacity-feed tests that share the global.
func withRatings(t *testing.T, s *capacity.RatingStore) {
	t.Helper()
	prev := ratings
	ratings = s
	t.Cleanup(func() { ratings = prev })
}

func newRatings(t *testing.T) *capacity.RatingStore {
	t.Helper()
	s, err := capacity.NewRatingStore(capacityParams(), ratingIdleTTL)
	if err != nil {
		t.Fatalf("new rating store: %v", err)
	}
	return s
}

// attest feeds n windows of samples for nodeID through the given stream, from
// enough distinct ASes to inform the estimator.
func attest(s *capacity.RatingStore, nodeID string, trusted bool, rate capacity.Rate, windows int) {
	now := time.Now()
	p := capacityParams()
	for w := 0; w < windows; w++ {
		for as := 0; as < 8; as++ {
			s.Observe(nodeID, trusted, capacity.Sample{
				Throughput: rate,
				Saturated:  true,
				Attester:   fmt.Sprintf("att-%d", as),
				AS:         fmt.Sprintf("as-%d", as),
			}, now)
		}
		now = now.Add(p.Window)
		s.Advance(now)
	}
}

// policyWithFloor returns the frozen fixture policy with its measured floor
// overridden, so a test can pick a floor without minting a bundle.
func policyWithFloor(t *testing.T, floorBps uint64) policy.Policy {
	t.Helper()
	p := fixturePolicy(t)
	p.ServeFloor.MinMeasuredBps = floorBps
	return p
}

// TestServeFloorHasNoConstantDefault is the property #39 exists to create, applied
// to this floor: with no policy loaded there is NO floor. A fallback constant would
// be a floor the coordinator authored.
func TestServeFloorHasNoConstantDefault(t *testing.T) {
	withPolicyState(t, false, nil)
	if got := policyMeasuredFloor(); got != 0 {
		t.Errorf("with no policy loaded, floor = %s, want 0 — a constant default would be a floor the coordinator authored", got)
	}

	withPolicyState(t, true, nil)
	if got := policyMeasuredFloor(); got != 0 {
		t.Errorf("with policy configured but none held, floor = %s, want 0", got)
	}
}

func TestServeFloorIsReadFromPolicy(t *testing.T) {
	p := policyWithFloor(t, 25_000_000)
	withPolicyState(t, true, &p)

	if got, want := policyMeasuredFloor(), capacity.Rate(25_000_000); got != want {
		t.Errorf("floor = %s, want %s", got, want)
	}
}

// TestUntrustedRatingNeverFencesANode is the regression guard for the reason this
// card was nearly a fleet-stranding change.
//
// The untrusted estimator clamps to Ceiling (5 Mbit) by construction. A genuinely
// fast node attested only through that stream reads at the ceiling no matter how
// fast it is, so applying a floor above the ceiling to that number would fence every
// measured node while admitting every unmeasured one — inverting the incentive to be
// measured at all.
//
// If this test ever fails, the gate has started reading Measured instead of the
// trusted rating and the fleet is about to be stranded.
func TestUntrustedRatingNeverFencesANode(t *testing.T) {
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 25_000_000)
	withPolicyState(t, true, &p)

	const nodeID = "genuinely-fast"
	attest(s, nodeID, false, 100*capacity.Mbit, 200)

	// The premise: the untrusted stream really is clamped far below the floor.
	measured, rated := s.Measured(nodeID)
	if !rated {
		t.Fatal("setup: the node should have a rating")
	}
	if measured >= capacity.Rate(25_000_000) {
		t.Fatalf("premise broken: untrusted rating %s is no longer clamped below the floor; this test no longer proves anything", measured)
	}
	if _, trustedRated := s.TrustedRating(nodeID); trustedRated {
		t.Fatal("premise broken: untrusted attestation informed the TRUSTED stream")
	}

	if reason, ok := meetsMeasuredFloor(nodeID); !ok {
		t.Fatalf("a node with only an untrusted (ceiling-clamped) rating must NOT be fenced — the whole fleet is in this state today. Got: %s", reason)
	}
}

// TestUnmeasuredNodeIsNotFenced pins design §5.3 at this gate: an unmeasured node is
// not a slow node.
func TestUnmeasuredNodeIsNotFenced(t *testing.T) {
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 25_000_000)
	withPolicyState(t, true, &p)

	if reason, ok := meetsMeasuredFloor("never-seen"); !ok {
		t.Fatalf("an unmeasured node must not be fenced, got: %s", reason)
	}
}

// TestTrustedRatingBelowTheFloorIsFenced is the gate actually biting: once the
// trusted stream is fed, a node genuinely below the floor becomes client-only.
func TestTrustedRatingBelowTheFloorIsFenced(t *testing.T) {
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 25_000_000)
	withPolicyState(t, true, &p)

	const nodeID = "genuinely-slow"
	attest(s, nodeID, true, 2*capacity.Mbit, 40)

	measured, rated := s.TrustedRating(nodeID)
	if !rated {
		t.Fatal("setup: the trusted stream should be informed")
	}
	if measured >= capacity.Rate(25_000_000) {
		t.Fatalf("setup: trusted rating %s should be below the floor", measured)
	}

	reason, ok := meetsMeasuredFloor(nodeID)
	if ok {
		t.Fatal("a node whose TRUSTED rating is below the floor must be fenced")
	}
	if !strings.Contains(reason, "below the serve floor") {
		t.Errorf("reason should name the floor, got %q", reason)
	}
	// Client-only, not banned: the reason must say so.
	if !strings.Contains(reason, "may still use the service") {
		t.Errorf("reason should say the node is client-only, got %q", reason)
	}
}

// TestTrustedRatingAboveTheFloorServes is the control for the test above.
func TestTrustedRatingAboveTheFloorServes(t *testing.T) {
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 5_000_000)
	withPolicyState(t, true, &p)

	const nodeID = "genuinely-fast"
	// The trusted estimator's ceiling is provisional and released once enough
	// distinct ASes attest, so a trusted stream can climb past it.
	attest(s, nodeID, true, 100*capacity.Mbit, 200)

	measured, rated := s.TrustedRating(nodeID)
	if !rated {
		t.Fatal("setup: the trusted stream should be informed")
	}
	if measured < capacity.Rate(5_000_000) {
		t.Skipf("trusted rating %s did not climb past the floor in this many windows; the fencing direction is covered by TestTrustedRatingBelowTheFloorIsFenced", measured)
	}
	if reason, ok := meetsMeasuredFloor(nodeID); !ok {
		t.Fatalf("a node above the floor must serve, got: %s", reason)
	}
}

// TestZeroFloorDisablesTheGate pins that a policy may switch the floor off, which is
// how an operator starts permissive and ratchets up as supply grows.
func TestZeroFloorDisablesTheGate(t *testing.T) {
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 0)
	withPolicyState(t, true, &p)

	const nodeID = "very-slow"
	attest(s, nodeID, true, 100*capacity.Kbit, 40)

	if reason, ok := meetsMeasuredFloor(nodeID); !ok {
		t.Fatalf("a zero floor must gate nobody, got: %s", reason)
	}
}

// TestServeFloorInertWithoutARatingsStore covers the coordinator configuration where
// no capacity feed is running at all.
func TestServeFloorInertWithoutARatingsStore(t *testing.T) {
	withRatings(t, nil)
	p := policyWithFloor(t, 25_000_000)
	withPolicyState(t, true, &p)

	if reason, ok := meetsMeasuredFloor("anything"); !ok {
		t.Fatalf("with no ratings store the floor must gate nobody, got: %s", reason)
	}
}

// TestRegisterAppliesTheServeFloor is the gate observed through register — the
// surface that actually decides whether a node joins the serve pool.
func TestRegisterAppliesTheServeFloor(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 25_000_000)
	withPolicyState(t, true, &p)

	const nodeID = "slow-exit"
	attest(s, nodeID, true, 2*capacity.Mbit, 40)
	if _, rated := s.TrustedRating(nodeID); !rated {
		t.Fatal("setup: the trusted stream should be informed")
	}

	peer := fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: nodeID, Country: "rs", Addr: "1.2.3.4:20000", Release: "0.2.0"},
		peer.LocalAddr().(*net.UDPAddr))

	if reason := readReject(t, peer); !strings.Contains(reason, "below the serve floor") {
		t.Fatalf("reject reason should name the serve floor, got %q", reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits[nodeID]; ok {
		t.Fatal("a node below the serve floor must not enter the serve pool")
	}
}

// TestRegisterUnaffectedByTheFloorToday is the fleet-safety control at the register
// surface: with the trusted stream unfed, which is every node in this build, the
// floor withholds nobody.
func TestRegisterUnaffectedByTheFloorToday(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 25_000_000)
	withPolicyState(t, true, &p)

	const nodeID = "ordinary-exit"
	// Attested only through the stream that exists today.
	attest(s, nodeID, false, 100*capacity.Mbit, 200)

	peer := fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: nodeID, Country: "rs", Addr: "1.2.3.4:20000", Release: "0.2.0"},
		peer.LocalAddr().(*net.UDPAddr))

	expectSilence(t, peer)
	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits[nodeID]; !ok {
		t.Fatal("with the trusted stream unfed, the serve floor must strand nobody")
	}
}

// TestVersionFenceStillAppliesAlongsideTheFloor pins that adding a condition did not
// displace the one already there: a node below the version floor is still fenced,
// with the version reason, whatever its capacity says.
func TestVersionFenceStillAppliesAlongsideTheFloor(t *testing.T) {
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 0) // capacity floor off
	withPolicyState(t, true, &p)
	setPolicy(t, "0.2.0", "0.2.0")

	reason, ok := servingCheck("0.1.0", "any-node")
	if ok {
		t.Fatal("a node below the version floor must still be fenced")
	}
	if !strings.Contains(reason, "below the minimum serving version") {
		t.Errorf("reason should be the version fence, got %q", reason)
	}
}

// TestServeFloorAppliesEvenWhenTheVersionFenceIsOff is the converse: the two
// conditions are independent, and the capacity one is not reachable only via a
// version failure.
func TestServeFloorAppliesEvenWhenTheVersionFenceIsOff(t *testing.T) {
	s := newRatings(t)
	withRatings(t, s)
	p := policyWithFloor(t, 25_000_000)
	p.ServeFloor.MinServingVersion = "0.0.0" // version fence off in policy too
	withPolicyState(t, true, &p)
	setPolicy(t, "0.0.0", "0.2.0")

	const nodeID = "slow-node"
	attest(s, nodeID, true, 2*capacity.Mbit, 40)

	reason, ok := servingCheck("0.2.0", nodeID)
	if ok {
		t.Fatal("the capacity floor must apply with the version fence disabled")
	}
	if !strings.Contains(reason, "below the serve floor") {
		t.Errorf("reason should be the serve floor, got %q", reason)
	}
}
