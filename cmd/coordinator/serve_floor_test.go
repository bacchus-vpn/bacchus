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

	reason, ok := servingCheck("0.1.0", "any-node", 0)
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

	reason, ok := servingCheck("0.2.0", nodeID, 0)
	if ok {
		t.Fatal("the capacity floor must apply with the version fence disabled")
	}
	if !strings.Contains(reason, "below the serve floor") {
		t.Errorf("reason should be the serve floor, got %q", reason)
	}
}

// ---------------------------------------------------------------------------
// The declared-quota floor (issue #49, ADR-0040 amendment).
//
// serve_floor.min_declared_quota_bytes has been in the signed policy since #15,
// parsed and validated, with nothing reading it — there was no byte-valued input on
// the register wire to compare it against. These cover the reader.
// ---------------------------------------------------------------------------

// policyWithQuotaFloor returns the frozen fixture policy with its DECLARED-QUOTA
// floor overridden and the measured floor off, so these tests exercise one condition
// at a time. The fixture's own min_declared_quota_bytes is non-zero (100 GB), which
// is itself the reason TestUndeclaredQuotaIsAdmittedUnderANonZeroFloor matters.
func policyWithQuotaFloor(t *testing.T, floorBytes uint64) policy.Policy {
	t.Helper()
	p := fixturePolicy(t)
	p.ServeFloor.MinMeasuredBps = 0
	p.ServeFloor.MinDeclaredQuotaBytes = floorBytes
	return p
}

// TestDeclaredQuotaFloorHasNoConstantDefault is #39's property applied to this floor:
// with no policy loaded there is NO floor, because a fallback constant would be a
// floor the coordinator authored rather than one an operator signed.
func TestDeclaredQuotaFloorHasNoConstantDefault(t *testing.T) {
	withPolicyState(t, false, nil)
	if got := policyDeclaredQuotaFloor(); got != 0 {
		t.Errorf("with no policy loaded, declared-quota floor = %s, want 0", got)
	}
	if _, ok := meetsDeclaredQuotaFloor(0); !ok {
		t.Error("with no policy loaded, a node declaring nothing must serve")
	}
}

// TestDeclaredQuotaFloorIsReadFromPolicy: the floor is the signed document's, in the
// unit the signed document states it in (BYTES, not the bits/s SpeedCap rides in).
func TestDeclaredQuotaFloorIsReadFromPolicy(t *testing.T) {
	p := policyWithQuotaFloor(t, 400_000_000_000)
	withPolicyState(t, true, &p)
	if got, want := policyDeclaredQuotaFloor(), capacity.Bytes(400_000_000_000); got != want {
		t.Errorf("declared-quota floor = %s, want %s", got, want)
	}
}

// TestDeclaredQuotaFloorRefusesAnUnderDeclaringNode is the floor actually DENYING,
// which is the half that makes it enforcement rather than decoration — and the half
// that was impossible before this issue, since the coordinator had no byte-valued
// input to compare.
//
// MUTATION: drop the meetsDeclaredQuotaFloor call from servingCheck and this goes red.
func TestDeclaredQuotaFloorRefusesAnUnderDeclaringNode(t *testing.T) {
	setPolicy(t, "0.0.0", "0.2.0") // version fence off, so this is the only condition
	p := policyWithQuotaFloor(t, 400*uint64(capacity.GB))
	withPolicyState(t, true, &p)

	reason, ok := servingCheck("0.2.0", "small-node", 100*capacity.GB)
	if ok {
		t.Fatal("a node declaring less than the policy floor must not serve")
	}
	// Safe to log: the reason names the two NUMBERS and nothing that identifies the
	// node or its operator — same discipline as the version fence's reason.
	if !strings.Contains(reason, "below the serve floor") {
		t.Errorf("reason should name the serve floor, got %q", reason)
	}
	if !strings.Contains(reason, (100*capacity.GB).String()) || !strings.Contains(reason, (400*capacity.GB).String()) {
		t.Errorf("reason should name the declared quota and the floor, got %q", reason)
	}
	if strings.Contains(reason, "small-node") {
		t.Errorf("reason names the node; it is logged, so it must carry no node identity: %q", reason)
	}
}

// TestDeclaredQuotaFloorAdmitsAtAndAboveTheFloor: the boundary is inclusive, so an
// operator who declares exactly what the policy asks for is not refused by a
// strictness nobody intended.
func TestDeclaredQuotaFloorAdmitsAtAndAboveTheFloor(t *testing.T) {
	setPolicy(t, "0.0.0", "0.2.0")
	p := policyWithQuotaFloor(t, 400*uint64(capacity.GB))
	withPolicyState(t, true, &p)

	for _, declared := range []capacity.Bytes{400 * capacity.GB, 4 * capacity.TB} {
		if reason, ok := servingCheck("0.2.0", "big-node", declared); !ok {
			t.Errorf("a node declaring %s must serve under a %s floor, got %q", declared, 400*capacity.GB, reason)
		}
	}
}

// TestUndeclaredQuotaIsAdmittedUnderANonZeroFloor is the compatibility claim, and the
// single most consequential assertion in issue #49.
//
// min_declared_quota_bytes has been parsed and validated since #15 with no reader, so
// a policy in the wild may already set it — the frozen fixture bundle sets 100 GB.
// Every node predating this change declares nothing. If an absent declaration failed
// the floor, upgrading one coordinator would fence the ENTIRE fleet out of the serve
// pool in a single restart, on a floor nobody knowingly switched on.
//
// So absent means "as today", exactly as an absent SpeedCap or QuotaState does
// (ADR-0040). What that costs — the floor is skippable by declaring nothing — is
// bounded by min_serving_version in this same gate: raise it past the release that
// sends the field and "declares nothing" stops being reachable, with no code change.
//
// MUTATION: make a zero declaration fail a non-zero floor and this goes red.
func TestUndeclaredQuotaIsAdmittedUnderANonZeroFloor(t *testing.T) {
	setPolicy(t, "0.0.0", "0.2.0")
	p := policyWithQuotaFloor(t, 400*uint64(capacity.GB))
	withPolicyState(t, true, &p)

	if reason, ok := servingCheck("0.2.0", "legacy-node", 0); !ok {
		t.Fatalf("a node predating the field must be treated exactly as today, got %q", reason)
	}
}

// TestDeclaredQuotaFloorAtZeroAdmitsEveryone is what makes this ship OFF: with the
// floor unset — every policy that does not set it, and every coordinator running no
// policy at all — no declaration is too small, including none.
func TestDeclaredQuotaFloorAtZeroAdmitsEveryone(t *testing.T) {
	setPolicy(t, "0.0.0", "0.2.0")
	p := policyWithQuotaFloor(t, 0)
	withPolicyState(t, true, &p)

	for _, declared := range []capacity.Bytes{0, 1, 100 * capacity.GB} {
		if reason, ok := servingCheck("0.2.0", "any-node", declared); !ok {
			t.Errorf("with the floor at zero a node declaring %s must serve, got %q", declared, reason)
		}
	}
}

// TestVersionFenceOutranksTheQuotaFloor pins the order servingCheck applies its three
// conditions in. A node that fails both is told to update first, because that is the
// one it can act on — and because a reason naming a quota floor would send an
// operator to the wrong config file.
func TestVersionFenceOutranksTheQuotaFloor(t *testing.T) {
	setPolicy(t, "0.2.0", "0.2.0")
	p := policyWithQuotaFloor(t, 400*uint64(capacity.GB))
	withPolicyState(t, true, &p)

	reason, ok := servingCheck("0.1.0", "old-small-node", 1*capacity.GB)
	if ok {
		t.Fatal("a node failing both the version fence and the quota floor must be fenced")
	}
	if !strings.Contains(reason, "below the minimum serving version") {
		t.Errorf("the version fence should answer first, got %q", reason)
	}
}

// TestRegisterAppliesTheDeclaredQuotaFloor is the gate observed through register —
// the surface that actually decides whether a node joins the serve pool — and it
// proves the wire field reaches the floor, not just that the predicate works.
func TestRegisterAppliesTheDeclaredQuotaFloor(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)
	p := policyWithQuotaFloor(t, 400*uint64(capacity.GB))
	withPolicyState(t, true, &p)

	const nodeID = "small-exit"
	peer := fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: nodeID, Country: "rs", Addr: "203.0.113.10:20000",
		Release: "0.2.0", DeclaredQuotaBytes: 100 * uint64(capacity.GB)}, peer.LocalAddr().(*net.UDPAddr))

	if reason := readReject(t, peer); !strings.Contains(reason, "below the serve floor") {
		t.Fatalf("reject reason should name the serve floor, got %q", reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits[nodeID]; ok {
		t.Fatal("a node below the declared-quota floor must not enter the serve pool")
	}
}

// TestRegisterStoresTheDeclaredQuota: a node that clears the floor is admitted AND
// its declaration is recorded on the registry entry beside speedCap. It is read off
// every register for the reason speedCap is — the entry is replaced wholesale, so a
// field carried once would be dropped on the next refresh.
func TestRegisterStoresTheDeclaredQuota(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)
	p := policyWithQuotaFloor(t, 400*uint64(capacity.GB))
	withPolicyState(t, true, &p)

	exit, relay := fakePeer(t), fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: "e1", Country: "rs", Addr: "203.0.113.10:20000",
		Release: "0.2.0", DeclaredQuotaBytes: 4 * uint64(capacity.TB)}, exit.LocalAddr().(*net.UDPAddr))
	handle(wire{Type: "register", Role: "relay", ID: "r1", Country: "rs",
		Release: "0.2.0", DeclaredQuotaBytes: 400 * uint64(capacity.GB)}, relay.LocalAddr().(*net.UDPAddr))

	mu.Lock()
	defer mu.Unlock()
	if exits["e1"] == nil {
		t.Fatal("an exit declaring above the floor must enter the serve pool")
	}
	if got, want := exits["e1"].declaredQuota, 4*uint64(capacity.TB); got != want {
		t.Errorf("exit declaredQuota = %d, want %d", got, want)
	}
	if relays["r1"] == nil {
		t.Fatal("a relay declaring at the floor must enter the serve pool")
	}
	if got, want := relays["r1"].declaredQuota, 400*uint64(capacity.GB); got != want {
		t.Errorf("relay declaredQuota = %d, want %d", got, want)
	}
}
