package capacity

import (
	"testing"
	"time"
)

// These tests pin the owner decision of old #157 (design §8.1.1) as encoded in
// NodeRating, and the coordinator-side lifecycle of RatingStore (§8.6). Like the
// estimator simulations, each pins one rule; if one fails, the decision is not
// implemented, not the test.

// ratingParams is the estimator config the tests share. Explicit values (not
// DefaultParams) so a change to the production defaults never silently moves a
// boundary a test below asserts against.
func ratingParams() Params {
	return Params{
		Window:        time.Minute,
		Quantile:      0.25,
		RiseFactor:    1.25,
		RiseThreshold: 0.9,
		FallThreshold: 0.7,
		MinASes:       2,
		Ceiling:       5 * Mbit,
		CeilingASes:   3,
		Floor:         256 * Kbit,
		HalfLife:      24 * time.Hour,
	}
}

func newTestRating(t *testing.T, p Params) *NodeRating {
	t.Helper()
	r, err := NewNodeRating(p, epoch)
	if err != nil {
		t.Fatalf("NewNodeRating: %v", err)
	}
	return r
}

// feedUntrusted / feedTrusted run one window on the named stream.
func feedUntrusted(r *NodeRating, now time.Time, samples ...Sample) Rate {
	for _, s := range samples {
		r.ObserveUntrusted(s)
	}
	return r.Advance(now)
}
func feedTrusted(r *NodeRating, now time.Time, samples ...Sample) Rate {
	for _, s := range samples {
		r.ObserveTrusted(s)
	}
	return r.Advance(now)
}

// TestUntrustedNeverExceedsCeiling is rule 3: the untrusted stream is clamped to
// Ceiling INSIDE the estimator, so no amount of unvouched attestation — any rate, from
// any number of ASes, for any number of windows — lifts a node above it. The feed rate
// (100 Mbit) is two orders over Ceiling on purpose; without the clamp the ratchet would
// sail past 5 Mbit within ~14 windows.
func TestUntrustedNeverExceedsCeiling(t *testing.T) {
	p := ratingParams()
	r := newTestRating(t, p)

	now := epoch
	// Four ASes clears CeilingASes (3), which for the TRUSTED stream would release the
	// provisional ceiling — the untrusted stream must ignore that release.
	high := fromASes("attacker-", 4, 100*Mbit)
	for i := 0; i < 40; i++ {
		now = now.Add(p.Window)
		m := feedUntrusted(r, now, high...)
		if m > p.Ceiling {
			t.Fatalf("window %d: untrusted rating %s exceeded the ceiling %s — the HardCeiling clamp is not holding", i, m, p.Ceiling)
		}
	}
	// Non-vacuity: it must actually have RISEN to the ceiling, so the assertion above is
	// a real bound and not "the feed never moved it".
	if got := r.Measured(); got != p.Ceiling {
		t.Fatalf("untrusted rating settled at %s after sustained max attestation; want exactly the ceiling %s", got, p.Ceiling)
	}
}

// TestTrustedCanExceedCeilingAndDecides is the other side of rule 3 and the core of
// rule 2: the trusted stream is NOT clamped (vouched attestation earns a rating above
// Ceiling), and where it exists it is the number Measured returns.
func TestTrustedCanExceedCeilingAndDecides(t *testing.T) {
	p := ratingParams()
	r := newTestRating(t, p)

	now := epoch
	high := fromASes("vouched-", 4, 100*Mbit) // 4 >= CeilingASes: releases the provisional ceiling
	for i := 0; i < 40; i++ {
		now = now.Add(p.Window)
		feedTrusted(r, now, high...)
	}
	if got := r.Measured(); got <= p.Ceiling {
		t.Fatalf("trusted rating = %s after sustained vouched attestation; a vouched stream must be able to earn above the ceiling %s", got, p.Ceiling)
	}
	st := r.Status()
	if st.Measured != st.Trusted.Estimate {
		t.Fatalf("Measured %s did not follow the trusted estimate %s — trusted must decide where it exists", st.Measured, st.Trusted.Estimate)
	}
}

// TestTrustedDecidesEvenWhenLowerThanUntrusted is rule 2 at its sharpest: trusted
// decides OUTRIGHT — no weighted average, no max, no tiebreak. A node whose trusted
// (vouched) evidence rates it BELOW its cheaply-forged untrusted ceiling must report the
// trusted number, not the higher untrusted one. A max() or a blend fails this.
func TestTrustedDecidesEvenWhenLowerThanUntrusted(t *testing.T) {
	p := ratingParams()
	r := newTestRating(t, p)

	now := epoch
	lowTrusted := fromASes("vouched-", 3, 1*Mbit) // real vouched evidence: this node is ~1 Mbit
	highUntrusted := fromASes("forged-", 4, Gbit) // cheap forgery: "it's a gigabit!"
	for i := 0; i < 40; i++ {
		now = now.Add(p.Window)
		for _, s := range lowTrusted {
			r.ObserveTrusted(s)
		}
		for _, s := range highUntrusted {
			r.ObserveUntrusted(s)
		}
		r.Advance(now)
	}
	st := r.Status()
	if st.Untrusted.Estimate != p.Ceiling {
		t.Fatalf("setup: untrusted did not reach the ceiling (%s); the forged high feed should pin it there", st.Untrusted.Estimate)
	}
	if st.Measured != st.Trusted.Estimate {
		t.Fatalf("Measured = %s, want the trusted estimate %s: trusted must decide outright, never be blended with or dominated by untrusted", st.Measured, st.Trusted.Estimate)
	}
	if st.Measured >= st.Untrusted.Estimate {
		t.Fatalf("Measured %s is not below the untrusted ceiling %s: a lower trusted rating was dragged UP by untrusted (a max/blend)", st.Measured, st.Untrusted.Estimate)
	}
}

// TestUnfedTrustedFallsBackToUntrusted is the whole v1 posture and the seam: with the
// trusted stream PERMANENTLY EMPTY (no vouched issuer yet, old #157), a node's rating
// is its untrusted estimate — lifted off Floor to at most Ceiling — NOT pinned at Floor.
// If Measured returned trusted unconditionally, every node would sit at Floor and the
// feed would strand the fleet; this is the test that the fleet survives it.
func TestUnfedTrustedFallsBackToUntrusted(t *testing.T) {
	p := ratingParams()
	r := newTestRating(t, p)

	now := epoch
	obs := fromASes("free-", 4, 100*Mbit)
	for i := 0; i < 40; i++ {
		now = now.Add(p.Window)
		feedUntrusted(r, now, obs...)
	}
	st := r.Status()
	if st.Trusted.Estimate != p.Floor {
		t.Fatalf("trusted estimate = %s with no trusted samples; want Floor %s (unfed)", st.Trusted.Estimate, p.Floor)
	}
	if st.Measured != st.Untrusted.Estimate {
		t.Fatalf("Measured = %s, want the untrusted estimate %s: with trusted unfed, untrusted decides", st.Measured, st.Untrusted.Estimate)
	}
	if st.Measured <= p.Floor {
		t.Fatalf("Measured = %s is still at Floor %s: an unfed trusted stream must not pin the node at Floor and strand it", st.Measured, p.Floor)
	}
}

// TestNodeRatingRequiresCeiling: a rating with no ceiling cannot clamp its untrusted
// stream, so construction fails rather than silently building an unclamped one.
func TestNodeRatingRequiresCeiling(t *testing.T) {
	p := ratingParams()
	p.Ceiling = 0
	if _, err := NewNodeRating(p, epoch); err == nil {
		t.Fatal("NewNodeRating accepted a zero ceiling; the untrusted stream would have nothing to clamp to")
	}
}

// --- RatingStore -----------------------------------------------------------

// TestRatingStoreEvictsIdleNodes pins §8.6's separate lifecycle: a node not attested for
// idleTTL has its rating dropped, so the map tracks live nodes rather than every node
// ever seen — while a node still being attested keeps its slot.
func TestRatingStoreEvictsIdleNodes(t *testing.T) {
	p := ratingParams()
	const idleTTL = 10 * time.Minute
	s, err := NewRatingStore(p, idleTTL)
	if err != nil {
		t.Fatalf("NewRatingStore: %v", err)
	}

	sample := Sample{Throughput: 2 * Mbit, Saturated: true, Attester: "c1", AS: "as1"}
	s.Observe("idle-node", false, sample, epoch)
	s.Observe("live-node", false, sample, epoch)
	if s.Len() != 2 {
		t.Fatalf("Len = %d after two Observes, want 2", s.Len())
	}

	// Keep live-node attested at t = idleTTL/2, then Advance past idleTTL from epoch.
	half := epoch.Add(idleTTL / 2)
	s.Observe("live-node", false, sample, half)

	past := epoch.Add(idleTTL + time.Minute) // idle-node last seen at epoch => now-lastSeen > idleTTL
	s.Advance(past)

	if _, ok := s.Measured("idle-node"); ok {
		t.Error("a node idle past idleTTL kept its rating; the store did not evict it")
	}
	if _, ok := s.Measured("live-node"); !ok {
		t.Error("a node attested within idleTTL was evicted; eviction must key on attestation idleness, not wall clock alone")
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d after eviction, want 1 (only live-node)", s.Len())
	}
}

// TestRatingStoreUsableAppliesMinDeclaredMeasured pins the Usable seam (§8.6): the store
// returns min(declared, measured) for a rated node, and `declared` unchanged for an
// un-rated one (no measurement to bind). The numbers are literals, never derived from
// the ceiling constant the feed happens to pin the rating to.
func TestRatingStoreUsableAppliesMinDeclaredMeasured(t *testing.T) {
	p := ratingParams()
	s, err := NewRatingStore(p, time.Hour)
	if err != nil {
		t.Fatalf("NewRatingStore: %v", err)
	}

	// Drive n1's untrusted rating up to the ceiling (5 Mbit) with sustained max attestation.
	now := epoch
	high := fromASes("a-", 4, 100*Mbit)
	for i := 0; i < 40; i++ {
		now = now.Add(p.Window)
		for _, sm := range high {
			s.Observe("n1", false, sm, now)
		}
		s.Advance(now)
	}
	measured, ok := s.Measured("n1")
	if !ok || measured != p.Ceiling {
		t.Fatalf("n1 measured = %s (ok=%v); want the ceiling %s", measured, ok, p.Ceiling)
	}

	// declared ABOVE measured: measured binds.
	if got := s.Usable("n1", 20*Mbit); got != measured {
		t.Errorf("Usable(20Mbit) = %s, want measured %s (the smaller term binds)", got, measured)
	}
	// declared BELOW measured: declared binds.
	if got := s.Usable("n1", 1*Mbit); got != 1*Mbit {
		t.Errorf("Usable(1Mbit) = %s, want the declared 1Mbit (the smaller term binds)", got)
	}
	// Un-rated node: no measurement, declared passes through unchanged.
	if got := s.Usable("never-seen", 20*Mbit); got != 20*Mbit {
		t.Errorf("Usable(unrated, 20Mbit) = %s, want 20Mbit unchanged — an unmeasured node is not a slow node", got)
	}
}

// TestRatingStoreRoutesToStreams confirms Observe routes to the stream its `trusted`
// flag names, and that the two never cross: a node fed only on the untrusted stream has
// an unfed (Floor, uninformed) trusted stream, and vice versa.
func TestRatingStoreRoutesToStreams(t *testing.T) {
	p := ratingParams()
	s, err := NewRatingStore(p, time.Hour)
	if err != nil {
		t.Fatalf("NewRatingStore: %v", err)
	}

	now := epoch
	high := fromASes("v-", 4, 50*Mbit)
	for i := 0; i < 40; i++ {
		now = now.Add(p.Window)
		for _, sm := range high {
			s.Observe("vouched-node", true, sm, now) // trusted stream
		}
		s.Advance(now)
	}
	st, ok := s.Status("vouched-node")
	if !ok {
		t.Fatal("no rating for vouched-node")
	}
	if st.Untrusted.Estimate != p.Floor {
		t.Errorf("untrusted estimate = %s, want Floor %s: a trusted-only feed must not leak into untrusted", st.Untrusted.Estimate, p.Floor)
	}
	if st.Measured <= p.Ceiling {
		t.Errorf("Measured = %s: a trusted feed above the ceiling should decide and exceed it", st.Measured)
	}
}
