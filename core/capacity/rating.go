package capacity

import (
	"fmt"
	"sync"
	"time"
)

// NodeRating holds the TWO capacity estimates old #157 settled a node must carry,
// and the rule for combining them into the single number the coordinator uses
// (design §8.1.1). It is the shape of the owner decision, in code.
//
//   - trusted is fed ONLY by samples from accounts a real person vouched for. It is the
//     rating the coordinator uses wherever it exists, and the ONLY stream that may rise
//     above Ceiling. In this build it is PERMANENTLY EMPTY: vouched-ness reaches the
//     coordinator through the admission credential, no issuer stamps it yet, and the
//     coordinator cannot import the private account service that will (old #157 seam).
//     The stream is defined and wired so the account service can feed it later with no
//     coordinator change — see cmd/coordinator's classifier.
//   - untrusted is fed by samples from anyone holding a client credential. It is clamped
//     to Ceiling INSIDE its estimator (Params.HardCeiling), so forging it buys exactly
//     what silence already buys — the ceiling, never more (the §1 spine applied to a
//     range instead of a direction).
//
// The two are SEPARATE estimators with SEPARATE sample streams, never one estimator
// with a weight field: the separation IS the security property, because a shared
// accumulator is one refactor away from a blend (design §8.1.1, rule 1). Safe for
// concurrent use (each estimator is); reads no clock.
type NodeRating struct {
	trusted   *Estimator
	untrusted *Estimator
}

// NewNodeRating builds a node's two estimators from p. The trusted estimator uses p as
// given (its Ceiling is provisional, released once CeilingASes distinct ASes attest);
// the untrusted one forces HardCeiling, so no amount of unvouched attestation can lift
// it past Ceiling. p must therefore declare a non-zero Ceiling.
func NewNodeRating(p Params, now time.Time) (*NodeRating, error) {
	if p.Ceiling == 0 {
		return nil, fmt.Errorf("capacity: a node rating needs a non-zero ceiling to clamp the untrusted stream to")
	}
	trusted, err := NewEstimator(p, now)
	if err != nil {
		return nil, fmt.Errorf("capacity: trusted estimator: %w", err)
	}
	up := p
	up.HardCeiling = true
	untrusted, err := NewEstimator(up, now)
	if err != nil {
		return nil, fmt.Errorf("capacity: untrusted estimator: %w", err)
	}
	return &NodeRating{trusted: trusted, untrusted: untrusted}, nil
}

// ObserveTrusted records a sample from a VOUCHED attester (old #157). No production
// caller feeds this yet: it is the seam the account service plugs into once it stamps
// vouched-ness into the credential the coordinator can read.
func (r *NodeRating) ObserveTrusted(s Sample) { r.trusted.Observe(s) }

// ObserveUntrusted records a sample from any credentialed attester. Its influence can
// never lift the node above Ceiling (the untrusted estimator's HardCeiling).
func (r *NodeRating) ObserveUntrusted(s Sample) { r.untrusted.Observe(s) }

// Advance closes the scoring window on BOTH streams and returns the combined Measured
// rate. The caller ticks it once per Params.Window whether or not a sample arrived,
// per Estimator.Advance's contract (decay only moves on a tick).
func (r *NodeRating) Advance(now time.Time) Rate {
	r.trusted.Advance(now)
	r.untrusted.Advance(now)
	return r.Measured()
}

// Measured is the single number the coordinator consumes, and it encodes the whole of
// old #157's decision:
//
//   - trusted DECIDES OUTRIGHT wherever it exists — no weighted average, no blend, no
//     tiebreak (design §8.1.1, rule 2). "Exists" means the trusted estimator holds a
//     rating earned from real evidence (Estimator.Informed), not merely that it was
//     constructed: an UNFED trusted estimator sits at Floor and does NOT decide.
//   - otherwise the untrusted rating decides — already clamped to Ceiling by its own
//     estimator, so the caller never has to (rule 3).
//
// Rule 4 ("a node with trusted above the ceiling ignores untrusted entirely") falls
// out of rule 2 rather than being a separate branch: if trusted is informed it decides,
// whatever untrusted says. With trusted permanently empty in this build, Measured always
// returns the untrusted (≤ Ceiling) rating — exactly "lift a free-tier-only node off
// Floor to at most Ceiling", which is what old #157 intends.
func (r *NodeRating) Measured() Rate {
	if r.trusted.Informed() {
		return r.trusted.Estimate()
	}
	return r.untrusted.Estimate()
}

// TrustedRating returns the TRUSTED estimate and whether that stream is informed.
// Unlike Measured it never falls back to the untrusted one.
//
// The distinction matters to exactly one kind of caller: an ELIGIBILITY gate that
// compares a node against a real-world capacity floor (issue #15). Measured is the
// right number for ranking, where "clamped to the ceiling" and "genuinely 5 Mbit"
// can be treated alike because both mean "assign accordingly". It is the wrong
// number for a floor, because the untrusted estimator's HardCeiling means an
// untrusted rating is bounded by Ceiling no matter how fast the node actually is —
// so a floor above Ceiling applied to Measured would fence every measured node in
// the fleet while admitting every unmeasured one, which inverts the incentive to be
// measured at all.
//
// A false here therefore means "no rating this gate may judge against a floor", not
// "slow". A caller must treat it the same way it treats a node with no rating: an
// unmeasured node is not a slow node (design §5.3), and neither is one whose only
// evidence is ceiling-bounded.
func (r *NodeRating) TrustedRating() (Rate, bool) {
	if !r.trusted.Informed() {
		return 0, false
	}
	return r.trusted.Estimate(), true
}

// RatingStatus is a diagnostic snapshot of a node's two estimates and the combined
// measured rate, for coordinator status output.
type RatingStatus struct {
	Measured  Rate
	Trusted   Status
	Untrusted Status
}

// Status snapshots both streams and the combined rate.
func (r *NodeRating) Status() RatingStatus {
	return RatingStatus{Measured: r.Measured(), Trusted: r.trusted.Status(), Untrusted: r.untrusted.Status()}
}

// RatingStore is the coordinator's per-node capacity ratings, kept in their OWN map
// with their OWN lifecycle — deliberately NOT on the node registry entry (design §8.6).
//
// The register handler replaces a node's registry struct wholesale on every ~10s
// heartbeat. A rating stored on that struct would be silently reconstructed — reset to
// Floor — on every heartbeat, resetting every rating forever, and NOTHING would fail
// visibly. So ratings live here, keyed by node id, surviving heartbeats, with eviction
// driven by attestation idleness rather than by the registry's churn.
//
// Safe for concurrent use. Reads no clock: every entry point takes now, matching
// Estimator, so a coordinator's tests can pin the lifecycle exactly.
type RatingStore struct {
	params  Params
	idleTTL time.Duration

	mu      sync.Mutex
	entries map[string]*ratingEntry
}

type ratingEntry struct {
	rating   *NodeRating
	lastSeen time.Time // last time a report for this node arrived; drives eviction (NOT touched by Advance)
}

// NewRatingStore builds a store whose per-node ratings use p, evicting a node's rating
// after idleTTL with no report. idleTTL should exceed p.HalfLife comfortably, so a
// rating is expired by DECAY (drifting back to Floor) well before eviction removes it —
// eviction is memory hygiene for departed nodes, not a rating decision.
func NewRatingStore(p Params, idleTTL time.Duration) (*RatingStore, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Ceiling == 0 {
		return nil, fmt.Errorf("capacity: rating store needs a non-zero ceiling (the untrusted clamp)")
	}
	if idleTTL <= 0 {
		return nil, fmt.Errorf("capacity: rating store idle TTL must be > 0")
	}
	return &RatingStore{params: p, idleTTL: idleTTL, entries: map[string]*ratingEntry{}}, nil
}

// Observe routes a sample to nodeID's rating — creating it on first sight — on the
// trusted stream when `trusted`, else untrusted. It stamps lastSeen so the entry
// survives eviction while reports keep arriving, even reports the estimator drops as
// unsaturated: the node is still active and worth keeping a rating slot for.
//
// A NewNodeRating error can only be a params bug (params were Validated at
// construction), so it drops the sample rather than propagating — a dropped sample is
// a missed measurement, not a coordinator fault.
func (s *RatingStore) Observe(nodeID string, trusted bool, sample Sample, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[nodeID]
	if e == nil {
		r, err := NewNodeRating(s.params, now)
		if err != nil {
			return
		}
		e = &ratingEntry{rating: r}
		s.entries[nodeID] = e
	}
	e.lastSeen = now
	if trusted {
		e.rating.ObserveTrusted(sample)
	} else {
		e.rating.ObserveUntrusted(sample)
	}
}

// Measured returns nodeID's combined measured rate and whether a rating exists for it.
// A node never attested returns (0, false), and the caller then applies NO measured
// clamp — an unmeasured node is not a slow node (design §5.3).
func (s *RatingStore) Measured(nodeID string) (Rate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[nodeID]
	if e == nil {
		return 0, false
	}
	return e.rating.Measured(), true
}

// TrustedRating returns nodeID's TRUSTED measured rate and whether a trusted rating
// exists for it. A node with no rating at all, or one whose only evidence came
// through the untrusted stream, returns (0, false).
//
// This is the accessor a serve-eligibility floor reads (issue #15). See
// NodeRating.TrustedRating for why a floor must not be applied to Measured: with the
// trusted stream unfed, as it is in this build, this returns false for every node
// and the floor consequently gates nobody. That is the intended shape — the gate is
// real machinery that becomes live when the account service feeds the trusted
// stream, with no further change at the caller.
func (s *RatingStore) TrustedRating(nodeID string) (Rate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[nodeID]
	if e == nil {
		return 0, false
	}
	return e.rating.TrustedRating()
}

// Usable returns min(declared, measured) for nodeID (capacity.Usable) — or `declared`
// unchanged when the node has no rating yet. This is the production caller the
// min(declared, measured) contract lacked (design §8.6): the coordinator's assignment
// surfaces call it. declared 0 means uncapped.
//
// It is deliberately NOT an eligibility test. Whether `usable` clears a bar to serve is
// old #145's policy call, which this lane does not make and does not enable — with the
// trusted stream empty every rating clamps to Ceiling, so a floor on `usable` would
// strand the whole fleet (design §8.6). Usable is computed and available; it gates
// nothing here.
func (s *RatingStore) Usable(nodeID string, declared Rate) Rate {
	measured, ok := s.Measured(nodeID)
	if !ok {
		return declared
	}
	return Usable(declared, measured)
}

// Advance closes the scoring window on every rating and evicts those idle past idleTTL.
// The coordinator calls it once per Params.Window from a ticker. Evicting HERE, on the
// rating's own clock rather than on register, is the point of the separate map: a node
// that stops being attested has its rating decay and then drop, independent of whether
// it is still heartbeating into the registry.
func (s *RatingStore) Advance(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.entries {
		if now.Sub(e.lastSeen) > s.idleTTL {
			delete(s.entries, id)
			continue
		}
		e.rating.Advance(now)
	}
}

// Len reports how many node ratings are currently held. For diagnostics and for tests
// that pin eviction.
func (s *RatingStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Status snapshots nodeID's rating for operator-facing output, and whether it exists.
func (s *RatingStore) Status(nodeID string) (RatingStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[nodeID]
	if e == nil {
		return RatingStatus{}, false
	}
	return e.rating.Status(), true
}
