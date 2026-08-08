package capacity

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// The tests in this file are the spike's actual deliverable (old #144).
//
// docs/design/node-capacity.md §7 argues that this estimator resists gaming, and
// the argument is quantitative — "an attacker cannot gain more than RiseFactor per
// window", "an attacker must control ~4x the honest attesting ASes". A design note
// that argues a bound and a test that MEASURES it are different artifacts, and the
// second is the one that survives someone refactoring the first into a filter.
//
// So each simulation below pins one claim from §7 exactly. If one of these fails,
// the design note is wrong, not the test.

var epoch = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

// feed submits one saturated sample per attester and closes the window.
func feed(t *testing.T, e *Estimator, now time.Time, samples ...Sample) Rate {
	t.Helper()
	for _, s := range samples {
		e.Observe(s)
	}
	return e.Advance(now)
}

// sybilAS builds n saturated samples at rate r, each from its own AS.
func fromASes(prefix string, n int, r Rate) []Sample {
	out := make([]Sample, 0, n)
	for i := 0; i < n; i++ {
		as := fmt.Sprintf("%s%d", prefix, i)
		out = append(out, Sample{Throughput: r, Saturated: true, Attester: "c-" + as, AS: as})
	}
	return out
}

func newTestEstimator(t *testing.T, p Params) *Estimator {
	t.Helper()
	e, err := NewEstimator(p, epoch)
	if err != nil {
		t.Fatalf("NewEstimator: %v", err)
	}
	return e
}

// TestRatchetBoundsSybilGain pins the central claim of design §6.3/§7: the rate
// limit is a SECURITY property. An attacker who forges every sample perfectly —
// maximal throughput, from enough distinct ASes to clear the provisional ceiling
// gate, every window, forever — still cannot move the estimate faster than
// RiseFactor per window.
//
// This is what separates the ratchet from a peak estimator, which one forged
// sample defeats permanently and immediately.
func TestRatchetBoundsSybilGain(t *testing.T) {
	p := DefaultParams()
	e := newTestEstimator(t, p)

	// The attacker's dream: 1 Gbit claimed from 3 distinct ASes (== CeilingASes, so
	// the provisional ceiling never binds), every single window.
	const claim = Gbit
	now := epoch
	for w := 1; w <= 40; w++ {
		now = now.Add(p.Window)
		got := feed(t, e, now, fromASes("sybil-", p.CeilingASes, claim)...)

		// The hard bound: no matter what the samples said, the estimate is at most
		// Floor * RiseFactor^w.
		want := Rate(float64(p.Floor) * math.Pow(p.RiseFactor, float64(w)))
		if got > want {
			t.Fatalf("window %d: estimate %s exceeds the ratchet bound %s — the rate limit leaked", w, got, want)
		}
		// Non-vacuity: the attacker IS gaining, just slowly. If this failed, the test
		// above would pass trivially against an estimator that never moves.
		if got <= p.Floor {
			t.Fatalf("window %d: estimate %s never left the floor — test is vacuous", w, got)
		}
	}

	// The headline number quoted in the design note: ~11 windows to reach 10x, not
	// one. Pinning both sides makes this a real bound rather than an inequality
	// anyone could satisfy.
	e2 := newTestEstimator(t, p)
	tenX := 10 * p.Floor
	now = epoch
	for w := 1; w <= 10; w++ {
		now = now.Add(p.Window)
		feed(t, e2, now, fromASes("sybil-", p.CeilingASes, claim)...)
	}
	if got := e2.Estimate(); got >= tenX {
		t.Errorf("after 10 windows estimate %s already reached 10x floor (%s) — ratchet is too loose", got, tenX)
	}
	now = now.Add(p.Window)
	feed(t, e2, now, fromASes("sybil-", p.CeilingASes, claim)...)
	if got := e2.Estimate(); got < tenX {
		t.Errorf("after 11 windows estimate %s still below 10x floor (%s) — ratchet is too tight to ever learn", got, tenX)
	}
}

// TestASSupermajorityRequiredToHoldRating pins the Sybil bound from design §6.4/
// §7.2: because the estimate is a LOW quantile over one-vote-per-AS values, honest
// attesters do not have to out-shout an attacker — they only have to EXIST.
//
// The table walks the exact boundary. With Quantile=0.25 the estimate is the
// value at rank floor(0.25*(n-1)); honest (throttled) ASes occupy the lowest
// ranks, so the attacker wins only when it outnumbers them roughly 4:1.
//
// This is the test that would fail loudly if someone "fixed" the estimator to use
// a peak or a mean — which is exactly the change that looks like an improvement
// and silently hands the rating to whoever forges the fastest sample.
func TestASSupermajorityRequiredToHoldRating(t *testing.T) {
	const (
		seed       = 100 * Mbit // the inflated rating the attacker is defending
		sybilClaim = Gbit       // attacker: "this node is fast"
		honestObs  = 2 * Mbit   // honest client, throttled: "no it isn't"
	)
	cases := []struct {
		honestASes, sybilASes int
		wantHonestWins        bool
	}{
		{1, 1, true},  // 1 honest vs 1 sybil: honest holds rank 0
		{1, 2, true},  // still rank 0
		{1, 3, true},  // still rank 0 — attacker at 3:1 is not enough
		{1, 4, false}, // n=5, rank 1 -> attacker finally wins at 4:1
		{2, 4, true},  // n=6, rank 1 -> honest occupy 0,1
		{2, 6, true},  // n=8, rank 1 -> still honest
		{2, 7, false}, // n=9, rank 2 -> attacker wins, again ~4:1
	}
	for _, c := range cases {
		name := fmt.Sprintf("honest=%d/sybil=%d", c.honestASes, c.sybilASes)
		t.Run(name, func(t *testing.T) {
			p := DefaultParams()
			p.Ceiling = 0 // disable the provisional ceiling: this test is about the quantile alone
			e := newTestEstimator(t, p)
			e.Seed(seed, epoch)

			var samples []Sample
			samples = append(samples, fromASes("honest-", c.honestASes, honestObs)...)
			samples = append(samples, fromASes("sybil-", c.sybilASes, sybilClaim)...)
			got := feed(t, e, epoch.Add(p.Window), samples...)

			if c.wantHonestWins {
				// The honest observation is far below FallThreshold*seed, so it snaps the
				// inflated rating straight down to the truth.
				if got != honestObs {
					t.Errorf("estimate = %s, want the honest observation %s — the attacker captured the quantile", got, honestObs)
				}
			} else {
				// The attacker owns the quantile: the rating rises instead of snapping.
				if got <= seed {
					t.Errorf("estimate = %s, want a rise above the seed %s (attacker should own the quantile here)", got, seed)
				}
			}
		})
	}
}

// TestASStuffingBuysNothing pins design §6.4's "one AS = one vote". The unit of
// Sybil cost is an AS, not a client and not a sample — so renting a hundred VPS in
// one datacenter buys exactly what renting one buys.
//
// The counterfactual is the point: if the estimator counted ATTESTERS instead of
// ASes, 100 sybils vs 1 honest would put rank floor(0.25*100)=25 deep inside the
// attacker's block and the attacker would win outright.
func TestASStuffingBuysNothing(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(100*Mbit, epoch)

	// 100 attesters, all in ONE AS, all claiming 1 Gbit.
	var samples []Sample
	for i := 0; i < 100; i++ {
		samples = append(samples, Sample{Throughput: Gbit, Saturated: true, Attester: fmt.Sprintf("sybil-%d", i), AS: "AS-attacker"})
	}
	// One honest attester in its own AS, throttled.
	samples = append(samples, Sample{Throughput: 2 * Mbit, Saturated: true, Attester: "honest", AS: "AS-honest"})

	got := feed(t, e, epoch.Add(p.Window), samples...)
	if got != 2*Mbit {
		t.Errorf("estimate = %s, want %s: 100 attesters in one AS must weigh exactly as much as one", got, 2*Mbit)
	}
}

// TestVolumeStuffingBuysNothing pins the per-attester collapse: one client
// submitting ten thousand samples moves the estimate exactly as much as one client
// submitting one.
func TestVolumeStuffingBuysNothing(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0

	run := func(copies int) Rate {
		e := newTestEstimator(t, p)
		e.Seed(100*Mbit, epoch)
		var samples []Sample
		for i := 0; i < copies; i++ {
			samples = append(samples, Sample{Throughput: Gbit, Saturated: true, Attester: "sybil", AS: "AS-attacker"})
		}
		samples = append(samples, Sample{Throughput: 2 * Mbit, Saturated: true, Attester: "honest", AS: "AS-honest"})
		return feed(t, e, epoch.Add(p.Window), samples...)
	}

	one, many := run(1), run(10_000)
	if one != many {
		t.Errorf("1 sample -> %s but 10000 samples -> %s: volume bought influence", one, many)
	}
	if one != 2*Mbit {
		t.Errorf("estimate = %s, want the honest observation %s", one, 2*Mbit)
	}
}

// TestHonestClientsSnapBackInflatedRating pins design §7.1's core dynamic: an
// attacker cannot both hold a high rating and dodge the traffic that rating
// attracts. The moment real clients are routed to the node and find it throttled,
// their attestations collapse the rating — and the asymmetry means that collapse
// takes ONE window, while building the rating took dozens.
func TestHonestClientsSnapBackInflatedRating(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)

	// Count the windows an attacker needs to ratchet to 100 Mbit from the floor.
	now := epoch
	rise := 0
	for e.Estimate() < 100*Mbit {
		now = now.Add(p.Window)
		feed(t, e, now, fromASes("sybil-", 3, Gbit)...)
		rise++
		if rise > 1000 {
			t.Fatal("estimate never reached 100Mbit — ratchet cannot rise at all")
		}
	}
	inflated := e.Estimate()

	// Now real clients arrive and find the node throttling them.
	now = now.Add(p.Window)
	got := feed(t, e, now, fromASes("honest-", p.MinASes, 2*Mbit)...)
	if got != 2*Mbit {
		t.Fatalf("after honest attestation estimate = %s, want a snap to the observed %s", got, 2*Mbit)
	}

	// The asymmetry, quantified: slow to trust, fast to distrust. Both sides pinned,
	// because design §7.4 quotes these numbers and its whole argument is that a failing
	// test means the document is wrong. A number only logged is a number not pinned.
	if rise != 27 {
		t.Errorf("rise to 100Mbit took %d windows, want 27 (design note §7.4 quotes 27; update both together)", rise)
	}
	t.Logf("rise to %s took %d windows; collapse to %s took 1 window", inflated, rise, got)
}

// TestUnsaturatedSamplesAreIgnored pins design §5.3: throughput without the
// saturation bit carries no capacity information, because it cannot distinguish a
// throttled node from an idle one. A busy-but-unsaturated node must not be
// mistaken for a slow one.
func TestUnsaturatedSamplesAreIgnored(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(50*Mbit, epoch)

	// Twenty clients across twenty ASes, all getting a trickle — because a trickle is
	// all any of them asked for.
	var samples []Sample
	for i := 0; i < 20; i++ {
		as := fmt.Sprintf("AS-%d", i)
		samples = append(samples, Sample{Throughput: 100 * Kbit, Saturated: false, Attester: "c-" + as, AS: as})
	}
	got := feed(t, e, epoch.Add(p.Window), samples...)

	// Only decay applies (one window against a 24h half-life is nearly nothing).
	if got < 49*Mbit {
		t.Errorf("estimate collapsed to %s on unsaturated samples — an idle node was mistaken for a slow one", got)
	}
}

// TestObserveRejectsUnattributableSamples pins that influence caps cannot be
// bypassed by simply omitting the fields the caps key on.
func TestObserveRejectsUnattributableSamples(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(50*Mbit, epoch)

	// Enough of these to clear MinASes several times over, if any were accepted.
	for i := 0; i < 5; i++ {
		as := fmt.Sprintf("AS-%d", i)
		e.Observe(Sample{Throughput: 2 * Mbit, Saturated: true, Attester: "", AS: as})               // no attester
		e.Observe(Sample{Throughput: 2 * Mbit, Saturated: true, Attester: "c" + as, AS: ""})         // no AS
		e.Observe(Sample{Throughput: 2 * Mbit, Saturated: false, Attester: "c" + as, AS: as + "-u"}) // not saturated
	}
	got := e.Advance(epoch.Add(p.Window))
	if got < 49*Mbit {
		t.Errorf("estimate = %s: an unattributable sample moved the estimate", got)
	}
}

// TestBlackholedClientsCountAgainstTheNode is the regression test for the worst bug
// in this file's history: Observe used to drop any sample with Throughput == 0.
//
// A saturated zero is not a missing measurement. It is a client that wanted bytes
// and got NONE — the strongest possible evidence a node is not delivering. Dropping
// it meant a node could BLACKHOLE strangers instead of throttling them, their
// samples would never reach the estimator at all, and the votes would be its
// colluders' alone. It was worth ~4800x: blackholing held a 1.2 Gbit rating where
// throttling to 1 bit/s collapsed to the floor.
//
// It also made the design's central claim — "every session is scored, so there is no
// unscored flow to hide in" (§7.1) — plainly false. There was one: the zero-byte
// flow. Serving nothing must never score better than serving almost nothing.
func TestBlackholedClientsCountAgainstTheNode(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0

	// Same attacker, same sybils, same honest ASes. The only difference is whether
	// the node blackholes its honest clients or merely strangles them.
	run := func(honestRate Rate) Rate {
		e := newTestEstimator(t, p)
		now := epoch
		for w := 0; w < 40; w++ {
			now = now.Add(p.Window)
			var samples []Sample
			samples = append(samples, fromASes("sybil-", 3, Gbit)...)
			samples = append(samples, fromASes("honest-", 5, honestRate)...)
			feed(t, e, now, samples...)
		}
		return e.Estimate()
	}

	blackholed := run(0) // "you get nothing"
	throttled := run(1)  // "you get one bit per second"
	if blackholed > throttled {
		t.Errorf("blackholing 5 honest ASes scored %s but throttling them scored %s — serving NOTHING beats serving almost nothing", blackholed, throttled)
	}
	if blackholed != p.Floor {
		t.Errorf("a node that blackholes 5 of 8 attesting ASes is rated %s, want the floor %s", blackholed, p.Floor)
	}
}

// TestSybilCannotCaptureAnHonestAS is the regression test for the per-AS collapse.
//
// It used to be a median over that AS's attesters, which let an attacker CAPTURE an
// AS that honest clients already attest from: n honest attesters are outvoted by
// n+1 sybils in the same AS, and n is typically one or two. No new AS required —
// just a few residential-proxy addresses in ASes that already attest. Measured, it
// held a 125 Mbit rating across four honest ASes each genuinely throttled to 2 Mbit.
//
// That silently falsified §6.4's headline: "honest clients do not have to out-shout
// the attacker, they only have to exist". With a median they DID have to out-shout
// it, inside their own AS. The per-AS minimum makes existing enough again.
func TestSybilCannotCaptureAnHonestAS(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(100*Mbit, epoch)

	var samples []Sample
	for i := 0; i < 4; i++ {
		as := fmt.Sprintf("AS-%d", i)
		// One honest client, genuinely throttled to 2 Mbit...
		samples = append(samples, Sample{Throughput: 2 * Mbit, Saturated: true, Attester: "honest-" + as, AS: as})
		// ...colonised by two sybils in the SAME AS, claiming the node is fast.
		samples = append(samples, Sample{Throughput: Gbit, Saturated: true, Attester: "sybil-a-" + as, AS: as})
		samples = append(samples, Sample{Throughput: Gbit, Saturated: true, Attester: "sybil-b-" + as, AS: as})
	}
	got := feed(t, e, epoch.Add(p.Window), samples...)

	if got != 2*Mbit {
		t.Errorf("estimate = %s, want the honest observation %s: sybils outnumbering an AS's honest attesters captured its vote", got, 2*Mbit)
	}
}

// TestProvisionalCeilingHoldsUntilEnoughASes pins design §6.4/§8.3: the ceiling
// answers the cold-start problem and prices the "decline to be measured" strategy.
// Silence, or attestation from too narrow a slice of the network, buys the ceiling
// and never more — no matter how long it goes on.
func TestProvisionalCeilingHoldsUntilEnoughASes(t *testing.T) {
	p := DefaultParams()
	e := newTestEstimator(t, p)

	// Two ASes: enough to be informative (MinASes) but short of CeilingASes.
	now := epoch
	for w := 0; w < 100; w++ {
		now = now.Add(p.Window)
		feed(t, e, now, fromASes("sybil-", 2, Gbit)...)
	}
	if got := e.Estimate(); got != p.Ceiling {
		t.Errorf("after 100 windows at 2 ASes estimate = %s, want it pinned at the provisional ceiling %s", got, p.Ceiling)
	}

	// A third AS unlocks the gate; the ratchet resumes from where it was.
	now = now.Add(p.Window)
	got := feed(t, e, now, fromASes("sybil-", 3, Gbit)...)
	if got <= p.Ceiling {
		t.Errorf("estimate = %s, want a rise past the ceiling %s once CeilingASes attested", got, p.Ceiling)
	}
}

// TestSeedIsClampedToTheCeiling pins the install-time probe's trust status
// (design §6.1, cmd/capacity-probe): a seed saves an honest node a slow ramp and
// can never buy a liar more than the provisional ceiling.
func TestSeedIsClampedToTheCeiling(t *testing.T) {
	p := DefaultParams()
	e := newTestEstimator(t, p)

	e.Seed(10*Gbit, epoch) // a probe result from a node that is lying, or a probe that was fooled
	if got := e.Estimate(); got != p.Ceiling {
		t.Errorf("Seed(10Gbit) -> %s, want the ceiling %s: an untrusted probe must not buy a rating", got, p.Ceiling)
	}
	e.Seed(1*Kbit, epoch) // absurdly low
	if got := e.Estimate(); got != p.Floor {
		t.Errorf("Seed(1kbit) -> %s, want the floor %s", got, p.Floor)
	}
}

// TestDecayExpiresStaleRating pins design §6.3: a rating is a claim about the
// recent past and must expire, which is also what makes collusion a RECURRING cost
// rather than a one-time purchase.
func TestDecayExpiresStaleRating(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(64*Mbit, epoch)

	// One half-life of silence halves the rating.
	e.Advance(epoch.Add(p.HalfLife))
	got := e.Estimate()
	want := 32 * Mbit
	if math.Abs(float64(got)-float64(want)) > float64(Mbit) {
		t.Errorf("after one half-life estimate = %s, want ~%s", got, want)
	}

	// Enough silence and it returns to the floor rather than lingering forever.
	e.Advance(epoch.Add(100 * p.HalfLife))
	if got := e.Estimate(); got != p.Floor {
		t.Errorf("after 100 half-lives estimate = %s, want the floor %s", got, p.Floor)
	}
}

// TestDecayIsIndependentOfAdvanceFrequency pins that decay is a function of how
// long a node has gone unattested and NOT of how often anyone called Advance.
//
// Regression test. The first cut scaled the current estimate by
// 0.5^(elapsed-since-last-informative-window) on every idle Advance, which
// compounds to 0.5^(SUM of elapsed) rather than 0.5^(elapsed) — quadratic decay.
// An idle node lost ~60% of its rating in one hour against a 24h half-life, and
// the size of the loss depended on the caller's tick rate, which is not a property
// a rating should have. Note that no adversarial test caught it: over-decaying
// looks like caution right up until it drives off the honest residential
// volunteers old #143 exists to recruit.
func TestDecayIsIndependentOfAdvanceFrequency(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	const seed = 40 * Mbit
	const idle = time.Hour

	// One Advance an hour later vs. 60 Advances a minute apart must agree.
	coarse := newTestEstimator(t, p)
	coarse.Seed(seed, epoch)
	coarse.Advance(epoch.Add(idle))

	fine := newTestEstimator(t, p)
	fine.Seed(seed, epoch)
	for now := epoch.Add(p.Window); !now.After(epoch.Add(idle)); now = now.Add(p.Window) {
		fine.Advance(now)
	}

	if coarse.Estimate() != fine.Estimate() {
		t.Errorf("decay depends on tick rate: 1 Advance/hour -> %s but 60 Advances/hour -> %s", coarse.Estimate(), fine.Estimate())
	}
	// And it is the correct exponential, not merely a consistent wrong one.
	want := Rate(float64(seed) * math.Pow(0.5, idle.Seconds()/p.HalfLife.Seconds()))
	if d := math.Abs(float64(coarse.Estimate()) - float64(want)); d > float64(100*Kbit) {
		t.Errorf("after %v idle estimate = %s, want ~%s", idle, coarse.Estimate(), want)
	}
	// Idempotence falls out of the same property.
	before := fine.Estimate()
	fine.Advance(epoch.Add(idle))
	if fine.Estimate() != before {
		t.Errorf("Advance at the same instant changed the estimate: %s -> %s", before, fine.Estimate())
	}
}

// TestIdleNodeKeepsItsRating pins design §7.3's honest-node story: an unused node
// is not a slow node. A volunteer whose node sits quiet overnight must not be
// punished for it — a gaming-resistant metric that penalises honest operators is
// not a solution.
func TestIdleNodeKeepsItsRating(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(20*Mbit, epoch)

	now := epoch
	for w := 0; w < 60; w++ { // an hour of complete silence
		now = now.Add(p.Window)
		e.Advance(now)
	}
	if got := e.Estimate(); got < 19*Mbit {
		t.Errorf("after an idle hour estimate = %s, want it near the seed 20Mbit — idle is not slow", got)
	}
}

// TestCongestionTracksReality pins the "periodic re-tests track reality" half of
// old #144, and design §5.3's deliberate conflation: a node whose uplink is
// congested and a node that is throttling are the same node from here, and the
// correct action for both is identical. No attribution is attempted, and none is
// needed.
func TestCongestionTracksReality(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(50*Mbit, epoch)

	// Evening: the operator's family starts streaming; real clients see 3 Mbit.
	now := epoch.Add(p.Window)
	if got := feed(t, e, now, fromASes("honest-", 4, 3*Mbit)...); got != 3*Mbit {
		t.Fatalf("congested estimate = %s, want %s", got, 3*Mbit)
	}

	// Overnight: the pipe frees up and the node earns its rating back — slowly,
	// because rise is rate-limited even for an honest node.
	windows := 0
	for e.Estimate() < 40*Mbit {
		now = now.Add(p.Window)
		feed(t, e, now, fromASes("honest-", 4, 50*Mbit)...)
		windows++
		if windows > 1000 {
			t.Fatal("estimate never recovered")
		}
	}
	// Pinned, not logged: design §7.4 quotes ~12 windows as the honest-recovery cost,
	// and an honest node's recovery time is a user-facing property — a regression that
	// doubled it would otherwise pass silently.
	if windows != 12 {
		t.Errorf("recovery from 3Mbit to 40Mbit took %d windows, want 12 (design note §7.4 quotes ~12; update both together)", windows)
	}
	t.Logf("recovery from 3Mbit to 40Mbit took %d windows (~%v)", windows, time.Duration(windows)*p.Window)
}

func TestUsable(t *testing.T) {
	cases := []struct {
		declared, measured, want Rate
	}{
		{0, 5 * Mbit, 5 * Mbit},         // no declared cap: measured binds
		{20 * Mbit, 5 * Mbit, 5 * Mbit}, // over-declaring is inert — the point of design §3
		{5 * Mbit, 20 * Mbit, 5 * Mbit}, // under-declaring is the operator's right
		{5 * Mbit, 5 * Mbit, 5 * Mbit},
	}
	for _, c := range cases {
		if got := Usable(c.declared, c.measured); got != c.want {
			t.Errorf("Usable(%s, %s) = %s, want %s", c.declared, c.measured, got, c.want)
		}
	}
}

func TestParamsValidate(t *testing.T) {
	if err := DefaultParams().Validate(); err != nil {
		t.Fatalf("DefaultParams must be valid: %v", err)
	}
	cases := map[string]func(*Params){
		"zero window":           func(p *Params) { p.Window = 0 },
		"quantile out of range": func(p *Params) { p.Quantile = 1.5 },
		"rise factor not > 1":   func(p *Params) { p.RiseFactor = 1 },
		"thresholds inverted":   func(p *Params) { p.RiseThreshold, p.FallThreshold = 0.5, 0.9 },
		"zero floor":            func(p *Params) { p.Floor = 0 },
		"ceiling below floor":   func(p *Params) { p.Ceiling = 1 },
		"zero half-life":        func(p *Params) { p.HalfLife = 0 },
		"min ASes below one":    func(p *Params) { p.MinASes = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := DefaultParams()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Errorf("Validate accepted invalid params (%s)", name)
			}
			if _, err := NewEstimator(p, epoch); err == nil {
				t.Errorf("NewEstimator accepted invalid params (%s)", name)
			}
		})
	}
}

func TestMedianAndQuantileAreConservative(t *testing.T) {
	// Even counts take the LOWER middle rather than averaging: the estimate is always
	// a rate someone actually observed, never one synthesised between two.
	if got := median([]Rate{10, 20}); got != 10 {
		t.Errorf("median([10 20]) = %v, want 10 (lower middle)", got)
	}
	if got := median([]Rate{30, 10, 20}); got != 20 {
		t.Errorf("median([30 10 20]) = %v, want 20", got)
	}
	if got := median(nil); got != 0 {
		t.Errorf("median(nil) = %v, want 0", got)
	}
	if got := quantile([]Rate{10, 20, 30, 40, 50}, 0.25); got != 20 {
		t.Errorf("quantile(.25) = %v, want 20 (rank 1)", got)
	}
	if got := quantile([]Rate{10, 20, 30, 40}, 0.25); got != 10 {
		t.Errorf("quantile(.25) of 4 = %v, want 10 (rank 0)", got)
	}
	if got := quantile([]Rate{42}, 0.25); got != 42 {
		t.Errorf("quantile of a single value = %v, want 42", got)
	}
}

func TestStatusReportsLastObservation(t *testing.T) {
	p := DefaultParams()
	p.Ceiling = 0
	e := newTestEstimator(t, p)
	e.Seed(10*Mbit, epoch)
	now := epoch.Add(p.Window)
	feed(t, e, now, fromASes("honest-", 3, 4*Mbit)...)

	st := e.Status()
	if st.LastObserved != 4*Mbit {
		t.Errorf("Status().LastObserved = %s, want %s", st.LastObserved, 4*Mbit)
	}
	if st.LastASes != 3 {
		t.Errorf("Status().LastASes = %d, want 3", st.LastASes)
	}
	if !st.LastInform.Equal(now) {
		t.Errorf("Status().LastInform = %v, want %v", st.LastInform, now)
	}
}
