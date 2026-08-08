package capacity

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Sample is one observation of what a node delivered to one client over one
// scoring window (old #144). It is derived from a co-signed usage receipt
// (core/accounting, ADR-0021) — bytes/interval is a throughput both the exit and
// the client had to agree on, so neither can move it ALONE.
//
// "Alone" is doing load-bearing work in that sentence, and the honest reading is
// in the design note §8.1: a co-signature proves two keys AGREED, not that any
// byte transited. A node and a client it controls can co-sign anything, for free.
// Everything below is built to bound what that buys, not to prevent it.
type Sample struct {
	// Throughput is the receipt's Bytes/IntervalSec, in bits per second.
	Throughput Rate

	// Saturated is the client's assertion that it had MORE to send or receive than
	// the link delivered for this whole interval — that it was demand-limited by the
	// node, not by itself.
	//
	// This single bit is what makes the whole scheme possible, because without it a
	// low throughput is ambiguous (throttled? or just idle?) and an estimator cannot
	// tell a strangled node from a quiet one. See the design note §5.3.
	//
	// It is also the weakest link (§8.2): only the client knows it, and the exit
	// cannot verify it, so unlike Throughput it is NOT protected by the
	// co-signature. A defaming client can assert it while idle. That is bounded —
	// one attester gets one vote (Advance), and the lie only LOWERS a rating, making
	// it an availability attack on an honest node rather than an integrity attack on
	// the estimate.
	Saturated bool

	// Attester identifies the client that co-signed (its accounting public key, as
	// hex). It exists so a single attester's influence can be capped: without it,
	// submitting the same sample a thousand times would move the estimate a
	// thousand times. Required — an unattributable sample cannot be capped and is
	// therefore rejected by Observe.
	Attester string

	// AS is the attesting client's autonomous system, derived by the coordinator
	// from the source address it OBSERVED at connect — never a self-report.
	//
	// This follows the rule core/coldstart.Entry already holds: the coordinator
	// cannot see a node's TCP listener so it does not trust a claimed ingress IP,
	// but it CAN see a source address, so what it observes is what it trusts. AS is
	// the unit of Sybil cost here (one AS = one vote, Advance), so letting a client
	// state its own would make that cost zero. Required.
	AS string
}

// Params are the estimator's tuning constants. Every value is a starting value,
// chosen with the reasoning recorded in ADR-0040 — none of them is a law, and the
// network has never run this loop in anger, so they are expected to move once
// there is real data. DefaultParams documents the choices.
//
// Two of them are load-bearing for SECURITY rather than for accuracy, and must
// not be "optimised" by someone reading them as smoothing:
//   - RiseFactor bounds what any amount of collusion buys per window (see Advance).
//   - Quantile is the Sybil bound: it sets the fraction of attesting ASes an
//     attacker must control (see Advance).
type Params struct {
	// Window is one scoring interval. Advance closes a window.
	Window time.Duration

	// Quantile selects the estimate from the per-AS values, LOW rather than high.
	//
	// This inverts the obvious choice and it is the single most important parameter
	// here. A peak (or a mean, or a sum) lets ONE colluding attester set the rating:
	// forge one fast sample, own the maximum. A low quantile means the attacker must
	// hold the whole lower tail — to keep the estimate at E, a fraction (1-Quantile)
	// of ALL attesting ASes must report >= E. At 0.25 that is 75% of the ASes
	// attesting to this node, and it grows as the node attracts honest clients.
	//
	// The cost of the conservative choice is real and accepted: a node with a few
	// genuinely bad clients is under-rated. That errs toward under-use, which merely
	// wastes capacity, rather than toward over-use, which hurts users (see Advance).
	Quantile float64

	// RiseFactor is the most the estimate may grow in one window, no matter what
	// the samples say. This is a RATE LIMIT AS A SECURITY PROPERTY, not smoothing:
	// it is what converts a one-shot lie into a sustained, public, self-revealing
	// one. See Advance's comment.
	RiseFactor float64

	// RiseThreshold is the fraction of the current estimate the observation must
	// reach for the node to count as "meeting its rating" and earn a rise. Below 1
	// because a node delivering at exactly its rating is measured at slightly under
	// it by any real sampler.
	RiseThreshold float64

	// FallThreshold is the fraction below which the node counts as failing to
	// deliver and the estimate snaps down to the observation. Meaningfully below
	// RiseThreshold so ordinary jitter does not flap the rating between rise and
	// fall.
	FallThreshold float64

	// MinASes is the distinct attesting ASes a window needs before it is allowed to
	// move the estimate at all. Below this the window carries no information — one
	// AS's view of a node is one path's view — and the estimate only decays.
	MinASes int

	// Ceiling is the PROVISIONAL cap a node cannot exceed until CeilingASes
	// distinct ASes have attested to it in a window. It answers the cold-start
	// chicken-and-egg (a new node has no history; to get history it must be given
	// traffic; to be given traffic it needs a rating) and it prices §8.3's
	// "decline to be measured" strategy: silence buys the ceiling, never more.
	Ceiling Rate

	// CeilingASes is the distinct-AS count needed in a window to rise past Ceiling.
	CeilingASes int

	// HardCeiling makes Ceiling a PERMANENT clamp rather than the provisional one
	// CeilingASes releases. It is the untrusted estimator's whole security property
	// (old #158, design §8.1.1): a rating attested by anyone-with-a-credential may
	// never exceed Ceiling no matter how many ASes attest, so forging the cheap
	// (untrusted) signal buys exactly what silence already buys — the ceiling, never
	// more. The clamp lives HERE, inside the estimator, not in the caller that reads
	// Estimate(): a clamp in a caller is a clamp someone later removes, and the moment
	// an unvouched sample can move a number above Ceiling the purchasable-identity
	// attack is back (design §8.1.1, rule 3). The trusted estimator leaves this false
	// and keeps the provisional (CeilingASes-released) ceiling, because vouched
	// attestation is what earns a rating above it.
	HardCeiling bool

	// Floor is the estimate's lower bound and its starting value. It MUST be > 0:
	// the ratchet is multiplicative, and a multiplicative ratchet starting at zero
	// never moves. It is NOT a serve-eligibility floor — that is old #145's
	// decision and is policy, not a constant (see DefaultParams).
	Floor Rate

	// HalfLife is how fast an un-re-earned rating decays when no window carries
	// information. A rating is a claim about the recent past and has to expire, or a
	// node that was fast in March still holds a rating in July. Decay is also what
	// makes collusion a RECURRING cost rather than a one-off purchase.
	HalfLife time.Duration
}

// DefaultParams returns the starting values, with the reasoning for each recorded
// in ADR-0040 §Decision. They are deliberately conservative: this loop has never
// run against a real fleet, and every parameter errs toward under-rating a node
// (which wastes capacity) over over-rating one (which hurts the users routed
// there).
//
// Note what is NOT here: the serve-eligibility floor. Whether a node rated at
// 2 Mbit is allowed to serve is old #145's call, and it is POLICY, not a
// constant — a 2 Mbit exit is worthless in Frankfurt and precious in a region
// where it is the only one, and the answer changes with how starved the network
// is. Floor below is estimator mechanics (the ratchet's zero point), not
// eligibility.
func DefaultParams() Params {
	return Params{
		// One minute: matches cmd/node's -acct-interval default, so one receipt is
		// exactly one sample and no re-windowing is needed.
		Window: time.Minute,
		// 0.25 — an attacker needs 75% of the attesting ASes. See Params.Quantile.
		Quantile: 0.25,
		// 1.25 — ~11 windows (≈11 min) of sustained collusion to reach 10x, every one
		// of them serving real clients at the rising rating who can snap it back.
		RiseFactor:    1.25,
		RiseThreshold: 0.9,
		FallThreshold: 0.7,
		MinASes:       2,
		// 5 Mbit — usable enough that a new or silent node is not useless, low enough
		// that being wrong about one for a while costs little.
		Ceiling:     5 * Mbit,
		CeilingASes: 3,
		// 256 kbit — non-zero (the ratchet needs a multiplicative starting point) and
		// small enough to be a rounding error if wrong.
		Floor: 256 * Kbit,
		// 24h — a rating survives a quiet night but not a quiet week.
		HalfLife: 24 * time.Hour,
	}
}

// Validate reports whether p is self-consistent, so a caller misconfiguring the
// estimator fails at construction rather than producing quietly wrong ratings.
func (p Params) Validate() error {
	switch {
	case p.Window <= 0:
		return fmt.Errorf("window must be > 0")
	case p.Quantile < 0 || p.Quantile > 1:
		return fmt.Errorf("quantile %v out of range [0,1]", p.Quantile)
	case p.RiseFactor <= 1:
		return fmt.Errorf("rise factor %v must be > 1 (a ratchet that cannot rise never learns)", p.RiseFactor)
	case p.RiseThreshold <= p.FallThreshold:
		return fmt.Errorf("rise threshold %v must exceed fall threshold %v, or the estimate flaps between rise and fall on jitter", p.RiseThreshold, p.FallThreshold)
	case p.Floor == 0:
		return fmt.Errorf("floor must be > 0: the ratchet is multiplicative and never leaves zero")
	case p.Ceiling != 0 && p.Ceiling < p.Floor:
		return fmt.Errorf("ceiling %s below floor %s", p.Ceiling, p.Floor)
	case p.HardCeiling && p.Ceiling == 0:
		return fmt.Errorf("hard ceiling requires a non-zero ceiling to clamp to")
	case p.MinASes < 1:
		return fmt.Errorf("min ASes must be >= 1")
	case p.HalfLife <= 0:
		return fmt.Errorf("half-life must be > 0: a rating that never decays is a claim about the past that never expires")
	}
	return nil
}

// Estimator tracks one node's measured deliverable rate: the rate a SATURATED
// session gets from it. Not the node's aggregate capacity — see the package doc.
//
// It is a ratchet, not a peak. The estimate is not "the fastest we ever saw" but
// "the level at which this node has REPEATEDLY been observed to deliver". Advance
// is where that distinction lives and is the function to read first.
//
// # The caller must tick
//
// Advance is the ONLY thing that moves the estimate, including its decay, so a
// caller must call it once per Params.Window whether or not any sample arrived.
// Estimate() reports the value as of the last Advance and does not itself decay —
// an estimator that is never ticked holds its rating forever, which is precisely
// the "a node that was fast in March still holds a rating in July" failure decay
// exists to prevent. A caller that reads Estimate() on demand (at assignment time,
// say) without a ticker gets a stale answer with no error.
//
// Safe for concurrent use. Reads no clock: every entry point takes `now`, which is
// what lets estimator_test.go pin the gaming-resistance bounds exactly.
type Estimator struct {
	p Params

	mu      sync.Mutex
	est     Rate
	pending map[string][]Rate // attester -> that attester's saturated throughputs this window
	asOf    map[string]string // attester -> its coordinator-observed AS

	// baseEst is the estimate as of lastInform, i.e. BEFORE any decay was applied.
	// Decay is computed fresh from this base every time rather than by repeatedly
	// scaling est, which is what keeps the decay a node suffers a function of how
	// long it has gone unattested and NOT of how often anyone called Advance. (The
	// naive version compounds 0.5^(sum of elapsed) instead of 0.5^(elapsed) and
	// decays quadratically: an idle node loses ~60% of its rating in an hour against
	// a 24h half-life. TestDecayIsIndependentOfAdvanceFrequency pins this.)
	baseEst Rate

	lastInform time.Time // last window that carried information; decay measures from here
	lastObs    Rate      // last informative observation, for operator-facing status
	lastASes   int

	// informed is true once a window has closed with enough distinct ASes to move the
	// estimate on real evidence, and false again once decay has pulled that evidence
	// all the way back to Floor. It is what lets a NodeRating (old #158) ask whether
	// a TRUSTED rating actually EXISTS for a node — "trusted decides wherever it exists"
	// (design §8.1.1, rule 2) — versus the node merely sitting at its unfed Floor, in
	// which case the untrusted rating decides. An unfed estimator is never informed,
	// which is exactly the trusted stream's state until the account service stamps
	// vouched-ness (old #157 seam). Seed does NOT set it: an install-probe seed is a
	// provisional starting point, not earned attestation.
	informed bool
}

// NewEstimator builds an Estimator starting at p.Floor.
func NewEstimator(p Params, now time.Time) (*Estimator, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("capacity params: %w", err)
	}
	return &Estimator{
		p:          p,
		est:        p.Floor,
		baseEst:    p.Floor,
		pending:    map[string][]Rate{},
		asOf:       map[string]string{},
		lastInform: now,
	}, nil
}

// Seed sets a provisional starting estimate, clamped to [Floor, Ceiling].
//
// This is where an install-time probe's number enters, and the clamp is the whole
// point: the probe is NOT trusted (cmd/capacity-probe's README explains why — a
// node can be fast to every Bacchus peer, whose addresses it can simply enumerate
// via `list`, and slow to every client). A seed only saves an HONEST node a slow
// ramp; it can never buy a liar more than Ceiling, and from there the node must
// earn its rating by delivering to real attesters like everyone else.
func (e *Estimator) Seed(r Rate, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r < e.p.Floor {
		r = e.p.Floor
	}
	if e.p.Ceiling != 0 && r > e.p.Ceiling {
		r = e.p.Ceiling
	}
	e.est, e.baseEst, e.lastInform = r, r, now
}

// Observe records a sample for the current window. Unsaturated samples are
// dropped: they carry no capacity information (a client that got 1 Mbit because it
// only wanted 1 Mbit says nothing about the node), and dropping most traffic is
// correct rather than wasteful — see the design note §5.3.
//
// Samples with no Attester or no AS are dropped too: influence caps are per
// attester and per AS, so an unattributable sample is one that cannot be capped,
// and accepting it would be a hole rather than a kindness.
//
// A SATURATED sample of ZERO throughput is kept, and keeping it matters more than
// any other single line here. It is not a missing measurement — it is a client that
// wanted bytes and got none, i.e. the strongest possible evidence a node is not
// delivering. Dropping it would leave the design's central claim ("every session is
// scored, so there is no unscored flow to hide in", §7.1) simply false: a node could
// BLACKHOLE strangers instead of throttling them, their samples would never reach
// the estimator at all, and the votes would be its colluders' alone. Measured, that
// bug was worth ~4800x — blackholing held a 1.2 Gbit rating where throttling to
// 1 bit/s collapsed to the floor. Serving nothing must never score better than
// serving almost nothing.
func (e *Estimator) Observe(s Sample) {
	if !s.Saturated || s.Attester == "" || s.AS == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending[s.Attester] = append(e.pending[s.Attester], s.Throughput)
	e.asOf[s.Attester] = s.AS
}

// Advance closes the current scoring window and returns the new estimate. It is
// the whole methodology in one function.
//
// # Collapsing samples to votes
//
// Volume must buy nothing, so influence is collapsed twice before anything is
// measured:
//
//  1. per attester -> the median of its samples. One client = one number, whether
//     it submitted one sample or ten thousand.
//  2. per AS -> the MINIMUM over that AS's attesters. One AS = ONE VOTE, whether
//     the attacker rented one VPS in it or a hundred. The AS is the coordinator-
//     OBSERVED one, so this cap cannot be evaded by claiming otherwise.
//
// The unit of Sybil cost is therefore an AS, not a client, not a sample.
//
// Step 2 takes the minimum rather than the median, and that difference is the whole
// point of the step. A median lets an attacker CAPTURE an AS that honest clients
// already attest from: n honest attesters are outvoted by n+1 sybil attesters in
// the same AS, and n is typically one or two — so a handful of residential-proxy
// addresses flips an AS the attacker never had to occupy. Measured, that bug held a
// 125 Mbit rating across four honest ASes each genuinely throttled to 2 Mbit. It
// also quietly falsified this design's claim that honest clients "only have to
// exist": with a median they must out-shout the attacker WITHIN their own AS.
//
// With a minimum, one honest throttled attester makes its AS vote honestly no matter
// how many sybils crowd in beside it. Existing is enough again.
//
// The cost is that one attester can also drag its AS's vote down — a defamer, or
// just a client on bad wifi. That is the trade the design note §8.2 already takes on
// purpose: this package errs toward under-rating, because over-rating hurts users
// now while under-rating only wastes capacity.
//
// # Selecting the estimate
//
// Over those per-AS votes, take a LOW quantile (Params.Quantile). An attacker
// wanting to hold estimate E must make (1-Quantile) of ALL attesting ASes report
// >= E — 75% of them at the default. Honest throttled clients do not have to
// out-shout the attacker; they only have to EXIST, because each one they add to
// the lower tail drags the quantile down.
//
// # Moving the estimate
//
// Rise is multiplicatively capped; fall snaps straight to the observation. The
// asymmetry is deliberate: the two errors are not equal. Over-estimation routes
// real users to a node that cannot carry them, and they suffer now.
// Under-estimation only wastes capacity, hurts nobody, and self-corrects on the
// next saturated window. So: slow to trust, fast to distrust.
//
// # Why the rise cap is the security property
//
// The estimate cannot grow by more than RiseFactor per window NO MATTER WHAT THE
// SAMPLES SAY. Even against an attacker who forges every sample perfectly, a 10x
// inflation costs ~11 consecutive windows of sustained collusion — and during
// every one of them the node is being handed real clients at its rising rating,
// whose own attestations snap it back down (fast, per the asymmetry above). The
// attacker cannot both hold a high rating and dodge the traffic that rating
// attracts. Decay then makes the cost recurring rather than a one-time purchase.
//
// That is the difference between this and a peak estimator, which one forged
// sample defeats permanently. The rate limit is not smoothing. Do not "optimise"
// it into one.
func (e *Estimator) Advance(now time.Time) Rate {
	e.mu.Lock()
	defer e.mu.Unlock()

	votes, ases := e.collapse()
	e.pending = map[string][]Rate{}
	e.asOf = map[string]string{}
	e.lastASes = len(votes)

	// Decay first, ALWAYS, so this window is judged against the rating the node
	// currently holds rather than a stale one. Decaying only on the uninformative
	// branch would mean a node that goes quiet for a week and then gets one good
	// window resumes its ratchet from a level it has not re-earned since. Decay is a
	// property of elapsed silence, not of which branch happens to run next.
	e.decay(now)

	// Too few distinct ASes to learn anything: one AS's view of a node is one
	// path's view. The window is not evidence of health, so it earns no rise; it is
	// not evidence of failure either, so it earns no snap-down.
	if len(votes) < e.p.MinASes {
		return e.est
	}

	observed := quantile(votes, e.p.Quantile)
	e.lastObs = observed

	// The provisional ceiling holds until enough distinct ASes have attested — or, for
	// the untrusted stream (HardCeiling), permanently (old #158, design §8.1.1).
	ceil := Rate(math.MaxUint64)
	if e.p.Ceiling != 0 && (e.p.HardCeiling || ases < e.p.CeilingASes) {
		ceil = e.p.Ceiling
	}

	switch {
	case observed >= Rate(float64(e.est)*e.p.RiseThreshold):
		// Meeting its rating: ratchet up, slowly, and never past the ceiling gate.
		next := Rate(float64(e.est) * e.p.RiseFactor)
		if next > ceil {
			next = ceil
		}
		if next > e.est {
			e.est = next
		}
	case observed < Rate(float64(e.est)*e.p.FallThreshold):
		// Failing to deliver: snap to what was actually observed. No attribution is
		// attempted or needed — a throttling node and a congested node are the same
		// node from here, and the right action for both is "route less traffic here".
		e.est = observed
	}
	if e.est < e.p.Floor {
		e.est = e.p.Floor
	}
	if e.est > ceil {
		e.est = ceil
	}
	// This window carried information, whichever way it moved the estimate (a node
	// sitting exactly at its rating is being re-earned too). Re-base the decay clock,
	// and mark the estimator informed: a rating now EXISTS (old #158), even if the
	// evidence put it at Floor, until decay expires it.
	e.lastInform, e.baseEst, e.informed = now, e.est, true
	return e.est
}

// collapse reduces this window's samples to one vote per AS: median per attester,
// then MINIMUM per AS. Returns the votes and the distinct AS count. Caller holds mu.
//
// See Advance for why step 2 is a minimum and not a median: a median is capturable
// by outnumbering an AS's honest attesters, which are usually one or two.
func (e *Estimator) collapse() (votes []Rate, ases int) {
	byAS := map[string][]Rate{}
	for attester, rates := range e.pending {
		as := e.asOf[attester]
		if as == "" || len(rates) == 0 {
			continue
		}
		byAS[as] = append(byAS[as], median(rates))
	}
	for _, v := range byAS {
		votes = append(votes, minRate(v))
	}
	return votes, len(byAS)
}

// minRate returns the smallest value in xs, or 0 for an empty slice.
func minRate(xs []Rate) Rate {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs[1:] {
		if x < m {
			m = x
		}
	}
	return m
}

// decay pulls an un-re-earned estimate back toward the floor. Caller holds mu.
//
// Computed fresh from baseEst (the estimate as of the last informative window)
// rather than by scaling the current est, so the result is a pure function of how
// long the node has gone unattested — idempotent, and independent of how often
// anyone calls Advance. Scaling est in place would compound 0.5^(sum of elapsed)
// instead of 0.5^(elapsed) and decay quadratically, punishing an honest idle node
// (see baseEst).
func (e *Estimator) decay(now time.Time) {
	elapsed := now.Sub(e.lastInform)
	if elapsed <= 0 {
		return
	}
	f := math.Pow(0.5, elapsed.Seconds()/e.p.HalfLife.Seconds())
	next := Rate(float64(e.baseEst) * f)
	if next < e.p.Floor {
		next = e.p.Floor
		// Decayed all the way back to Floor: the informative evidence has fully
		// expired, so this estimator no longer holds a rating that "exists" for the
		// NodeRating combine (old #158). A future window with fresh evidence re-sets
		// it (Advance).
		e.informed = false
	}
	e.est = next
}

// Estimate returns the current measured rate without closing a window.
func (e *Estimator) Estimate() Rate {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.est
}

// Informed reports whether this estimator currently holds a rating earned from real
// evidence — at least one window has closed with enough distinct ASes to move the
// estimate, and decay has not since pulled that evidence back to Floor. A NodeRating
// uses it to decide whether a TRUSTED rating EXISTS for a node (design §8.1.1): an
// unfed or fully-decayed trusted estimator is not informed, so the untrusted rating
// decides instead. See the informed field.
func (e *Estimator) Informed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.informed
}

// Status is an operator-facing snapshot of an estimator, for logs and diagnostics.
type Status struct {
	Estimate     Rate
	LastObserved Rate
	LastASes     int
	LastInform   time.Time
}

// Status returns a snapshot for operator-facing output.
func (e *Estimator) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{Estimate: e.est, LastObserved: e.lastObs, LastASes: e.lastASes, LastInform: e.lastInform}
}

// Usable is the number the rest of the system consumes:
//
//	usable = min(declared, measured)
//
// with the declared term omitted when the operator declared no cap (zero =
// unlimited), and the measured term binding always. This is the one place the two
// halves of the lane meet, and the direction of each is what makes the other safe
// — see the package doc's trust asymmetry.
//
// It is NOT an eligibility test. Whether `usable` clears a bar to serve is
// old #145's policy decision.
func Usable(declared Rate, measured Rate) Rate {
	if declared == 0 {
		return measured
	}
	if measured < declared {
		return measured
	}
	return declared
}

// median returns the middle value of xs, taking the LOWER of the two middles for
// an even count rather than averaging them. Lower because every tie-break in this
// package errs toward under-rating, and because averaging would invent a rate
// nobody observed.
func median(xs []Rate) Rate {
	if len(xs) == 0 {
		return 0
	}
	s := append([]Rate(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[(len(s)-1)/2]
}

// quantile returns the q-quantile of xs by nearest-rank, rounding the index DOWN.
//
// Nearest-rank rather than interpolating: it always returns a value some AS
// actually reported, so the estimate is always a rate that was really observed
// rather than one synthesised between two observations. Rounding down keeps the
// conservative direction consistent with median.
func quantile(xs []Rate, q float64) Rate {
	if len(xs) == 0 {
		return 0
	}
	s := append([]Rate(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(q * float64(len(s)-1))
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}
