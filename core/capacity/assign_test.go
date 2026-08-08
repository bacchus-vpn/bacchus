package capacity

import "testing"

// Assignment arithmetic (old #146, ADR-0042).

// TestProjectedShareReportsUnlimitedRatherThanEncodingIt pins the distinction the type
// exists for. "No information" cannot be a number: 0 would rank an uncapped node last
// and a maximum sentinel would let an unrated node outrank every measured one forever.
// It is returned as a flag so the caller has to decide.
func TestProjectedShareReportsUnlimitedRatherThanEncodingIt(t *testing.T) {
	share, unlimited := ProjectedShare(0, 3)
	if !unlimited {
		t.Error("a usable rate of 0 (uncapped, unrated) did not report unlimited")
	}
	if share != 0 {
		t.Errorf("share = %s alongside unlimited; want 0 so a caller cannot read it by mistake", share)
	}

	for _, tc := range []struct {
		usable   Rate
		sessions int
		want     Rate
	}{
		{8 * Mbit, 0, 8 * Mbit},  // idle: the whole pipe
		{8 * Mbit, 1, 4 * Mbit},  // one session already: halved
		{8 * Mbit, 3, 2 * Mbit},  // three: quartered
		{8 * Mbit, -1, 8 * Mbit}, // a negative count is clamped, never a divide-by-zero
	} {
		got, unlimited := ProjectedShare(tc.usable, tc.sessions)
		if unlimited {
			t.Errorf("ProjectedShare(%s, %d) reported unlimited for a capped node", tc.usable, tc.sessions)
		}
		if got != tc.want {
			t.Errorf("ProjectedShare(%s, %d) = %s; want %s", tc.usable, tc.sessions, got, tc.want)
		}
	}
}

// TestRankShareMakesForgingWorthWhatSilenceIsWorth is the old #157 rule applied to
// assignment. An UNRATED node's capacity is its own self-report, so ranking on it raw
// would pay a liar in assignments. Clamped, a node claiming 10 Gbit ranks exactly
// level with one claiming nothing at all — and level with an honestly measured node at
// the ceiling.
func TestRankShareMakesForgingWorthWhatSilenceIsWorth(t *testing.T) {
	const ceiling = 5 * Mbit

	liar := RankShare(10*Gbit, 0, false, ceiling)  // unrated, declares an absurd cap
	silent := RankShare(0, 0, false, ceiling)      // unrated, declares nothing
	honest := RankShare(ceiling, 0, true, ceiling) // measured at the ceiling
	modest := RankShare(1*Mbit, 0, true, ceiling)  // measured below the ceiling

	if liar != silent {
		t.Errorf("an unrated node declaring 10 Gbit ranks %s but declaring nothing ranks %s; forging must buy exactly what silence buys", liar, silent)
	}
	if liar != honest {
		t.Errorf("an unrated liar ranks %s and an honestly measured node at the ceiling ranks %s; the clamp must level them", liar, honest)
	}
	if !(modest < honest) {
		t.Errorf("a node measured at %s does not rank below one at the ceiling (%s vs %s)", 1*Mbit, modest, honest)
	}

	// A RATED node above the ceiling is still clamped: the ceiling is the bound on
	// what any rating can be worth here, not merely a bound on self-reports.
	if got := RankShare(10*Gbit, 0, true, ceiling); got != honest {
		t.Errorf("a rated node above the ceiling ranks %s; want it clamped to %s", got, honest)
	}

	// The LOAD term is not clamped — it is the part the coordinator observed itself,
	// and today the only part that discriminates.
	busy := RankShare(0, 3, false, ceiling)
	if !(busy < silent) {
		t.Errorf("load did not lower the rank: 3 sessions ranks %s, idle ranks %s", busy, silent)
	}
}

// TestOctaveFloorAdmitsExactlyWithinAFactorOfTwo pins the tier boundary as a RELATIVE
// band, which is the property the doc claims: everything admitted is within 2x of the
// best, everything rejected is more than 2x worse. An earlier absolute power-of-two
// bucketing failed this — 1.0 and 1.9 Mbit straddle 2^20 and landed in different
// tiers, so a node just under a boundary gained a tier for a marginal improvement,
// which is a boundary to tune against.
func TestOctaveFloorAdmitsExactlyWithinAFactorOfTwo(t *testing.T) {
	// The straddling pair that broke absolute bucketing: same tier now, from either
	// direction, because the band is measured from the best candidate.
	if OctaveFloor(1_900_000) > 1_000_000 {
		t.Errorf("1.0 Mbit excluded from 1.9 Mbit's tier (floor %s); they are within a factor of two",
			OctaveFloor(1_900_000))
	}

	for _, tc := range []struct {
		best, share Rate
		want        bool
	}{
		{8 * Mbit, 8 * Mbit, true},    // the best candidate always clears its own floor
		{8 * Mbit, 4 * Mbit, true},    // exactly half: still indistinguishable
		{8 * Mbit, 4*Mbit - 1, false}, // a hair under half: excluded
		{8 * Mbit, 1 * Mbit, false},   // 8x worse
		{1, 1, true},                  // smallest non-zero clears its own floor
		{0, 0, true},                  // a zero field: everything ties
	} {
		got := tc.share >= OctaveFloor(tc.best)
		if got != tc.want {
			t.Errorf("share %s against best %s: in-tier = %v, want %v (floor %s)",
				tc.share, tc.best, got, tc.want, OctaveFloor(tc.best))
		}
	}

	// The floor never exceeds the best candidate, or the best candidate itself would
	// be excluded and chooseExit's second pass would find nothing.
	for _, best := range []Rate{0, 1, 2, 3, 255, 256 * Kbit, 1 * Mbit, 5 * Mbit, 1 * Gbit} {
		if OctaveFloor(best) > best {
			t.Errorf("OctaveFloor(%s) = %s exceeds the best share itself", best, OctaveFloor(best))
		}
	}
}

// TestFullIsOffAtZeroAndNeverCatchesAnUncappedNode pins both halves of how old #147's
// share-based trigger ships: disabled at zero, and — even when enabled — inert for a
// node that declared nothing and has been measured at nothing, which is the standing
// opt-in promise declared limits make everywhere else.
func TestFullIsOffAtZeroAndNeverCatchesAnUncappedNode(t *testing.T) {
	// minShare 0: nothing is ever full, however loaded.
	if Full(1*Kbit, 1_000_000, false, 0) {
		t.Error("Full fired with minShare 0; the share-based trigger must be off at zero")
	}

	// Uncapped and unrated: never full, even under a floor it could not possibly meet.
	if Full(0, 1_000_000, Unmetered(0, false), 1*Gbit) {
		t.Error("an uncapped, unrated node was reported full; declared limits are opt-in")
	}

	// Non-vacuity: with a real cap and a real floor, the trigger does fire — so the
	// two assertions above are about the guards, not about Full never working.
	if !Full(1*Mbit, 9, false, 256*Kbit) {
		t.Error("a 1 Mbit node carrying 9 sessions is not full against a 256 Kbit floor; the mechanism is dead")
	}
	if Full(1*Mbit, 1, false, 256*Kbit) {
		t.Error("a 1 Mbit node carrying 1 session was reported full against a 256 Kbit floor")
	}
}

// TestFullExemptsSilenceOnly pins the boundary of the opt-out, which is much narrower
// than "uncapped nodes are exempt" — the claim ADR-0042 used to make.
//
// Usable(0, measured) returns `measured`: a declared zero means "uncapped" and does not
// survive a measurement. So a node that declared nothing but has been measured carries
// a finite usable rate and IS subject to the floor. Under ADR-0041 ("measurement IS
// serving") that is every node actually carrying traffic — the opposite of "raising the
// floor cannot strand today's fleet".
func TestFullExemptsSilenceOnly(t *testing.T) {
	const floor = 1 * Gbit

	// Declared nothing, measured never: exempt.
	if Full(0, 10, Unmetered(0, false), floor) {
		t.Error("an uncapped, unrated node was reported full; that is the opt-in promise")
	}
	// Declared nothing, but measured at 2 Mbit: NOT exempt. Its usable rate is the
	// measurement, and 2Mbit/11 is far below a 1 Gbit floor.
	if !Full(2*Mbit, 10, Unmetered(0, true), floor) {
		t.Error("a node that declared nothing but HAS been measured escaped the floor; " +
			"Usable(0, measured) == measured, so a measured node is metered and subject to it")
	}
	// DECLARED a cap, never measured: also NOT exempt. Declaring is opting in — the
	// exemption is for silence, not for every unmeasured node.
	if !Full(2*Mbit, 10, Unmetered(2_000_000, false), floor) {
		t.Error("a node that declared a cap escaped the floor; a declaration is what the mechanism honours")
	}
}

// TestFullExemptionSurvivesAClampedRate is the hazard the caller-obligation version of
// this contract could not prevent.
//
// RankShare clamps an unrated node's capacity term to the ceiling so a self-declaration
// cannot buy assignments. That clamped value is non-zero, so a fullness gate keyed on
// "usable == 0" flips to the opposite answer for exactly the nodes the opt-in promise
// protects — and nothing fails while it does. Unmetered is computed from the operator's
// declaration and the rating flag, neither of which a clamp touches, so the exemption
// holds whatever rate is passed alongside it.
func TestFullExemptionSurvivesAClampedRate(t *testing.T) {
	const floor = 1 * Gbit
	unmetered := Unmetered(0, false)

	clamped := RankShare(0, 10, false, 5*Mbit)
	if clamped == 0 {
		t.Fatal("setup: RankShare should clamp an unrated node to a non-zero ceiling share")
	}
	if Full(clamped, 10, unmetered, floor) {
		t.Error("a clamped rank share flipped an unrated, undeclared node to full")
	}
	// And the same clamped number for a METERED node is still judged on its merits, so
	// the exemption is doing the work rather than the value being ignored.
	if !Full(clamped, 10, false, floor) {
		t.Error("a metered node at the same clamped rate escaped the floor")
	}
}
