package capacity

// This file holds the arithmetic the coordinator's country-scoped exit assignment
// runs on (old #146, ADR-0042). Only the arithmetic: which exit is actually chosen
// is policy and lives in cmd/coordinator, because it depends on registry state
// (liveness, quota disposition, the client's exclusions) this package knows nothing
// about.
//
// The shape is deliberately coarse. ADR-0033's pickRelay argues at length that a
// DETERMINISTIC best-node pick is harmful — it lets a node that controls its own
// advertised numbers make itself the perpetual choice, concentrates on it the source
// addresses and timing a forwarder can observe, and defeats the client's
// cross-coordinator failover, since every coordinator would keep handing back the
// same node. ADR-0040 draws the same conclusion for declared limits: they compose as
// a FILTER, never as a sort.
//
// Country-scoped assignment needs *some* preference order, so the compromise is a
// tier rather than a total order: every node within a factor of two of the roomiest
// candidate is indistinguishable from it, and the caller picks at random among them.
// Two properties fall out. A node has to be about twice as roomy as the field to be
// preferred at all, so shaving a number buys nothing. And ranking by projected share
// is self-correcting in a way freshest-first never was — every session assigned to the
// roomiest node lowers that node's own share, so the choice moves on by itself.

// ProjectedShare is the bandwidth a node could offer ONE MORE session: its usable
// rate divided among the sessions it already carries plus the prospective one.
//
// unlimited reports that the node's usable rate carries no information at all —
// neither a declared cap nor a measured rating (see Usable, where a declared 0 means
// uncapped). That case must be reported rather than encoded as a number, because the
// natural encodings are both wrong: 0 would rank an uncapped node LAST, and a
// maximum sentinel would let an unrated node outrank every measured one forever. The
// caller decides what "no information" is worth; this function refuses to guess.
//
// share is 0 when unlimited is true — read one, not the other.
func ProjectedShare(usable Rate, sessions int) (share Rate, unlimited bool) {
	if usable == 0 {
		return 0, true
	}
	if sessions < 0 {
		sessions = 0
	}
	return usable / Rate(sessions+1), false
}

// RankShare is ProjectedShare with the anti-forgery clamp assignment ranking needs,
// and is what a caller ordering candidates should use.
//
// The clamp: a node with no measured rating falls back to its DECLARED cap (see
// RatingStore.Usable), which is a self-report. Ranking on it raw would mean an
// unrated node claiming 10 Gbit outranks an honestly-measured neighbour — paying for
// the claim in assignments, which is exactly the trade old #157 refused. So an unrated
// node's capacity contribution is clamped to `ceiling`, the same bound the untrusted
// estimator clamps to, making a forged or inflated declaration buy precisely what
// silence buys and not one bit more.
//
// rated says whether the node has a measured rating; pass RatingStore.Measured's
// second return. When it is false the capacity term is clamped, and an unrated node
// with no declared cap is treated as exactly `ceiling` rather than unlimited — again
// so that declaring nothing and declaring everything land in the same place.
//
// The LOAD term is never clamped, and today it is the only term that discriminates:
// with the trusted sample stream unfed every rating sits at or below `ceiling`, so
// candidates tie on capacity and are separated by how many sessions they already
// carry — a number this coordinator OBSERVED and no node can assert.
func RankShare(usable Rate, sessions int, rated bool, ceiling Rate) Rate {
	if !rated || usable == 0 || usable > ceiling {
		usable = ceiling
	}
	share, _ := ProjectedShare(usable, sessions)
	return share
}

// OctaveFloor returns the lowest share that still counts as indistinguishable from
// best: a candidate is in the top tier when its share is >= OctaveFloor(best), which
// is to say within a factor of two of the roomiest candidate.
//
// The band is RELATIVE to the best candidate, not a fixed power-of-two bucket. That
// matters: absolute bucketing puts a fixed boundary in the number line, and a node
// sitting just under one climbs a whole tier for a marginal improvement — a boundary
// to tune against. Measured from the best candidate there is no fixed boundary to sit
// beneath, and the property is exactly true rather than approximately: everything in
// the tier really is within 2x of the best, and everything excluded really is more
// than 2x worse.
//
// This is the granularity of the whole preference order, and it is intentionally
// crude — see this file's doc. A finer order would be false precision over a number
// that is part self-report and part ceiling-clamped estimate, and it would rebuild the
// deterministic winner ADR-0033 forbids.
func OctaveFloor(best Rate) Rate {
	return (best + 1) / 2
}

// Full reports whether a node has no room for another session: whether the share one
// more session could expect has fallen below minShare.
//
// Unmetered reports that nothing at all is known about a node's capacity: its operator
// declared no cap (declared == 0 means uncapped, see Usable) and no measurement exists.
//
// It is a named predicate rather than a condition spelled out at each call site because
// it is the exact boundary of the opt-in promise declared limits make (old #143, ADR-0040),
// and because the obvious shorthand for it is wrong. "usable == 0" LOOKS equivalent —
// for an unrated node the usable rate IS the declaration — but it survives only until a
// caller passes a transformed rate. RankShare's output, for instance, clamps an unrated
// node to the ceiling, which is non-zero, so a gate keyed on usable == 0 silently flips
// to the opposite answer for exactly the nodes the promise protects.
//
// Taking the operator's own declaration and the rating flag closes that off: neither is
// something a clamp or a projection can alter on the way in.
func Unmetered(declared uint64, rated bool) bool { return !rated && declared == 0 }

// Full reports whether a node has no room for another session: whether the share one
// more session could expect has fallen below minShare.
//
// unmetered is [Unmetered] for the node — pass it, do not reconstruct it.
//
// # The opt-out, stated precisely
//
// An unmetered node is never full: an operator who declared nothing, about whom nothing
// is known, is treated exactly as they were before any of this existed.
//
// The promise stops exactly there, and the boundary is worth stating because it is
// narrower than it first reads. Usable(0, measured) returns `measured` — a declared
// zero means "uncapped", so it does not survive a measurement. An exit that declared
// nothing and has received ANY capacity report is therefore rated, carries a finite
// usable rate, and IS subject to this test. Under ADR-0041 ("measurement IS serving")
// that is every exit actually carrying traffic. So raising minShare reaches the serving
// fleet; it is only the never-measured, never-declared node it cannot touch.
//
// A node that DECLARED a cap and has not been measured is likewise subject to it, and
// deliberately: declaring a cap is the operator saying what they are willing to carry,
// and honouring it is what the mechanism is for. The exemption is for silence, not for
// every unmeasured node.
//
// minShare of 0 makes this always false. That is how it SHIPS — see ADR-0042: a floor
// above zero, applied to ratings that are all ceiling-clamped today, would cap a
// rated exit at a couple of dozen sessions when it can carry orders of magnitude
// more, stranding users to protect a number that is not yet real. It is the same trap
// old #145's serve floor is held at zero for, and it lifts on the same condition: a fed
// trusted stream.
func Full(usable Rate, sessions int, unmetered bool, minShare Rate) bool {
	if minShare == 0 {
		return false
	}
	if unmetered {
		// Checked before ProjectedShare so the exemption holds whatever rate the
		// caller passed — including a clamped one.
		return false
	}
	share, unlimited := ProjectedShare(usable, sessions)
	if unlimited {
		return false
	}
	return share < minShare
}
