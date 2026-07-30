package main

import (
	"log"
	"net"
	"sort"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/geoip"
)

// Country-scoped exit assignment and country-granularity backpressure (issues #146
// and #147, ADR-0042).
//
// The user picks a COUNTRY; this coordinator picks the exit inside it. There is no
// exact-exit pinning for anyone — not as a tier perk, not as a debug affordance —
// because a client that can name an exit both defeats load balancing and carries a
// small, stable tracking handle. Removing the pin deletes the handle.
//
// Every function here is called with mu held (from handle), and reads the same
// registry maps the rest of the file does.

// countryInfo is one entry in the country list a client receives from `list`. It is
// the whole of what a client learns about the network's shape, and it is aggregate by
// construction — counts and dispositions per country, never per node.
//
// This is strictly LESS than clients used to get. The old reply enumerated every
// exit's id, which is both a network map and the raw material for pinning; a count is
// not.
type countryInfo struct {
	Country string `json:"country"`

	// Exits is how many exits this coordinator knows in the country, Available how
	// many of those it would assign right now. Both are needed: Exits alone cannot
	// express "the country exists but is full", which is the state #147 has to be
	// able to say out loud.
	Exits     int `json:"exits"`
	Available int `json:"available"`

	// Busy is Available == 0 — the country is known but nothing in it is assignable.
	// Sent as its own field rather than left to the client to infer, because it is
	// the thing the UI renders ("<country> is busy — try another") and a derived
	// condition invites two clients to derive it differently.
	Busy bool `json:"busy"`

	// PingMs is the aggregate round-trip time clients have observed to this country,
	// in milliseconds; 0 means "not known" and the client shows no latency.
	//
	// It is ALWAYS 0 today. This is an unfed seam, exactly like ADR-0041's trusted
	// rating stream: the only honest source of a client-to-country latency is the
	// clients themselves, whose reporting path lives outside this lane. The field
	// ships so the shape is settled and a client can render it the moment it is fed;
	// it does not ship carrying a number derived from something else. Deriving it
	// from THIS coordinator's own RTT to each exit was considered and rejected — it
	// measures coordinator-to-exit latency, which is not the quantity the user is
	// choosing on, and a plausible-looking wrong number is worse than a blank.
	PingMs int `json:"pingMs,omitempty"`
}

// assignRefusal names why a country-scoped connect could not be satisfied. It is sent
// to the client in wire.Reason.
//
// The pre-#146 connect answered every failure with a bare error, deliberately, so a
// probing client could not tell "no such exit" from "that exit is out of quota". That
// reticence does not apply to these two: both facts are already in the country list
// the same credentialed client just fetched, so naming them tells it nothing it could
// not already read, and #147 specifically requires the client be ABLE to distinguish
// "busy, try another country" from "that country does not exist".
type assignRefusal string

const (
	refuseNone        assignRefusal = ""
	refuseNoCountry   assignRefusal = "no-such-country"
	refuseCountryBusy assignRefusal = "country-busy"
	refuseNoHop       assignRefusal = "no-such-hop"
	// refuseHopNotRelayMode answers a connect that names a first hop without
	// asking for relay mode. It names the client's own malformed request back to
	// it and reveals nothing about the network — see the wire.FirstHop guard in
	// the connect handler for why the combination is refused rather than honoured.
	refuseHopNotRelayMode assignRefusal = "hop-needs-relay-mode"
	// refuseNoNonce answers a connect carrying no per-connect idempotency key, or one
	// too long to store (issue #1, ADR-0042 §2). Like refuseHopNotRelayMode it names
	// the client's own malformed request back to it and reveals nothing about the
	// network — an unnonced connect is refused identically whether the country is
	// empty, busy, or full of exits.
	//
	// Refusing rather than falling back to per-datagram assignment is the decision, not
	// the message. An idempotency key a client may omit gives the pre-#1 behaviour —
	// several independent exit draws per request — to precisely the client that wants
	// it, so the guard would bind only the honest.
	refuseNoNonce assignRefusal = "connect-needs-nonce"
	// refuseUnknownTier answers a client whose credential's (trust, plan) pair
	// resolves to no row in the signed policy this coordinator holds (issue #58,
	// ADR-0048; ADR-0006 decision 5). It is a refusal and never a fallback — see
	// resolveTier for why substituting either a permissive or a restrictive default
	// is worse than refusing.
	//
	// Named rather than bare on the same reasoning as refuseCountryBusy: the pair is
	// the client's OWN credential's claim about itself and the policy is a signed
	// document its holder can read, so naming it back reveals nothing it does not
	// already hold — and it is the only refusal here whose fix is "your plan is not
	// provisioned on this coordinator", which is unguessable from a bare error.
	refuseUnknownTier assignRefusal = "unknown-tier"
)

// resolveFirstHop answers a connect that names its own first peeling hop (issue
// #142, ADR-0038; the wire.FirstHop field ADR-0042 §9 reserved).
//
// It is deliberately NOT chooseExit with a filter. Nothing about country, ranking,
// load or exclusion applies: the client is not asking this coordinator to choose,
// it is asking to be wired to one specific node it already selected out of the
// signed directory, and the only question left is whether that node is currently a
// registered exit this coordinator can pair to at all.
//
// Capacity is not consulted, and that is a real decision rather than an omission. A
// chained session is invisible to exit ranking by construction (§9 — it records no
// exit id, because this coordinator does not know the terminating exit), so there is
// no meaningful load number to compare it against, and refusing a hop for fullness
// would leak the ranking state of a node the client is not egressing through. What
// bounds a hop's load is the hop's own quota enforcement and the directory it is
// published in, not this decision.
//
// The refusal is named (refuseNoHop) rather than bare because it is ACTIONABLE in a
// way no other failure is: it means the client's cached directory has drifted from
// this coordinator's registry, and the fix is to refresh it. It reveals only whether
// a node the client already holds an id for is registered here right now — which the
// same client learns from any snapshot it fetches.
func resolveFirstHop(id string) (*exitNode, assignRefusal) {
	e, ok := exits[id]
	if !ok || e.exhausted || e.udp == nil {
		return nil, refuseNoHop
	}
	return e, refuseNone
}

// minShare is the smallest bandwidth share an exit must be able to offer a new
// session before it is considered full (capacity.Full, issue #147).
//
// It MUST stay zero here, and zero means the share-based fullness test never fires.
// With the trusted sample stream unfed every measured rating sits at or below
// capacity Ceiling (5 Mbit, ADR-0041), so any floor above zero would cap a rated exit
// at a couple of dozen sessions when it can carry orders of magnitude more — the same
// trap #145's serve floor is pinned at zero for, reached from the other direction.
//
// #147 is NOT inert as a result: the quota-exhaustion trigger below is live today, so
// a country all of whose exits have spent their declared monthly quota is refused with
// refuseCountryBusy right now. What is off is only the share-based trigger, and it
// lifts on the same condition as #145 — a fed trusted stream.
//
// A var rather than a const only so a test can flip it and prove the mechanism is
// real; production never sets it.
var minShare capacity.Rate

// exitRating returns an exit's usable rate and whether it has a measured rating at
// all. The bool is what stops a self-reported declaration from being ranked as though
// it had been measured — see capacity.RankShare.
func exitRating(nodeID string, declared uint64) (usable capacity.Rate, rated bool) {
	if ratings == nil {
		return capacity.Rate(declared), false
	}
	_, rated = ratings.Measured(nodeID)
	return ratings.Usable(nodeID, capacity.Rate(declared)), rated
}

// exitSessions counts the recently-active sessions assigned to each exit, keyed by
// exit id. This is the load half of the assignment ranking, and the half that
// discriminates at all today: it is a number this coordinator OBSERVED itself, so
// unlike a declared cap there is nothing for a NODE to inflate.
//
// A client used to be a different matter, and the asymmetry is worth recording where
// the number is built. One Connect() puts several connect copies on the wire (sendN,
// once per mode) and each minted its own session, so a client could raise an exit's
// count several-fold without carrying any traffic through it — ADR-0042 §2's
// retransmission residual. The per-connect idempotency key (issue #1) closes that: the
// copies of one request now share one session, so a client raising this count pays one
// full pairing request per increment, and every one of them is observed here.
//
// It still counts sessions MINTED rather than tunnels served — see below — so a client
// willing to spend a request per increment can still inflate it. What changed is the
// price, from one datagram to one request.
//
// Built once per assignment rather than kept as a counter on exitNode, deliberately:
// the register handler replaces a node's registry struct wholesale every ~10 s, so a
// count stored there would silently reset to zero on every heartbeat and nothing
// would fail visibly — the identical trap ADR-0041 §5 hit with ratings. The sessions
// map is the single source of truth; a derived count cannot drift from it.
//
// # What this number is NOT
//
// It is not a tunnel registry. `sessions` is a SIGNALING RENDEZVOUS cache: only
// offer/answer/candidate refresh lastSeen, and pion stops emitting ICE candidates
// seconds after setup, so a perfectly healthy tunnel goes quiet here within seconds
// and its entry ages out. A session therefore contributes to load for about
// sessionTTL after it is paired and nothing after that. In steady state most exits
// read zero, tie at Ceiling/(0+1), and the tier pick degenerates to uniform random.
// That is the honest state of ranking today and ADR-0042 §6 says so out loud rather
// than implying a live load signal exists. The data plane deliberately does not touch
// this coordinator (ADR-0009/0033), so there is no honest liveness signal to read
// here; a node's own session count would be one, and it is precisely the number a
// node profits from understating.
//
// # Why the recency test is applied here and not left to prune
//
// prune EXEMPTS peer-relay sessions (main.go), because their liveness is their
// relay's and reselectDeadRelays is their sole reaper — correct for that purpose. But
// it means a peer-relay session lingers in the map for as long as its relay lives
// while a direct session vanishes after sessionTTL, so counting the raw map would
// give an exit serving relayed traffic a permanent load figure and its direct-serving
// neighbour a zero. Ranking on that systematically DEPRIORITISES exactly the exits
// carrying relayed traffic. Applying one recency window here makes every disposition
// decay identically: ranking stays uniformly blind, which is survivable, instead of
// asymmetrically wrong, which is not. TestRankingDecaysUniformlyAcrossDispositions
// pins both halves.
func exitSessions(now time.Time) map[string]int {
	load := make(map[string]int, len(exits))
	for _, s := range sessions {
		if s.exitID == "" {
			// No terminating exit is known for this session, so there is nothing to
			// attribute it to. Today only a malformed session could reach that state;
			// it is also the shape a client-assembled onion takes (ADR-0038, #142),
			// where the coordinator learns the first hop and never the exit. Such a
			// session must stay invisible to exit ranking rather than be charged to
			// the hop it does know — see ADR-0042 §9.
			continue
		}
		if now.Sub(s.lastSeen) > sessionTTL {
			continue
		}
		load[s.exitID]++
	}
	return load
}

// exitAssignable reports whether an exit may be given a new session right now. It is
// the single definition of assignable, shared by the country list and the assignment
// itself, so the aggregate a client is shown can never disagree with what it gets.
//
// It is per-CLIENT as of issue #58, because two of the signed policy's tier limits
// are answers to this question: a tier's endpoint-quality floor decides which exits
// it may be assigned to at all, and its priority decides how full an exit may be
// before it is refused one. Threading the resolved limits through here rather than
// applying them at the connect keeps the invariant this function exists for — the
// country list a client is shown is computed under the same limits the connect will
// enforce, so Available cannot promise what connect would then refuse.
//
// l is the zero tierLimits when no tier applies (see resolveTier), and every gate
// below is inert for it, which is the pre-#58 behaviour exactly.
func exitAssignable(e *exitNode, sessions int, l tierLimits) bool {
	if e.exhausted {
		// Its operator's declared monthly quota is spent for this cycle (#143).
		return false
	}
	if e.country == countryUnknown {
		// No country could be derived and no usable hint was given (#136), so this exit
		// is not reachable through a country choice at all.
		//
		// This cannot currently fire, and that is deliberate rather than overlooked:
		// countrySnapshot skips a country-less exit before it gets here (there is no
		// country to group it under), and chooseExit only ever considers exits whose
		// country EQUALS a canonical, non-empty code, which "" never does. It is kept
		// as an explicit guard because "may this exit take a new session" is the
		// question this predicate answers, and an unreachable exit is a genuine no —
		// so any future caller gets the right answer without having to know about the
		// two filters upstream. TestCountrylessExitIsNotAssignable exercises it
		// directly, so it is not untested dead code.
		return false
	}
	if !meetsServeFloor(e.id, e.speedCap) {
		// Issue #145's serve-eligibility floor; OFF (serveFloor is zero).
		return false
	}
	if _, ok := meetsEndpointQuality(e.id, l); !ok {
		// The signed policy's endpoint_quality for this client's tier (issue #58).
		// Withholds nobody while no class source is fed — see meetsEndpointQuality.
		return false
	}
	usable, rated := exitRating(e.id, e.speedCap)
	// The fullness floor is the tier's, not the network's: priority buys a session
	// admission onto an exit that is already full for a lower tier (tierMinShare).
	// Inert while minShare is zero, which is how it ships.
	return !capacity.Full(usable, sessions, capacity.Unmetered(e.speedCap, rated), tierMinShare(l))
}

// countrySnapshot aggregates the exit registry into the per-country view a client
// selects from (#146) and sees backpressure through (#147).
//
// A country with zero assignable exits is INCLUDED, marked busy. Dropping it — which
// is what the old per-exit list did with an exhausted exit — would make a full
// country silently vanish from the picker, and then there is no way to tell the user
// "<country> is busy" because the country is not there to label.
//
// Exits whose country could not be derived are absent entirely: they belong to no
// country, so no country choice can reach them.
//
// l is the requesting client's resolved tier limits (issue #58). Exits counts every
// exit in the country regardless of tier — it is the network's shape, and it must
// not become a per-tier oracle for how many premium exits a country holds — while
// Available is what THIS client could be assigned, which is the number Busy is
// derived from and the number connect has to agree with.
func countrySnapshot(now time.Time, l tierLimits) []countryInfo {
	load := exitSessions(now)
	agg := map[string]*countryInfo{}
	for _, e := range exits {
		if e.country == countryUnknown {
			continue
		}
		ci := agg[e.country]
		if ci == nil {
			ci = &countryInfo{Country: e.country}
			agg[e.country] = ci
		}
		ci.Exits++
		if exitAssignable(e, load[e.id], l) {
			ci.Available++
		}
	}
	out := make([]countryInfo, 0, len(agg))
	for _, ci := range agg {
		ci.Busy = ci.Available == 0
		out = append(out, *ci)
	}
	// Sorted so the reply is stable across calls — a country picker that reshuffles
	// itself every refresh is a bad picker, and a deterministic order makes the
	// aggregate testable. Ordering countries reveals nothing; which EXIT gets chosen
	// inside one is the thing kept unpredictable (see chooseExit).
	sort.Slice(out, func(i, j int) bool { return out[i].Country < out[j].Country })
	return out
}

// maxExcludeSessions bounds how many just-failed sessions one connect may name.
//
// This is a RESOURCE bound, not the security property — the security comes from the
// session binding in excludedExits. It sits comfortably above a legitimate client's
// own per-country retry budget (core/pool.go's countryAttempts), so an honest retry is
// never truncated, and it keeps a hostile connect from making this coordinator build
// an arbitrarily large map per datagram.
const maxExcludeSessions = 4

// minCandidatesAfterExclude is the smallest set of assignable exits an exclusion may
// leave behind. Honouring an exclusion that would leave fewer is refused — the whole
// exclusion is dropped and selection runs as if none had been sent.
//
// Two is the least number that preserves the property the tier pick exists for: with
// two or more survivors the client still cannot predict which it gets, and with one it
// can. See chooseExit's "Why exclusion cannot pin" for why the floor matters even
// though the session binding already makes exclusion expensive.
const minCandidatesAfterExclude = 2

// excludedExits resolves the session ids a client named on a connect into the set of
// exits to avoid, and is the whole reason exclusion cannot be turned into a pin.
//
// A client names SESSIONS THIS COORDINATOR MINTED FOR IT, never exit ids. That single
// substitution is what closes the complement attack: to exclude an exit you must first
// have been ASSIGNED that exit, and assignment is the randomized tier pick you are
// trying to steer. Naming the complement of a target is no longer something a client
// can simply assert — it has to actually be handed every other exit in the country
// first, at which point it has already been paying the same per-connect odds it was
// trying to avoid. Exclusion becomes non-amplifying by construction rather than by a
// bound chosen to be large enough.
//
// Two guards beyond that:
//
//   - src binding. A session is honoured only if it was minted for THIS source
//     address, so a client cannot name a session id it did not receive to discover or
//     steer around somebody else's exit. Session ids are 8 random bytes, so guessing
//     was already infeasible; the check makes the property structural instead of
//     probabilistic.
//   - A reaped or unknown session contributes nothing. It is silently skipped rather
//     than refused: the connect still succeeds, it simply may be handed the exit the
//     client hoped to avoid — which is exactly what happens when no exclusion is sent
//     at all, and is the behaviour ADR-0035's relay dedupe already degrades to.
func excludedExits(src *net.UDPAddr, sids []string) map[string]bool {
	if src == nil || len(sids) == 0 {
		return nil
	}
	if len(sids) > maxExcludeSessions {
		sids = sids[:maxExcludeSessions]
	}
	skip := make(map[string]bool, len(sids))
	for _, sid := range sids {
		s := sessions[sid]
		if s == nil || s.exitID == "" {
			continue // reaped, unknown, or an onion session with no exit to exclude
		}
		if s.client == nil || s.client.String() != src.String() {
			continue // not this client's session — never honour it
		}
		skip[s.exitID] = true
	}
	return skip
}

// chooseExit picks the exit to assign for a country, or explains why it cannot.
//
// exclude is the resolved output of excludedExits: exits this client has just failed
// against, so a retry is not handed the same broken exit — the same rotation-dedupe
// idea ADR-0035 introduced for relays (RelayTag), applied to exits now that the client
// no longer names one itself.
//
// # Why exclusion cannot pin
//
// Exclusion is bounded ADVISORY input, in two independent ways, because a hard
// unbounded filter is a pin wearing a different hat: a client that excludes every exit
// but one has named the one it wants, deterministically, and #146's central removal is
// undone by its complement.
//
//   - It is expressed in sessions, not exit ids (excludedExits), so the complement
//     cannot be asserted — only walked, one randomized assignment at a time.
//   - It is honoured only while it leaves minCandidatesAfterExclude assignable exits
//     behind. Past that the exclusion is dropped WHOLE and selection runs over the full
//     candidate set, so the most a client can ever do is narrow the field to a set it
//     still cannot choose within.
//
// Dropping the exclusion silently (rather than refusing) is deliberate. A refusal would
// tell the client its exclusion had crossed the threshold, which is a one-bit oracle on
// how many assignable exits the country holds; repeated, it counts them. Falling back
// to an ordinary assignment reveals nothing a plain connect would not.
//
// # How the winner is chosen, and why it is not simply "the best"
//
// ADR-0033's pickRelay forbids a deterministic best-node pick, and the reasons carry
// over to exits with force: a node that could make itself the perpetual choice would
// collect every client's source address and timing, and every coordinator in the pool
// would hand back the same node, so a client failing over between coordinators would
// keep landing on it. So this ranks into COARSE TIERS (capacity.Octave — a factor of
// two apart) and then picks at random within the best non-empty tier:
//
//   - A node cannot climb a tier by shaving a number; it has to be about twice as
//     roomy. And its capacity contribution is clamped unless it has actually been
//     measured (capacity.RankShare), so inflating a declaration buys what silence
//     buys.
//   - Ranking on projected share is self-correcting: each session assigned to the
//     roomiest exit lowers that exit's own share, so the choice moves along on its
//     own instead of piling onto one winner.
//
// The random pick inside the tier is Go's randomized map iteration order — the same
// mechanism, and the same argument, pickRelay already relies on. Two passes are
// needed because the best tier is not known until every candidate has been seen; the
// second pass's independent iteration order is what selects among the ties.
// l is the client's resolved tier limits (issue #58), applied through
// exitAssignable so the candidate set is exactly the one countrySnapshot counted
// as Available for the same client.
//
// Note where the tier does NOT reach: the octave banding below is untouched. The
// tier decides which exits a client may be assigned and how full one may be, not
// which of the survivors wins — turning priority into a sort would rebuild the
// deterministic best-node pick ADR-0033 forbids and ADR-0042 §3 keeps out, and it
// would do it with a number a paying client would then be able to observe.
func chooseExit(country string, exclude map[string]bool, now time.Time, l tierLimits) (*exitNode, assignRefusal) {
	cc := geoip.Canonical(country)
	if cc == countryUnknown {
		return nil, refuseNoCountry
	}
	load := exitSessions(now)

	// Pass 1: is the country known at all, and which of its exits are assignable?
	// Collected in map-iteration order, which Go randomizes per range — that is the
	// source of the arbitrary pick below, the same mechanism (and the same argument)
	// ADR-0033's pickRelay already relies on.
	known := false
	var candidates []*exitNode
	for _, e := range exits {
		if e.country != cc {
			continue
		}
		known = true
		if exitAssignable(e, load[e.id], l) {
			candidates = append(candidates, e)
		}
	}
	if !known {
		return nil, refuseNoCountry
	}
	if len(candidates) == 0 {
		// The country exists but nothing in it is assignable: every exit is out of
		// quota, withheld, below this tier's endpoint-quality floor, or too full for
		// its priority. This is #147. Note that exclusion cannot reach this branch —
		// it is applied below, and only when it leaves a real choice — so a client can
		// never busy out a country by excluding its way through it.
		//
		// A tier-driven refusal reports country-busy rather than a distinct reason,
		// deliberately: the alternative tells a client how many exits in a country sit
		// above or below its own class, which is a per-tier map of the network built
		// one connect at a time. #146 removed the per-exit list to close exactly that,
		// and the client's action is the same either way — try another country.
		return nil, refuseCountryBusy
	}

	// Apply the client's exclusions, but only while they leave a set it still cannot
	// choose within. Below the floor the exclusion is dropped whole and we assign from
	// the full candidate set, so narrowing to one is not something a client can do.
	if len(exclude) > 0 {
		kept := make([]*exitNode, 0, len(candidates))
		for _, e := range candidates {
			if !exclude[e.id] {
				kept = append(kept, e)
			}
		}
		if len(kept) >= minCandidatesAfterExclude {
			candidates = kept
		} else if len(kept) != len(candidates) {
			log.Printf("assign: ignoring an exclusion in %s — honouring it would leave %d assignable exit(s), below the floor of %d (ADR-0042 §7)",
				cc, len(kept), minCandidatesAfterExclude)
		}
	}

	// Pass 2: return the first candidate within one octave of the roomiest. Because
	// `candidates` was built in randomized order, "first within the tier" is an
	// arbitrary choice among the indistinguishable ones that varies per call — which
	// is the property, not an accident.
	floor := tierFloor(candidates, load)
	for _, e := range candidates {
		if rankShare(e, load[e.id]) >= floor {
			return e, refuseNone
		}
	}
	// Unreachable: the candidate at exactly `best` always clears the floor, and mu is
	// held throughout so nothing changed between the passes.
	return nil, refuseCountryBusy
}

// tierFloor is the minimum rank share a candidate must offer to be in the best tier —
// one octave below the roomiest of them (capacity.OctaveFloor).
//
// It is the whole of what the RANKING decides. Which member of the tier is then returned
// is deliberately arbitrary (see chooseExit), so this floor is the only part of
// assignment that has a definite answer, and it is therefore the only part a test can
// assert on without depending on a distribution the design does not promise.
//
// Named rather than inlined for exactly that reason: the property "the load term moved
// this exit into/out of contention" had no name, so a test could only observe it
// indirectly by sampling winners — which needs the arbitrary pick to be near-uniform,
// and it is not (see TestChooseExitDoesNotConcentrateOnOneNode). Extracting it changes
// no behaviour; chooseExit computes exactly what it computed before.
//
// The band is measured FROM the best candidate rather than from fixed power-of-two
// buckets, which is what stops a node sitting just beneath an absolute boundary and
// crossing it for a marginal gain (ADR-0042 §3).
func tierFloor(candidates []*exitNode, load map[string]int) capacity.Rate {
	var best capacity.Rate
	for _, e := range candidates {
		if s := rankShare(e, load[e.id]); s > best {
			best = s
		}
	}
	return capacity.OctaveFloor(best)
}

// rankShare is the per-exit ranking number: the bandwidth one more session could
// expect, with an unmeasured node's self-declared capacity clamped to the ceiling so
// it cannot out-declare a measured neighbour (capacity.RankShare).
func rankShare(e *exitNode, sessions int) capacity.Rate {
	usable, rated := exitRating(e.id, e.speedCap)
	return capacity.RankShare(usable, sessions, rated, capacityParams().Ceiling)
}
