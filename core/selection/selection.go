package selection

import (
	"sort"
	"strings"
	"time"
)

// Mode is how a candidate reaches its exit.
const (
	ModeDirect = "direct" // P2P hole-punch straight to the exit (the fast path)
	ModeRelay  = "relay"  // routed through a relay node (the "route through nodes" tier)
)

// Candidate is one connection path the client can try: a transport, a country, and
// a mode. It is comparable, so it doubles as a map key for de-duplication and
// health memory.
//
// The country replaced an exit id here (old #146, ADR-0042), and the substitution is
// not cosmetic: a candidate must name something the client can actually ASK FOR, and
// under country-only assignment the client cannot ask for an exit. The coordinator
// picks the exit, so which exit a candidate lands on is an OUTCOME of dialing it — it
// varies between attempts on the same candidate, and it is reported back by
// dialAndValidate rather than carried in here. Leaving an exit id in this struct would
// have made a candidate mean "the exit I want", which the wire can no longer express.
type Candidate struct {
	Transport string // built transport name, e.g. "webrtc" or "reality"
	Country   string // country to egress in (ISO-3166-1 alpha-2)
	Mode      string // ModeDirect or ModeRelay
}

// Country is one country the coordinator will assign exits in. RTT is the last
// measured client<->exit round-trip observed for that country; zero means unknown
// (never validated), which sorts after every known-RTT country but is still tried.
//
// Available/Busy come straight from the coordinator's aggregate (old #147) and are what
// let the ladder skip a country that cannot take a session at all, rather than
// spending a whole race discovering it by refusal.
type Country struct {
	Code      string
	Available int           // exits the coordinator would assign there right now
	Busy      bool          // Available == 0: known but nothing assignable
	RTT       time.Duration // last measured round-trip; 0 = unknown
}

// LadderInput is everything [Ladder] needs to order the candidate paths.
type LadderInput struct {
	// Geo restricts candidates to a single country the user picked ("" = no
	// restriction: every assignable country the coordinator offers is a candidate).
	Geo string
	// Countries are the countries currently offered by the coordinator.
	Countries []Country
	// Transports is the configured pool in preference order; Transports[0] is the
	// primary ("main") protocol tried first, and the rest are fallbacks.
	Transports []string
	// Learned, when non-nil, is the winning combination remembered for this
	// network+geo ([Store.Best]). It is tried first — the point of learning.
	Learned *Candidate
	// Cooling reports whether a candidate recently failed and should sink to the
	// back of its tier (health memory). Nil means nothing is cooling.
	Cooling func(Candidate) bool
}

// Ladder orders the candidate paths to try, highest priority first:
//
//  0. the learned winner for this network+geo, if any — try what worked last time
//  1. primary transport, in-scope countries by ping (fastest first), direct
//  2. alternate transports, in-scope countries by ping, direct
//  3. relay ("route through nodes"), primary transport — last resort
//
// Exhausting countries on the fast (direct) primary path before changing protocol,
// and changing protocol before routing through nodes, keeps the common path
// low-latency and low-noise; nodes are used only when nothing direct works.
// Within each tier cooling candidates sink to the back but are still tried. The
// result is de-duplicated keeping first occurrence — the learned pick and health
// sinking can otherwise repeat an entry — so the ladder never dials one path
// twice.
//
// A BUSY country is dropped entirely rather than sunk (old #147): the coordinator has
// already said it will refuse, so dialing it spends a whole candidate's stagger and
// timeout to be told what we were told at list time. That is the one place the
// aggregate the client is shown feeds selection directly.
func Ladder(in LadderInput) []Candidate {
	countries := sortByPing(inScope(in.Countries, in.Geo))
	var tiers [][]Candidate

	// Tier 0: what worked here last time — tried first, but only if that country is
	// still assignable and the learned path is not itself cooling. Skipping a
	// cooling learned winner is what lets failover move off a path that just
	// dropped instead of immediately retrying the candidate that failed; once its
	// cooldown lapses it returns to the front.
	if in.Learned != nil && countryPresent(countries, in.Learned.Country) && !isCooling(*in.Learned, in.Cooling) {
		tiers = append(tiers, []Candidate{*in.Learned})
	}
	if len(in.Transports) > 0 {
		primary := in.Transports[0]
		// Tiers 1+2: primary transport across every in-scope country, fastest first.
		tiers = append(tiers, countriesAs(primary, countries, ModeDirect))
		// Tier 3: alternate transports, same countries.
		var alt []Candidate
		for _, tr := range in.Transports[1:] {
			alt = append(alt, countriesAs(tr, countries, ModeDirect)...)
		}
		tiers = append(tiers, alt)
		// Tier 4: relay through nodes, primary transport — the last resort.
		tiers = append(tiers, countriesAs(primary, countries, ModeRelay))
	}

	var out []Candidate
	for _, tier := range tiers {
		out = append(out, sinkCooling(tier, in.Cooling)...)
	}
	return dedup(out)
}

// inScope keeps the countries a candidate may be built for: those that can take a
// session now, restricted to geo when the user picked one (case-insensitive). It
// copies, never aliasing the caller's slice.
//
// A user-chosen geo is honoured even when that country is BUSY. Silently substituting
// another country for the one the user asked for would egress them somewhere they did
// not choose — see core's pickCountry for the same rule stated at the other end. The
// candidate is built, the connect is refused, and the refusal reaches the user.
func inScope(countries []Country, geo string) []Country {
	out := make([]Country, 0, len(countries))
	for _, c := range countries {
		if geo != "" {
			if strings.EqualFold(c.Code, geo) {
				out = append(out, c)
			}
			continue
		}
		if !c.Busy {
			out = append(out, c)
		}
	}
	return out
}

// sortByPing orders countries fastest-first by RTT. Unknown RTT (zero) sorts after
// every measured country — we prefer a path known to be fast but still fall through
// to unprobed ones. Stable, so equal-RTT countries keep coordinator order (which is
// alphabetical, hence deterministic).
func sortByPing(countries []Country) []Country {
	out := append([]Country(nil), countries...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := out[i].RTT, out[j].RTT
		switch {
		case ri == 0:
			return false // i unknown: never before j
		case rj == 0:
			return true // j unknown, i known: i first
		default:
			return ri < rj
		}
	})
	return out
}

// countriesAs pairs every country with a transport and mode, preserving order.
func countriesAs(transport string, countries []Country, mode string) []Candidate {
	out := make([]Candidate, 0, len(countries))
	for _, c := range countries {
		out = append(out, Candidate{Transport: transport, Country: c.Code, Mode: mode})
	}
	return out
}

func countryPresent(countries []Country, code string) bool {
	for _, c := range countries {
		if strings.EqualFold(c.Code, code) {
			return true
		}
	}
	return false
}

// isCooling reports whether c is currently cooling, treating a nil predicate as
// "nothing is cooling".
func isCooling(c Candidate, cooling func(Candidate) bool) bool {
	return cooling != nil && cooling(c)
}

// sinkCooling stable-partitions a tier so cooling candidates move to the back
// while healthy ones keep their (ping) order.
func sinkCooling(tier []Candidate, cooling func(Candidate) bool) []Candidate {
	if cooling == nil {
		return tier
	}
	healthy := make([]Candidate, 0, len(tier))
	var cold []Candidate
	for _, c := range tier {
		if cooling(c) {
			cold = append(cold, c)
		} else {
			healthy = append(healthy, c)
		}
	}
	return append(healthy, cold...)
}

// dedup removes repeated candidates, keeping first occurrence (highest priority).
func dedup(in []Candidate) []Candidate {
	seen := make(map[Candidate]bool, len(in))
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
