package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/bacchus-vpn/bacchus/core/geoip"
)

// errNoGeoIPButRequired rejects a contradictory configuration at startup rather than
// letting it run: with no database staged, -geoip-required would strip the country
// from every node in the fleet and leave nothing assignable.
var errNoGeoIPButRequired = errors.New("coordinator: -geoip-required needs -geoip; with no database staged no node would ever get a country and nothing would be assignable")

// minPlausibleBlocks is the fewest prefixes a staged database may hold before this
// coordinator refuses to start with it.
//
// It is not a tuning knob. A GeoLite2 Country release carries hundreds of thousands of
// prefixes per family, so this sits three orders of magnitude below any legitimate
// staging and exists solely to catch the copy that died in its first moments. It is
// deliberately NOT set near the real row count: MaxMind's counts move with every
// publication, and a floor that tracked them would take the coordinator down over an
// ordinary release.
//
// It lives here rather than in core/geoip because only this binary knows what it is
// pointed at — the package is a CSV loader that must stay usable with small fixtures.
const minPlausibleBlocks = 1000

// Coordinator-derived node country (issue #136, ADR-0042).
//
// A node's country used to be whatever its -country flag said. That is a NODE
// SELF-REPORT, and this project's standing rule is that an OBSERVED address is
// trusted while a claimed one is not — the rule coldstart.Entry.Ingress follows for a
// relay's forwarding address (#124) and observedAS follows for a capacity attester's
// network (#158). Country is now derived the same way: from the source address the
// coordinator observed the node register from, resolved against a local database.
//
// Two problems close at once. A hostile or Sybil node can no longer place itself in a
// country it is not in, which matters because country is the ONLY thing a user selects
// on (#146) — a node that can claim a country can draw traffic that believes it is
// exiting somewhere else. And the ordinary operator error goes away too: a typo'd or
// forgotten tag silently corrupted the client's filter, which is how the multi-exit
// bring-up lost an exit to a wrong tag.

var (
	// geoDB is the loaded country database, or nil when none was staged. Every read
	// path is nil-safe (geoip.DB methods tolerate a nil receiver), so an unconfigured
	// coordinator behaves exactly as it did before #136: the node's hint is the only
	// source of a country tag.
	//
	// Written once in setupGeoIP before the packet loop starts and never mutated
	// after, so the loop reads it without a lock — the same discipline as `operators`
	// (issue #124).
	geoDB *geoip.DB

	// requireGeoIP drops the self-reported fallback entirely: a node whose observed
	// address does not resolve gets NO country and is therefore invisible to
	// country-scoped assignment, rather than being placed by its own claim.
	//
	// Off by default because it would blank the country of every node on the local
	// smoke stack (all registering from loopback, which no database resolves) and of
	// any node on a range the database misses. On, it is the hardened posture: no
	// node self-report reaches a client's country choice under any circumstance.
	requireGeoIP bool
)

// Country provenance, recorded per node so the operator log and the diagnostics can
// distinguish "we resolved this" from "the node told us" — and, for an exit, from "we
// resolved it, but only for the address its SIGNALING came from".
const (
	countryObserved = "observed" // derived from the observed source IP, and the node's advertised data-plane endpoint agrees with it
	countryHinted   = "hint"     // fell back to the node's self-reported -country
	countryUnknown  = ""         // neither resolved nor hinted: no country tag
	// countrySplit is an exit whose observed SIGNALING address resolved, but whose
	// advertised data-plane endpoint is a different address (or a name this
	// coordinator will not resolve). The country describes where the exit signals
	// from, which is not necessarily where its traffic egresses — see exitEndpointAgrees.
	countrySplit = "observed-signaling-only"
)

// setupGeoIP loads the country database from dir, or leaves the coordinator running
// without one when dir is empty.
//
// A configured-but-unloadable database is FATAL, deliberately: an operator who passed
// -geoip asked for derived countries, and silently falling back to node self-reports
// would leave the trust property they asked for quietly absent — the failure mode
// #136 exists to remove. A MISSING configuration is fine and merely logged, because
// that is the local-development and pre-staging case.
func setupGeoIP(dir string, require bool) error {
	requireGeoIP = require
	if dir == "" {
		if require {
			return errNoGeoIPButRequired
		}
		log.Printf("geoip: DISABLED (-geoip not set) — node country falls back to each node's self-reported -country tag (issue #136)")
		return nil
	}
	db, err := geoip.LoadDir(dir)
	if err != nil {
		return err
	}
	geoDB = db
	v4, v6 := db.Len()
	log.Printf("geoip: loaded %d IPv4 + %d IPv6 prefixes from %s (%d unusable rows skipped) (issue #136)", v4, v6, dir, db.Skipped)
	if v4+v6 < minPlausibleBlocks {
		// The loader is scale-free by design and cannot know what size to expect (see
		// geoip.plausible). This binary can: -geoip points at a GeoLite2 Country
		// release, which carries hundreds of thousands of prefixes per family. An order
		// of magnitude under that is a half-copied staging directory, and it fails
		// silently in the worst way — every node in the missing ranges falls back to
		// its own self-reported country, which is what #136 exists to stop.
		//
		// Fatal rather than a warning, for the same reason an unloadable database is:
		// an operator who passed -geoip asked for derived countries, and running with a
		// table too small to derive them leaves the property they asked for quietly
		// absent.
		return fmt.Errorf("coordinator: the geoip database at %s holds only %d prefixes, far below the ~10^5 a GeoLite2 Country release carries — the staging directory looks truncated or incomplete; restage it (issue #136)", dir, v4+v6)
	}
	if db.Stale {
		// Not fatal: a stale table still resolves most of the address space, and
		// taking a coordinator down over data hygiene is worse than a warning. But
		// it must be said, because stale geodata mislabels countries without
		// failing anywhere.
		log.Printf("WARNING: geoip database at %s was built %s and is older than %s — reassigned address space may resolve to the wrong country; restage it",
			dir, geoDB.BuiltAt.Format("2006-01-02"), geoip.StaleAfter)
	}
	if require {
		log.Printf("geoip: -geoip-required set — a node whose observed address does not resolve gets NO country and is excluded from country assignment (its -country claim is ignored)")
	}
	return nil
}

// deriveCountry resolves the country tag for a node registering from src, and reports
// where the tag came from.
//
// Precedence is the whole point and is not configurable: an observed resolution ALWAYS
// wins over the node's claim. The claim is consulted only when the observed address
// resolves to nothing — an unmapped or newly-allocated range, or the loopback address
// every node registers from in a local stack — and not at all under -geoip-required.
//
// Both paths pass through geoip.Canonical, so a malformed tag from either source
// becomes "unknown" rather than a country string no client filter will ever match.
// That is what makes the typo class impossible rather than merely unlikely.
func deriveCountry(src *net.UDPAddr, hint string) (cc string, source string) {
	if src != nil {
		if cc, ok := geoDB.LookupAddr(src.IP); ok {
			// Canonical is belt-and-braces here: the loader already canonicalized
			// every code in the table.
			if cc = geoip.Canonical(cc); cc != "" {
				return cc, countryObserved
			}
		}
	}
	if requireGeoIP {
		return countryUnknown, countryUnknown
	}
	if cc = geoip.Canonical(hint); cc != "" {
		return cc, countryHinted
	}
	return countryUnknown, countryUnknown
}

// deriveExitCountry is deriveCountry for an EXIT, which unlike a relay advertises a
// data-plane endpoint of its own and so can have the two disagree.
//
// # The gap this closes, and the one it only labels
//
// deriveCountry resolves the source of the register datagram — the SIGNALING address.
// An exit also advertises `advertised` (its -advertise host:port), which is the
// endpoint a relay dials to reach it, and nothing previously compared the two. An
// operator running an exit in country Y and forwarding only its coordinator signaling
// through a cheap host in country X (socat, DNAT, a tunnelled control channel) had
// country=X derived and advertised to clients while traffic egressed in Y. For a
// project whose entire user-facing choice is jurisdiction, that is the misrouting the
// feature exists to prevent, and -geoip-required did not help: the address resolved
// fine, just to the wrong machine.
//
// When the advertised host is an IP that EQUALS the observed source, signaling and
// data plane are the same machine as far as this coordinator can tell, and the derived
// country is countryObserved as before. When they disagree — or when the advertised
// host is a name — the split is recorded as countrySplit and, under -geoip-required,
// the country is dropped entirely so the exit is not offered at all.
//
// What this does NOT do is verify that traffic egresses where the advertised endpoint
// sits. The advertised address is still a claim; it is merely a claim that must now
// agree with an observation instead of being unconstrained. A determined operator can
// still place the whole apparatus behind one address and egress elsewhere, because in
// direct mode the data path is decided by ICE candidates the exit puts in its own SDP
// and this coordinator never sees the egress. That residual is stated in ADR-0042 §8
// rather than papered over.
//
// Names are deliberately not resolved. A DNS lookup here would be a blocking call on
// the packet handler for a name the node itself chose — an attacker-controlled stall,
// and a resolution this coordinator could not trust anyway.
func deriveExitCountry(src *net.UDPAddr, hint, advertised string) (cc string, source string) {
	cc, source = deriveCountry(src, hint)
	if source != countryObserved || exitEndpointAgrees(advertised, src) {
		return cc, source
	}
	if requireGeoIP {
		// The strict posture means no node self-assertion of location reaches a
		// client, and an endpoint this coordinator never observed is exactly that.
		return countryUnknown, countryUnknown
	}
	return cc, countrySplit
}

// exitEndpointAgrees reports whether an exit's advertised data-plane endpoint names
// the same address this coordinator observed its signaling arrive from.
//
// An empty advertisement agrees vacuously: there is no claim to contradict the
// observation. A host that is not an IP literal does not agree, because it cannot be
// checked (see deriveExitCountry on why it is not resolved).
func exitEndpointAgrees(advertised string, src *net.UDPAddr) bool {
	if advertised == "" || src == nil {
		return true
	}
	host := advertised
	if h, _, err := net.SplitHostPort(advertised); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false // a name: not checkable, so not agreed
	}
	return ip.Equal(src.IP)
}

// rederiveCountry refreshes a node's country after its observed address changed,
// without a fresh self-reported hint to consult (a heartbeat carries none).
//
// The stored tag is re-offered as the hint ONLY if it was hinted in the first place.
// That asymmetry is the point: a previously OBSERVED tag must never be recycled as a
// hint, because doing so would let a node that moves to an unresolvable address keep
// the country it used to be resolved to — laundering a stale observation into a
// standing claim. A previously hinted tag, by contrast, is still exactly what the node
// told us, so continuing to fall back to it changes nothing.
func rederiveCountry(src *net.UDPAddr, storedCC, storedSource string) (cc string, source string) {
	return deriveCountry(src, rederiveHint(storedCC, storedSource))
}

// rederiveExitCountry is rederiveCountry for an exit, re-running the data-plane
// endpoint agreement check (deriveExitCountry) against its STORED advertisement — the
// address it gave at register, since a heartbeat carries none. An exit whose signaling
// address moves under it must not silently keep an agreement that was established
// against the old one.
func rederiveExitCountry(src *net.UDPAddr, advertised, storedCC, storedSource string) (cc string, source string) {
	return deriveExitCountry(src, rederiveHint(storedCC, storedSource), advertised)
}

// rederiveHint decides whether a stored country tag may be re-offered as the
// self-reported hint on a re-derivation.
//
// Only a previously HINTED tag may be, and the asymmetry is the point: recycling a
// previously OBSERVED tag would let a node that moves to an unresolvable address keep
// the country it used to resolve to, laundering a stale observation into a standing
// claim. A previously hinted tag is still exactly what the node told us, so continuing
// to fall back to it changes nothing. countrySplit is observed-derived and so is NOT
// recyclable either — it is a resolution this coordinator made, not one the node
// asserted.
func rederiveHint(storedCC, storedSource string) string {
	if storedSource == countryHinted {
		return storedCC
	}
	return ""
}

// countryOrUnknown renders a country tag for the operator log, naming the empty case
// rather than printing a blank.
func countryOrUnknown(cc string) string {
	if cc == countryUnknown {
		return "unknown"
	}
	return cc
}

// countrySourceLabel renders where a country tag came from, for the operator log. The
// provenance is worth a word on every registration line: "hint" on a node an operator
// expected to be resolved is the visible symptom of a missing or stale database.
func countrySourceLabel(source string) string {
	switch source {
	case countryObserved:
		return "observed IP"
	case countrySplit:
		return "observed SIGNALING IP only — advertised endpoint differs"
	case countryHinted:
		return "node hint, unresolved IP"
	default:
		return "unresolved"
	}
}
