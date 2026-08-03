package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/geoip"
)

// errNoGeoIPButRequired rejects a contradictory configuration at startup rather than
// letting it run: with no database staged, -geoip-required would strip the country
// from every node in the fleet and leave nothing assignable.
var errNoGeoIPButRequired = errors.New("coordinator: -geoip-required needs -geoip; with no database staged no node would ever get a country and nothing would be assignable")

// minPlausibleBlocks is the fewest rows a staged database may hold before this
// coordinator refuses to start with it.
//
// It is not a tuning knob. Either supported release — iptoasn's IP-to-Country files or a
// GeoLite2 Country CSV — carries hundreds of thousands of rows per family, so this sits
// three orders of magnitude below any legitimate staging and exists solely to catch the
// copy that died in its first moments. It is deliberately NOT set near the real row
// count: both publishers' counts move with every release, and a floor that tracked them
// would take the coordinator down over an ordinary refresh.
//
// It lives here rather than in core/geoip because only this binary knows what it is
// pointed at — the package is a loader that must stay usable with small fixtures.
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
	// from, which is not necessarily where its traffic egresses — see exitEndpoint.
	countrySplit = "observed-signaling-only"
	// countryNoEndpoint is an exit that resolved fine but advertises NO data-plane
	// endpoint at all, under -geoip-required (issue #2). It carries no country, for the
	// reason derivedExitCountry gives; the provenance is recorded separately from
	// countryUnknown because the two are diagnosed completely differently by an
	// operator. countryUnknown means "we could not resolve your address"; this means
	// "we resolved it, and you have not given us the second address that would let us
	// tie it to your egress" — and the fix is a flag, not a database.
	countryNoEndpoint = "unverifiable-no-endpoint"
	// countryOverride is a country an ADMIN of this coordinator asserted by hand in
	// -country-overrides, replacing whatever this coordinator derived (issue #113). It
	// is neither of the other two kinds of thing: not a resolution this coordinator
	// made, and not a claim the node made. See applyCountryOverride.
	countryOverride = "admin-override"
)

// countryClaims is everything this coordinator knows about one node's country.
//
// It exists because "country" was one name over two different claims (issue #113), and
// deriveCountry used to compute both and return one — so from the moment a node
// registered, nothing anywhere could tell there had ever been a second answer. Keeping
// them in one value means every path that carries a country carries both, and the
// disagreement becomes a fact a surface can list instead of a line in a log that has
// already scrolled.
type countryClaims struct {
	// derived is the country this coordinator PUBLISHES for the node: resolved from the
	// address it observed, or — where an admin has corrected that resolution — the
	// correction. Never the node's own declaration. Empty means no country could be
	// established, which for an exit means it is unreachable (issue #146).
	derived string
	// source is where derived came from: one of the country* provenance values above.
	source string
	// declared is the node's own -country tag, canonicalized. A bare self-report: it
	// answers "which building is the machine in", which only the operator knows and
	// nobody can check, where derived answers "what will destination sites conclude",
	// which is a property of the address. It is stored and published beside derived,
	// never instead of it, and it is NEVER promoted into derived — see
	// applyCountryOverride for the one place that distinction is load-bearing.
	declared string
	// displaced is the provenance the DERIVATION produced, in the case where an admin
	// override then replaced it — so the operator log can say what the correction
	// overrode. Meaningful only when source is countryOverride, and empty there means
	// the derivation established nothing at all. Not stored on the registry entry: it
	// describes one act of overriding, and every heartbeat re-derives.
	displaced string
}

// countryOverridesReload is how often -country-overrides is re-read, matching the
// bootstrap-secrets and revocation-list cadence.
//
// It composes with the ~10s heartbeat: a node's country is re-derived on every
// heartbeat (see rederiveCountry), so a correction an admin writes to the file takes
// effect within roughly one reload plus one heartbeat, with no restart and no touch to
// the node.
const countryOverridesReload = 30 * time.Second

// countryOverrides maps a node id to the country an ADMIN of this coordinator asserted
// for it, replacing what the derivation produced (issue #113, ADR-0042 §8 update
// 2026-08-03).
//
// Coordinator-side truth, NOT a node self-report — the same standing as `operators`
// (issue #124) and deliberately unlike wire.Country, which is the node talking. What
// separates them is who is speaking, not how sure anyone is: an admin can be wrong, but
// an admin who is wrong is an operational fault with an operator to fix it, where a node
// that is wrong is the adversary ADR-0042 was written about.
//
// Swapped atomically rather than written in place, and stored as a pointer to a map so
// the whole set changes at once: a reader must never see half of one edit. Read on every
// register and every heartbeat, from the packet goroutine, while the reload loop writes.
var countryOverrides atomic.Pointer[map[string]string]

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
	// The source is named because -geoip accepts two formats and the row counts alone do
	// not say which one was read, so without it this line cannot confirm that the file an
	// operator staged is the file that loaded (geoip.LoadDir prefers the range format when
	// a directory holds both).
	log.Printf("geoip: loaded %d IPv4 + %d IPv6 rows from %s [%s] (%d unusable rows skipped) (issue #136)", v4, v6, dir, db.Source, db.Skipped)
	if v4+v6 < minPlausibleBlocks {
		// The loader is scale-free by design and cannot know what size to expect (see
		// geoip.plausible). This binary can: -geoip points at a published country
		// release, and both accepted formats carry hundreds of thousands of rows per
		// family. An order of magnitude under that is a half-copied staging directory,
		// and it fails silently in the worst way — every node in the missing ranges falls
		// back to its own self-reported country, which is what #136 exists to stop.
		//
		// Fatal rather than a warning, for the same reason an unloadable database is:
		// an operator who passed -geoip asked for derived countries, and running with a
		// table too small to derive them leaves the property they asked for quietly
		// absent.
		return fmt.Errorf("coordinator: the geoip database at %s holds only %d rows, far below the ~10^5 a published country release carries — the staging directory looks truncated or incomplete; restage it (issue #136)", dir, v4+v6)
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

// deriveCountry resolves the country claims for the node with id registering from src:
// the tag this coordinator publishes, where that tag came from, and — separately — what
// the node itself declared.
//
// Precedence is the whole point and is not configurable: an observed resolution ALWAYS
// wins over the node's claim. The claim is consulted only when the observed address
// resolves to nothing — an unmapped or newly-allocated range, or the loopback address
// every node registers from in a local stack — and not at all under -geoip-required.
//
// Both paths pass through geoip.Canonical, so a malformed tag from either source
// becomes "unknown" rather than a country string no client filter will ever match.
// That is what makes the typo class impossible rather than merely unlikely.
//
// What changed with issue #113 is only that the claim is now KEPT when it loses. It is
// canonicalized unconditionally, including on the observed path (which used to return
// before ever looking at it) and under -geoip-required (which used to skip it entirely)
// — carrying it is not using it, and every rule above about what may become the
// published country is unchanged.
func deriveCountry(id string, src *net.UDPAddr, hint string) countryClaims {
	return applyCountryOverride(id, derivedCountry(src, hint))
}

// deriveExitCountry is deriveCountry for an EXIT, plus the admin override on top. The
// derivation itself is derivedExitCountry; see applyCountryOverride for why the
// correction is applied after it rather than before.
func deriveExitCountry(id string, src *net.UDPAddr, hint, advertised string) countryClaims {
	return applyCountryOverride(id, derivedExitCountry(src, hint, advertised))
}

// derivedCountry is deriveCountry's derivation proper, without the admin override on
// top. Split out so the override has exactly one application point and so a test can
// state what the coordinator would have concluded on its own.
func derivedCountry(src *net.UDPAddr, hint string) countryClaims {
	// The declaration is recorded first and unconditionally, so that every return below
	// carries it. It is the value #113 found being computed and thrown away.
	c := countryClaims{declared: geoip.Canonical(hint)}
	if src != nil {
		if cc, ok := geoDB.LookupAddr(src.IP); ok {
			// Canonical is belt-and-braces here: the loader already canonicalized
			// every code in the table.
			if cc = geoip.Canonical(cc); cc != "" {
				c.derived, c.source = cc, countryObserved
				return c
			}
		}
	}
	if requireGeoIP {
		// The strict posture: the declaration is recorded but must not be reached for.
		// With both values carried, "refuse" and "fall back" became two distinct
		// options and this flag is the one that refuses.
		return c
	}
	if c.declared != "" {
		c.derived, c.source = c.declared, countryHinted
	}
	return c
}

// applyCountryOverride replaces a node's DERIVED country with an admin's correction
// from -country-overrides, if one is staged for that node id (issue #113).
//
// # It wins, and it wins under -geoip-required too
//
// That flag's promise is that no NODE SELF-REPORT reaches a client's country choice.
// An admin correction is not a node self-report — it is this coordinator's own operator
// speaking, the same standing `operators` has — so honouring it leaves the promise
// exactly as strong as it was. Saying so out loud matters more than usual here: a flag
// whose guarantee quietly narrows one exception at a time ends up guaranteeing nothing,
// which is what happened to it once already (ADR-0042 §8, issue #2).
//
// # It is a correction to the DERIVED value, never a promotion of the DECLARED one
//
// This is the whole of the distinction and it is invisible at the moment of editing,
// because both look like "fix the country":
//
//   - Legitimate: "your GeoIP table is wrong — this address really does present as DE."
//     An assertion about the ADDRESS. The admin has evidence this coordinator does not,
//     and can check it against what real sites conclude.
//   - Illegitimate: "the machine is physically in DE even though its address resolves
//     US." That is [countryClaims.declared], and promoting it delivers the misrouting
//     ADR-0042 §8 exists to prevent — from the operator's side instead of the node's. A
//     user picks DE to be TREATED AS German by every site; an address that resolves US
//     is treated as US regardless of which building it sits in.
//
// Nothing here can tell the two apart — both arrive as a country code beside a node id
// — so the distinction is enforced by being legible where the admin meets it: the flag
// text and the file's documented format, not only in an ADR.
//
// # It is terminal, and it is applied LAST
//
// The derivation runs to completion first — including, for an exit, the
// signaling-vs-advertised-endpoint comparison — and the override then replaces its
// verdict wholesale. Running it first would be simpler and would lose the one thing
// worth keeping: with the derivation complete, this coordinator KNOWS what it would have
// concluded, so displaced can name it and noteCountryOverride can warn when a correction
// has switched off the countrySplit label a chaining client fails closed on. Applied
// first, an override would suppress that verdict before it was ever computed and nothing
// could report what had been suppressed.
//
// Terminal is the point, though: the endpoint comparison is not re-run against the
// override and cannot demote it back to "contradicted". An override that could be
// demoted would not be an override. That cost is real, is paid deliberately, and is why
// the warning exists.
func applyCountryOverride(id string, c countryClaims) countryClaims {
	cc := countryOverrideFor(id)
	if cc == "" {
		return c
	}
	c.displaced = c.source
	c.derived, c.source = cc, countryOverride
	return c
}

// countryOverrideFor returns the admin's asserted country for a node id, or "" when
// none is staged. Every value in the map is already canonical (loadCountryOverrides
// refuses a file containing anything else), so callers need not re-check.
func countryOverrideFor(id string) string {
	m := countryOverrides.Load()
	if m == nil {
		return ""
	}
	return (*m)[id]
}

// derivedExitCountry is derivedCountry for an EXIT, which unlike a relay advertises a
// data-plane endpoint of its own and so can have the two disagree. It is the derivation
// only; deriveExitCountry above is this plus the admin override.
//
// # The gap this closes, and the one it only labels
//
// derivedCountry resolves the source of the register datagram — the SIGNALING address.
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
// # The empty advertisement, and why it is not agreement (issue #2)
//
// The first version of this treated an exit that advertises NOTHING as agreeing
// vacuously: no claim, nothing to contradict, tag it observed. That reads as
// conservative and is the opposite, because `-advertise` defaults to empty and a
// DIRECT-mode exit never needs it — relays dial an advertised address, ICE does not.
// So the split-endpoint operator this check exists to catch defeated it by OMITTING a
// flag they had no reason to set: run the exit in RU, forward only its UDP signaling
// through a cheap host abroad, and be tagged with the foreign country, source=observed,
// no warning, fully assignable — under the very flag whose promise is that no node
// self-report reaches a client's country choice.
//
// Under -geoip-required an empty advertisement is therefore treated as UNVERIFIABLE
// rather than as agreed, and such an exit gets no country. The distinction that makes
// this coherent is between a claim that is CONTRADICTED and an observation that cannot
// be CORROBORATED: the flag's promise is about what this coordinator can establish, and
// with one address and nothing to check it against it has established where the exit
// signals from and nothing about where its traffic leaves.
//
// Without the flag, an empty advertisement still keeps its observed tag. That is
// deliberate and it is the reason this was chosen over making `-advertise` mandatory
// for the exit role: an operator who has not asked for the guarantee should not have
// their working direct-mode exit refused at register for omitting a flag it does not
// need. The flag is what buys the property, and now it buys the whole of it.
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
func derivedExitCountry(src *net.UDPAddr, hint, advertised string) countryClaims {
	c := derivedCountry(src, hint)
	if c.source != countryObserved {
		// Hinted or unresolved: there is no observation for an endpoint to corroborate
		// or contradict, so the advertisement has nothing to say either way.
		return c
	}
	switch exitEndpoint(advertised, src) {
	case endpointAgrees:
		return c
	case endpointAbsent:
		if requireGeoIP {
			c.derived, c.source = countryUnknown, countryNoEndpoint
		}
		return c
	default: // endpointDisagrees
		if requireGeoIP {
			// The strict posture means no node self-assertion of location reaches a
			// client, and an endpoint this coordinator never observed is exactly that.
			// The provenance is kept even though the country is dropped, so the
			// operator log can say WHICH of the two refusals this was.
			c.derived = countryUnknown
		}
		c.source = countrySplit
		return c
	}
}

// endpointVerdict is what an exit's advertised data-plane endpoint says about the
// country derived from its signaling source.
//
// Three values rather than a bool, and that is the whole of issue #2's fix. The
// predicate this replaces answered "does the advertisement agree?" and had to say
// something about an exit that advertises nothing; it said yes — vacuously true, and
// the default configuration. Collapsing "made no claim" into "made a claim that
// checks out" is what let the check be bypassed by omission. Kept apart, each caller
// has to decide what an absent claim means to it, which is a decision rather than a
// fallthrough.
type endpointVerdict int

const (
	// endpointAgrees: the advertised host is an IP literal equal to the observed
	// signaling source. Signaling and data plane are the same machine as far as this
	// coordinator can tell.
	endpointAgrees endpointVerdict = iota
	// endpointDisagrees: the advertised host is a different address, or a name — which
	// is not checkable without a DNS lookup this coordinator will not perform (see
	// derivedExitCountry). Unverifiable and verified-false are the same answer here: in
	// both cases the observation has not been corroborated.
	endpointDisagrees
	// endpointAbsent: no data-plane endpoint was advertised at all.
	endpointAbsent
)

// exitEndpoint classifies an exit's advertised data-plane endpoint against the address
// this coordinator observed its signaling arrive from.
func exitEndpoint(advertised string, src *net.UDPAddr) endpointVerdict {
	if advertised == "" {
		return endpointAbsent
	}
	if src == nil {
		// No observation to compare against. Reached only from a synthetic call site;
		// the register path always has a source address.
		return endpointAbsent
	}
	host := advertised
	if h, _, err := net.SplitHostPort(advertised); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return endpointDisagrees // a name: not checkable, so not corroborated
	}
	if ip.Equal(src.IP) {
		return endpointAgrees
	}
	return endpointDisagrees
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
func rederiveCountry(id string, src *net.UDPAddr, stored countryClaims) countryClaims {
	c := deriveCountry(id, src, rederiveHint(stored))
	// The DECLARATION survives untouched. A heartbeat carries no -country tag, so
	// re-deriving it from the recycled hint would blank it on the first heartbeat for
	// every node whose address resolved — which is to say, for exactly the nodes whose
	// two claims disagree and whose declaration #113 exists to keep (issue #113).
	c.declared = stored.declared
	return c
}

// rederiveExitCountry is rederiveCountry for an exit, re-running the data-plane
// endpoint agreement check (derivedExitCountry) against its STORED advertisement — the
// address it gave at register, since a heartbeat carries none. An exit whose signaling
// address moves under it must not silently keep an agreement that was established
// against the old one.
func rederiveExitCountry(id string, src *net.UDPAddr, advertised string, stored countryClaims) countryClaims {
	c := deriveExitCountry(id, src, rederiveHint(stored), advertised)
	c.declared = stored.declared // see rederiveCountry
	return c
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
// asserted. countryOverride is not recyclable for the same reason one step further out:
// it is an ADMIN's assertion, and recycling it would let a withdrawn correction persist
// as though the node had claimed it (issue #113).
//
// Note what this deliberately does NOT do, now that the declaration is stored beside the
// derived tag: it does not re-offer stored.declared. It could — the declaration is
// exactly what the node told us, so re-offering it launders nothing — but that would
// give a node which moved to an unresolvable address a country it does not have today,
// changing what the -country fallback covers rather than what is carried. #113 lists
// that as one of the things not to settle by accident, so this rule is byte-for-byte the
// pre-#113 one and the gap closes on the node's next register either way.
func rederiveHint(stored countryClaims) string {
	if stored.source == countryHinted {
		return stored.derived
	}
	return ""
}

// noteCountryOverride logs a CHANGE in whether an admin correction is deciding a node's
// country — it coming into force, its value changing, or it being withdrawn (issue
// #113). prior is nil for a node not currently in the registry.
//
// Called from both the register and the heartbeat path, because either can be the one
// that first re-derives after an edit and whichever runs second must find nothing left
// to report. It says nothing on the steady state, so a node under a stable override is
// silent across the ten-second re-registration it does forever.
//
// The escalation to WARNING is the honest half. An override is terminal — it replaces
// the derivation before the data-plane endpoint comparison is reached — so overriding an
// exit whose signaling and advertised endpoint DISAGREE also erases the countrySplit
// label a chaining client fails closed on (ADR-0042 §8, issue #3). That is a real
// property being switched off by hand, and the one place an admin can be told is the
// moment they switch it off.
func noteCountryOverride(role, id string, prior *countryClaims, now countryClaims) {
	priorSource, priorDerived := "", ""
	if prior != nil {
		priorSource, priorDerived = prior.source, prior.derived
	}
	switch {
	case now.source == countryOverride && priorSource == countryOverride && priorDerived == now.derived:
		return // steady state: nothing changed
	case now.source == countryOverride:
		switch now.displaced {
		case countrySplit, countryNoEndpoint:
			log.Printf("WARNING: %s %s: an admin override sets country=%s, replacing what this coordinator derived (%s). That comparison is NOT re-run against the override, so this node no longer reports the endpoint disagreement a chaining client refuses on — remove the override to get it back (issue #113, ADR-0042 §8)",
				role, id, now.derived, countrySourceLabel(now.displaced))
		default:
			log.Printf("%s %s: an admin override sets country=%s, replacing what this coordinator derived (%s; previously published %s). It is a correction to the DERIVATION — the node's own claim of %s is carried separately and is NOT what this promotes (issue #113)",
				role, id, now.derived, countrySourceLabel(now.displaced), countryOrUnknown(priorDerived), countryOrUnknown(now.declared))
		}
	case priorSource == countryOverride:
		log.Printf("%s %s: the admin override is withdrawn; country=%s is this coordinator's own derivation again (%s) (issue #113)",
			role, id, countryOrUnknown(now.derived), countrySourceLabel(now.source))
	}
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
	case countryNoEndpoint:
		return "observed SIGNALING IP only — no advertised endpoint to corroborate it, and -geoip-required is set"
	case countryHinted:
		return "node hint, unresolved IP"
	case countryOverride:
		return "ADMIN OVERRIDE, not derived"
	default:
		return "unresolved"
	}
}

// publishedDeclaration returns the node's declared country for the SIGNED DIRECTORY, or
// "" under -geoip-required (owner ruling, 2026-08-03).
//
// The declaration is derived, stored, logged and overridable exactly as before under
// either setting. This gates one thing: whether it is handed to a client inside the
// signed artifact.
//
// ADR-0042 §9 made that artifact THE exit-discovery path for relay chaining — a chaining
// client picks its terminating jurisdiction out of it with no live reply to check it
// against. -geoip-required's promise is that no node self-report reaches a client's
// country choice, and putting a labelled self-claim into the one artifact a client
// chooses a jurisdiction from is not that promise kept, whatever the label says. The
// argument that nothing reads the field today is a fact about today, in a file designed
// to be durable; the next implementer sees a country inside a signed document. The
// cheapest way to keep a promise is not to hand out the thing you promised not to hand
// out.
//
// It is scoped to the FLAG and not to the per-node outcome — an overridden node under
// the flag publishes no declaration either, even though its country was established.
// A rule that depended on how each node's derivation happened to land would be a rule
// the next reader has to reconstruct before they can trust it.
func publishedDeclaration(declared string) string {
	if requireGeoIP {
		return ""
	}
	return declared
}

// countryClaimLabel renders the whole of what this coordinator knows about a node's
// country for one registration line: where the published tag came from, and — only when
// they disagree — what the node itself declared.
//
// This is the one operator-facing surface that exists today, so it is where issue #113's
// second answer becomes visible at all. It is stated as a plain fact and NOT as a
// warning, deliberately: the disagreement is the ordinary case on cloud address space
// (two exits in three, on the fleet that found this), and a warning an operator learns
// to ignore is worse than no warning. The register handler still warns loudly, and
// separately, about the cases that really are faults.
//
// It says nothing when the two agree, and nothing when the node declared nothing. An
// operator reading a bare "(observed IP)" is reading "no disagreement to report".
func countryClaimLabel(c countryClaims) string {
	if c.declared == "" || c.declared == c.derived {
		return countrySourceLabel(c.source)
	}
	return fmt.Sprintf("%s; node declares %s", countrySourceLabel(c.source), c.declared)
}

// loadCountryOverrides reads the admin's per-node country corrections from path: a JSON
// object {"<node id>": "<ISO-3166-1 alpha-2 code>"}, the same operator-managed-file
// shape as -operators, the bootstrap secrets and the two revocation lists (issue #113).
//
// A path that does not exist yields an empty map and no error, matching the "a missing
// file means nothing is configured" convention every other file here follows. An empty
// path disables the feature outright.
//
// A present file with ANY unusable row is refused WHOLE, and that is the decision worth
// naming. The alternative — skip the bad row, apply the rest — produces a correction
// that looks applied and is not, which is the failure mode #113 was found through: a
// documentation placeholder pasted into COUNTRY= and accepted verbatim, silently
// mislabelling an exit for as long as nobody looked. Refusing the file costs the admin a
// second edit; accepting most of it costs a user the jurisdiction they chose. At startup
// the refusal is fatal (see setupCountryOverrides); on a reload the corrections already
// in effect are kept and the refusal is logged, so a bad edit never silently drops the
// good ones that preceded it.
func loadCountryOverrides(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read country overrides file %s: %w", path, err)
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse country overrides file %s: %w (want a JSON object {\"<node id>\": \"<two-letter country code>\"})", path, err)
	}
	out := make(map[string]string, len(raw))
	for id, cc := range raw {
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("country overrides file %s: an entry has an empty node id — an override keyed to nothing corrects nothing", path)
		}
		canon := geoip.Canonical(cc)
		if canon == "" {
			return nil, fmt.Errorf("country overrides file %s: node %q is assigned %q, which is not a two-letter ISO-3166-1 alpha-2 country code; the whole file is refused rather than applying the rest, because a correction that is silently dropped looks applied and is not (issue #113)", path, id, cc)
		}
		out[id] = canon
	}
	return out, nil
}

// setupCountryOverrides loads the admin's country corrections and starts the reload
// loop, so an admin can correct a country without restarting the coordinator.
//
// # Hot-reloaded rather than load-once, which is a choice against the nearest precedent
//
// -operators, the file this one is shaped after, is read once at startup and never
// again. That is right for what it holds: an operator/vouch-subtree assignment changes
// when the fleet's ownership changes, which is a planned event around which a restart is
// nothing. This file is the opposite kind of thing. ADR-0042's ruling B has an admin
// EDIT IT WHEN PROMPTED — the coordinator surfaces a country it could not agree on, and
// somebody answers — so a correction that needs a coordinator restart to take effect is
// a correction that will be deferred, batched, and eventually not made. The whole value
// of the override is that it closes the loop while the operator is still looking at it.
//
// The two revocation files are the precedent for this half (main.go's
// -admission-revocations and -device-revocations), and they are the closer analogy for a
// second reason: like a revocation, this is an admin statement that some piece of what
// the network currently believes is wrong, and the interval between believing it and
// stopping is the whole point.
//
// The cost of hot reload is that a bad write can change what the coordinator publishes
// with nobody at a terminal, which is why loadCountryOverrides refuses a file whole and
// this loop keeps the last good set. Note also that unlike a trust anchor (see
// setupAdmission's argument for keeping anchors in flags), a wrong value here cannot
// widen who may join the network — it can only mislabel where a node is, which is
// visible, reversible with one edit, and already the thing the admin is being asked
// about.
func setupCountryOverrides(ctx context.Context, path string) error {
	m, err := loadCountryOverrides(path)
	if err != nil {
		return err
	}
	countryOverrides.Store(&m)
	switch {
	case path == "":
		log.Printf("country overrides: DISABLED (-country-overrides empty) — every node's country is this coordinator's own derivation (issue #113)")
		return nil
	case len(m) == 0:
		log.Printf("country overrides: none loaded (-country-overrides %s absent/empty) — every node's country is this coordinator's own derivation (issue #113)", path)
	default:
		log.Printf("country overrides: %d admin correction(s) loaded from %s, re-read every %s. Each REPLACES what this coordinator derived for that node, including under -geoip-required, and is a correction to the DERIVATION — never a promotion of the node's own -country claim (issue #113, ADR-0042 §8)", len(m), path, countryOverridesReload)
	}
	go reloadCountryOverridesLoop(ctx, path)
	return nil
}

// reloadCountryOverridesLoop re-reads the override file on a ticker and swaps in any
// change. A refused file leaves the corrections already in effect untouched — fail-safe
// in the same direction as reloadRevocationsLoop, where a malformed file must not
// silently un-revoke everyone.
func reloadCountryOverridesLoop(ctx context.Context, path string) {
	t := time.NewTicker(countryOverridesReload)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reloadCountryOverrides(path)
		}
	}
}

// reloadCountryOverrides performs one reload, logging ONLY when something changed.
//
// The change log is what tells an admin their edit landed. Without it the file is a
// write into silence: a per-node registration line fires only for a node new to the
// registry (see the register handler), so an override added to a node that has been up
// for an hour would otherwise produce no output anywhere until that node restarted.
func reloadCountryOverrides(path string) {
	// Nil-safe on both paths: the pointer is stored before this loop is ever started, so
	// nil means something replaced it out from under a still-running loop — a test
	// restoring globals, not a state this coordinator reaches — and crashing a whole
	// binary over it would be the wrong trade for a diagnostic reload.
	var prev map[string]string
	if p := countryOverrides.Load(); p != nil {
		prev = *p
	}
	next, err := loadCountryOverrides(path)
	if err != nil {
		log.Printf("country overrides: reload from %s REFUSED — keeping the %d correction(s) already in effect: %v", path, len(prev), err)
		return
	}
	changes := describeOverrideChanges(prev, next)
	if changes == "" {
		return
	}
	countryOverrides.Store(&next)
	log.Printf("country overrides: reloaded from %s — %d correction(s) now in effect; changed: %s. A change takes effect on each affected node's next register or heartbeat (issue #113)", path, len(next), changes)
}

// describeOverrideChanges renders the difference between two override sets for the
// operator log, or "" when they are identical. Sorted by node id so the line is
// deterministic and diffable across reloads.
func describeOverrideChanges(prev, next map[string]string) string {
	ids := make([]string, 0, len(prev)+len(next))
	seen := map[string]bool{}
	for id := range prev {
		ids, seen[id] = append(ids, id), true
	}
	for id := range next {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		before, after := prev[id], next[id]
		switch {
		case before == after:
		case before == "":
			out = append(out, fmt.Sprintf("%s=%s (added)", id, after))
		case after == "":
			out = append(out, fmt.Sprintf("%s: %s withdrawn, reverting to this coordinator's own derivation", id, before))
		default:
			out = append(out, fmt.Sprintf("%s: %s -> %s", id, before, after))
		}
	}
	return strings.Join(out, ", ")
}
