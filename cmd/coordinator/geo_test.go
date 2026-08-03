package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/geoip"
)

// Coordinator-derived node country (issue #136, ADR-0042).
//
// Every address here is from a reserved documentation range (RFC 5737 / RFC 3849).

const (
	// Addresses inside the staged fixture's blocks.
	ipInNL = "192.0.2.10"
	ipInDE = "198.51.100.10"
	ipInRU = "203.0.113.10"
	// A routable address the fixture maps to nothing.
	ipUnmapped = "192.0.2.200" // inside RFC 5737, outside every staged block
)

// stageGeoIP loads a small country database and installs it for the duration of the
// test, restoring the previous state afterwards.
//
// The fixture is in the RANGE format (issue #61) rather than MaxMind's CSV, because that
// is what an operator stages and so what this binary's derivation path should be exercised
// against end to end. Both formats are covered where the choice between them lives, in
// core/geoip's own tests; here the format is incidental and the derivation is the subject.
func stageGeoIP(t *testing.T, require bool) {
	t.Helper()
	dir := t.TempDir()
	// Each range stops half way through its /24, so ipUnmapped can sit inside a reserved
	// documentation range and still resolve to nothing. Covering whole /24s would leave no
	// unmapped address inside RFC 5737 to probe with, which is why an earlier fixture
	// stepped one address outside it, into globally allocated space.
	body := "192.0.2.0\t192.0.2.127\tNL\n" +
		"198.51.100.0\t198.51.100.127\tDE\n" +
		"203.0.113.0\t203.0.113.127\tRU\n"
	if err := os.WriteFile(filepath.Join(dir, geoip.FileRangesV4), []byte(body), 0o600); err != nil {
		t.Fatalf("stage %s: %v", geoip.FileRangesV4, err)
	}
	db, err := geoip.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Source != geoip.SourceRanges {
		t.Fatalf("staged the range format but LoadDir read %q", db.Source)
	}
	prevDB, prevReq := geoDB, requireGeoIP
	geoDB, requireGeoIP = db, require
	t.Cleanup(func() { geoDB, requireGeoIP = prevDB, prevReq })
}

// from builds a synthetic source address, so a test can register a node as though it
// came from a routable IP. Registers draw no reply, so nothing is ever sent to it.
func from(ip string) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: 20000}
}

// registerExitFrom registers an HONEST exit from an arbitrary observed address,
// carrying the self-reported country hint claim.
//
// Honest means its advertised data-plane endpoint is the address its signaling comes
// from — the two agree, so the derived country describes where traffic actually
// egresses (deriveExitCountry). A fixture that advertised some other address would be
// a SPLIT-ENDPOINT exit, which is a different subject with its own tests below; using
// one here would silently make every country-derivation test assert about the
// unverified path.
func registerExitFrom(id, claim string, src *net.UDPAddr) {
	handle(wire{Type: "register", Role: "exit", ID: id, Country: claim, Addr: net.JoinHostPort(src.IP.String(), "20000")}, src)
}

// registerSplitExit registers an exit whose signaling arrives from src but whose
// advertised data-plane endpoint is elsewhere — the shape an operator produces by
// forwarding only their coordinator signaling through a host in another country.
func registerSplitExit(id, claim string, src *net.UDPAddr, advertised string) {
	handle(wire{Type: "register", Role: "exit", ID: id, Country: claim, Addr: advertised}, src)
}

// registerNoAdvertiseExit registers an exit that advertises NO data-plane endpoint —
// `-advertise` left at its default, which is what a direct-mode exit runs as, since
// relays dial an advertised address and ICE does not.
//
// Nothing covered this shape before issue #2, and its absence is exactly why the
// bypass survived: registerExitFrom always sets Addr from the source (so it always
// agrees) and registerSplitExit always sets a different one (so it always disagrees).
// The default configuration — the one an operator actually runs, and the one the
// bypass needs — was the case no fixture could produce.
func registerNoAdvertiseExit(id, claim string, src *net.UDPAddr) {
	handle(wire{Type: "register", Role: "exit", ID: id, Country: claim}, src)
}

func exitCountry(t *testing.T, id string) (cc, source string) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	e := exits[id]
	if e == nil {
		t.Fatalf("exit %s is not registered", id)
	}
	return e.country, e.countrySource
}

// TestObservedIPBeatsSelfReportedCountry is the whole point of #136. A node registering
// from an address in the Netherlands while claiming to be in Russia is recorded as being
// in the Netherlands. Without this, a hostile or Sybil node places itself in any country
// it likes — and country is the only thing a user selects on (#146), so a node that can
// claim a country can draw traffic that believes it exits somewhere else.
func TestObservedIPBeatsSelfReportedCountry(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	registerExitFrom("liar", "RU", from(ipInNL))

	cc, source := exitCountry(t, "liar")
	if cc != "NL" {
		t.Errorf("country = %q; want NL, the country of the OBSERVED address — the node's claim of RU must not win", cc)
	}
	if source != countryObserved {
		t.Errorf("country source = %q; want %q", source, countryObserved)
	}
}

// TestUnresolvedAddressFallsBackToHint: the claim is still consulted when the observed
// address resolves to nothing — an unmapped range, or the loopback every node registers
// from in a local stack. Issue #136 explicitly keeps -country as a fallback.
func TestUnresolvedAddressFallsBackToHint(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	registerExitFrom("unmapped", "de", from(ipUnmapped))
	cc, source := exitCountry(t, "unmapped")
	if cc != "DE" || source != countryHinted {
		t.Errorf("unmapped address: country = %q (%s); want DE via the hint", cc, source)
	}

	// Canonicalized on the way in, so a lower-case hint cannot produce a tag that
	// case-sensitive consumers would treat as a different country.
	registerExitFrom("loopback", "ru", from("127.0.0.1"))
	if cc, _ := exitCountry(t, "loopback"); cc != "RU" {
		t.Errorf("loopback: country = %q; want the canonicalized hint RU", cc)
	}
}

// TestMalformedHintBecomesUnknown: the typo class #136 names as its first motivation.
// A hint that is not an ISO-3166 alpha-2 code yields NO country rather than a tag no
// client filter will ever match.
func TestMalformedHintBecomesUnknown(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	for _, claim := range []string{"Netherlands", "NLD", "N", "", "N1", "нл"} {
		id := "e-" + claim
		registerExitFrom(id, claim, from(ipUnmapped))
		if cc, source := exitCountry(t, id); cc != countryUnknown {
			t.Errorf("claim %q produced country %q (%s); want unknown", claim, cc, source)
		}
	}
}

// TestGeoIPRequiredIgnoresTheHintEntirely pins the hardened posture: with
// -geoip-required, a node whose observed address does not resolve gets no country at
// all, so no node self-report can reach a client's country choice under any
// circumstance.
func TestGeoIPRequiredIgnoresTheHintEntirely(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)

	registerExitFrom("claims-nl", "NL", from(ipUnmapped))
	if cc, source := exitCountry(t, "claims-nl"); cc != countryUnknown {
		t.Errorf("with -geoip-required, an unresolved address took the hint: country = %q (%s)", cc, source)
	}

	// Non-vacuity: the same flag still resolves an address that IS in the database, so
	// the assertion above is about the hint being ignored, not about everything failing.
	registerExitFrom("real-nl", "RU", from(ipInNL))
	if cc, _ := exitCountry(t, "real-nl"); cc != "NL" {
		t.Errorf("with -geoip-required, a resolvable address did not resolve: country = %q", cc)
	}
}

// TestSetupGeoIPRejectsContradictoryConfig: -geoip-required with no database staged
// would strip every node's country and leave nothing assignable, so it is refused at
// startup rather than discovered as an empty country list.
func TestSetupGeoIPRejectsContradictoryConfig(t *testing.T) {
	prevDB, prevReq := geoDB, requireGeoIP
	t.Cleanup(func() { geoDB, requireGeoIP = prevDB, prevReq })

	if err := setupGeoIP("", true); err == nil {
		t.Error("setupGeoIP accepted -geoip-required with no database")
	}
	// And an unreadable database is fatal rather than a silent fallback to hints: an
	// operator who asked for derived countries must not quietly get self-reported ones.
	if err := setupGeoIP(filepath.Join(t.TempDir(), "absent"), false); err == nil {
		t.Error("setupGeoIP accepted a configured-but-missing database")
	}
	// No database configured at all is fine — the pre-#136 behaviour.
	if err := setupGeoIP("", false); err != nil {
		t.Errorf("setupGeoIP rejected an unconfigured database: %v", err)
	}
}

// TestExitWithoutACountryIsUnreachable states a consequence of #136 + #146 out loud: a
// node with no derivable country is registered and healthy but cannot be reached,
// because a country is the only thing a client can ask for. The register handler logs a
// warning for exactly this reason.
func TestExitWithoutACountryIsUnreachable(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)
	client := fakePeer(t)

	registerExitFrom("nowhere", "NL", from(ipUnmapped)) // required-mode: no country
	if cc, _ := exitCountry(t, "nowhere"); cc != countryUnknown {
		t.Fatal("setup: exit unexpectedly has a country")
	}

	requestList(client)
	reply := recvWire(t, client, time.Second)
	if len(reply.Countries) != 0 {
		t.Errorf("a country-less exit appeared in the country list: %+v", reply.Countries)
	}
	if e, refusal := chooseExit("NL", nil, time.Now(), tierLimits{}); e != nil || refusal != refuseNoCountry {
		t.Errorf("chooseExit reached a country-less exit: (%v, %q)", e, refusal)
	}
}

// TestCountrylessExitIsNotAssignable exercises exitAssignable's country guard directly.
//
// It exists because mutation testing showed that removing the guard changes nothing
// observable through list or connect: countrySnapshot skips a country-less exit before
// reaching the predicate, and chooseExit only considers exits matching a canonical
// non-empty code. The guard is kept as defence in depth for any future caller, and this
// test is what keeps it from being untested dead code rather than merely unreachable.
func TestCountrylessExitIsNotAssignable(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)

	registerExitFrom("nowhere", "NL", from(ipUnmapped)) // required-mode: no country
	registerExitFrom("somewhere", "", from(ipInNL))     // resolves to NL

	mu.Lock()
	defer mu.Unlock()
	if exitAssignable(exits["nowhere"], 0, tierLimits{}) {
		t.Error("exitAssignable accepted an exit with no country; it is unreachable and cannot take a session")
	}
	// Non-vacuity: an otherwise identical exit that HAS a country is assignable, so the
	// assertion above is about the country and not about the fixture.
	if !exitAssignable(exits["somewhere"], 0, tierLimits{}) {
		t.Error("exitAssignable rejected a healthy exit with a country; the fixture is broken")
	}
}

// TestSplitEndpointExitIsNotCountedAsObserved is the data-plane binding (ADR-0042 §8).
//
// deriveCountry resolves the source of the REGISTER — the signaling address. An exit
// also advertises its own data-plane endpoint, and nothing used to compare the two. An
// operator running an exit in one country while forwarding only its coordinator
// signaling through a cheap host in another got the forwarding host's country derived
// and advertised to clients, while traffic egressed somewhere else entirely. For a
// product whose entire user-facing choice is jurisdiction, that is the misrouting the
// feature exists to prevent, and -geoip-required did not help: the address resolved
// fine, just to the wrong machine.
func TestSplitEndpointExitIsNotCountedAsObserved(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	// Signals from NL, claims to serve traffic from an RU address.
	registerSplitExit("forwarded", "", from(ipInNL), net.JoinHostPort(ipInRU, "20000"))
	cc, source := exitCountry(t, "forwarded")
	if source != countrySplit {
		t.Errorf("an exit whose advertised endpoint differs from its signaling source was recorded as %q; want %q", source, countrySplit)
	}
	if cc != "NL" {
		t.Errorf("country = %q; without -geoip-required the signaling-derived tag is still used, marked unverified", cc)
	}

	// Non-vacuity: the same exit advertising the address it signals from IS verified,
	// so the flag is about the mismatch and not about every registration.
	registerExitFrom("honest", "", from(ipInNL))
	if _, source := exitCountry(t, "honest"); source != countryObserved {
		t.Errorf("an exit advertising the address it signals from was recorded as %q; want %q", source, countryObserved)
	}
}

// TestGeoIPRequiredRefusesASplitEndpoint: under the hardened posture, a country that
// cannot be tied to the egress path is no country at all.
//
// This is what makes -geoip-required mean what an operator reads it to mean. A split
// endpoint IS a node self-assertion of location — the advertised address is the node's
// own claim, and the flag's promise is that no self-report reaches a client's country
// choice. An exit with no country is invisible to country-scoped assignment, so it is
// simply not offered.
func TestGeoIPRequiredRefusesASplitEndpoint(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)

	registerSplitExit("forwarded", "", from(ipInNL), net.JoinHostPort(ipInRU, "20000"))
	if cc, source := exitCountry(t, "forwarded"); cc != countryUnknown {
		t.Errorf("with -geoip-required a split-endpoint exit kept country %q (%s); it must get none", cc, source)
	}
	// Non-vacuity: an honest exit from the same address still resolves under the flag.
	registerExitFrom("honest", "", from(ipInNL))
	if cc, _ := exitCountry(t, "honest"); cc != "NL" {
		t.Errorf("with -geoip-required an honest exit did not resolve: country = %q", cc)
	}
}

// TestGeoIPRequiredRefusesAnExitThatAdvertisesNothing is issue #2: the bypass that
// defeated -geoip-required by OMITTING a flag.
//
// TestGeoIPRequiredRefusesASplitEndpoint above covers the operator who forwards their
// signaling and still advertises their real address. The cheaper attack was to advertise
// nothing: `-advertise` defaults to empty, a direct-mode exit never needs it, and an
// empty advertisement used to pass the comparison vacuously. So the exit ran in RU,
// forwarded only its UDP signaling through a host abroad, set no flag it had any reason
// to set, and came out tagged with the foreign country, source=observed, no warning
// logged, fully assignable — under the flag that exists to prevent precisely this.
//
// Under the flag an unadvertised endpoint is now UNVERIFIABLE rather than agreed. Note
// what is asserted: not just the tag, but that the exit is unreachable — a country tag
// is the only thing a client can ask for (#146), so a country the coordinator will not
// state is an exit no client can be sent to.
func TestGeoIPRequiredRefusesAnExitThatAdvertisesNothing(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)

	// Signals from NL (a host abroad), advertises nothing at all.
	registerNoAdvertiseExit("silent", "", from(ipInNL))
	cc, source := exitCountry(t, "silent")
	if cc != countryUnknown {
		t.Errorf("an exit advertising no endpoint kept country %q (%s) under -geoip-required; it must get none — an observation with nothing to corroborate it is not a verified country (issue #2)", cc, source)
	}
	if source != countryNoEndpoint {
		t.Errorf("provenance = %q, want %q — an operator must be able to tell 'you did not set -advertise' from 'your address did not resolve'", source, countryNoEndpoint)
	}

	// The tag is the mechanism; being unassignable is the property. A client can only
	// ask for a country, so an exit without one must be unreachable through every
	// surface: it is absent from the country map, and a connect naming NL is refused.
	if _, refusal := chooseExit("NL", nil, time.Now(), tierLimits{}); refusal != refuseNoCountry {
		t.Errorf("connect to NL was refused %q; want %q — the unverified exit is still assignable", refusal, refuseNoCountry)
	}
	if _, found := countryIn(wire{Countries: countrySnapshot(time.Now(), tierLimits{})}, "NL"); found {
		t.Error("the unverified exit still appears in the country map — a client would be offered a country it cannot be paired in")
	}

	// Non-vacuity: an exit that DOES advertise the address it signals from resolves
	// under the same flag, so this refuses the unverifiable case and not every exit.
	registerExitFrom("honest", "", from(ipInNL))
	if cc, source := exitCountry(t, "honest"); cc != "NL" || source != countryObserved {
		t.Errorf("an exit advertising the address it signals from got (%q, %q) under -geoip-required; want NL %q", cc, source, countryObserved)
	}
}

// TestNoAdvertisementKeepsItsCountryWithoutTheFlag is the other half of the decision,
// and the reason the fix is scoped to -geoip-required rather than making -advertise
// mandatory for the exit role.
//
// An operator who has not asked for the guarantee must not have their working
// direct-mode exit silently disqualified for omitting a flag it does not need. The flag
// buys the property; without it, the pre-#2 behaviour is unchanged.
func TestNoAdvertisementKeepsItsCountryWithoutTheFlag(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	registerNoAdvertiseExit("silent", "", from(ipInNL))
	cc, source := exitCountry(t, "silent")
	if cc != "NL" || source != countryObserved {
		t.Errorf("without -geoip-required a no-advertise exit got (%q, %q); want NL %q — the flag is what buys the guarantee, and -advertise stays optional without it", cc, source, countryObserved)
	}
	if _, refusal := chooseExit("NL", nil, time.Now(), tierLimits{}); refusal != refuseNone {
		t.Errorf("the exit was not assignable (%q) — an ordinary direct-mode exit must keep working with no -advertise set", refusal)
	}
}

// TestSplitEndpointUnderTheFlagKeepsItsProvenance: dropping the country must not drop
// the REASON. Both refusals leave an exit with no country, and an operator reading the
// log has to tell "you forwarded your signaling" from "you set no -advertise" from
// "your address did not resolve" — three different faults with three different fixes,
// which the register-time warning now names individually.
func TestSplitEndpointUnderTheFlagKeepsItsProvenance(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)

	registerSplitExit("forwarded", "", from(ipInNL), net.JoinHostPort(ipInRU, "20000"))
	if cc, source := exitCountry(t, "forwarded"); cc != countryUnknown || source != countrySplit {
		t.Errorf("a split endpoint under -geoip-required recorded (%q, %q); want no country with provenance %q", cc, source, countrySplit)
	}
	registerNoAdvertiseExit("silent", "", from(ipInNL))
	if _, source := exitCountry(t, "silent"); source != countryNoEndpoint {
		t.Errorf("a no-advertise exit recorded provenance %q; want %q — the two refusals must stay distinguishable", source, countryNoEndpoint)
	}
	registerExitFrom("unmapped", "", from(ipUnmapped))
	if cc, source := exitCountry(t, "unmapped"); cc != countryUnknown || source != countryUnknown {
		t.Errorf("an unresolved address recorded (%q, %q); want no country and no provenance — it is neither of the endpoint cases", cc, source)
	}
}

// TestUnadvertisedCountryIsNotLaunderedThroughAHeartbeat: the refusal has to survive
// the re-derivation every heartbeat runs, or the exit is unassignable for ten seconds
// and then quietly assignable forever after.
//
// rederiveExitCountry re-checks against the STORED advertisement, which for this exit is
// empty — so the empty case has to be re-decided, not remembered. And the tag must not
// come back as a hint either: countryNoEndpoint is a resolution this coordinator made,
// not something the node said, so rederiveHint must not recycle it.
func TestUnadvertisedCountryIsNotLaunderedThroughAHeartbeat(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)

	registerNoAdvertiseExit("silent", "NL", from(ipInNL)) // claims NL too, for good measure
	if cc, _ := exitCountry(t, "silent"); cc != countryUnknown {
		t.Fatalf("setup: country = %q, want none", cc)
	}
	handle(wire{Type: "heartbeat", ID: "silent"}, from(ipInNL))
	if cc, source := exitCountry(t, "silent"); cc != countryUnknown || source != countryNoEndpoint {
		t.Errorf("after a heartbeat the unadvertised exit got (%q, %q); want no country still — a refusal that a heartbeat undoes is no refusal", cc, source)
	}
}

// TestUnverifiableHostnameAdvertisementIsASplit: a hostname cannot be checked against
// the observed source without a DNS lookup, and this coordinator will not do one — it
// would be a blocking call on the packet handler for a name the node itself chose.
// Unverifiable is recorded as unverified rather than quietly accepted.
func TestUnverifiableHostnameAdvertisementIsASplit(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	registerSplitExit("named", "", from(ipInNL), "exit.example:20000")
	if _, source := exitCountry(t, "named"); source != countrySplit {
		t.Errorf("a hostname advertisement was recorded as %q; want %q — it cannot be checked", source, countrySplit)
	}
}

// TestHeartbeatMoveIsUnverifiedUntilTheNextRegister: an exit whose signaling address
// moves under it no longer agrees with the endpoint it advertised from the old one, so
// the verdict correctly drops to unverified — and a fresh register, which every node
// sends on its own interval, restores it. The window is one register cycle.
func TestHeartbeatMoveIsUnverifiedUntilTheNextRegister(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	registerExitFrom("mover", "", from(ipInNL))
	if _, source := exitCountry(t, "mover"); source != countryObserved {
		t.Fatalf("setup: source = %q, want %q", source, countryObserved)
	}
	handle(wire{Type: "heartbeat", ID: "mover"}, from(ipInDE))
	if cc, source := exitCountry(t, "mover"); cc != "DE" || source != countrySplit {
		t.Errorf("after a heartbeat move: (%q, %q); want DE marked %q — the stored advertisement is from the address it left", cc, source, countrySplit)
	}
	// The node re-registers on its own interval, carrying a fresh Addr; agreement is
	// re-established and the tag is verified again.
	registerExitFrom("mover", "", from(ipInDE))
	if cc, source := exitCountry(t, "mover"); cc != "DE" || source != countryObserved {
		t.Errorf("after re-registering from the new address: (%q, %q); want DE %q", cc, source, countryObserved)
	}
}

// TestHeartbeatRederivesCountryWithoutLaunderingAnObservation covers the asymmetry in
// rederiveCountry. A node's observed address is refreshed on every heartbeat, so its
// country is too; but a previously OBSERVED tag must never be recycled as a hint, or a
// node that moves to an unresolvable address would keep the country it used to resolve
// to — turning a stale observation into a standing claim.
func TestHeartbeatRederivesCountryWithoutLaunderingAnObservation(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	// Registers in NL (observed), then heartbeats from DE: the country follows.
	registerExitFrom("mover", "", from(ipInNL))
	if cc, _ := exitCountry(t, "mover"); cc != "NL" {
		t.Fatalf("setup: country = %q, want NL", cc)
	}
	handle(wire{Type: "heartbeat", ID: "mover"}, from(ipInDE))
	// A heartbeat carries no Addr, so the stored (NL) advertisement no longer matches
	// the new (DE) signaling source and the tag is correctly marked unverified — see
	// TestHeartbeatMoveIsUnverifiedUntilTheNextRegister. What matters here is that the
	// country FOLLOWED the observed address and was not taken from a hint.
	if cc, source := exitCountry(t, "mover"); cc != "DE" || source == countryHinted {
		t.Errorf("after moving to a DE address: country = %q (%s); want DE, observed-derived", cc, source)
	}

	// Now it moves to an address that resolves to nothing. The previously observed DE
	// must NOT be carried forward as a hint.
	handle(wire{Type: "heartbeat", ID: "mover"}, from(ipUnmapped))
	if cc, source := exitCountry(t, "mover"); cc != countryUnknown {
		t.Errorf("an observed country was laundered into a hint: country = %q (%s); want unknown", cc, source)
	}

	// A HINTED tag, by contrast, is still exactly what the node told us, so it
	// survives an address change that resolves to nothing.
	registerExitFrom("hinted", "RU", from(ipUnmapped))
	if cc, source := exitCountry(t, "hinted"); cc != "RU" || source != countryHinted {
		t.Fatalf("setup: country = %q (%s), want RU hinted", cc, source)
	}
	handle(wire{Type: "heartbeat", ID: "hinted"}, from("127.0.0.1"))
	if cc, source := exitCountry(t, "hinted"); cc != "RU" || source != countryHinted {
		t.Errorf("a hinted country was dropped on heartbeat: country = %q (%s); want RU hinted", cc, source)
	}
}

// TestRelayCountryIsDerivedAndAdvertisedInTheSignedDirectory: relays register a
// -country exactly as exits do, but before #136 the coordinator had nowhere to put it
// and silently discarded it. It is now derived from the observed address and carried in
// the SIGNED snapshot, which is what makes it a fact this coordinator established
// rather than a relay's claim — the same standard Ingress and Operator are held to.
func TestRelayCountryIsDerivedAndAdvertisedInTheSignedDirectory(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	// Claims RU, observed in DE, and advertises an ingress port so it is relay-eligible.
	handle(wire{Type: "register", Role: "relay", ID: "r1", Country: "RU", IngressPort: 9443}, from(ipInDE))

	// buildSnapshot takes the registry lock itself (see its doc), so it is called
	// without holding mu.
	snap := buildSnapshot("198.51.100.1:8080")

	var relay *coldstart.Entry
	for i := range snap.Entries {
		if snap.Entries[i].Role == "relay" {
			relay = &snap.Entries[i]
		}
	}
	if relay == nil {
		t.Fatal("no relay entry in the snapshot")
	}
	if relay.Country != "DE" {
		t.Errorf("relay entry Country = %q; want DE (the observed address), not the claimed RU", relay.Country)
	}

	// It really is inside the signed bytes, not merely on the in-memory struct.
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var back coldstart.Snapshot
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	for _, e := range back.Entries {
		if e.Role == "relay" && e.Country != "DE" {
			t.Errorf("relay country did not survive the signed encoding: %q", e.Country)
		}
	}
}

// TestSnapshotCarriesCountryProvenance is issue #3: the signed directory must say HOW
// it arrived at each country, not only what it is.
//
// countrySplit was computed, logged, and then thrown away at the snapshot boundary, so a
// split-endpoint exit shipped in the SIGNED directory byte-identical in shape to a
// verified one — {Country:"NL", Addr:"<RU address>"} — and so did an exit whose country
// is nothing but its own -country flag. The signature proves the coordinator said it; it
// says nothing about which of the three it was, and ADR-0042 §9 made this artifact the
// exit-discovery path for chaining.
func TestSnapshotCarriesCountryProvenance(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	registerExitFrom("honest", "", from(ipInNL))                                        // observed
	registerSplitExit("forwarded", "", from(ipInNL), net.JoinHostPort(ipInRU, "20000")) // split
	registerExitFrom("hinted", "RU", from(ipUnmapped))                                  // hint
	handle(wire{Type: "register", Role: "relay", ID: "r-hinted", Country: "DE", IngressPort: 9443}, from(ipUnmapped))

	// Read the provenance out of the SIGNED bytes, not the in-memory struct: a field
	// that never reaches the wire is a field a consumer cannot act on, which is
	// precisely the state countrySplit was already in.
	snap := buildSnapshot("198.51.100.1:8080")
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var back coldstart.Snapshot
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	got := map[string]coldstart.Entry{}
	for _, e := range back.Entries {
		got[e.ID] = e
	}

	for id, want := range map[string]string{
		"honest":    coldstart.CountryObserved,
		"forwarded": coldstart.CountrySignalingOnly,
		"hinted":    coldstart.CountryHinted,
		"r-hinted":  coldstart.CountryHinted, // a RELAY's country is a self-report too when its address resolves to nothing
	} {
		e, ok := got[id]
		if !ok {
			t.Errorf("%s is missing from the snapshot", id)
			continue
		}
		if e.CountrySource != want {
			t.Errorf("%s shipped CountrySource=%q, want %q — a consumer cannot tell a derived country from a self-reported one", id, e.CountrySource, want)
		}
	}

	// And the decision, asserted rather than left implicit: the split-endpoint exit is
	// NOT withheld. This snapshot is also the mesh-walk courier list (ADR-0037), and
	// dropping a reachable peer over a property of its country withdraws recovery
	// capacity at the moment recovery is needed; without -geoip-required such an exit
	// is also still assignable through connect (ADR-0042 §8), so withholding it here
	// would put the directory out of step with what the coordinator actually hands out.
	if e, ok := got["forwarded"]; !ok || e.Addr == "" {
		t.Error("the split-endpoint exit was withheld from the snapshot — it must ship labelled, so it stays a mesh-walk courier and the directory keeps agreeing with connect (issue #3)")
	}
	if !got["forwarded"].CountryContradicted() {
		t.Error("the split-endpoint exit's entry does not report itself contradicted — the label is what a chaining client fails closed on")
	}
	if got["honest"].CountryContradicted() || got["hinted"].CountryContradicted() {
		t.Error("an observed or hinted country reported itself contradicted — only an OBSERVED disagreement is one")
	}
}

// TestCountrySourceWireContract pins this binary's copy of the provenance literals
// against core/coldstart's, which owns the signed artifact's schema. This binary
// deliberately does not import core (see wire's doc in main.go), so the vocabulary
// exists twice; core has its own test of the same name pinning the other side. The same
// arrangement TestQuotaStateWireContract uses for the quota literals (#97).
//
// A drift here is worse than most, because it fails OPEN: a consumer that does not
// recognize a provenance value treats the entry as not contradicted and selects it.
func TestCountrySourceWireContract(t *testing.T) {
	for _, tc := range []struct{ mine, theirs string }{
		{countryObserved, coldstart.CountryObserved},
		{countryHinted, coldstart.CountryHinted},
		{countrySplit, coldstart.CountrySignalingOnly},
		{countryNoEndpoint, coldstart.CountryNoEndpoint},
		{countryOverride, coldstart.CountryAdminOverride},
	} {
		if tc.mine != tc.theirs {
			t.Errorf("country provenance literal drifted: coordinator has %q, coldstart has %q", tc.mine, tc.theirs)
		}
	}
}

// TestNoGeoIPKeepsThePreviousBehaviour: with no database staged the coordinator behaves
// exactly as it did before #136 — the node's tag is the only source of a country. This
// is what keeps the local smoke stack and the current deployment working unchanged.
func TestNoGeoIPKeepsThePreviousBehaviour(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	prevDB, prevReq := geoDB, requireGeoIP
	geoDB, requireGeoIP = nil, false
	t.Cleanup(func() { geoDB, requireGeoIP = prevDB, prevReq })

	registerExitFrom("e1", "nl", from(ipInNL))
	if cc, source := exitCountry(t, "e1"); cc != "NL" || source != countryHinted {
		t.Errorf("with no database: country = %q (%s); want the hint NL", cc, source)
	}
}

// Two claims under one name (issue #113, ADR-0042 §8 update 2026-08-03).
//
// A node's country was two different claims collapsed at derivation time: where the
// ADDRESS resolves, which is what every destination site concludes, and where the
// MACHINE is, which only its operator knows. deriveCountry computed both and returned
// one, so from the moment a node registered nothing could tell there had been a second
// answer. These cover keeping both, keeping them apart, and the admin correction that
// can replace the first — never promote the second.

// exitClaims reads everything the registry holds about an exit's country.
func exitClaims(t *testing.T, id string) countryClaims {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	e := exits[id]
	if e == nil {
		t.Fatalf("exit %s is not registered", id)
	}
	return e.claims()
}

func relayClaims(t *testing.T, id string) countryClaims {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	r := relays[id]
	if r == nil {
		t.Fatalf("relay %s is not registered", id)
	}
	return r.claims()
}

// stageCountryOverrides installs a set of admin corrections for the duration of a test,
// restoring the previous set afterwards. It writes the map directly rather than through
// a file, so a test of the DERIVATION does not also depend on the loader; the loader has
// its own tests below.
func stageCountryOverrides(t *testing.T, m map[string]string) {
	t.Helper()
	prev := countryOverrides.Load()
	countryOverrides.Store(&m)
	t.Cleanup(func() { countryOverrides.Store(prev) })
}

// writeOverridesFile writes an override file and returns its path.
func writeOverridesFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "country-overrides.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestBothCountryClaimsAreKept is issue #113 itself: a node whose observed address and
// self-reported tag disagree keeps BOTH, distinguishably, and the derived one is still
// the one that wins.
//
// This is the shape the staging run found — an exit whose operator knows it is in DE
// while its provider's address block resolves elsewhere — and it is the normal case, not
// an anomaly. Before this, the declaration was computed and dropped on the floor.
func TestBothCountryClaimsAreKept(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	// Observed in NL, declares DE.
	registerExitFrom("cloudy", "DE", from(ipInNL))
	c := exitClaims(t, "cloudy")
	if c.derived != "NL" || c.source != countryObserved {
		t.Errorf("derived = %q (%s); want NL observed — the derivation must still win", c.derived, c.source)
	}
	if c.declared != "DE" {
		t.Errorf("declared = %q; want DE — the node's own claim must survive losing (issue #113)", c.declared)
	}

	// A relay is covered too: #113 is about both roles, and a relay's country falls back
	// to its hint just as an exit's does.
	handle(wire{Type: "register", Role: "relay", ID: "r-cloudy", Country: "de", IngressPort: 9443}, from(ipInNL))
	rc := relayClaims(t, "r-cloudy")
	if rc.derived != "NL" || rc.declared != "DE" {
		t.Errorf("relay claims = %+v; want derived NL, declared DE (canonicalized)", rc)
	}

	// And both reach the SIGNED directory, which is the only place a consumer can read
	// them. A value that never leaves the coordinator is a value nothing can act on —
	// exactly the state the split-endpoint provenance was in before #3.
	snap := buildSnapshot("198.51.100.1:8080")
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var back coldstart.Snapshot
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	for _, id := range []string{"cloudy", "r-cloudy"} {
		e := findEntry(t, back, id)
		if e.Country != "NL" || e.DeclaredCountry != "DE" {
			t.Errorf("%s shipped Country=%q DeclaredCountry=%q; want NL / DE", id, e.Country, e.DeclaredCountry)
		}
		if !e.DeclaredCountryDiffers() {
			t.Errorf("%s does not report its two claims as differing — the disagreement is not a fact any surface can list", id)
		}
		// The trap: this must NOT have become the fail-closed jurisdiction refusal.
		if e.CountryContradicted() {
			t.Errorf("%s reports itself CONTRADICTED because its declaration disagrees — that predicate is fail-closed and this is the ordinary case; it would refuse most of a cloud fleet", id)
		}
	}
}

// TestDeclarationSurvivesAHeartbeat: a heartbeat carries no -country tag, so a
// re-derivation that rebuilt the declaration from the recycled hint would blank it on
// the first heartbeat for every node whose address resolved — which is exactly the set
// of nodes whose two claims disagree.
func TestDeclarationSurvivesAHeartbeat(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)

	registerExitFrom("cloudy", "DE", from(ipInNL))
	handle(wire{Type: "register", Role: "relay", ID: "r-cloudy", Country: "DE"}, from(ipInNL))
	handle(wire{Type: "heartbeat", ID: "cloudy"}, from(ipInNL))
	handle(wire{Type: "heartbeat", ID: "r-cloudy"}, from(ipInNL))

	if c := exitClaims(t, "cloudy"); c.declared != "DE" || c.derived != "NL" {
		t.Errorf("after a heartbeat the exit holds %+v; want derived NL, declared DE", c)
	}
	if c := relayClaims(t, "r-cloudy"); c.declared != "DE" || c.derived != "NL" {
		t.Errorf("after a heartbeat the relay holds %+v; want derived NL, declared DE", c)
	}
}

// TestGeoIPRequiredRecordsTheDeclarationWithoutUsingIt: with both values carried,
// "refuse" and "fall back" became two distinct options, and the strict posture must stay
// the first. The declaration is RECORDED and published as a labelled declaration —
// carrying a claim is not choosing one — while the country stays empty and the exit
// stays unreachable.
func TestGeoIPRequiredRecordsTheDeclarationWithoutUsingIt(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)

	registerExitFrom("claims-de", "DE", from(ipUnmapped))
	c := exitClaims(t, "claims-de")
	if c.derived != countryUnknown || c.source != countryUnknown {
		t.Errorf("with -geoip-required an unresolved address took the declaration: %+v", c)
	}
	if c.declared != "DE" {
		t.Errorf("declared = %q; want DE — the refusal is about what may become the country, not about what may be recorded", c.declared)
	}
	// The property, not just the tag: the exit is still invisible to assignment.
	if _, refusal := chooseExit("DE", nil, time.Now(), tierLimits{}); refusal != refuseNoCountry {
		t.Errorf("connect to DE was refused %q; want %q — the declaration must not have become assignable", refusal, refuseNoCountry)
	}
	if _, found := countryIn(wire{Countries: countrySnapshot(time.Now(), tierLimits{})}, "DE"); found {
		t.Error("the declared country appeared in the country map — a client would be offered a country nothing verified")
	}
	// On the wire it ships as what it is: no country, and a labelled claim beside it.
	e := findEntry(t, buildSnapshot("198.51.100.1:8080"), "claims-de")
	if e.Country != "" || e.DeclaredCountry != "DE" {
		t.Errorf("snapshot entry = {Country:%q DeclaredCountry:%q}; want no country and the declaration carried", e.Country, e.DeclaredCountry)
	}
	if e.DeclaredCountryDiffers() {
		t.Error("an entry with no published country reported a disagreement — there is nothing to disagree with")
	}
}

// TestCountryOverrideBeatsTheDerivation is ruling B's correcting half: an admin who
// holds evidence this coordinator does not — "your table is wrong, that address really
// does present as DE" — can say so, and it wins.
func TestCountryOverrideBeatsTheDerivation(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)
	stageCountryOverrides(t, map[string]string{"corrected": "DE"})

	registerExitFrom("corrected", "RU", from(ipInNL)) // resolves NL, declares RU
	c := exitClaims(t, "corrected")
	if c.derived != "DE" {
		t.Errorf("derived = %q; want DE, the admin's correction", c.derived)
	}
	if c.source != countryOverride {
		t.Errorf("source = %q; want %q — an admin correction is neither an observation nor a node claim, and must not be reported as either", c.source, countryOverride)
	}
	if c.declared != "RU" {
		t.Errorf("declared = %q; the override must not touch what the node claimed", c.declared)
	}
	// What the correction DISPLACED is carried on the derivation rather than stored on
	// the entry (it describes one act of overriding, and every heartbeat re-derives), so
	// it is read where it is produced. The operator log needs it to say what was
	// overridden.
	if d := deriveExitCountry("corrected", from(ipInNL), "RU", net.JoinHostPort(ipInNL, "20000")); d.displaced != countryObserved {
		t.Errorf("displaced = %q; want %q — the operator log has to be able to say what the correction overrode", d.displaced, countryObserved)
	}

	// It is the country for every purpose, not a decoration: assignment groups on it.
	if _, refusal := chooseExit("DE", nil, time.Now(), tierLimits{}); refusal != refuseNone {
		t.Errorf("connect to DE was refused %q; the corrected country must be the assignable one", refusal)
	}
	if _, refusal := chooseExit("NL", nil, time.Now(), tierLimits{}); refusal != refuseNoCountry {
		t.Errorf("connect to NL was refused %q; want %q — the displaced country must not still be assignable", refusal, refuseNoCountry)
	}
	e := findEntry(t, buildSnapshot("198.51.100.1:8080"), "corrected")
	if e.Country != "DE" || e.CountrySource != coldstart.CountryAdminOverride {
		t.Errorf("snapshot entry = {Country:%q CountrySource:%q}; want DE / %q", e.Country, e.CountrySource, coldstart.CountryAdminOverride)
	}
	if e.CountryContradicted() {
		t.Error("an admin-corrected entry reports itself contradicted — a correction is an assertion, not a discovered disagreement")
	}
}

// TestCountryOverrideWinsUnderGeoIPRequired states the exemption out loud, because it is
// exactly the kind of quiet erosion that flag exists to prevent.
//
// The flag's promise is that no NODE SELF-REPORT reaches a client's country choice. An
// admin correction is this coordinator's own operator speaking — the same standing
// -operators has — so honouring it leaves the promise as strong as it was. What must
// stay refused under the flag is the NODE's claim, and the second half asserts that it
// is: an identical node with no override still gets nothing.
func TestCountryOverrideWinsUnderGeoIPRequired(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, true)
	stageCountryOverrides(t, map[string]string{"corrected": "DE"})

	registerExitFrom("corrected", "RU", from(ipUnmapped)) // resolves to nothing
	c := exitClaims(t, "corrected")
	if c.derived != "DE" || c.source != countryOverride {
		t.Errorf("under -geoip-required the override did not win: %+v", c)
	}
	// Non-vacuity: the node's own claim is still refused under the same flag.
	registerExitFrom("uncorrected", "RU", from(ipUnmapped))
	if c := exitClaims(t, "uncorrected"); c.derived != countryUnknown {
		t.Errorf("-geoip-required let a node self-report through: %+v — the exemption is for the ADMIN, not for the node", c)
	}
}

// TestCountryOverrideIsNotAPromotionOfTheDeclaration pins the crux of ruling B in the
// one way code can pin it.
//
// Whether an admin typed the RIGHT value is not checkable here — "the address presents
// as DE" and "the machine is in DE" arrive as the same two letters, which is why the
// distinction is written where the admin edits. What IS checkable is that the mechanism
// never promotes the declaration on its own, and never launders a correction into either
// of the other two provenances: an override that happens to equal what the node claimed
// is still recorded as an admin assertion, so nothing downstream can conclude the
// coordinator resolved it or that the node was believed.
func TestCountryOverrideIsNotAPromotionOfTheDeclaration(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)
	stageCountryOverrides(t, map[string]string{"agrees": "RU"})

	// The node declared RU; the admin also says RU. Same letters, different speaker.
	registerExitFrom("agrees", "RU", from(ipInNL))
	c := exitClaims(t, "agrees")
	if c.source != countryOverride {
		t.Errorf("source = %q; want %q — a correction that happens to match the node's claim is still the ADMIN's statement, not the node's", c.source, countryOverride)
	}
	if c.declared != "RU" {
		t.Errorf("declared = %q; want RU, unchanged", c.declared)
	}

	// And with no override staged for it, a declaration is never promoted no matter how
	// far it is from the derivation.
	registerExitFrom("unpromoted", "RU", from(ipInNL))
	if c := exitClaims(t, "unpromoted"); c.derived != "NL" {
		t.Errorf("derived = %q; want NL — nothing promotes a declaration on its own", c.derived)
	}
}

// TestCountryOverrideIsTerminalForTheEndpointCheck records a cost rather than a benefit,
// because it is invisible otherwise.
//
// An override replaces the derivation before the signaling-vs-advertised-endpoint
// comparison is reached, so an overridden split-endpoint exit stops reporting the
// contradiction a chaining client fails closed on (ADR-0042 §8). That is the price of an
// override that cannot be demoted back to "contradicted" — an override that could be
// would not be an override — and the coordinator warns when it happens.
func TestCountryOverrideIsTerminalForTheEndpointCheck(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)
	stageCountryOverrides(t, map[string]string{"forwarded": "DE"})

	registerSplitExit("forwarded", "", from(ipInNL), net.JoinHostPort(ipInRU, "20000"))
	c := exitClaims(t, "forwarded")
	if c.source != countryOverride || c.derived != "DE" {
		t.Errorf("claims = %+v; want the override to win over a split endpoint too", c)
	}
	// The derivation is run to completion BEFORE the override replaces it, precisely so
	// this coordinator can name the verdict a correction switched off. Applied first, the
	// override would suppress the endpoint comparison before it was ever computed and
	// nothing could report what had been suppressed.
	if d := deriveExitCountry("forwarded", from(ipInNL), "", net.JoinHostPort(ipInRU, "20000")); d.displaced != countrySplit {
		t.Errorf("displaced = %q; want %q — the warning has to be able to name what was switched off", d.displaced, countrySplit)
	}
	if findEntry(t, buildSnapshot("198.51.100.1:8080"), "forwarded").CountryContradicted() {
		t.Error("an overridden split-endpoint exit still reports itself contradicted; if that ever becomes true, the override is not terminal and this test's comment is the wrong story")
	}

	// Non-vacuity: without an override the same exit is still labelled, so this is about
	// the override and not about the check having been removed.
	registerSplitExit("untouched", "", from(ipInNL), net.JoinHostPort(ipInRU, "20000"))
	if c := exitClaims(t, "untouched"); c.source != countrySplit {
		t.Errorf("an un-overridden split endpoint recorded %q; want %q", c.source, countrySplit)
	}
}

// TestCountryOverrideIsNotRecycledAsAHint: a withdrawn correction must not survive as
// though the node had claimed it. Same asymmetry rederiveHint already enforces for an
// observed tag, one step further out — an ADMIN's assertion is not a node's.
func TestCountryOverrideIsNotRecycledAsAHint(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)
	m := map[string]string{"corrected": "DE"}
	stageCountryOverrides(t, m)

	registerExitFrom("corrected", "", from(ipInNL))
	if c := exitClaims(t, "corrected"); c.derived != "DE" {
		t.Fatalf("setup: %+v", c)
	}
	// The admin withdraws it, and the node moves to an address that resolves to nothing.
	stageCountryOverrides(t, map[string]string{})
	handle(wire{Type: "heartbeat", ID: "corrected"}, from(ipUnmapped))
	if c := exitClaims(t, "corrected"); c.derived != countryUnknown {
		t.Errorf("after the override was withdrawn the node kept %+v; a correction must not persist as a hint", c)
	}
}

// TestLoadCountryOverridesRefusesABadFileWhole covers the loader's decisions: a missing
// file and an empty path are "nothing configured", and a present file with ANY unusable
// row is refused ENTIRELY rather than partly applied.
//
// The partial-application alternative produces a correction that looks applied and is
// not, which is the failure #113 was found through — a documentation placeholder pasted
// into COUNTRY= and accepted verbatim.
func TestLoadCountryOverridesRefusesABadFileWhole(t *testing.T) {
	if m, err := loadCountryOverrides(""); err != nil || len(m) != 0 {
		t.Errorf("empty path: (%v, %v); want an empty map and no error", m, err)
	}
	if m, err := loadCountryOverrides(filepath.Join(t.TempDir(), "absent.json")); err != nil || len(m) != 0 {
		t.Errorf("missing file: (%v, %v); want an empty map and no error", m, err)
	}

	good := writeOverridesFile(t, `{"n1":"de","n2":"RU"}`)
	m, err := loadCountryOverrides(good)
	if err != nil {
		t.Fatalf("good file: %v", err)
	}
	if m["n1"] != "DE" || m["n2"] != "RU" {
		t.Errorf("loaded %v; want canonicalized codes — a lower-case correction must not produce a tag no filter matches", m)
	}

	for _, tc := range []struct{ name, body string }{
		{"not an object", `["n1","DE"]`},
		{"not a country code", `{"n1":"DE","n2":"Germany"}`},
		{"a placeholder pasted in", `{"n1":"<TAG>"}`},
		{"empty code", `{"n1":""}`},
		{"empty node id", `{"":"DE"}`},
		{"truncated", `{"n1":`},
	} {
		if _, err := loadCountryOverrides(writeOverridesFile(t, tc.body)); err == nil {
			t.Errorf("%s: accepted %s — one unusable row must refuse the whole file, not leave a correction silently unapplied", tc.name, tc.body)
		}
	}
}

// TestCountryOverridesReloadKeepsTheLastGoodSet is the hot-reload half, and its failure
// direction.
//
// An admin edits this file when prompted, so it takes effect without a restart — but a
// bad write must never silently drop the corrections already in force, the same
// direction reloadRevocationsLoop fails in (a malformed file must not un-revoke
// everyone).
func TestCountryOverridesReloadKeepsTheLastGoodSet(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	stageGeoIP(t, false)
	prev := countryOverrides.Load()
	// The reload loop setupCountryOverrides starts is a real goroutine on a real ticker,
	// so it is cancelled BEFORE the globals it reads are restored — a loop left running
	// past its test reads another test's state.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); countryOverrides.Store(prev) })

	path := writeOverridesFile(t, `{"corrected":"DE"}`)
	if err := setupCountryOverrides(ctx, path); err != nil {
		t.Fatalf("setupCountryOverrides: %v", err)
	}
	registerExitFrom("corrected", "", from(ipInNL))
	if c := exitClaims(t, "corrected"); c.derived != "DE" {
		t.Fatalf("setup: %+v", c)
	}

	// A good edit lands with no restart, on the node's next heartbeat.
	if err := os.WriteFile(path, []byte(`{"corrected":"FR"}`), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	reloadCountryOverrides(path)
	handle(wire{Type: "heartbeat", ID: "corrected"}, from(ipInNL))
	if c := exitClaims(t, "corrected"); c.derived != "FR" {
		t.Errorf("after an edit and a heartbeat: %+v; want FR — a correction behind a restart is a correction that will not be made", c)
	}

	// A bad edit changes nothing at all.
	if err := os.WriteFile(path, []byte(`{"corrected":"Germany"}`), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	reloadCountryOverrides(path)
	handle(wire{Type: "heartbeat", ID: "corrected"}, from(ipInNL))
	if c := exitClaims(t, "corrected"); c.derived != "FR" {
		t.Errorf("a malformed edit disturbed the corrections in force: %+v; want FR still", c)
	}

	// And a withdrawal reverts to this coordinator's own derivation.
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	reloadCountryOverrides(path)
	handle(wire{Type: "heartbeat", ID: "corrected"}, from(ipInNL))
	if c := exitClaims(t, "corrected"); c.derived != "NL" || c.source != countryObserved {
		t.Errorf("after withdrawing the override: %+v; want the observed NL back", c)
	}
}

// TestSetupCountryOverridesIsFatalOnABadFile: at startup a present-but-unusable file is
// an error rather than a shrug, matching -operators and -geoip. An admin who staged a
// correction must not get a coordinator that came up looking configured while still
// publishing the country they were correcting.
func TestSetupCountryOverridesIsFatalOnABadFile(t *testing.T) {
	prev := countryOverrides.Load()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); countryOverrides.Store(prev) })

	if err := setupCountryOverrides(ctx, writeOverridesFile(t, `{"n1":"nonsense"}`)); err == nil {
		t.Error("setupCountryOverrides accepted an unusable file")
	}
	// And the ordinary cases are not errors: no file, and no path at all.
	if err := setupCountryOverrides(ctx, filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Errorf("setupCountryOverrides rejected a missing file: %v", err)
	}
	if err := setupCountryOverrides(ctx, ""); err != nil {
		t.Errorf("setupCountryOverrides rejected an empty path: %v", err)
	}
}

// TestDescribeOverrideChanges pins the line an admin reads to know their edit landed.
// Empty means "nothing changed", which is what keeps a 30s ticker from printing forever.
func TestDescribeOverrideChanges(t *testing.T) {
	for _, tc := range []struct {
		name       string
		prev, next map[string]string
		want       string
	}{
		{"unchanged", map[string]string{"a": "DE"}, map[string]string{"a": "DE"}, ""},
		{"both empty", map[string]string{}, map[string]string{}, ""},
		{"added", map[string]string{}, map[string]string{"a": "DE"}, "a=DE (added)"},
		{"changed", map[string]string{"a": "DE"}, map[string]string{"a": "FR"}, "a: DE -> FR"},
		{"withdrawn", map[string]string{"a": "DE"}, map[string]string{}, "a: DE withdrawn, reverting to this coordinator's own derivation"},
		{"sorted", map[string]string{}, map[string]string{"b": "FR", "a": "DE"}, "a=DE (added), b=FR (added)"},
	} {
		if got := describeOverrideChanges(tc.prev, tc.next); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCountryClaimLabel pins the one operator-facing surface that exists today, which is
// where #113's second answer becomes visible at all.
//
// A plain fact rather than a warning, deliberately: the disagreement is the ordinary
// case on cloud address space, and a warning an operator learns to ignore is worse than
// none. Silence means "no disagreement to report".
func TestCountryClaimLabel(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    countryClaims
		want string
	}{
		{"agreeing", countryClaims{derived: "NL", source: countryObserved, declared: "NL"}, "observed IP"},
		{"nothing declared", countryClaims{derived: "NL", source: countryObserved}, "observed IP"},
		{"disagreeing", countryClaims{derived: "NL", source: countryObserved, declared: "DE"}, "observed IP; node declares DE"},
		{"refused under the flag", countryClaims{source: countryNoEndpoint, declared: "DE"}, "observed SIGNALING IP only — no advertised endpoint to corroborate it, and -geoip-required is set; node declares DE"},
		{"corrected", countryClaims{derived: "FR", source: countryOverride, declared: "DE"}, "ADMIN OVERRIDE, not derived; node declares DE"},
	} {
		if got := countryClaimLabel(tc.c); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
