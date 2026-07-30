package main

import (
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
func stageGeoIP(t *testing.T, require bool) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		geoip.FileLocations: "geoname_id,locale_code,country_iso_code,country_name\n" +
			"1,en,NL,Netherlands\n2,en,DE,Germany\n3,en,RU,Russia\n",
		// Sub-/24 blocks, so ipUnmapped can sit inside a reserved documentation range
		// and still resolve to nothing. Whole /24s leave no unmapped address inside
		// RFC 5737 to probe with, which is why the previous fixture stepped one
		// address outside it, into globally allocated space.
		geoip.FileBlocksV4: "network,geoname_id,registered_country_geoname_id\n" +
			"192.0.2.0/25,1,1\n198.51.100.0/25,2,2\n203.0.113.0/25,3,3\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("stage %s: %v", name, err)
		}
	}
	db, err := geoip.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
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
