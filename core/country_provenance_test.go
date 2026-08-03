package core

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// Consumer half of country provenance in the signed directory (issue #3).
//
// ADR-0042 §9 made the signed snapshot THE exit-discovery path for relay chaining, so a
// chaining client picks its terminating exit — the jurisdiction the whole feature exists
// to choose — out of this artifact, with no live reply to check it against. Before #3
// the artifact could not say which of "resolved from an address we observed", "taken
// verbatim from the node's own flag" and "resolved from an address that disagrees with
// where the node says it serves traffic" a country was, so all three read the same.
//
// The failure is silent by construction: a client that picks a contradicted exit
// connects perfectly well and egresses in the wrong country, which is the one outcome
// country selection exists to prevent and the one a passing connection cannot reveal.

func provenanceExitID(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	return hex.EncodeToString(k[:])
}

// TestChainExitRefusesAContradictedCountry: an exit the coordinator flagged as
// signaling-only is not a candidate for terminating a chain, however well its tag
// matches the country the user asked for.
//
// This is core/relaychain.go's fail-closed rule applied to jurisdiction: a user who
// asked to egress in NL and was handed an exit whose NL tag the coordinator can see
// describes a different machine has been given a weaker path than the one they asked
// for, and would go on acting on an assurance they no longer have.
func TestChainExitRefusesAContradictedCountry(t *testing.T) {
	split := provenanceExitID(t)
	dir := loadTestDirectory(t, []coldstart.Entry{
		{Role: "exit", ID: split, Country: "NL", CountrySource: coldstart.CountrySignalingOnly, Addr: "198.51.100.9:20000"},
	})

	if got := dir.exitsIn("NL"); len(got) != 0 {
		t.Fatalf("exitsIn(NL) offered %d candidate(s); an exit whose country the coordinator flagged as describing where it SIGNALS from must not be a terminating-exit candidate (issue #3)", len(got))
	}
	// Withheld, and countable — so the client can say WHY rather than reporting the
	// country as empty when the directory plainly lists an exit there.
	if n := dir.contradictedIn("NL"); n != 1 {
		t.Errorf("contradictedIn(NL) = %d, want 1 — a client that cannot name the reason sends its user looking in the wrong place", n)
	}
}

// TestChainExitAcceptsObservedAndHintedCountries is the non-vacuity half, and it is what
// keeps the fix from being a fleet-wide outage.
//
// Refusing every country that is not VERIFIED would refuse every hinted one, and a
// coordinator with no geo database staged — the default, and today's deployment — tags
// every node in the fleet by its own -country hint. A client would simply stop being
// able to chain against a coordinator behaving exactly as it always has. The line drawn
// is contradiction, not uncertainty.
func TestChainExitAcceptsObservedAndHintedCountries(t *testing.T) {
	observed, hinted, legacy := provenanceExitID(t), provenanceExitID(t), provenanceExitID(t)
	dir := loadTestDirectory(t, []coldstart.Entry{
		{Role: "exit", ID: observed, Country: "NL", CountrySource: coldstart.CountryObserved, Addr: "198.51.100.1:20000"},
		{Role: "exit", ID: hinted, Country: "NL", CountrySource: coldstart.CountryHinted, Addr: "198.51.100.2:20000"},
		// No provenance at all: a coordinator predating the field. Accepted, because
		// that is the pre-#3 status quo rather than a discovered disagreement — and
		// refusing it would break every client against an un-upgraded coordinator.
		{Role: "exit", ID: legacy, Country: "NL", Addr: "198.51.100.3:20000"},
	})

	got := dir.exitsIn("NL")
	if len(got) != 3 {
		var ids []string
		for _, h := range got {
			ids = append(ids, h.id[:8])
		}
		t.Fatalf("exitsIn(NL) offered %d candidate(s) (%s); want all 3 — observed, hinted and provenance-less countries must all stay selectable, or chaining breaks wherever no geo database is staged", len(got), strings.Join(ids, ","))
	}
}

// TestContradictedExitIsStillUsableAsAHop pins the scope of the refusal.
//
// A contradicted country says something about where a node EGRESSES, which matters only
// for the node that terminates the path. A peeling hop egresses nothing — it hands its
// layer to the next node — and hop diversity is operator- and AS-based (ADR-0038 §4),
// not country-based. Dropping such a node from the hop pool would shrink the candidate
// set for no gain, and the pool is the scarce resource in this design.
//
// It also stays a mesh-walk courier, which is the other half of why the coordinator
// keeps publishing it at all rather than withholding the entry.
func TestContradictedExitIsStillUsableAsAHop(t *testing.T) {
	split := provenanceExitID(t)
	dir := loadTestDirectory(t, []coldstart.Entry{
		{Role: "exit", ID: split, Country: "NL", CountrySource: coldstart.CountrySignalingOnly, Addr: "198.51.100.9:20000"},
	})

	var found bool
	for _, h := range dir.hops {
		if h.id == split {
			found = true
		}
	}
	if !found {
		t.Error("a contradicted exit vanished from the hop pool — the flag is about terminating a path, not about relaying one")
	}
	if !dir.dialable["198.51.100.9:20000"] {
		t.Error("a contradicted exit's address left the forwarding allow-list — it is still a node in the signed directory")
	}
}

// TestChainExitNamesWhyTheCountryHadNoUsableExit: the diagnosis has to survive to the
// caller. "No exit in NL" against a directory that visibly lists an exit in NL is the
// kind of failure that gets chased in the wrong place; the real condition is both
// diagnosable and not the user's fault.
func TestChainExitNamesWhyTheCountryHadNoUsableExit(t *testing.T) {
	split := provenanceExitID(t)
	signed := signTestSnapshot(t, testSnapPriv(t), []coldstart.Entry{
		{Role: "exit", ID: split, Country: "NL", CountrySource: coldstart.CountrySignalingOnly, Addr: "198.51.100.9:20000"},
		// A second, usable exit elsewhere, so the directory itself loads.
		{Role: "exit", ID: provenanceExitID(t), Country: "DE", CountrySource: coldstart.CountryObserved, Addr: "198.51.100.8:20000"},
	})
	dir, err := loadRelayDirectory(signed, testSnapPub(t), "", time.Now())
	if err != nil {
		t.Fatalf("load directory: %v", err)
	}
	e := &Engine{}

	_, err = e.chooseChainExit(dir, "NL")
	if err == nil {
		t.Fatal("chooseChainExit picked a contradicted exit")
	}
	if !strings.Contains(err.Error(), "SIGNAL") {
		t.Errorf("error %q does not say why the country had no usable exit — a user must be able to tell 'no exits there' from 'exits there that cannot be trusted to be there'", err)
	}
}

// TestCountrySourceWireContract pins core's copy of the provenance literals against the
// values the coordinator stamps. cmd/coordinator holds an identical unexported set
// because that binary deliberately does not import core, and its own test of the same
// name pins the other side — the same arrangement TestQuotaStateWireContract uses for
// the quota literals (#97). Two copies of one wire vocabulary need a pin on each side or
// they drift silently, and a drifted provenance value reads as "unrecognized, therefore
// not contradicted", which fails OPEN.
func TestCountrySourceWireContract(t *testing.T) {
	if coldstart.CountryObserved != "observed" ||
		coldstart.CountryHinted != "hint" ||
		coldstart.CountrySignalingOnly != "observed-signaling-only" ||
		coldstart.CountryNoEndpoint != "unverifiable-no-endpoint" ||
		coldstart.CountryAdminOverride != "admin-override" {
		t.Fatalf("country provenance literals drifted: %q %q %q %q %q",
			coldstart.CountryObserved, coldstart.CountryHinted,
			coldstart.CountrySignalingOnly, coldstart.CountryNoEndpoint,
			coldstart.CountryAdminOverride)
	}
	// And the predicate the client fails closed on must fire for exactly one of them.
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{coldstart.CountryObserved, false},
		{coldstart.CountryHinted, false},
		{coldstart.CountrySignalingOnly, true},
		{coldstart.CountryNoEndpoint, false},
		// An admin correction is not a discovered disagreement: a coordinator operator
		// asserted this country, which is the opposite of two observations failing to
		// agree (issue #113).
		{coldstart.CountryAdminOverride, false},
		{"", false},
	} {
		if got := (coldstart.Entry{Country: "NL", CountrySource: tc.source}).CountryContradicted(); got != tc.want {
			t.Errorf("CountryContradicted() for source %q = %v, want %v", tc.source, got, tc.want)
		}
	}
}
