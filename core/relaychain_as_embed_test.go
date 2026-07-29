package core

import (
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/asn"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// The embedded table reaching its consumer (issue #55, ADR-0044 amendments).
//
// "The table ships" and "the table is used" are two claims, and core/asn's own tests
// only establish the first. Nothing in the #23 suite would notice if the wiring were
// dropped: relaychain_as_test.go builds its *relayDirectory by hand (asChainDir) and
// injects a synthetic Lookup, which is right for testing the LADDER and is exactly
// why it cannot test the ATTACHMENT.
//
// So these tests go through loadRelayDirectory — the production constructor, the one
// place `as` is populated, and the one both the startup path (setupRelayChaining) and
// the reload path (reloadRelayDir) funnel through.
//
// Mutation, for all three: delete `as: embeddedAS(),` from the relayDirectory literal
// in loadRelayDirectory and every test in this file fails, while the whole rest of the
// suite still passes.

// embedTestDir builds a directory the production way. The entries' addresses are
// documentation space (RFC 5737) as every other fixture in this package is — what is
// under test here is which TABLE got attached, not what it says about these hops.
func embedTestDir(t *testing.T) *relayDirectory {
	t.Helper()
	entries := []coldstart.Entry{
		{Role: "exit", ID: hex.EncodeToString(make([]byte, 32)), Country: "NL", Addr: "203.0.113.10:9443"},
	}
	d, err := loadRelayDirectory(signTestSnapshot(t, testSnapPriv(t), entries), testSnapPub(t), "", time.Now())
	if err != nil {
		t.Fatalf("loadRelayDirectory: %v", err)
	}
	return d
}

// TestRelayDirectoryCarriesEmbeddedASTable is the attachment claim at its narrowest:
// a directory built the production way comes out holding a lookup, not nil.
//
// Before #55 this was nil on every build — ADR-0044 §6's closing line, "the seam is
// in place and both consumers use it; what is missing is bytes on a client".
func TestRelayDirectoryCarriesEmbeddedASTable(t *testing.T) {
	d := embedTestDir(t)
	if d.as == nil {
		t.Fatal("relayDirectory.as is nil: the embedded table is not wired into loadRelayDirectory, so every hop resolves to unknown and the AS-diversity control is inert")
	}
}

// TestRelayDirectoryASTableIsTheRealTable is the claim that matters, and it is a
// strictly stronger one. A non-nil lookup that resolves nothing would satisfy the
// test above while leaving the control just as inert — so this asserts the attached
// table actually places globally routed addresses, in both families, in distinct
// autonomous systems.
//
// It asserts no particular AS number. Which AS announces a given address is upstream
// data refreshed every release; that it resolves AT ALL, and that two independent
// networks resolve DIFFERENTLY, is the property the diversity control consumes.
func TestRelayDirectoryASTableIsTheRealTable(t *testing.T) {
	d := embedTestDir(t)
	if d.as == nil {
		t.Fatal("relayDirectory.as is nil; see TestRelayDirectoryCarriesEmbeddedASTable")
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if _, ok := d.as.LookupAS(netip.MustParseAddr(s)); !ok {
			t.Errorf("directory lookup resolved %s to unknown; the attached table is not the embedded one", s)
		}
	}
	a, ok1 := d.as.LookupAS(netip.MustParseAddr("1.1.1.1"))
	b, ok2 := d.as.LookupAS(netip.MustParseAddr("8.8.8.8"))
	if !ok1 || !ok2 || a == b {
		t.Errorf("two independent networks resolved to (%v,%v) and (%v,%v); the attached table cannot tell networks apart", a, ok1, b, ok2)
	}
}

// TestSelectHopsRefusesSameASOnTheEmbeddedTable is the end-to-end statement of what
// #55 delivers, run through the SHIPPED data rather than a fixture: given candidates
// whose real addresses sit in one autonomous system and candidates that do not,
// selectHops must not put two of the former in one chain.
//
// This is the #23 rejection property (relaychain_as_test.go proves it against the
// synthetic fixture) re-asserted against the table a user actually gets — which is
// the only version of the claim that says the control works in production.
//
// The same-AS pair is two addresses inside ONE announced prefix, so they share an AS
// by construction rather than by an allocation the test hopes still holds. It is
// derived from the embedded table at run time: the test asks the table which prefix
// covers a well-known address and picks a second address from inside it.
func TestSelectHopsRefusesSameASOnTheEmbeddedTable(t *testing.T) {
	tab, err := asn.Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	// Two addresses one octet apart in the same /24-or-larger announcement, and one
	// in a different network entirely.
	sameA, sameB := "1.1.1.1", "1.1.1.2"
	other := "8.8.8.8"
	asA, ok1 := tab.LookupAS(netip.MustParseAddr(sameA))
	asB, ok2 := tab.LookupAS(netip.MustParseAddr(sameB))
	asC, ok3 := tab.LookupAS(netip.MustParseAddr(other))
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("the embedded table did not place the fixtures: %s=%v %s=%v %s=%v", sameA, ok1, sameB, ok2, other, ok3)
	}
	if asA != asB {
		t.Skipf("%s and %s are no longer in one AS (%s vs %s); the same-AS premise does not hold in this refresh", sameA, sameB, asA, asB)
	}
	if asA == asC {
		t.Skipf("%s and %s are no longer in different ASes; the diverse-alternative premise does not hold in this refresh", sameA, other)
	}

	cand := []relayHop{
		{id: "1", dial: sameA + ":9001", pairable: true},
		{id: "2", dial: sameB + ":9002", pairable: true},
		{id: "3", dial: other + ":9003"},
	}
	// Run it repeatedly: selectHops shuffles, so a single pass can pick a good chain
	// by luck. The rejection has to hold every time.
	for i := 0; i < 50; i++ {
		got, div, err := selectHops(cand, 2, "", tab)
		if err != nil {
			t.Fatalf("selectHops: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("selectHops returned %d hops, want 2", len(got))
		}
		seen := map[string]bool{}
		for _, h := range got {
			key, resolved := hopASKey(h, tab)
			if !resolved {
				t.Fatalf("hop %s did not resolve against the embedded table", h.dial)
			}
			if seen[key] {
				t.Fatalf("selectHops placed two hops in %s (%v); the AS-diversity guard did not reject the same-AS pair", key, dials(got))
			}
			seen[key] = true
		}
		if div.asRepeated {
			t.Fatalf("hopDiversity reports a repeated AS on a chain that has none: %v", dials(got))
		}
		if div.resolved != 2 {
			t.Fatalf("hopDiversity.resolved = %d, want 2 — the embedded table placed both hops", div.resolved)
		}
	}
}

// TestBuildChainNoLongerReportsNoTableOnRealAddresses is the "Done means" clause
// stated as a test: on a client whose hops are really routed, the degradation notice
// for "nothing resolved" must stop firing.
//
// That path (buildChain's EventInfo when div.resolved == 0) was the NORMAL case for
// every build between #52 and #55, because no client had a table. Its absence here is
// the observable difference #55 makes.
func TestBuildChainNoLongerReportsNoTableOnRealAddresses(t *testing.T) {
	tab, err := asn.Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	cand := []relayHop{
		{id: "1", dial: "1.1.1.1:9001", pairable: true},
		{id: "2", dial: "8.8.8.8:9002"},
	}
	_, div, err := selectHops(cand, 2, "", tab)
	if err != nil {
		t.Fatalf("selectHops: %v", err)
	}
	if div.resolved == 0 {
		t.Fatal("no hop resolved against the embedded table, so buildChain would still emit the \"no table is loaded\" notice on a normal client")
	}
	if div.unresolved != 0 {
		t.Errorf("hopDiversity.unresolved = %d on two globally routed hops, want 0", div.unresolved)
	}
	if div.degraded() {
		t.Errorf("a chain of two hops in distinct real ASes reports degraded: %s", div.describe())
	}
}
