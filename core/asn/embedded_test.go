package asn

import (
	"net/netip"
	"testing"
	"time"
)

// The embedded table (issue #55) is deliberately tested THINLY.
//
// ADR-0044's amendment says why: committing the real table is the product, pointing
// the tests at it is not. Every behavioural test for parsing, disjointness, pooling
// and the diversity ladder runs against the synthetic fixture in testdata, where a
// failure names four rows a reader can check by eye. A 700,000-row table in that
// path would make the same failures unreadable.
//
// So what is checked here is only what the fixture CANNOT check: that the bytes
// committed to this repository are real, loadable, and behave like a routing table.
// Nothing here asserts a specific AS for a specific address — that would pin the
// test to an allocation upstream is free to change, and would fail on a refresh that
// was entirely correct.

// TestEmbeddedTableLoads is the build-fault detector. The embedded bytes cannot
// change between build and run, so a table that does not load is a committed-file
// fault, and this is the thing that catches it before a release carries it — see
// core/relaychain.go's embeddedAS, which degrades rather than refusing at runtime
// precisely because this test is what fails instead.
func TestEmbeddedTableLoads(t *testing.T) {
	tab, err := Embedded()
	if err != nil {
		t.Fatalf("the committed table did not load: %v", err)
	}
	v4, v6 := tab.Len()
	if v4+v6 != tab.Rows {
		t.Errorf("rows %d != v4 %d + v6 %d", tab.Rows, v4, v6)
	}
	// Floors, not exact counts: the table is refreshed per release and the numbers
	// move every time. These are low enough that only a truncated, stubbed or
	// wrong-family table trips them, and Load has already enforced the properties
	// that actually matter (disjoint, sorted, no AS0).
	if v4 < 100_000 {
		t.Errorf("IPv4 spans = %d, far below a real routing table; is the committed table truncated?", v4)
	}
	if v6 < 10_000 {
		t.Errorf("IPv6 spans = %d, far below a real routing table; was it staged with -family v4?", v6)
	}
}

// TestEmbeddedTableResolvesGlobalAddresses proves the committed bytes are a routing
// table and not merely a well-formed file: they place addresses that are globally
// routed, they place both families, and they place two of them in DIFFERENT
// autonomous systems — which is the only property the diversity control consumes.
//
// The addresses are long-lived public anycast resolvers, chosen because their
// allocations are about as stable as the routing system offers. The assertions are
// still only "resolved" and "distinct", never a particular AS number, so a refresh
// that renumbers one of them keeps passing.
func TestEmbeddedTableResolvesGlobalAddresses(t *testing.T) {
	tab, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	for _, s := range []string{
		"1.1.1.1", "8.8.8.8",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
		"::ffff:8.8.8.8", // a v4-mapped v6, what a dual-stack socket hands back
	} {
		if _, ok := tab.LookupAS(netip.MustParseAddr(s)); !ok {
			t.Errorf("LookupAS(%s) = unknown, want a resolved AS", s)
		}
	}

	a, ok1 := tab.LookupAS(netip.MustParseAddr("1.1.1.1"))
	b, ok2 := tab.LookupAS(netip.MustParseAddr("8.8.8.8"))
	if ok1 && ok2 && a == b {
		t.Errorf("two independently operated networks both resolved to %s; the table cannot distinguish anything", a)
	}
}

// TestEmbeddedTableReturnsUnknownForUnroutableSpace is the other half, and it is the
// one the staging transform can actually get wrong.
//
// asn-stage drops the upstream's `AS0 / Not routed` markers so unrouted space becomes
// a GAP. If it merged across a gap instead, an address nobody announces would inherit
// a neighbour's AS — the exact failure ADR-0044 §6 named — and it would show up here,
// because documentation and private space is unrouted by construction.
func TestEmbeddedTableReturnsUnknownForUnroutableSpace(t *testing.T) {
	tab, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	for _, s := range []string{
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // RFC 5737 documentation
		"2001:db8::1",                           // RFC 3849 documentation
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC 1918
		"127.0.0.1", "::1", // loopback
		"169.254.1.1", // link-local
		"224.0.0.1",   // multicast
	} {
		if as, ok := tab.LookupAS(netip.MustParseAddr(s)); ok {
			t.Errorf("LookupAS(%s) = %s, want unknown — no AS announces this space", s, as)
		}
	}
}

// tableMaxAge is how stale the committed table may get before CI says so.
//
// 90 days, which is both core/geoip's staleness threshold and the quarterly cadence
// ADR-0044 §6 measured: at ~1.3% drift per month the error is near 3.6% at this point,
// which §6 treats as the acceptable operating range for an embedded table. A project
// shipping quarterly never sees this fire; one that has not shipped in a quarter is
// exactly the case where somebody should be told.
const tableMaxAge = 90 * 24 * time.Hour

// TestEmbeddedTableIsFresh is the forcing function behind "refreshed per release".
//
// Before this existed the refresh was written down in two places and enforced by
// neither, which made it folklore: nothing in the repository could even tell you the
// table was old, because the retrieval date lived only in TABLE.md prose and the gzip
// header's mtime is deliberately zeroed for determinism.
//
// It FAILS rather than logs. A t.Log on a passing test is invisible without -v, so a
// warning here would be indistinguishable from no check at all. The cost of failing is
// real and worth naming: once the table goes stale this blocks unrelated work until
// somebody refreshes it. That is the intended pressure — the threshold is generous
// enough that hitting it means the table genuinely is out of the range ADR-0044
// costed, and the message says exactly what to run.
func TestEmbeddedTableIsFresh(t *testing.T) {
	retrieved, err := time.Parse(time.DateOnly, TableRetrieved)
	if err != nil {
		t.Fatalf("TableRetrieved = %q, which is not a YYYY-MM-DD date: %v", TableRetrieved, err)
	}
	if retrieved.After(time.Now()) {
		t.Fatalf("TableRetrieved = %s is in the future; was it typed rather than taken from the refresh?", TableRetrieved)
	}
	if age := time.Since(retrieved); age > tableMaxAge {
		t.Errorf(`the committed IP→AS table was retrieved %s, %d days ago (limit %d).

At ~1.3%% drift per month it is now roughly %.1f%% wrong, which is outside the range
ADR-0044 costed for an embedded table. Refresh it:

    curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
    go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip

then set TableRetrieved in core/asn/embedded.go to today and update the hashes and row
counts in core/asn/TABLE.md.`,
			TableRetrieved, int(age.Hours()/24), int(tableMaxAge.Hours()/24),
			1.3*age.Hours()/24/30)
	}
}

// TestEmbeddedIsParsedOnce pins the sync.OnceValues contract, which is load-bearing
// rather than decorative: core/relaychain.go's directory RELOADS on an interval
// (reloadRelayDirLoop), and every reload asks for this table. Were it parsed per
// call, a long-running client would spend ~190 ms and ~28 MB again on every reload,
// forever, for a result that cannot have changed.
func TestEmbeddedIsParsedOnce(t *testing.T) {
	a, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	b, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded (second call): %v", err)
	}
	if a != b {
		t.Error("Embedded returned a different *Table on the second call; it is re-parsing the whole table per caller")
	}
}
