package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/asn"
)

// Coordinator-side AS resolution (issue #23, ADR-0044).
//
// Every address here is documentation space (RFC 5737 / RFC 3849) and every AS is a
// documentation AS (RFC 5398). Nothing describes a real allocation.

const asnTestTable = "" +
	"192.0.2.0/26\t64496\n" +
	"198.51.100.0/26\t64496\n" + // ONE AS, a different /24 — the Sybil shape
	"203.0.113.0/26\t64500\n" +
	"2001:db8::/48\t64502\n"

func asnTestLookup(t *testing.T) asn.Lookup {
	t.Helper()
	tab, err := asn.Read(strings.NewReader(asnTestTable))
	if err != nil {
		t.Fatalf("building the test table: %v", err)
	}
	return tab
}

func udp(ip string) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 9000} }

// TestObservedASResolvesThroughTheTable is what ADR-0041 line 173 asked for: the AS
// the ~4:1 bound is denominated in is a real AS, not a routing-prefix proxy.
func TestObservedASResolvesThroughTheTable(t *testing.T) {
	l := asnTestLookup(t)
	for _, tc := range []struct{ ip, want string }{
		{"192.0.2.1", "AS64496"},
		{"192.0.2.60", "AS64496"},
		{"198.51.100.1", "AS64496"}, // a different /24, and the SAME AS
		{"203.0.113.1", "AS64500"},
		{"2001:db8::1", "AS64502"},
	} {
		if got := observedAS(udp(tc.ip), l); got != tc.want {
			t.Errorf("observedAS(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

// TestObservedASCollapsesOneASAcrossTwoPrefixes is the correctness point the prefix
// mask cannot reach, and the reason the trusted stream needed a real table: the
// estimator counts DISTINCT AS values to decide whether a node has been attested
// widely enough to rise past the ceiling, so one AS announcing two /24s must count
// ONCE. Under the mask it counts twice, which makes the ceiling cheaper to reach
// than the AS bound intends.
func TestObservedASCollapsesOneASAcrossTwoPrefixes(t *testing.T) {
	l := asnTestLookup(t)
	a := observedAS(udp("192.0.2.1"), l)
	b := observedAS(udp("198.51.100.1"), l)
	if a != b {
		t.Fatalf("observedAS gave %q and %q for two prefixes of one AS; they must collapse to one vote", a, b)
	}
	// And the mask, which is what this replaces, does NOT collapse them — stated as a
	// test so the improvement is a fact rather than a claim in a comment.
	if asFallback(net.ParseIP("192.0.2.1")) == asFallback(net.ParseIP("198.51.100.1")) {
		t.Fatal("the prefix-mask fallback collapsed two /24s; the fixture no longer demonstrates what the table buys")
	}
}

// TestObservedASFallsBackToThePrefixMask pins that the pre-#23 behaviour is intact
// wherever the table cannot answer — including with no table at all, which is what a
// coordinator started without -asn-table runs.
func TestObservedASFallsBackToThePrefixMask(t *testing.T) {
	l := asnTestLookup(t)
	for _, tc := range []struct {
		name   string
		lookup asn.Lookup
		ip     string
		want   string
	}{
		{"no table configured at all", nil, "192.0.2.1", "192.0.2.0/24"},
		{"a nil *asn.Table through the interface", (*asn.Table)(nil), "192.0.2.1", "192.0.2.0/24"},
		{"staged table, address not in it", l, "192.0.2.200", "192.0.2.0/24"},
		{"staged table, loopback (every node in a local stack)", l, "127.0.0.1", "127.0.0.0/24"},
		{"staged table, RFC1918", l, "10.1.2.3", "10.1.2.0/24"},
		{"staged table, v6 not in it", l, "2001:db8:ffff::1", "2001:db8:ffff::/48"},
		{"no table, v6", nil, "2001:db8::1", "2001:db8::/48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := observedAS(udp(tc.ip), tc.lookup); got != tc.want {
				t.Errorf("observedAS(%s) = %q, want the masked fallback %q", tc.ip, got, tc.want)
			}
		})
	}
}

// TestObservedASNeverEmptyForAUsableAddress guards a live failure mode: an empty AS
// makes handleCapacityReport DROP the sample, so a fallback that returned "" instead
// of a masked prefix would silently switch the capacity feed off on every developer
// box and in the smoke stack, where every node registers from loopback.
func TestObservedASNeverEmptyForAUsableAddress(t *testing.T) {
	l := asnTestLookup(t)
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.0.2.200", "::1", "2001:db8:ffff::1"} {
		if got := observedAS(udp(ip), l); got == "" {
			t.Errorf("observedAS(%s) = \"\" — the sample would be dropped as unattributable", ip)
		}
	}
}

func TestObservedASEmptyWithoutASourceAddress(t *testing.T) {
	l := asnTestLookup(t)
	if got := observedAS(nil, l); got != "" {
		t.Errorf("observedAS(nil) = %q, want \"\"", got)
	}
	if got := observedAS(&net.UDPAddr{}, l); got != "" {
		t.Errorf("observedAS(no IP) = %q, want \"\"", got)
	}
}

// TestASKeySpacesAreDisjoint: a resolved answer and a fallback answer share one field
// (capacity.Sample.AS) and one distinct-value count, so they must never be mistakable
// for one another by a consumer that only sees the string.
func TestASKeySpacesAreDisjoint(t *testing.T) {
	l := asnTestLookup(t)
	resolved := observedAS(udp("192.0.2.1"), l)
	fallback := observedAS(udp("127.0.0.1"), l)
	if !strings.HasPrefix(resolved, "AS") || strings.Contains(resolved, "/") {
		t.Errorf("resolved key %q does not look like an AS", resolved)
	}
	if !strings.Contains(fallback, "/") || strings.HasPrefix(fallback, "AS") {
		t.Errorf("fallback key %q does not look like a prefix", fallback)
	}
	if resolved == fallback {
		t.Error("a resolved AS and a masked prefix produced the same key")
	}
}

// ---------- staging ----------

func withASNTable(t *testing.T, tab *asn.Table) {
	t.Helper()
	prev := asnTable
	asnTable = tab
	t.Cleanup(func() { asnTable = prev })
}

func TestSetupASNTable(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "table.tsv")
	if err := os.WriteFile(good, []byte(asnTestTable), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "overlapping.tsv")
	if err := os.WriteFile(bad, []byte("192.0.2.0/24\t64496\n192.0.2.0/26\t64497\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("no path leaves the coordinator with no table", func(t *testing.T) {
		withASNTable(t, nil)
		if err := setupASNTable(""); err != nil {
			t.Fatalf("setupASNTable(\"\") = %v, want nil — no table is a choice, not an error", err)
		}
		if asnTable != nil {
			t.Error("an empty path staged a table")
		}
		// And the fallback is what runs.
		if got := observedAS(udp("192.0.2.1"), asnTable); got != "192.0.2.0/24" {
			t.Errorf("observedAS = %q, want the masked fallback", got)
		}
	})

	t.Run("a good path loads", func(t *testing.T) {
		withASNTable(t, nil)
		if err := setupASNTable(good); err != nil {
			t.Fatalf("setupASNTable(%s) = %v", good, err)
		}
		if asnTable == nil {
			t.Fatal("a valid table did not load")
		}
		if got := observedAS(udp("192.0.2.1"), asnTable); got != "AS64496" {
			t.Errorf("observedAS = %q, want AS64496", got)
		}
	})

	// A configured-but-unusable table must be FATAL, not a warning. An operator who
	// passed -asn-table believes AS resolution is running; starting anyway would hand
	// them the prefix-mask fallback under its name, silently — the exact failure this
	// card exists to remove.
	t.Run("a bad path is an error, not a silent fallback", func(t *testing.T) {
		withASNTable(t, nil)
		for _, path := range []string{bad, filepath.Join(dir, "absent.tsv")} {
			if err := setupASNTable(path); err == nil {
				t.Errorf("setupASNTable(%s) = nil, want an error", path)
			}
			if asnTable != nil {
				t.Errorf("setupASNTable(%s) staged a table despite failing", path)
			}
		}
	})
}
