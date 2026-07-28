package asn

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func loadFixture(t *testing.T) *Table {
	t.Helper()
	tab, err := Load("testdata/table.tsv")
	if err != nil {
		t.Fatalf("Load(testdata/table.tsv): %v", err)
	}
	return tab
}

func TestLoadFixture(t *testing.T) {
	tab := loadFixture(t)
	v4, v6 := tab.Len()
	if v4 != 7 || v6 != 3 {
		t.Errorf("Len() = (%d, %d), want (7, 3)", v4, v6)
	}
	if tab.Rows != 10 {
		t.Errorf("Rows = %d, want 10", tab.Rows)
	}
}

func TestLookupResolves(t *testing.T) {
	tab := loadFixture(t)
	for _, tc := range []struct {
		ip   string
		want AS
	}{
		{"192.0.2.1", 64496},
		{"192.0.2.63", 64496}, // last address of the /26
		{"192.0.2.64", 64497}, // first address of the next /26 — the boundary
		{"192.0.2.127", 64497},
		{"192.0.2.130", 64498},
		{"198.51.100.5", 64496}, // same AS as 192.0.2.x, a different /24
		{"198.51.100.65", 64499},
		{"203.0.113.1", 64500},
		{"203.0.113.65", 64501},
		{"2001:db8::1", 64502},
		{"2001:db8:1::1", 64503},
		{"2001:db8:2::1", 64502},
	} {
		got, ok := tab.LookupAS(netip.MustParseAddr(tc.ip))
		if !ok || got != tc.want {
			t.Errorf("LookupAS(%s) = (%v, %v), want (%v, true)", tc.ip, got, ok, tc.want)
		}
	}
}

// TestOneASSpansTwoRanges is the shape the whole control exists to catch: two
// addresses that share no visible label, in different /24s, announced by ONE AS. If
// this ever stops holding the fixture has lost the only case that proves a diversity
// check can reject anything.
func TestOneASSpansTwoRanges(t *testing.T) {
	tab := loadFixture(t)
	a, aok := tab.LookupAS(netip.MustParseAddr("192.0.2.1"))
	b, bok := tab.LookupAS(netip.MustParseAddr("198.51.100.1"))
	if !aok || !bok {
		t.Fatalf("both addresses must resolve: got (%v,%v) and (%v,%v)", a, aok, b, bok)
	}
	if a != b {
		t.Fatalf("192.0.2.1 -> %v and 198.51.100.1 -> %v; the fixture must keep ONE AS spanning two ranges", a, b)
	}
}

func TestLookupUnknown(t *testing.T) {
	tab := loadFixture(t)
	for _, tc := range []struct {
		ip, why string
	}{
		// Global unicast as far as the stdlib is concerned, and simply absent from
		// the table — the "routable address this table does not cover" case. It is
		// reached with a documentation address on purpose: a real routable address
		// would be the one thing this repo must not carry.
		{"192.0.2.200", "in a covered /24 but in a gap the table does not span"},
		{"198.51.100.200", "gap"},
		{"203.0.113.200", "gap"},
		{"2001:db8:ffff::1", "v6 gap"},
		{"127.0.0.1", "loopback — the ordinary local-stack case"},
		{"10.1.2.3", "RFC1918"},
		{"192.168.1.1", "RFC1918"},
		{"172.16.0.1", "RFC1918"},
		{"169.254.1.1", "link-local"},
		{"224.0.0.1", "multicast"},
		{"::1", "v6 loopback"},
		{"fe80::1", "v6 link-local"},
	} {
		if got, ok := tab.LookupAS(netip.MustParseAddr(tc.ip)); ok {
			t.Errorf("LookupAS(%s) = (%v, true), want unknown (%s)", tc.ip, got, tc.why)
		}
	}
}

// TestLookupUnmapsV4MappedV6 covers the silent whole-family failure: a dual-stack
// UDP socket hands back ::ffff:a.b.c.d for a v4 peer, which resolves against the v6
// table (and finds nothing) unless it is unmapped first.
func TestLookupUnmapsV4MappedV6(t *testing.T) {
	tab := loadFixture(t)
	got, ok := tab.LookupAS(netip.MustParseAddr("::ffff:192.0.2.1"))
	if !ok || got != 64496 {
		t.Errorf("LookupAS(::ffff:192.0.2.1) = (%v, %v), want (AS64496, true)", got, ok)
	}
}

// TestNilTableResolvesNothing is the "no table staged" state the client ships in
// (ADR-0044). It must be a lookup that answers unknown, not a crash.
func TestNilTableResolvesNothing(t *testing.T) {
	var tab *Table
	if got, ok := tab.LookupAS(netip.MustParseAddr("192.0.2.1")); ok {
		t.Errorf("nil table LookupAS = (%v, true), want unknown", got)
	}
	if v4, v6 := tab.Len(); v4 != 0 || v6 != 0 {
		t.Errorf("nil table Len() = (%d, %d), want (0, 0)", v4, v6)
	}
	// And through the seam, which is how both consumers hold it.
	var l Lookup = tab
	if _, ok := l.LookupAS(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("nil *Table through the Lookup interface must resolve nothing")
	}
}

func TestLookupInvalidAddr(t *testing.T) {
	tab := loadFixture(t)
	if _, ok := tab.LookupAS(netip.Addr{}); ok {
		t.Error("the zero netip.Addr must resolve to unknown")
	}
}

func TestReadRejects(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"overlap: nested more-specific", "192.0.2.0/24\t64496\n192.0.2.0/26\t64497\n", "overlap"},
		{"overlap: duplicate prefix", "192.0.2.0/26\t64496\n192.0.2.0/26\t64497\n", "overlap"},
		{"overlap: v6 nested", "2001:db8::/32\t64496\n2001:db8:1::/48\t64497\n", "overlap"},
		{"AS0 is reserved", "192.0.2.0/26\t0\n", "RFC 7607"},
		{"host bits set", "192.0.2.1/26\t64496\n", "host bits"},
		{"one field", "192.0.2.0/26\n", "want `prefix"},
		{"three fields", "192.0.2.0/26\t64496\textra\n", "want `prefix"},
		{"bad prefix", "not-a-prefix\t64496\n", "prefix"},
		{"bad asn", "192.0.2.0/26\tnotanumber\n", "asn"},
		{"asn out of range", "192.0.2.0/26\t4294967296\n", "asn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(tc.in))
			if err == nil {
				t.Fatalf("Read(%q) succeeded, want an error mentioning %q", tc.in, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Read(%q) error = %v, want it to mention %q", tc.in, err, tc.want)
			}
		})
	}
}

// TestReadRejectsEmpty pins the distinct-error decision: a table that parses to zero
// rows is an operator mistake, not a table that resolves nothing.
func TestReadRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "# only a comment\n", "\n\n   \n", "# c\n\n# c2\n"} {
		_, err := Read(strings.NewReader(in))
		if !errors.Is(err, ErrEmpty) {
			t.Errorf("Read(%q) error = %v, want ErrEmpty", in, err)
		}
	}
}

// TestReadAcceptsAdjacentNotOverlapping guards the disjointness check against being
// so strict it rejects a legitimate table: prefixes that merely touch are fine.
func TestReadAcceptsAdjacentNotOverlapping(t *testing.T) {
	tab, err := Read(strings.NewReader("192.0.2.0/26\t64496\n192.0.2.64/26\t64497\n"))
	if err != nil {
		t.Fatalf("adjacent, non-overlapping prefixes must load: %v", err)
	}
	if got, ok := tab.LookupAS(netip.MustParseAddr("192.0.2.64")); !ok || got != 64497 {
		t.Errorf("LookupAS(192.0.2.64) = (%v, %v), want (AS64497, true)", got, ok)
	}
}

// TestReadSortsUnsortedInput: the file is not required to be in order, so an
// operator concatenating two staged fragments does not get a table that silently
// resolves wrongly. Disjointness is checked after the sort, not before.
func TestReadSortsUnsortedInput(t *testing.T) {
	tab, err := Read(strings.NewReader("203.0.113.0/26\t64500\n192.0.2.0/26\t64496\n198.51.100.0/26\t64499\n"))
	if err != nil {
		t.Fatalf("unsorted input must load: %v", err)
	}
	for ip, want := range map[string]AS{"192.0.2.1": 64496, "198.51.100.1": 64499, "203.0.113.1": 64500} {
		if got, ok := tab.LookupAS(netip.MustParseAddr(ip)); !ok || got != want {
			t.Errorf("LookupAS(%s) = (%v, %v), want (%v, true)", ip, got, ok, want)
		}
	}
}

func TestReadIgnoresCommentsAndBlanks(t *testing.T) {
	in := "# leading comment\n\n192.0.2.0/26\t64496   # trailing comment\n\n  \n192.0.2.64/26\t64497\n"
	tab, err := Read(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if tab.Rows != 2 {
		t.Errorf("Rows = %d, want 2", tab.Rows)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("testdata/does-not-exist.tsv"); err == nil {
		t.Fatal("Load of a missing file must fail")
	}
}

func TestASString(t *testing.T) {
	if got := AS(64496).String(); got != "AS64496" {
		t.Errorf("AS(64496).String() = %q, want %q", got, "AS64496")
	}
	// The "AS" prefix keeps a resolved key out of the fallback key namespace —
	// cmd/coordinator's observedAS falls back to a masked prefix, and the two must
	// never be mistakable for one another.
	if strings.Contains(AS(64496).String(), "/") {
		t.Error("an AS key must not look like a CIDR fallback key")
	}
}

func TestOfHostPort(t *testing.T) {
	tab := loadFixture(t)
	for _, tc := range []struct {
		in   string
		want AS
		ok   bool
	}{
		{"192.0.2.1:9000", 64496, true},
		{"192.0.2.1", 64496, true}, // bare address, no port
		{"[2001:db8::1]:9000", 64502, true},
		{"2001:db8::1", 64502, true},
		{"192.0.2.200:9000", 0, false}, // a gap
		{"relay.example:9000", 0, false},
		{"example", 0, false},
		{"", 0, false},
	} {
		got, ok := OfHostPort(tab, tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("OfHostPort(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := OfHostPort(nil, "192.0.2.1:9000"); ok {
		t.Error("OfHostPort against a nil Lookup must resolve nothing")
	}
}

// TestOfHostPortDoesNotResolveNames pins the deliberate refusal: a name would need a
// DNS call from inside chain selection, leaking the directory to a resolver and
// taking an attacker-influenced answer for the very node under scrutiny.
func TestOfHostPortDoesNotResolveNames(t *testing.T) {
	tab := loadFixture(t)
	for _, name := range []string{"localhost:9000", "localhost", "example.invalid:443"} {
		if got, ok := OfHostPort(tab, name); ok {
			t.Errorf("OfHostPort(%q) = (%v, true), want unknown — names must not be resolved", name, got)
		}
	}
}

func TestOfAddr(t *testing.T) {
	tab := loadFixture(t)
	if got, ok := OfAddr(tab, net.ParseIP("192.0.2.1")); !ok || got != 64496 {
		t.Errorf("OfAddr(192.0.2.1) = (%v, %v), want (AS64496, true)", got, ok)
	}
	if got, ok := OfAddr(tab, net.ParseIP("2001:db8::1")); !ok || got != 64502 {
		t.Errorf("OfAddr(2001:db8::1) = (%v, %v), want (AS64502, true)", got, ok)
	}
	if _, ok := OfAddr(tab, net.ParseIP("192.0.2.200")); ok {
		t.Error("OfAddr on a gap must resolve nothing")
	}
	if _, ok := OfAddr(tab, nil); ok {
		t.Error("OfAddr(nil IP) must resolve nothing")
	}
	if _, ok := OfAddr(nil, net.ParseIP("192.0.2.1")); ok {
		t.Error("OfAddr against a nil Lookup must resolve nothing")
	}
}
