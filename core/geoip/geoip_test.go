package geoip

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every address in this file is from a reserved documentation range (RFC 5737
// 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; RFC 3849 2001:db8::/32). The repo
// carries no real address, and a test fixture is not an exception to that.
//
// The fixture blocks are deliberately SUB-/24 (/26 pieces) rather than whole /24s.
// Whole /24s leave no room inside the reserved range for the "immediately below the
// lowest block" and "immediately above a block's last address" probes: those had to
// step one address outside the documentation /24s, into globally allocated space, under
// a comment asserting the opposite. Smaller blocks keep every boundary probe inside the
// reserved /24 with no coverage lost.

const locationsCSV = `geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
2750405,en,EU,Europe,NL,Netherlands,1
2921044,en,EU,Europe,DE,Germany,1
2017370,en,EU,Europe,RU,Russia,0
6255148,en,EU,Europe,,Europe,0
`

// blocksV4CSV is deliberately NOT in ascending network order — the loader must sort
// it — and row 4 exercises the blank-geoname_id fallback to the registered country.
const blocksV4CSV = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
203.0.113.0/26,2017370,2017370,,0,0
192.0.2.64/26,2750405,2750405,,0,0
2001:db8:dead::/48,2921044,2921044,,0,0
198.51.100.0/26,,2921044,,0,0
192.0.2.128/26,2921044,2921044,,0,0
`

const blocksV6CSV = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
2001:db8::/48,2750405,2750405,,0,0
2001:db8:1::/48,2017370,2017370,,0,0
`

// stage writes a database directory and returns its path.
func stage(t *testing.T, locations, v4, v6 string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if body == "" {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write(FileLocations, locations)
	write(FileBlocksV4, v4)
	write(FileBlocksV6, v6)
	return dir
}

func mustLoad(t *testing.T, locations, v4, v6 string) *DB {
	t.Helper()
	db, err := LoadDir(stage(t, locations, v4, v6))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	return db
}

// TestLookupResolvesAndRespectsBoundaries is the core contract: an address inside a
// block resolves to that block's country, both edges of the range included, and an
// address in the gap between blocks resolves to nothing. The boundary cases are the
// ones a binary-search bug shows up in first, and the "gap" case is what proves the
// search is not just returning its nearest neighbour.
func TestLookupResolvesAndRespectsBoundaries(t *testing.T) {
	db := mustLoad(t, locationsCSV, blocksV4CSV, blocksV6CSV)

	for _, tc := range []struct {
		ip   string
		want string
	}{
		{"192.0.2.64", "NL"},    // first address of 192.0.2.64/26
		{"192.0.2.100", "NL"},   // interior
		{"192.0.2.127", "NL"},   // last address of the /26
		{"192.0.2.128", "DE"},   // first address of the adjacent /26: must not bleed
		{"192.0.2.191", "DE"},   // last address of the second /26
		{"203.0.113.7", "RU"},   // a different, non-adjacent block
		{"198.51.100.9", "DE"},  // blank geoname_id -> registered_country fallback
		{"2001:db8::5", "NL"},   // v6 table
		{"2001:db8:1::5", "RU"}, // adjacent v6 block
		{"192.0.2.63", ""},      // immediately BELOW the lowest v4 block
		{"192.0.2.192", ""},     // immediately ABOVE the highest v4 block in that /24
		{"198.51.100.200", ""},  // in a gap between blocks
		{"203.0.113.64", ""},    // immediately ABOVE a block's last address
		{"2001:db8:2::1", ""},   // v6 gap
	} {
		got, ok := db.Lookup(netip.MustParseAddr(tc.ip))
		if tc.want == "" {
			if ok {
				t.Errorf("Lookup(%s) = %q, true; want unresolved", tc.ip, got)
			}
			continue
		}
		if !ok {
			t.Errorf("Lookup(%s) unresolved; want %q", tc.ip, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("Lookup(%s) = %q; want %q", tc.ip, got, tc.want)
		}
	}
}

// TestLookupUnmapsV4MappedV6 guards a silent whole-family failure. A dual-stack UDP
// socket hands back a v4 peer as ::ffff:a.b.c.d; if Lookup searched the v6 table for
// that, every IPv4 node would resolve to "unknown" and the coordinator would fall
// back to the self-reported hint for the entire fleet — old #136 defeated, with
// nothing failing visibly.
func TestLookupUnmapsV4MappedV6(t *testing.T) {
	db := mustLoad(t, locationsCSV, blocksV4CSV, blocksV6CSV)

	mapped := netip.MustParseAddr("::ffff:192.0.2.100")
	if mapped.Is4() {
		t.Fatal("fixture is not actually a v4-mapped v6 address, so this test proves nothing")
	}
	got, ok := db.Lookup(mapped)
	if !ok || got != "NL" {
		t.Fatalf("Lookup(%s) = %q, %v; want \"NL\", true", mapped, got, ok)
	}

	// LookupAddr takes the 16-byte net.IP form the UDP source address arrives in.
	if got, ok := db.LookupAddr(net.ParseIP("192.0.2.100")); !ok || got != "NL" {
		t.Fatalf("LookupAddr = %q, %v; want \"NL\", true", got, ok)
	}
}

// TestLookupSkipsNonRoutable pins the case the local smoke stack lives in: every
// node registers from loopback, so GeoIP must resolve nothing and let the caller
// fall back to the -country hint. A table that "resolved" 127.0.0.1 would tag the
// whole dev fleet with whatever country owns that range in the data.
func TestLookupSkipsNonRoutable(t *testing.T) {
	db := mustLoad(t, locationsCSV, blocksV4CSV, blocksV6CSV)

	for _, s := range []string{
		"127.0.0.1",   // loopback
		"::1",         // v6 loopback
		"10.0.0.7",    // RFC1918
		"192.168.1.1", // RFC1918
		"172.16.0.1",  // RFC1918
		"169.254.1.1", // link-local
		"fc00::1",     // v6 unique-local
		"0.0.0.0",     // unspecified
		"224.0.0.1",   // multicast
	} {
		if cc, ok := db.Lookup(netip.MustParseAddr(s)); ok {
			t.Errorf("Lookup(%s) = %q, true; want unresolved (non-routable)", s, cc)
		}
	}

	// A zero Addr and a nil DB are both "unresolved", not a panic: the coordinator
	// calls this on every register, including before a database is staged.
	if _, ok := db.Lookup(netip.Addr{}); ok {
		t.Error("Lookup(zero Addr) resolved")
	}
	var nilDB *DB
	if _, ok := nilDB.Lookup(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("nil DB resolved a lookup")
	}
	if v4, v6 := nilDB.Len(); v4 != 0 || v6 != 0 {
		t.Errorf("nil DB Len = %d, %d; want 0, 0", v4, v6)
	}
}

// TestLoadRejectsOverlappingPrefixes pins the disjointness invariant Lookup's
// single-probe search depends on. Without this check a corrupt or hand-edited table
// would resolve silently and wrongly for the overlapped range; the assumption is
// enforced at load instead.
func TestLoadRejectsOverlappingPrefixes(t *testing.T) {
	overlapping := `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
192.0.2.0/24,2750405,2750405,,0,0
192.0.2.128/25,2921044,2921044,,0,0
`
	_, err := LoadDir(stage(t, locationsCSV, overlapping, ""))
	if err == nil {
		t.Fatal("Load accepted an overlapping table; want an error")
	}
	if !strings.Contains(err.Error(), "overlapping") {
		t.Fatalf("error %q does not name the overlap", err)
	}
}

// TestLoadAddressesColumnsByName proves the parser is not index-positional. MaxMind
// has reordered and added columns before; a positional parser would keep loading and
// silently read the wrong field as the country, which is exactly the class of
// invisible corruption old #136 exists to remove.
func TestLoadAddressesColumnsByName(t *testing.T) {
	// Same data, columns shuffled and an extra one inserted first.
	shuffledLocations := `is_in_european_union,country_iso_code,geoname_id,locale_code,country_name
1,NL,2750405,en,Netherlands
`
	shuffledBlocks := `is_anonymous_proxy,registered_country_geoname_id,network,extra_new_column,geoname_id
0,2750405,192.0.2.0/24,whatever,2750405
`
	db, err := LoadDir(stage(t, shuffledLocations, shuffledBlocks, ""))
	if err != nil {
		t.Fatalf("LoadDir with reordered columns: %v", err)
	}
	if cc, ok := db.Lookup(netip.MustParseAddr("192.0.2.1")); !ok || cc != "NL" {
		t.Fatalf("Lookup = %q, %v; want \"NL\", true", cc, ok)
	}
}

// TestLoadRejectsMissingColumnAndEmptyTable: a database that cannot be understood
// must fail loudly at startup, not resolve everything to "unknown" and quietly
// degrade the whole fleet to self-reported countries.
func TestLoadRejectsMissingColumnAndEmptyTable(t *testing.T) {
	noNetwork := `geoname_id,registered_country_geoname_id
2750405,2750405
`
	if _, err := LoadDir(stage(t, locationsCSV, noNetwork, "")); err == nil {
		t.Error("Load accepted a blocks file with no network column")
	}

	// Well-formed header, but every row resolves to no country: an empty table.
	unknownOnly := `network,geoname_id,registered_country_geoname_id
192.0.2.0/24,6255148,6255148
`
	if _, err := LoadDir(stage(t, locationsCSV, unknownOnly, "")); err == nil {
		t.Error("Load accepted a database with zero usable blocks")
	}

	// A locations file with no usable country rows is equally unusable.
	if _, err := LoadDir(stage(t, "geoname_id,country_iso_code\n6255148,\n", blocksV4CSV, "")); err == nil {
		t.Error("Load accepted a locations file with no country codes")
	}
}

// TestLoadKeepsFamiliesSeparate: a v6 row sitting in the v4 blocks file (the fixture
// has one) must be skipped, not filed into the v4 table where it would corrupt the
// sort order the binary search relies on.
func TestLoadKeepsFamiliesSeparate(t *testing.T) {
	db := mustLoad(t, locationsCSV, blocksV4CSV, blocksV6CSV)

	v4, v6 := db.Len()
	// blocksV4CSV has 5 rows, one of which is v6 and must be dropped.
	if v4 != 4 {
		t.Errorf("v4 table has %d blocks; want 4 (the v6 row must be skipped)", v4)
	}
	if v6 != 2 {
		t.Errorf("v6 table has %d blocks; want 2", v6)
	}
	// The v6 row that was in the v4 file must not be resolvable from the v6 table
	// either — it was never loaded.
	if cc, ok := db.Lookup(netip.MustParseAddr("2001:db8:dead::1")); ok {
		t.Errorf("Lookup(2001:db8:dead::1) = %q; want unresolved (row was in the v4 file)", cc)
	}
}

// TestLoadDirToleratesMissingIPv6 but requires IPv4: a v4-only staging is a valid
// deployment, a directory with neither is a mistake.
func TestLoadDirToleratesMissingIPv6(t *testing.T) {
	db, err := LoadDir(stage(t, locationsCSV, blocksV4CSV, ""))
	if err != nil {
		t.Fatalf("LoadDir without an IPv6 file: %v", err)
	}
	if _, v6 := db.Len(); v6 != 0 {
		t.Errorf("v6 table is not empty (%d) with no v6 file staged", v6)
	}
	if _, ok := db.Lookup(netip.MustParseAddr("2001:db8::5")); ok {
		t.Error("resolved a v6 address with no v6 table")
	}

	if _, err := LoadDir(stage(t, locationsCSV, "", "")); err == nil {
		t.Error("LoadDir accepted a directory with no IPv4 blocks file")
	}
}

// TestStaleFlag: staleness is advisory — a stale database still loads, because
// refusing would take a coordinator down over data hygiene — but it must be
// reported, since a stale table mislabels countries without failing.
func TestStaleFlag(t *testing.T) {
	dir := stage(t, locationsCSV, blocksV4CSV, "")
	fresh, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if fresh.Stale {
		t.Error("a just-written database is reported stale")
	}
	if fresh.BuiltAt.IsZero() {
		t.Error("BuiltAt is zero for a file-backed load")
	}

	// Backdate every input past the threshold. StaleAfter is not recomputed here
	// from the constant under test — the offset is deliberately far beyond it.
	old := time.Now().Add(-2 * StaleAfter)
	for _, n := range []string{FileLocations, FileBlocksV4} {
		if err := os.Chtimes(filepath.Join(dir, n), old, old); err != nil {
			t.Fatalf("chtimes %s: %v", n, err)
		}
	}
	stale, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir (backdated): %v", err)
	}
	if !stale.Stale {
		t.Errorf("a database backdated to %s is not reported stale", old.Format(time.DateOnly))
	}
	// Still fully usable: staleness must not withhold resolution.
	if cc, ok := stale.Lookup(netip.MustParseAddr("192.0.2.100")); !ok || cc != "NL" {
		t.Errorf("stale database stopped resolving: %q, %v", cc, ok)
	}
}

// TestPrefixRangeCoversExactlyThePrefix pins the conversion the MaxMind loader depends
// on. Every row of a GeoLite2 staging passes through it, so an off-by-one at either end
// would shift every country boundary in the table by one address — and it would do it
// silently, because the result is still disjoint, still sorted, and still resolves.
func TestPrefixRangeCoversExactlyThePrefix(t *testing.T) {
	for _, tc := range []struct{ cidr, lo, hi string }{
		{"192.0.2.0/24", "192.0.2.0", "192.0.2.255"},
		{"192.0.2.0/26", "192.0.2.0", "192.0.2.63"},
		{"192.0.2.64/26", "192.0.2.64", "192.0.2.127"},
		{"192.0.2.0/31", "192.0.2.0", "192.0.2.1"},
		{"192.0.2.7/32", "192.0.2.7", "192.0.2.7"}, // a single address
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255"},
		{"2001:db8::/32", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::/48", "2001:db8::", "2001:db8:0:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::1/128", "2001:db8::1", "2001:db8::1"},
		{"::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		lo, hi := prefixRange(netip.MustParsePrefix(tc.cidr))
		if lo != netip.MustParseAddr(tc.lo) || hi != netip.MustParseAddr(tc.hi) {
			t.Errorf("prefixRange(%s) = %s–%s; want %s–%s", tc.cidr, lo, hi, tc.lo, tc.hi)
		}
	}

	// The property behind the table, checked at every prefix length rather than at the
	// handful above: hi is the LARGEST address the prefix contains. A host-bit mask that
	// is one bit short or one bit long fails here at some length even when it happens to
	// be right at /24 and /26.
	for _, base := range []string{"192.0.2.137", "2001:db8:1234:5678:9abc:def0:1234:5678"} {
		a := netip.MustParseAddr(base)
		for bits := 0; bits <= a.BitLen(); bits++ {
			p := netip.PrefixFrom(a, bits).Masked()
			lo, hi := prefixRange(p)
			if lo != p.Addr() {
				t.Errorf("prefixRange(%s) low = %s; want the network address %s", p, lo, p.Addr())
			}
			if !p.Contains(hi) {
				t.Errorf("prefixRange(%s) high = %s, which the prefix does not contain", p, hi)
			}
			if next := hi.Next(); next.IsValid() && p.Contains(next) {
				t.Errorf("prefixRange(%s) high = %s, but %s is also inside it", p, hi, next)
			}
		}
	}
}

// TestCanonical pins the normalization every country tag passes through — the
// GeoIP-derived one and the node's fallback hint alike. The rejections are the point:
// a malformed hint becomes "unknown" rather than a country no filter will ever match.
func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"NL":          "NL",
		"nl":          "NL",
		"nL":          "NL",
		"  de  ":      "DE",
		"\tru\n":      "RU",
		"":            "",
		"N":           "",
		"NLD":         "",
		"Netherlands": "",
		"N1":          "",
		"12":          "",
		"N-":          "",
		"н л":         "",
		"НЛ":          "", // Cyrillic lookalikes must not pass as ASCII letters
	} {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q; want %q", in, got, want)
		}
	}
}
