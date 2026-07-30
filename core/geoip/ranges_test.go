package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every address in this file is from a reserved documentation range (RFC 5737
// 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; RFC 3849 2001:db8::/32). The repo
// carries no real address, and a test fixture is not an exception to that — the same rule
// core/asn/testdata follows for the AS table.

// rangesV4 is the IPv4 country fixture. It is deliberately NOT in ascending order (the
// loader must sort it), and it is built to exercise what the range format can express and
// the CIDR one cannot:
//
//   - 192.0.2.200–192.0.2.209 is ten addresses and is NOT CIDR-aligned. A loader that
//     round-tripped ranges through prefixes would have to split it, and one that split it
//     wrongly would answer for 192.0.2.210 or refuse 192.0.2.209. It is the whole reason
//     the table holds ranges.
//   - Two adjacent ranges (…0–63, …64–127) with different countries, so a boundary that
//     bleeds by one address is a failure and not a rounding.
//   - `nl` in lower case, because the loader must canonicalize (Canonical) rather than
//     store whatever the file said.
//   - Two rows that must become GAPS rather than answers: a ZZ row and upstream's `None`
//     marker. See ccUnattributed.
//   - One IPv6 row, which belongs to the other family and must be skipped rather than
//     filed into the v4 table where it would corrupt the sort.
const rangesV4 = `# Synthetic IP-to-Country fixture — issue #61.
# Documentation address space only (RFC 5737 / RFC 3849).

203.0.113.0	203.0.113.127	FR
192.0.2.64	192.0.2.127	DE
2001:db8:dead::	2001:db8:dead::ffff	DE
192.0.2.0	192.0.2.63	nl
198.51.100.0	198.51.100.255	ZZ
192.0.2.200	192.0.2.209	RU
203.0.113.200	203.0.113.255	None
192.0.2.128	192.0.2.191	GB
`

const rangesV6 = `2001:db8::	2001:db8::ffff	NL
2001:db8:1::	2001:db8:1::ffff	RU
`

// stageRanges writes a range-format database directory and returns its path.
func stageRanges(t *testing.T, v4, v6 string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{FileRangesV4: v4, FileRangesV6: v6} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func mustLoadRanges(t *testing.T, v4, v6 string) *DB {
	t.Helper()
	db, err := LoadDir(stageRanges(t, v4, v6))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Source != SourceRanges {
		t.Fatalf("Source = %q; want %q", db.Source, SourceRanges)
	}
	return db
}

// TestLoadRangesResolvesAndRespectsBoundaries is the core contract for the range loader:
// an address inside a range resolves to that range's country with BOTH bounds included,
// an address in a gap resolves to nothing, and the non-aligned range resolves exactly.
//
// The boundary probes are where an inclusive/exclusive confusion shows up first, and the
// gap probes are what prove the binary search is not returning its nearest neighbour.
func TestLoadRangesResolvesAndRespectsBoundaries(t *testing.T) {
	db := mustLoadRanges(t, rangesV4, rangesV6)

	for _, tc := range []struct {
		ip   string
		want string
	}{
		{"192.0.2.0", "NL"},      // first address of the first range, lower-cased in the file
		{"192.0.2.30", "NL"},     // interior
		{"192.0.2.63", "NL"},     // last address of the range
		{"192.0.2.64", "DE"},     // first address of the adjacent range: must not bleed
		{"192.0.2.127", "DE"},    // last address of the adjacent range
		{"192.0.2.128", "GB"},    // third adjacent range
		{"192.0.2.200", "RU"},    // first address of the NON-CIDR-aligned range
		{"192.0.2.205", "RU"},    // interior of it
		{"192.0.2.209", "RU"},    // its last address — the one an aligned split gets wrong
		{"203.0.113.7", "FR"},    // a different, non-adjacent range
		{"2001:db8::", "NL"},     // v6 table, first address
		{"2001:db8::ffff", "NL"}, // v6 last address
		{"2001:db8:1::5", "RU"},  // adjacent v6 range
		{"192.0.2.192", ""},      // gap between GB's end and RU's start
		{"192.0.2.199", ""},      // still the gap, one below RU
		{"192.0.2.210", ""},      // one ABOVE the non-aligned range's last address
		{"203.0.113.128", ""},    // one above FR's last address
		{"198.51.100.9", ""},     // the ZZ row must be a gap, not an answer
		{"203.0.113.250", ""},    // the `None` row must be a gap, not an answer
		{"2001:db8:dead::1", ""}, // the v6 row that sat in the v4 file was never loaded
		{"2001:db8:2::1", ""},    // v6 gap
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

	// Five attributed rows load; the ZZ row, the `None` row and the v6 row in the v4
	// file are the three skips.
	if v4, v6 := db.Len(); v4 != 5 || v6 != 2 {
		t.Errorf("Len = %d, %d; want 5, 2", v4, v6)
	}
	if db.Skipped != 3 {
		t.Errorf("Skipped = %d; want 3 (a ZZ row, a None row, and a v6 row in the v4 file)", db.Skipped)
	}
}

// TestLoadRangesRejectsStructurallyBrokenRows is the difference between this loader and
// the MaxMind one, and it is the point of the card rather than a detail: a row upstream
// would never publish means the staged file is corrupt or is not the file it should be,
// and loading the rest of it would report success on a PARTIAL country table. Every
// address in the missing ranges then falls back to the node's own self-report, which is
// the failure deriving country from an observed address exists to remove — reached with
// nothing failing visibly.
func TestLoadRangesRejectsStructurallyBrokenRows(t *testing.T) {
	for name, row := range map[string]string{
		"too few fields":     "192.0.2.0\t192.0.2.63\n",
		"too many fields":    "192.0.2.0\t192.0.2.63\tNL\tsomething\n",
		"unparseable start":  "not-an-address\t192.0.2.63\tNL\n",
		"unparseable end":    "192.0.2.0\tnot-an-address\tNL\n",
		"end precedes start": "192.0.2.63\t192.0.2.0\tNL\n",
		"families mixed":     "192.0.2.0\t2001:db8::1\tNL\n",
	} {
		t.Run(name, func(t *testing.T) {
			// Two good rows around the bad one, so a loader that skipped it would
			// succeed with a plausible-looking table and this test would catch that
			// rather than an empty-database error.
			body := "192.0.2.0\t192.0.2.63\tNL\n" + row + "203.0.113.0\t203.0.113.127\tFR\n"
			_, err := LoadDir(stageRanges(t, body, ""))
			if err == nil {
				t.Fatalf("LoadRanges accepted a %s row; want an error", name)
			}
			// The line number is the whole of what makes this actionable: an operator
			// with a 400k-row file needs to be told where to look.
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("error %q does not name the offending line", err)
			}
		})
	}
}

// TestLoadRangesRejectsOverlap pins the disjointness invariant Lookup's single-probe
// search depends on. A file that overlaps would resolve silently and wrongly for the
// overlapped span, so the assumption is enforced at load rather than trusted.
func TestLoadRangesRejectsOverlap(t *testing.T) {
	overlapping := "192.0.2.0\t192.0.2.127\tNL\n192.0.2.64\t192.0.2.191\tDE\n"
	_, err := LoadDir(stageRanges(t, overlapping, ""))
	if err == nil {
		t.Fatal("LoadRanges accepted overlapping ranges; want an error")
	}
	if !strings.Contains(err.Error(), "overlapping") {
		t.Fatalf("error %q does not name the overlap", err)
	}
	// Both ends of both ranges, so an operator can find the two rows.
	for _, want := range []string{"192.0.2.0–192.0.2.127", "192.0.2.64–192.0.2.191"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name the range %s", err, want)
		}
	}
}

// TestLoadRangesRejectsMostlyUnusableFile is the plausible() floor on the new path. The
// realistic mistake it catches is staging the IPv6 file under the IPv4 name: every row is
// skipped as the wrong family, the load "succeeds", and a coordinator runs with an empty
// v4 table while every IPv4 node in the fleet silently falls back to its own hint.
func TestLoadRangesRejectsMostlyUnusableFile(t *testing.T) {
	// The v6 file's contents, staged under the v4 name.
	_, err := LoadDir(stageRanges(t, rangesV6, ""))
	if err == nil {
		t.Fatal("LoadRanges accepted a file whose every row was unusable; want an error")
	}
	if !strings.Contains(err.Error(), "unusable") {
		t.Fatalf("error %q does not say the rows were unusable", err)
	}
}

// TestLoadRangesRefusesAnEmptyTable: a file whose rows are all unattributed parses
// cleanly and holds nothing. Loading it "successfully" would leave the whole fleet on
// self-reported countries under a flag whose promise is the opposite.
func TestLoadRangesRefusesAnEmptyTable(t *testing.T) {
	// A single ZZ row: structurally fine, semantically empty. Nothing is skipped as
	// malformed, so this reaches the both-families-empty refusal rather than plausible.
	if _, err := LoadDir(stageRanges(t, "192.0.2.0\t192.0.2.63\tZZ\n", "")); err == nil {
		t.Error("LoadRanges accepted a table with no attributed rows")
	}
	// Comments and blank lines only.
	if _, err := LoadDir(stageRanges(t, "# nothing here\n\n", "")); err == nil {
		t.Error("LoadRanges accepted a file of comments")
	}
}

// TestLoadRangesToleratesMissingIPv6 but requires IPv4: a v4-only staging is a valid
// deployment, a directory with neither is a mistake — and the error must name both
// accepted formats, because either would have been loaded.
func TestLoadRangesToleratesMissingIPv6(t *testing.T) {
	db := mustLoadRanges(t, rangesV4, "")
	if _, v6 := db.Len(); v6 != 0 {
		t.Errorf("v6 table is not empty (%d) with no v6 file staged", v6)
	}
	if _, ok := db.Lookup(netip.MustParseAddr("2001:db8::5")); ok {
		t.Error("resolved a v6 address with no v6 table")
	}

	_, err := LoadDir(t.TempDir())
	if err == nil {
		t.Fatal("LoadDir accepted an empty directory")
	}
	for _, want := range []string{FileRangesV4, FileBlocksV4} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s as an accepted staging", err, want)
		}
	}
}

// TestLoadRangesSkipsNonRoutable pins the case the local smoke stack lives in through the
// new loader specifically: every node registers from loopback, so GeoIP must resolve
// nothing and let the caller fall back to the -country hint. The rule lives in Lookup and
// is shared, but a range file that covered loopback would tag the whole dev fleet, so the
// two are worth asserting together.
func TestLoadRangesSkipsNonRoutable(t *testing.T) {
	db := mustLoadRanges(t, rangesV4, rangesV6)
	for _, s := range []string{"127.0.0.1", "::1", "10.0.0.7", "192.168.1.1", "169.254.1.1", "fc00::1", "0.0.0.0", "224.0.0.1"} {
		if cc, ok := db.Lookup(netip.MustParseAddr(s)); ok {
			t.Errorf("Lookup(%s) = %q, true; want unresolved (non-routable)", s, cc)
		}
	}
}

// TestLoadDirPrefersTheRangeFormat pins the dispatch rule. A directory carrying both is a
// MaxMind staging that was superseded and not cleaned up; preferring the CSV would leave
// an operator who staged the documented file silently running on the old one.
//
// The two fixtures deliberately DISAGREE about 192.0.2.10, so this proves which file was
// read rather than merely that something loaded.
func TestLoadDirPrefersTheRangeFormat(t *testing.T) {
	dir := stageRanges(t, "192.0.2.0\t192.0.2.63\tNL\n", "")
	// The same address, attributed to Germany, in MaxMind's format alongside it.
	for name, body := range map[string]string{
		FileLocations: locationsCSV,
		FileBlocksV4:  "network,geoname_id,registered_country_geoname_id\n192.0.2.0/26,2921044,2921044\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Source != SourceRanges {
		t.Errorf("Source = %q; want %q — the range format must win", db.Source, SourceRanges)
	}
	if cc, ok := db.Lookup(netip.MustParseAddr("192.0.2.10")); !ok || cc != "NL" {
		t.Errorf("Lookup = %q, %v; want \"NL\", true — the CSV, which says DE, was read instead", cc, ok)
	}
}

// TestLoadDirReportsTheMaxMindSource is the other half of the dispatch: with no range file
// staged, the CSV loads and says so. DB.Source is what puts that in the startup log, and
// it is the only thing that distinguishes the two formats there, since row counts do not.
func TestLoadDirReportsTheMaxMindSource(t *testing.T) {
	db, err := LoadDir(stage(t, locationsCSV, blocksV4CSV, blocksV6CSV))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Source != SourceMaxMind {
		t.Errorf("Source = %q; want %q", db.Source, SourceMaxMind)
	}
}
