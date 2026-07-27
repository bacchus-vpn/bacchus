// Package geoip resolves an IP address to an ISO-3166-1 alpha-2 country code from
// a database staged on local disk, with no network access of any kind.
//
// It exists for issue #136. An exit's or relay's country used to be a hand-typed
// -country flag, which is a NODE SELF-REPORT: the trust model treats those as
// untrusted (a hostile or Sybil node can claim any country), and it is also simply
// easy to typo — a wrong tag silently corrupts the client's country filter. The
// coordinator instead derives the tag from the source IP it OBSERVED the node
// register from, which is the same rule coldstart.Entry.Ingress (issue #124) and
// capacity's observedAS (issue #158) already follow: an observed address is
// trusted, a claimed one is not.
//
// # Why local, never a lookup service
//
// An outbound geo-service call would (a) tell a third party the IP of every node in
// the network, which is the one thing this project spends the most effort not
// leaking, and (b) add a dependency on reaching a foreign HTTPS endpoint from
// inside a censored network — the exact failure mode the whole design routes
// around. So the database is a local file, staged and refreshed out of band, and a
// lookup is a pure in-memory search. There is no fetch path in this package, on
// purpose: nothing here can ever make a network call.
//
// # Database format and provenance
//
// The input is MaxMind's GeoLite2 **Country CSV** distribution — the two files
// GeoLite2-Country-Blocks-IPv4.csv / -IPv6.csv (network → geoname_id) joined
// against GeoLite2-Country-Locations-en.csv (geoname_id → country_iso_code). The
// CSV rather than the .mmdb binary, deliberately:
//
//   - It needs no third-party decoder, so this package is stdlib-only and the whole
//     parse is auditable in one screen. A binary-format reader would be another
//     dependency in the trusted path that assigns users to countries.
//   - It is the upstream artifact as published, so provenance is direct: there is no
//     intermediate conversion step a reviewer would have to trust.
//
// The files are NOT committed — they are a licensed third-party dataset and a large
// binary-ish blob, and the repo stays publishable and small. docs/RUNNING.md
// documents how to fetch and stage them; .gitignore keeps them out.
//
// The cost of the CSV choice is that the table is held in memory (order 500k
// prefixes, tens of MB) rather than mmap'd. A coordinator loads once at startup and
// then only searches, so that is the right trade.
package geoip

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// Conventional filenames inside MaxMind's GeoLite2-Country-CSV distribution. LoadDir
// looks for exactly these, so an operator stages the unzipped directory as-published
// and does not have to rename anything.
const (
	FileLocations = "GeoLite2-Country-Locations-en.csv"
	FileBlocksV4  = "GeoLite2-Country-Blocks-IPv4.csv"
	FileBlocksV6  = "GeoLite2-Country-Blocks-IPv6.csv"
)

// StaleAfter is how old a staged database may be before Load flags it via DB.Stale.
// GeoIP data drifts as address space is reassigned, and a stale table does not fail
// loudly — it silently mislabels a node's country, which is the same class of defect
// as the typo'd -country flag this package replaces. Ninety days is a few of
// MaxMind's weekly release cycles: long enough not to nag, short enough that a
// forgotten database is noticed before it is badly wrong.
//
// It is advisory. Load never refuses a stale database, because refusing would take a
// coordinator down over data hygiene; the caller logs it.
const StaleAfter = 90 * 24 * time.Hour

// block is one contiguous CIDR range mapped to a country. cc is interned across the
// whole table (there are ~250 distinct values across ~500k rows), so the strings
// cost a couple of KB rather than tens of MB.
type block struct {
	p  netip.Prefix
	cc string
}

// DB is an immutable IP→country table. It is safe for concurrent use: nothing
// mutates after Load returns, so a coordinator can look up from its packet loop
// without a lock. Reload by building a new DB and swapping the pointer.
type DB struct {
	// v4 and v6 are each sorted by network address and verified DISJOINT at load
	// (see validate). Disjointness is what lets Lookup be a single binary search
	// plus one containment check instead of a longest-prefix walk, so it is
	// enforced rather than assumed — MaxMind publishes disjoint blocks, and a file
	// that is not is a corrupt or hand-edited file we would rather reject than
	// silently resolve wrongly.
	v4, v6 []block

	// BuiltAt is the newest modification time among the input files — the closest
	// honest proxy for "when this data was published", since the CSVs carry no
	// build stamp of their own. Zero when loaded from a reader rather than a file.
	BuiltAt time.Time

	// Stale reports that BuiltAt is older than StaleAfter (always false when
	// BuiltAt is zero). Advisory; see StaleAfter.
	Stale bool

	// Skipped is how many data rows across both families were read but not usable —
	// an unparseable prefix, a prefix belonging to the other family, or a row whose
	// geoname resolved to no country. A handful is normal (MaxMind ships rows
	// attributed to no country); a large number means the file or the locations table
	// it is joined against is not what it should be. Surfaced so an operator can see
	// it in the startup log rather than have it absorbed silently — see plausible.
	Skipped int
}

// maxSkippedFraction is the largest share of a blocks file's data rows that may be
// unusable before the file is rejected. A handful of unattributable rows is normal —
// MaxMind ships some — but most of the file being unusable means the blocks and
// locations files do not belong to the same release, or one of them is corrupt.
//
// A ratio rather than a row count, deliberately: it is scale-free, so it means the
// same thing for a four-row fixture as for a four-hundred-thousand-row database, and
// there is no threshold to keep in step with MaxMind's weekly publication sizes.
const maxSkippedFraction = 0.5

// plausible rejects a blocks file that parsed cleanly but cannot be the database it
// claims to be.
//
// It narrows a specific silent failure: readBlocks skips any row it cannot use, and
// Load errors only when BOTH families end up empty, so a mismatched CSV loaded
// "successfully" and every node in the missing ranges quietly fell back to its own
// self-reported country hint — the exact outcome deriving country from an observed
// address exists to prevent, reached without a single error.
//
// It narrows it rather than closing it, and the distinction is stated rather than
// glossed. This catches a blocks/locations mismatch and a file that is mostly
// unparseable. It does NOT catch a file truncated at a line boundary to, say, 60% of
// its rows: that has valid prefixes, skips nothing, and is indistinguishable here from
// a smaller publication. The load counts are surfaced (DB.Len, DB.Skipped) so a
// caller that knows what size to expect can say so — cmd/coordinator does, in its
// startup log — but detecting partial truncation properly needs a checksum against
// MaxMind's published digest, which is a staging-pipeline property and not a loader
// one. ADR-0042 §3 states the residual.
func plausible(loaded, skipped int, family, path string) error {
	if total := loaded + skipped; skipped > 0 && float64(skipped)/float64(total) > maxSkippedFraction {
		return fmt.Errorf("geoip: %s blocks %s: %d of %d data rows were unusable (>%.0f%%): the blocks and locations files probably do not belong to the same release",
			family, path, skipped, total, maxSkippedFraction*100)
	}
	return nil
}

// Load reads a database from the three GeoLite2 Country CSV files at the given
// paths. Either blocks path may be empty to skip that address family, which is how
// a deployment that has no IPv6 nodes avoids paying for the v6 table.
func Load(locationsPath, blocksV4Path, blocksV6Path string) (*DB, error) {
	locations, err := loadLocations(locationsPath)
	if err != nil {
		return nil, err
	}
	db := &DB{}
	for _, in := range []struct {
		path string
		dst  *[]block
		want func(netip.Prefix) bool
		fam  string
	}{
		{blocksV4Path, &db.v4, func(p netip.Prefix) bool { return p.Addr().Is4() }, "IPv4"},
		{blocksV6Path, &db.v6, func(p netip.Prefix) bool { return p.Addr().Is6() }, "IPv6"},
	} {
		if in.path == "" {
			continue
		}
		f, err := os.Open(in.path)
		if err != nil {
			return nil, fmt.Errorf("geoip: open blocks: %w", err)
		}
		blocks, skipped, err := readBlocks(f, locations, in.want)
		cerr := f.Close()
		if err != nil {
			return nil, fmt.Errorf("geoip: %s blocks %s: %w", in.fam, in.path, err)
		}
		if cerr != nil {
			return nil, fmt.Errorf("geoip: close blocks: %w", cerr)
		}
		if err := validate(blocks); err != nil {
			return nil, fmt.Errorf("geoip: %s blocks %s: %w", in.fam, in.path, err)
		}
		if err := plausible(len(blocks), skipped, in.fam, in.path); err != nil {
			return nil, err
		}
		db.Skipped += skipped
		*in.dst = blocks
	}
	if len(db.v4) == 0 && len(db.v6) == 0 {
		return nil, errors.New("geoip: database is empty (no usable blocks in either family)")
	}
	db.BuiltAt = newestModTime(locationsPath, blocksV4Path, blocksV6Path)
	db.Stale = !db.BuiltAt.IsZero() && time.Since(db.BuiltAt) > StaleAfter
	return db, nil
}

// LoadDir reads a database from an unzipped GeoLite2-Country-CSV directory, using
// MaxMind's own filenames. The IPv6 blocks file is optional — absent, the DB simply
// resolves no IPv6 address — because a deployment may legitimately stage only v4.
// The IPv4 file is required: a directory with neither is a staging mistake, not a
// configuration.
func LoadDir(dir string) (*DB, error) {
	v4 := filepath.Join(dir, FileBlocksV4)
	if _, err := os.Stat(v4); err != nil {
		return nil, fmt.Errorf("geoip: %s not found in %s: %w", FileBlocksV4, dir, err)
	}
	v6 := filepath.Join(dir, FileBlocksV6)
	if _, err := os.Stat(v6); err != nil {
		v6 = ""
	}
	return Load(filepath.Join(dir, FileLocations), v4, v6)
}

// Lookup returns the ISO-3166-1 alpha-2 country code for ip, or ("", false) when
// the address is not resolvable.
//
// Not-resolvable covers three distinct cases, deliberately answered the same way,
// because the caller's response to all three is identical (fall back to the node's
// hint, per issue #136):
//
//   - The address is not globally routable — loopback, RFC1918, link-local,
//     unspecified, or multicast. This is the ordinary case on a developer box and in
//     the local smoke stack, where every node registers from 127.0.0.1.
//   - The address is global but absent from the table (unallocated space, or a range
//     MaxMind maps to no country).
//   - No table for that address family was staged.
//
// A v4-mapped v6 address (::ffff:a.b.c.d, which is what a dual-stack UDP socket
// hands back for a v4 peer) is unmapped first and resolved against the v4 table.
// Missing that is a silent whole-family failure, so it is done here rather than left
// to every caller.
func (d *DB) Lookup(ip netip.Addr) (string, bool) {
	if d == nil || !ip.IsValid() {
		return "", false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "", false
	}
	table := d.v6
	if ip.Is4() {
		table = d.v4
	}
	// The table is sorted by network address and disjoint, so the only prefix that
	// can contain ip is the last one starting at or before it.
	i, _ := slices.BinarySearchFunc(table, ip, func(b block, target netip.Addr) int {
		return b.p.Addr().Compare(target)
	})
	// BinarySearchFunc returns the insertion point; the candidate is the element
	// before it (or the exact hit at i, which Contains also accepts).
	if i < len(table) && table[i].p.Addr() == ip {
		return table[i].cc, true
	}
	if i == 0 {
		return "", false
	}
	if b := table[i-1]; b.p.Contains(ip) {
		return b.cc, true
	}
	return "", false
}

// LookupAddr is Lookup for a net.IP, the form the coordinator's UDP source address
// arrives in.
func (d *DB) LookupAddr(ip net.IP) (string, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", false
	}
	return d.Lookup(a)
}

// Len reports how many prefixes the table holds, per family. Used for the startup
// log line, which is the only evidence an operator gets that the staged database is
// the one they meant.
func (d *DB) Len() (v4, v6 int) {
	if d == nil {
		return 0, 0
	}
	return len(d.v4), len(d.v6)
}

// Canonical normalizes a country tag to its ISO-3166-1 alpha-2 form, returning ""
// for anything that is not exactly two ASCII letters.
//
// Every country tag in the system passes through here — the GeoIP-derived one and
// the node's fallback hint alike — which buys two things. It kills the typo class
// that motivated issue #136 even on the hint path ("Netherlands", "nl ", "N1" all
// become ""), so a malformed tag becomes "unknown" rather than a country no filter
// will ever match. And it makes the tag's case canonical at the source, which
// removes the standing asymmetry between core/selection's case-INSENSITIVE
// filterGeo and its case-SENSITIVE learned-path store key: if every tag the
// coordinator ever emits is upper-case, the two agree by construction.
func Canonical(cc string) string {
	cc = strings.TrimSpace(cc)
	if len(cc) != 2 {
		return ""
	}
	out := []byte(strings.ToUpper(cc))
	for _, c := range out {
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return string(out)
}

// loadLocations builds geoname_id → ISO country code from the Locations CSV.
func loadLocations(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open locations: %w", err)
	}
	defer f.Close()
	out, err := readLocations(f)
	if err != nil {
		return nil, fmt.Errorf("geoip: locations %s: %w", path, err)
	}
	return out, nil
}

// readLocations parses the Locations CSV. Columns are addressed BY HEADER NAME, not
// by index, so a MaxMind column reordering or insertion cannot silently shift which
// field is read as the country code.
func readLocations(r io.Reader) (map[string]string, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	idID, err := column(head, "geoname_id")
	if err != nil {
		return nil, err
	}
	idCC, err := column(head, "country_iso_code")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	intern := map[string]string{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if idID >= len(rec) || idCC >= len(rec) {
			continue
		}
		cc := Canonical(rec[idCC])
		if cc == "" {
			// A location row with no country code: continent-level or
			// supranational entries do exist in this file. A block pointing at
			// one resolves to "unknown", which is the honest answer.
			continue
		}
		if s, ok := intern[cc]; ok {
			cc = s
		} else {
			intern[cc] = cc
		}
		out[rec[idID]] = cc
	}
	if len(out) == 0 {
		return nil, errors.New("no usable rows")
	}
	return out, nil
}

// readBlocks parses a Blocks CSV into sorted prefix→country pairs, keeping only
// prefixes that want() accepts (so a v6 row in the v4 file is skipped rather than
// silently landing in the wrong table).
//
// skipped counts data rows that were read but not usable. Every skip is individually
// legitimate — the other family's rows, and rows MaxMind attributes to no country —
// which is why they are skipped rather than fatal; but the TOTAL is a signal about the
// file as a whole, so it is returned rather than discarded (see plausible).
func readBlocks(r io.Reader, locations map[string]string, want func(netip.Prefix) bool) (out []block, skipped int, err error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	head, err := cr.Read()
	if err != nil {
		return nil, 0, fmt.Errorf("read header: %w", err)
	}
	idNet, err := column(head, "network")
	if err != nil {
		return nil, 0, err
	}
	idGeo, err := column(head, "geoname_id")
	if err != nil {
		return nil, 0, err
	}
	// registered_country_geoname_id is the fallback for a block whose geoname_id is
	// blank — common for ranges MaxMind attributes to a registrant but not to a
	// physical location. Using it materially reduces the "unknown" rate, and for
	// this purpose (where is this node) the registrant's country is the better
	// answer than nothing.
	idReg, err := column(head, "registered_country_geoname_id")
	if err != nil {
		return nil, 0, err
	}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		if idNet >= len(rec) {
			skipped++
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(rec[idNet]))
		if err != nil || !p.IsValid() || !want(p) {
			skipped++
			continue
		}
		cc := ""
		if idGeo < len(rec) {
			cc = locations[rec[idGeo]]
		}
		if cc == "" && idReg < len(rec) {
			cc = locations[rec[idReg]]
		}
		if cc == "" {
			skipped++
			continue
		}
		out = append(out, block{p: p.Masked(), cc: cc})
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].p.Addr().Compare(out[j].p.Addr()); c != 0 {
			return c < 0
		}
		return out[i].p.Bits() < out[j].p.Bits()
	})
	return out, skipped, nil
}

// validate enforces the disjointness Lookup's single-probe search depends on. Given
// the sort, an overlap can only appear as a block whose network address falls inside
// its predecessor's range, so one linear pass is exhaustive.
func validate(blocks []block) error {
	for i := 1; i < len(blocks); i++ {
		if blocks[i-1].p.Contains(blocks[i].p.Addr()) {
			return fmt.Errorf("overlapping prefixes %s and %s: expected a disjoint table", blocks[i-1].p, blocks[i].p)
		}
	}
	return nil
}

// bom is the UTF-8 byte-order mark. It is not whitespace, so it survives TrimSpace
// and would otherwise make the first CSV column never match its own header name.
const bom = "\xef\xbb\xbf"

// column resolves a CSV header name to its index.
func column(head []string, name string) (int, error) {
	for i, h := range head {
		// The first cell of a UTF-8 CSV can carry a byte-order mark, which is not
		// whitespace and so survives TrimSpace. Strip it explicitly, or the very
		// first column never matches its own name.
		if strings.TrimSpace(strings.TrimPrefix(h, bom)) == name {
			return i, nil
		}
	}
	return 0, fmt.Errorf("missing column %q", name)
}

// newestModTime returns the latest mtime among the paths that exist, or the zero
// time if none do.
func newestModTime(paths ...string) time.Time {
	var newest time.Time
	for _, p := range paths {
		if p == "" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}
