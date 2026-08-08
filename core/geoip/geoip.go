// Package geoip resolves an IP address to an ISO-3166-1 alpha-2 country code from
// a database staged on local disk, with no network access of any kind.
//
// It exists for old #136. An exit's or relay's country used to be a hand-typed
// -country flag, which is a NODE SELF-REPORT: the trust model treats those as
// untrusted (a hostile or Sybil node can claim any country), and it is also simply
// easy to typo — a wrong tag silently corrupts the client's country filter. The
// coordinator instead derives the tag from the source IP it OBSERVED the node
// register from, which is the same rule coldstart.Entry.Ingress (old #124) and
// capacity's observedAS (old #158) already follow: an observed address is
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
// Two input formats load, both plain text. LoadDir takes a staged directory and reads
// whichever is in it.
//
//   - RANGE format, and the one this project stages: iptoasn.com's IP-to-Country
//     files, one `range_start range_end country_code` row per line. See ranges.go.
//   - MaxMind's GeoLite2 Country CSV distribution — the two blocks files
//     (network → geoname_id) joined against the locations file
//     (geoname_id → country_iso_code). Below, and still supported.
//
// The range format is preferred on LICENCE, not on shape (issue #61). GeoLite2 needs a
// free MaxMind account and a licence key to download, and its terms restrict
// redistribution. That is survivable while one operator runs every coordinator — nobody
// redistributes anything, each host fetches its own — and becomes an onboarding tax the
// moment coordinators federate, because every volunteer operator would need their own
// MaxMind account before their coordinator could derive a country honestly. The
// alternative to deriving it is trusting the node's self-report, which is the whole
// thing this package exists to stop, so the licence sits directly upstream of a security
// property. iptoasn.com publishes under PDDL v1.0 — public domain, no account, no key,
// no redistribution question — and it is already the source ADR-0044 chose for
// core/asn's table, so one feed covers both.
//
// The MaxMind loader is kept rather than deleted: it works, it is tested, and an
// existing deployment has a directory staged in that format. Nothing about it stopped
// being true.
//
// Text rather than a packed binary (MaxMind's .mmdb, or a varint-coded range table),
// deliberately, and the reasoning is the same for both formats:
//
//   - It needs no third-party decoder, so this package is stdlib-only and the whole
//     parse is auditable in one screen. A binary-format reader would be another
//     dependency in the trusted path that assigns users to countries.
//   - It is the upstream artifact as published, so provenance is direct: there is no
//     intermediate conversion step a reviewer would have to trust. This is why the
//     range format is read as published rather than transformed into CIDR prefixes by
//     a staging tool first, which is what core/asn does — that table is COMMITTED, so
//     it has to be byte-reproducible; this one is fetched per host, so a transform step
//     would buy nothing and cost a tool in the path.
//
// Neither format's files are committed — they are bulk third-party data, and one of them
// is licensed besides. docs/RUNNING.md documents how to fetch and stage them;
// .gitignore keeps them out.
//
// The cost of the text choice is that the table is held in memory (order 500k rows, tens
// of MB) rather than mmap'd. A coordinator loads once at startup and then only searches,
// so that is the right trade.
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

// The database formats this package loads, as reported by DB.Source.
const (
	// SourceRanges is iptoasn.com's IP-to-Country range files — what this project
	// stages. See ranges.go.
	SourceRanges = "iptoasn ip2country"
	// SourceMaxMind is MaxMind's GeoLite2 Country CSV distribution.
	SourceMaxMind = "GeoLite2 Country CSV"
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

// block is one contiguous address range, bounds INCLUSIVE, mapped to a country. cc is
// interned across the whole table (there are ~250 distinct values across ~500k rows), so
// the strings cost a couple of KB rather than tens of MB.
//
// A range rather than a netip.Prefix, so that both loaders store the same thing. The
// range is the more general of the two shapes: every prefix is a range, while an
// arbitrary range is up to 62 prefixes, so holding prefixes would have meant either
// decomposing each upstream range at load — more rows than the file has, and a
// bit-twiddling decomposition to get wrong — or a second table with its own search and
// its own disjointness rule, which is worse. Prefixes convert in the one direction that
// is cheap and exact (prefixRange), so the MaxMind loader is the one that adapts.
type block struct {
	lo, hi netip.Addr
	cc     string
}

// String renders a block's range for an error message. Both bounds, because that is what
// the disjointness failures are about.
func (b block) String() string { return b.lo.String() + "–" + b.hi.String() }

// DB is an immutable IP→country table. It is safe for concurrent use: nothing
// mutates after Load returns, so a coordinator can look up from its packet loop
// without a lock. Reload by building a new DB and swapping the pointer.
type DB struct {
	// v4 and v6 are each sorted by range start and verified DISJOINT at load (see
	// validate). Disjointness is what lets Lookup be a single binary search plus one
	// containment check instead of a longest-prefix walk, so it is enforced rather
	// than assumed — both upstreams publish disjoint data, and a file that is not is
	// a corrupt or hand-edited file we would rather reject than silently resolve
	// wrongly.
	v4, v6 []block

	// Source names the format that was loaded — one of the Source constants.
	//
	// It exists because LoadDir now accepts two formats, and the per-family row counts
	// alone no longer say which one an operator staged. The startup log line is the only
	// evidence they get that the database is the one they meant, so it has to be able to
	// name the file it read; cmd/coordinator prints this.
	Source string

	// BuiltAt is the newest modification time among the input files — the closest
	// honest proxy for "when this data was published", since the CSVs carry no
	// build stamp of their own. Zero when loaded from a reader rather than a file.
	BuiltAt time.Time

	// Stale reports that BuiltAt is older than StaleAfter (always false when
	// BuiltAt is zero). Advisory; see StaleAfter.
	Stale bool

	// Skipped is how many data rows across both families were read but not usable — a
	// row belonging to the other address family, or one that resolved to no country. A
	// handful is normal (both upstreams ship space they attribute to nobody); a large
	// number means the staged file is not what it should be. Surfaced so an operator can
	// see it in the startup log rather than have it absorbed silently — see plausible.
	//
	// What is NOT counted here is a structurally broken row, because the range loader
	// refuses to load one at all; readRanges says why the two formats differ.
	Skipped int
}

// maxSkippedFraction is the largest share of a data file's rows that may be unusable
// before the file is rejected. A handful of unattributable rows is normal — both
// upstreams ship some — but most of the file being unusable means the wrong file is
// staged, or a MaxMind blocks and locations pair from two different releases.
//
// A ratio rather than a row count, deliberately: it is scale-free, so it means the
// same thing for a four-row fixture as for a four-hundred-thousand-row database, and
// there is no threshold to keep in step with MaxMind's weekly publication sizes.
const maxSkippedFraction = 0.5

// plausible rejects a data file that parsed cleanly but cannot be the database it claims
// to be.
//
// It narrows a specific silent failure: a loader skips any row it cannot use, and
// assemble errors only when BOTH families end up empty, so a mismatched file loaded
// "successfully" and every node in the missing ranges quietly fell back to its own
// self-reported country hint — the exact outcome deriving country from an observed
// address exists to prevent, reached without a single error.
//
// It narrows it rather than closing it, and the distinction is stated rather than
// glossed. This catches a blocks/locations mismatch, a file staged for the wrong address
// family, and a file that is mostly unusable. It does NOT catch a file truncated at a
// line boundary to, say, 60% of its rows: that has valid rows, skips nothing, and is
// indistinguishable here from a smaller publication. The load counts are surfaced
// (DB.Len, DB.Skipped) so a caller that knows what size to expect can say so —
// cmd/coordinator does, in its startup log — but detecting partial truncation properly
// needs a checksum against the publisher's own digest, which is a staging-pipeline
// property and not a loader one. ADR-0042 §3 states the residual.
func plausible(loaded, skipped int, noun, family, path string) error {
	if total := loaded + skipped; skipped > 0 && float64(skipped)/float64(total) > maxSkippedFraction {
		return fmt.Errorf("geoip: %s %s %s: %d of %d data rows were unusable (>%.0f%%): this is probably not the file it should be — for a range file, the other address family staged under this one's name; for the MaxMind CSV, blocks and locations from two different releases",
			family, noun, path, skipped, total, maxSkippedFraction*100)
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
	read := func(r io.Reader, is func(netip.Addr) bool) ([]block, int, error) {
		return readBlocks(r, locations, is)
	}
	// The locations file is passed for the mtime stamp only; it is already parsed.
	return assemble(SourceMaxMind, "blocks", read, blocksV4Path, blocksV6Path, locationsPath)
}

// parser reads one family's data file into range→country rows, keeping only rows whose
// addresses is() accepts, and reporting how many rows it read but could not use.
type parser func(r io.Reader, is func(netip.Addr) bool) (rows []block, skipped int, err error)

// assemble builds a DB by running one parser over the per-family input paths.
//
// It exists so that the two formats cannot drift apart in the checks that matter. Every
// load — either format — goes through the same disjointness validation, the same
// plausibility floor, the same both-families-empty refusal and the same staleness stamp;
// the loaders differ only in how they turn bytes into rows. Written as two functions
// instead, the second one acquires a weaker set of guards the first day someone forgets
// one, and nothing fails visibly when it does, because every gap in a country table reads
// as "fall back to the node's self-report".
//
// An empty path skips that family. noun names the rows in error messages ("blocks",
// "ranges"), and alsoStamp carries any further files whose mtime should count toward
// BuiltAt.
func assemble(source, noun string, read parser, v4Path, v6Path string, alsoStamp ...string) (*DB, error) {
	db := &DB{Source: source}
	for _, in := range []struct {
		path string
		dst  *[]block
		is   func(netip.Addr) bool
		fam  string
	}{
		{v4Path, &db.v4, netip.Addr.Is4, "IPv4"},
		{v6Path, &db.v6, netip.Addr.Is6, "IPv6"},
	} {
		if in.path == "" {
			continue
		}
		f, err := os.Open(in.path)
		if err != nil {
			return nil, fmt.Errorf("geoip: open %s: %w", noun, err)
		}
		rows, skipped, err := read(f, in.is)
		cerr := f.Close()
		if err != nil {
			return nil, fmt.Errorf("geoip: %s %s %s: %w", in.fam, noun, in.path, err)
		}
		if cerr != nil {
			return nil, fmt.Errorf("geoip: close %s: %w", noun, cerr)
		}
		if err := validate(rows); err != nil {
			return nil, fmt.Errorf("geoip: %s %s %s: %w", in.fam, noun, in.path, err)
		}
		if err := plausible(len(rows), skipped, noun, in.fam, in.path); err != nil {
			return nil, err
		}
		db.Skipped += skipped
		*in.dst = rows
	}
	if len(db.v4) == 0 && len(db.v6) == 0 {
		return nil, fmt.Errorf("geoip: database is empty (no usable %s in either family)", noun)
	}
	db.BuiltAt = newestModTime(append([]string{v4Path, v6Path}, alsoStamp...)...)
	db.Stale = !db.BuiltAt.IsZero() && time.Since(db.BuiltAt) > StaleAfter
	return db, nil
}

// LoadDir reads a database from a staged directory, in whichever supported format is
// present, using each upstream's own filenames — so an operator stages what was published
// and renames nothing. It is the entry point behind the coordinator's -geoip flag, and
// the reason that flag names a directory rather than a file.
//
// The RANGE format wins when both are staged. It is the format this project documents
// (docs/RUNNING.md), so a directory holding both is a MaxMind staging that has been
// superseded and not cleaned up, and preferring the other way round would mean an
// operator who staged the new file kept silently running on the old one. DB.Source
// reports which was read, so the choice is visible in the startup log rather than
// inferred from row counts.
//
// The IPv6 file is optional in both formats — absent, the DB simply resolves no IPv6
// address — because a deployment may legitimately stage only v4. The IPv4 file is
// required: a directory with neither is a staging mistake, not a configuration, and the
// error names both formats because either one would have been accepted.
func LoadDir(dir string) (*DB, error) {
	if v4 := optional(dir, FileRangesV4); v4 != "" {
		return LoadRanges(v4, optional(dir, FileRangesV6))
	}
	v4 := filepath.Join(dir, FileBlocksV4)
	if _, err := os.Stat(v4); err != nil {
		return nil, fmt.Errorf("geoip: no country database in %s: expected %s, or %s alongside %s: %w",
			dir, FileRangesV4, FileBlocksV4, FileLocations, err)
	}
	return Load(filepath.Join(dir, FileLocations), v4, optional(dir, FileBlocksV6))
}

// optional returns the path to name inside dir, or "" when it is not there — which is the
// form Load and LoadRanges take for a family to skip.
func optional(dir, name string) string {
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// Lookup returns the ISO-3166-1 alpha-2 country code for ip, or ("", false) when
// the address is not resolvable.
//
// Not-resolvable covers three distinct cases, deliberately answered the same way,
// because the caller's response to all three is identical (fall back to the node's
// hint, per old #136):
//
//   - The address is not globally routable — loopback, RFC1918, link-local,
//     unspecified, or multicast. This is the ordinary case on a developer box and in
//     the local smoke stack, where every node registers from 127.0.0.1.
//   - The address is global but absent from the table (unallocated space, or a range
//     the database attributes to no country).
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
	// The table is sorted by range start and disjoint, so the only range that can
	// contain ip is the last one starting at or before it.
	i, _ := slices.BinarySearchFunc(table, ip, func(b block, target netip.Addr) int {
		return b.lo.Compare(target)
	})
	// BinarySearchFunc returns the insertion point; the candidate is the element
	// before it, or an exact hit on a range's first address at i.
	if i < len(table) && table[i].lo == ip {
		return table[i].cc, true
	}
	if i == 0 {
		return "", false
	}
	// table[i-1].lo <= ip by the search, so containment is the upper bound alone.
	if b := table[i-1]; !b.hi.Less(ip) {
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
// that motivated old #136 even on the hint path ("Netherlands", "nl ", "N1" all
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

// readBlocks parses a Blocks CSV into sorted range→country rows, keeping only prefixes
// whose address is() accepts (so a v6 row in the v4 file is skipped rather than silently
// landing in the wrong table).
//
// skipped counts data rows that were read but not usable. Every skip is individually
// legitimate — the other family's rows, and rows MaxMind attributes to no country —
// which is why they are skipped rather than fatal; but the TOTAL is a signal about the
// file as a whole, so it is returned rather than discarded (see plausible). The range
// loader draws this line differently, for a reason readRanges gives.
func readBlocks(r io.Reader, locations map[string]string, is func(netip.Addr) bool) (out []block, skipped int, err error) {
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
		if err != nil || !p.IsValid() || !is(p.Addr()) {
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
		lo, hi := prefixRange(p)
		out = append(out, block{lo: lo, hi: hi, cc: cc})
	}
	sortBlocks(out)
	return out, skipped, nil
}

// prefixRange converts a CIDR prefix to the inclusive address range it covers — the form
// the table holds (see block). Exact in both directions for a prefix; it is the reverse
// that is lossy, which is why the store keeps ranges and this adapts MaxMind's rows to
// them rather than the other way round.
func prefixRange(p netip.Prefix) (lo, hi netip.Addr) {
	p = p.Masked()
	lo = p.Addr()
	// The last address is the first with every host bit set. Done a byte at a time so
	// one expression covers both families: shifting a 128-bit address needs two halves,
	// and getting that wrong is a silent off-by-one at every range boundary.
	var buf []byte
	if lo.Is4() {
		b := lo.As4()
		buf = b[:]
	} else {
		b := lo.As16()
		buf = b[:]
	}
	for i := range buf {
		host := 8*(i+1) - p.Bits() // host bits inside byte i
		if host <= 0 {
			continue // wholly network
		}
		if host > 8 {
			host = 8 // wholly host
		}
		buf[i] |= byte(0xff >> (8 - host))
	}
	hi, _ = netip.AddrFromSlice(buf)
	return lo, hi
}

// sortBlocks orders a family by range start, then by end. Both loaders call it, because
// the sort is what validate's single linear pass and Lookup's single binary probe are
// both stated against.
//
// Equal starts can only be an overlap, which validate rejects whichever way they are
// ordered; the second key is there so the order is total and the rejection deterministic.
func sortBlocks(rows []block) {
	slices.SortFunc(rows, func(a, b block) int {
		if c := a.lo.Compare(b.lo); c != 0 {
			return c
		}
		return a.hi.Compare(b.hi)
	})
}

// validate enforces the disjointness Lookup's single-probe search depends on. Given the
// sort, an overlap can only appear as a row starting at or before its predecessor's end,
// so one linear pass is exhaustive.
func validate(rows []block) error {
	for i := 1; i < len(rows); i++ {
		if prev, cur := rows[i-1], rows[i]; !prev.hi.Less(cur.lo) {
			return fmt.Errorf("overlapping ranges %s and %s: expected a disjoint table", prev, cur)
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
