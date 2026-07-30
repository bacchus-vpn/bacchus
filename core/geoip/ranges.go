package geoip

// This file holds the loader for the RANGE-format country database — iptoasn.com's
// IP-to-Country files, which is what this project stages (issue #61; the package doc
// records why). The MaxMind CSV loader lives in geoip.go. Both parse into the same
// in-memory table and both are wrapped by assemble, so neither can quietly acquire a
// weaker set of load-time checks than the other.

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Conventional filenames inside iptoasn.com's IP-to-Country distribution. LoadDir looks
// for exactly these, so an operator stages what upstream publishes under the names it
// publishes it under and does not have to rename anything.
//
// Upstream ships them gzipped (ip2country-v4.tsv.gz). This loader takes the decompressed
// file, so staging is a fetch and a gunzip — there is deliberately no decompression path
// here, because it would be a second way to read the same file and a second thing to
// keep tested, in exchange for one pipe in docs/RUNNING.md's staging command.
const (
	FileRangesV4 = "ip2country-v4.tsv"
	FileRangesV6 = "ip2country-v6.tsv"
)

// ccUnattributed is the ISO-3166-1 alpha-2 code an upstream feed carries for address
// space it can attribute to no country. Rows carrying it are skipped, not loaded.
//
// That is a correctness choice rather than tidiness. ZZ is user-assigned in ISO-3166-1
// and conventionally means "unknown", so it is an absence of information wearing the
// shape of an answer. Loading it would do two bad things: it would put a selectable
// pseudo-country in the table, and — worse — it would make an address in unattributed
// space RESOLVE, which under deriveCountry's precedence rule beats the node's own hint.
// The result would be a confident wrong answer in exactly the case where the honest
// answer is "no idea". An absence is represented as a gap, which resolves to unknown and
// lets the caller fall back.
const ccUnattributed = "ZZ"

// LoadRanges reads a database from iptoasn.com's IP-to-Country range files. Either path
// may be empty to skip that address family, which is how a deployment with no IPv6 nodes
// avoids paying for the v6 table.
//
// Upstream publishes the two families as separate files, which is why this takes two
// paths and not one: there is no combined country export to split.
func LoadRanges(rangesV4Path, rangesV6Path string) (*DB, error) {
	return assemble(SourceRanges, "ranges", readRanges, rangesV4Path, rangesV6Path)
}

// readRanges parses an IP-to-Country range file into range→country rows, keeping only
// rows whose addresses is() accepts (so a v6 row in the v4 file is skipped rather than
// filed into the wrong table, where it would corrupt the sort order the binary search
// depends on).
//
// The format is one `range_start<TAB>range_end<TAB>country_code` row per line, with
// INCLUSIVE bounds and no header. `#` begins a comment and blank lines are ignored,
// neither of which upstream emits — they are for the fixtures, which need to explain
// themselves, exactly as core/asn's table format does.
//
// # Why a malformed row is fatal here when readBlocks skips one
//
// The two loaders draw the line in different places, deliberately. MaxMind's blocks file
// legitimately contains rows this package cannot use — the other family's, and ranges
// attributed to no country — so readBlocks counts them and moves on. In a range file the
// only legitimate skips are those same two cases; an unparseable address, a range that
// mixes families, and an end before its start are things upstream does not publish, so
// each means a corrupt file or the wrong file altogether.
//
// Skipping past that would load PART of a table and report success, and a partially
// loaded country table is the specific failure this package exists to remove: every
// address in the missing ranges falls back to the node's own self-reported country, with
// nothing failing visibly (issue #136). So structural damage is fatal and semantic
// absence is a gap — the same split asn.Read draws for the AS table.
//
// The exact field count earns its strictness on the likeliest staging mistake of all:
// upstream publishes the IP-to-ASN files from the same page, in the same shape, with five
// columns. Staged under a country filename, every row of one fails here on line 1 with the
// count named, rather than loading with the AS number read as a country code.
func readRanges(r io.Reader, is func(netip.Addr) bool) (out []block, skipped int, err error) {
	sc := bufio.NewScanner(r)
	// Upstream rows are short, but a scanner that stops at the default 64 KiB limit
	// reports a truncated table as a clean EOF, which is the silent-partial-load failure
	// above. Raise the ceiling so an over-long line is an error rather than an ending.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	intern := map[string]string{}
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		if text = strings.TrimSpace(text); text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, 0, fmt.Errorf("line %d: want `range_start range_end country_code`, got %d field(s)", line, len(fields))
		}
		lo, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, 0, fmt.Errorf("line %d: range start %q: %w", line, fields[0], err)
		}
		hi, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, 0, fmt.Errorf("line %d: range end %q: %w", line, fields[1], err)
		}
		// Unmap before anything else: a v4-mapped v6 literal (::ffff:192.0.2.1) must
		// land in the v4 table, and Lookup unmaps too, so the two agree on which table
		// an address belongs to.
		lo, hi = lo.Unmap(), hi.Unmap()
		if lo.Is4() != hi.Is4() {
			return nil, 0, fmt.Errorf("line %d: range %s–%s mixes address families", line, lo, hi)
		}
		if hi.Less(lo) {
			return nil, 0, fmt.Errorf("line %d: range end %s precedes start %s", line, hi, lo)
		}
		if !is(lo) {
			skipped++
			continue
		}
		cc := Canonical(fields[2])
		if cc == "" || cc == ccUnattributed {
			skipped++
			continue
		}
		// Intern the code: there are ~250 distinct values across a few hundred thousand
		// rows, so sharing the strings costs a couple of KB instead of tens of MB.
		if s, ok := intern[cc]; ok {
			cc = s
		} else {
			intern[cc] = cc
		}
		out = append(out, block{lo: lo, hi: hi, cc: cc})
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	sortBlocks(out)
	return out, skipped, nil
}
