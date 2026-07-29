// asn-stage turns a published IP→ASN *range* feed into the disjoint CIDR-prefix
// table core/asn loads, and is the tool the per-release refresh runs.
//
// It exists because ADR-0044 pushed two obligations into staging and then committed
// the output. §2 requires prefixes that are DISJOINT — `asn.Load` rejects a file
// where they are not — and the amendment's "the table is committed, not fetched at
// build time" makes the transform that produced it something a reviewer has to be
// able to re-run and compare. A one-off local script satisfies neither: it cannot be
// reviewed, and "refreshed per release" is a step someone performs repeatedly.
//
// # What it does, and the one rule that matters
//
// The upstream feed is a sorted list of address RANGES covering the whole space,
// routed spans interleaved with explicit `0 / Not routed` markers. This tool:
//
//  1. drops every column but the range and the AS — country and description are
//     unused by core/asn and are the bulk of the bytes;
//  2. drops the unrouted markers, turning them into GAPS;
//  3. merges runs that are genuinely adjacent AND share an AS;
//  4. splits each surviving range into the minimal set of aligned CIDR prefixes.
//
// **Step 2 is the correctness-critical one, and dropping is what keeps it correct.**
// core/asn resolves an address by containment, so an address in a gap matches no
// prefix and returns *unknown* — which is exactly what an unrouted address should
// return. The alternative, carrying the marker as a row, is not available and should
// not be: `asn.Load` rejects AS0 outright (RFC 7607), and its error says why —
// "omit the row instead — an address the table does not cover is already unknown".
// ADR-0044 §6 measured a form that kept explicit markers because a delta-varint
// encoding is a run of contiguous spans and needs something to break the run. A
// prefix table does not: gaps are free and implicit.
//
// Step 3 must never merge ACROSS a gap. Two same-AS ranges either side of unrouted
// space are not one span, and joining them would announce an AS over address space
// nobody announces — a lookup inheriting a neighbour's AS, which is the failure
// ADR-0044 §6 named when it said gaps must stay explicit. Adjacency is therefore
// tested on ADDRESSES (end+1 == next.start), which the unrouted span itself defeats
// by occupying the addresses between them. See merge for why that makes carrying the
// markers past step 2 unnecessary.
//
// # Usage
//
//	curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
//	go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip
//
// The download is deliberately NOT this tool's job. Keeping the fetch a separate,
// documented step is what leaves the transform hermetic — it reads a local file and
// writes a file, so re-running it on the same input reproduces the same bytes, and a
// reviewer can check the committed table against a feed they fetched themselves. See
// docs/RUNNING.md ("Refreshing the IP→AS table").
//
// The input's terms are the caller's responsibility and this tool does not assert
// them. The source Bacchus ships is iptoasn.com's combined feed under PDDL v1.0 —
// public domain, redistribution permitted, no attribution required — which is what
// makes the output committable to an AGPL-3.0 repository at all. ADR-0044's second
// amendment records that; core/asn/TABLE.md records it beside the data.
package main

import (
	"bufio"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func main() {
	in := flag.String("in", "", "upstream range feed, `path` to .tsv or .tsv.gz (required)")
	out := flag.String("out", "", "staged table `path`; empty writes to stdout")
	gz := flag.Bool("gzip", false, "gzip the output (best compression)")
	family := flag.String("family", "both", "which families to emit: `both`, v4, or v6")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "asn-stage: -in is required")
		flag.Usage()
		os.Exit(2)
	}
	if *family != "both" && *family != "v4" && *family != "v6" {
		fmt.Fprintf(os.Stderr, "asn-stage: -family must be both, v4 or v6, got %q\n", *family)
		os.Exit(2)
	}
	if err := run(*in, *out, *gz, *family); err != nil {
		fmt.Fprintln(os.Stderr, "asn-stage:", err)
		os.Exit(1)
	}
}

func run(inPath, outPath string, gz bool, family string) error {
	f, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = bufio.NewReaderSize(f, 1<<20)
	if strings.HasSuffix(inPath, ".gz") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return fmt.Errorf("read %s: %w", inPath, err)
		}
		defer zr.Close()
		r = zr
	}

	ranges, stat, err := parse(r, family)
	if err != nil {
		return err
	}
	merged := merge(ranges)
	rows := toPrefixes(merged)

	w := io.Writer(os.Stdout)
	var closers []io.Closer
	if outPath != "" {
		of, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer of.Close()
		w = of
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	w = bw
	if gz {
		// BestCompression, not the default: this output is written once per release
		// and read by every client that ever downloads the binary, so spending the
		// compressor's time here is free and the bytes it saves are not.
		zw, err := gzip.NewWriterLevel(bw, gzip.BestCompression)
		if err != nil {
			return err
		}
		closers = append(closers, zw)
		w = zw
	}
	if err := write(w, rows); err != nil {
		return err
	}
	for _, c := range closers {
		if err := c.Close(); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr,
		"asn-stage: %d upstream rows (%d routed, %d unrouted) → %d merged ranges → %d prefixes; %d distinct ASNs\n",
		stat.rows, stat.routed, stat.unrouted, len(merged), len(rows), stat.asns())
	return nil
}

// rng is one upstream row reduced to the only three things that survive: the
// inclusive range bounds and the AS announcing them. as == 0 marks unrouted space
// and is carried through parsing ONLY so merge can see that it breaks adjacency;
// no such row is ever emitted.
type rng struct {
	lo, hi netip.Addr
	as     uint32
}

type stats struct {
	rows, routed, unrouted int
	seen                   map[uint32]struct{}
}

func (s *stats) asns() int { return len(s.seen) }

// parse reads the upstream feed. The expected shape is iptoasn.com's combined
// export: `range_start<TAB>range_end<TAB>AS_number<TAB>country<TAB>description`.
//
// Only the first three columns are read, and the trailing two are not merely
// ignored but must be tolerated in any form: AS descriptions are free text that
// routinely contain commas, quotes and even tab-adjacent whitespace, so the row is
// split into at most 4 pieces and everything past the AS number is discarded
// untouched. Parsing it would be work in service of nothing.
func parse(r io.Reader, family string) ([]rng, stats, error) {
	st := stats{seen: map[uint32]struct{}{}}
	var out []rng
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimRight(sc.Text(), "\r")
		if text == "" {
			continue
		}
		fields := strings.SplitN(text, "\t", 4)
		if len(fields) < 3 {
			return nil, st, fmt.Errorf("line %d: want at least 3 tab-separated columns, got %d", line, len(fields))
		}
		lo, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, st, fmt.Errorf("line %d: range start %q: %w", line, fields[0], err)
		}
		hi, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, st, fmt.Errorf("line %d: range end %q: %w", line, fields[1], err)
		}
		lo, hi = lo.Unmap(), hi.Unmap()
		if lo.Is4() != hi.Is4() {
			return nil, st, fmt.Errorf("line %d: range %s–%s mixes address families", line, lo, hi)
		}
		if hi.Less(lo) {
			return nil, st, fmt.Errorf("line %d: range end %s precedes start %s", line, hi, lo)
		}
		as64, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return nil, st, fmt.Errorf("line %d: AS number %q: %w", line, fields[2], err)
		}
		st.rows++
		if as64 == 0 {
			st.unrouted++
		} else {
			st.routed++
			st.seen[uint32(as64)] = struct{}{}
		}
		if (family == "v4" && !lo.Is4()) || (family == "v6" && lo.Is4()) {
			continue
		}
		out = append(out, rng{lo: lo, hi: hi, as: uint32(as64)})
	}
	if err := sc.Err(); err != nil {
		return nil, st, err
	}
	if st.routed == 0 {
		return nil, st, errors.New("input holds no routed row; is this the right feed?")
	}
	return out, st, nil
}

// merge drops the unrouted rows and joins runs that are BOTH adjacent and same-AS.
//
// # Why dropping the markers first is safe
//
// It looks like it should not be. Two same-AS ranges either side of unrouted space
// must never collapse into one span, because that span would announce an AS across
// address space nobody announces — a lookup inheriting a neighbour's AS, the failure
// ADR-0044 §6 required gaps to prevent.
//
// What prevents it is that adjacency is tested on ADDRESSES, not on row order:
// `next(prev.hi) == cur.lo`. Upstream ranges are disjoint and sorted, so an unrouted
// span BETWEEN two ranges occupies addresses, which is precisely what makes those two
// ranges numerically non-adjacent. The gap defeats the merge whether or not its
// marker row is still in hand — and conversely, two ranges that ARE numerically
// adjacent have no room between them for a marker to have been dropped from.
//
// So no sentinel is needed and none is kept. This was written the other way first,
// carrying AS0 rows through the loop to "break the run"; the tests pass identically
// without them, because the arithmetic was doing the work the whole time.
//
// The input is required to be sorted within a family, which the upstream feed is;
// write verifies the result rather than trusting it.
func merge(in []rng) []rng {
	var out []rng
	for _, cur := range in {
		if cur.as == 0 {
			continue // unrouted: becomes a gap, which resolves to unknown
		}
		if n := len(out); n > 0 {
			prev := &out[n-1]
			if prev.as == cur.as && prev.lo.Is4() == cur.lo.Is4() && next(prev.hi) == cur.lo {
				prev.hi = cur.hi
				continue
			}
		}
		out = append(out, cur)
	}
	return out
}

// toPrefixes splits every range into the minimal set of aligned CIDR prefixes, in
// order, and is where the range form becomes the form core/asn loads.
func toPrefixes(in []rng) []prefixAS {
	out := make([]prefixAS, 0, len(in)*2)
	for _, r := range in {
		out = appendRangeCIDRs(out, r)
	}
	return out
}

// prefixAS is one emitted row: a prefix and the AS announcing it.
type prefixAS struct {
	p  netip.Prefix
	as uint32
}

// appendRangeCIDRs decomposes one inclusive range into aligned CIDR blocks.
//
// The standard greedy split: at each step take the largest block that is both
// ALIGNED at the current position (bounded by the trailing zero bits of the address)
// and no larger than what remains (bounded by the span's magnitude). Both bounds are
// necessary — the first alone overshoots the end, the second alone emits a prefix
// whose host bits are set, which asn.Read rejects by design.
//
// big.Int carries the arithmetic so v4 and v6 run the same code path. The tool runs
// once per release over a few hundred thousand ranges, so the cost is irrelevant and
// one uniform implementation is worth more than two fast ones.
func appendRangeCIDRs(out []prefixAS, r rng) []prefixAS {
	bitLen := 128
	if r.lo.Is4() {
		bitLen = 32
	}
	cur := new(big.Int).SetBytes(r.lo.AsSlice())
	end := new(big.Int).SetBytes(r.hi.AsSlice())
	one := big.NewInt(1)

	for cur.Cmp(end) <= 0 {
		// How large a block may start here without misaligning: the number of
		// trailing zero bits. Zero itself aligns to everything.
		align := bitLen
		if cur.Sign() != 0 {
			align = trailingZeros(cur, bitLen)
		}
		// How large a block fits in what remains: 2^k <= (end - cur + 1).
		span := new(big.Int).Sub(end, cur)
		span.Add(span, one)
		fit := span.BitLen() - 1

		size := min(align, fit)
		ones := bitLen - size
		addr, _ := netip.AddrFromSlice(leftPad(cur.Bytes(), bitLen/8))
		out = append(out, prefixAS{p: netip.PrefixFrom(addr.Unmap(), ones), as: r.as})

		step := new(big.Int).Lsh(one, uint(size))
		cur = new(big.Int).Add(cur, step)
	}
	return out
}

// trailingZeros counts the trailing zero bits of a positive big.Int, capped at
// bitLen. big.Int has no direct accessor, so it is read off the low words.
func trailingZeros(x *big.Int, bitLen int) int {
	n := 0
	for _, w := range x.Bits() {
		if w == 0 {
			n += bits.UintSize
			continue
		}
		n += bits.TrailingZeros(uint(w))
		break
	}
	return min(n, bitLen)
}

// leftPad zero-extends a big.Int's minimal big-endian bytes to a fixed width, which
// is what netip.AddrFromSlice needs to infer the family.
func leftPad(b []byte, width int) []byte {
	if len(b) >= width {
		return b[len(b)-width:]
	}
	p := make([]byte, width)
	copy(p[width-len(b):], b)
	return p
}

// next returns the address one above a, or the zero Addr at the end of a family.
// Used only for the adjacency test, where the wrap cannot arise: the feed's last
// range ends at the top of its family and has no successor to be adjacent to.
func next(a netip.Addr) netip.Addr { return a.Next() }

// write emits the staged table, and verifies on the way out that what it is about to
// write is a table core/asn will accept.
//
// The checks duplicate asn.Read's, deliberately. A malformed table caught here names
// the transform that produced it; caught at load it names a file, in a client, at
// connect time. The expensive one is disjointness, which is what §2 requires and
// what a bug in the CIDR split would break — and it is checked in one pass because
// the output is already ordered.
func write(w io.Writer, rows []prefixAS) error {
	var lastV4, lastV6 netip.Prefix
	for _, r := range rows {
		if r.as == 0 {
			return fmt.Errorf("internal: emitted %s with AS0, which asn.Read rejects", r.p)
		}
		if r.p != r.p.Masked() {
			return fmt.Errorf("internal: emitted %s with host bits set", r.p)
		}
		last := &lastV6
		if r.p.Addr().Is4() {
			last = &lastV4
		}
		if last.IsValid() {
			if r.p.Addr().Less(last.Addr()) {
				return fmt.Errorf("internal: emitted %s after %s, out of order", r.p, *last)
			}
			if last.Contains(r.p.Addr()) {
				return fmt.Errorf("internal: emitted %s overlapping %s", r.p, *last)
			}
		}
		*last = r.p
		if _, err := fmt.Fprintf(w, "%s\t%d\n", r.p, r.as); err != nil {
			return err
		}
	}
	return nil
}
