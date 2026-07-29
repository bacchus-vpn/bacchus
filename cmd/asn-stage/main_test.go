package main

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// asn-stage's tests, and why they are the load-bearing ones in this change.
//
// The committed table is 700,000 rows nobody reviews by eye. What a reviewer CAN
// check is the transform that produced it, so the properties ADR-0044 requires are
// asserted here, on inputs small enough to read:
//
//   - unrouted space becomes a GAP, never a neighbour's AS (§6, and the reason §3's
//     unknown-pooling means anything);
//   - the output is DISJOINT (§2, which asn.Load enforces and this must not rely on);
//   - ranges become the minimal set of aligned CIDR prefixes, host bits clear.
//
// Every address here is documentation space (RFC 5737 / RFC 3849) and every AS is a
// documentation AS (RFC 5398), matching core/asn/testdata's rule. The transform does
// not care what the numbers mean, so there is no reason to use real ones.

// stage runs the whole pipeline over a feed literal and returns the emitted rows.
func stage(t *testing.T, feed string) []prefixAS {
	t.Helper()
	ranges, _, err := parse(strings.NewReader(feed), "both")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return toPrefixes(merge(ranges))
}

// lines renders emitted rows in the committed table's own format, for assertions
// that read the way the file does.
func lines(rows []prefixAS) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.p.String()+"\t"+itoa(r.as))
	}
	return out
}

func itoa(u uint32) string {
	var b [10]byte
	i := len(b)
	if u == 0 {
		return "0"
	}
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d rows %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("row %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRangeBecomesAlignedCIDRs is the arithmetic: an arbitrary inclusive range
// decomposes into aligned blocks, and a range that is already one block stays one.
func TestRangeBecomesAlignedCIDRs(t *testing.T) {
	// A clean /24.
	eq(t, lines(stage(t, "192.0.2.0\t192.0.2.255\t64496\tZZ\tdoc\n")), "192.0.2.0/24\t64496")

	// A clean /26.
	eq(t, lines(stage(t, "192.0.2.0\t192.0.2.63\t64496\tZZ\tdoc\n")), "192.0.2.0/26\t64496")

	// A range that is NOT a single block: 192.0.2.1–192.0.2.6 is
	// .1/32 + .2/31 + .4/31 + .6/32. Both bounds of the greedy split are exercised —
	// alignment at the start, magnitude at the end.
	eq(t, lines(stage(t, "192.0.2.1\t192.0.2.6\t64496\tZZ\tdoc\n")),
		"192.0.2.1/32\t64496",
		"192.0.2.2/31\t64496",
		"192.0.2.4/31\t64496",
		"192.0.2.6/32\t64496")

	// A single address.
	eq(t, lines(stage(t, "192.0.2.7\t192.0.2.7\t64497\tZZ\tdoc\n")), "192.0.2.7/32\t64497")
}

// TestEmittedPrefixesHaveHostBitsClear pins the property asn.Read rejects a file
// for. A split that got alignment wrong would emit something like 192.0.2.1/24,
// which Read refuses with "has host bits set" — at a client, at connect time.
func TestEmittedPrefixesHaveHostBitsClear(t *testing.T) {
	rows := stage(t, "192.0.2.1\t198.51.100.77\t64496\tZZ\tdoc\n2001:db8::1\t2001:db8::ffff\t64498\tZZ\tdoc\n")
	if len(rows) == 0 {
		t.Fatal("no rows emitted")
	}
	for _, r := range rows {
		if r.p != r.p.Masked() {
			t.Errorf("%s has host bits set", r.p)
		}
	}
}

// TestUnroutedSpaceBecomesAGap is the correctness-critical one, and the reason this
// transform is a reviewed tool rather than a script.
//
// Two ranges in the SAME AS with unrouted space between them must NOT merge. If they
// did, every address in the gap would resolve to that AS — a hop inheriting a
// neighbour's AS, which is precisely what ADR-0044 §6 required gaps to prevent and
// what §3's unknown-pooling assumes cannot happen.
//
// Mutation: drop the `next(prev.hi) == cur.lo` term from merge's condition — so it
// joins on same-AS alone — and this fails, with the two ranges collapsing into one
// 192.0.2.0/25-and-more span that swallows the unrouted middle.
//
// Note which term that is. Removing the unrouted rows EARLIER does not break this,
// and the tool was first written as though it would: adjacency is arithmetic on
// addresses, and the gap defeats the merge by occupying them. The address test is the
// guard; the marker rows never were.
func TestUnroutedSpaceBecomesAGap(t *testing.T) {
	rows := stage(t, strings.Join([]string{
		"192.0.2.0\t192.0.2.63\t64496\tZZ\tdoc",
		"192.0.2.64\t192.0.2.127\t0\tNone\tNot routed",
		"192.0.2.128\t192.0.2.191\t64496\tZZ\tdoc", // same AS, other side of the gap
		"",
	}, "\n"))
	eq(t, lines(rows), "192.0.2.0/26\t64496", "192.0.2.128/26\t64496")

	// And the gap really is unresolvable: no emitted prefix contains an address in it.
	gap := netip.MustParseAddr("192.0.2.100")
	for _, r := range rows {
		if r.p.Contains(gap) {
			t.Fatalf("%s covers %s, which upstream marks unrouted", r.p, gap)
		}
	}
}

// TestAdjacentSameASRangesMerge is the other half: where there is NO gap, adjacent
// same-AS ranges must join, because merging before splitting is what keeps the output
// from being needlessly larger than it has to be.
func TestAdjacentSameASRangesMerge(t *testing.T) {
	// .0–.127 and .128–.255 are adjacent and share an AS: one /24, not two /25s.
	eq(t, lines(stage(t, strings.Join([]string{
		"192.0.2.0\t192.0.2.127\t64496\tZZ\tdoc",
		"192.0.2.128\t192.0.2.255\t64496\tZZ\tdoc",
		"",
	}, "\n"))), "192.0.2.0/24\t64496")
}

// TestAdjacentDifferentASRangesDoNotMerge guards the obvious inverse. Merging on
// adjacency alone would erase the boundary between two operators, which is the one
// distinction the whole table exists to record.
func TestAdjacentDifferentASRangesDoNotMerge(t *testing.T) {
	eq(t, lines(stage(t, strings.Join([]string{
		"192.0.2.0\t192.0.2.127\t64496\tZZ\tdoc",
		"192.0.2.128\t192.0.2.255\t64497\tZZ\tdoc",
		"",
	}, "\n"))), "192.0.2.0/25\t64496", "192.0.2.128/25\t64497")
}

// TestIPv6RangesStage covers the family that shares every code path but the width,
// including that a v6 range adjacent to a v4 one never merges across families.
func TestIPv6RangesStage(t *testing.T) {
	eq(t, lines(stage(t, strings.Join([]string{
		"2001:db8::\t2001:db8:0:ffff:ffff:ffff:ffff:ffff\t64498\tZZ\tdoc",
		"",
	}, "\n"))), "2001:db8::/48\t64498")

	// Mixed input keeps both families and does not merge across them.
	rows := stage(t, strings.Join([]string{
		"192.0.2.0\t192.0.2.255\t64496\tZZ\tdoc",
		"2001:db8::\t2001:db8::ffff\t64496\tZZ\tdoc",
		"",
	}, "\n"))
	eq(t, lines(rows), "192.0.2.0/24\t64496", "2001:db8::/112\t64496")
}

// TestAS0IsNeverEmitted states the invariant asn.Read enforces from the other side:
// AS0 is reserved (RFC 7607) and Read rejects any row carrying it, so a table with
// one would fail to load at a client.
func TestAS0IsNeverEmitted(t *testing.T) {
	rows := stage(t, strings.Join([]string{
		"192.0.2.0\t192.0.2.63\t0\tNone\tNot routed",
		"192.0.2.64\t192.0.2.127\t64496\tZZ\tdoc",
		"198.51.100.0\t198.51.100.255\t0\tNone\tNot routed",
		"",
	}, "\n"))
	eq(t, lines(rows), "192.0.2.64/26\t64496")
	for _, r := range rows {
		if r.as == 0 {
			t.Errorf("emitted %s with AS0", r.p)
		}
	}
}

// TestWriteRejectsOverlapAndDisorder proves write's guard is real, by handing it rows
// the transform would never produce. §2's disjointness requirement is enforced at
// load by asn.Read; catching it here names the transform instead of naming a file in
// a client at connect time.
func TestWriteRejectsOverlapAndDisorder(t *testing.T) {
	overlapping := []prefixAS{
		{p: netip.MustParsePrefix("192.0.2.0/24"), as: 64496},
		{p: netip.MustParsePrefix("192.0.2.128/25"), as: 64497}, // nested inside the /24
	}
	if err := write(new(bytes.Buffer), overlapping); err == nil {
		t.Error("write accepted overlapping prefixes; asn.Load would have rejected the file it produced")
	}
	misordered := []prefixAS{
		{p: netip.MustParsePrefix("198.51.100.0/24"), as: 64496},
		{p: netip.MustParsePrefix("192.0.2.0/24"), as: 64497},
	}
	if err := write(new(bytes.Buffer), misordered); err == nil {
		t.Error("write accepted out-of-order prefixes")
	}
	withAS0 := []prefixAS{{p: netip.MustParsePrefix("192.0.2.0/24"), as: 0}}
	if err := write(new(bytes.Buffer), withAS0); err == nil {
		t.Error("write accepted an AS0 row")
	}
}

// TestParseRejectsMalformedInput covers the failures a refresh would actually hit:
// the wrong file, a truncated download, a feed that changed shape.
func TestParseRejectsMalformedInput(t *testing.T) {
	for name, feed := range map[string]string{
		"too few columns":  "192.0.2.0\t192.0.2.255\n",
		"bad start":        "not-an-ip\t192.0.2.255\t64496\tZZ\tdoc\n",
		"bad end":          "192.0.2.0\tnot-an-ip\t64496\tZZ\tdoc\n",
		"bad asn":          "192.0.2.0\t192.0.2.255\tnope\tZZ\tdoc\n",
		"reversed range":   "192.0.2.255\t192.0.2.0\t64496\tZZ\tdoc\n",
		"mixed families":   "192.0.2.0\t2001:db8::1\t64496\tZZ\tdoc\n",
		"no routed row":    "192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n",
		"empty":            "",
		"asn out of range": "192.0.2.0\t192.0.2.255\t4294967296\tZZ\tdoc\n",
	} {
		if _, _, err := parse(strings.NewReader(feed), "both"); err == nil {
			t.Errorf("%s: parse accepted it", name)
		}
	}
}

// TestParseToleratesFreeTextDescriptions is a real-feed property, not a hypothetical:
// AS descriptions carry commas, quotes, colons and stray whitespace, and a row must
// survive all of it because only the first three columns are ever read.
func TestParseToleratesFreeTextDescriptions(t *testing.T) {
	eq(t, lines(stage(t, "192.0.2.0\t192.0.2.255\t64496\tZZ\tSOME-AS, \"quoted\", Contact: noc@example\textra\n")),
		"192.0.2.0/24\t64496")
}

// TestFamilyFilter covers -family. ADR-0044's second amendment §2 declined the
// IPv4-only reduction on measurement (0.65 MB saved, every IPv6 hop blinded), so this
// covers a diagnostic switch rather than a shipping configuration — both families ship.
func TestFamilyFilter(t *testing.T) {
	feed := strings.Join([]string{
		"192.0.2.0\t192.0.2.255\t64496\tZZ\tdoc",
		"2001:db8::\t2001:db8::ffff\t64498\tZZ\tdoc",
		"",
	}, "\n")
	for family, want := range map[string]string{
		"v4": "192.0.2.0/24\t64496",
		"v6": "2001:db8::/112\t64498",
	} {
		ranges, _, err := parse(strings.NewReader(feed), family)
		if err != nil {
			t.Fatalf("%s: parse: %v", family, err)
		}
		eq(t, lines(toPrefixes(merge(ranges))), want)
	}
}

// TestRunIsDeterministic is what makes "the table is committed, not fetched at build
// time" reviewable at all: a reviewer re-runs the transform against the same feed and
// compares bytes. If the output moved between runs — a map iteration leaking into
// ordering, a timestamp in the gzip header — that check would be impossible and every
// refresh would show a diff nobody could verify.
func TestRunIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.tsv")
	if err := os.WriteFile(feed, []byte(strings.Join([]string{
		"192.0.2.0\t192.0.2.63\t64496\tZZ\tdoc",
		"192.0.2.64\t192.0.2.127\t0\tNone\tNot routed",
		"192.0.2.128\t192.0.2.191\t64497\tZZ\tdoc",
		"2001:db8::\t2001:db8::ffff\t64498\tZZ\tdoc",
		"",
	}, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	var runs [2][]byte
	for i := range runs {
		out := filepath.Join(dir, "out.tsv.gz")
		if err := run(feed, out, true, "both"); err != nil {
			t.Fatalf("run: %v", err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		runs[i] = b
	}
	if !bytes.Equal(runs[0], runs[1]) {
		t.Error("two runs over one input produced different bytes; the refresh is not reproducible")
	}

	// And the gzip really does hold the table, in the format asn.Read parses.
	zr, err := gzip.NewReader(bytes.NewReader(runs[0]))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	got, err := readAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	want := "192.0.2.0/26\t64496\n192.0.2.128/26\t64497\n2001:db8::/112\t64498\n"
	if got != want {
		t.Errorf("staged table:\n%q\nwant:\n%q", got, want)
	}
}

func readAll(r interface{ Read([]byte) (int, error) }) (string, error) {
	var b bytes.Buffer
	if _, err := b.ReadFrom(r); err != nil {
		return "", err
	}
	return b.String(), nil
}
