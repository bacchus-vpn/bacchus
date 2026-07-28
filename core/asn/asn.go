// Package asn resolves an observed IP address to the autonomous system that
// announces it, from a table staged on local disk, with no network access of any
// kind.
//
// It exists for issue #23. Relay chaining picks hops for network diversity, and the
// only diversity that means anything is AS diversity: controlling the FIRST and LAST
// hop of a chain re-links client to exit, and two hops in one AS are one operator's
// hops however they are labelled. The AS a node sits in is therefore a security
// input, and it is deliberately NOT carried in the signed directory — neither a node
// nor a coordinator can be trusted to assert an AS number, because a Sybil operator
// asked to state its own diversity would simply fabricate it (the ADR-0038 #124
// amendment says so explicitly). The number has to be DERIVED, by the party relying
// on it, from an address it did not choose.
//
// That derivation is what this package is. It is the same rule the rest of the
// system already follows for observed addresses — coldstart.Entry.Ingress (#124),
// the coordinator's derived country (#136, core/geoip), and capacity's observedAS
// (#158): an observed address is trusted, a claimed one is not.
//
// # Why local, never a lookup service
//
// An outbound whois/RDAP/route-lookup call would tell a third party the IP of every
// node a client is about to build a chain through — which is the one correlation
// this whole subsystem exists to deny — and would add a dependency on reaching a
// foreign endpoint from inside a censored network. There is no fetch path in this
// package, on purpose: nothing here can ever make a network call. How the table
// GETS to disk is a separate question, and an open one — see ADR-0044.
//
// # Table format
//
// One `prefix<TAB>asn` row per line; `#` begins a comment; blank lines are ignored.
// Prefixes must be DISJOINT, and Load rejects a file where they are not.
//
// Disjointness is a real constraint on the input, not a simplification, and it is
// worth being plain about what it costs. A BGP table as observed carries
// more-specifics: a /16 announced by one AS with a /24 inside it announced by
// another. Resolving that needs a longest-prefix match, which is a slower lookup and
// a more intricate one to audit. Flattening those overlaps into disjoint spans is a
// mechanical transform that belongs in whatever stages the table — it is the same
// shape the widely published IP→ASN range datasets already ship in — so this package
// takes the flattened form and verifies it, rather than carrying a longest-prefix
// implementation that every reader of this file would have to check. Load fails
// loudly on an unflattened file instead of silently resolving to whichever row it
// happened to hit first.
//
// The text format, rather than a packed binary one, follows core/geoip's reasoning:
// it needs no decoder, the whole parse is auditable in one screen, and a fixture is
// readable by anyone reviewing a diversity test. ADR-0044 records what the compact
// encodings measure at, for the distribution decision that has not been made yet.
package asn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

// AS is an autonomous system number.
//
// The zero value is not a valid AS: AS0 is reserved and must never appear in a
// routing announcement (RFC 7607), so it cannot collide with a real answer. That
// makes it a safe zero, but it is NOT the way to test for one — every lookup returns
// an explicit ok bool, and that bool is the contract. See Lookup.
type AS uint32

// String renders an AS in the conventional "AS13335" form.
//
// The prefix is not decoration. This string is used as a diversity KEY by callers
// that also have a non-AS fallback key to place (cmd/coordinator's observedAS falls
// back to a masked prefix like "192.0.2.0/24" when no table is staged), and a bare
// number would sit in the same namespace as those. Keeping the two forms
// syntactically disjoint means a resolved answer and a fallback answer can never be
// mistaken for one another by a consumer that only sees the string.
func (a AS) String() string { return "AS" + strconv.FormatUint(uint64(a), 10) }

// Lookup resolves an observed IP address to the AS that announces it.
//
// It is the seam issue #23 asks for, and the only thing either consumer depends on.
// Relay-chain hop selection (core/relaychain.go) and the coordinator's capacity
// attestation (cmd/coordinator/capacity_feed.go) both hold one of these and neither
// knows, or can know, where the table behind it came from — which is the point,
// because how the table ships and refreshes is an open decision (ADR-0044). When it
// is made, it changes the implementation here and nothing at either call site.
//
// # The unknown answer is part of the contract
//
// ok is false when this lookup has no answer: no table loaded, an address absent
// from the table, or an address no AS can announce (loopback, RFC1918, link-local,
// multicast). A caller MUST be able to tell that apart from a resolved AS, and MUST
// NOT treat it as "diverse from everything" — an unknown that counts as distinct
// hands a Sybil operator free diversity for the cost of using address space the
// table does not cover, which inverts the control it is feeding. Callers pool
// unknowns into a single bucket instead, so two unresolved hops collide with each
// other; core/relaychain.go's selectHops documents that at the point it does it.
type Lookup interface {
	LookupAS(ip netip.Addr) (AS, bool)
}

// span is one contiguous prefix mapped to an AS.
type span struct {
	p  netip.Prefix
	as AS
}

// Table is an immutable IP→AS table and the file-backed implementation of Lookup.
//
// It is safe for concurrent use: nothing mutates after Load returns, so a chain
// build or a packet loop can read it without a lock. Refresh by building a new Table
// and swapping the pointer, exactly as core/geoip is refreshed.
//
// Every method is nil-safe, and a nil *Table is a meaningful value: it is a lookup
// that resolves nothing. That is what makes "no table staged" behave as "every
// address is unknown" rather than as a crash, and it is the state the client ships
// in today — see ADR-0044 on why the client cannot have a table until the
// distribution question is answered.
type Table struct {
	// v4 and v6 are each sorted by network address and verified DISJOINT at load
	// (see validate). Disjointness is what lets LookupAS be a single binary search
	// plus one containment check rather than a longest-prefix walk; it is enforced
	// rather than assumed, because a file that overlaps is one this package would
	// otherwise resolve by accident of ordering.
	v4, v6 []span

	// Rows is how many data rows were read, across both families. Surfaced so a
	// caller can log what it actually loaded — the only evidence an operator gets
	// that the staged table is the one they meant.
	Rows int
}

// Compile-time proof that the file-backed table satisfies the seam. If this ever
// stops holding, it fails here rather than at whichever call site is unlucky.
var _ Lookup = (*Table)(nil)

// ErrEmpty reports a table that parsed without error but holds no usable row.
//
// It is a distinct error because it is a distinct operator mistake — a path that
// pointed at the wrong file, or at a file whose rows were all comments — and it must
// not be reachable by accident: a Table that loaded "successfully" with zero rows
// resolves every address to unknown, which is silently indistinguishable from
// staging nothing at all. A caller that wants that behaviour gets it by not staging
// a table, not by staging an empty one.
var ErrEmpty = errors.New("asn: table holds no usable rows")

// Load reads a table from the file at path.
func Load(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("asn: open table: %w", err)
	}
	defer f.Close()
	t, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("asn: table %s: %w", path, err)
	}
	return t, nil
}

// Read parses a table from r. Load is Read against a file; this form is what a test
// (and any future non-file distribution) uses.
func Read(r io.Reader) (*Table, error) {
	t := &Table{}
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: want `prefix<TAB>asn`, got %d field(s)", line, len(fields))
		}
		p, err := netip.ParsePrefix(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: prefix %q: %w", line, fields[0], err)
		}
		// A prefix whose host bits are set (192.0.2.1/24) is a typo in every case
		// that matters, and silently masking it would map an address range the
		// author did not write. Masked() is compared rather than applied.
		if p != p.Masked() {
			return nil, fmt.Errorf("line %d: prefix %q has host bits set (did you mean %s?)", line, fields[0], p.Masked())
		}
		n, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: asn %q: %w", line, fields[1], err)
		}
		// AS0 is reserved and must never be announced (RFC 7607). A row carrying it
		// is either a placeholder or a bug, and admitting it would put a value in the
		// table that String() renders as "AS0" and that no caller can distinguish
		// from the zero value it also uses for "no answer".
		if n == 0 {
			return nil, fmt.Errorf("line %d: AS0 is reserved and cannot be announced (RFC 7607); omit the row instead — an address the table does not cover is already unknown", line)
		}
		s := span{p: p.Masked(), as: AS(n)}
		if p.Addr().Is4() {
			t.v4 = append(t.v4, s)
		} else {
			t.v6 = append(t.v6, s)
		}
		t.Rows++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if t.Rows == 0 {
		return nil, ErrEmpty
	}
	for _, tab := range []struct {
		rows []span
		fam  string
	}{{t.v4, "IPv4"}, {t.v6, "IPv6"}} {
		slices.SortFunc(tab.rows, func(a, b span) int { return a.p.Addr().Compare(b.p.Addr()) })
		if err := validate(tab.rows); err != nil {
			return nil, fmt.Errorf("%s: %w", tab.fam, err)
		}
	}
	return t, nil
}

// validate rejects a sorted family whose spans are not disjoint.
//
// Sorted by network address, an overlap can only be a row whose network address
// falls inside its predecessor's range — either a duplicate prefix or a
// more-specific nested in a less-specific. Both are rejected with the pair named,
// because "the table overlaps" is not something an operator can act on and "these
// two rows overlap" is.
func validate(rows []span) error {
	for i := 1; i < len(rows); i++ {
		prev, cur := rows[i-1], rows[i]
		if prev.p.Contains(cur.p.Addr()) {
			return fmt.Errorf("prefixes %s (AS%d) and %s (AS%d) overlap; the table must be flattened to disjoint spans before it is staged",
				prev.p, prev.as, cur.p, cur.as)
		}
	}
	return nil
}

// LookupAS resolves ip to the AS announcing it, or reports unknown.
//
// The three unknown conditions are deliberately collapsed into one answer, because a
// caller's response to all three is identical (pool it, never count it as diverse —
// see Lookup):
//
//   - The address is one no AS announces: loopback, RFC1918, link-local,
//     unspecified, or multicast. This is the ordinary case on a developer box and in
//     the local smoke stack, where every node registers from 127.0.0.1.
//   - The address is global but absent from the table.
//   - No table is loaded at all (a nil *Table).
//
// A v4-mapped v6 address (::ffff:a.b.c.d, which is what a dual-stack UDP socket
// hands back for a v4 peer) is unmapped first and resolved against the v4 table.
// Missing that is a silent whole-family failure, so it is done here rather than left
// to each caller to remember.
func (t *Table) LookupAS(ip netip.Addr) (AS, bool) {
	if t == nil || !ip.IsValid() {
		return 0, false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return 0, false
	}
	rows := t.v6
	if ip.Is4() {
		rows = t.v4
	}
	// The family is sorted by network address and disjoint, so the only span that
	// can contain ip is the last one starting at or before it.
	i, _ := slices.BinarySearchFunc(rows, ip, func(s span, target netip.Addr) int {
		return s.p.Addr().Compare(target)
	})
	// BinarySearchFunc returns the insertion point; the candidate is the element
	// before it, or an exact hit at i.
	if i < len(rows) && rows[i].p.Addr() == ip {
		return rows[i].as, true
	}
	if i == 0 {
		return 0, false
	}
	if s := rows[i-1]; s.p.Contains(ip) {
		return s.as, true
	}
	return 0, false
}

// Len reports how many spans the table holds, per family.
func (t *Table) Len() (v4, v6 int) {
	if t == nil {
		return 0, 0
	}
	return len(t.v4), len(t.v6)
}

// OfAddr is LookupAS for a net.IP, the form a coordinator's UDP source address
// arrives in. It is a free function over the interface rather than a method so it
// works against any Lookup, including a test double.
func OfAddr(l Lookup, ip net.IP) (AS, bool) {
	if l == nil {
		return 0, false
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return 0, false
	}
	return l.LookupAS(a)
}

// OfHostPort is LookupAS for a "host:port" string, the form the signed relay
// directory carries a hop's address in (coldstart.Entry.Ingress / .Addr).
//
// A host that is a NAME rather than a literal address resolves to unknown, and does
// so without a DNS lookup. That is not a limitation to work around: resolving it
// would mean a network call from the middle of chain selection, leaking the
// directory's contents to a resolver, and the answer would be attacker-influenced
// for exactly the node whose diversity claim is in question.
func OfHostPort(l Lookup, hostport string) (AS, bool) {
	if l == nil {
		return 0, false
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport // tolerate a bare address
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return 0, false
	}
	return l.LookupAS(a)
}
