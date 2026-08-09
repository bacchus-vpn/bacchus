package main

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
)

// The forwarder and the ledger.
//
// PASSIVITY IS THE WHOLE DESIGN CONSTRAINT (wave ruling R1): bytes out equal
// bytes in, in both directions, with nothing rewritten, reordered, dropped or
// delayed. A tap that alters the flight it measures gives a confident wrong
// answer, and the answer this one is built to give — "the largest datagram on
// this hop was N bytes" — is exactly the kind that would survive being wrong.
//
// Four things enforce it, and each is a decision rather than an accident:
//
//   - THE DATAGRAM IS FORWARDED BEFORE IT IS LOOKED AT. Classification, logging
//     and bookkeeping all happen after the write, so none of them sits in the
//     path's latency.
//   - ONE GOROUTINE PER DIRECTION PER FLOW. Reads and writes are sequential
//     within a direction, so the tap cannot be the thing that reordered a
//     handshake flight. (UDP may still reorder underneath; that is the path's
//     doing and the tap must not add to it.)
//   - THE READ BUFFER CANNOT TRUNCATE. A short buffer makes recvfrom discard the
//     tail of an oversized datagram with no error at all, which on this hop
//     would silently repair the one defect the budget exists to catch. The
//     buffer is larger than any UDP payload can be, and a read that fills it is
//     refused rather than forwarded.
//   - NOTHING IS EXPIRED. A flow table with an idle sweep could close a socket
//     under a late reply, and dropping a datagram is the one thing this must
//     never do. It is unbounded on purpose; this is an instrument run by hand
//     for the length of a testbed run, not a service.

// maxDatagram is one byte larger than the largest UDP payload that can exist
// (65527 over IPv6, 65507 over IPv4), so a read that returns exactly this many
// bytes is impossible and can be treated as a bug rather than as data.
const maxDatagram = 65536

// The path arithmetic behind the budget (ADR-0057). The tap measures UDP
// PAYLOAD, which is what the budget is stated in; these turn a payload back into
// the IP datagram an operator has to fit through a link, because #183 was a
// 1453-byte payload refused for needing a 1481-byte datagram, and the number
// that mattered was the second one.
const (
	ipv6Overhead = 40 + 8
	ipv4Overhead = 20 + 8
	pathFloor    = 1280
)

type direction int

const (
	outbound direction = iota // client -> coordinator
	inbound                   // coordinator -> client
)

func (d direction) arrow() string {
	if d == outbound {
		return "->"
	}
	return "<-"
}

func (d direction) String() string {
	if d == outbound {
		return "client to coordinator"
	}
	return "coordinator to client"
}

// flow is one client 5-tuple and the upstream socket standing in for it.
type flow struct {
	client *net.UDPAddr
	up     *net.UDPConn

	mu   sync.Mutex
	seen [2][]observation
}

func (f *flow) record(d direction, o observation) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen[d] = append(f.seen[d], o)
	return len(f.seen[d])
}

func (f *flow) snapshot() [2][]observation {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [2][]observation
	for d := range f.seen {
		out[d] = append([]observation(nil), f.seen[d]...)
	}
	return out
}

type config struct {
	listen   string
	upstream string
	budget   int
	quiet    bool
	lead     int
	out      io.Writer
}

type tap struct {
	cfg      config
	ln       *net.UDPConn
	upstream *net.UDPAddr

	mu    sync.Mutex
	flows map[string]*flow
	order []string

	// errs are the tap's OWN failures — a write that did not go through, a read
	// that filled the buffer. They are kept apart from the wire observations
	// because a broken instrument and a broken wire are different findings and
	// the summary must never let one read as the other.
	errs []string
}

func newTap(cfg config) (*tap, error) {
	up, err := net.ResolveUDPAddr("udp", cfg.upstream)
	if err != nil {
		return nil, fmt.Errorf("-upstream %q: %w", cfg.upstream, err)
	}
	laddr, err := net.ResolveUDPAddr("udp", cfg.listen)
	if err != nil {
		return nil, fmt.Errorf("-listen %q: %w", cfg.listen, err)
	}
	ln, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", cfg.listen, err)
	}
	return &tap{cfg: cfg, ln: ln, upstream: up, flows: map[string]*flow{}}, nil
}

// addr is where a client should be pointed. Read back off the socket rather than
// echoed from the flag, so a -listen with port 0 reports the port it got.
func (t *tap) addr() *net.UDPAddr { return t.ln.LocalAddr().(*net.UDPAddr) }

// close stops the tap: the listening socket first, so serve returns, then every
// flow's upstream socket, so its pump does too. Called once, at shutdown — the
// flow table is never swept while the tap is running, because expiring a flow
// could close a socket under a late reply.
func (t *tap) close() error {
	err := t.ln.Close()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, f := range t.flows {
		f.up.Close()
	}
	return err
}

// serve runs until the listening socket is closed.
func (t *tap) serve() {
	buf := make([]byte, maxDatagram)
	for {
		n, src, err := t.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f, err := t.flowFor(src)
		if err != nil {
			t.fail("%s: no upstream socket, so its datagram was NOT forwarded: %v", src, err)
			continue
		}
		if n == len(buf) {
			t.fail("%s sent %d bytes, which fills this tap's read buffer — the datagram may have "+
				"been truncated by the kernel, so it was NOT forwarded rather than forwarded short", src, n)
			continue
		}
		// FORWARD FIRST. Everything below this line is bookkeeping and must not
		// come between the two writes.
		if _, err := f.up.Write(buf[:n]); err != nil {
			t.fail("%s -> %s: forwarding %d bytes: %v", src, t.upstream, n, err)
		}
		t.log(f, outbound, classify(buf[:n]), buf[:n])
	}
}

// pump carries one flow's replies back. One goroutine, so the order the
// coordinator sent them in is the order the client sees.
func (t *tap) pump(f *flow) {
	buf := make([]byte, maxDatagram)
	for {
		n, err := f.up.Read(buf)
		if err != nil {
			return
		}
		if n == len(buf) {
			t.fail("%s sent %d bytes back, which fills this tap's read buffer — it may have been "+
				"truncated, so it was NOT forwarded", t.upstream, n)
			continue
		}
		if _, err := t.ln.WriteToUDP(buf[:n], f.client); err != nil {
			t.fail("%s -> %s: returning %d bytes: %v", t.upstream, f.client, n, err)
		}
		t.log(f, inbound, classify(buf[:n]), buf[:n])
	}
}

func (t *tap) flowFor(src *net.UDPAddr) (*flow, error) {
	key := src.String()
	t.mu.Lock()
	if f, ok := t.flows[key]; ok {
		t.mu.Unlock()
		return f, nil
	}
	t.mu.Unlock()

	// Dialled, not bound: a connected socket accepts replies only from the
	// coordinator, so nothing else on the network can inject a datagram into a
	// flight this tool is about to describe as the coordinator's.
	up, err := net.DialUDP("udp", nil, t.upstream)
	if err != nil {
		return nil, err
	}
	f := &flow{client: src, up: up}

	t.mu.Lock()
	if existing, ok := t.flows[key]; ok {
		t.mu.Unlock()
		up.Close()
		return existing, nil
	}
	t.flows[key] = f
	t.order = append(t.order, key)
	t.mu.Unlock()

	t.printf("flow %s opened, forwarding to %s from %s\n", src, t.upstream, up.LocalAddr())
	go t.pump(f)
	return f, nil
}

func (t *tap) log(f *flow, d direction, o observation, raw []byte) {
	n := f.record(d, o)
	if t.cfg.quiet {
		return
	}
	over := ""
	if o.size > t.cfg.budget {
		over = fmt.Sprintf("  OVER BUDGET by %d B", o.size-t.cfg.budget)
	}
	tell := ""
	if o.carriesJSONTell {
		tell = fmt.Sprintf("  carries %s at offset %d", jsonTell, o.jsonTellOffset)
	}
	t.printf("%s %s #%d  %5d B  %s: %s%s%s\n", f.client, d.arrow(), n, o.size, o.family, o.detail, over, tell)
	if t.cfg.lead > 0 {
		t.printf("      %s\n", leadingHex(raw, t.cfg.lead))
	}
}

func leadingHex(raw []byte, n int) string {
	if n > len(raw) {
		n = len(raw)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%02x", raw[i])
	}
	if n < len(raw) {
		fmt.Fprintf(&b, " … (%d more)", len(raw)-n)
	}
	return b.String()
}

func (t *tap) fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	t.mu.Lock()
	t.errs = append(t.errs, msg)
	t.mu.Unlock()
	t.printf("TAP FAULT: %s\n", msg)
}

func (t *tap) printf(format string, args ...any) {
	fmt.Fprintf(t.cfg.out, format, args...)
}

// ---------------------------------------------------------------------------
// The report.
//
// SIZES, NOT VERDICTS. Every number this tool measured is printed whether or not
// anything failed, and every assertion is printed with the measurement behind it
// rather than as a bare word. The largest datagram seen in a test of this hop was
// 756 bytes; that figure appears nowhere here, because the thing to check
// against is the BUDGET and a tool that quietly compared against last time's
// number would report a pass on a regression that stayed under it.

// assertion is one line of the report: what was asked, whether it held, and the
// measurement that settles it.
type assertion struct {
	what     string
	held     bool
	evidence string
}

// measurements is what the tap counted. It is a field of the report rather than
// something printed on the way to producing one, so the numbers and the verdicts
// come out of the same object and a test can read either.
type measurements struct {
	addr    string
	budget  int
	count   [2]int
	total   [2]int
	largest [2]int
	sizes   [2][]int
}

func (m measurements) worst() int {
	if m.largest[inbound] > m.largest[outbound] {
		return m.largest[inbound]
	}
	return m.largest[outbound]
}

type report struct {
	measured   measurements
	assertions []assertion
	faults     []string
}

func (r report) ok() bool {
	if len(r.faults) > 0 {
		return false
	}
	for _, a := range r.assertions {
		if !a.held {
			return false
		}
	}
	return true
}

func (t *tap) report() report {
	t.mu.Lock()
	order := append([]string(nil), t.order...)
	flows := make([]*flow, 0, len(order))
	for _, k := range order {
		flows = append(flows, t.flows[k])
	}
	rep := report{
		measured: measurements{addr: t.addr().String(), budget: t.cfg.budget},
		faults:   append([]string(nil), t.errs...),
	}
	t.mu.Unlock()

	if len(flows) == 0 {
		rep.assertions = append(rep.assertions, assertion{
			what:     "a client reached this tap",
			held:     false,
			evidence: "no datagram arrived on " + rep.measured.addr + ", so nothing was measured",
		})
		return rep
	}

	m := &rep.measured
	var tells, overs int
	for _, f := range flows {
		seen := f.snapshot()
		for d := range seen {
			for _, o := range seen[d] {
				m.count[d]++
				m.total[d] += o.size
				m.sizes[d] = append(m.sizes[d], o.size)
				if o.size > m.largest[d] {
					m.largest[d] = o.size
				}
				if o.carriesJSONTell {
					tells++
				}
				if o.size > t.cfg.budget {
					overs++
				}
			}
		}

		// The two ordering assertions are per flow: they are about the first two
		// datagrams a client sends, and a second client is a second flow.
		out := seen[outbound]
		who := f.client.String()
		switch {
		case len(out) < 1:
			rep.assertions = append(rep.assertions, assertion{
				what: who + ": the first datagram out is a STUN Binding Request", held: false,
				evidence: "this flow sent nothing",
			})
		default:
			rep.assertions = append(rep.assertions, assertion{
				what:     who + ": the first datagram out is a STUN Binding Request",
				held:     out[0].bindingRequest,
				evidence: fmt.Sprintf("%d B, %s: %s", out[0].size, out[0].family, out[0].detail),
			})
		}
		switch {
		case len(out) < 2:
			rep.assertions = append(rep.assertions, assertion{
				what: who + ": the second datagram out leads with 0x16, a DTLS handshake record", held: false,
				evidence: fmt.Sprintf("this flow sent %d datagram(s)", len(out)),
			})
		default:
			rep.assertions = append(rep.assertions, assertion{
				what: who + ": the second datagram out leads with 0x16, a DTLS handshake record",
				held: out[1].leading == dtlsHandshake && out[1].dtlsHandshake,
				evidence: fmt.Sprintf("%d B, leading byte 0x%02x, %s: %s",
					out[1].size, out[1].leading, out[1].family, out[1].detail),
			})
		}
	}

	rep.assertions = append(rep.assertions, assertion{
		what:     fmt.Sprintf("no datagram carries %s", jsonTell),
		held:     tells == 0,
		evidence: fmt.Sprintf("%d of %d datagrams carry it", tells, m.count[outbound]+m.count[inbound]),
	})
	rep.assertions = append(rep.assertions, assertion{
		what: fmt.Sprintf("no datagram exceeds the %d-byte budget", t.cfg.budget),
		held: overs == 0,
		evidence: fmt.Sprintf("%d over; largest out %d B (%s), largest in %d B (%s)",
			overs,
			m.largest[outbound], headroom(m.largest[outbound], t.cfg.budget),
			m.largest[inbound], headroom(m.largest[inbound], t.cfg.budget)),
	})
	return rep
}

func headroom(size, budget int) string {
	if size > budget {
		return fmt.Sprintf("%d B OVER", size-budget)
	}
	return fmt.Sprintf("%d B spare", budget-size)
}

func sizeList(sizes []int) string {
	if len(sizes) == 0 {
		return "(none)"
	}
	parts := make([]string, len(sizes))
	for i, s := range sizes {
		parts[i] = fmt.Sprint(s)
	}
	return strings.Join(parts, " ")
}

// print renders the measurements first and the assertions under them, in that
// order and unconditionally, because the numbers are the output and the verdicts
// are derived from them.
func (r report) print(w io.Writer) {
	m := r.measured
	fmt.Fprintf(w, "\nMEASURED, on %s\n", m.addr)
	for _, d := range []direction{outbound, inbound} {
		fmt.Fprintf(w, "  %-24s %d datagrams, %d bytes, largest %d B\n",
			d.String()+":", m.count[d], m.total[d], m.largest[d])
		fmt.Fprintf(w, "      sizes: %s\n", sizeList(m.sizes[d]))
	}
	fmt.Fprintf(w, "  largest datagram either way: %d B payload — a %d-byte IPv6 datagram, %d-byte IPv4,\n",
		m.worst(), m.worst()+ipv6Overhead, m.worst()+ipv4Overhead)
	fmt.Fprintf(w, "      against the %d-byte path floor the %d-byte budget is derived from (ADR-0057)\n",
		pathFloor, m.budget)

	fmt.Fprintf(w, "\nASSERTIONS (#212 step 2)\n")
	sorted := append([]assertion(nil), r.assertions...)
	sort.SliceStable(sorted, func(i, j int) bool { return !sorted[i].held && sorted[j].held })
	for _, a := range sorted {
		verdict := "held"
		if !a.held {
			verdict = "DID NOT HOLD"
		}
		fmt.Fprintf(w, "  [%-12s] %s\n      %s\n", verdict, a.what, a.evidence)
	}
	if len(r.faults) > 0 {
		fmt.Fprintf(w, "\nTAP FAULTS — these are this tool's own failures, not the wire's, and every\n"+
			"assertion above is unsafe to read while any are present:\n")
		for _, f := range r.faults {
			fmt.Fprintf(w, "  %s\n", f)
		}
	}
}
