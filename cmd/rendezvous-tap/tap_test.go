package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoUpstream stands in for the coordinator: it records every datagram it was
// given, verbatim, and answers each with the reply the caller supplies.
type echoUpstream struct {
	conn  *net.UDPConn
	reply func(i int, in []byte) []byte

	mu   sync.Mutex
	got  [][]byte
	sent [][]byte
}

func startUpstream(t *testing.T, reply func(i int, in []byte) []byte) *echoUpstream {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	// Generous, so a burst cannot be lost by the socket rather than by the code
	// under test. A dropped datagram here would read as the tap dropping one,
	// which is the exact claim these tests exist to settle.
	_ = conn.SetReadBuffer(1 << 20)
	u := &echoUpstream{conn: conn, reply: reply}
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			in := append([]byte(nil), buf[:n]...)
			u.mu.Lock()
			i := len(u.got)
			u.got = append(u.got, in)
			u.mu.Unlock()
			if u.reply == nil {
				continue
			}
			out := u.reply(i, in)
			if out == nil {
				continue
			}
			u.mu.Lock()
			u.sent = append(u.sent, append([]byte(nil), out...))
			u.mu.Unlock()
			_, _ = conn.WriteToUDP(out, from)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return u
}

func (u *echoUpstream) received() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][]byte(nil), u.got...)
}

func (u *echoUpstream) replies() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][]byte(nil), u.sent...)
}

// syncBuffer is the tap's log destination in tests. The tap writes to it from
// its serve and pump goroutines while the test reads it, and in production that
// destination is os.Stdout, which is safe for concurrent use; a plain
// bytes.Buffer is not.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startTap(t *testing.T, upstream string, cfg config) (*tap, *syncBuffer) {
	t.Helper()
	log := &syncBuffer{}
	cfg.listen = "127.0.0.1:0"
	cfg.upstream = upstream
	if cfg.budget == 0 {
		cfg.budget = defaultBudget
	}
	cfg.out = log
	tp, err := newTap(cfg)
	if err != nil {
		t.Fatalf("newTap: %v", err)
	}
	_ = tp.ln.SetReadBuffer(1 << 20)
	go tp.serve()
	t.Cleanup(func() { tp.close() })
	return tp, log
}

// dtlsRecord builds a syntactically real DTLS record of the given content type
// with n payload bytes, so a test can send something the classifier must accept
// without linking a DTLS stack.
func dtlsRecord(contentType byte, n int) []byte {
	b := make([]byte, dtlsHeaderLen+n)
	b[0] = contentType
	b[1], b[2] = 0xfe, 0xfd // DTLS 1.2
	binary.BigEndian.PutUint16(b[11:13], uint16(n))
	for i := range b[dtlsHeaderLen:] {
		b[dtlsHeaderLen+i] = byte(i)
	}
	return b
}

// stunBindingRequest builds a bare Binding Request: type, zero attribute length,
// the magic cookie and a transaction id.
func stunBindingRequest() []byte {
	b := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	_, _ = rand.Read(b[8:20])
	return b
}

// THE TEST THIS TOOL IS WORTH MORE THAN ANY OTHER. Bytes out equal bytes in, in
// both directions, in order, for a corpus chosen to include every case that
// could plausibly be mangled: an EMPTY datagram (legal over UDP and easy to drop
// by treating 0 as end-of-stream), a single byte, datagrams at and over the
// budget, and one far larger than any of the buffers involved.
//
// An instrument that alters the flight it measures gives a confident wrong
// answer, and the answers this one gives are sizes — which is exactly the kind of
// answer that can be wrong without looking wrong.
func TestTheTapChangesNothing(t *testing.T) {
	corpus := [][]byte{
		{},
		{0x00},
		stunBindingRequest(),
		dtlsRecord(dtlsHandshake, 700),
		bytes.Repeat([]byte{0xAB}, defaultBudget),
		bytes.Repeat([]byte{0xCD}, defaultBudget+1),
		bytes.Repeat([]byte{0xEF}, 4000),
		randomBytes(t, 1453), // #183's datagram, to the byte
	}
	// Replies of their own varied shapes, including an empty one, so the return
	// direction is held to the same standard as the outbound one.
	reply := func(i int, in []byte) []byte {
		switch i % 4 {
		case 0:
			return []byte{}
		case 1:
			return bytes.Repeat([]byte{byte(i)}, 40)
		case 2:
			return randomBytes(t, 1100)
		default:
			return bytes.Repeat([]byte{0x16}, 3000)
		}
	}
	up := startUpstream(t, reply)
	tp, _ := startTap(t, up.conn.LocalAddr().String(), config{quiet: true})

	client, err := net.DialUDP("udp", nil, tp.addr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	var back [][]byte
	buf := make([]byte, maxDatagram)
	for _, out := range corpus {
		if _, err := client.Write(out); err != nil {
			t.Fatalf("client write of %d bytes: %v", len(out), err)
		}
		// One at a time, so a lost datagram is a failure of this tool rather
		// than of the test's pacing. The burst case is covered below.
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("no reply to the %d-byte datagram: %v", len(out), err)
		}
		back = append(back, append([]byte(nil), buf[:n]...))
	}

	got := up.received()
	if len(got) != len(corpus) {
		t.Fatalf("the coordinator side saw %d datagrams and the client sent %d", len(got), len(corpus))
	}
	for i := range corpus {
		if !bytes.Equal(got[i], corpus[i]) {
			t.Errorf("datagram %d arrived changed: sent %d bytes, %d arrived%s",
				i, len(corpus[i]), len(got[i]), firstDifference(corpus[i], got[i]))
		}
	}
	sent := up.replies()
	if len(back) != len(sent) {
		t.Fatalf("the coordinator sent %d replies and the client received %d", len(sent), len(back))
	}
	for i := range sent {
		if !bytes.Equal(back[i], sent[i]) {
			t.Errorf("reply %d arrived changed: sent %d bytes, %d arrived%s",
				i, len(sent[i]), len(back[i]), firstDifference(sent[i], back[i]))
		}
	}
}

// Order, under a burst rather than a ping-pong. The tap uses one goroutine per
// direction per flow precisely so it cannot be the thing that reordered a
// handshake flight, and this is what holds that to account.
func TestTheTapPreservesOrderUnderABurst(t *testing.T) {
	const n = 16
	up := startUpstream(t, nil)
	tp, _ := startTap(t, up.conn.LocalAddr().String(), config{quiet: true})

	client, err := net.DialUDP("udp", nil, tp.addr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	want := make([][]byte, n)
	for i := range want {
		// Sizes that vary, so an out-of-order arrival is visible in the length
		// as well as in the contents.
		want[i] = bytes.Repeat([]byte{byte(i)}, 20+i*37)
		if _, err := client.Write(want[i]); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	var got [][]byte
	for time.Now().Before(deadline) {
		got = up.received()
		if len(got) >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) != n {
		t.Fatalf("the coordinator side saw %d of %d datagrams", len(got), n)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("datagram %d out of order or changed: wanted %d bytes of 0x%02x, got %d bytes of 0x%02x",
				i, len(want[i]), want[i][0], len(got[i]), got[i][0])
		}
	}
}

// A datagram over the budget is the finding, not an error condition: it must be
// forwarded exactly as it arrived and then reported. A tap that dropped or
// truncated it would repair, in the measurement, the one defect the budget
// exists to catch — which is how #183 stayed invisible.
func TestAnOverBudgetDatagramIsForwardedUnchangedAndReported(t *testing.T) {
	oversized := randomBytes(t, 1453)
	up := startUpstream(t, nil)
	tp, _ := startTap(t, up.conn.LocalAddr().String(), config{quiet: true})

	client, err := net.DialUDP("udp", nil, tp.addr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(oversized); err != nil {
		t.Fatalf("client write: %v", err)
	}
	waitFor(t, func() bool { return len(up.received()) == 1 })

	if got := up.received()[0]; !bytes.Equal(got, oversized) {
		t.Fatalf("the over-budget datagram was altered in transit: sent %d bytes, %d arrived", len(oversized), len(got))
	}
	rep := tp.report()
	a := findAssertion(t, rep, "budget")
	if a.held {
		t.Fatalf("a %d-byte datagram against a %d-byte budget was reported as holding: %s",
			len(oversized), defaultBudget, a.evidence)
	}
	if !strings.Contains(a.evidence, fmt.Sprint(len(oversized))) {
		t.Errorf("the budget assertion must report the size it measured; evidence was %q", a.evidence)
	}
}

// The four assertions, over a flight shaped the way a current client's is.
func TestTheReportReadsAWellShapedFlight(t *testing.T) {
	up := startUpstream(t, func(i int, in []byte) []byte {
		if i == 0 {
			// A Binding Success Response, roughly the 40 bytes a coordinator
			// sends over IPv4.
			b := make([]byte, 40)
			binary.BigEndian.PutUint16(b[0:2], 0x0101)
			binary.BigEndian.PutUint16(b[2:4], 20)
			binary.BigEndian.PutUint32(b[4:8], magicCookie)
			return b
		}
		return dtlsRecord(dtlsHandshake, 300)
	})
	tp, log := startTap(t, up.conn.LocalAddr().String(), config{})

	client, err := net.DialUDP("udp", nil, tp.addr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	for _, out := range [][]byte{stunBindingRequest(), dtlsRecord(dtlsHandshake, 743), dtlsRecord(dtlsApplicationData, 200)} {
		if _, err := client.Write(out); err != nil {
			t.Fatalf("client write: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitFor(t, func() bool { return len(up.received()) == 3 })

	rep := tp.report()
	for _, a := range rep.assertions {
		if !a.held {
			t.Errorf("assertion %q did not hold on a well-shaped flight: %s", a.what, a.evidence)
		}
	}
	if len(rep.faults) != 0 {
		t.Errorf("the tap reported faults of its own: %v", rep.faults)
	}

	// SIZES, NOT VERDICTS: the measurements must be printed whether or not
	// anything failed, and the headroom must be computed against the BUDGET. The
	// second outbound datagram here is 756 bytes on purpose — the figure #212
	// records from an earlier run — so a tool that had quietly adopted it as its
	// threshold would report 0 B spare instead of 476.
	var out bytes.Buffer
	rep.print(&out)
	printed := out.String()
	for _, want := range []string{"MEASURED", "sizes:", "756", "1232-byte budget", "476 B spare", "804-byte IPv6"} {
		if !strings.Contains(printed, want) {
			t.Errorf("the report does not mention %q\n%s", want, printed)
		}
	}
	if !strings.Contains(log.String(), "756 B") {
		t.Errorf("the per-datagram log does not report the size it forwarded:\n%s", log.String())
	}
}

// The first two assertions are about ORDER, and a flight that gets them the wrong
// way round has to be refused rather than accepted on the strength of containing
// both shapes somewhere.
func TestAFlightInTheWrongOrderIsRefused(t *testing.T) {
	up := startUpstream(t, nil)
	tp, _ := startTap(t, up.conn.LocalAddr().String(), config{quiet: true})

	client, err := net.DialUDP("udp", nil, tp.addr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	for _, out := range [][]byte{dtlsRecord(dtlsHandshake, 100), stunBindingRequest()} {
		if _, err := client.Write(out); err != nil {
			t.Fatalf("client write: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitFor(t, func() bool { return len(up.received()) == 2 })

	rep := tp.report()
	if a := findAssertion(t, rep, "first datagram out"); a.held {
		t.Errorf("a DTLS record sent first was accepted as a STUN Binding Request: %s", a.evidence)
	}
	if a := findAssertion(t, rep, "second datagram out"); a.held {
		t.Errorf("a Binding Request sent second was accepted as a DTLS handshake record: %s", a.evidence)
	}
	if rep.ok() {
		t.Error("the report as a whole reads as passing")
	}
}

// Cleartext JSON on this hop is the thing ADR-0059 removed, and it is caught
// wherever it sits in the datagram rather than only at the front.
func TestCleartextJSONIsCaughtAnywhereInTheDatagram(t *testing.T) {
	buried := append(bytes.Repeat([]byte{0x00}, 64), []byte(`{"type":"connect"}`)...)
	up := startUpstream(t, nil)
	tp, _ := startTap(t, up.conn.LocalAddr().String(), config{quiet: true})

	client, err := net.DialUDP("udp", nil, tp.addr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(buried); err != nil {
		t.Fatalf("client write: %v", err)
	}
	waitFor(t, func() bool { return len(up.received()) == 1 })

	rep := tp.report()
	a := findAssertion(t, rep, `{"type"`)
	if a.held {
		t.Fatalf("a datagram carrying the tell 64 bytes in was reported clean: %s", a.evidence)
	}
}

// The tap forwards credentials and must not be the thing that writes them to a
// terminal. Default output is a size and a sentence; -bytes is the opt-in.
func TestTheDefaultLogPrintsNoPayloadBytes(t *testing.T) {
	const secret = "SECRET-DEVICE-CREDENTIAL-BYTES"
	payload := append(dtlsRecord(dtlsHandshake, 0), []byte(secret)...)
	up := startUpstream(t, nil)
	tp, log := startTap(t, up.conn.LocalAddr().String(), config{})

	client, err := net.DialUDP("udp", nil, tp.addr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	waitFor(t, func() bool { return len(up.received()) == 1 })
	waitFor(t, func() bool { return strings.Contains(log.String(), "B  DTLS") })

	if strings.Contains(log.String(), secret) {
		t.Fatalf("the default log printed payload bytes:\n%s", log.String())
	}
	if !strings.Contains(log.String(), fmt.Sprint(len(payload))) {
		t.Errorf("the log does not report the size it forwarded:\n%s", log.String())
	}
}

// Nothing arrived is a result the report has to state, not a clean run. An
// operator who mistyped -listen and read a green tap would conclude the wire was
// fine on the evidence of never having seen it.
func TestATapNothingReachedDoesNotReadAsAPass(t *testing.T) {
	up := startUpstream(t, nil)
	tp, _ := startTap(t, up.conn.LocalAddr().String(), config{quiet: true})
	rep := tp.report()
	if rep.ok() {
		t.Fatal("a tap that saw no datagram at all reported that every assertion held")
	}
	if a := findAssertion(t, rep, "reached this tap"); a.held {
		t.Fatalf("evidence: %s", a.evidence)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func firstDifference(want, got []byte) string {
	n := len(want)
	if len(got) < n {
		n = len(got)
	}
	for i := 0; i < n; i++ {
		if want[i] != got[i] {
			return fmt.Sprintf(", first difference at byte %d: 0x%02x became 0x%02x", i, want[i], got[i])
		}
	}
	return ""
}

func findAssertion(t *testing.T, r report, substr string) assertion {
	t.Helper()
	for _, a := range r.assertions {
		if strings.Contains(a.what, substr) {
			return a
		}
	}
	t.Fatalf("no assertion mentioning %q; the report had %d", substr, len(r.assertions))
	return assertion{}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the datagrams to arrive")
}
