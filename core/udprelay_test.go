package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestWriteReadUDPFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello udp frame")
	if err := writeUDPFrame(&buf, payload); err != nil {
		t.Fatalf("writeUDPFrame: %v", err)
	}
	got, err := readUDPFrame(&buf, make([]byte, maxUDPDatagram))
	if err != nil {
		t.Fatalf("readUDPFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("readUDPFrame = %q, want %q", got, payload)
	}
}

func TestWriteUDPFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := writeUDPFrame(&buf, make([]byte, maxUDPDatagram+1)); err == nil {
		t.Fatal("writeUDPFrame should reject a payload over maxUDPDatagram")
	}
}

func TestEncodeDecodeSOCKSUDPFrameRoundTrip(t *testing.T) {
	ip := net.IPv4(203, 0, 113, 7).To4()
	const port = 51820
	payload := []byte("quic-ish payload")

	frame := encodeSOCKSUDPFrame(ip, port, payload)
	got, gotIP, gotPort, err := decodeSOCKSUDPFrame(frame)
	if err != nil {
		t.Fatalf("decodeSOCKSUDPFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if !gotIP.Equal(ip) || gotPort != port {
		t.Fatalf("addr = %s:%d, want %s:%d", gotIP, gotPort, ip, port)
	}
}

func TestDecodeSOCKSUDPFrameRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":               {0, 0, 0, 1, 1, 2, 3},
		"nonzero RSV":             {1, 0, 0, 1, 1, 2, 3, 4, 0, 53, 'x'},
		"nonzero FRAG":            {0, 0, 1, 1, 1, 2, 3, 4, 0, 53, 'x'},
		"unsupported ATYP domain": {0, 0, 0, 3, 1, 2, 3, 4, 0, 53, 'x'},
	}
	for name, b := range cases {
		if _, _, _, err := decodeSOCKSUDPFrame(b); err == nil {
			t.Errorf("%s: decodeSOCKSUDPFrame should have rejected %v", name, b)
		}
	}
}

// TestExitTerminateUDPRoundTrip drives the real dispatch in exitTerminate
// (core/forwarder.go): a client sends udpTargetPrefix+target through the
// identical Noise_NK handshake CONNECT uses, and the exit relays datagrams to
// a real loopback UDP echo target and back, bidirectionally, through both
// framing layers (udprelay.go's writeUDPFrame over the E2E stream, and the
// real net.UDPConn on the exit's side).
func TestExitTerminateUDPRoundTrip(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer echo.Close()
	go func() { // a trivial UDP echo server standing in for the real destination
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()
	target := echo.LocalAddr().String()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, udpIdleTimeout: 5 * time.Second}
	go e.exitTerminate("", nil, sConn)

	nc, err := clientHandshake(cConn, key.Public, udpTargetPrefix+target, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	payload := []byte("ping over udp relay")
	if err := writeUDPFrame(nc, payload); err != nil {
		t.Fatalf("writeUDPFrame: %v", err)
	}
	got, err := readUDPFrame(nc, make([]byte, maxUDPDatagram))
	if err != nil {
		t.Fatalf("readUDPFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed payload = %q, want %q", got, payload)
	}
}

// TestExitTerminateUDPIdleTimeout proves the exit-side backstop actually
// tears the association down: with no datagram either way for longer than a
// (shrunk, for the test) udpIdleTimeout, the E2E stream closes on its own —
// nothing needs to time out on the client side for this to happen.
func TestExitTerminateUDPIdleTimeout(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer echo.Close()
	target := echo.LocalAddr().String()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, udpIdleTimeout: 40 * time.Millisecond}
	go e.exitTerminate("", nil, sConn)

	nc, err := clientHandshake(cConn, key.Public, udpTargetPrefix+target, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	// No datagram either way; wait past udpIdleTimeout, then the exit must
	// have closed its end — a read now returns an error rather than hanging.
	time.Sleep(200 * time.Millisecond)
	_ = cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readUDPFrame(nc, make([]byte, maxUDPDatagram)); err == nil {
		t.Fatal("expected the idle-timed-out exit to have closed the stream")
	}
}

// ---------------------------------------------------------------------------
// UDP-side tier shaping (issue #74, ADR-0048 §5).
// ---------------------------------------------------------------------------

// burstResponder binds a loopback UDP listener that waits for one datagram (the
// exit's, which is what teaches it the exit's ephemeral source address) and then
// fires back count datagrams of size bytes as fast as it can.
//
// It stands in for TestSessionCapShapesTheExitEgress's (session_cap_test.go) TCP
// server writing one large payload on accept, adapted to UDP's framing: a single
// datagram cannot exceed maxUDPDatagram, so a payload big enough to clear the
// token bucket's burst has to cross as several datagrams rather than one write.
func burstResponder(t *testing.T, size, count int) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		_, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		payload := make([]byte, size)
		for i := 0; i < count; i++ {
			_, _ = conn.WriteToUDP(payload, from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// TestUDPSessionCapShapesTheExitEgress is TestSessionCapShapesTheExitEgress's
// (session_cap_test.go) UDP counterpart: same tier cap, same exitTerminate entry
// point, driven through the udpTargetPrefix branch instead of a TCP dial.
//
// The bucket starts full at burstBytes, so the assertion is on the bytes BEYOND
// the burst: at 512 kbit/s (64 KB/s) a 64 KB overshoot cannot cross in under a
// second however fast the machine is, because a token bucket's rate is not a
// property of the hardware.
//
// MUTATION: drop either pace.WaitN call from exitTerminateUDP and this goes red —
// the datagrams arrive immediately.
func TestUDPSessionCapShapesTheExitEgress(t *testing.T) {
	const capBps = 512_000     // 64 KB/s
	const datagramSize = 65000 // under maxUDPDatagram
	const numDatagrams = 2     // 130,000 bytes — clears one 64 KB burst
	const wantAtLeast = 900 * time.Millisecond

	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	dest := burstResponder(t, datagramSize, numDatagrams)

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, udpIdleTimeout: 5 * time.Second, limiterCtx: context.Background()}
	pace := sessionPace(wire{Type: "assign", Session: "s1", SessionCapBps: capBps})
	if pace == nil {
		t.Fatal("no limiter built for a capped assignment")
	}
	go e.exitTerminate("s1", pace, sConn)

	nc, err := clientHandshake(cConn, key.Public, udpTargetPrefix+dest.String(), nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	// One datagram out, to teach the responder where to answer. It is also the
	// client->exit direction's own trip through pace.WaitN.
	if err := writeUDPFrame(nc, []byte("ping")); err != nil {
		t.Fatalf("writeUDPFrame: %v", err)
	}

	start := time.Now()
	buf := make([]byte, maxUDPDatagram)
	for i := 0; i < numDatagrams; i++ {
		if _, err := readUDPFrame(nc, buf); err != nil {
			t.Fatalf("readUDPFrame %d of %d: %v", i+1, numDatagrams, err)
		}
	}
	elapsed := time.Since(start)

	if elapsed < wantAtLeast {
		t.Errorf("%d bytes crossed a %d bps session cap in %s; want at least %s — the UDP relay is NOT shaped to its tier",
			numDatagrams*datagramSize, capBps, elapsed.Truncate(time.Millisecond), wantAtLeast)
	}
}

// TestUDPUncappedSessionIsNotShaped is the control for the test above, mirroring
// TestUncappedSessionIsNotShaped: with no cap on the assignment the same
// datagrams cross at memory speed. Without it the timing assertion above could be
// satisfied by any accidental stall and would keep passing while proving nothing.
func TestUDPUncappedSessionIsNotShaped(t *testing.T) {
	const datagramSize = 65000
	const numDatagrams = 2

	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	dest := burstResponder(t, datagramSize, numDatagrams)

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, udpIdleTimeout: 5 * time.Second, limiterCtx: context.Background()}
	go e.exitTerminate("s1", sessionPace(wire{Type: "assign", Session: "s1"}), sConn)

	nc, err := clientHandshake(cConn, key.Public, udpTargetPrefix+dest.String(), nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	if err := writeUDPFrame(nc, []byte("ping")); err != nil {
		t.Fatalf("writeUDPFrame: %v", err)
	}

	start := time.Now()
	buf := make([]byte, maxUDPDatagram)
	for i := 0; i < numDatagrams; i++ {
		if _, err := readUDPFrame(nc, buf); err != nil {
			t.Fatalf("readUDPFrame %d of %d: %v", i+1, numDatagrams, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("an UNCAPPED UDP session took %s to move %d bytes — an unpoliced coordinator's UDP sessions are being shaped", elapsed, numDatagrams*datagramSize)
	}
}

// TestMaxUDPDatagramFitsTheLimiterBurst pins the invariant exitTerminateUDP's
// WaitN calls rely on: capacity.Limiter.WaitN errors rather than deadlocking when
// asked for more bytes than the bucket can ever hold, and the only reason that
// error is unreachable in the UDP relay is that a datagram cannot be that large.
//
// It is a one-line assertion standing in for a whole failure mode: widen
// maxUDPDatagram past the burst and every capped UDP session would start dropping
// its largest datagrams instead of pacing them, with nothing else in the suite
// noticing.
func TestMaxUDPDatagramFitsTheLimiterBurst(t *testing.T) {
	pace := sessionPace(wire{Type: "assign", Session: "s1", SessionCapBps: 512_000})
	if pace == nil {
		t.Fatal("no limiter built for a capped assignment")
	}
	if err := pace.WaitN(context.Background(), maxUDPDatagram); err != nil {
		t.Fatalf("a maxUDPDatagram-sized datagram (%d bytes) exceeds the limiter's burst: %v — exitTerminateUDP would fail every large datagram rather than pace it",
			maxUDPDatagram, err)
	}
}

// pipeSession is a minimal one-shot fake Session: its single OpenStream
// returns one half of a net.Pipe(), delivering the other half through peer.
// It exists so handleSocksUDPAssociate can be driven against a real
// exitHandshake/exitTerminate on the peer side without the full
// loopbackTransport/Signaler machinery in transport_test.go, which is built
// for multi-stream reconnect scenarios this test doesn't need.
type pipeSession struct {
	peer chan Stream
}

func newPipeSession() *pipeSession { return &pipeSession{peer: make(chan Stream, 1)} }

func (s *pipeSession) OpenStream(ctx context.Context, label string) (Stream, error) {
	a, b := net.Pipe()
	s.peer <- &lbStream{Conn: b, label: label}
	return &lbStream{Conn: a, label: label}, nil
}
func (s *pipeSession) AcceptStream(ctx context.Context) (Stream, error) {
	select {
	case st := <-s.peer:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *pipeSession) Closed() <-chan struct{} { return nil }
func (s *pipeSession) Close() error            { return nil }

// TestHandleSocksUDPAssociateRoundTrip drives the whole client-core-side path
// (issue #41): a manually-driven RFC 1928 SOCKS5 UDP ASSOCIATE handshake
// (standing in for clients/windows/udprelay.go's dialSOCKSUDPAssociate, which
// lives in a separate package and is tested on its own there) against
// handleSocksUDPAssociate, which in turn opens a real E2E channel to an exit
// side relaying to a real loopback UDP echo target — proving both framing
// layers (RFC 1928 at the SOCKS boundary, the simpler internal framing on the
// E2E stream) compose correctly end to end.
func TestHandleSocksUDPAssociateRoundTrip(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	sess := newPipeSession()
	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, udpIdleTimeout: 5 * time.Second}
	go func() {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		e.exitTerminate("", nil, st)
	}()

	ctrlA, ctrlB := net.Pipe()
	deadline(t, ctrlA, ctrlB)
	go func() {
		buf := make([]byte, 262)
		if _, err := io.ReadFull(ctrlB, buf[:2]); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:int(buf[1])]); err != nil {
			return
		}
		if _, err := ctrlB.Write([]byte{5, 0}); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:4]); err != nil {
			return
		}
		e.handleSocksUDPAssociate(ctrlB, buf, sess, key.Public, nil)
	}()

	// Client side of the control connection: no-auth negotiation, then the
	// UDP ASSOCIATE request itself (mirrors dialSOCKSUDPAssociate exactly).
	if _, err := ctrlA.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	var method [2]byte
	if _, err := io.ReadFull(ctrlA, method[:]); err != nil || method[1] != 0 {
		t.Fatalf("method negotiation reply: %v %v", method, err)
	}
	if _, err := ctrlA.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write UDP ASSOCIATE request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrlA, reply); err != nil || reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply: %v %v", reply, err)
	}
	bndAddr := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}

	data, err := net.DialUDP("udp", nil, bndAddr)
	if err != nil {
		t.Fatalf("dial relay socket: %v", err)
	}
	defer data.Close()

	payload := []byte("ping through socks udp associate")
	frame := encodeSOCKSUDPFrame(echoAddr.IP.To4(), uint16(echoAddr.Port), payload)
	if _, err := data.Write(frame); err != nil {
		t.Fatalf("write first datagram: %v", err)
	}

	_ = data.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := data.Read(buf)
	if err != nil {
		t.Fatalf("read echoed datagram: %v", err)
	}
	got, ip, port, err := decodeSOCKSUDPFrame(buf[:n])
	if err != nil {
		t.Fatalf("malformed reply frame: %v (%v)", buf[:n], err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed payload = %q, want %q", got, payload)
	}
	if !ip.Equal(echoAddr.IP.To4()) || port != uint16(echoAddr.Port) {
		t.Fatalf("reply addressed as %s:%d, want %s:%d", ip, port, echoAddr.IP, echoAddr.Port)
	}
}

// echoUDPCapture starts a loopback UDP echo server like the other tests'
// echo helpers, but also forwards a copy of every payload it receives onto
// the returned channel — so a test can assert on exactly what the exit
// actually dialed and sent, not just what eventually came back through the
// round trip.
func echoUDPCapture(t *testing.T) (addr *net.UDPAddr, received chan []byte) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	received = make(chan []byte, 16)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received <- append([]byte(nil), buf[:n]...)
			_, _ = conn.WriteToUDP(buf[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), received
}

// TestHandleSocksUDPAssociateDropsCrossDestinationDatagram proves the
// one-destination-per-association invariant (issue #99): once an
// association's destination is fixed by its first datagram (here, echoA), a
// later datagram on the same association naming a *different* destination
// (echoB) must be dropped — not silently forwarded to the association's
// already-fixed target, which is what serveSOCKSUDPAssociate used to do
// (ADR-0034's "known limitation").
func TestHandleSocksUDPAssociateDropsCrossDestinationDatagram(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	echoAAddr, echoAReceived := echoUDPCapture(t)
	echoBAddr, echoBReceived := echoUDPCapture(t)

	sess := newPipeSession()
	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, udpIdleTimeout: 5 * time.Second}
	go func() {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		e.exitTerminate("", nil, st)
	}()

	ctrlA, ctrlB := net.Pipe()
	deadline(t, ctrlA, ctrlB)
	go func() {
		buf := make([]byte, 262)
		if _, err := io.ReadFull(ctrlB, buf[:2]); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:int(buf[1])]); err != nil {
			return
		}
		if _, err := ctrlB.Write([]byte{5, 0}); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:4]); err != nil {
			return
		}
		e.handleSocksUDPAssociate(ctrlB, buf, sess, key.Public, nil)
	}()

	if _, err := ctrlA.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	var method [2]byte
	if _, err := io.ReadFull(ctrlA, method[:]); err != nil || method[1] != 0 {
		t.Fatalf("method negotiation reply: %v %v", method, err)
	}
	if _, err := ctrlA.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write UDP ASSOCIATE request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrlA, reply); err != nil || reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply: %v %v", reply, err)
	}
	bndAddr := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}

	data, err := net.DialUDP("udp", nil, bndAddr)
	if err != nil {
		t.Fatalf("dial relay socket: %v", err)
	}
	defer data.Close()

	// First datagram fixes the association's destination at echoA.
	first := encodeSOCKSUDPFrame(echoAAddr.IP.To4(), uint16(echoAAddr.Port), []byte("first"))
	if _, err := data.Write(first); err != nil {
		t.Fatalf("write first datagram: %v", err)
	}
	select {
	case got := <-echoAReceived:
		if string(got) != "first" {
			t.Fatalf("echoA got %q, want %q", got, "first")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first datagram to reach echoA")
	}

	// Second datagram: same association, but addressed to echoB instead of
	// the now-fixed echoA. Must be dropped, not forwarded to echoA.
	second := encodeSOCKSUDPFrame(echoBAddr.IP.To4(), uint16(echoBAddr.Port), []byte("second"))
	if _, err := data.Write(second); err != nil {
		t.Fatalf("write second (cross-destination) datagram: %v", err)
	}

	select {
	case got := <-echoAReceived:
		t.Fatalf("cross-destination datagram was misrouted to echoA (got %q)", got)
	case <-time.After(500 * time.Millisecond):
		// Dropped, as required.
	}
	select {
	case got := <-echoBReceived:
		t.Fatalf("cross-destination datagram reached echoB (got %q) — the exit only ever dials the association's first destination, so this should be structurally impossible, not just policy", got)
	default:
	}
}

// failingSession is a Session whose OpenStream always fails — standing in
// for a tunnel that can't be reached (the underlying transport/exit session
// is down), to drive serveSOCKSUDPAssociate's fail-closed path (issue #99).
// opened signals every OpenStream attempt, so a test can distinguish "never
// even tried to open the tunnel" (which would make a negative assertion pass
// vacuously) from "tried, and correctly didn't fall back to anything else."
type failingSession struct{ opened chan struct{} }

func newFailingSession() *failingSession {
	return &failingSession{opened: make(chan struct{}, 1)}
}

var errSimulatedTunnelDown = errors.New("core: simulated tunnel-down for test")

func (s *failingSession) OpenStream(ctx context.Context, label string) (Stream, error) {
	select {
	case s.opened <- struct{}{}:
	default:
	}
	return nil, errSimulatedTunnelDown
}
func (s *failingSession) AcceptStream(ctx context.Context) (Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *failingSession) Closed() <-chan struct{} { return nil }
func (s *failingSession) Close() error            { return nil }

// TestServeSOCKSUDPAssociateDropsWhenTunnelUnreachable is the core-side
// counterpart to clients/windows/udprelay_test.go's
// TestHandleGeneralUDPDropsWhenTunnelUnreachable (issue #99): when the
// tunnel itself can't be reached (sess.OpenStream fails — the transport
// session to the exit is down), the client's datagram must be dropped, never
// relayed anywhere else — in particular, never dialed directly to its
// destination from core's own machine. target stands in for "the open
// internet destination" the client's datagram is addressed to; if
// serveSOCKSUDPAssociate ever grew a direct-dial fallback for this case,
// this is what would receive the leaked datagram. core has no TUN/netstack
// layer of its own to bridge (that's the client's concern), so unlike the
// windows-side test this drives the real production entry point
// (handleSocksUDPAssociate) directly over a real loopback SOCKS control
// connection rather than through a gVisor forwarder.
func TestServeSOCKSUDPAssociateDropsWhenTunnelUnreachable(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer target.Close()
	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		n, _, err := target.ReadFromUDP(buf)
		if err == nil {
			received <- append([]byte(nil), buf[:n]...)
		}
	}()

	sess := newFailingSession()
	e := &Engine{udpIdleTimeout: 5 * time.Second}

	ctrlA, ctrlB := net.Pipe()
	deadline(t, ctrlA, ctrlB)
	go func() {
		buf := make([]byte, 262)
		if _, err := io.ReadFull(ctrlB, buf[:2]); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:int(buf[1])]); err != nil {
			return
		}
		if _, err := ctrlB.Write([]byte{5, 0}); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:4]); err != nil {
			return
		}
		e.handleSocksUDPAssociate(ctrlB, buf, sess, nil, nil)
	}()

	// Client side of the control connection: no-auth negotiation, then the
	// UDP ASSOCIATE request (mirrors dialSOCKSUDPAssociate/
	// TestHandleSocksUDPAssociateRoundTrip exactly).
	if _, err := ctrlA.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	var method [2]byte
	if _, err := io.ReadFull(ctrlA, method[:]); err != nil || method[1] != 0 {
		t.Fatalf("method negotiation reply: %v %v", method, err)
	}
	if _, err := ctrlA.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write UDP ASSOCIATE request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrlA, reply); err != nil || reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply: %v %v", reply, err)
	}
	bndAddr := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}

	data, err := net.DialUDP("udp", nil, bndAddr)
	if err != nil {
		t.Fatalf("dial relay socket: %v", err)
	}
	defer data.Close()

	targetAddr := target.LocalAddr().(*net.UDPAddr)
	frame := encodeSOCKSUDPFrame(targetAddr.IP.To4(), uint16(targetAddr.Port), []byte("must-not-leak"))
	if _, err := data.Write(frame); err != nil {
		t.Fatalf("write first datagram: %v", err)
	}

	// Guard against a vacuous pass: this test's whole point is the negative
	// assertion below, which would trivially hold if serveSOCKSUDPAssociate
	// were never even reached (e.g. a wiring bug upstream of it).
	select {
	case <-sess.opened:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSOCKSUDPAssociate never attempted to open the tunnel — this test would otherwise pass vacuously")
	}

	select {
	case b := <-received:
		t.Fatalf("target received %q — the datagram leaked outside the tunnel", b)
	case <-time.After(500 * time.Millisecond):
		// No leak: correct, fail-closed behavior.
	}
}

// ---------- the UDP path over a relay chain that loses a hop (issue #82) ----------
//
// These two run on core/relaychain_liveness_test.go's mesh — real forwarding nodes on
// loopback, the production relayPipe standing in for the assigned blind splice, and a
// client engine from the real New() with RelayHops actually set — so what they drive is
// the shipped chaining path, reached through the shipped SOCKS5 UDP ASSOCIATE entry
// point rather than by calling the dial seam directly.

// The destination every association below is fixed to. It is RFC 5737 documentation
// space and nothing ever dials it: these tests terminate on the mesh's ECHOING exit,
// which answers the innermost handshake and then echoes the E2E stream instead of
// resolving a destination and dialing it. Exit-side UDP termination is
// TestExitTerminateUDPRoundTrip's subject; the subject here is which PATH the
// association came up over, and an unreachable destination keeps the two apart.
var udpChainTarget = net.IPv4(192, 0, 2, 10)

const udpChainTargetPort = 5353

// socksUDPAssociateOver drives the client side of one SOCKS5 UDP ASSOCIATE against
// e.handleSocksUDPAssociate over sess — method negotiation, the ASSOCIATE request, and
// the reply naming the relay socket — and returns a UDP conn dialed to that socket:
// the thing a SOCKS client sends datagrams into.
//
// Note what has NOT happened when this returns. handleSocksUDPAssociate binds and
// answers before it opens anything, so no E2E channel exists yet and no chain has been
// dialed; the association's destination is not even known until its first datagram
// arrives. Sending that datagram is what triggers the dial, which is why every
// assertion about streams, chains and cooling below is made after the round trip and
// not after this call.
func socksUDPAssociateOver(t *testing.T, e *Engine, sess Session, exitPub []byte) *net.UDPConn {
	t.Helper()
	ctrlA, ctrlB := net.Pipe()
	deadline(t, ctrlA, ctrlB)
	// Closing the control connection is RFC 1928's teardown signal for the
	// association, and the only thing that ends the relay loop short of its idle
	// timeout — so the goroutine started below exits with the test rather than
	// outliving it by udpIdleTimeout.
	t.Cleanup(func() { _ = ctrlA.Close() })
	go func() {
		buf := make([]byte, 262)
		if _, err := io.ReadFull(ctrlB, buf[:2]); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:int(buf[1])]); err != nil {
			return
		}
		if _, err := ctrlB.Write([]byte{5, 0}); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrlB, buf[:4]); err != nil {
			return
		}
		e.handleSocksUDPAssociate(ctrlB, buf, sess, exitPub, nil)
	}()

	if _, err := ctrlA.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	var method [2]byte
	if _, err := io.ReadFull(ctrlA, method[:]); err != nil || method[1] != 0 {
		t.Fatalf("method negotiation reply: %v %v", method, err)
	}
	if _, err := ctrlA.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write UDP ASSOCIATE request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrlA, reply); err != nil || reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply: %v %v", reply, err)
	}
	bnd := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}
	data, err := net.DialUDP("udp", nil, bnd)
	if err != nil {
		t.Fatalf("dial relay socket: %v", err)
	}
	t.Cleanup(func() { _ = data.Close() })
	return data
}

// udpAssociateCarries sends payload into the association and requires it back, which
// is what makes this a test of a working path rather than of a dial that returned no
// error: the first datagram is what opens the E2E channel, and the reply can only have
// come back down the chain that channel was built over.
func udpAssociateCarries(t *testing.T, data *net.UDPConn, payload string) {
	t.Helper()
	frame := encodeSOCKSUDPFrame(udpChainTarget.To4(), udpChainTargetPort, []byte(payload))
	if _, err := data.Write(frame); err != nil {
		t.Fatalf("write datagram into the association: %v", err)
	}
	_ = data.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := data.Read(buf)
	if err != nil {
		t.Fatalf("nothing came back through the association: %v", err)
	}
	got, ip, port, err := decodeSOCKSUDPFrame(buf[:n])
	if err != nil {
		t.Fatalf("malformed reply frame: %v (%v)", buf[:n], err)
	}
	if string(got) != payload {
		t.Fatalf("payload came back as %q, want %q", got, payload)
	}
	if !ip.Equal(udpChainTarget.To4()) || port != udpChainTargetPort {
		t.Fatalf("reply addressed as %s:%d, want the association's fixed destination %s:%d", ip, port, udpChainTarget, udpChainTargetPort)
	}
}

// TestUDPAssociateRebuildsAroundADeadChainHop is issue #82, and is
// TestChainRebuildDoesNotReuseTheHopThatDied (core/relaychain_liveness_test.go) put to
// the UDP path.
//
// The gap it closes is worth naming precisely. The old call site reached dialChain
// through dialE2E, so it did inherit the per-layer stall bound and the fault
// attribution, which live in there — a wedged hop was bounded and the error named the
// hop to blame. What it inherited none of is the machinery that ACTS on that: cooling,
// the dead-head escalation and the rebuild are all in dialChainedStream. So the old
// path named a suspect and then discarded it, and the rebuild it could not do at all,
// because a rebuild needs a fresh stream (ADR-0038 §5) and this caller had already
// spent the one it was handed.
//
// So midA is killed BEFORE the association is opened: this flow is the first thing to
// meet the dead hop and has nobody else's rebuild to inherit. That ordering is the
// whole test — it is the case where the UDP path failed and the equivalent TCP path
// succeeded. (Inheriting another path's rebuild was never broken, since planOf is read
// per associate; that is why it is not what this drives.)
//
// Mutation: put this call site back on OpenStream + dialE2E and the association never
// carries a byte, which is precisely what #82 reported.
func TestUDPAssociateRebuildsAroundADeadChainHop(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)
	midA, midB := m.mids[0], m.mids[1]

	sess := withChain(newChainTestSession(func() string { return m.head.addr }), planVia(m, midA))
	ts := sess.(*chainedSession).Session.(*chainTestSession)

	midA.kill()

	data := socksUDPAssociateOver(t, client, sess, m.exitKey.Public)
	udpAssociateCarries(t, data, "REBUILT_CHAIN_CARRIES_DATAGRAMS_0123456789")

	got := planOf(sess)
	if got == nil {
		t.Fatal("the session carries no chain after a rebuild")
	}
	for i, h := range got.hops {
		if h.id == midA.id {
			t.Fatalf("the rebuilt chain reuses the hop that died, at position %d/%d — a UDP flow that rebuilds onto the dead node has not recovered, it has retried", i+1, len(got.hops))
		}
	}
	if len(got.hops) != 2 {
		t.Errorf("rebuilt chain has %d peeling hops, want 2 — an association must not quietly take a shorter path than the one the user configured", len(got.hops))
	}
	if got.hops[0].id != m.head.id {
		t.Errorf("rebuilt chain is headed by %s, want the head the session terminates at (%s)", shortID(got.hops[0].id), shortID(m.head.id))
	}
	if got.hops[1].id != midB.id {
		t.Errorf("rebuilt middle hop = %s, want the only live alternative %s", shortID(got.hops[1].id), shortID(midB.id))
	}
	if !client.hopCooling(midA.id) {
		t.Error("the dead hop was not sunk into the cooling memory, so the next chain this client builds is free to select it again")
	}
	if client.hopCooling(midB.id) || client.hopCooling(m.head.id) {
		t.Error("a working hop was cooled — cooling the wrong node shrinks the usable directory for every later chain")
	}
	if n := ts.streamsOpened(); n != 2 {
		t.Errorf("opened %d streams, want 2 (the failed circuit, then the rebuilt one) — ADR-0038 §5 discards a broken circuit rather than splicing onto it, so a rebuild costs exactly one fresh stream", n)
	}
	if ts.isClosed() {
		t.Error("the session was dropped even though only a MIDDLE hop died — every other UDP association and TCP stream on it died with it, for nothing")
	}
}

// TestUDPAssociateOverAHealthyChainDialsOnceAndRebuildsNothing is the negative half,
// and it is the reason the test above says anything at all: without it every assertion
// up there would hold just as well if the UDP path rebuilt on EVERY associate — which
// would re-select the whole circuit per captured flow, and a browser opens a great many
// UDP flows.
//
// Same mesh, same depth, same associate. Nothing killed. Exactly one stream, the chain
// the session started with, and an empty cooling memory.
func TestUDPAssociateOverAHealthyChainDialsOnceAndRebuildsNothing(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)
	midA := m.mids[0]

	before := planVia(m, midA)
	sess := withChain(newChainTestSession(func() string { return m.head.addr }), before)
	ts := sess.(*chainedSession).Session.(*chainTestSession)

	data := socksUDPAssociateOver(t, client, sess, m.exitKey.Public)
	udpAssociateCarries(t, data, "HEALTHY_CHAIN_CARRIES_DATAGRAMS_0123456789")

	if n := ts.streamsOpened(); n != 1 {
		t.Errorf("opened %d streams for one associate over a healthy chain, want 1 — an associate that rebuilds when nothing failed re-selects the whole path per captured flow", n)
	}
	if planOf(sess) != before {
		t.Error("the session's chain was replaced although nothing failed — every TCP stream on this session pays for that too, since they all read the same plan")
	}
	if client.hopCooling(midA.id) || client.hopCooling(m.head.id) || client.hopCooling(m.exitID) {
		t.Error("a node was cooled on a successful associate, which would drain the usable directory one healthy flow at a time")
	}
}
