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

	e := &Engine{exitKey: key, udpIdleTimeout: 5 * time.Second}
	go e.exitTerminate("", sConn)

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

	e := &Engine{exitKey: key, udpIdleTimeout: 40 * time.Millisecond}
	go e.exitTerminate("", sConn)

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
	e := &Engine{exitKey: key, udpIdleTimeout: 5 * time.Second}
	go func() {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		e.exitTerminate("", st)
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
	e := &Engine{exitKey: key, udpIdleTimeout: 5 * time.Second}
	go func() {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		e.exitTerminate("", st)
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
