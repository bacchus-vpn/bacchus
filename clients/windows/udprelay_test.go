//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// --- fake tunnel: a local SOCKS5 UDP ASSOCIATE echo server ---

// fakeSOCKSUDPAssociateEcho starts a local TCP listener that accepts one
// SOCKS5 UDP ASSOCIATE request per connection (the same subset
// core/client.go's real handleSocksUDPAssociate implements) and echoes every
// RFC 1928-framed datagram it receives straight back — enough to exercise
// dialSOCKSUDPAssociate's framing and pumpUDP's wiring end to end without a
// live core engine or exit.
func fakeSOCKSUDPAssociateEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSOCKSUDPAssociate(c)
		}
	}()
	return ln.Addr().String()
}

func serveFakeSOCKSUDPAssociate(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 3 {
		return
	}
	if buf[3] != 1 {
		return
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil { // DST.ADDR, advisory: discarded
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil { // DST.PORT, advisory: discarded
		return
	}

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer relay.Close()
	bnd := relay.LocalAddr().(*net.UDPAddr)
	reply := make([]byte, 10)
	reply[0], reply[3] = 5, 1
	copy(reply[4:8], bnd.IP.To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(bnd.Port))
	if _, err := c.Write(reply); err != nil {
		return
	}

	ctrlDone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, c); close(ctrlDone) }()

	echoBuf := make([]byte, 65535)
	for {
		select {
		case <-ctrlDone:
			return
		default:
		}
		_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := relay.ReadFromUDP(echoBuf)
		if err != nil {
			return
		}
		if _, err := relay.WriteToUDP(echoBuf[:n], from); err != nil {
			return
		}
	}
}

func TestDialSOCKSUDPAssociateRoundTrip(t *testing.T) {
	socksAddr := fakeSOCKSUDPAssociateEcho(t)
	relay, err := dialSOCKSUDPAssociate(socksAddr, "203.0.113.9:51820")
	if err != nil {
		t.Fatalf("dialSOCKSUDPAssociate: %v", err)
	}
	defer relay.Close()

	payload := []byte("quic-ish datagram")
	if _, err := relay.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := relay.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echoed = %q, want %q", buf[:n], payload)
	}
}

func TestDialSOCKSUDPAssociateFailsWhenNothingListens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // now nothing listens on addr

	if _, err := dialSOCKSUDPAssociate(addr, "203.0.113.9:51820"); err == nil {
		t.Fatal("dialSOCKSUDPAssociate should fail against a dead SOCKS address")
	}
}

// fakeSOCKSUDPAssociateNonLoopbackReply completes the SOCKS5 UDP ASSOCIATE
// handshake like fakeSOCKSUDPAssociateEcho, but replies with a non-loopback
// BND.ADDR — standing in for a compromised or misconfigured local SOCKS
// server, to prove dialSOCKSUDPAssociate refuses to dial it (issue #99).
func fakeSOCKSUDPAssociateNonLoopbackReply(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 262)
		if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
			return
		}
		if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
			return
		}
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return
		}
		if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 3 {
			return
		}
		if _, err := io.ReadFull(c, buf[:6]); err != nil { // DST.ADDR+DST.PORT, discarded
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 8, 8, 8, 8, 0x27, 0x11}) // BND.ADDR = 8.8.8.8:10001
		_, _ = io.Copy(io.Discard, c)
	}()
	return ln.Addr().String()
}

func TestDialSOCKSUDPAssociateRejectsNonLoopbackReply(t *testing.T) {
	socksAddr := fakeSOCKSUDPAssociateNonLoopbackReply(t)
	if _, err := dialSOCKSUDPAssociate(socksAddr, "203.0.113.9:51820"); err == nil {
		t.Fatal("dialSOCKSUDPAssociate should reject a non-loopback BND.ADDR")
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
		if _, _, _, ok := decodeSOCKSUDPFrame(b); ok {
			t.Errorf("%s: decodeSOCKSUDPFrame should have rejected %v", name, b)
		}
	}
}

// --- pumpUDP: in-memory relay pairs, no real sockets ---

// fakeUDPRelay is an in-memory udpRelay. Two of them, from
// newFakeUDPRelayPair, are cross-wired like net.Pipe(): writing to one is
// readable from the other, and both share one underlying "closed" signal so
// closing either end is visible from both.
type fakeUDPRelay struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   *sync.Once
}

func newFakeUDPRelayPair() (a, b *fakeUDPRelay) {
	ab := make(chan []byte, 16)
	ba := make(chan []byte, 16)
	closed := make(chan struct{})
	once := &sync.Once{}
	return &fakeUDPRelay{in: ba, out: ab, closed: closed, once: once},
		&fakeUDPRelay{in: ab, out: ba, closed: closed, once: once}
}

func (f *fakeUDPRelay) Read(p []byte) (int, error) {
	select {
	case b := <-f.in:
		return copy(p, b), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeUDPRelay) Write(p []byte) (int, error) {
	select {
	case f.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-f.closed:
		return 0, io.ErrClosedPipe
	}
}

func (f *fakeUDPRelay) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func TestPumpUDPBidirectional(t *testing.T) {
	connPump, connTest := newFakeUDPRelayPair() // pumpUDP's "conn" side / the test's driver
	relayPump, relayTest := newFakeUDPRelayPair()

	done := make(chan struct{})
	go func() { pumpUDP(connPump, relayPump, time.Second); close(done) }()

	// Outbound: the "app" (connTest) sends a datagram; it must reach the
	// "tunnel" (relayTest).
	if _, err := connTest.Write([]byte("outbound")); err != nil {
		t.Fatalf("connTest.Write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := readWithTimeout(t, relayTest, buf)
	if err != nil {
		t.Fatalf("relayTest.Read: %v", err)
	}
	if string(buf[:n]) != "outbound" {
		t.Fatalf("relay saw %q, want %q", buf[:n], "outbound")
	}

	// Inbound: the "tunnel" (relayTest) sends a reply; it must reach the
	// "app" (connTest).
	if _, err := relayTest.Write([]byte("inbound")); err != nil {
		t.Fatalf("relayTest.Write: %v", err)
	}
	n, err = readWithTimeout(t, connTest, buf)
	if err != nil {
		t.Fatalf("connTest.Read: %v", err)
	}
	if string(buf[:n]) != "inbound" {
		t.Fatalf("conn saw %q, want %q", buf[:n], "inbound")
	}

	connTest.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pumpUDP should have stopped once conn closed")
	}
}

func TestPumpUDPIdleTimeoutClosesBothSides(t *testing.T) {
	connPump, connTest := newFakeUDPRelayPair()
	relayPump, relayTest := newFakeUDPRelayPair()

	go pumpUDP(connPump, relayPump, 40*time.Millisecond)

	select {
	case <-connTest.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("pumpUDP should have torn the conn side down after going idle")
	}
	select {
	case <-relayTest.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("pumpUDP should have torn the relay side down after going idle")
	}
}

func TestPumpUDPActivityDelaysIdleTimeout(t *testing.T) {
	connPump, connTest := newFakeUDPRelayPair()
	relayPump, relayTest := newFakeUDPRelayPair()

	const idle = 80 * time.Millisecond
	go pumpUDP(connPump, relayPump, idle)

	// Keep sending well inside the idle window, for longer than idle would
	// allow if activity didn't reset it.
	deadline := time.Now().Add(idle * 4)
	for time.Now().Before(deadline) {
		if _, err := connTest.Write([]byte("keepalive")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := readWithTimeout(t, relayTest, make([]byte, 64)); err != nil {
			t.Fatalf("relay read: %v", err)
		}
		time.Sleep(idle / 4)
	}
	select {
	case <-connTest.closed:
		t.Fatal("pumpUDP closed the flow despite continuous activity")
	default:
	}

	// Now actually go idle and confirm it does eventually close.
	select {
	case <-connTest.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("pumpUDP should tear down once activity actually stops")
	}
}

func readWithTimeout(t *testing.T, r udpRelay, buf []byte) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	out := make(chan result, 1)
	go func() {
		n, err := r.Read(buf)
		out <- result{n, err}
	}()
	select {
	case res := <-out:
		return res.n, res.err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a datagram")
		return 0, nil
	}
}

// --- handleGeneralUDP: real gVisor forwarding, no OS TUN device needed ---
//
// gonet.DialUDP against the *same* stack that owns the UDP forwarder does
// NOT exercise handleGeneralUDP: a DialUDP endpoint is a locally-owned,
// already-claimed socket, so the stack routes its outbound packets straight
// to the channel.Endpoint (as if handing them to a TUN device) rather than
// through the forwarder, which only fires for arriving packets no local
// endpoint has claimed yet. So this needs two stacks — one standing in for
// "the app" (a plain stack DialUDP can use normally), one standing in for
// the tunnel's real netstack (with the forwarder registered) — bridged by
// pumping whatever one emits into the other's InjectInbound, exactly
// mirroring how netTun's pumpInbound/pumpOutbound (tun2socks.go) bridge the
// real OS TUN device to the netstack. That makes the app stack's outbound
// packets arrive at the tunnel stack as genuinely unclaimed inbound traffic,
// which is what actually triggers the forwarder.

// newBridgedTunnelStack returns the "app" stack: dial through it with
// gonet.DialUDP to simulate a captured local app connection. Its packets are
// bridged into a second, separate "tunnel" stack with fn wired up as its UDP
// forwarder (handleGeneralUDP in production) — no OS TUN device or admin
// privilege needed anywhere in this.
func newBridgedTunnelStack(t *testing.T, fn func(r *udp.ForwarderRequest)) *stack.Stack {
	t.Helper()
	epApp := channel.New(64, 1500, "")
	epTun := channel.New(64, 1500, "")

	appStack := newIPv4UDPStack(t, epApp, tcpip.AddrFrom4([4]byte{10, 0, 0, 5}))
	tunStack := newIPv4UDPStack(t, epTun, tcpip.AddrFrom4([4]byte{10, 66, 0, 2}))
	_ = tunStack.SetSpoofing(nicID, true)
	_ = tunStack.SetPromiscuousMode(nicID, true)

	udpFwd := udp.NewForwarder(tunStack, fn)
	tunStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go bridgeEndpoints(ctx, epApp, epTun)
	go bridgeEndpoints(ctx, epTun, epApp)

	return appStack
}

// newIPv4UDPStack builds a minimal gVisor stack (IPv4+UDP only) over ep,
// addressed as addr with a catch-all default route — the shared setup both
// sides of newBridgedTunnelStack need. AllowExternalLoopbackTraffic is on
// because TestHandleGeneralUDPDropsWhenTunnelUnreachable deliberately uses a
// loopback address as its "internet destination" stand-in (so it can bind a
// real listener to prove nothing arrives there) — without this, gVisor's own
// martian-packet filter silently drops that packet before it ever reaches
// the UDP forwarder, which would make that test pass vacuously (it did,
// until this was caught) rather than actually exercising handleGeneralUDP.
func newIPv4UDPStack(t *testing.T, ep *channel.Endpoint, addr tcpip.Address) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	t.Cleanup(s.Close)
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return s
}

// bridgeEndpoints pumps every packet src emits into dst's inbound queue —
// the same job netTun.pumpInbound/pumpOutbound (tun2socks.go) do between the
// real OS TUN device and the netstack, just stack-to-stack here.
func bridgeEndpoints(ctx context.Context, src, dst *channel.Endpoint) {
	for {
		pkt := src.ReadContext(ctx)
		if pkt == nil {
			return
		}
		buf := pkt.ToBuffer()
		b := buf.Flatten()
		pkt.DecRef()
		if len(b) == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch b[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		default:
			continue
		}
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), b...)),
		})
		dst.InjectInbound(proto, newPkt)
		newPkt.DecRef()
	}
}

// TestHandleGeneralUDPForwardsThroughFakeTunnel proves the feature actually
// works end to end through the real netstack forwarder: a flow captured by
// the stack, addressed to a destination the split-tunnel policy routes
// through the tunnel, is relayed via SOCKS5 UDP ASSOCIATE and the reply
// comes back correctly.
func TestHandleGeneralUDPForwardsThroughFakeTunnel(t *testing.T) {
	socksAddr := fakeSOCKSUDPAssociateEcho(t)
	policy := newBypassPolicy("exclude", nil) // nothing bypassed -> everything tunnels

	s := newBridgedTunnelStack(t, func(r *udp.ForwarderRequest) {
		go handleGeneralUDP(r, socksAddr, policy)
	})

	raddr := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 9}), Port: 51820}
	conn, err := gonet.DialUDP(s, nil, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello through the tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echoed = %q, want %q", buf[:n], payload)
	}
}

// TestHandleGeneralUDPDropsWhenTunnelUnreachable is the hard-invariant test
// (issue #41): when the tunnel relay can't be established, the captured
// datagram must be dropped — never sent to the real destination in the
// clear. target stands in for "the open internet destination" this flow is
// addressed to; if handleGeneralUDP ever fell back to a direct send despite
// split-tunnel policy requiring the tunnel, this is what would receive it.
func TestHandleGeneralUDPDropsWhenTunnelUnreachable(t *testing.T) {
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

	// Nothing listens here — the tunnel path's dial fails immediately,
	// simulating "the tunnel is down."
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	socksAddr := deadLn.Addr().String()
	deadLn.Close()

	policy := newBypassPolicy("exclude", nil) // nothing bypassed -> must tunnel, never go direct

	// A dedicated guard, independent of "received" below: this test's whole
	// point is a *negative* assertion (nothing arrives), which is trivially
	// true if handleGeneralUDP was never even reached — e.g. gVisor's own
	// martian-packet filtering silently dropping the packet earlier (this
	// exact trap already caught once when writing this test; see
	// newIPv4UDPStack's doc comment). forwarderInvoked makes that failure
	// mode loud instead of the test passing for the wrong reason.
	forwarderInvoked := make(chan struct{}, 1)
	s := newBridgedTunnelStack(t, func(r *udp.ForwarderRequest) {
		select {
		case forwarderInvoked <- struct{}{}:
		default:
		}
		go handleGeneralUDP(r, socksAddr, policy)
	})

	targetAddr := target.LocalAddr().(*net.UDPAddr)
	raddr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte(targetAddr.IP.To4())),
		Port: uint16(targetAddr.Port),
	}
	conn, err := gonet.DialUDP(s, nil, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("must-not-leak")); err != nil {
		t.Fatalf("write into tunnel-bound conn: %v", err)
	}

	select {
	case <-forwarderInvoked:
	case <-time.After(2 * time.Second):
		t.Fatal("handleGeneralUDP's forwarder was never invoked — this test would otherwise pass vacuously")
	}

	select {
	case b := <-received:
		t.Fatalf("target received %q — the datagram leaked outside the tunnel", b)
	case <-time.After(500 * time.Millisecond):
		// No leak: correct, fail-closed behavior.
	}
}
