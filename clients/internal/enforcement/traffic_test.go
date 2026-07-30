// Parity item 8: a traffic-level test, not a state-level one.
//
// ADR-0039's Scope section records why this item exists at all. The Fyne
// client reached Protected, reported "your connection is private and secure",
// and sent 100% of the user's traffic in the clear, because it asked core for
// an ephemeral SOCKS port nothing could ever discover. Every build-time check
// stayed green through it. Every test asked the state machine how it felt,
// and the state machine was telling the truth — the tunnel really was up. The
// sentence about it was the lie.
//
// So the bar for a platform's Enforcer is not "Start returned nil". It is a
// real byte round-tripped through a real exit over the ENFORCED path, plus a
// leak check. That is what these two tests do, and everything below the wire
// is real: a real gVisor netstack, a real SOCKS5 bridge, a real core.Engine
// on both ends, a real transport handshake, a real exit egressing to a real
// listener. The one simulated part is the TUN device itself (memtun_test.go),
// which is what lets this run unelevated on every push instead of by hand on
// an administrator's Windows box.
//
// What that substitution does and does not cover is worth being exact about,
// because overclaiming here is the same failure this item exists to catch.
// Covered: everything from the IP packet inward — capture, forwarding, the
// split-tunnel decision, SOCKS5, the engine, the exit, and the return path.
// Not covered: whether the OS actually hands this device the packets in the
// first place, which is the route table's job and lives behind PowerShell in
// routes_windows.go (see killswitch_windows_test.go for the ordering those
// calls have to keep, and ADR-0039's 2026-07-30 amendment for what a live
// elevated Windows run confirmed on top of these).
package enforcement

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// deviceIP is the "rest of the machine" side of the simulated TUN wire: the
// source address packets arrive from, standing in for whatever application on
// the device opened the connection.
const deviceIP = "10.66.0.9"

// TestEnforcedPathCarriesRealTraffic is parity item 8's first half. A byte
// enters at the TUN device — as a real IP packet, from a real TCP stack that
// knows nothing about Bacchus — and has to come back having been to a real
// exit. If the netstack, the split-tunnel decision, the SOCKS bridge, the
// engine or the exit is broken or bypassed, the payload does not come back
// and this fails.
//
// It is deliberately not asserting on any state, event, or return value from
// the enforcement layer. Those are exactly what were green while the client
// leaked.
func TestEnforcedPathCarriesRealTraffic(t *testing.T) {
	socksAddr := startTunnelledSession(t)
	echoAddr := startEchoServer(t)

	dev := newMemTun()
	t.Cleanup(func() { _ = dev.Close() })

	tunAddr, err := v4Address(tunIP)
	if err != nil {
		t.Fatalf("v4Address: %v", err)
	}
	nt, err := startNetstack(dev, tunAddr, socksAddr, "", newBypassPolicy(BypassModeExclude, nil))
	if err != nil {
		t.Fatalf("startNetstack: %v", err)
	}
	t.Cleanup(nt.Close)

	payload := []byte("bacchus carries this over the enforced path or the banner is a lie")
	got, err := deviceRoundTrip(t, dev, echoAddr, payload, 25*time.Second)
	if err != nil {
		t.Fatalf("a byte entering at the TUN device never came back: %v\n"+
			"The enforced path is what the user is told protects their whole device; if traffic does not "+
			"traverse it, every 'Protected' this client shows is the ADR's own false-headline defect.", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip over the enforced path returned %q, want %q", got, payload)
	}
}

// TestEnforcedPathDropsRatherThanLeakingWhenTheTunnelDies is parity item 8's
// second half: the leak check.
//
// The kill-switch's own guarantee — an OS-level filter that keeps blocking
// after this process is gone — is a firewall property, and it is asserted
// where it lives, against the exact cmdlet sequence
// (killswitch_windows_test.go). What is asserted here is the half that is
// this package's own code rather than the OS's, and it is the half a port
// would actually get wrong: when the tunnel is gone, a flow to a destination
// that was supposed to be tunnelled must be DROPPED, not quietly re-dialled
// on the physical interface because that path still works.
//
// tun2socks.go states this as a hard invariant for UDP and
// TestHandleGeneralUDPDropsWhenTunnelUnreachable proves it at the handler
// level. This proves the TCP side of it at the traffic level, from the
// device's own point of view, against a real listener that records whether
// anything ever reached it: the failure mode being ruled out is not "an error
// is returned" but "the byte arrives anyway, by another route".
func TestEnforcedPathDropsRatherThanLeakingWhenTheTunnelDies(t *testing.T) {
	// A SOCKS address with nothing behind it: the tunnel this session was
	// bridged into is dead, exactly as it is after a crash or a mid-session
	// transport failure, with the physical path to the destination still
	// perfectly usable.
	deadSocks := reserveLoopbackAddr(t)

	reached := make(chan string, 4)
	echoAddr := startRecordingServer(t, reached)

	dev := newMemTun()
	t.Cleanup(func() { _ = dev.Close() })

	tunAddr, err := v4Address(tunIP)
	if err != nil {
		t.Fatalf("v4Address: %v", err)
	}
	nt, err := startNetstack(dev, tunAddr, deadSocks, "", newBypassPolicy(BypassModeExclude, nil))
	if err != nil {
		t.Fatalf("startNetstack: %v", err)
	}
	t.Cleanup(nt.Close)

	// Expected to fail — there is no tunnel. What matters is what happened to
	// the destination, not what this returned.
	_, _ = deviceRoundTrip(t, dev, echoAddr, []byte("this must never arrive"), 3*time.Second)

	select {
	case who := <-reached:
		t.Fatalf("traffic reached %s with the tunnel down (connection from %s).\n"+
			"A destination the policy routes through the tunnel must be dropped when the tunnel is unavailable, "+
			"never dialled directly as a fallback: that is a silent leak of exactly the traffic the user asked to protect.", echoAddr, who)
	case <-time.After(2 * time.Second):
		// Nothing arrived, which is the pass condition.
	}
}

// TestEnforcedPathSendsBypassDestinationsDirect is two things at once.
//
// It is parity item 1's traffic-level half: a destination in the split-tunnel
// bypass set must egress the physical interface rather than the tunnel, and
// "egress" is checked by the destination actually receiving the connection,
// not by asking bypassPolicy what it thinks.
//
// It is also the control for the leak test above, and that is why it uses
// the same dead SOCKS address. Without it, a leak check that observes nothing
// arriving is indistinguishable from a leak check whose instrument is broken
// — a listener nothing can ever reach passes forever, including on the day
// the code starts leaking. This is the same setup with one field changed
// (the destination is in the bypass set), and it must see the connection.
// One of these two tests failing is a real defect; both passing is what makes
// either meaningful.
func TestEnforcedPathSendsBypassDestinationsDirect(t *testing.T) {
	deadSocks := reserveLoopbackAddr(t)

	reached := make(chan string, 4)
	echoAddr := startRecordingServer(t, reached)
	host, _, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}

	dev := newMemTun()
	t.Cleanup(func() { _ = dev.Close() })

	tunAddr, err := v4Address(tunIP)
	if err != nil {
		t.Fatalf("v4Address: %v", err)
	}
	// Exclude mode with the destination listed: "listed destinations go
	// direct, everything else is tunnelled" (splittunnel.go).
	nt, err := startNetstack(dev, tunAddr, deadSocks, "", newBypassPolicy(BypassModeExclude, []string{host}))
	if err != nil {
		t.Fatalf("startNetstack: %v", err)
	}
	t.Cleanup(nt.Close)

	payload := []byte("a bypass destination keeps the real path")
	got, err := deviceRoundTrip(t, dev, echoAddr, payload, 10*time.Second)
	if err != nil {
		t.Fatalf("a bypass destination did not reach the physical path: %v\n"+
			"Split-tunnel exclude mode means listed destinations go direct; if they cannot, the feature is broken. "+
			"This also means the leak test above proves nothing, since its listener is evidently unreachable either way.", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("direct round trip returned %q, want %q", got, payload)
	}
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("the direct round trip succeeded but the listener recorded no connection — the leak test's instrument does not work")
	}
}

// deviceRoundTrip drives one real TCP connection from the "device side" of
// the TUN wire to target, through whatever the netstack on the other side
// does with it, and returns the echoed bytes.
//
// The device side is a second, independent gVisor stack whose link endpoint
// is wired to the memTun — so the connection really is carried as IP packets
// over the device, with a real three-way handshake, rather than by calling
// into the enforcement netstack's handlers directly. A test that called the
// handlers would prove the handlers work; this proves the path does.
func deviceRoundTrip(t *testing.T, dev *memTun, target string, payload []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()

	s := startDeviceStack(t, dev)

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("split target: %w", err)
	}
	ip4 := net.ParseIP(host).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("target must be an IPv4 literal, got %q", host)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte(ip4)),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("dial over the tun device: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return nil, fmt.Errorf("read echo: %w", err)
	}
	return got, nil
}

// startDeviceStack builds the "rest of the machine" end of the TUN wire: a
// plain IPv4/TCP stack that routes everything at the device, with no
// knowledge of Bacchus at all. Its outbound packets become the netstack's
// reads and vice versa.
func startDeviceStack(t *testing.T, dev *memTun) *stack.Stack {
	t.Helper()

	const mtu = 1420
	ep := channel.New(256, mtu, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() { ep.Close(); s.Close() })

	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("device stack: create nic: %v", err)
	}
	addr, err := v4Address(deviceIP)
	if err != nil {
		t.Fatalf("device stack: %v", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("device stack: add address: %v", err)
	}
	// Everything goes at the tunnel, which is what an installed default route
	// does on a real machine — the route table's job, simulated here because
	// the route table itself is the part that cannot run unelevated.
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	// Spoofing so this stack may originate from deviceIP toward any
	// destination without owning a route to it specifically.
	_ = s.SetSpoofing(1, true)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// device -> tun device (what the enforcement netstack will Read)
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			buf := pkt.ToBuffer()
			b := buf.Flatten()
			pkt.DecRef()
			if len(b) == 0 {
				continue
			}
			select {
			case dev.toStack <- b:
			case <-ctx.Done():
				return
			}
		}
	}()
	// tun device -> device (what the enforcement netstack Wrote)
	go func() {
		for {
			select {
			case b := <-dev.toDevice:
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(b),
				})
				ep.InjectInbound(ipv4.ProtocolNumber, pkt)
				pkt.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	return s
}

// startTunnelledSession brings up a real exit, a real client engine and a
// real transport between them over loopback, and returns the client's local
// SOCKS5 address — the same thing core.Engine.Connect hands the enforcement
// layer in production.
func startTunnelledSession(t *testing.T) string {
	t.Helper()

	coord := newFakeCoordinator(t)

	exitEng, err := core.New(core.Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{core.RoleExit},
		ListenAddr:   "127.0.0.1:0",
		Advertise:    "127.0.0.1:1",
		Country:      "zz",
	})
	if err != nil {
		t.Fatalf("exit New: %v", err)
	}
	if err := exitEng.Start(context.Background()); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	t.Cleanup(exitEng.Stop)

	if !waitFor(5*time.Second, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return coord.exit != nil
	}) {
		t.Fatal("exit never registered with the fake coordinator")
	}

	socksAddr := reserveLoopbackAddr(t)
	cliEng, err := core.New(core.Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{core.RoleClient},
		SocksAddr:    socksAddr,
	})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := cliEng.Start(ctx); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	t.Cleanup(cliEng.Stop)
	if err := cliEng.Connect(ctx); err != nil {
		t.Fatalf("client Connect: %v", err)
	}
	return socksAddr
}

// reserveLoopbackAddr picks a free loopback port and returns it as host:port.
// core exposes no accessor for a bound SOCKS address (the defect ADR-0039's
// Scope section records), so a caller that needs to know the address has to
// choose it up front — which is exactly what both clients do.
func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// listenOffLoopback starts a listener on this host's first non-loopback IPv4
// address, because the destination in these tests has to survive the netstack
// under test.
//
// startNetstack's NIC is not a loopback NIC, and gVisor drops an inbound
// packet addressed to 127.0.0.0/8 on a non-loopback NIC as a martian
// (ipv4.go's AllowExternalLoopbackTraffic check). That is correct production
// behaviour and is left exactly as it is: a real device has no business
// routing loopback into the tunnel, and relaxing it in the code under test to
// make a test pass would be testing a netstack this client does not ship.
//
// So the "internet" end of the round trip lives off loopback, the way the
// real one does. The address is discovered at runtime and never logged or
// written anywhere — nothing about this host reaches the repository.
func listenOffLoopback(t *testing.T) net.Listener {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("enumerate interfaces: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(ipnet.IP.String(), "0"))
		if err != nil {
			continue
		}
		return ln
	}
	t.Skip("no non-loopback IPv4 address on this host, so the enforced path cannot be driven to a destination " +
		"the netstack will accept — parity item 8 is UNVERIFIED on this run, not passing")
	return nil
}

// startEchoServer is a TCP echo the exit can dial: the "internet" end of the
// round trip. Mirrors the helper of the same name in
// clients/fyne/internal/appstate and cmd/node, off loopback for the reason
// listenOffLoopback documents.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln := listenOffLoopback(t)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startRecordingServer is startEchoServer's leak-check counterpart: it still
// echoes, but it also reports every connection it receives, so a test can
// assert that nothing arrived rather than merely that the client saw an
// error.
func startRecordingServer(t *testing.T, reached chan<- string) string {
	t.Helper()
	ln := listenOffLoopback(t)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case reached <- c.RemoteAddr().String():
			default:
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func waitFor(limit time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}
