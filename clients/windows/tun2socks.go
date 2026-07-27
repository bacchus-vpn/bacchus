//go:build windows

// Bridges a raw IP packet device (the wintun adapter) to a userspace network
// stack (gVisor's netstack — pure Go, Apache-2.0, no GPL dependency) and
// forwards each intercepted flow into the client's own local SOCKS5 listener,
// exactly as if it were a SOCKS5-aware application: TCP flows use SOCKS5
// CONNECT (handleTCP/dialSOCKS), UDP flows use SOCKS5 UDP ASSOCIATE (issue
// #41, handleGeneralUDP/dialSOCKSUDPAssociate in udprelay.go). Both reuse the
// same WebRTC-tunnelled SOCKS server in core/client.go, which now answers
// both SOCKS commands (core/udprelay.go) — this file has no tunnel-internal
// knowledge either way, just standard SOCKS5 client behavior.
//
// DNS (UDP/53) keeps its pre-existing special case (handleDNSUDP): resolved
// via DNS-over-TCP through the same SOCKS tunnel rather than the general UDP
// path, so name resolution doesn't depend on the newer, less-proven code.
//
// Hard invariant for the general UDP path: if a flow's tunnel relay can't be
// established, its datagrams are dropped — never sent in the clear, and
// never a fallback to a direct dial for a destination that was supposed to
// be tunnelled (see splittunnel.go's policy.direct and the kill-switch,
// killswitch.go). See udprelay_test.go for the test proving this.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID tcpip.NICID = 1

// netTun owns the gVisor stack and the pump goroutines that move packets
// between it and the OS TUN device.
type netTun struct {
	dev   tun.Device
	ep    *channel.Endpoint
	stack *stack.Stack
	stop  context.CancelFunc
}

// startNetstack brings up a userspace netstack over dev: localIP is the
// client's own address on the tunnel (assigned to the stack's NIC, not the
// OS interface — that's routes.go's job). socksAddr is the existing local
// SOCKS5 server core.Engine.Connect already runs; dnsUpstream is the plain
// DNS (port 53) server queried over DNS-over-TCP through that SOCKS tunnel.
// policy is the destination-based split-tunnelling decision (splittunnel.go)
// consulted for every flow and every intercepted DNS exchange.
func startNetstack(dev tun.Device, localIP tcpip.Address, socksAddr, dnsUpstream string, policy *bypassPolicy) (*netTun, error) {
	mtu, err := dev.MTU()
	if err != nil || mtu <= 0 {
		mtu = 1420
	}

	ep := channel.New(1024, uint32(mtu), "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("netstack: create nic: %v", err)
	}
	// Promiscuous + spoofing: this stack is acting as a router for the whole
	// device, not as a single end host, so it must accept/originate packets
	// for addresses other than its own.
	_ = s.SetPromiscuousMode(nicID, true)
	_ = s.SetSpoofing(nicID, true)
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: localIP.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("netstack: add address: %v", err)
	}
	// IPv4 is routed to this NIC; IPv6 has no route (and no address) so it is
	// dropped here as a second line of defense — the OS-level IPv6 block in
	// routes.go is the primary one.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})

	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		go handleTCP(r, socksAddr, policy)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		go handleUDP(r, socksAddr, dnsUpstream, policy)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	ctx, cancel := context.WithCancel(context.Background())
	nt := &netTun{dev: dev, ep: ep, stack: s, stop: cancel}
	go nt.pumpInbound(ctx)
	go nt.pumpOutbound(ctx)
	return nt, nil
}

// Close tears the netstack down and stops the pump goroutines.
func (nt *netTun) Close() {
	nt.stop()
	nt.ep.Close()
	nt.stack.Close()
}

// pumpInbound reads raw IP packets off the OS TUN device and injects them
// into the netstack.
func (nt *netTun) pumpInbound(ctx context.Context) {
	batch := nt.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := nt.dev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			data := bufs[i][:sizes[i]]
			if len(data) == 0 {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch data[0] >> 4 {
			case 4:
				proto = ipv4.ProtocolNumber
			case 6:
				proto = ipv6.ProtocolNumber
			default:
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append([]byte(nil), data...)),
			})
			nt.ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}
}

// pumpOutbound reads packets the netstack produced (replies, forwarded
// traffic) and writes them to the OS TUN device.
func (nt *netTun) pumpOutbound(ctx context.Context) {
	for {
		pkt := nt.ep.ReadContext(ctx)
		if pkt == nil {
			return // ctx cancelled
		}
		buf := pkt.ToBuffer()
		b := buf.Flatten()
		pkt.DecRef()
		if len(b) == 0 {
			continue
		}
		_, _ = nt.dev.Write([][]byte{b}, 0)
	}
}

// handleTCP bridges one intercepted TCP flow either to the local SOCKS5
// server (the tunnel) or directly out the physical interface, per policy —
// see splittunnel.go's file doc comment for why "direct" only actually
// leaves the machine when an exclusion route already exists for it.
func handleTCP(r *tcp.ForwarderRequest, socksAddr string, policy *bypassPolicy) {
	id := r.ID()
	dst := net.IP(id.LocalAddress.AsSlice())
	target := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	var remote net.Conn
	var dialErr error
	if policy.direct(dst) {
		remote, dialErr = net.Dial("tcp", target)
	} else {
		remote, dialErr = dialSOCKS(socksAddr, target)
	}
	if dialErr != nil {
		return
	}
	defer remote.Close()

	go func() { _, _ = io.Copy(remote, local); _ = remote.Close() }()
	_, _ = io.Copy(local, remote)
}

// handleUDP dispatches an intercepted UDP flow: DNS (port 53) keeps its
// pre-existing DNS-over-TCP special case (handleDNSUDP); everything else is
// general UDP forwarding (issue #41, handleGeneralUDP) — QUIC/HTTP3, VoIP,
// games, or any other UDP application, tunnelled the same way TCP already is.
func handleUDP(r *udp.ForwarderRequest, socksAddr, dnsUpstream string, policy *bypassPolicy) {
	if r.ID().LocalPort == 53 {
		handleDNSUDP(r, socksAddr, dnsUpstream, policy)
		return
	}
	handleGeneralUDP(r, socksAddr, policy)
}

// handleDNSUDP intercepts DNS (port 53); every query/answer pair is also
// handed to policy.observeDNS so a bypass domain's resolved addresses get
// learned as split-tunnelling destinations — before the answer goes back to
// whatever on the device asked for it, so its exclusion route exists before
// the follow-up TCP connect can race it.
func handleDNSUDP(r *udp.ForwarderRequest, socksAddr, dnsUpstream string, policy *bypassPolicy) {
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	conn := gonet.NewUDPConn(&wq, ep)
	defer conn.Close()

	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		resp, err := resolveDNSOverTCP(buf[:n], socksAddr, dnsUpstream)
		if err != nil {
			continue
		}
		policy.observeDNS(buf[:n], resp)
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

// handleGeneralUDP bridges one intercepted non-DNS UDP flow (issue #41) to
// either a direct local UDP dial or the tunnel's SOCKS5 UDP ASSOCIATE, per
// policy — mirrors handleTCP exactly, including why "direct" only actually
// leaves the machine when an exclusion route already exists for it
// (splittunnel.go's file doc comment).
//
// Hard invariant: if the tunnel relay can't be established, relayErr is
// non-nil and this returns immediately without ever touching conn again — the
// intercepted datagram(s) are simply dropped. There is deliberately no
// fallback to a direct dial here: a destination policy routed through the
// tunnel must never reach the network any other way just because the tunnel
// path failed. See TestHandleGeneralUDPDropsWhenTunnelUnreachable in
// udprelay_test.go.
func handleGeneralUDP(r *udp.ForwarderRequest, socksAddr string, policy *bypassPolicy) {
	id := r.ID()
	dst := net.IP(id.LocalAddress.AsSlice())
	target := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	conn := gonet.NewUDPConn(&wq, ep)
	defer conn.Close()

	var relay udpRelay
	var relayErr error
	if policy.direct(dst) {
		relay, relayErr = dialDirectUDP(target)
	} else {
		relay, relayErr = dialSOCKSUDPAssociate(socksAddr, target)
	}
	if relayErr != nil {
		return
	}
	defer relay.Close()

	pumpUDP(conn, relay, udpIdleTimeout)
}

// resolveDNSOverTCP forwards one DNS query to dnsUpstream over a
// SOCKS5-tunnelled TCP connection (RFC 1035 2-byte length-prefixed framing)
// and returns the raw answer payload.
func resolveDNSOverTCP(query []byte, socksAddr, dnsUpstream string) ([]byte, error) {
	conn, err := dialSOCKS(socksAddr, dnsUpstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	var lenPrefix [2]byte
	binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(query)))
	if _, err := conn.Write(lenPrefix[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenPrefix[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenPrefix[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func dialSOCKS(socksAddr, target string) (net.Conn, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return d.Dial("tcp", target)
}
