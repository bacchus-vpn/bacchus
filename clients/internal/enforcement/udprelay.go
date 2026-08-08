// General UDP forwarding (old #41): a genuine SOCKS5 UDP ASSOCIATE client
// (RFC 1928 §4/§7) against the tunnel's local SOCKS server
// (core/client.go's handleSocksUDPAssociate, core/udprelay.go), plus the
// idle-timeout pump that bridges one gVisor-captured flow to it (or to a
// direct dial, for split-tunnel destinations). This file has no tunnel-
// internal knowledge — it treats the local SOCKS server as any standard
// SOCKS5 UDP ASSOCIATE server, the same relationship dialSOCKS already has
// with it for CONNECT.
package enforcement

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxUDPDatagram    = 65535             // largest possible UDP payload
	socksUDPHeaderLen = 2 + 1 + 1 + 4 + 2 // RFC 1928 §7, IPv4 only: RSV+FRAG+ATYP+addr+port
)

// udpIdleTimeout is how long a captured UDP flow may sit with no datagram in
// either direction before pumpUDP tears it down — the client-driven half of
// old #41's NAT-style association expiry (core/engine.go's udpIdleTimeout
// field is the exit-side backstop for when this signal never arrives). A
// var, not a const, so a test can shrink it.
var udpIdleTimeout = 45 * time.Second

// udpRelay is a fixed-destination datagram relay: each Read returns exactly
// one inbound datagram's payload and each Write sends exactly one outbound
// datagram's payload. A direct local UDP socket (net.Conn, from net.Dial)
// and socksUDPAssoc both satisfy this identically, so pumpUDP doesn't need
// to know which one it's holding.
type udpRelay interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// dialDirectUDP dials target directly, bypassing the tunnel — the
// split-tunnel "direct" path (policy.direct in handleGeneralUDP), mirroring
// handleTCP's net.Dial("tcp", ...) direct case.
func dialDirectUDP(target string) (udpRelay, error) {
	return net.Dial("udp", target)
}

// pumpUDP relays datagrams both ways between conn (the gVisor-side virtual
// socket for one captured flow — a *gonet.UDPConn in production, satisfying
// udpRelay structurally like everything else here) and relay (either a
// direct dial or a SOCKS UDP ASSOCIATE tunnel) until either side
// closes/errors or idle passes with no datagram either way — the 5-tuple
// flow's NAT-style expiry (old #41). Both sides are the same interface so
// tests can fake either end without a real netstack.
func pumpUDP(conn udpRelay, relay udpRelay, idle time.Duration) {
	var lastActivity atomic.Int64
	touch := func() { lastActivity.Store(time.Now().UnixNano()) }
	touch()

	stopCh := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopCh); conn.Close(); relay.Close() }) }
	defer stop()

	go func() { // idle reaper
		t := time.NewTicker(idle/3 + 1) // +1: never a zero-interval ticker if idle rounds down to 0
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if time.Since(time.Unix(0, lastActivity.Load())) >= idle {
					stop()
					return
				}
			case <-stopCh:
				return
			}
		}
	}()

	go func() { // relay -> conn (inbound)
		defer stop()
		buf := make([]byte, maxUDPDatagram)
		for {
			n, err := relay.Read(buf)
			if err != nil {
				return
			}
			touch()
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, maxUDPDatagram) // conn -> relay (outbound)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		touch()
		if _, err := relay.Write(buf[:n]); err != nil {
			return
		}
	}
}

// socksUDPAssoc is one SOCKS5 UDP ASSOCIATE relay (RFC 1928 §4/§7): ctrl is
// the TCP control connection, kept open for the association's whole
// lifetime — closing it (Close, below) is how the server knows to tear its
// side down too (RFC 1928 §4), and the reverse (the server closing it first)
// is watched for the same reason, in dialSOCKSUDPAssociate. data is the UDP
// socket connected to the server's advertised relay address. target/port are
// this flow's one fixed destination, framed into every outbound datagram and
// checked on every inbound one. rbuf is read-loop scratch space — safe to
// reuse unsynchronized because pumpUDP only ever calls Read from one
// goroutine at a time.
type socksUDPAssoc struct {
	ctrl   net.Conn
	data   *net.UDPConn
	target net.IP
	port   uint16
	rbuf   []byte
}

// dialSOCKSUDPAssociate performs a SOCKS5 UDP ASSOCIATE handshake against the
// tunnel's local SOCKS server for target, and returns a relay ready to carry
// that flow's datagrams. target must be an IPv4 host:port — the only shape
// the netstack ever captures (this client is IPv4-only end to end).
func dialSOCKSUDPAssociate(socksAddr, target string) (udpRelay, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("dialSOCKSUDPAssociate: %q is not an IPv4 address", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	ctrl, err := net.Dial("tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			ctrl.Close()
		}
	}()

	// No-auth method negotiation, then the UDP ASSOCIATE request. The server
	// (core/client.go) never uses the advertised address, but RFC 1928
	// requires sending one — 0.0.0.0:0, same as most SOCKS5 clients that
	// don't know their own send-from address in advance.
	if _, err := ctrl.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var method [2]byte
	if _, err := io.ReadFull(ctrl, method[:]); err != nil {
		return nil, err
	}
	if method[0] != 5 || method[1] != 0 {
		return nil, fmt.Errorf("dialSOCKSUDPAssociate: SOCKS method negotiation failed")
	}
	if _, err := ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	bndIP, bndPort, err := readSOCKSUDPAssociateReply(ctrl)
	if err != nil {
		return nil, err
	}
	// The tunnel's local SOCKS server only ever binds its relay to loopback
	// (core/udprelay.go's handleSocksUDPAssociate); refuse anything else
	// rather than silently sending this flow's datagrams to a non-loopback
	// address a compromised or misconfigured server named.
	if !bndIP.IsLoopback() {
		return nil, fmt.Errorf("dialSOCKSUDPAssociate: relay address %s is not loopback", bndIP)
	}

	data, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: bndIP, Port: int(bndPort)})
	if err != nil {
		return nil, err
	}

	// The server closing ctrl first (its own idle timeout, or an exit
	// rejection) has to be noticed here too, not just the reverse: closing
	// data unblocks a pumpUDP goroutine blocked reading it, the same way any
	// other relay error would.
	go func() { _, _ = io.Copy(io.Discard, ctrl); _ = data.Close() }()

	ok = true
	return &socksUDPAssoc{
		ctrl:   ctrl,
		data:   data,
		target: ip,
		port:   uint16(port),
		rbuf:   make([]byte, maxUDPDatagram+socksUDPHeaderLen),
	}, nil
}

// readSOCKSUDPAssociateReply reads the server's SOCKS5 reply to a UDP
// ASSOCIATE request and returns its BND.ADDR/BND.PORT (IPv4 only — the local
// server, core/client.go, never replies with anything else).
func readSOCKSUDPAssociateReply(c net.Conn) (net.IP, uint16, error) {
	buf := make([]byte, 10)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, 0, err
	}
	if buf[0] != 5 || buf[1] != 0 || buf[3] != 1 {
		return nil, 0, fmt.Errorf("dialSOCKSUDPAssociate: unexpected SOCKS reply %v", buf[:4])
	}
	ip := append(net.IP(nil), buf[4:8]...)
	port := binary.BigEndian.Uint16(buf[8:10])
	return ip, port, nil
}

// Read returns the next datagram addressed to this association's fixed
// target/port; a datagram that doesn't decode as a well-formed RFC 1928 §7
// frame, or names a different destination, is skipped rather than treated
// as fatal — one malformed or stray datagram isn't a reason to tear the
// whole flow down (loopback-only and single-peer in practice, so this should
// never actually happen).
func (a *socksUDPAssoc) Read(p []byte) (int, error) {
	for {
		n, err := a.data.Read(a.rbuf)
		if err != nil {
			return 0, err
		}
		payload, ip, port, ok := decodeSOCKSUDPFrame(a.rbuf[:n])
		if !ok || port != a.port || !ip.Equal(a.target) {
			continue
		}
		return copy(p, payload), nil
	}
}

// Write sends p as one RFC 1928 §7 UDP request datagram addressed to this
// association's fixed target/port.
func (a *socksUDPAssoc) Write(p []byte) (int, error) {
	if _, err := a.data.Write(encodeSOCKSUDPFrame(a.target, a.port, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the association: the control connection closing is what tells
// the server (core/client.go's handleSocksUDPAssociate) to tear its side
// down too (RFC 1928 §4).
func (a *socksUDPAssoc) Close() error {
	_ = a.data.Close()
	return a.ctrl.Close()
}

// decodeSOCKSUDPFrame parses one RFC 1928 §7 UDP request datagram (IPv4
// only; RSV must be zero and FRAG must be 0 — this client never fragments,
// so a nonzero FRAG is rejected rather than reassembled) and returns its
// payload, destination IP, and destination port. Deliberately duplicated
// from core/udprelay.go's identical helper rather than shared: this file is
// meant to stay a self-contained generic SOCKS5 client with no coupling to
// core internals beyond the plain protocol.
func decodeSOCKSUDPFrame(b []byte) (payload []byte, ip net.IP, port uint16, ok bool) {
	if len(b) < socksUDPHeaderLen || b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 1 {
		return nil, nil, 0, false
	}
	ip = append(net.IP(nil), b[4:8]...) // copy: b is a caller-owned, reused buffer
	port = binary.BigEndian.Uint16(b[8:10])
	return b[socksUDPHeaderLen:], ip, port, true
}

// encodeSOCKSUDPFrame builds one RFC 1928 §7 UDP request datagram (IPv4,
// FRAG=0) wrapping payload, addressed to ip:port.
func encodeSOCKSUDPFrame(ip net.IP, port uint16, payload []byte) []byte {
	frame := make([]byte, socksUDPHeaderLen+len(payload))
	frame[3] = 1 // ATYP = IPv4; frame[0:3] (RSV, FRAG) stay zero
	copy(frame[4:8], ip.To4())
	binary.BigEndian.PutUint16(frame[8:10], port)
	copy(frame[socksUDPHeaderLen:], payload)
	return frame
}
