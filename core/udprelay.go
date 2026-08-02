package core

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// UDP relay forwarding (issue #41): carries a client's captured UDP flow
// (QUIC, VoIP, games — anything but the DNS special case tun2socks.go already
// handles) across the same E2E channel a TCP CONNECT uses, via the
// udpTargetPrefix sentinel (core/e2e.go). One flow is one fixed destination
// for its whole lifetime, learned once from the client's SOCKS5 UDP ASSOCIATE
// request (handleSocksUDPAssociate, below) — not full RFC 1928 multi-
// destination multiplexing, which this project's own client never needs since
// it opens one association per captured 5-tuple flow (one gVisor
// ForwarderRequest, one association, one destination). That single
// destination is enforced, not just assumed of a well-behaved client:
// serveSOCKSUDPAssociate drops (rather than misroutes) any later datagram
// addressed elsewhere (issue #99).
//
// Two framing layers, not one:
//   - The client-facing SOCKS boundary (handleSocksUDPAssociate, and the
//     windows client's dialSOCKSUDPAssociate on the other end) speaks genuine
//     RFC 1928 §7 UDP request framing (RSV+FRAG+ATYP+DST.ADDR+DST.PORT+DATA,
//     FRAG must be 0 — no fragmentation support), so the windows client stays
//     a boring generic SOCKS5 client, the same boundary CONNECT already has.
//   - The internal client<->exit hop, over the E2E stream (writeUDPFrame/
//     readUDPFrame), is a plain 2-byte-length-prefixed payload with no
//     repeated address header — the destination is already fixed by the E2E
//     target string for the stream's whole lifetime, so there is nothing to
//     repeat per datagram.

const maxUDPDatagram = 65535 // largest possible UDP payload; also each hop's frame-length cap

// --- internal client<->exit framing (the E2E stream hop) ---

// writeUDPFrame writes one datagram payload to w as a 2-byte big-endian
// length prefix followed by the payload.
func writeUDPFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxUDPDatagram {
		return errFrameTooLarge
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	_, err := w.Write(frame)
	return err
}

// readUDPFrame reads one writeUDPFrame-framed payload from r into buf,
// returning the payload as a subslice of buf.
func readUDPFrame(r io.Reader, buf []byte) ([]byte, error) {
	var lenPrefix [2]byte
	if _, err := io.ReadFull(r, lenPrefix[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenPrefix[:]))
	if n > len(buf) {
		return nil, errFrameTooLarge
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// --- exit side: dial real UDP, relay to/from the E2E stream ---

// exitTerminateUDP is exitTerminate's (core/forwarder.go) UDP counterpart: nc
// has already completed the Noise_NK responder handshake, and target is the
// client's requested destination with udpTargetPrefix already stripped. It
// dials one connected UDP socket to target and relays writeUDPFrame-framed
// datagrams bidirectionally until either side closes or errors, or
// udpIdleTimeout passes with no datagram in either direction (NAT-style
// expiry — the backstop; see udpIdleTimeout's doc in core/engine.go for why
// the client is expected to drive teardown first in the common case).
//
// pace is the tier's per-session speed cap (issue #58/#74, ADR-0048), nil for
// uncapped — the same *Limiter exitTerminate wraps a reader with on the TCP
// path, applied here per datagram through WaitN instead, because this loop
// moves whole datagrams and there is no reader to wrap. It sits inside meterN's
// operator-declared cap exactly as it does on that path: accounting counts what
// the session moved, pace what its tier is entitled to, meterN what the
// operator will carry.
func (e *Engine) exitTerminateUDP(sid string, pace *capacity.Limiter, nc *noiseConn, target string) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	// Served, like the TCP egress beside it (issue #109): this is other
	// people's traffic leaving under this operator's address, and on a machine
	// that also routes itself the socket has to say so.
	conn, err := e.dialServedUDP(raddr)
	if err != nil {
		return
	}

	var ctr *accounting.Counter
	if sid != "" && e.acctEnabled() {
		ctr = e.acctCounter(sid)
	}

	// stop (deferred) is the only place either conn or nc gets closed here —
	// nc is otherwise left to exitTerminate's own defer (raw.Close()), just as
	// its TCP path never closes nc itself, only remote.
	var closeOnce sync.Once
	stop := func() { closeOnce.Do(func() { conn.Close(); nc.Close() }) }
	defer stop()
	touch, stopReaper := startIdleReaper(e.udpIdleTimeout, stop)
	defer stopReaper()

	go func() { // conn (real UDP) -> nc (E2E stream)
		defer stop()
		buf := make([]byte, maxUDPDatagram)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			touch()
			ctr.Add(uint64(n))
			// Tier cap (issue #74, ADR-0048 §4): what this session's plan is entitled
			// to, checked before the operator's own declared cap below so the two
			// compose in the same order the TCP path nests them in.
			//
			// n cannot exceed burstBytes, which is what makes WaitN's error case
			// unreachable here rather than merely unlikely: a UDP payload cannot be
			// larger than maxUDPDatagram (65535), one byte under capacity's 64 KiB
			// burst. That headroom is load-bearing — do not widen maxUDPDatagram
			// without revisiting it.
			if err := pace.WaitN(e.limiterCtx, n); err != nil {
				return
			}
			// Declared limits (issue #143): pace and count this datagram against the
			// operator's cap, and stop the flow once the quota is spent. meter() cannot
			// reach here — this loop moves datagrams, not a stream.
			if err := e.meterN(n); err != nil {
				return
			}
			if err := writeUDPFrame(nc, buf[:n]); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, maxUDPDatagram) // nc (E2E stream) -> conn (real UDP)
	for {
		payload, err := readUDPFrame(nc, buf)
		if err != nil {
			return
		}
		touch()
		ctr.Add(uint64(len(payload)))
		if err := pace.WaitN(e.limiterCtx, len(payload)); err != nil { // tier cap (issue #74); see above
			return
		}
		if err := e.meterN(len(payload)); err != nil { // declared limits (issue #143); see above
			return
		}
		if _, err := conn.Write(payload); err != nil {
			return
		}
	}
}

// startIdleReaper starts a background goroutine that calls stop once idle
// passes with no touch() call in between. The caller must call touch() for
// every datagram it relays in either direction, and must call the returned
// cleanup func (via defer) once its relay loop ends, which also stops the
// reaper goroutine. stop must be idempotent (every caller wraps theirs in
// sync.Once) — the reaper and each direction's own error path can all call it
// concurrently.
func startIdleReaper(idle time.Duration, stop func()) (touch func(), cleanup func()) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	touch = func() { lastActivity.Store(time.Now().UnixNano()) }

	stopCh := make(chan struct{})
	go func() {
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
	return touch, func() { close(stopCh) }
}

// --- client-core side: genuine SOCKS5 UDP ASSOCIATE, RFC 1928 §7 framing ---

// socksUDPHeaderLen is the RFC 1928 §7 UDP request header length for ATYP=1
// (IPv4) — the only address type this hop ever uses: this project's netstack
// is IPv4-only end to end (clients/windows/tunnel.go), so every destination
// core learns here is already an IPv4 host:port.
const socksUDPHeaderLen = 2 + 1 + 1 + 4 + 2 // RSV + FRAG + ATYP + IPv4 + PORT

var errBadSOCKSUDPFrame = errors.New("core: malformed or unsupported SOCKS5 UDP request frame")

// decodeSOCKSUDPFrame parses one RFC 1928 §7 UDP request datagram (IPv4 only;
// RSV must be zero and FRAG must be 0 — this project never fragments, so a
// nonzero FRAG is rejected as a protocol violation rather than reassembled)
// and returns its payload, destination IP, and destination port.
func decodeSOCKSUDPFrame(b []byte) (payload []byte, ip net.IP, port uint16, err error) {
	if len(b) < socksUDPHeaderLen || b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 1 {
		return nil, nil, 0, errBadSOCKSUDPFrame
	}
	ip = append(net.IP(nil), b[4:8]...) // copy: b is a caller-owned, reused buffer
	port = binary.BigEndian.Uint16(b[8:10])
	return b[socksUDPHeaderLen:], ip, port, nil
}

// encodeSOCKSUDPFrame builds one RFC 1928 §7 UDP request datagram (IPv4,
// FRAG=0) wrapping payload, addressed to/from ip:port.
func encodeSOCKSUDPFrame(ip net.IP, port uint16, payload []byte) []byte {
	frame := make([]byte, socksUDPHeaderLen+len(payload))
	frame[3] = 1 // ATYP = IPv4; frame[0:3] (RSV, FRAG) stay zero
	copy(frame[4:8], ip.To4())
	binary.BigEndian.PutUint16(frame[8:10], port)
	copy(frame[socksUDPHeaderLen:], payload)
	return frame
}

// handleSocksUDPAssociate serves one SOCKS5 UDP ASSOCIATE request (RFC 1928
// §4, issue #41): buf already holds the VER/CMD/RSV/ATYP header handleSocks
// read. The DST.ADDR/DST.PORT that follows is the client's advertised
// send-from address — purely advisory (most SOCKS5 clients, including this
// project's own, send 0.0.0.0:0 since they don't know it in advance) and
// discarded here; this relay simply answers whichever source its first
// datagram arrives from (see serveSOCKSUDPAssociate).
//
// It binds a loopback UDP relay socket and replies with its address. RFC 1928
// ties the association's lifetime to the control connection c, which carries
// no further SOCKS data after this reply — closing it (the client
// disconnecting, or its own idle timeout tearing its side down) is this
// association's teardown signal.
func (e *Engine) handleSocksUDPAssociate(c net.Conn, buf []byte, sess Session, exitPub []byte, ctr *accounting.Counter) {
	if _, err := readSOCKSAddr(c, buf); err != nil {
		return
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()

	bnd := relay.LocalAddr().(*net.UDPAddr)
	reply := make([]byte, 10)
	reply[0], reply[1], reply[2], reply[3] = 5, 0, 0, 1
	copy(reply[4:8], bnd.IP.To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(bnd.Port))
	if _, err := c.Write(reply); err != nil {
		return
	}

	ctrlDone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, c); close(ctrlDone) }()

	e.serveSOCKSUDPAssociate(relay, ctrlDone, sess, exitPub, ctr)
}

// serveSOCKSUDPAssociate is handleSocksUDPAssociate's relay loop: it waits
// (bounded by udpIdleTimeout, so an association that's opened and then never
// used doesn't leak the goroutine/socket forever) for the client's first
// datagram on relay to learn the flow's one fixed destination — see this
// file's doc comment for the one-destination simplification — and which
// source address to answer, opens the E2E channel to the exit for that
// destination (udpTargetPrefix + target), then relays datagrams
// bidirectionally — RFC 1928 §7 framed on the relay/client side, writeUDPFrame
// framed on the nc/exit side — until ctrlDone fires (the SOCKS control
// connection closed) or udpIdleTimeout passes with no datagram either way.
func (e *Engine) serveSOCKSUDPAssociate(relay *net.UDPConn, ctrlDone <-chan struct{}, sess Session, exitPub []byte, ctr *accounting.Counter) {
	_ = relay.SetReadDeadline(time.Now().Add(e.udpIdleTimeout))
	first := make([]byte, maxUDPDatagram+socksUDPHeaderLen)
	n, from, err := relay.ReadFromUDP(first)
	if err != nil {
		return
	}
	_ = relay.SetReadDeadline(time.Time{}) // clear it — the idle reaper (below) takes over

	payload, ip, port, err := decodeSOCKSUDPFrame(first[:n])
	if err != nil {
		return
	}
	target := net.JoinHostPort(ip.String(), fmt.Sprint(port))

	openCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Chained exactly like the TCP path (issue #142). A UDP association that took a
	// shorter path than the user's configured chain would be a silent hole in the
	// property they asked for — and UDP is most of what a browser moves.
	//
	// Through dialChainedStream, rather than opening the stream here and handshaking
	// over it, so a dead hop is rebuilt around instead of failing the flow (issue #82).
	//
	// Dialing dialE2E directly still ran dialChain, and the per-layer stall bound and
	// the fault attribution both live in there: a wedged hop was already bounded, and
	// the error already named which hop to hold responsible. What this path did not
	// have was anything that ACTS on that attribution. markHopCooling, the dead-head
	// escalation and the rebuild all live in dialChainedStream, so the suspect was
	// named into an error, emitted, and then dropped — nothing cooled the node, and the
	// next associate was free to select it again. Only the rebuild is hard to move:
	// ADR-0038 §5 discards a broken circuit rather than splicing a fresh tail onto it,
	// so the outermost handshake is spent and the stream it was spent on with it, which
	// makes stream ownership the requirement and this seam the only caller that has it.
	// A UDP flow that was the FIRST thing to meet a dead hop therefore failed where the
	// equivalent TCP flow rebuilt and succeeded.
	//
	// What was never missing is picking up a chain some OTHER path rebuilt, since
	// planOf(sess) is read per associate — that much came from reading the session.
	nc, err := e.dialChainedStream(openCtx, sess, exitPub, udpTargetPrefix+target)
	if err != nil {
		e.emit(EventError, "", "exit rejected: %v", err)
		return
	}

	stopCh := make(chan struct{})
	var closeOnce sync.Once
	stop := func() {
		closeOnce.Do(func() {
			close(stopCh)
			relay.Close()
			nc.Close()
		})
	}
	defer stop()
	touch, stopReaper := startIdleReaper(e.udpIdleTimeout, stop)
	defer stopReaper()

	// The control connection closing is the client's explicit "tear this
	// down" signal; stopCh closing means that already happened some other
	// way (idle timeout, a relay error), so this goroutine doesn't leak
	// waiting on a ctrlDone that will now never matter.
	go func() {
		select {
		case <-ctrlDone:
			stop()
		case <-stopCh:
		}
	}()

	if err := writeUDPFrame(nc, payload); err != nil {
		return
	}
	touch()
	ctr.Add(uint64(len(payload)))

	go func() { // nc (exit's replies) -> relay (back to the client, RFC 1928 framed)
		defer stop()
		buf := make([]byte, maxUDPDatagram)
		for {
			p, err := readUDPFrame(nc, buf)
			if err != nil {
				return
			}
			touch()
			ctr.Add(uint64(len(p)))
			if _, err := relay.WriteToUDP(encodeSOCKSUDPFrame(ip, port, p), from); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, maxUDPDatagram+socksUDPHeaderLen) // relay (client's later datagrams) -> nc
	for {
		n, src, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if src.Port != from.Port || !src.IP.Equal(from.IP) {
			continue // not this association's one client peer; loopback-only, shouldn't happen
		}
		p, dstIP, dstPort, err := decodeSOCKSUDPFrame(buf[:n])
		if err != nil {
			continue // one malformed datagram is not a reason to tear the whole flow down
		}
		if dstPort != port || !dstIP.Equal(ip) {
			continue // one destination per association (issue #99): drop, don't misroute to ip:port
		}
		touch()
		ctr.Add(uint64(len(p)))
		if err := writeUDPFrame(nc, p); err != nil {
			return
		}
	}
}
