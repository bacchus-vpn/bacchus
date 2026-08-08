package rendezvous

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	dtls "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

const (
	// peerHandshakeTimeout bounds one association's handshake.
	peerHandshakeTimeout = 20 * time.Second

	// peerQueue is how many inbound datagrams may be queued for one association's
	// DTLS reader before further ones are dropped, exactly as the network may.
	peerQueue = 16
)

// Peer terminates the shaped rendezvous hop on a UDP socket: it answers the ICE
// connectivity check, completes the DTLS handshake, and hands the decrypted
// messages to a caller that never learns which shape they arrived in.
//
// A cleartext datagram is delivered unchanged, so one Peer serves a client on the
// shaped hop and anything else that still speaks raw JSON. The reply goes back in
// whichever shape the sender used, which is the single rule the whole thing turns
// on — see WriteTo.
//
// It is not safe to assume anything about ordering across sources; it is safe for
// concurrent use.
type Peer struct {
	pc  *net.UDPConn
	cfg *dtls.Config

	mu     sync.Mutex
	assocs map[string]*assoc

	out    chan inbound
	closed chan struct{}
	once   sync.Once
}

type inbound struct {
	msg []byte
	src *net.UDPAddr
}

// Serve starts terminating on pc and returns the Peer. The caller owns pc and
// closes it; Close stops the goroutines Serve started.
//
// The certificate is self-signed and generated per Peer. It authenticates nothing,
// which is the coordinator's posture too and not a shortcut in either place: the
// client holds no coordinator key it could check one against, so the authentication
// that matters travels inside (ADR-0059 §6).
func Serve(pc *net.UDPConn) (*Peer, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	p := &Peer{
		pc:     pc,
		assocs: map[string]*assoc{},
		out:    make(chan inbound, 64),
		closed: make(chan struct{}),
		cfg: &dtls.Config{
			Certificates:         []tls.Certificate{cert},
			ClientAuth:           dtls.NoClientCert,
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		},
	}
	// Any deadline a previous Peer on this socket set to unblock its own reader is
	// cleared here, so a caller can retire one Peer and Serve another on the same
	// socket — which is what a coordinator restart looks like from the other end.
	_ = pc.SetReadDeadline(time.Time{})
	go p.readSocket()
	return p, nil
}

// ReadFrom returns the next message and the address it came from, decrypted when it
// arrived inside an association. It returns net.ErrClosed once the socket or the
// Peer is closed.
func (p *Peer) ReadFrom() ([]byte, *net.UDPAddr, error) {
	select {
	case in := <-p.out:
		return in.msg, in.src, nil
	case <-p.closed:
		return nil, nil, net.ErrClosed
	}
}

// WriteTo replies to to in whichever shape it reached this Peer in: inside its
// association when it has one, in the clear otherwise.
//
// This is the whole of the reply side, and it is one branch because the coordinator
// found the same thing (ADR-0059 §5): every piece of per-source state at this hop
// keys on the UDP source address, and an association preserves it.
func (p *Peer) WriteTo(b []byte, to *net.UDPAddr) (int, error) {
	if to == nil {
		return 0, errors.New("rendezvous: no destination")
	}
	p.mu.Lock()
	a := p.assocs[to.String()]
	p.mu.Unlock()
	if a != nil {
		if conn := a.live(); conn != nil {
			// A failure here is NOT a reason to fall back to cleartext: the peer
			// asked for the shaped hop, and answering in the clear would undo the
			// property it exists for on the one path where nobody would notice.
			return conn.Write(b)
		}
	}
	return p.pc.WriteToUDP(b, to)
}

// Close stops the Peer, including the goroutine reading the socket. The socket
// itself is the caller's to close.
//
// The reader is blocked in ReadFromUDP and the socket does not belong to this Peer,
// so it is woken with a read deadline rather than by closing the socket underneath
// its owner. Serve clears the deadline again, which is what lets a second Peer take
// over a socket the first has finished with instead of the two of them stealing each
// other's datagrams.
func (p *Peer) Close() error {
	p.once.Do(func() {
		close(p.closed)
		_ = p.pc.SetReadDeadline(time.Now())
		p.mu.Lock()
		for k, a := range p.assocs {
			_ = a.Close()
			delete(p.assocs, k)
		}
		p.mu.Unlock()
	})
	return nil
}

func (p *Peer) deliver(msg []byte, src *net.UDPAddr) {
	c := make([]byte, len(msg))
	copy(c, msg)
	select {
	case p.out <- inbound{msg: c, src: src}:
	case <-p.closed:
	}
}

func (p *Peer) readSocket() {
	buf := make([]byte, 65535)
	for {
		n, src, err := p.pc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			p.Close()
			return
		}
		p.route(buf[:n], src)
	}
}

// route classifies one datagram: an ICE connectivity check is answered in place, a
// DTLS record goes to this source's association, and anything else is delivered as
// it stands.
func (p *Peer) route(raw []byte, src *net.UDPAddr) {
	// The check is answered with the codec the real coordinator uses, because two
	// stand-ins answering the same question with differently-shaped bytes is exactly
	// the distinguisher ADR-0060 refused to create.
	ap := src.AddrPort()
	if resp, ok := coldstart.BindingResponse(raw, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())); ok {
		_, _ = p.pc.WriteToUDP(resp, src)
		return
	}
	if !LooksLikeDTLS(raw) {
		p.deliver(raw, src)
		return
	}
	key := src.String()
	p.mu.Lock()
	a, held := p.assocs[key]
	if !held {
		if raw[0] != handshakeRecord {
			// A stray record from a source with no association: a leftover from one
			// that has gone, or a spoof. Creating state for it would let an attacker
			// mint associations without ever starting a handshake.
			p.mu.Unlock()
			return
		}
		a = newAssoc(p.pc, src)
		p.assocs[key] = a
		p.mu.Unlock()
		go p.serve(a)
	} else {
		p.mu.Unlock()
	}
	a.deliver(raw)
}

func (p *Peer) serve(a *assoc) {
	defer p.drop(a)

	conn, err := dtls.Server(a, a.raddr, p.cfg)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerHandshakeTimeout)
	defer cancel()
	go func() {
		select {
		case <-a.done:
			cancel()
		case <-p.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return
	}
	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		p.deliver(buf[:n], a.raddr)
	}
}

func (p *Peer) drop(a *assoc) {
	_ = a.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	if cur, ok := p.assocs[a.raddr.String()]; ok && cur == a {
		delete(p.assocs, a.raddr.String())
	}
}

// DecodeJSON is a convenience for a caller whose messages are JSON: it decodes msg
// into v and reports whether it parsed. It exists so a stand-in's read loop keeps
// reading exactly as it did, one call further in.
func DecodeJSON(msg []byte, v any) bool { return json.Unmarshal(msg, v) == nil }

// ---------- one association ----------

// assoc is one client's association: the virtual packet conn the DTLS layer rides,
// fed by the Peer's single socket reader.
type assoc struct {
	pc    *net.UDPConn
	raddr *net.UDPAddr

	in   chan []byte
	done chan struct{}
	once sync.Once

	mu   sync.Mutex
	conn *dtls.Conn

	deadlineMu sync.Mutex
	deadline   time.Time
	deadlineCh chan struct{}
}

func newAssoc(pc *net.UDPConn, raddr *net.UDPAddr) *assoc {
	return &assoc{
		pc:         pc,
		raddr:      raddr,
		in:         make(chan []byte, peerQueue),
		done:       make(chan struct{}),
		deadlineCh: make(chan struct{}),
	}
}

func (a *assoc) live() *dtls.Conn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conn
}

func (a *assoc) deliver(raw []byte) {
	c := make([]byte, len(raw))
	copy(c, raw)
	select {
	case a.in <- c:
	case <-a.done:
	default: // queue full — drop, exactly as the network may
	}
}

func (a *assoc) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		a.deadlineMu.Lock()
		dl, ch := a.deadline, a.deadlineCh
		a.deadlineMu.Unlock()

		var timer <-chan time.Time
		if !dl.IsZero() {
			t := time.NewTimer(time.Until(dl))
			defer t.Stop()
			timer = t.C
		}
		select {
		case pkt, ok := <-a.in:
			if !ok {
				return 0, a.raddr, net.ErrClosed
			}
			return copy(b, pkt), a.raddr, nil
		case <-a.done:
			return 0, a.raddr, net.ErrClosed
		case <-timer:
			return 0, a.raddr, peerTimeout{}
		case <-ch:
		}
	}
}

func (a *assoc) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-a.done:
		return 0, net.ErrClosed
	default:
	}
	return a.pc.WriteToUDP(b, a.raddr)
}

func (a *assoc) Close() error {
	a.once.Do(func() { close(a.done) })
	return nil
}

func (a *assoc) LocalAddr() net.Addr { return a.pc.LocalAddr() }

func (a *assoc) SetDeadline(t time.Time) error {
	_ = a.SetWriteDeadline(t)
	return a.SetReadDeadline(t)
}

func (a *assoc) SetReadDeadline(t time.Time) error {
	a.deadlineMu.Lock()
	prev := a.deadlineCh
	a.deadline = t
	a.deadlineCh = make(chan struct{})
	a.deadlineMu.Unlock()
	close(prev)
	return nil
}

func (a *assoc) SetWriteDeadline(time.Time) error { return nil }

type peerTimeout struct{}

func (peerTimeout) Error() string   { return "i/o timeout" }
func (peerTimeout) Timeout() bool   { return true }
func (peerTimeout) Temporary() bool { return true }
