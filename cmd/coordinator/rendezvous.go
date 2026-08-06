package main

// The rendezvous hop stops being cleartext (issue #175 slice 1, ADR-0059).
//
// Before this, the first packet a Bacchus client ever sent was plaintext JSON
// over raw UDP: core/coordpool.go marshalled a wire struct and wrote it, and this
// binary read it with net.ListenUDP / ReadFromUDP / json.Unmarshal. A DPI box saw
// the literal bytes {"type":"connect" in a UDP payload to one port — so every
// stage the transport ladder protects sat downstream of a stage that
// self-identified in cleartext, and one signature dropped every client before the
// protected ladder ever ran.
//
// This file makes the signaling port ALSO speak DTLS, alongside raw JSON, on the
// same socket — and, since issue #202, answer the STUN connectivity check that
// precedes DTLS in a real WebRTC flow. It is deliberately the coordinator half
// only: it refuses nothing it accepted before, so it deploys on its own, ahead
// of any client that speaks the new shape. The client half is slice 2.
//
// The two halves are one shape. DTLS alone leaves a ClientHello arriving from
// nowhere, which is DTLS-shaped and not WebRTC-shaped; the STUN prefix is what
// makes the exchange resemble the ICE-then-DTLS sequence a video call produces.
// See answerSTUN and ADR-0060.
//
// # Why one port and not two
//
// A second port is a second thing to enumerate and a second thing to block, and
// it would tell a censor that the two shapes belong to one product. One port with
// two shapes tells them nothing they did not already have.
//
// # How the three shapes are told apart
//
// STUN is tested first because it has the strongest signature — a four-byte
// magic cookie at a fixed offset, an exact method, and a length field that must
// account for the whole datagram. That ordering is for the reader, not for
// correctness: the three classifiers are mutually exclusive, so swapping the
// STUN and DTLS tests changes no behaviour, and
// TestLooksLikeSTUNIsDisjointFromTheOtherTwoShapes is what keeps that true. See
// looksLikeSTUN for why the first byte cannot settle STUN-versus-DTLS the way it
// settles JSON.
//
// Then DTLS, by the first three bytes, and it is not a heuristic. A DTLS record begins with
// a one-byte ContentType (20 change_cipher_spec, 21 alert, 22 handshake, 23
// application_data, 25 connection_id) followed by the two-byte protocol version,
// which for DTLS is 0xfeff (1.0) or 0xfefd (1.2). A JSON value begins with '{',
// '[', '"', a digit, '-', 't', 'f', 'n' or ASCII whitespace. Those sets are
// disjoint on the FIRST byte alone; the version check is belt and braces, and it
// is what makes a misclassification impossible rather than merely unlikely.
//
// The polarity of the check matters: anything that is not conclusively DTLS goes
// down the JSON path EXACTLY as before. A false "this is DTLS" would break a
// deployed client; a false "this is JSON" costs a json.Unmarshal that fails and a
// dropped datagram, which is what this loop already did with malformed input.
//
// # What does NOT change, and it is most of the work that was feared
//
// handle(m, src) and everything under it. Every piece of per-source state in this
// binary — the challenge store, the connect-nonce dedupe, session routing — keys
// on the UDP source address, and a DTLS association preserves it: the datagrams
// still arrive from the same host and port. So the DTLS layer is a wrapper on the
// read and reply paths and nothing else, which is why this is one file.
//
// # What it does not do
//
// It does not authenticate the coordinator to the client. The desktop client
// holds no coordinator public key at all (MeshPubKey/MeshPeers/MeshProof appear
// nowhere under clients/), so a client verifying this certificate would be
// verifying it against nothing. The certificate is here to make the handshake
// look like the WebRTC handshake it is imitating, not to prove anything; the
// authentication that matters is the admission credential inside, which is
// unchanged. See ADR-0059 on why that is acceptable at this hop and what closes
// it (#193's per-coordinator keys).

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	dtls "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

const (
	// dtlsRecordVersionMajor is the first byte of every DTLS protocol version.
	// DTLS versions are the 1's complement of their TLS counterparts, so 1.0 is
	// 0xfeff and 1.2 is 0xfefd — both begin 0xfe, and no JSON document does.
	dtlsRecordVersionMajor = 0xfe

	// dtlsRecordHeaderSize is the fixed part of a DTLS record header: type(1) +
	// version(2) + epoch(2) + sequence(6) + length(2). A datagram shorter than
	// this cannot be a DTLS record whatever its first byte says.
	dtlsRecordHeaderSize = 13

	// dtlsHandshakeTimeout bounds one association's handshake. pion retransmits
	// its flights on its own timer, so this is the outer limit on how long a
	// half-open association may hold its slot — the resource an unauthenticated
	// source can consume here.
	dtlsHandshakeTimeout = 20 * time.Second

	// dtlsAssocIdle is how long an established association survives with no
	// traffic. A client's rendezvous is a burst, not a stream: it greets, it
	// connects, it signals a handshake through, and then it is done. Holding the
	// association past that costs memory for nothing.
	dtlsAssocIdle = 2 * time.Minute

	// maxDTLSAssocs caps live associations. UDP source addresses are SPOOFABLE,
	// so anything keyed on them is fillable by an attacker who never completes a
	// handshake — the same property maxPendingChallenges exists for, and the same
	// answer. DTLS's own cookie exchange bounds the damage further: a spoofed
	// source never returns the HelloVerifyRequest cookie, so it never gets past
	// flight 1, and the slot is reclaimed by dtlsHandshakeTimeout.
	maxDTLSAssocs = 4096

	// dtlsAssocSweep is how often idle and dead associations are reclaimed even
	// with no new traffic, mirroring challengeSweep.
	dtlsAssocSweep = 30 * time.Second

	// dtlsAssocQueue is how many inbound datagrams may be queued for one
	// association's DTLS reader before further ones are DROPPED. Dropping is
	// correct here and not a compromise: this is UDP, the peer's stack may drop a
	// datagram for any reason at any time, and DTLS retransmits its own handshake
	// flights. Blocking instead would let one stalled association stall the whole
	// read loop.
	dtlsAssocQueue = 16

	// stunHeaderSize is the fixed STUN message header: type(2) + length(2) +
	// magic cookie(4) + transaction id(12). Every STUN message is at least this
	// long and a Binding Request with no attributes is exactly this long.
	stunHeaderSize = 20

	// stunMagicCookie sits at bytes 4..8 of every RFC 5389 message. It is the
	// strongest single signature of the three shapes this port carries, which is
	// why the STUN test runs first.
	stunMagicCookie = 0x2112A442

	// stunBindingRequest is the only STUN method this port answers. Anything
	// else — Allocate, Refresh, ChannelBind — is left alone: the signaling port
	// is not a TURN server and must not start looking like one.
	stunBindingRequest = 0x0001
)

// looksLikeDTLS reports whether raw is conclusively the start of a DTLS record.
//
// It is deliberately conservative: everything it is not certain about is left to
// the JSON path, which behaves exactly as it did before this file existed. See
// the package comment on why the polarity of that choice is load-bearing.
func looksLikeDTLS(raw []byte) bool {
	if len(raw) < dtlsRecordHeaderSize {
		return false
	}
	switch raw[0] {
	case 20, 21, 22, 23, 25: // change_cipher_spec, alert, handshake, application_data, connection_id
	default:
		return false
	}
	// 0xfeff is DTLS 1.0, 0xfefd is DTLS 1.2. pion forces 1.2 but accepts a 1.0
	// record version in a ClientHello, which is what a real browser sends.
	return raw[1] == dtlsRecordVersionMajor && (raw[2] == 0xff || raw[2] == 0xfd)
}

// looksLikeSTUN reports whether raw is conclusively a STUN Binding Request
// (issue #202, ADR-0060).
//
// This is a stronger signature than the DTLS one, and it has to be, because
// disjointness cannot be settled on the first byte here the way it is for JSON:
// a DTLS ContentType (20, 21, 22, 23, 25) also has its two high bits clear, so
// it satisfies the leading-zero-bits rule every STUN message type obeys. The
// magic cookie is what separates them. Bytes 4..8 of a DTLS record are its
// two-byte epoch followed by the first two bytes of a 48-bit sequence number,
// both counting up from zero, so they cannot reach 0x2112A442 in any association
// this coordinator will hold. Requiring the exact method narrows it further.
//
// The length test is the last of it: over UDP a STUN message IS the datagram, so
// the declared attribute length must account for every remaining byte rather
// than merely fit. That costs nothing and removes the last way something that is
// not STUN reaches the responder.
func looksLikeSTUN(raw []byte) bool {
	if len(raw) < stunHeaderSize {
		return false
	}
	if binary.BigEndian.Uint16(raw[0:2]) != stunBindingRequest {
		return false
	}
	if binary.BigEndian.Uint32(raw[4:8]) != stunMagicCookie {
		return false
	}
	return stunHeaderSize+int(binary.BigEndian.Uint16(raw[2:4])) == len(raw)
}

// ---------- one association ----------

// dtlsAssoc is one client's DTLS association with this coordinator: a virtual
// packet conn fed by the shared read loop, the dtls.Conn riding it, and the
// goroutine that turns decrypted records back into wire messages for handle().
type dtlsAssoc struct {
	raddr *net.UDPAddr
	pc    *net.UDPConn // the shared socket, for the write side
	in    chan []byte
	done  chan struct{} // closed when this association is finished

	closeOnce sync.Once

	mu       sync.Mutex
	conn     *dtls.Conn // nil until the handshake completes
	lastSeen time.Time

	// readDeadline backs SetReadDeadline for the virtual conn. pion sets it
	// during handshake retransmission, so it has to be real rather than a stub.
	deadlineMu sync.Mutex
	deadline   time.Time
	deadlineCh chan struct{}
}

// The virtual net.PacketConn the association hands to dtls.Server. Reads come
// from the shared socket via the mux; writes go straight back out of the shared
// socket to this association's peer.

func (a *dtlsAssoc) ReadFrom(b []byte) (int, net.Addr, error) {
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
		case p, ok := <-a.in:
			if !ok {
				return 0, a.raddr, net.ErrClosed
			}
			n := copy(b, p)
			return n, a.raddr, nil
		case <-a.done:
			return 0, a.raddr, net.ErrClosed
		case <-timer:
			return 0, a.raddr, os0Timeout{}
		case <-ch:
			// The deadline was replaced while we were waiting; re-read it.
		}
	}
}

func (a *dtlsAssoc) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-a.done:
		return 0, net.ErrClosed
	default:
	}
	return a.pc.WriteToUDP(b, a.raddr)
}

func (a *dtlsAssoc) Close() error {
	a.closeOnce.Do(func() { close(a.done) })
	return nil
}

func (a *dtlsAssoc) LocalAddr() net.Addr { return a.pc.LocalAddr() }

func (a *dtlsAssoc) SetDeadline(t time.Time) error {
	_ = a.SetWriteDeadline(t)
	return a.SetReadDeadline(t)
}

func (a *dtlsAssoc) SetReadDeadline(t time.Time) error {
	a.deadlineMu.Lock()
	prev := a.deadlineCh
	a.deadline = t
	a.deadlineCh = make(chan struct{})
	a.deadlineMu.Unlock()
	close(prev) // wake any reader so it picks the new deadline up
	return nil
}

// SetWriteDeadline is a no-op: writes go to a shared, non-blocking UDP socket
// and cannot outlive a deadline. Returning an error instead would fail
// pion's SetDeadline, which sets both.
func (a *dtlsAssoc) SetWriteDeadline(time.Time) error { return nil }

// os0Timeout is a net.Error that reports itself as a timeout, which is what pion
// checks for when a handshake flight needs retransmitting.
type os0Timeout struct{}

func (os0Timeout) Error() string   { return "i/o timeout" }
func (os0Timeout) Timeout() bool   { return true }
func (os0Timeout) Temporary() bool { return true }

// deliver hands one inbound datagram to this association's DTLS reader, dropping
// it if the queue is full. See dtlsAssocQueue on why dropping is right.
func (a *dtlsAssoc) deliver(raw []byte) {
	p := make([]byte, len(raw))
	copy(p, raw)
	select {
	case a.in <- p:
	case <-a.done:
	default: // queue full — drop, exactly as the network may
	}
}

// live reports whether the handshake has completed and the association is
// usable for a reply.
func (a *dtlsAssoc) live() *dtls.Conn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conn
}

// ---------- the mux ----------

// rendezvousMux owns the signaling socket and routes each datagram to the shape
// it is: STUN Binding Requests answered in place, DTLS records to a per-source
// association, everything else to the JSON path this binary has always had.
type rendezvousMux struct {
	pc  *net.UDPConn
	cfg *dtls.Config

	mu        sync.Mutex
	assocs    map[string]*dtlsAssoc
	capacity  int // zero means maxDTLSAssocs; a field so a test need not mint 4096
	lastSweep time.Time
	// atCapacity latches the first refusal so the log records the condition once
	// rather than once per spoofed datagram, the shape challengeStore uses.
	atCapacity bool
}

// newRendezvousMux builds the mux and its DTLS server configuration.
//
// The certificate is self-signed and generated fresh at startup, per process. It
// authenticates nothing (see the package comment), so what it costs is a
// fingerprint: a long-lived coordinator presents one stable certificate. That is
// acceptable here and nowhere else, because the thing it identifies — this
// coordinator — is the address the client already dialled to reach it. Rotating
// it belongs with the fingerprint profiles in slice 3, not here.
func newRendezvousMux(pc *net.UDPConn) (*rendezvousMux, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	return &rendezvousMux{
		pc:     pc,
		assocs: map[string]*dtlsAssoc{},
		cfg: &dtls.Config{
			Certificates: []tls.Certificate{cert},
			// The client presents no certificate: it has nothing this coordinator
			// could check it against, and the credential that DOES gate admission
			// travels inside, unchanged (ADR-0023, ADR-0045).
			ClientAuth: dtls.NoClientCert,
			// RequireExtendedMasterSecret matches what core/transport_webrtc.go
			// negotiates, so the two handshakes this product emits do not differ
			// on a field a classifier can read.
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		},
	}, nil
}

func (m *rendezvousMux) cap() int {
	if m.capacity > 0 {
		return m.capacity
	}
	return maxDTLSAssocs
}

// answerSTUN answers an ICE connectivity check on the signaling socket and
// reports whether it consumed the datagram (issue #202, ADR-0060).
//
// This is the second half of the WebRTC shape. S1 made the port speak DTLS, but
// a DTLS ClientHello arriving from nowhere is DTLS-shaped, not WebRTC-shaped: a
// real endpoint runs ICE connectivity checks on a 5-tuple and only then runs
// DTLS on that same 5-tuple, and the difference is free for a classifier to
// read. Without this half, core/ice_fingerprint.go — which draws browser-shaped
// ufrag/pwd precisely because pion's own are a distinguisher — has no caller at
// this hop at all.
//
// # What it answers, and to whom
//
// Anything well-formed, from anyone. That is a ruling rather than an oversight,
// and the postures rejected to reach it are recorded in ADR-0060. Answering
// openly is what makes the port resemble the generic VoIP infrastructure the
// design set out to hide among; a port that returns silence to an ordinary
// Binding Request resembles nothing, and looking like nothing is itself a
// signal.
//
// # The reflection cost, measured rather than asserted
//
// A bare Binding Request is 20 bytes and draws 40 back over IPv4 (header 20 +
// XOR-MAPPED-ADDRESS 12 + FINGERPRINT 8), or 52 over IPv6, so a spoofed source
// buys an attacker 2.0x or 2.6x. Accepted, on two grounds. It sits far below the
// 50x-500x that makes a reflector worth building a campaign on — at 2x an
// attacker gains almost nothing over sending the packets directly. And this
// coordinator ALREADY runs a real STUN/TURN server on -turn-addr with
// coldstart.Demux blended onto it, answering the same request with the same two
// attributes; this is therefore a second instance of an exposure the deployment
// has already accepted, not a new class of one.
func (m *rendezvousMux) answerSTUN(raw []byte, src *net.UDPAddr) bool {
	if m == nil || src == nil || !looksLikeSTUN(raw) {
		return false
	}
	// XOR-MAPPED-ADDRESS has to name the family the peer actually reached us on.
	// UDPAddr.AddrPort keeps an IPv4 peer as a 4-in-6 mapped address, which
	// reports Is4() false and would encode the 20-byte IPv6 form for a v4
	// client — wrong on the wire, and a distinguisher, since no real STUN server
	// does that. Unmap before encoding.
	ap := src.AddrPort()
	resp, ok := coldstart.BindingResponse(raw, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	if !ok {
		return false
	}
	if _, err := m.pc.WriteToUDP(resp, src); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			log.Printf("rendezvous: STUN reply to %s failed: %v", src, err)
		}
	}
	// Consumed either way: a write failure does not make the datagram JSON.
	return true
}

// route classifies one datagram and returns true if it was consumed as DTLS. A
// false return means the caller should handle it exactly as it always did.
func (m *rendezvousMux) route(raw []byte, src *net.UDPAddr) bool {
	if m == nil || !looksLikeDTLS(raw) {
		return false
	}
	a, fresh := m.assocFor(raw, src)
	if a == nil {
		return true // at capacity, or not a handshake from an unknown source
	}
	if fresh {
		go m.serveAssoc(a)
	}
	a.deliver(raw)
	return true
}

// assocFor finds or creates the association for src. fresh reports whether it was
// created by this call.
//
// A datagram from an UNKNOWN source only creates an association when it is a
// handshake record (type 22). An application-data or alert record from a source
// with no association is a stray from an association that has already gone — or a
// spoof — and creating state for it would let an attacker mint associations
// without ever starting a handshake, skipping the cookie exchange that is the
// whole reason a spoofed source is cheap to refuse.
func (m *rendezvousMux) assocFor(raw []byte, src *net.UDPAddr) (a *dtlsAssoc, fresh bool) {
	key := src.String()
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if a, ok := m.assocs[key]; ok {
		a.mu.Lock()
		a.lastSeen = now
		a.mu.Unlock()
		return a, false
	}
	if raw[0] != 22 { // not a handshake record
		return nil, false
	}
	if now.Sub(m.lastSweep) > dtlsAssocSweep {
		m.sweepLocked(now)
	}
	if len(m.assocs) >= m.cap() {
		if !m.atCapacity {
			m.atCapacity = true
			log.Printf("rendezvous: DTLS association table is at capacity (%d) — refusing new handshakes until it drains; "+
				"a spoofed source flood cannot get past the cookie exchange, but it can hold slots for up to %s",
				m.cap(), dtlsHandshakeTimeout)
		}
		return nil, false
	}
	a = &dtlsAssoc{
		raddr:      src,
		pc:         m.pc,
		in:         make(chan []byte, dtlsAssocQueue),
		done:       make(chan struct{}),
		lastSeen:   now,
		deadlineCh: make(chan struct{}),
	}
	m.assocs[key] = a
	return a, true
}

// sweepLocked drops associations that are finished or idle. The caller holds mu.
func (m *rendezvousMux) sweepLocked(now time.Time) {
	m.lastSweep = now
	for k, a := range m.assocs {
		select {
		case <-a.done:
			delete(m.assocs, k)
			continue
		default:
		}
		a.mu.Lock()
		idle := now.Sub(a.lastSeen)
		a.mu.Unlock()
		if idle > dtlsAssocIdle {
			_ = a.Close()
			delete(m.assocs, k)
		}
	}
	if len(m.assocs) < m.cap() {
		m.atCapacity = false
	}
}

// serveAssoc runs one association: the handshake, then the read loop that turns
// decrypted records into wire messages.
func (m *rendezvousMux) serveAssoc(a *dtlsAssoc) {
	defer m.drop(a)

	conn, err := dtls.Server(a, a.raddr, m.cfg)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dtlsHandshakeTimeout)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		// Not logged per failure. A spoofed source that never answers the
		// HelloVerifyRequest reaches exactly this line, and one line per spoofed
		// datagram is how a log becomes as good as no log at all (see
		// coordLink.noteUnroutable for the same rule on the other side).
		_ = conn.Close()
		return
	}

	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(dtlsAssocIdle))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		a.lastSeen = time.Now()
		a.mu.Unlock()

		var w wire
		if json.Unmarshal(buf[:n], &w) != nil {
			continue // same treatment a malformed cleartext datagram gets
		}
		handle(w, a.raddr)
	}
}

// drop closes an association and forgets it.
func (m *rendezvousMux) drop(a *dtlsAssoc) {
	_ = a.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.assocs[a.raddr.String()]; ok && cur == a {
		delete(m.assocs, a.raddr.String())
	}
}

// sweepLoop reclaims idle associations on a timer, so a burst does not stay
// resident until the next handshake happens to arrive.
func (m *rendezvousMux) sweepLoop(ctx context.Context) {
	t := time.NewTicker(dtlsAssocSweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			m.mu.Lock()
			m.sweepLocked(now)
			m.mu.Unlock()
		}
	}
}

// replyTo writes m to to's established DTLS association, reporting whether there
// was one. A source with no association — every client on the current build —
// gets the cleartext reply it has always got.
//
// This is the whole of the reply side. It is called from send(), which every
// handler already goes through, so no handler had to learn that a client might be
// on the other shape.
func (m *rendezvousMux) replyTo(to *net.UDPAddr, b []byte) bool {
	if m == nil || to == nil {
		return false
	}
	m.mu.Lock()
	a := m.assocs[to.String()]
	m.mu.Unlock()
	if a == nil {
		return false
	}
	conn := a.live()
	if conn == nil {
		return false
	}
	if _, err := conn.Write(b); err != nil {
		// A write failure here is not a reason to fall back to cleartext. The
		// peer asked for DTLS; answering in the clear would undo the property
		// this file exists for, on the one path where nobody would notice.
		if !errors.Is(err, net.ErrClosed) {
			log.Printf("rendezvous: DTLS reply to %s failed: %v", to, err)
		}
		return true
	}
	return true
}
