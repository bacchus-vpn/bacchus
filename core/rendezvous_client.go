package core

// The client's own path to a coordinator stops being cleartext (issue #175 slice
// 2, ADR-0062).
//
// Slice 1 (ADR-0059) made the coordinator's signaling port serve DTLS alongside
// raw JSON, and #202 (ADR-0060) made it answer the STUN connectivity check that
// precedes DTLS in a real WebRTC flow. Both halves were deliberately deployable on
// their own, because nothing emitted either shape: coordLink.send marshalled a wire
// struct and wrote it, so THE FIRST PACKET A BACCHUS CLIENT EVER SENT WAS PLAINTEXT
// JSON OVER RAW UDP and a DPI box read the literal bytes {"type":"connect" off a
// UDP payload to one port. Everything the transport ladder protects sits downstream
// of that. This file is the half that makes the ladder reachable.
//
// # The shape
//
// One ICE connectivity check on the 5-tuple, then DTLS on that same 5-tuple, which
// is the order a real endpoint produces and the reason both halves are needed: a
// ClientHello arriving from nowhere is DTLS-shaped, not WebRTC-shaped.
//
// # There is no fallback to cleartext, and that is a ruling rather than an omission
//
// ADR-0059 §4 planned "try DTLS, fall back, remember" as the compatibility
// mechanism. It was ruled out. A censor dropping DTLS and a coordinator predating
// slice 1 are INDISTINGUISHABLE to that rule — both produce silence — so the
// fallback would read as "when the disguise is blocked, send the cleartext the
// disguise existed to remove", which hands a censor the plaintext by dropping two
// datagrams. With no signed release channel (#34) there is no way to withdraw it
// afterwards either, so whatever ships in the 1.0 client is permanent.
//
// The consequence is that a coordinator which does not speak this shape is
// UNREACHABLE to this client, exactly as a blocked one is. It is not a silent
// downgrade: the client rotates to another pool member on the existing 30-second
// cooldown, and a member whose handshake does not complete says so once (see
// noteHandshakeFailed) rather than presenting as an unexplained timeout.
//
// # What slice 1 left in writing, and why the shim exists
//
// dialPool builds its links with net.DialUDP, and a CONNECTED *net.UDPConn fails
// every WriteTo with "use of WriteTo with pre-connected connection" — while
// dtls.Client requires a net.PacketConn. The fix is this file's shim, whose WriteTo
// calls Write, and NOT unconnecting the socket: ADR-0057 §4 depends on a connected
// socket surfacing a dead peer's ICMP port-unreachable as ECONNREFUSED on the next
// write, which is the one signal separating an unreachable coordinator from a
// silent one.
//
// # One reader for the socket
//
// The link's socket carries three things now — DTLS records, the Binding Response
// to our own check, and (in principle) a cleartext reply from something that is not
// a slice-1 coordinator. So exactly one goroutine reads it and routes by shape,
// which is the coordinator's mux inverted. Two readers would steal each other's
// datagrams, and a DTLS layer reading the socket directly would consume the Binding
// Response and error on it.
//
// # What this file does not do
//
// It does not apply the fingerprint profiles in core/dtls_fingerprint.go. Those
// need a dtls.Config counterpart to dtlsProfile.apply, which takes a
// *webrtc.SettingEngine today; that is slice 3 and #175 stays open for it. What
// this file DOES take from that file is the substance underneath the profiles — the
// negotiable suites and the browser supported-groups list — because those are what
// ADR-0059 §3 measured the 37-byte record overhead against.
//
// It also does not probe, race or learn. #175's remaining ladder work, and the two
// design questions it turns on (what a probe is with no end-to-end Noise channel,
// and whether a coordinator-hop probe is itself a distinguisher), are untouched and
// deliberately unanswered here. In particular the Binding Response below decides
// NOTHING; see sendCheck.

import (
	"context"
	"net"
	"sync"
	"time"

	dtls "github.com/pion/dtls/v3"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/rendezvous"
)

const (
	// dtlsRecordOverhead is what one DTLS record costs on top of the payload it
	// carries: a 13-byte DTLS 1.2 record header, an 8-byte explicit GCM nonce and a
	// 16-byte tag.
	//
	// Measured rather than derived (ADR-0059 §3), between two endpoints configured
	// exactly as this file configures them, counting bytes at the socket. It is 37
	// for both AES-GCM suites and 29 for ChaCha20-Poly1305; the worst suite in
	// negotiableSuites is AES-256-CBC-SHA at 52, which is not what negotiates. The
	// fingerprint profiles make no difference to it — they reshape the ClientHello,
	// not the record layer.
	dtlsRecordOverhead = 37

	// maxShapedRendezvousPayload is maxRendezvousPayload less the record overhead:
	// what a rendezvous message may weigh once it travels inside an association.
	//
	// It is a SEPARATE constant rather than a smaller maxRendezvousPayload because
	// the two are both live. A forwarder's link is still cleartext (see
	// Engine.Start), so the same code path serves both budgets, and a link reports
	// against the one it actually speaks.
	maxShapedRendezvousPayload = maxRendezvousPayload - dtlsRecordOverhead

	// rendezvousHandshakeTimeout bounds one association's handshake. Three client
	// flights and three server flights is 2 RTT before the first byte of a connect
	// can leave, and pion retransmits its own flights on a 1-second initial timer.
	//
	// Three seconds is the arithmetic on the path this product is for, not a round
	// number: a 400ms RTT gives 0.4s for the connectivity check and 0.8s for the
	// handshake, leaving room for one retransmitted flight. It is deliberately well
	// under the budgets it spends — listTimeout is 8s, directTimeout 12s — because a
	// member whose handshake fails is one to rotate PAST, and the legs no longer wait
	// out their own deadline after one fails (see coordLink.handshakeFailed).
	rendezvousHandshakeTimeout = 3 * time.Second

	// rendezvousHandshakeBackoff is how long a link whose handshake FAILED reports
	// that failure immediately instead of trying again.
	//
	// Without it one leg pays the timeout several times over: ListCountries greets a
	// member and then sends three copies of its request, and each send would start
	// its own doomed handshake. It is short — one leg's worth — rather than aligned
	// with the pool's 30-second health cooldown, because rankCoordinators still tries
	// a cooling member when every member is cooling ("a slow retry beats a client
	// that refuses to connect at all"), and a link that refused to retry would make
	// that promise false.
	//
	// It applies to a handshake that never completed. An association that completed
	// and then failed a WRITE is retried on the very next send, because that is a
	// different fact about a member that was working.
	//
	// It does NOT cover an association that died without failing anything, which is
	// most of them: a coordinator restart leaves this side writing into a
	// conversation the other end has forgotten, every write succeeds because a UDP
	// send into a dead association is a local success forever, and nothing here ever
	// learns of it. That case is not the link's to notice — see rendezvousAssocIdle
	// for the one clock this file has, and coordLink.relink for what actually
	// recovers it (issue #225).
	rendezvousHandshakeBackoff = 2 * time.Second

	// rendezvousAssocIdle is how long an association survives with no traffic before
	// the next send replaces it, and the number is chosen against the COORDINATOR's
	// clock rather than this client's.
	//
	// The coordinator sweeps an association after 2 minutes of idleness and sweeps on
	// a 30-second ticker, so it may hold one for up to 2m30s. Until it lets go, a
	// fresh ClientHello from the same 5-tuple is delivered INTO the association it
	// still holds — its mux finds the source in its table before it looks at the
	// record type — and the handshake never completes. So this must be LONGER than
	// the coordinator's window, not shorter, which is the opposite of what an idle
	// timeout usually wants.
	//
	// Without it the link wedges silently. A client idle past the coordinator's
	// sweep holds an association the other end has forgotten; its next datagram is a
	// record from a source with no association, which the coordinator drops, and
	// nothing on this side errors — so the send succeeds, the reply never comes, and
	// the member reads as blocked forever. A rendezvous is a burst (greet, list,
	// connect, signal a handshake through) and then nothing for as long as the
	// session lasts, so that gap is the ordinary case and not an edge one.
	//
	// # What this clock is NOT, which cost a hundred minutes to find out
	//
	// It measures time since this link was last USED, and lastUsed is stamped by
	// every send — by establish itself, before the association is even handed back.
	// So it retires an association nobody is talking through, and only that. It can
	// never retire one being sent to, which is the wedge that matters: a client whose
	// coordinator restarted underneath it retries, and every retry stamps the very
	// clock that was supposed to rescue it. On the box issue #225 was found on, a
	// reconnect every ~53 seconds and a volunteer's register every 10 kept this
	// threshold permanently three minutes away, for a hundred minutes.
	//
	// It is left as it is rather than re-pointed at a "last HEARD" clock, because
	// hearing nothing is the NORMAL state of a healthy link: the coordinator answers
	// list, connect and challenge, and answers neither hello nor register, so a
	// volunteer that is merely registering hears nothing from a coordinator that is
	// perfectly well. A clock that retired on silence alone would churn every
	// healthy forwarder's association forever. Recovery is driven by evidence
	// instead, from the leg that has it — see Engine.relinkIfStale.
	rendezvousAssocIdle = 3 * time.Minute

	// rendezvousCheckWait is how long the ICE connectivity check is given to be
	// answered before the handshake starts anyway.
	//
	// It is a shape, not a gate — see sendCheck. Long enough to cover an
	// ordinary round trip so the observable order is check, response, ClientHello;
	// short enough that a coordinator which does not answer costs a fraction of one
	// attempt rather than an attempt.
	rendezvousCheckWait = 400 * time.Millisecond

	// shapedQueue is how many inbound datagrams may be queued for the DTLS layer
	// before further ones are DROPPED. Dropping is correct rather than a
	// compromise: this is UDP, a datagram may be lost at any hop for any reason,
	// and DTLS retransmits its own handshake flights. Blocking instead would let
	// the DTLS layer stall the one goroutine that owns the socket.
	shapedQueue = 16
)

// ---------- one association ----------

// shapedAssoc is one attempt at an association with a coordinator: the virtual
// packet conn the DTLS layer rides, and the result of its handshake.
//
// It is also the shim ADR-0059 §"What slice 2 inherits" describes: WriteTo ignores
// the address and calls Write on the CONNECTED socket, which is what lets a
// dtls.Client run over a link dialled with net.DialUDP without unconnecting it.
type shapedAssoc struct {
	pc *net.UDPConn // the link's connected socket

	in    chan []byte   // DTLS records, from the link's reader
	check chan struct{} // closed once the ICE check is answered
	ready chan struct{} // closed once conn/err below are final
	done  chan struct{} // closed when this attempt is finished

	checkOnce sync.Once
	closeOnce sync.Once

	// conn and err are written before ready is closed and read only after, so the
	// close is the whole of the synchronisation.
	conn *dtls.Conn
	err  error

	// readDeadline backs SetReadDeadline for the virtual conn. pion sets it while
	// retransmitting handshake flights, so it has to be real rather than a stub.
	deadlineMu sync.Mutex
	deadline   time.Time
	deadlineCh chan struct{}
}

func newShapedAssoc(pc *net.UDPConn) *shapedAssoc {
	return &shapedAssoc{
		pc:         pc,
		in:         make(chan []byte, shapedQueue),
		check:      make(chan struct{}),
		ready:      make(chan struct{}),
		done:       make(chan struct{}),
		deadlineCh: make(chan struct{}),
	}
}

func (a *shapedAssoc) ReadFrom(b []byte) (int, net.Addr, error) {
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
				return 0, a.pc.RemoteAddr(), net.ErrClosed
			}
			return copy(b, p), a.pc.RemoteAddr(), nil
		case <-a.done:
			return 0, a.pc.RemoteAddr(), net.ErrClosed
		case <-timer:
			return 0, a.pc.RemoteAddr(), shapedTimeout{}
		case <-ch:
			// The deadline was replaced while we were waiting; re-read it.
		}
	}
}

// WriteTo is the shim. The address is ignored because the socket is connected —
// which is the point: WriteTo on a pre-connected *net.UDPConn fails every time, and
// unconnecting it would cost ADR-0057 §4 the ECONNREFUSED that distinguishes a dead
// coordinator from a silent one.
func (a *shapedAssoc) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-a.done:
		return 0, net.ErrClosed
	default:
	}
	return a.pc.Write(b)
}

func (a *shapedAssoc) Close() error {
	a.closeOnce.Do(func() { close(a.done) })
	return nil
}

func (a *shapedAssoc) LocalAddr() net.Addr { return a.pc.LocalAddr() }

func (a *shapedAssoc) SetDeadline(t time.Time) error {
	_ = a.SetWriteDeadline(t)
	return a.SetReadDeadline(t)
}

func (a *shapedAssoc) SetReadDeadline(t time.Time) error {
	a.deadlineMu.Lock()
	prev := a.deadlineCh
	a.deadline = t
	a.deadlineCh = make(chan struct{})
	a.deadlineMu.Unlock()
	close(prev) // wake any reader so it picks the new deadline up
	return nil
}

// SetWriteDeadline is a no-op: writes go straight to a non-blocking UDP socket and
// cannot outlive a deadline. Returning an error instead would fail pion's
// SetDeadline, which sets both.
func (a *shapedAssoc) SetWriteDeadline(time.Time) error { return nil }

// shapedTimeout is a net.Error that reports itself as a timeout, which is what pion
// checks for when a handshake flight needs retransmitting.
type shapedTimeout struct{}

func (shapedTimeout) Error() string   { return "i/o timeout" }
func (shapedTimeout) Timeout() bool   { return true }
func (shapedTimeout) Temporary() bool { return true }

// deliver hands one datagram to the DTLS layer, dropping it when the queue is full
// — see shapedQueue.
func (a *shapedAssoc) deliver(raw []byte) {
	p := make([]byte, len(raw))
	copy(p, raw)
	select {
	case a.in <- p:
	case <-a.done:
	default:
	}
}

// noteCheckAnswered records that the ICE connectivity check drew a response. It is
// idempotent because a real check may be answered more than once.
func (a *shapedAssoc) noteCheckAnswered() { a.checkOnce.Do(func() { close(a.check) }) }

// ---------- the link ----------

// shapedLink is one coordinator link's message transport: the association, the
// goroutine that owns the socket, and the lazy, re-establishable lifecycle around
// them.
//
// LAZY is load-bearing. dialPool dials every pool member up front, and dialing a
// UDP socket puts nothing on the wire — which is why a client can hold its whole
// fallback set without revealing it. A handshake at dial time would undo that and
// hand a censor every member at startup. So an association is minted by the first
// SEND to a member, which is exactly the rotation the client already controls.
type shapedLink struct {
	pc    *net.UDPConn
	raddr net.Addr

	mu      sync.Mutex
	cur     *shapedAssoc
	wake    chan struct{} // closed and replaced whenever cur changes
	started bool          // the socket reader has been started
	closed  bool

	// failedUntil and failErr cache a handshake that did not complete, so the rest
	// of one leg's sends report it immediately rather than each starting another.
	// See rendezvousHandshakeBackoff.
	failedUntil time.Time
	failErr     error

	// lastUsed is when this link last carried a message either way. See
	// rendezvousAssocIdle for why an association is replaced once it goes stale, and
	// why the threshold is set by the coordinator's sweep rather than by this side.
	lastUsed time.Time

	// unshaped counts replies that arrived in neither shape this link speaks. It is
	// a counter rather than a log line because this file has no engine to emit
	// through; coordLink reports it, memoized, in the place every other link
	// diagnosis already lives.
	unshapedMu sync.Mutex
	unshaped   int
}

func newShapedLink(pc *net.UDPConn) *shapedLink {
	return &shapedLink{pc: pc, raddr: pc.RemoteAddr(), wake: make(chan struct{})}
}

// bump wakes anything waiting for the current association to change. The caller
// holds mu.
func (l *shapedLink) bump() {
	close(l.wake)
	l.wake = make(chan struct{})
}

// Write puts one datagram inside the association, establishing one first if this
// link has none. It blocks for at most one handshake.
func (l *shapedLink) Write(b []byte) (int, error) {
	a, err := l.establish()
	if err != nil {
		return 0, err
	}
	n, err := a.conn.Write(b)
	switch {
	case err == nil:
		l.mu.Lock()
		l.lastUsed = time.Now()
		l.mu.Unlock()
	case isMessageTooLong(err):
		// A datagram this host refused for its SIZE says nothing about the
		// association, and retiring one over it would turn a local path limit into a
		// lost coordinator — plus a re-handshake on the same 5-tuple is swallowed
		// while the far end still holds the old association, so the member would be
		// unreachable for minutes over a message that was simply too big. Measured:
		// the kernel's EMSGSIZE reaches this caller intact through pion, so issue
		// #183's diagnosis survives the shaped hop.
	default:
		// A dead association is dropped rather than retried here: the next send
		// starts a fresh handshake, and retrying inside one send would spend a
		// caller's budget without telling it.
		l.drop(a)
	}
	return n, err
}

// live reports whether this link currently holds a completed association. It is what
// separates "the handshake never happened" from "the write failed" at the send site,
// which want different diagnoses.
func (l *shapedLink) live() bool {
	l.mu.Lock()
	a := l.cur
	l.mu.Unlock()
	if a == nil {
		return false
	}
	select {
	case <-a.ready:
		return a.err == nil && a.conn != nil
	default:
		return false
	}
}

// Read returns the next decrypted message. It blocks until this link has an
// association — which, on a link nothing has sent to yet, is forever, and is what
// keeps the read loop from touching the network before the client rotates here.
func (l *shapedLink) Read(b []byte) (int, error) {
	var last *shapedAssoc
	for {
		a, ok := l.await(last)
		if !ok {
			return 0, net.ErrClosed
		}
		last = a
		<-a.ready
		if a.err != nil {
			continue // this attempt failed; wait for the next send to start another
		}
		n, err := a.conn.Read(b)
		if err == nil {
			l.mu.Lock()
			l.lastUsed = time.Now()
			l.mu.Unlock()
			return n, nil
		}
		l.drop(a)
		if l.isClosed() {
			return 0, err
		}
	}
}

// Close stops this link. The socket itself is closed by the caller (coordLink),
// which is what ends the reader goroutine.
func (l *shapedLink) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	a := l.cur
	l.cur = nil
	l.bump()
	l.mu.Unlock()
	if a != nil {
		_ = a.Close()
	}
	return nil
}

func (l *shapedLink) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// unshapedReplies returns and clears the count of replies that arrived in neither
// shape this link speaks.
func (l *shapedLink) unshapedReplies() int {
	l.unshapedMu.Lock()
	defer l.unshapedMu.Unlock()
	n := l.unshaped
	l.unshaped = 0
	return n
}

// establish returns a live association, minting and handshaking one if needed.
func (l *shapedLink) establish() (*shapedAssoc, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	if l.failErr != nil && time.Now().Before(l.failedUntil) {
		err := l.failErr
		l.mu.Unlock()
		return nil, err
	}
	if !l.started {
		l.started = true
		go l.readSocket()
	}
	a := l.cur
	if a != nil && !l.lastUsed.IsZero() && time.Since(l.lastUsed) > rendezvousAssocIdle {
		// Stale: the coordinator has certainly swept its half by now, so this one is
		// holding a conversation the other end has forgotten. Retired here rather
		// than on a read error, because there is no error to read — see
		// rendezvousAssocIdle.
		l.cur = nil
		l.bump()
		stale := a
		a = nil
		l.mu.Unlock()
		closeAssoc(stale)
		l.mu.Lock()
		// Re-read: the lock was released to close the stale association, and a
		// concurrent send may have started a fresh one in the meantime. Overwriting it
		// would leave two associations racing for one socket.
		a = l.cur
	}
	if a == nil {
		a = newShapedAssoc(l.pc)
		l.cur = a
		l.bump()
		go l.handshake(a)
	}
	l.lastUsed = time.Now()
	l.mu.Unlock()

	<-a.ready
	if a.err != nil {
		l.mu.Lock()
		l.failedUntil, l.failErr = time.Now().Add(rendezvousHandshakeBackoff), a.err
		l.mu.Unlock()
		l.drop(a)
		return nil, a.err
	}
	l.mu.Lock()
	l.failedUntil, l.failErr = time.Time{}, nil
	l.mu.Unlock()
	return a, nil
}

// await blocks until this link's current association is something other than prev,
// or the link is closed.
func (l *shapedLink) await(prev *shapedAssoc) (*shapedAssoc, bool) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, false
		}
		if l.cur != nil && l.cur != prev {
			a := l.cur
			l.mu.Unlock()
			return a, true
		}
		w := l.wake
		l.mu.Unlock()
		<-w
	}
}

// drop retires a, if it is still the current association, so the next send starts a
// fresh handshake.
func (l *shapedLink) drop(a *shapedAssoc) {
	l.mu.Lock()
	if l.cur == a {
		l.cur = nil
		l.bump()
	}
	l.mu.Unlock()
	closeAssoc(a)
}

// closeAssoc retires an association and, if its handshake had already finished,
// the DTLS conn under it.
//
// a.conn is written before a.ready is closed and read only after, so the closed
// channel is the whole of the synchronisation. Retiring one whose handshake is
// still in flight closes a.done instead, which fails its next read and lets the
// handshake goroutine clean up its own conn — see handshake.
func closeAssoc(a *shapedAssoc) {
	_ = a.Close()
	select {
	case <-a.ready:
		if a.conn != nil {
			_ = a.conn.Close()
		}
	default:
	}
}

// handshake runs one attempt: the ICE connectivity check, then DTLS on the same
// 5-tuple. It always closes a.ready.
func (l *shapedLink) handshake(a *shapedAssoc) {
	defer close(a.ready)

	if err := l.sendCheck(a); err != nil {
		a.err = err
		return
	}

	conn, err := dtls.Client(a, l.raddr, shapedDTLSConfig())
	if err != nil {
		a.err = err
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), rendezvousHandshakeTimeout)
	defer cancel()
	// The association's own teardown cancels the handshake, so a Stop during one
	// does not hold the engine's WaitGroup for the full timeout.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-a.done:
			cancel()
		case <-stop:
		}
	}()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		a.err = err
		return
	}
	a.conn = conn
	// Retired while the handshake ran — a Stop, or a stale association swept out
	// from under it. Nothing will read a.conn, so close it here rather than leaving
	// it to be collected.
	select {
	case <-a.done:
		_ = conn.Close()
		a.conn, a.err = nil, net.ErrClosed
	default:
	}
}

// sendCheck emits one ICE connectivity check and gives it rendezvousCheckWait to be
// answered.
//
// # The response decides nothing, and that is deliberate
//
// This is not a probe, and #175's open question about what a probe would even be at
// a hop with no end-to-end Noise channel is untouched by it. The handshake proceeds
// on a response, on the timeout, and on a coordinator that answers checks with
// silence, identically. Making the response a precondition would turn the check
// into a reachability test whose failure mode is "do not try", which is a decision
// this slice is not entitled to make and which would also give the client a new
// externally visible behaviour to be fingerprinted by.
//
// What the wait buys is ORDER. A real endpoint runs the check and then runs DTLS on
// the same 5-tuple, so emitting a ClientHello in the same breath as the check would
// produce a sequence no ICE agent produces — which is the tell this half exists to
// remove.
//
// One check, not a retransmission ladder. A lost check costs the shape of this
// association and nothing else, since the handshake follows regardless; retrying
// would spend the caller's budget on camouflage.
func (l *shapedLink) sendCheck(a *shapedAssoc) error {
	ufrag, pwd, err := browserICECredentials(dtlsProfile{})
	if err != nil {
		// Camouflage that cannot be drawn is not a reason to fail a connect: skip
		// the check and let the handshake carry the association. A client that
		// refused here would be one that stops working when crypto/rand hiccups.
		return nil
	}
	// USERNAME on a real check is "remote-ufrag:local-ufrag". There is no remote
	// ufrag at this hop, so both halves are drawn locally — the shape is what
	// travels, and coldstart.BindingRequest's doc is explicit that the integrity
	// attribute it keys with pwd is camouflage rather than authentication.
	if _, err := l.pc.Write(coldstart.BindingRequest(ufrag+":"+ufrag, []byte(pwd))); err != nil {
		return err
	}
	select {
	case <-a.check:
	case <-a.done:
		return net.ErrClosed
	case <-time.After(rendezvousCheckWait):
	}
	return nil
}

// readSocket owns the link's socket for its whole life and routes each datagram to
// the shape it is. It exits when the socket is closed, which coordLink.close does.
func (l *shapedLink) readSocket() {
	buf := make([]byte, 65535)
	for {
		n, err := l.pc.Read(buf)
		if err != nil {
			l.mu.Lock()
			a := l.cur
			l.mu.Unlock()
			if a != nil {
				_ = a.Close()
			}
			return
		}
		l.mu.Lock()
		a := l.cur
		l.mu.Unlock()
		if a == nil {
			continue
		}
		switch {
		case rendezvous.LooksLikeDTLS(buf[:n]):
			a.deliver(buf[:n])
		case coldstart.LooksLikeBindingSuccess(buf[:n]):
			a.noteCheckAnswered()
		default:
			// Neither shape this link speaks. Counted rather than dropped silently,
			// for issue #5's reason: a reply nothing can route is indistinguishable
			// at the waiting leg from a coordinator that never answered, and the
			// client then reports a healthy member as unreachable. The likeliest
			// cause is a coordinator running with the shaped hop switched off, and
			// under ADR-0062 that member is unreachable to this client — which it
			// should be told, once, rather than left to infer from a timeout.
			l.unshapedMu.Lock()
			l.unshaped++
			l.unshapedMu.Unlock()
		}
	}
}

// shapedDTLSConfig is what this client offers at the rendezvous hop.
//
// # InsecureSkipVerify, and why it is not a shortcut
//
// The coordinator presents a self-signed certificate generated fresh at startup and
// it AUTHENTICATES NOTHING. That is not a gap this flag papers over — it is the
// design, recorded in ADR-0059 §6: the desktop client holds no coordinator public
// key at all, so a client "verifying" this certificate would be verifying it against
// nothing it could check. What DTLS buys at this hop is confidentiality against a
// passive observer and integrity against an off-path injector; the authentication
// that matters travels INSIDE and is unchanged — the admission credential
// (ADR-0023/0047) and the device-credential chain (ADR-0045/0046), both of which
// bind to the address this client chose to dial.
//
// Per-coordinator keys carried in the signed directory would make verification
// meaningful. That is #193's mechanism and this file does not pre-empt it.
//
// # The suites and curves
//
// negotiableSuites and browserCurves come from core/dtls_fingerprint.go, which is
// where the browser profiles live, and they are the substance under those profiles
// rather than the profiles themselves: they are what a browser will actually agree
// to, and they are the configuration ADR-0059 §3 measured the 37-byte record
// overhead against. The ClientHello REWRITE — the part that reshapes the bytes — is
// slice 3.
func shapedDTLSConfig() *dtls.Config {
	return &dtls.Config{
		CipherSuites:   negotiableSuites,
		EllipticCurves: browserCurves,
		// Matches what the coordinator requires and what core/transport_webrtc.go
		// negotiates, so the two DTLS handshakes this product emits do not differ on
		// a field a classifier can read.
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		InsecureSkipVerify:   true,
	}
}
