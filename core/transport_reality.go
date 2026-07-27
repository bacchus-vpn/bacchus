package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// The reality transport is the second Transport implementation (issue #16,
// ADR-0008): TCP :443 wrapped in camouflage TLS, so it fails on a different axis
// than WebRTC. WebRTC is UDP/DTLS and dies where an operator throttles UDP or
// DataChannels; this rides TCP :443 with a borrowed-looking TLS handshake, the
// surface that still survives in Russia (all of banking/Gosuslugi rides it).
// Coverage is the union of the two, selected per user by the pool (issue #15).
//
// Session model, mirrored onto TCP from the WebRTC one: a session is a set of
// TLS connections to the exit's :443; each stream is one such connection,
// labelled in an inner handshake; one "control" connection (ctrlLabel, shared
// with the WebRTC path) carries no data and exists only to prove the path is
// usable and to signal teardown when it drops. One TLS conn per stream — rather
// than a multiplexer over a single conn — keeps reliability on TCP where it
// belongs and reads on the wire like a browser opening many parallel HTTPS
// connections.
const (
	realityName = "reality"

	// realityMagic tags the inner handshake. It rides *inside* the TLS session,
	// so it is invisible to on-path DPI; it exists for versioning and to reject
	// obvious garbage early, not as camouflage.
	realityMagic    = "BKR1"
	realityTokenLen = 16 // one session token, minted per Accept
	realityAckOK    = 0x01

	// realityHSTimeout bounds the outer TLS + inner handshake on the responder,
	// so a port scan or a stalled probe cannot pin a goroutine open.
	realityHSTimeout = 10 * time.Second

	// realityProbeTimeout bounds the whole active-probe response — the reverse
	// proxy to the origin, or the hold-and-drain when the origin is unreachable —
	// so a slow prober cannot pin a goroutine open indefinitely (issue #62).
	realityProbeTimeout = 30 * time.Second

	// realityProbeOff is the RealityProbeOrigin sentinel that disables probe
	// proxying and restores the bare immediate-close response.
	realityProbeOff = "off"

	defaultRealitySNI    = "www.microsoft.com"
	defaultRealityListen = ":443"
)

// realityOffer is the client's opening frame: it carries nothing the exit needs
// except its arrival (proving the client is live and giving the coordinator a
// return path), but it keeps the offer/answer shape the coordinator already
// relays and leaves room to negotiate later.
type realityOffer struct {
	Proto string `json:"p"`
}

// realityAnswer is the exit's reply: where to dial, the one-time session token to
// present in the inner handshake, the SNI to wear on the outer TLS, and the exit's
// static X25519 public key (hex) the client seals its ClientHello authenticator to
// (ADR-0032). The answer rides the coordinator-authenticated channel, so the public
// key needs no separate distribution.
type realityAnswer struct {
	Addr  string `json:"a"`
	Token string `json:"t"`
	SNI   string `json:"s"`
	Pub   string `json:"k"`
}

// realityTransport implements Transport over TCP+TLS. A single value serves many
// concurrent sessions in both directions: a client only ever calls Dial (never
// binds a listener), while an exit/relay calls Accept, which lazily brings up
// one shared TLS listener demultiplexed by the token each session mints.
type realityTransport struct {
	// Initiator (client) side.
	sni string // camouflage SNI to fall back on if an answer omits one

	// Responder (exit/relay) side.
	listenAddr  string              // TCP bind, default :443
	advertise   string              // host:port put in the answer; the bound addr when empty
	serverTLS   *tls.Config         // fallback self-signed config presented on the terminate path
	probeOrigin string              // host:port of the impersonated origin: splice/mimic/bridge target; "" disables (issue #62 / ADR-0032)
	realityKey  *realityKeyPair     // exit's static X25519 identity; public half rides in the answer (ADR-0032)
	replay      *realityReplayGuard // rejects verbatim ClientHello replays on the terminate path

	// mimicTLS is the terminate-path config once the impersonated origin's actual
	// certificate chain has been borrowed byte-for-byte (warmed in the background,
	// issue #92); nil until then, when the self-signed serverTLS stands in. Read on
	// the hot path, so it is atomic.
	mimicTLS atomic.Pointer[tls.Config]

	onEvent func(kind, msg string)

	// splice enforces the operator's declared limits (issue #143, ADR-0040) on the
	// active-probing reverse proxy — the one path that spent the operator's line
	// unmetered (design §8.7, issue #163). nil when no limits are declared (today's
	// fleet), in which case every splice path behaves exactly as it did before #163.
	// Injected by the engine after construction (Engine.attachRealitySplice), because
	// it shares the engine's quota+limiter and those outlive any one transport.
	splice *realitySpliceLimits

	// onUnderlayDial, when non-nil, is called with the exit's dial address just
	// before each underlay TCP connection to it is opened (dialInner), so a
	// full-device client can exclude that address from its tunnel first — the
	// only point at which reality's dynamically-learned address is known before
	// the connection exists (Config.OnUnderlayDial, issue #109). Client dial
	// path only; the responder side never sets it.
	onUnderlayDial func(addr string)

	lnOnce sync.Once
	lnErr  error

	// wg tracks every background goroutine the transport itself spawns (acceptLoop,
	// warmMimicCert, one serveInbound per inbound conn, one answer per Accept), so
	// close can Wait() for them instead of merely closing the listener and hoping
	// (issue #65). They are all already bounded (listener close, realityHSTimeout,
	// or ctx-cancel) — this makes that boundedness a real barrier, not a new timeout.
	wg sync.WaitGroup

	mu      sync.Mutex
	ln      net.Listener
	pending map[string]*realitySession // hex token -> session awaiting its conns
	closed  bool
}

// spawn runs fn on a new goroutine tracked by t.wg, so close's Wait() only returns
// once every spawned goroutine has actually exited.
func (t *realityTransport) spawn(fn func()) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		fn()
	}()
}

// newRealityTransport builds the transport from a node Config. The camouflage
// certificate and the exit's static X25519 identity (ADR-0032) are generated here
// so a bad crypto draw fails New(), not the first Accept. onEvent, when non-nil,
// receives transport-level notices.
func newRealityTransport(cfg Config, onEvent func(kind, msg string)) (*realityTransport, error) {
	sni := cfg.RealitySNI
	if sni == "" {
		sni = defaultRealitySNI
	}
	listen := cfg.RealityListen
	if listen == "" {
		listen = defaultRealityListen
	}
	// Reuse the exit's already-configured advertised host:port when a
	// reality-specific one isn't set — an exit advertises one reachable address.
	adv := cfg.RealityAdvertise
	if adv == "" {
		adv = cfg.Advertise
	}
	tlsCfg, err := realityServerTLS(sni)
	if err != nil {
		return nil, fmt.Errorf("core: reality server TLS: %w", err)
	}
	key, err := newRealityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("core: reality static key: %w", err)
	}
	// Active-probe response (issue #62): a failed inner handshake is reverse-
	// proxied to a real origin so a prober sees an ordinary website, not the tell
	// of an instant close. On by default — an unset origin means the SNI host on
	// :443; the sentinel "off" restores the bare immediate close.
	origin := cfg.RealityProbeOrigin
	switch origin {
	case "":
		origin = net.JoinHostPort(sni, "443")
	case realityProbeOff:
		origin = ""
	}
	return &realityTransport{
		sni:            sni,
		listenAddr:     listen,
		advertise:      adv,
		serverTLS:      tlsCfg,
		probeOrigin:    origin,
		realityKey:     key,
		replay:         newRealityReplayGuard(),
		onEvent:        onEvent,
		onUnderlayDial: cfg.OnUnderlayDial,
		pending:        map[string]*realitySession{},
	}, nil
}

func (t *realityTransport) Name() string { return realityName }

// Dial is the initiator: announce readiness, learn the exit's address + token
// from the answer, then open one control connection. Returning only once that
// connection is up makes Dial a real reachability probe — a blocked :443 fails
// here, which is what the transport pool (issue #15) needs to fail over.
func (t *realityTransport) Dial(ctx context.Context, sig Signaler) (Session, error) {
	if err := sendFrames(ctx, sig, sigOffer, mustJSON(realityOffer{Proto: realityName}), 2); err != nil {
		return nil, err
	}
	ans, err := awaitAnswer(ctx, sig)
	if err != nil {
		return nil, err
	}

	s := newRealitySession(t.onEvent)
	// The session dials fresh connections for later streams with the same
	// address + token; the token stays valid for the session's lifetime.
	s.dialer = func(ctx context.Context, label string) (net.Conn, error) {
		return t.dialInner(ctx, ans, label)
	}

	ctrl, err := t.dialInner(ctx, ans, ctrlLabel)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.useControl(ctrl)
	return s, nil
}

// Accept is the responder: bring up the shared listener and run the signaling
// exchange in the background so it returns promptly (the engine calls it
// inline). Streams then arrive via AcceptStream as the client dials them.
func (t *realityTransport) Accept(ctx context.Context, sig Signaler) (Session, error) {
	if err := t.ensureListener(); err != nil {
		return nil, err
	}
	s := newRealitySession(t.onEvent)
	s.transport = t
	t.spawn(func() { t.answer(sig, s) })
	return s, nil
}

// answer waits for the client's offer, mints and registers a one-time token,
// and replies with the dial address. It runs on the session's own context so
// Close unblocks it. Registering only after an offer keeps stray tokens out of
// the pending map.
func (t *realityTransport) answer(sig Signaler, s *realitySession) {
	if _, err := awaitKind(s.ctx, sig, sigOffer); err != nil {
		s.Close()
		return
	}
	tokHex := hex.EncodeToString(newToken())

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		s.Close()
		return
	}
	t.pending[tokHex] = s
	adv := t.advertise
	if adv == "" && t.ln != nil {
		adv = t.ln.Addr().String() // loopback / ephemeral-port: advertise what we bound
	}
	t.mu.Unlock()

	// Record the token on the session so its Close unregisters it. The session
	// escaped to the engine the moment Accept returned, so Close may already
	// have run (before this offer even arrived): if so, it read an empty token
	// and will not forget this one, so we must — otherwise the entry we just put
	// in t.pending leaks for the life of the process.
	if !s.bindToken(tokHex) {
		t.forget(tokHex)
		return
	}

	ans := realityAnswer{Addr: adv, Token: tokHex, SNI: t.sni, Pub: hex.EncodeToString(t.realityKey.pub)}
	_ = sendFrames(s.ctx, sig, sigAnswer, mustJSON(ans), 2)
}

// ensureListener binds the shared TLS listener once and starts its accept loop.
// Idempotent and safe across the many Accept calls a single exit makes.
//
// Honors t.closed on both sides of the net.Listen call (issue #101): without
// this, a close() that runs concurrently with (or just before) the very first
// Accept's call to ensureListener could still let this sync.Once fire, binding a
// fresh listener and spawning acceptLoop/warmMimicCert after close() already
// flipped t.closed and returned — close() would have read t.ln as still nil (not
// yet published) and skipped closing it, and its wg.Wait() would have seen no
// spawned goroutines yet and returned immediately, leaking a listener and its
// goroutines past what the caller believed was a fully quiesced transport. The
// publish-and-spawn step below happens inside the same critical section as the
// second t.closed check, so close()'s own critical section (set t.closed, read
// t.ln) can only ever observe this either fully before it (t.ln still nil, wg
// still empty — nothing to leak) or fully after it (t.ln and both spawned
// goroutines already visible, so close() closes the listener and wg.Wait()
// correctly blocks on them).
func (t *realityTransport) ensureListener() error {
	t.lnOnce.Do(func() {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			t.lnErr = errors.New("core: reality transport closed")
			return
		}
		t.mu.Unlock()

		ln, err := net.Listen("tcp", t.listenAddr)
		if err != nil {
			t.lnErr = err
			return
		}

		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			t.lnErr = errors.New("core: reality transport closed")
			_ = ln.Close()
			return
		}
		t.ln = ln
		t.spawn(func() { t.acceptLoop(ln) })
		t.spawn(t.warmMimicCert)
		t.mu.Unlock()
	})
	return t.lnErr
}

// warmMimicCert borrows the impersonated origin's actual certificate chain once,
// in the background, so the terminate path can present the same publicly-chaining
// bytes the origin itself serves instead of a self-signed leaf (issue #92). Best-
// effort: if the origin is unreachable or probing is disabled, the self-signed
// serverTLS stands in.
func (t *realityTransport) warmMimicCert() {
	if t.probeOrigin == "" {
		return
	}
	cfg, err := realityMimicTLS(t.probeOrigin, t.sni)
	if err != nil {
		if t.onEvent != nil {
			t.onEvent(EventInfo, "reality: mimic cert unavailable, using self-signed ("+err.Error()+")")
		}
		return
	}
	t.mimicTLS.Store(cfg)
}

// terminateTLS is the config presented to an authenticated client: the origin's
// borrowed certificate chain once warmed, else the self-signed fallback. Either
// way the client does not validate the chain (trust is the Noise end-to-end
// handshake, ADR-0009) and, on the borrowed-chain path specifically, does not
// require the CertificateVerify signature to check out either (ADR-0032 / #92) —
// the exit does not hold the origin's private key, only its public bytes.
func (t *realityTransport) terminateTLS() *tls.Config {
	if cfg := t.mimicTLS.Load(); cfg != nil {
		return cfg
	}
	return t.serverTLS
}

func (t *realityTransport) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		t.spawn(func() { t.serveInbound(c) })
	}
}

// serveInbound handles one inbound TCP connection. It forks on the ClientHello
// before terminating TLS (ADR-0032): a connection whose legacy_session_id carries a
// valid authenticator is handled locally — terminate TLS, read the inner handshake,
// attach to the session its token names — while every other connection (a prober, a
// real browser, junk) is spliced to the impersonated origin so it completes its
// handshake against that origin and sees the origin's genuine certificate. No
// self-signed leaf of ours is ever shown to a stranger.
func (t *realityTransport) serveInbound(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(realityHSTimeout))
	peeked, hello, err := peekClientHello(raw)
	if err != nil || hello == nil || !t.authenticated(hello) {
		t.onUnauthenticated(raw, peeked)
		return
	}

	// Authenticated: terminate TLS ourselves, replaying the peeked ClientHello into
	// the local server so the handshake completes as if we never looked.
	tconn := tls.Server(&prefixConn{Conn: raw, prefix: peeked}, t.terminateTLS())
	if err := tconn.Handshake(); err != nil {
		t.reject(raw, "tls handshake: "+err.Error())
		return
	}
	// Record what the inner-handshake read consumes: on a failure this connection
	// falls back to the ADR-0027 reverse-proxy, and replaying these opening bytes
	// keeps that request from being truncated by the header we read to detect it.
	rec := &recordingReader{r: tconn}
	tok, label, err := readInnerHandshake(rec)
	if err != nil {
		t.onProbe(tconn, rec.buf, "inner handshake: "+err.Error())
		return
	}

	t.mu.Lock()
	s := t.pending[tok]
	t.mu.Unlock()
	if s == nil {
		t.onProbe(tconn, rec.buf, "unknown session token")
		return
	}

	if _, err := tconn.Write([]byte{realityAckOK}); err != nil {
		_ = tconn.Close()
		return
	}
	_ = tconn.SetDeadline(time.Time{}) // steady state carries no deadline
	s.attach(label, tconn)
}

// authenticated reports whether a peeked ClientHello carries a valid, fresh Reality
// authenticator: an X25519 key share plus a legacy_session_id that opens under the
// exit's static key and survives the replay guard. A stranger cannot forge it
// without the exit's private key, and a sniffed authenticator cannot be lifted onto
// another ClientHello (it is bound to this hello's random and key share).
func (t *realityTransport) authenticated(hello *realityClientHello) bool {
	if hello.x25519 == nil || len(hello.sessionID) != realitySessionIDLen {
		return false
	}
	secret, err := t.realityKey.secretFrom(hello.x25519)
	if err != nil {
		return false
	}
	ts, err := realityOpenSessionID(secret, hello.random, hello.sessionID)
	if err != nil {
		return false
	}
	return t.replay.admit(hello.sessionID, ts, time.Now())
}

// onUnauthenticated forks a connection that did not authenticate at the ClientHello
// to the impersonated origin (ADR-0032). It raw-splices the peeked bytes and the
// rest of the connection to the origin at the TCP layer, so the peer completes its
// TLS handshake directly against the origin and validates the origin's real
// certificate chain — the exit never presents a certificate to a stranger. If the
// origin is unreachable it holds and drains (as ADR-0027) rather than closing, so an
// unreachable origin does not reintroduce an instant-close tell; an operator who set
// the origin to "off" gets the bare immediate close it opted into.
func (t *realityTransport) onUnauthenticated(raw net.Conn, peeked []byte) {
	if t.probeOrigin == "" { // explicitly disabled
		t.reject(raw, "unauthenticated clienthello")
		return
	}
	// Declared-limit admission (issue #163). Once the operator's monthly quota is
	// spent — or this source IP is flooding new splices — do NOT open a reverse proxy:
	// drain instead, the same camouflaged response ADR-0027 already uses for an
	// unreachable origin, so refusing to amplify never becomes an instant-close tell.
	// A splice already in flight is untouched (option (c)); only NEW ones are refused.
	ok, release := t.splice.admitSplice(raw.RemoteAddr(), time.Now())
	if !ok {
		t.holdAndDrain(raw)
		return
	}
	defer release()
	if t.onEvent != nil {
		t.onEvent(EventInfo, "reality: splicing unauthenticated connection to origin")
	}
	_ = raw.SetDeadline(time.Now().Add(realityProbeTimeout))
	origin, err := net.DialTimeout("tcp", t.probeOrigin, realityHSTimeout)
	if err != nil {
		t.holdAndDrain(raw) // chosen fallback: no instant-close signal
		return
	}
	t.rawSplice(raw, origin, peeked)
}

// rawSplice shuttles bytes between an unauthenticated peer and the impersonated
// origin at the TCP layer: the peeked ClientHello is replayed to the origin, then
// the two connections are spliced so the peer's TLS handshake and everything after
// it happen against the origin. Teardown is aggressive — the first direction to end
// closes both — and the probe deadline the caller set bounds a half-open direction.
// Both connections are closed on return.
func (t *realityTransport) rawSplice(peer, origin net.Conn, peeked []byte) {
	defer peer.Close()
	defer origin.Close()

	_ = origin.SetDeadline(time.Now().Add(realityProbeTimeout))
	if len(peeked) > 0 {
		if _, err := origin.Write(peeked); err != nil {
			return
		}
	}
	// Both directions are metered (issue #163): each leg is a forwarded byte crossing
	// the operator's line twice, so it is counted and paced exactly like the forwarder's
	// meter — but never cut mid-copy, since truncating a probe response is the tell
	// ADR-0027 exists to avoid (see realitySpliceLimits).
	done := make(chan struct{}, 2) // buffered so the losing copy never blocks on exit
	go func() { _, _ = io.Copy(origin, t.splice.meterSplice(peer)); done <- struct{}{} }()
	go func() { _, _ = io.Copy(peer, t.splice.meterSplice(origin)); done <- struct{}{} }()
	<-done
}

// recordingReader wraps a reader and keeps every byte read through it. When a
// connection fails the inner handshake it becomes a probe to reverse-proxy, and
// these captured bytes are the prober's opening request — replayed to the origin
// so the proxied request is not missing the handshake header we already read.
type recordingReader struct {
	r   io.Reader
	buf []byte
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	rr.buf = append(rr.buf, p[:n]...)
	return n, err
}

// reject is the least-information response: log and close. Used when a
// connection cannot be reverse-proxied (TLS never completed) or when an operator
// has explicitly disabled probe-proxying.
func (t *realityTransport) reject(conn net.Conn, reason string) {
	if t.onEvent != nil {
		t.onEvent(EventInfo, "reality: rejected inbound ("+reason+")")
	}
	_ = conn.Close()
}

// onProbe governs a connection that completed the camouflage TLS handshake but
// failed the inner one — a port scan, a censor's active probe, or a stale dial.
// consumed is the prober's already-read opening bytes, replayed to the origin so
// the proxied request stays intact.
//
// Policy (issue #62, ADR-0024 follow-up). "Completes a TLS handshake, then
// instantly closes on unrecognized bytes" is a behaviour an active prober can
// measure — how Russia and China confirm and then kill a circumvention endpoint.
// A real :443 server serves a page instead. So, ON BY DEFAULT (probeOrigin is
// the SNI host on :443 unless overridden), reverse-proxy the connection to that
// origin so the prober sees an ordinary website's response. If the origin cannot
// be reached, hold the connection open and drain it rather than closing, so an
// unreachable origin does not reintroduce the instant-close tell. Only an
// operator who sets the origin to "off" gets the bare immediate close.
func (t *realityTransport) onProbe(tconn *tls.Conn, consumed []byte, reason string) {
	if t.probeOrigin == "" { // explicitly disabled
		t.reject(tconn, reason)
		return
	}
	// Declared-limit admission (issue #163), as in onUnauthenticated: an exhausted
	// quota or a per-IP flood refuses the NEW reverse proxy and drains instead, so the
	// operator's line is not spent amplifying a probe past the cap. In-flight bridges
	// are unaffected (option (c)).
	ok, release := t.splice.admitSplice(tconn.RemoteAddr(), time.Now())
	if !ok {
		t.holdAndDrain(tconn)
		return
	}
	defer release()
	if t.onEvent != nil {
		t.onEvent(EventInfo, "reality: proxying probe to origin ("+reason+")")
	}
	// Bound the whole response so a slow prober cannot pin the goroutine open.
	_ = tconn.SetDeadline(time.Now().Add(realityProbeTimeout))

	origin, err := t.dialProbeOrigin(tconn)
	if err != nil {
		t.holdAndDrain(tconn) // chosen fallback: no instant-close signal
		return
	}
	t.bridge(tconn, origin, consumed)
}

// dialProbeOrigin opens the camouflage-matching connection to the fallback
// origin: TLS to probeOrigin wearing the same SNI and the very ALPN we
// negotiated with the prober, so the relayed conversation speaks one dialect end
// to end. The origin's certificate is not verified — we are borrowing its bytes
// as cover, not trusting it with a secret.
func (t *realityTransport) dialProbeOrigin(tconn *tls.Conn) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), realityHSTimeout)
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", t.probeOrigin)
	if err != nil {
		return nil, err
	}
	protos := []string{"h2", "http/1.1"}
	if alpn := tconn.ConnectionState().NegotiatedProtocol; alpn != "" {
		protos = []string{alpn}
	}
	oc := tls.Client(raw, &tls.Config{
		ServerName:         t.sni,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         protos,
		InsecureSkipVerify: true, // borrowing bytes for cover, not trusting identity
	})
	if err := oc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return oc, nil
}

// bridge reverse-proxies the probe: replay the prober's already-read opening
// bytes to the origin, then splice the two plaintext streams so the prober
// receives the origin's genuine response. Teardown is aggressive — the moment
// either direction ends (the origin served its page and closed, or the prober
// hung up) both sides close; the probe deadline the caller set bounds a
// half-open direction. Both connections are closed on return.
func (t *realityTransport) bridge(prober *tls.Conn, origin net.Conn, consumed []byte) {
	defer prober.Close()
	defer origin.Close()

	_ = origin.SetDeadline(time.Now().Add(realityProbeTimeout))
	if len(consumed) > 0 {
		if _, err := origin.Write(consumed); err != nil {
			return
		}
	}
	// Metered like rawSplice (issue #163): both legs count and pace, neither cuts.
	done := make(chan struct{}, 2) // buffered so the losing copy never blocks on exit
	go func() { _, _ = io.Copy(origin, t.splice.meterSplice(prober)); done <- struct{}{} }()
	go func() { _, _ = io.Copy(prober, t.splice.meterSplice(origin)); done <- struct{}{} }()
	<-done
}

// holdAndDrain keeps a probe connection open and discards whatever the prober
// sends, up to the probe deadline the caller set, instead of closing. An
// unreachable origin would otherwise force the instant-close tell; draining
// denies the prober that timing signal, and the bounded deadline caps the
// resource a flood of probes can tie up.
func (t *realityTransport) holdAndDrain(conn net.Conn) {
	defer conn.Close()
	// Count the drained inbound bytes against the quota — once; they only arrive
	// (issue #163). This is what makes "every reality byte is accounted" literally
	// true, not just "every reverse-proxied one". It does not pace: a drain emits
	// nothing to shape. countDrain is nil-inert for an unmetered node.
	_, _ = io.Copy(io.Discard, t.splice.countDrain(conn))
}

// dialInner opens one connection for label: TCP dial, the authenticated Reality
// ClientHello handshake, then the inner handshake carrying the session token and
// label. The outer TLS certificate is deliberately not verified — it is camouflage,
// and the session's authentication is the ClientHello authenticator plus the token
// (delivered over the coordinator-authenticated signaling channel) plus the Noise
// end-to-end handshake above this transport (ADR-0009, ADR-0032).
func (t *realityTransport) dialInner(ctx context.Context, ans realityAnswer, label string) (net.Conn, error) {
	tok, err := hex.DecodeString(ans.Token)
	if err != nil || len(tok) != realityTokenLen {
		return nil, errors.New("core: reality answer carries a malformed token")
	}
	if ans.Addr == "" {
		return nil, errors.New("core: reality answer carries no dial address")
	}
	exitPub, err := hex.DecodeString(ans.Pub)
	if err != nil || len(exitPub) != 32 {
		return nil, errors.New("core: reality answer carries no exit key")
	}

	// Hand the caller the underlay's address before opening the connection to it
	// (issue #109). A full-device tunnel excludes ans.Addr from its own default
	// route — and, under the kill-switch, allow-lists it — inside this call, so
	// the connection below rides the physical interface instead of looping into
	// the tunnel it is establishing. This is the one moment reality's address is
	// known but no connection to it yet exists; doing it here (not after the
	// session commits) is what keeps a mid-session failover's re-dial from racing
	// the route flip. Synchronous by contract: the handler returns only once the
	// address is tunnel-safe.
	if t.onUnderlayDial != nil {
		t.onUnderlayDial(ans.Addr)
	}

	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", ans.Addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	} else {
		_ = raw.SetDeadline(time.Now().Add(realityHSTimeout))
	}

	sni := ans.SNI
	if sni == "" {
		sni = t.sni
	}
	tconn, err := realityClientHandshake(ctx, raw, sni, exitPub)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := writeInnerHandshake(tconn, tok, label); err != nil {
		_ = tconn.Close()
		return nil, err
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(tconn, ack); err != nil || ack[0] != realityAckOK {
		_ = tconn.Close()
		return nil, errors.New("core: reality handshake rejected by exit")
	}
	_ = raw.SetDeadline(time.Time{}) // clear for steady state
	return tconn, nil
}

// realityClientHandshake performs the outer TLS handshake as an authenticated
// Reality client (ADR-0032): a Chrome-fidelity uTLS ClientHello whose
// legacy_session_id is the sealed authenticator only the exit's static key can open,
// bound to this hello's random and X25519 key share. The exit reads that
// authenticator before it terminates TLS and, seeing it valid, handles the
// connection itself instead of splicing it to the impersonated origin — presenting
// the impersonated origin's real certificate chain, byte-for-byte, but signed with
// its own key rather than the origin's (issue #92; it does not hold that key).
//
// InsecureSkipCertVerifySignature (third_party/utls/PATCHES.md) is what lets this
// specific handshake complete despite that: it tolerates a CertificateVerify
// signature that fails to validate under the presented leaf's public key, which is
// exactly what borrowing a certificate without its private key produces. This is
// the ONLY call site in the codebase that may set it — trust for this transport
// comes from the Noise end-to-end handshake (ADR-0009) and the ClientHello-embedded
// authenticator above, not from the outer TLS layer, so the outer chain and its
// signature were never load-bearing here. Do not copy this flag onto any other TLS
// config; doing so would turn a narrowly-justified protocol tolerance into a
// general TLS downgrade.
func realityClientHandshake(ctx context.Context, raw net.Conn, sni string, exitPub []byte) (*utls.UConn, error) {
	u := utls.UClient(raw, &utls.Config{
		ServerName:                      sni,
		InsecureSkipVerify:              true,
		InsecureSkipCertVerifySignature: true, // see func doc: scoped to this one handshake
	}, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	ks := u.HandshakeState.State13.KeyShareKeys
	if ks == nil || ks.Ecdhe == nil {
		return nil, errors.New("core: reality clienthello has no x25519 key share")
	}
	secret, err := realityClientSecret(ks.Ecdhe, exitPub)
	if err != nil {
		return nil, err
	}
	sid, err := realitySealSessionID(secret, u.HandshakeState.Hello.Random, time.Now())
	if err != nil {
		return nil, err
	}
	// Swap the random legacy_session_id uTLS produced for our sealed one, then
	// re-marshal so the wire ClientHello carries it, and complete the handshake.
	u.HandshakeState.Hello.SessionId = sid
	if err := u.MarshalClientHello(); err != nil {
		return nil, err
	}
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// forget drops a session's token so no further connection can attach to it.
func (t *realityTransport) forget(token string) {
	t.mu.Lock()
	delete(t.pending, token)
	t.mu.Unlock()
}

// close stops the shared listener, blocks new registrations, and waits for every
// background goroutine the transport spawned to actually exit (issue #65) — so a
// caller that has returned from close knows the transport is fully quiescent, not
// just that its listener is down. It does not tear down live sessions — the engine
// closes those, and their own watchControl goroutine is joined by Session.Close.
//
// The wg.Wait below is the one latency #98 flagged as worth surfacing: every
// goroutine it joins is already bounded (listener close, realityHSTimeout, or
// realityProbeTimeout — see the wg doc comment), but a serveInbound goroutine mid
// probe response (onProbe/holdAndDrain) can hold it for up to realityProbeTimeout,
// so Engine.Stop calling this can stall that long draining one stuck prober. There
// is no cheap way to bound it further without truncating a probe response
// mid-flight — reintroducing the instant-close tell #62 exists to avoid — so
// reportDrain turns the wait into an observable duration instead of a silent pause.
func (t *realityTransport) close() error {
	t.mu.Lock()
	t.closed = true
	ln := t.ln
	t.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	start := time.Now()
	t.wg.Wait()
	t.reportDrain(time.Since(start))
	return err
}

// reportDrain surfaces how long close's wg.Wait() actually blocked (issue #98), via
// the same onEvent channel every other notable transport occurrence already uses.
func (t *realityTransport) reportDrain(d time.Duration) {
	if t.onEvent != nil {
		t.onEvent(EventInfo, fmt.Sprintf("reality: transport stop drained background goroutines in %s", d))
	}
}

// --- session ---------------------------------------------------------------

// realitySession is a set of TLS connections to one peer behind the Session
// interface. On the initiator it holds a dialer to open more; on the responder
// it receives connections the listener routes to it by token.
type realitySession struct {
	onEvent func(kind, msg string)
	ctx     context.Context
	cancel  context.CancelFunc

	transport *realityTransport // responder side, for forget on close
	token     string            // hex; responder side
	dialer    func(ctx context.Context, label string) (net.Conn, error)

	accept chan Stream
	closed chan struct{}
	once   sync.Once

	// wg tracks the session's own background goroutines (watchControl), so Close
	// can Wait() for them (issue #65) instead of leaving them to exit on their own
	// time after Close has already returned.
	wg sync.WaitGroup

	mu       sync.Mutex
	isClosed bool
	conns    map[net.Conn]struct{} // every live conn, closed on teardown
}

func newRealitySession(onEvent func(kind, msg string)) *realitySession {
	ctx, cancel := context.WithCancel(context.Background())
	return &realitySession{
		onEvent: onEvent,
		ctx:     ctx,
		cancel:  cancel,
		accept:  make(chan Stream, 8),
		closed:  make(chan struct{}),
		conns:   map[net.Conn]struct{}{},
	}
}

// useControl adopts conn as the session's control channel: it carries no data,
// and its closure (peer gone or transport failure) tears the session down. A conn
// arriving for an already-closed session is simply closed by track — no goroutine
// is spawned that Close would then have no chance to join (issue #65).
func (s *realitySession) useControl(conn net.Conn) {
	// The s.wg.Add(1) must sit under s.mu, atomically with the tracked-conn
	// insert, so it is serialized against closeAndTeardown's isClosed flip.
	// Adding after track() had released the lock let it race Close's
	// s.wg.Wait(): once any control goroutine is live the counter is >0, so a
	// concurrent teardown's Wait() is already blocking when a second control
	// conn's Add lands — a WaitGroup-reuse panic, and a peer-triggerable one
	// (the peer opens the control channel). Under the lock, either we observe
	// isClosed and never Add, or the Add happens-before teardown, hence Wait.
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		s.watchControl(conn)
	}()
}

// watchControl calls closeAndTeardown, not Close: it runs on a goroutine Close
// itself waits for (s.wg), so calling back into Close would deadlock — a second
// once.Do caller blocks until the first's function returns, which here would be
// waiting on this very goroutine to finish. closeAndTeardown is the same teardown
// without that wait, safe to call from any goroutine including this one.
func (s *realitySession) watchControl(conn net.Conn) {
	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			s.closeAndTeardown()
			return
		}
		// The control channel is not supposed to carry bytes; ignore any and
		// keep waiting for the connection to end.
	}
}

// attach routes an inbound connection (responder side) to the session: the
// control connection drives liveness, every other connection is a stream.
func (s *realitySession) attach(label string, conn net.Conn) {
	if label == ctrlLabel {
		s.useControl(conn)
		return
	}
	s.track(conn)
	select {
	case s.accept <- &realityStream{Conn: conn, label: label}:
	case <-s.closed:
		_ = conn.Close()
	}
}

// track adds c to the session's live-connection set, or closes it immediately if
// the session has already torn down. Reports whether c was tracked.
func (s *realitySession) track(c net.Conn) bool {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	return true
}

// bindToken records the pending-map token on the session so Close unregisters
// it. It reports false if the session has already closed, in which case the
// caller must forget the token itself — Close is past the point where it reads
// it. token is only ever touched under s.mu, so it never races Close.
func (s *realitySession) bindToken(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return false
	}
	s.token = tok
	return true
}

func (s *realitySession) OpenStream(ctx context.Context, label string) (Stream, error) {
	select {
	case <-s.closed:
		return nil, errSessionClosed
	default:
	}
	if s.dialer == nil {
		return nil, errors.New("core: reality responder session cannot open streams")
	}
	conn, err := s.dialer(ctx, label)
	if err != nil {
		return nil, err
	}
	s.track(conn)
	return &realityStream{Conn: conn, label: label}, nil
}

func (s *realitySession) AcceptStream(ctx context.Context) (Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.closed:
		return nil, errSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *realitySession) Closed() <-chan struct{} { return s.closed }

// Close tears the session down and blocks until its own background goroutines
// (watchControl) have actually exited (issue #65) — not merely triggered.
//
// The teardown itself is split out into closeAndTeardown so that watchControl,
// which runs on a goroutine this method waits for, can trigger it without calling
// back into Close: a second, concurrent once.Do caller blocks until the first
// caller's function returns, so if watchControl called Close directly, its own
// Wait would be waiting on watchControl to finish while watchControl waited on
// that same once.Do to unblock — a self-deadlock.
func (s *realitySession) Close() error {
	s.closeAndTeardown()
	start := time.Now()
	s.wg.Wait()
	s.reportDrain(time.Since(start))
	return nil
}

// reportDrain surfaces how long Close's wg.Wait() actually blocked joining
// watchControl, the control-conn goroutine (issue #98). Ordinarily near-instant —
// closeAndTeardown already closed the tracked conns, so watchControl's blocking
// Read unblocks right away — but that is an assumption about the underlying
// net.Conn's Close/Read interaction, not a guarantee, so it is worth surfacing
// rather than leaving a caller to wonder whether Close briefly hung.
func (s *realitySession) reportDrain(d time.Duration) {
	if s.onEvent != nil {
		s.onEvent(EventInfo, fmt.Sprintf("reality: session close drained control-conn goroutine in %s", d))
	}
}

// closeAndTeardown runs the actual teardown exactly once (cancel, close tracked
// conns, forget the responder-side token) but never waits on s.wg, so it is safe
// to call from any goroutine — including one s.wg is tracking.
func (s *realitySession) closeAndTeardown() {
	s.once.Do(func() {
		s.cancel()
		close(s.closed)
		s.mu.Lock()
		s.isClosed = true
		conns := s.conns
		s.conns = nil
		token := s.token // read under s.mu; answer sets it the same way
		s.mu.Unlock()
		for c := range conns {
			_ = c.Close()
		}
		if s.transport != nil && token != "" {
			s.transport.forget(token)
		}
	})
}

// realityStream is one TLS connection tagged with the label its opener supplied.
// A *tls.Conn already satisfies io.ReadWriteCloser; the embedding also exposes
// the TLS state, which tests use to confirm the outer handshake looks like HTTPS.
type realityStream struct {
	net.Conn
	label string
}

func (s *realityStream) Label() string { return s.label }

// --- wire helpers ----------------------------------------------------------

// writeInnerHandshake sends magic ‖ token ‖ uint16(len(label)) ‖ label. It rides
// inside the established TLS session, so it is confidential on the wire.
func writeInnerHandshake(w io.Writer, token []byte, label string) error {
	if len(label) > 0xffff {
		return errors.New("core: reality stream label too long")
	}
	buf := make([]byte, 0, len(realityMagic)+len(token)+2+len(label))
	buf = append(buf, realityMagic...)
	buf = append(buf, token...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(label)))
	buf = append(buf, l[:]...)
	buf = append(buf, label...)
	_, err := w.Write(buf)
	return err
}

// readInnerHandshake reads the frame writeInnerHandshake wrote, returning the
// token as hex (the pending-map key) and the label.
func readInnerHandshake(r io.Reader) (token, label string, err error) {
	const fixed = len(realityMagic) + realityTokenLen + 2
	hdr := make([]byte, fixed)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return "", "", err
	}
	if string(hdr[:len(realityMagic)]) != realityMagic {
		return "", "", errors.New("core: bad reality magic")
	}
	tok := hdr[len(realityMagic) : len(realityMagic)+realityTokenLen]
	llen := binary.BigEndian.Uint16(hdr[len(realityMagic)+realityTokenLen:])
	lb := make([]byte, llen)
	if _, err = io.ReadFull(r, lb); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(tok), string(lb), nil
}

func newToken() []byte {
	b := make([]byte, realityTokenLen)
	_, _ = rand.Read(b)
	return b
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// sendFrames sends a frame a few times, since coordinator signaling rides
// best-effort UDP (mirrors the WebRTC path's sendSDP).
func sendFrames(ctx context.Context, sig Signaler, kind string, data json.RawMessage, times int) error {
	for i := 0; i < times; i++ {
		if err := sig.Send(ctx, SignalFrame{Kind: kind, Data: data}); err != nil {
			return err
		}
		if i < times-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return nil
}

// awaitKind returns the next frame of the given kind, skipping retransmits and
// unrelated kinds, until ctx is done or the session tears down.
func awaitKind(ctx context.Context, sig Signaler, kind string) (SignalFrame, error) {
	for {
		f, err := sig.Recv(ctx)
		if err != nil {
			return SignalFrame{}, err
		}
		if f.Kind == kind {
			return f, nil
		}
	}
}

func awaitAnswer(ctx context.Context, sig Signaler) (realityAnswer, error) {
	f, err := awaitKind(ctx, sig, sigAnswer)
	if err != nil {
		return realityAnswer{}, err
	}
	var ans realityAnswer
	if err := json.Unmarshal(f.Data, &ans); err != nil {
		return realityAnswer{}, errors.New("core: malformed reality answer")
	}
	return ans, nil
}

// realityServerTLS builds the exit's fallback terminate-path config: a self-signed
// leaf for sni, advertising HTTP ALPN so the session reads as ordinary web traffic.
// It is presented only to authenticated clients (who do not verify it, ADR-0009) and
// to passive observers of those flows until the origin's real chain is warmed
// (realityMimicTLS). A prober never sees it: unauthenticated peers are spliced to the
// real origin (ADR-0032).
func realityServerTLS(sni string) (*tls.Config, error) {
	return realityMintTLS(pkix.Name{CommonName: sni}, []string{sni},
		time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
}

// realityMimicTLS borrows the impersonated origin's certificate chain byte-for-byte
// (issue #92) and wraps it in a terminate-path config signed by a fresh key of ours.
// A passive observer that fully validates the chain up to a public CA now sees the
// same publicly-chaining bytes the origin itself serves, on our own authenticated
// flows and not only the spliced unauthenticated ones ADR-0032 already covered.
//
// The exit does not hold the origin's private key, so it cannot produce a
// CertificateVerify signature that validates under this chain's leaf public key —
// only our own client dials this transport, and it is told to tolerate that one
// signature check failing (InsecureSkipCertVerifySignature, third_party/utls),
// never to skip validating the chain itself. See docs/adr/0032 for why that
// narrow, opt-in tolerance is safe here: trust for this transport already comes
// from the Noise end-to-end handshake (ADR-0009) and the ClientHello-embedded ECDH
// authenticator (ADR-0032), not from the outer TLS layer.
//
// The fresh key's class — RSA bit length, or EC curve — matches the borrowed leaf's
// own public key (realityMatchingSigner), rather than always a fixed P-256 ECDSA key
// regardless of the origin (issue #98): Go's TLS stack picks the CertificateVerify
// signature scheme from the *signing* key's type, not the leaf's, so a class mismatch
// (an RSA leaf signed as if it were ECDSA-P256) is an internally-inconsistent tell to
// anything that can inspect that message. Nobody can under ordinary TLS 1.3 — it is
// encrypted (RFC 8446 §4.4, the framing #94's review settled on — see ADR-0032) — but
// a forced TLS 1.2 downgrade or a credentialed insider could, and matching the class
// costs nothing.
func realityMimicTLS(dest, sni string) (*tls.Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), realityHSTimeout)
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, err
	}
	oc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := oc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	certs := oc.ConnectionState().PeerCertificates
	_ = oc.Close()
	if len(certs) == 0 {
		return nil, errors.New("core: impersonated origin presented no certificate")
	}

	// The origin's exact DER bytes, leaf first then any intermediates, exactly as
	// x509.Certificate.Raw preserved them off the wire — nothing here is re-derived
	// or re-encoded, so the chain still validates up to the origin's real root.
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	// A fresh key of ours signs CertificateVerify; it cannot match the stolen leaf's
	// embedded public key (see the func doc above), but it is minted in that key's
	// own class so the signature scheme TLS negotiates for it is at least the one a
	// genuine certificate of this leaf's type would use (issue #98).
	signer, err := realityMatchingSigner(certs[0].PublicKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: signer, Leaf: certs[0]}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// realityMatchingSigner mints a fresh private key in the same class as pub — the
// same RSA bit length, or the same EC curve (restricted to curves Chrome's mimicked
// ClientHello actually offers, see below), or Ed25519 — so the CertificateVerify
// signature scheme Go's TLS stack negotiates for a borrowed leaf (issue #92) is the
// one a genuine certificate of that leaf's type would use, not always the P-256
// ECDSA signature scheme a fixed signer key would force regardless of the leaf
// (issue #98). Go picks the scheme from the signing key's own type
// (signatureSchemesForCertificate inspects cert.PrivateKey, never cert.Leaf), so a
// mismatched class is what would make the borrowed chain internally inconsistent —
// this closes that narrower tell without needing, or being able to get, the
// origin's actual private key.
//
// The ECDSA branch mints only on elliptic.P256() or elliptic.P384(): the two curves
// utls.HelloChrome_Auto's supported_signature_algorithms extension actually offers
// a scheme for (ecdsa_secp256r1_sha256 / ecdsa_secp384r1_sha384). Minting
// unconditionally on the origin leaf's own curve (pre-#104) let a P-521 leaf mint a
// P-521 signer successfully — TLS 1.3 requires the CertificateVerify scheme to name
// the signer's exact curve (RFC 8446 §4.2.3), and Chrome's ClientHello never offers
// ecdsa_secp521r1_sha512, so the terminate handshake then failed with no
// mutually-supported scheme, well past the point where warmMimicCert's fallback
// could catch it. Any curve outside that pair now errors here instead, the same as
// any other unmintable key class below (issue #104).
//
// Ed25519 is the same case as P-521, one key class over: an Ed25519 leaf mints an
// Ed25519 signer fine, but Chrome's ClientHello offers no ed25519 scheme (0x0807),
// so it too errors here rather than handing back a signer the terminate handshake
// cannot use. RSA is unaffected — Chrome offers rsa_pss_rsae_* schemes for it.
//
// An origin whose leaf uses a key class or curve this cannot mint a
// Chrome-compatible match for errors rather than guessing a mismatched substitute;
// the caller (warmMimicCert) already falls back to the self-signed terminate-path
// config (itself a P-256 ECDSA leaf, realityMintTLS) on any realityMimicTLS error,
// so this stays a narrowing, not a new failure mode.
func realityMatchingSigner(pub crypto.PublicKey) (crypto.Signer, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256(), elliptic.P384():
			return ecdsa.GenerateKey(p.Curve, rand.Reader)
		default:
			return nil, fmt.Errorf("core: origin leaf ECDSA curve %s has no signature scheme in the mimicked Chrome ClientHello", p.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return rsa.GenerateKey(rand.Reader, p.N.BitLen())
	case ed25519.PublicKey:
		// Chrome's mimicked ClientHello offers no Ed25519 signature scheme (0x0807
		// absent from HelloChrome_133's supported_signature_algorithms), so minting an
		// Ed25519 signer here repeats the P-521 failure the ECDSA branch guards
		// against: the mint succeeds but the terminate handshake then has no
		// mutually-supported CertificateVerify scheme and fails past warmMimicCert's
		// fallback. Error so the caller falls back to the self-signed P-256 config,
		// whose scheme Chrome does offer (issue #104).
		return nil, errors.New("core: origin leaf Ed25519 has no signature scheme in the mimicked Chrome ClientHello")
	default:
		return nil, fmt.Errorf("core: origin leaf key type %T has no matching signer", pub)
	}
}

// realityMintTLS mints a self-signed P-256 leaf with the given identity fields and
// wraps it in a server config advertising HTTP ALPN.
func realityMintTLS(subject pkix.Name, dnsNames []string, notBefore, notAfter time.Time) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
