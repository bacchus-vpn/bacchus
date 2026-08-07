package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/rendezvous"
)

// This file drives issue #121's first item: the cmd/node supervisor glue in
// runNode that consumes Engine.NeedsRecovery -> reads RecoveredDirectory ->
// Stop()s the old engine -> rebuilds against rediscovered coordinators
// (courier.go, the <-eng.NeedsRecovery() branch) had no direct test. The
// engine-side contract is well covered in core/ (core/meshwalk_midsession_test.go),
// but that coverage stops at NeedsRecovery firing — nothing exercised what
// runNode does with it. NeedsRecovery is never touched directly here: the test
// drives the real conditions (a genuinely silent coordinator, a genuinely
// dropped session, a real courier) that make the engine close it itself, so the
// handoff runNode performs is pinned for real, per issue #105's lesson that a
// stubbed signal would not have caught the double-connect/strand class of bug.
//
// cmd/node has no access to core's unexported test seams (fakeTransport,
// eng.establishFn, etc. — those are core-package white-box tools), so this
// necessarily runs a real WebRTC handshake against a real coldstart courier
// through a minimal, wire-compatible fake coordinator (rvWire/fakeRendezvous
// below) — the same black-box-fake-server pattern core's own tests use
// (core/reconnect_smoke_test.go's fakeConnectCoordinator), just extended to
// relay real offer/answer/candidate signaling since there is no fake-transport
// seam to skip that here. cmd/coordinator is not imported (it's a package
// main, not importable, and out of scope this wave regardless) or modified.

// rvWire mirrors the subset of core's private wire protocol this fake
// coordinator needs to speak: registration, connect/session/assign pairing,
// and signal relay. JSON field names must match core/engine.go's wire exactly;
// any field not listed here is simply dropped on decode and never sent.
type rvWire struct {
	Type    string `json:"type"`
	Role    string `json:"role,omitempty"`
	ID      string `json:"id,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Session string `json:"session,omitempty"`
	// Country is what a CONNECT names (issue #146, ADR-0042). A client no longer
	// names an exit; it names a place, and the coordinator picks inside it.
	Country string `json:"country,omitempty"`
	// ExitID travels the other way: it is the coordinator's ANSWER on the session
	// reply, naming the exit it chose. It is load-bearing rather than informational —
	// an exit's id IS its Noise static public key (ADR-0009), so a client that does
	// not receive it cannot bring up the end-to-end channel at all, and core refuses a
	// mint that omits it.
	ExitID string          `json:"exitId,omitempty"`
	Cand   json.RawMessage `json:"cand,omitempty"`
}

// fakeRendezvous is a minimal, wire-compatible stand-in for cmd/coordinator's
// UDP rendezvous protocol — real loopback UDP, real session mint, real
// offer/answer/candidate relay, so a genuine WebRTC handshake completes between
// a real client and real exit core.Engine. It serves exactly one client<->exit
// pairing for its lifetime: repeated "connect" sends (core's attemptWith
// retries 3x to ride out UDP loss) are deduped to a single mint so the exit is
// never handed a second "assign" for a session the client will never dial —
// which would otherwise leave a stray transport Accept() blocked until its own
// internal handshake timeout, stalling this coordinator's one read loop.
// silence, once set, drops every datagram — the all-coordinators-unreachable
// condition mesh-walk recovery keys on (core/client.go's ErrNoCoordinatorReachable).
type fakeRendezvous struct {
	pc *net.UDPConn
	// peer terminates the shaped rendezvous hop (issue #175 slice 2, ADR-0062). A
	// client speaks an ICE connectivity check and then DTLS with no cleartext
	// fallback, so a socket that only answers JSON no longer stands in for a
	// coordinator. Cleartext passes through unchanged, which is what keeps the
	// exit-role engine in this test — whose links are not shaped — served by the
	// same object.
	peer *rendezvous.Peer

	mu         sync.Mutex
	silent     bool
	exitAddr   *net.UDPAddr
	exitID     string // learned from the exit's register; sent back on every session mint
	clientAddr *net.UDPAddr
	sid        string
}

func newFakeRendezvous(t *testing.T, label string) *fakeRendezvous {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen fake coordinator %s: %v", label, err)
	}
	peer, err := rendezvous.Serve(pc)
	if err != nil {
		t.Fatalf("fake coordinator %s: rendezvous.Serve: %v", label, err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	c := &fakeRendezvous{pc: pc, peer: peer, sid: label + "-session"}
	go c.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return c
}

func (c *fakeRendezvous) addr() string { return c.pc.LocalAddr().String() }

// setSilent, once true, makes this coordinator drop every datagram — a client
// dialing it sees exactly what it sees from a censor-blocked coordinator.
func (c *fakeRendezvous) setSilent(v bool) {
	c.mu.Lock()
	c.silent = v
	c.mu.Unlock()
}

func (c *fakeRendezvous) hasExit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitAddr != nil
}

// registeredExit is the exit id this coordinator learned from the exit's own register
// and hands back on every session mint — the value the client keys its end-to-end
// handshake on (issue #146).
func (c *fakeRendezvous) registeredExit() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitID
}

func (c *fakeRendezvous) serve() {
	for {
		raw, src, err := c.peer.ReadFrom()
		if err != nil {
			return // closed by test cleanup
		}
		c.mu.Lock()
		silent := c.silent
		c.mu.Unlock()
		if silent {
			continue
		}
		var m rvWire
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		c.handle(m, src)
	}
}

func (c *fakeRendezvous) send(addr *net.UDPAddr, m rvWire) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	_, _ = c.peer.WriteTo(b, addr)
}

func (c *fakeRendezvous) handle(m rvWire, src *net.UDPAddr) {
	switch m.Type {
	case "register":
		if m.Role == "exit" {
			c.mu.Lock()
			c.exitAddr = src
			c.exitID = m.ID
			c.mu.Unlock()
		}
	case "connect":
		c.mu.Lock()
		exit, exitID := c.exitAddr, c.exitID
		firstMint := c.clientAddr == nil
		if firstMint {
			c.clientAddr = src
		}
		sid := c.sid
		c.mu.Unlock()
		if exit == nil || m.Country == "" {
			// A connect that names no country is refused, exactly as the real
			// coordinator refuses it (refuseNoCountry) — so this fake cannot quietly
			// accept a request shape no coordinator would.
			c.send(src, rvWire{Type: "error"})
			return
		}
		if firstMint {
			// No ExitAddr => direct egress, mirroring cmd/coordinator's mode:"direct"
			// assign shape exactly (core/forwarder.go's handlerFor keys on that).
			c.send(exit, rvWire{Type: "assign", Session: sid})
		}
		c.send(src, rvWire{Type: "session", Session: sid, ExitID: exitID})
	case "offer", "answer", "candidate":
		c.mu.Lock()
		sid, client, exit := c.sid, c.clientAddr, c.exitAddr
		c.mu.Unlock()
		if sid == "" || m.Session != sid || client == nil || exit == nil {
			return
		}
		other := exit
		if src.String() == exit.String() {
			other = client
		}
		c.send(other, m)
	}
}

// startTestCourier runs a bare coldstart.ServeCourier over loopback UDP primed
// with cache. Mesh-walk recovery (core.Engine.MeshWalk) fetches from it
// directly — no coordinator round trip is needed to populate the cache, since
// the test controls its contents up front.
func startTestCourier(t *testing.T, pub ed25519.PublicKey, cache *coldstart.SnapshotCache) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test courier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = coldstart.ServeCourier(ctx, pc, pub, cache); close(done) }()
	t.Cleanup(func() {
		cancel()
		_ = pc.Close()
		<-done
	})
	return pc.LocalAddr().String()
}

// startEchoServer binds a loopback TCP listener that echoes back whatever it
// reads on each connection — the "destination" the exit dials on a SOCKS
// CONNECT, so the test can prove real bytes cross the rebuilt tunnel, not
// merely that Connect returned nil.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
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

// socksEchoRoundTrip drives one real SOCKS5 CONNECT through socksAddr to
// target, writes payload, and returns the echoed bytes — proving the tunnel is
// genuinely usable end to end (real transport handshake, real E2E Noise
// handshake, real exit egress), not merely that some internal call returned no
// error.
func socksEchoRoundTrip(socksAddr, target string, payload []byte) ([]byte, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial socks: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := c.Write([]byte{5, 1, 0}); err != nil { // VER 5, 1 method, no-auth
		return nil, fmt.Errorf("write greeting: %w", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return nil, fmt.Errorf("read greeting reply: %w", err)
	}
	if greet[0] != 5 || greet[1] != 0 {
		return nil, fmt.Errorf("socks greeting rejected: %v", greet)
	}

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
	req := []byte{5, 1, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		return nil, fmt.Errorf("write connect: %w", err)
	}
	connReply := make([]byte, 10)
	if _, err := io.ReadFull(c, connReply); err != nil {
		return nil, fmt.Errorf("read connect reply: %w", err)
	}
	if connReply[1] != 0 {
		return nil, fmt.Errorf("socks connect failed, rep=%d", connReply[1])
	}

	if _, err := c.Write(payload); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return nil, fmt.Errorf("read echo: %w", err)
	}
	return got, nil
}

func randomExitKeyHex(t *testing.T) string {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	return hex.EncodeToString(seed)
}

// startTestExit brings up a real exit core.Engine registered with coords.
// exitKeyHex fixes its identity (the exit id is its static public key), so two
// separate startTestExit calls sharing the same hex are the SAME exit as far
// as a client's Config.ExitID is concerned — used to hand the rebuild a fresh
// process standing in for the same node reappearing on a different
// coordinator, without carrying the original (now-dead) instance across it.
func startTestExit(t *testing.T, ctx context.Context, exitKeyHex string, coords []string) *core.Engine {
	t.Helper()
	eng, err := core.New(core.Config{
		Roles:        []string{core.RoleExit},
		Coordinators: coords,
		ExitKeyHex:   exitKeyHex,
		Advertise:    "127.0.0.1:1", // relay-splice egress only; unused by direct-mode WebRTC
		ListenAddr:   "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start exit: %v", err)
	}
	t.Cleanup(eng.Stop) // idempotent; a no-op if the test already stopped it
	return eng
}

func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

// waitUntilNoErr retries attempt until it succeeds or timeout elapses,
// returning the last error for a caller that wants to report it.
func waitUntilNoErr(timeout time.Duration, attempt func() error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := attempt(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("timed out before the first attempt")
	}
	return lastErr
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestRunNode_MidSessionMeshWalkRecoversToCleanSocksRebind is issue #121's
// first item: runNode's <-eng.NeedsRecovery() branch — Stop the dead engine,
// read RecoveredDirectory, rebuild core.New against the rediscovered
// coordinators, reconnect — was exercised nowhere. This drives it for real.
//
// Sequence: a real client core.Engine connects through a real (fake but
// wire-compatible) coordinator to a real exit engine over real WebRTC, proven
// by an actual SOCKS5 CONNECT + echo round trip. The coordinator then goes
// silent and the exit dies, forcing a genuine session drop; the engine's own
// reconnect loop retries until its own mesh-walk (core/client.go's
// tryMeshRecovery) recovers a fresh directory from a real courier and closes
// NeedsRecovery. runNode's supervisor loop must then Stop the dead engine,
// rebuild against the rediscovered coordinator, and reconnect through a fresh
// exit instance sharing the dead one's identity — proven by a second real
// SOCKS5 CONNECT + echo round trip succeeding on the SAME cfg.SocksAddr (the
// "clean rebind": no leftover listener, no port-in-use failure, no strand).
//
// Slow and gated behind -short: it rides core's real, fixed, unexported
// reconnect/mesh-walk timeouts (directTimeout/relayTimeout/meshRecoveryAfter),
// which cmd/node has no seam to shorten from outside the core package — three
// consecutive all-silent passes at up to ~30s each before mesh-walk even
// engages, atop real ICE failure detection and two real WebRTC handshakes.
// core's own real-WebRTC tests (core/dtls_fingerprint_test.go) are skipped the
// same way for the same reason.
//
// This does run automated, on every change that touches it (issue #131):
// .github/workflows/ci.yml's "server" job invokes plain `go test ./core/...
// ./bind/... ./cmd/...` with no -short, so testing.Short() above is false in
// CI and this test executes for real there — confirmed against the run that
// introduced this file (2026-07-11, "chore(rendezvous): mesh-walk mid-session
// recovery follow-ups"), whose `go test` step logged
// "ok  	github.com/bacchus-vpn/bacchus/cmd/node	93.926s" (not "(cached)"),
// matching the ~94s floor above almost exactly. Runs after that show
// "(cached)" instead whenever nothing this test depends on changed — Go's
// ordinary test-result caching, not the test being skipped; touching this
// file, runNode, or anything in core/ it exercises invalidates that cache and
// forces a fresh, real run. See ci.yml's own comment on that step before ever
// adding -short there.
func TestRunNode_MidSessionMeshWalkRecoversToCleanSocksRebind(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real mid-session mesh-walk recovery in -short")
	}

	exitKeyHex := randomExitKeyHex(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	coord1 := newFakeRendezvous(t, "coord1")
	coord2 := newFakeRendezvous(t, "coord2")
	echoAddr := startEchoServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// exit1 serves the initial connect through coord1.
	exit1 := startTestExit(t, ctx, exitKeyHex, []string{coord1.addr()})
	exitID := exit1.ID()
	if !waitUntil(20*time.Second, coord1.hasExit) {
		t.Fatal("exit1 never registered with coord1")
	}

	// The courier serves a fresh directory naming coord2 — what the client must
	// recover to. proof is a stale snapshot naming coord1, standing in for a
	// cached snapshot carried over from a genuine prior session.
	cache := coldstart.NewSnapshotCache()
	cache.Store(signedTestSnapshot(t, priv, coord2.addr()))
	courierAddr := startTestCourier(t, pub, cache)
	proof := signedTestSnapshot(t, priv, coord1.addr())

	socksAddr := freeTCPAddr(t)
	cfg := core.Config{
		Roles:     []string{core.RoleClient},
		SocksAddr: socksAddr,
		// A client names a COUNTRY (issue #146); the coordinator picks the exit and
		// tells the client which it got. exitID below is the exit's own identity,
		// asserted against what the client is handed — not something it asks for.
		Geo: "NL",
	}
	mesh := &meshRecovery{peers: []string{courierAddr}, proof: proof, pubkey: pub}

	errCh := make(chan error, 1)
	go func() { errCh <- runNode(ctx, cfg, []string{coord1.addr()}, mesh) }()

	const payload1 = "hello-before-recovery"
	if err := waitUntilNoErr(90*time.Second, func() error {
		got, err := socksEchoRoundTrip(socksAddr, echoAddr, []byte(payload1))
		if err != nil {
			return err
		}
		if string(got) != payload1 {
			return fmt.Errorf("echo mismatch: got %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("initial connect never came up over a real SOCKS5 round trip: %v", err)
	}
	// The SOCKS round trip above only completes if the client ran its end-to-end Noise
	// handshake against the right static key, and the only place it could have learned
	// that key is the session reply — it never named an exit. Assert the identity
	// explicitly so a regression reads as "the wrong exit" rather than as a timeout.
	if got := coord1.registeredExit(); got != exitID {
		t.Fatalf("the coordinator handed back exit %q; the running exit is %q", got, exitID)
	}

	// exit2 shares exit1's identity (same key => same id) and is registered with
	// coord2 before exit1 dies, so it is already reachable the instant the
	// rebuild dials in.
	startTestExit(t, ctx, exitKeyHex, []string{coord2.addr()}) // cleanup-registered; not otherwise referenced
	if !waitUntil(20*time.Second, coord2.hasExit) {
		t.Fatal("exit2 never registered with coord2")
	}

	// Force the drop for real: coord1 goes silent (the all-coordinators-
	// unreachable condition mesh-walk keys on) and exit1 dies (a real
	// PeerConnection teardown the client's live session actually observes —
	// silencing the coordinator alone does not touch an already-established
	// direct data plane, which by design no longer depends on it).
	coord1.setSilent(true)
	exit1.Stop()

	const payload2 = "hello-after-recovery"
	if err := waitUntilNoErr(240*time.Second, func() error {
		got, err := socksEchoRoundTrip(socksAddr, echoAddr, []byte(payload2))
		if err != nil {
			return err
		}
		if string(got) != payload2 {
			return fmt.Errorf("echo mismatch: got %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("mid-session recovery never rebuilt a working SOCKS path on the same address: %v", err)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runNode returned an error after clean shutdown: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("runNode did not return after ctx cancellation")
	}
}
