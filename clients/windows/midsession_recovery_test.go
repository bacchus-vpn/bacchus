//go:build windows

package main

// This file drives issue #129's requirement (inherited from the #125
// review of #122): watchMeshRecovery's stop/rebuild/swap orchestration in
// main.go had no live path in any automated test — only the pure
// rebuildRecoveryConfig helper was unit-tested. Mirrors cmd/node's own
// analogous test (cmd/node/midsession_recovery_test.go, issue #121) at the
// same "supervisor" layer: a real client core.Engine and a real exit
// core.Engine, paired through a hand-rolled, wire-compatible fake
// coordinator, with a real coldstart courier for the mesh-walk to query.
// NeedsRecovery is never touched directly — both tests drive the real
// conditions (a genuinely silent coordinator, a genuinely dropped session,
// a real courier) that make the engine close it itself, per issue #105's
// lesson that a stubbed signal would not catch the double-connect/strand
// class of bug.
//
// Deliberately does NOT go through connect()/startTunnel(): that would
// require a real wintun adapter and Administrator elevation, mutating the
// actual OS routing table — this package's own existing test suite already
// avoids that for every other test, for the same reason. watchMeshRecovery
// itself never touches the tunnel at all (only core.Engine and the
// package's own engine/mu globals — see its doc comment in main.go), so
// seeding those globals the same way connect() does and driving
// watchMeshRecovery directly exercises the real orchestration path without
// needing the OS-level layer.
//
// setStatus/trayHide/trayShow (main.go) are all nil-safe before onReady has
// set mConn/mDisc/mStatus up — never true in the real app, only reachable
// from a test like this one that drives connect()/disconnect()/
// watchMeshRecovery()/switchExit() without onReady() ever running. Found by
// this file's own first real run: disconnect() panicked on a nil mDisc
// before that guard existed.

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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// rvWire mirrors the subset of core's private wire protocol this fake
// coordinator needs to speak: registration, connect/session/assign pairing,
// and signal relay. JSON field names must match core/engine.go's wire
// exactly; any field not listed here is simply dropped on decode and never
// sent.
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
// offer/answer/candidate relay, so a genuine WebRTC handshake completes
// between a real client and real exit core.Engine. It serves exactly one
// client<->exit pairing for its lifetime: repeated "connect" sends (core's
// attemptWith retries 3x to ride out UDP loss) are deduped to a single mint
// so the exit is never handed a second "assign" for a session the client
// will never dial — which would otherwise leave a stray transport Accept()
// blocked until its own internal handshake timeout, stalling this
// coordinator's one read loop. silence, once set, drops every datagram —
// the all-coordinators-unreachable condition mesh-walk recovery keys on
// (core/client.go's ErrNoCoordinatorReachable).
type fakeRendezvous struct {
	pc *net.UDPConn

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
	c := &fakeRendezvous{pc: pc, sid: label + "-session"}
	go c.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return c
}

func (c *fakeRendezvous) addr() string { return c.pc.LocalAddr().String() }

// setSilent, once true, makes this coordinator drop every datagram — a
// client dialing it sees exactly what it sees from a censor-blocked
// coordinator.
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

// registeredExit is the id this coordinator learned from the exit's register and
// hands back on every session mint. Tests assert the client ended up on the exit
// the coordinator actually chose, rather than inferring it from a timeout.
func (c *fakeRendezvous) registeredExit() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitID
}

func (c *fakeRendezvous) serve() {
	buf := make([]byte, 65535)
	for {
		n, src, err := c.pc.ReadFromUDP(buf)
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
		if json.Unmarshal(buf[:n], &m) != nil {
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
	_, _ = c.pc.WriteToUDP(b, addr)
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
			// No ExitAddr => direct egress, mirroring cmd/coordinator's
			// mode:"direct" assign shape exactly (core/forwarder.go's
			// handlerFor keys on that).
			c.send(exit, rvWire{Type: "assign", Session: sid})
		}
		// ExitID is the coordinator's answer: the client cannot bring up the
		// end-to-end Noise channel without the exit's static public key, and core
		// treats a session reply that omits it as a refusal.
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

// startTestCourier runs a bare coldstart.ServeCourier over loopback UDP
// primed with cache. Mesh-walk recovery (core.Engine.MeshWalk) fetches from
// it directly — no coordinator round trip is needed to populate the cache,
// since the test controls its contents up front.
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

// startEchoServer binds a loopback TCP listener that echoes back whatever
// it reads on each connection — the "destination" the exit dials on a
// SOCKS CONNECT, so the test can prove real bytes cross the rebuilt
// tunnel, not merely that Connect returned nil.
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
// target, writes payload, and returns the echoed bytes — proving the
// engine is genuinely usable end to end (real transport handshake, real
// E2E Noise handshake, real exit egress), not merely that some internal
// call returned no error.
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

// testCountry and testCountryAlt are the country tags the fixture exits register
// under. Two are needed because a switch is only a switch if the country changes
// (switchCountry no-ops on the live one). They are deliberately not real ISO
// codes for anywhere this project operates — nothing here should read as a claim
// about where infrastructure is.
const (
	testCountry    = "AA"
	testCountryAlt = "ZZ"
)

// startTestExit brings up a real exit core.Engine registered with coords, in
// country. exitKeyHex fixes its identity (the exit id is its static public key),
// so two separate startTestExit calls sharing the same hex are the SAME exit as
// far as the coordinator's assignment is concerned — used to hand the rebuild a
// fresh process standing in for the same node reappearing on a different
// coordinator, without carrying the original (now-dead) instance across it.
//
// The country is self-reported on register, which is what a coordinator with no
// GeoIP database falls back to (issue #136). The fake here does not model
// country assignment at all — it has exactly one exit and answers for it — but
// the field is set anyway so the register datagram has the shape a real
// coordinator would receive.
func startTestExit(t *testing.T, ctx context.Context, exitKeyHex string, coords []string, country string) *core.Engine {
	t.Helper()
	eng, err := core.New(core.Config{
		Roles:        []string{core.RoleExit},
		Coordinators: coords,
		ExitKeyHex:   exitKeyHex,
		Country:      country,
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

func signedTestSnapshot(t *testing.T, priv ed25519.PrivateKey, coordAddr string) []byte {
	t.Helper()
	signed, err := coldstart.Sign(priv, coldstart.Snapshot{
		Version:   coldstart.SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []coldstart.Entry{
			{Role: "coordinator", ID: "coord", Addr: coordAddr},
			{Role: "relay", ID: "relay-1", Addr: "203.0.113.7:20000"},
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

// resetConnectionState clears the package's connection-state globals both
// before and after the test, so a failure partway through this test can't
// leak a live engine/goroutine into whatever test runs next in this
// package, and so a prior failure can't start this one from dirty state.
func resetConnectionState(t *testing.T) {
	t.Helper()
	clear := func() {
		mu.Lock()
		eng, t2 := engine, activeTunnel
		engine, engineCancel, activeTunnel, liveCountry = nil, nil, nil, ""
		selectedID, selectedLbl = "", ""
		mu.Unlock()
		if eng != nil {
			eng.Stop()
		}
		if t2 != nil {
			t2.Close()
		}
	}
	clear()
	t.Cleanup(clear)
}

// testEventSink returns a core.Config.OnEvent value that logs to t instead
// of onEngineEvent's real one (main.go), which calls setStatus/logEvent —
// setStatus is safe here (nil-guarded, see main.go), but logEvent writes to
// the event log.
//
// Substituting the sink is not on its own enough to keep a test off the
// developer's real %APPDATA%\Bacchus\bacchus.log: watchMeshRecovery,
// abortSession and runPS all reach logEvent/logLine directly, outside any
// injected sink. redirectEventLogForTest is what actually contains it, and
// every test here calls it.
func testEventSink(t *testing.T, label string) func(core.Event) {
	return func(ev core.Event) {
		t.Logf("[%s] %s: %s", label, ev.Kind, ev.Message)
	}
}

// redirectEventLogForTest points the process-wide event log at a temp file
// for the duration of one test, mirroring what redirectRunKeyForTest does for
// the autostart registry key (clients/fyne/internal/appstate). The whole
// singleton is swapped, not just the path: openLog is once-per-process, so a
// path change alone would be ignored the moment anything had already opened
// the real file.
func redirectEventLogForTest(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	origPath, origOnce, origLogger, origFile := logPath, logOnce, logger, logFile
	logPath = func() string { return filepath.Join(dir, "bacchus.log") }
	logOnce, logger, logFile = new(sync.Once), nil, nil
	t.Cleanup(func() {
		// Close before t.TempDir's own cleanup tries to remove the
		// directory — Windows refuses to delete a file still held open.
		// Cleanups run LIFO, so this one goes first.
		if logFile != nil {
			_ = logFile.Close()
		}
		logPath, logOnce, logger, logFile = origPath, origOnce, origLogger, origFile
	})
}

// gateEngineRebuild parks any supervisor rebuild inside its own
// construct-and-start window until the test releases it, by substituting
// newCoreEngine (main.go).
//
// This is what makes a concurrent-disconnect test discriminating rather than
// hopeful. The window a rebuild has to survive — between "is this session
// still mine?" and "publish the replacement" — is core.New plus Start, which
// on loopback is a couple of milliseconds. Firing disconnect() and hoping it
// lands inside those milliseconds gives a test that passes either way: on the
// runs where disconnect() arrives first, the rebuild backs off at its
// staleness check and the assertions hold whether or not the swap itself is
// guarded. Pinning the interleaving means disconnect() provably completes
// inside the window, every run, so the assertions can only be satisfied by
// the guard actually being there.
//
// Returns the channel that fires once a rebuild has entered the window, and
// the channel that lets it continue. Everything after the gate is the real
// thing: a real core.Engine, a real Start, a real Connect.
func gateEngineRebuild(t *testing.T) (entered <-chan struct{}, release chan<- struct{}) {
	t.Helper()
	in := make(chan struct{}, 1)
	out := make(chan struct{})
	orig := newCoreEngine
	newCoreEngine = func(cfg core.Config) (*core.Engine, error) {
		in <- struct{}{}
		<-out
		return orig(cfg)
	}
	t.Cleanup(func() { newCoreEngine = orig })
	return in, out
}

// requireFreeSocksAddr fails early and legibly if something already holds the
// package's fixed local SOCKS address. switchCountry binds socksAddr itself
// (that fixed address is the property ADR-0039 turns on, so the test cannot
// substitute a free port the way the other tests here do), and a port already
// in use would otherwise surface as an unrelated-looking Start failure.
func requireFreeSocksAddr(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		t.Fatalf("switchCountry binds the fixed %s and something else already holds it: %v", socksAddr, err)
	}
	_ = ln.Close()
}

// seedLiveSession puts the package globals into the state connect() leaves
// behind once a session is fully up, without going through connect() itself
// (see this file's doc comment for why). The stand-in tunnel matters as much
// as the engine: switchCountry only acts on a session whose tunnel is up, and
// the failure this file's switch test is about is precisely an engine
// outliving that tunnel. Carrying a real poolExcluder keeps switchCountry on
// its production path of reusing the live one.
//
// country seeds BOTH liveCountry and the picker selection, because those are
// what switchCountry compares: it reads the picked country itself rather than
// being handed one, so a test that seeded only liveCountry would leave the
// picker empty and every switch would no-op on the code == "" guard.
//
// Closing this stub is nearly, but not entirely, inert: tunnel.Close() reaches
// enablePhysicalIPv6(t.gw.ifAlias) with no guard on the zero-value alias, which
// shells out to a real PowerShell that fails harmlessly ("Cannot bind argument
// to parameter 'Name' because it is an empty string"). Harmless, but it is a
// real OS call from a suite whose header says it makes none — recorded here
// rather than left for the next reader to rediscover.
func seedLiveSession(eng *core.Engine, cancel context.CancelFunc, country string) *tunnel {
	stub := &tunnel{excluder: newPoolExcluder()}
	mu.Lock()
	engine, engineCancel, activeTunnel, liveCountry = eng, cancel, stub, country
	selectedID, selectedLbl = country, country
	mu.Unlock()
	return stub
}

// TestWatchMeshRecovery_MidSessionRecoversToCleanSocksRebind is issue
// #129's first requirement (inherited from the #125 review of #122):
// watchMeshRecovery's <-eng.NeedsRecovery() branch — Stop the dead engine,
// read RecoveredDirectory, rebuild core.New against the rediscovered
// coordinators, swap the package's engine global, reconnect — was
// exercised nowhere; only the pure rebuildRecoveryConfig helper was
// unit-tested (main_test.go).
//
// Sequence: a real client core.Engine connects through a real (fake but
// wire-compatible) coordinator to a real exit engine over real WebRTC,
// proven by an actual SOCKS5 CONNECT + echo round trip, with the package's
// engine/engineCancel/liveExitID globals seeded the same way connect()
// seeds them. The coordinator then goes silent and the exit dies, forcing
// a genuine session drop; the engine's own reconnect loop retries until its
// own mesh-walk (core/client.go's tryMeshRecovery) recovers a fresh
// directory from a real courier and closes NeedsRecovery. watchMeshRecovery
// must then stop the dead engine, rebuild against the rediscovered
// coordinator, swap the package's engine global, and reconnect through a
// fresh exit instance sharing the dead one's identity — proven by a second
// real SOCKS5 CONNECT + echo round trip succeeding on the SAME socksAddr
// (no leftover listener, no port-in-use failure, no strand) and by the
// package's engine global actually pointing at the new instance.
//
// Slow and gated behind -short, for the identical reason
// cmd/node/midsession_recovery_test.go is: it rides core's real, fixed,
// unexported reconnect/mesh-walk timeouts (directTimeout/relayTimeout/
// meshRecoveryAfter), which this package has no seam to shorten from
// outside core. See ci.yml's windows-client job for why this still runs
// automated rather than only locally.
func TestWatchMeshRecovery_MidSessionRecoversToCleanSocksRebind(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real mid-session mesh-walk recovery in -short")
	}
	// Redirect the log BEFORE seeding connection state: t.Cleanup runs LIFO, so
	// resetConnectionState's teardown (which stops engines and closes a tunnel,
	// both of which log) still lands in the temp file rather than the
	// developer's real %APPDATA%\Bacchus\bacchus.log.
	redirectEventLogForTest(t)
	resetConnectionState(t)

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

	exit1 := startTestExit(t, ctx, exitKeyHex, []string{coord1.addr()}, testCountry)
	exitID := exit1.ID()
	if !waitUntil(20*time.Second, coord1.hasExit) {
		t.Fatal("exit1 never registered with coord1")
	}

	// The courier serves a fresh directory naming coord2 — what the client
	// must recover to. proof is a stale snapshot naming coord1, standing in
	// for a cached snapshot carried over from a genuine prior session.
	cache := coldstart.NewSnapshotCache()
	cache.Store(signedTestSnapshot(t, priv, coord2.addr()))
	courierAddr := startTestCourier(t, pub, cache)
	proof := signedTestSnapshot(t, priv, coord1.addr())

	socksAddr := freeTCPAddr(t)
	engCfg := core.Config{
		Roles:     []string{core.RoleClient},
		SocksAddr: socksAddr,
		// A client names a COUNTRY (issue #146); the coordinator picks the exit and
		// tells the client which it got. exitID below is the exit's own identity,
		// asserted against what the client is handed — not something it asks for.
		// Setting Geo also means resolveCountry settles without a country-list round
		// trip, which this fake does not serve.
		Geo:          testCountry,
		Coordinators: []string{coord1.addr()},
		OnEvent:      testEventSink(t, "recovery"),
		MeshPeers:    []string{courierAddr},
		MeshProof:    proof,
		MeshPubKey:   pub,
	}

	eng, err := core.New(engCfg)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	if err := eng.Start(sessionCtx); err != nil {
		sessionCancel()
		t.Fatalf("Start: %v", err)
	}

	// Seed the package globals the way connect() does (main.go), without
	// going through connect() itself — see the file doc comment.
	mu.Lock()
	engine = eng
	engineCancel = sessionCancel
	liveCountry = testCountry
	selectedID, selectedLbl = testCountry, testCountry
	mu.Unlock()

	// The exit is never named by the client; the only thing that could have keyed
	// the Noise handshake is the id on the session reply. Assert it explicitly so a
	// regression reads as "the wrong exit" rather than as a timeout.
	if got := coord1.registeredExit(); got != exitID {
		t.Fatalf("the coordinator handed back exit %q; the running exit is %q", got, exitID)
	}

	if err := eng.Connect(sessionCtx); err != nil {
		t.Fatalf("initial Connect: %v", err)
	}
	go watchMeshRecovery(sessionCtx, eng, engCfg, "test")

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

	// exit2 shares exit1's identity (same key => same id) and is registered
	// with coord2 before exit1 dies, so it is already reachable the instant
	// the rebuild dials in.
	startTestExit(t, ctx, exitKeyHex, []string{coord2.addr()}, testCountry) // cleanup-registered; not otherwise referenced
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

	// Prove the package's own view of the live engine actually swapped —
	// not just that traffic happens to still flow. A stale `engine` here
	// would mean disconnect() from this point on tears down the wrong (a
	// dead) engine, exactly the "strand" ADR-0037 requires this loop avoid.
	mu.Lock()
	swapped := engine != nil && engine != eng
	mu.Unlock()
	if !swapped {
		t.Fatal("engine global was never swapped to the rebuilt engine")
	}
}

// TestWatchMeshRecovery_ConcurrentDisconnectDoesNotStrand is issue #129's
// second requirement: a concurrent-disconnect race against
// watchMeshRecovery's own rebuild.
//
// The #183 review was right that the first version of this could not
// discriminate. It woke on the same NeedsRecovery close as the watcher and
// called disconnect() immediately, but disconnect() takes mu right away
// while the watcher first does RecoveredDirectory() and eng.Stop() (which
// waits on its goroutines), so in practice disconnect() always won the
// staleness check and the rebuild simply backed off before it ever reached
// the swap. Both orderings satisfied the old assertion, and it was read the
// instant disconnect() returned — so a late unconditional swap, the exact
// shape of the switchExit blocker, was invisible to it.
//
// Now the interleaving is pinned instead of hoped for: gateEngineRebuild
// parks the rebuild inside its own construct-and-start window, disconnect()
// runs to completion there, and the assertions are read only after the
// watcher goroutine has actually returned — so a late republication is
// visible where before it was not.
//
// What this does and does not prove, stated plainly. A mesh-walk rebuild
// reuses the *session's* context, which disconnect() cancels, so the resumed
// rebuild is normally stopped by that cancellation at its Connect before it
// ever reaches the swap; adoptEngine's re-check is the second line behind it,
// not the first. The test therefore pins the whole path's convergence
// deterministically, but it is TestSwitchExit_ConcurrentDisconnectDoes
// NotResurrectTheSession that discriminates on the guard itself — a live exit
// switch runs its new engine on a fresh context disconnect() never touches
// and adopts before Connect, so there the swap is genuinely reached with the
// session gone.
func TestWatchMeshRecovery_ConcurrentDisconnectDoesNotStrand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real mid-session mesh-walk recovery in -short")
	}
	// Redirect the log BEFORE seeding connection state: t.Cleanup runs LIFO, so
	// resetConnectionState's teardown (which stops engines and closes a tunnel,
	// both of which log) still lands in the temp file rather than the
	// developer's real %APPDATA%\Bacchus\bacchus.log.
	redirectEventLogForTest(t)
	resetConnectionState(t)

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

	exit1 := startTestExit(t, ctx, exitKeyHex, []string{coord1.addr()}, testCountry)
	exitID := exit1.ID()
	if !waitUntil(20*time.Second, coord1.hasExit) {
		t.Fatal("exit1 never registered with coord1")
	}

	cache := coldstart.NewSnapshotCache()
	cache.Store(signedTestSnapshot(t, priv, coord2.addr()))
	courierAddr := startTestCourier(t, pub, cache)
	proof := signedTestSnapshot(t, priv, coord1.addr())

	socksAddr := freeTCPAddr(t)
	engCfg := core.Config{
		Roles:     []string{core.RoleClient},
		SocksAddr: socksAddr,
		// A country, never an exit (issue #146) — and setting it keeps
		// resolveCountry off the country-list round trip this fake does not serve.
		Geo:          testCountry,
		Coordinators: []string{coord1.addr()},
		OnEvent:      testEventSink(t, "race"),
		MeshPeers:    []string{courierAddr},
		MeshProof:    proof,
		MeshPubKey:   pub,
	}

	eng, err := core.New(engCfg)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	if err := eng.Start(sessionCtx); err != nil {
		sessionCancel()
		t.Fatalf("Start: %v", err)
	}

	mu.Lock()
	engine = eng
	engineCancel = sessionCancel
	liveCountry = testCountry
	selectedID, selectedLbl = testCountry, testCountry
	mu.Unlock()

	if got := coord1.registeredExit(); got != exitID {
		t.Fatalf("the coordinator handed back exit %q; the running exit is %q", got, exitID)
	}

	if err := eng.Connect(sessionCtx); err != nil {
		t.Fatalf("initial Connect: %v", err)
	}
	setStatus("Protected — test")
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		watchMeshRecovery(sessionCtx, eng, engCfg, "test")
	}()

	const payload1 = "hello-before-race"
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

	startTestExit(t, ctx, exitKeyHex, []string{coord2.addr()}, testCountry)
	if !waitUntil(20*time.Second, coord2.hasExit) {
		t.Fatal("exit2 never registered with coord2")
	}

	// Gate installed before the outage, so the rebuild the outage triggers
	// parks in its window rather than racing past it.
	entered, release := gateEngineRebuild(t)
	coord1.setSilent(true)
	exit1.Stop()

	select {
	case <-entered:
	case <-time.After(240 * time.Second):
		t.Fatal("watchMeshRecovery never reached its engine-rebuild window")
	}
	disconnect()
	close(release)

	// Only now, once the watcher has actually returned: a swap that lands
	// after disconnect() is exactly what this test exists to catch, and
	// reading the state while the watcher is still running cannot see one.
	select {
	case <-watcherDone:
	case <-time.After(180 * time.Second):
		t.Fatal("watchMeshRecovery never returned after the concurrent disconnect")
	}

	// The rebuild reached its swap with the session already torn down, so
	// every one of these is a claim about the swap being conditional — not
	// about eventual convergence.
	mu.Lock()
	engineNil, cancelNil, tunnelNil, countryEmpty := engine == nil, engineCancel == nil, activeTunnel == nil, liveCountry == ""
	mu.Unlock()
	if !engineNil || !cancelNil || !tunnelNil || !countryEmpty {
		t.Fatalf("a mesh-walk rebuild republished itself over a concurrent disconnect: engine-set=%v cancel-set=%v tunnel-set=%v country-set=%v, status=%q",
			!engineNil, !cancelNil, !tunnelNil, !countryEmpty, currentStatus())
	}
	if got := currentStatus(); got != "Disconnected" {
		t.Errorf("status after the raced rebuild is %q, want %q — the client is claiming a session it does not have", got, "Disconnected")
	}

	// The original engine must have fully stopped — proves the watcher
	// goroutine (or disconnect(), whichever handled it) actually tore it
	// down rather than leaving it to run forever unobserved.
	if !waitUntil(15*time.Second, func() bool {
		select {
		case <-eng.Done():
			return true
		default:
			return false
		}
	}) {
		t.Fatal("original engine never reached Done() after the concurrent disconnect race")
	}
	// Nothing may still hold the SOCKS address: a rebuild that lost the race
	// but left its own engine running would still be bound here.
	if !waitUntil(20*time.Second, func() bool {
		ln, err := net.Listen("tcp", socksAddr)
		if err != nil {
			return false
		}
		_ = ln.Close()
		return true
	}) {
		t.Errorf("something is still serving %s after the raced rebuild", socksAddr)
	}
}
