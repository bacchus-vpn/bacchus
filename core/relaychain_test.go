package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/flynn/noise"
)

// Relay chaining (issue #142, ADR-0038). These drive the SHIPPED code paths —
// the production exitTerminate on each hop, the production relayPipe standing in
// for the coordinator-assigned blind relay, and the production dialChain on the
// client — because the claims being made are about what ships, not about a model
// of it. cmd/relaychain-probe demonstrates the cryptographic construction in
// isolation; this proves the wiring.

// signTestSnapshot builds and signs a directory snapshot fixture. Every address
// in it is loopback: a public repo carries no real infrastructure (see the
// workspace publishability rule), and the chain neither knows nor cares.
func signTestSnapshot(t *testing.T, priv ed25519.PrivateKey, entries []coldstart.Entry) []byte {
	t.Helper()
	signed, err := coldstart.Sign(priv, coldstart.Snapshot{
		Version:   coldstart.SnapshotVersion,
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries:   entries,
	})
	if err != nil {
		t.Fatalf("sign snapshot: %v", err)
	}
	return signed
}

// startForwardNode runs a real onion-forwarding relay on a loopback TCP listener:
// each accepted connection goes through the production exitTerminate, which runs
// the Noise responder, reads the "hop:" target, checks it against dir, and
// splices. It holds only the relay role, so the same code path would refuse to
// egress to the internet (see TestRelayOnlyNodeRefusesInternetEgress).
func startForwardNode(t *testing.T, key noise.DHKey, dir *relayDirectory) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hop listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	e := &Engine{
		roles:    map[string]bool{RoleRelay: true},
		exitKey:  key,
		relayDir: dir,
		cfg:      Config{RelayIngress: ln.Addr().String()},
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Bounded, so a broken topology fails the test instead of hanging it to Go's
			// package timeout — see hopTestDeadline.
			_ = c.SetDeadline(time.Now().Add(hopTestDeadline))
			go e.exitTerminate("", c)
		}
	}()
	return ln.Addr().String()
}

// chainFixture is a whole assembled mesh for one test: a real exit, n forwarding
// hops, a signed directory naming all of them, and the admission root the client
// anchors to.
type chainFixture struct {
	rootPub  ed25519.PublicKey
	exitKey  noise.DHKey
	exitAddr string
	hops     []relayHop
	dir      *relayDirectory
	plan     *chainPlan
}

// A fixed snapshot-signing keypair for the fixtures, generated once per process.
// It signs only synthetic loopback directories.
var testSnapPubKey ed25519.PublicKey
var testSnapPrivKey ed25519.PrivateKey

func testSnapKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	if testSnapPrivKey == nil {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		testSnapPubKey, testSnapPrivKey = pub, priv
	}
	return testSnapPubKey, testSnapPrivKey
}

func testSnapPub(t *testing.T) ed25519.PublicKey   { p, _ := testSnapKeys(t); return p }
func testSnapPriv(t *testing.T) ed25519.PrivateKey { _, p := testSnapKeys(t); return p }

// TestRelayChainPreservesE2EAdmission is the #142 acceptance and the n-hop
// analogue of TestPeerRelaySplicePreservesE2E: with TWO peeling hops behind the
// coordinator's blind relay — three nodes between client and exit — the exit's
// admission credential (#60/#69) is still verified end to end, the real target
// still reaches only the exit, and traffic flows both ways.
//
// Every node in the path is production code: relayPipe for the assigned relay,
// exitTerminate for both hops and the exit, dialChain for the client. The
// credential is checked by the same verifier a direct connection uses, over a
// channel that crossed three splices — which is the whole claim.
func TestRelayChainPreservesE2EAdmission(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const target = "example.com:443"
	const payload = "CHAINED_E2E_PAYLOAD_0987654321"

	exitDone := make(chan error, 1)
	fx := newChainFixtureWithCred(t, 2, rootPub, rootPriv, target, payload, exitDone)
	// Guard the premise: this test only means anything if the traffic really
	// crosses two peeling hops on top of the blind relay. A fixture that quietly
	// built a shorter chain would still pass every assertion below.
	if len(fx.plan.hops) != 2 {
		t.Fatalf("fixture built %d peeling hops, want 2", len(fx.plan.hops))
	}

	// The coordinator-assigned relay in front of the chain: a real relayPipe blind
	// splice to the chain's first peeling hop, exactly as ADR-0033 ships it. It is
	// told the first hop's address and nothing else — never the exit.
	clientConn, relayEnd := net.Pipe()
	deadline(t, clientConn, relayEnd)
	var assigned Engine
	go assigned.relayPipe(pipeStream{Conn: relayEnd, label: e2eLabel}, fx.hops[0].dial)

	client := &Engine{exitVerifier: verifierFor(t, rootPub)}
	nc, err := client.dialChain(clientConn, fx.plan, target)
	if err != nil {
		t.Fatalf("client could not build a 2-hop chain to an authorized exit: %v", err)
	}
	defer nc.Close()

	if _, err := nc.Write([]byte(payload)); err != nil {
		t.Fatalf("write through the chain: %v", err)
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(nc, ack); err != nil {
		t.Fatalf("read return-path ack through the chain: %v", err)
	}
	if err := <-exitDone; err != nil {
		t.Fatalf("exit side (through 1 blind relay + 2 peeling hops): %v", err)
	}
}

// newChainFixtureWithCred is newChainFixture with the exit credential minted
// against the supplied admission root, so the client's verifier accepts it.
func newChainFixtureWithCred(t *testing.T, nHops int, rootPub ed25519.PublicKey, rootPriv ed25519.PrivateKey, target, payload string, exitDone chan<- error) *chainFixture {
	t.Helper()
	// The exit key has to exist before its credential can name it, so mint a key,
	// issue against it, then build the fixture around that exact key.
	exitKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitID := hex.EncodeToString(exitKey.Public)
	// Windowed on the wall clock, not the fixed admissionNow the direct-path tests
	// use: the chained verifier runs at time.Now() like the shipped one does.
	cred := issueExitCred(t, rootPriv, exitID, []admission.Role{admission.RoleExit},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	fx := newChainFixtureFor(t, nHops, rootPub, exitKey, cred, target, payload, exitDone)
	return fx
}

// newChainFixtureFor is newChainFixture with the exit's keypair supplied.
func newChainFixtureFor(t *testing.T, nHops int, rootPub ed25519.PublicKey, exitKey noise.DHKey, cred []byte, target, payload string, exitDone chan<- error) *chainFixture {
	t.Helper()
	exitAddr := startExitIngress(t, exitKey, cred, target, payload, exitDone)

	keys := make([]noise.DHKey, nHops)
	for i := range keys {
		k, err := generateExitKey()
		if err != nil {
			t.Fatalf("hop key: %v", err)
		}
		keys[i] = k
	}
	dirEntries := []coldstart.Entry{{Role: "exit", ID: hex.EncodeToString(exitKey.Public), Addr: exitAddr}}
	addrs := make([]string, nHops)
	for i := nHops - 1; i >= 0; i-- {
		signed := signTestSnapshot(t, testSnapPriv(t), dirEntries)
		dir, err := loadRelayDirectory(signed, testSnapPub(t), "", time.Now())
		if err != nil {
			t.Fatalf("hop directory: %v", err)
		}
		addrs[i] = startForwardNode(t, keys[i], dir)
		dirEntries = append(dirEntries, coldstart.Entry{
			Role: "relay", ID: hex.EncodeToString(keys[i].Public),
			Ingress: addrs[i], Operator: fmt.Sprintf("op%d", i),
		})
	}
	signed := signTestSnapshot(t, testSnapPriv(t), dirEntries)
	dir, err := loadRelayDirectory(signed, testSnapPub(t), "", time.Now())
	if err != nil {
		t.Fatalf("client directory: %v", err)
	}
	hops := make([]relayHop, nHops)
	for i := range keys {
		hops[i] = relayHop{id: hex.EncodeToString(keys[i].Public), pub: keys[i].Public, dial: addrs[i]}
	}
	return &chainFixture{
		rootPub: rootPub, exitKey: exitKey, exitAddr: exitAddr, hops: hops, dir: dir,
		plan: &chainPlan{hops: hops, exitPub: exitKey.Public, exitDia: exitAddr},
	}
}

// verifierFor builds the client-side exit-admission verifier anchored at root —
// the same construction Connect uses, so the chained path is checked by exactly
// the verifier an unchained one would be.
func verifierFor(t *testing.T, root ed25519.PublicKey) *admission.Verifier {
	t.Helper()
	v, _, err := buildExitVerifier(hex.EncodeToString(root), "", "", false, time.Now())
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}
	return v
}

// TestRelayChainRejectsUnauthorizedExit is the security half: chaining must not
// weaken #60/#69. An exit at the end of a 2-hop chain that presents a credential
// signed by a root the client does not trust is rejected before the real target
// is ever sent — and no hop can vouch for it, because the credential is verified
// inside a channel every hop only splices.
func TestRelayChainRejectsUnauthorizedExit(t *testing.T) {
	rootPub, _, err := ed25519.GenerateKey(nil) // what the client trusts
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, rogueRoot, err := ed25519.GenerateKey(nil) // what actually signed the exit
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	exitKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	rogueCred := issueExitCred(t, rogueRoot, hex.EncodeToString(exitKey.Public),
		[]admission.Role{admission.RoleExit}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	exitDone := make(chan error, 1)
	fx := newChainFixtureFor(t, 2, rootPub, exitKey, rogueCred, "example.com:443", "unused", exitDone)

	clientConn, relayEnd := net.Pipe()
	deadline(t, clientConn, relayEnd)
	var assigned Engine
	go assigned.relayPipe(pipeStream{Conn: relayEnd, label: e2eLabel}, fx.hops[0].dial)

	client := &Engine{exitVerifier: verifierFor(t, rootPub)}
	nc, err := client.dialChain(clientConn, fx.plan, "example.com:443")
	_ = clientConn.Close()
	if err == nil {
		_ = nc.Close()
		t.Fatal("client accepted an unauthorized exit at the end of a 2-hop chain; want abort before the target is sent")
	}
	if !strings.Contains(err.Error(), "chain exit layer") {
		t.Errorf("rejection came from %v, want the innermost (exit) layer — a hop layer rejecting instead would mean the E2E check is not what stopped it", err)
	}
	<-exitDone
}

// TestRelayChainHostileHopFailsHandshake pins the per-hop authentication of
// ADR-0038 §4.3: a hop is authenticated by the X25519 key the SIGNED directory
// publishes for it, so a substituted node — one a hostile coordinator or a
// directory-tamperer put in the path — cannot complete that hop's handshake. The
// failure is at the substituted hop and nothing downstream is ever contacted.
func TestRelayChainHostileHopFailsHandshake(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	exitDone := make(chan error, 1)
	fx := newChainFixtureWithCred(t, 2, rootPub, rootPriv, "example.com:443", "unused", exitDone)

	// Swap the SECOND hop's expected key for one nobody in the path holds, as a
	// substituted hop would look to a client that selected the real one.
	wrong, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	plan := &chainPlan{
		hops:    []relayHop{fx.plan.hops[0], {id: fx.plan.hops[1].id, pub: wrong.Public, dial: fx.plan.hops[1].dial}},
		exitPub: fx.plan.exitPub, exitDia: fx.plan.exitDia,
	}

	clientConn, relayEnd := net.Pipe()
	deadline(t, clientConn, relayEnd)
	var assigned Engine
	go assigned.relayPipe(pipeStream{Conn: relayEnd, label: e2eLabel}, fx.hops[0].dial)

	client := &Engine{exitVerifier: verifierFor(t, rootPub)}
	nc, err := client.dialChain(clientConn, plan, "example.com:443")
	_ = clientConn.Close()
	if err == nil {
		_ = nc.Close()
		t.Fatal("a hop whose key the client did not select completed its handshake; want failure")
	}
	if !strings.Contains(err.Error(), "chain hop 2/2") {
		t.Errorf("failure reported as %v, want it attributed to hop 2 — the substituted one", err)
	}
}

// TestChainHopLearnsOnlyItsNeighbours proves the peel property that the whole
// design rests on: each hop recovers exactly its OWN next-hop address and nothing
// else — never the destination, never a later hop. It reads the targets straight
// off real exitHandshake responders standing in for the hops, which is the only
// way to observe what a hop actually learned.
func TestChainHopLearnsOnlyItsNeighbours(t *testing.T) {
	const dest = "example.com:443"
	h1Key, _ := generateExitKey()
	h2Key, _ := generateExitKey()
	exitKey, _ := generateExitKey()

	// Each spy runs the real responder, records its target, and hand-splices to the
	// next — the same peel-and-forward relayForward performs, instrumented.
	h2Addr, h2Target := startSpyHop(t, h2Key, nil)
	h1Addr, h1Target := startSpyHop(t, h1Key, &forwardTarget{addr: h2Addr})

	exitDone := make(chan error, 1)
	exitAddr := startExitIngress(t, exitKey, nil, dest, "x", exitDone)
	// h2 forwards to the exit; rebind its forward target now that the exit exists.
	h2TargetSink(t, h2Addr).set(exitAddr)

	clientConn, hopEnd := net.Pipe()
	deadline(t, clientConn, hopEnd)
	go func() {
		up, err := net.Dial("tcp", h1Addr)
		if err != nil {
			return
		}
		defer up.Close()
		go func() { _, _ = io.Copy(up, hopEnd) }()
		_, _ = io.Copy(hopEnd, up)
	}()

	plan := &chainPlan{
		hops: []relayHop{
			{id: hex.EncodeToString(h1Key.Public), pub: h1Key.Public, dial: h1Addr},
			{id: hex.EncodeToString(h2Key.Public), pub: h2Key.Public, dial: h2Addr},
		},
		exitPub: exitKey.Public, exitDia: exitAddr,
	}
	var client Engine
	nc, err := client.dialChain(clientConn, plan, dest)
	if err != nil {
		t.Fatalf("dialChain: %v", err)
	}
	defer nc.Close()
	if _, err := nc.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-exitDone; err != nil {
		t.Fatalf("exit: %v", err)
	}

	// What each hop actually recovered.
	got1, got2 := <-h1Target, <-h2Target
	if got1 != hopTargetPrefix+h2Addr {
		t.Errorf("hop 1 learned %q, want only the next hop %q", got1, hopTargetPrefix+h2Addr)
	}
	if got2 != hopTargetPrefix+exitAddr {
		t.Errorf("hop 2 learned %q, want only the exit's address %q", got2, hopTargetPrefix+exitAddr)
	}
	for i, got := range []string{got1, got2} {
		if strings.Contains(got, dest) {
			t.Errorf("hop %d learned the DESTINATION %q — the onion leaked the one thing it exists to hide", i+1, dest)
		}
	}
}

// spyForward is the mutable forward target of a spy hop, so a hop can be bound
// before the node it forwards to exists.
var spyForward = map[string]*forwardTarget{}

// forwardTarget is a spy hop's override next-hop address, settable after the hop is
// already listening (the exit does not exist yet when the hop in front of it binds).
//
// It carries a lock because the test's main goroutine writes it while the spy's
// accept goroutine reads it. The ordering happens to hold today — the client dials
// after the write — but that is timing, not synchronisation, and a test helper whose
// correctness rests on the scheduler is one that will eventually report a race
// against code that has none.
type forwardTarget struct {
	mu   sync.Mutex
	addr string
}

func (f *forwardTarget) set(a string) {
	f.mu.Lock()
	f.addr = a
	f.mu.Unlock()
}

func (f *forwardTarget) get() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addr
}

func h2TargetSink(t *testing.T, addr string) *forwardTarget {
	t.Helper()
	p, ok := spyForward[addr]
	if !ok {
		t.Fatalf("no spy hop at %s", addr)
	}
	return p
}

// startSpyHop runs a real Noise_NK responder that records the target it was given
// and then splices to whatever forward names. It exists to observe what a hop
// learns; production hops go through exitTerminate/relayForward instead.
func startSpyHop(t *testing.T, key noise.DHKey, forward *forwardTarget) (string, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("spy hop listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()
	if forward == nil {
		forward = &forwardTarget{}
	}
	spyForward[addr] = forward
	targets := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Bound every inter-hop connection. Without it a broken topology does not fail
		// the test, it hangs it to Go's 10-minute package timeout — which reports as an
		// infrastructure problem rather than as the regression it is.
		_ = conn.SetDeadline(time.Now().Add(hopTestDeadline))
		nc, tgt, err := exitHandshake(conn, key, nil)
		if err != nil {
			return
		}
		targets <- tgt
		_, next := splitTargetPrefix(tgt)
		if override := forward.get(); override != "" {
			next = override
		}
		up, err := net.DialTimeout("tcp", next, hopTestDeadline)
		if err != nil {
			return
		}
		defer up.Close()
		_ = up.SetDeadline(time.Now().Add(hopTestDeadline))
		go func() { _, _ = io.Copy(up, nc); _ = up.Close() }()
		_, _ = io.Copy(nc, up)
	}()
	return addr, targets
}

// hopTestDeadline bounds every TCP connection between test hops. Generous enough
// never to fire on a working topology on a loaded machine, short enough that a
// broken one fails inside the package timeout rather than as it.
const hopTestDeadline = 30 * time.Second

// ---------- default depth 1 is today's path ----------

// recordConn records the length of every raw write, which for a noiseConn is one
// frame per write — so the recorded sequence IS the client's wire shape.
type recordConn struct {
	net.Conn
	frames *[]int
}

func (r recordConn) Write(p []byte) (int, error) {
	*r.frames = append(*r.frames, len(p))
	return r.Conn.Write(p)
}

// TestDefaultDepthIsByteIdenticalToTodaysHandshake is the zero-regression proof
// the whole feature is gated on: at the default hop count, dialE2E emits exactly
// the wire shape clientHandshake emits — same number of frames, same lengths, in
// the same order. Noise_NK message sizes are deterministic for a given pattern
// and payload, so this is an exact comparison, not a sampled one.
//
// It is a check on the structure, not a substitute for it: dialE2E with no plan
// IS a call to clientHandshake, which is what makes the property hold. The test
// exists so that a future refactor that inserts anything into the default path —
// a preamble, a capability byte, an extra frame — fails here.
func TestDefaultDepthIsByteIdenticalToTodaysHandshake(t *testing.T) {
	const target = "example.com:443"
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}

	shape := func(dial func(io.ReadWriteCloser) (*noiseConn, error)) []int {
		t.Helper()
		var frames []int
		cConn, sConn := net.Pipe()
		deadline(t, cConn, sConn)
		done := make(chan struct{})
		go func() {
			defer close(done)
			nc, _, err := exitHandshake(sConn, key, nil)
			if err == nil {
				_ = nc.Close()
			}
		}()
		nc, err := dial(recordConn{Conn: cConn, frames: &frames})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = nc.Close()
		<-done
		return frames
	}

	var e Engine
	direct := shape(func(raw io.ReadWriteCloser) (*noiseConn, error) {
		return clientHandshake(raw, key.Public, target, nil)
	})
	seam := shape(func(raw io.ReadWriteCloser) (*noiseConn, error) {
		return e.dialE2E(raw, nil, key.Public, target)
	})

	if len(direct) != len(seam) {
		t.Fatalf("default-depth dialE2E wrote %d frames, today's clientHandshake wrote %d — the default path is NOT unchanged", len(seam), len(direct))
	}
	for i := range direct {
		if direct[i] != seam[i] {
			t.Fatalf("frame %d: default-depth dialE2E wrote %d bytes, today's clientHandshake wrote %d — the default path is NOT unchanged", i, seam[i], direct[i])
		}
	}
}

// TestDefaultDepthNeedsNoDirectory pins the other half of "default 1 == today":
// an engine at the default hop count never consults a relay directory, so a
// client with no directory at all still connects exactly as it does now. Together
// with the frame-shape test above, this is what makes the feature a strict
// superset rather than a change with a compatibility mode.
func TestDefaultDepthNeedsNoDirectory(t *testing.T) {
	for _, hops := range []int{0, 1} {
		e := &Engine{cfg: Config{RelayHops: hops}} // relayDir deliberately nil
		if e.chaining() {
			t.Errorf("RelayHops=%d reports chaining; the default must not", hops)
		}
		for _, mode := range []string{modeDirect, modeRelay} {
			plan, err := e.chainFor(mode, "deadbeef")
			if err != nil {
				t.Errorf("RelayHops=%d mode=%s: chainFor errored (%v); the default path must not depend on a directory", hops, mode, err)
			}
			if plan != nil {
				t.Errorf("RelayHops=%d mode=%s: built a chain; the default must engage no onion at all", hops, mode)
			}
		}
	}
}

// TestDirectModeIsNeverChained pins ADR-0038 §4.4: hop count applies only once
// the ladder has reached the relay tier. A chaining client's DIRECT candidates
// must stay exactly what they are today — there is no relay in a direct path to
// unlink from, and chaining one would cost latency for nothing.
func TestDirectModeIsNeverChained(t *testing.T) {
	e := &Engine{cfg: Config{RelayHops: 3}, relayDir: &relayDirectory{}}
	plan, err := e.chainFor(modeDirect, "deadbeef")
	if err != nil || plan != nil {
		t.Fatalf("chainFor(direct) = (%v, %v), want (nil, nil) — direct paths are unaffected by hop count", plan, err)
	}
}

// ---------- fail closed, never a silent downgrade ----------

// TestChainFailsClosedRatherThanDowngrading is the behavioural rule that matters
// most: every way of failing to build the requested chain must be an ERROR, never
// a shorter chain. A user who asked for a path no single relay can link, and
// silently got a linkable one, would act on an assurance they no longer have.
func TestChainFailsClosedRatherThanDowngrading(t *testing.T) {
	const cc = "NL"
	exitID := hex.EncodeToString(make([]byte, 32))
	// A directory holding one usable exit in cc and two peeling candidates: enough
	// to build a depth-3 chain, not enough for a depth-4 one.
	dirWith := func(exitAddr string) *relayDirectory {
		return &relayDirectory{
			hops: []relayHop{
				{id: exitID, pub: make([]byte, 32), dial: exitAddr, country: cc, pairable: true},
				{id: "aa", pub: make([]byte, 32), dial: "127.0.0.1:1", country: cc, pairable: true, operator: "a"},
				{id: "bb", pub: make([]byte, 32), dial: "127.0.0.1:2", country: cc, operator: "b"},
			},
			exitAddr: map[string]string{exitID: exitAddr, "aa": "127.0.0.1:1"},
		}
	}

	t.Run("no directory at all", func(t *testing.T) {
		e := &Engine{cfg: Config{RelayHops: 2}}
		if _, err := e.buildChain(2, cc); err == nil {
			t.Fatal("built a chain with no directory; want an error, never a fallback to one hop")
		}
	})

	t.Run("directory too small for the requested depth", func(t *testing.T) {
		e := &Engine{cfg: Config{RelayHops: 4}, relayDir: dirWith("127.0.0.1:9")}
		// Depth 4 needs 3 peeling hops. Whichever exit is chosen is excluded from the
		// hop pool, leaving 2.
		_, err := e.buildChain(4, cc)
		if err == nil {
			t.Fatal("built a 4-deep chain from a 3-node directory; want an error, never a shortened chain")
		}
		if !strings.Contains(err.Error(), "not enough distinct relay hops") {
			t.Errorf("error = %v, want it to name the too-short directory", err)
		}
	})

	t.Run("no exit in the requested country", func(t *testing.T) {
		e := &Engine{cfg: Config{RelayHops: 2}, relayDir: dirWith("127.0.0.1:9")}
		// The directory is perfectly usable — it just holds nothing in DE. A chain
		// that egressed somewhere the user did not choose would be the same class of
		// silent substitution as a shortened one.
		_, err := e.buildChain(2, "DE")
		if err == nil {
			t.Fatal("built a chain terminating outside the requested country; want an error")
		}
		if !strings.Contains(err.Error(), "names no exit") {
			t.Errorf("error = %v, want it to name the missing exit", err)
		}
	})

	t.Run("exit with no reachable address", func(t *testing.T) {
		d := dirWith("")
		delete(d.exitAddr, exitID)
		delete(d.exitAddr, "aa")
		e := &Engine{cfg: Config{RelayHops: 2}, relayDir: d}
		// With no address for any exit, no last hop could be told where to send the
		// innermost layer — so there is no chain, and there must be no fallback.
		if _, err := e.buildChain(2, cc); err == nil {
			t.Fatal("built a chain to an exit with no known address; want an error")
		}
	})
}

// ---------- relay side: never an open proxy, never an exit ----------

// TestOnionForwardRefusesTargetOutsideTheDirectory is ADR-0038 principle #4. The
// next-hop address is attacker-chosen — anyone who can reach a hop can complete
// its handshake, since that needs only the hop's public key — so a hop that
// dialed whatever it was handed would be an open TCP proxy egressing under its
// operator's address. Only addresses in the SIGNED directory are admitted.
func TestOnionForwardRefusesTargetOutsideTheDirectory(t *testing.T) {
	// A listener standing in for the host an abuser would point the hop at. If the
	// hop dials it, the test sees the connection and fails.
	victim, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer victim.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := victim.Accept(); err == nil {
			dialed <- struct{}{}
			_ = c.Close()
		}
	}()

	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	// A directory that names some OTHER address, so the victim is genuinely absent
	// rather than the directory being trivially empty.
	dir := &relayDirectory{dialable: map[string]bool{"127.0.0.1:65000": true}}
	hopAddr := startForwardNode(t, key, dir)

	conn, err := net.Dial("tcp", hopAddr)
	if err != nil {
		t.Fatalf("dial hop: %v", err)
	}
	defer conn.Close()
	// A well-formed onion layer asking the hop to forward to the victim.
	nc, err := clientHandshake(conn, key.Public, hopTargetPrefix+victim.Addr().String(), nil)
	if err != nil {
		t.Fatalf("handshake with the hop: %v", err)
	}
	defer nc.Close()

	select {
	case <-dialed:
		t.Fatal("the hop dialed an address that is NOT in its signed directory — it is an open proxy")
	case <-time.After(500 * time.Millisecond):
	}
}

// TestRelayOnlyNodeRefusesInternetEgress is the relay/exit safety line. A node
// holding only the relay role runs the same accept loop an exit does (its onion
// ingress), so without an explicit role gate a bare target would make it dial the
// internet under its operator's address. It must refuse — including when the
// request comes from a hostile coordinator that assigned it a direct session.
func TestRelayOnlyNodeRefusesInternetEgress(t *testing.T) {
	victim, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer victim.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := victim.Accept(); err == nil {
			dialed <- struct{}{}
			_ = c.Close()
		}
	}()

	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	// The victim IS in the directory, so only the role gate can stop this: the point
	// is that a relay must not EGRESS even to a known address.
	dir := &relayDirectory{dialable: map[string]bool{victim.Addr().String(): true}}
	hopAddr := startForwardNode(t, key, dir)

	conn, err := net.Dial("tcp", hopAddr)
	if err != nil {
		t.Fatalf("dial hop: %v", err)
	}
	defer conn.Close()
	// A BARE target — "dial the internet" — not a hop: forwarding.
	nc, err := clientHandshake(conn, key.Public, victim.Addr().String(), nil)
	if err != nil {
		t.Fatalf("handshake with the relay: %v", err)
	}
	defer nc.Close()

	select {
	case <-dialed:
		t.Fatal("a relay-only node egressed to the internet; the relay/exit safety line is broken")
	case <-time.After(500 * time.Millisecond):
	}
}

// ---------- hop selection ----------

// TestSelectHopsSpreadsAcrossOperators pins the anti-correlation control: two
// hops of one chain must not sit in the same operator's subtree while a
// distinct-operator alternative exists, because controlling the first and last
// hop is what re-links client to exit.
func TestSelectHopsSpreadsAcrossOperators(t *testing.T) {
	cand := []relayHop{
		{id: "1", dial: "127.0.0.1:1", operator: "acme", pairable: true},
		{id: "2", dial: "127.0.0.1:2", operator: "acme"},
		{id: "3", dial: "127.0.0.1:3", operator: "acme"},
		{id: "4", dial: "127.0.0.1:4", operator: "globex"},
		{id: "5", dial: "127.0.0.1:5", operator: "initech"},
	}
	for i := 0; i < 40; i++ { // selection is randomized; the invariant must hold every time
		got, err := selectHops(cand, 3, "")
		if err != nil {
			t.Fatalf("selectHops: %v", err)
		}
		seen := map[string]bool{}
		for _, h := range got {
			if seen[h.operator] {
				t.Fatalf("two hops from operator %q in one chain: %v — a single operator can then correlate both ends", h.operator, got)
			}
			seen[h.operator] = true
		}
		if !got[0].pairable {
			t.Fatalf("chain head %+v is not pairable; the coordinator cannot wire a client to it", got[0])
		}
	}
}

// TestSelectHopsNeverReusesTheExitOrAHop keeps a chain from doubling back: a hop
// that is also the exit would see both sides of itself, and a repeated hop wastes
// a layer while adding no diversity.
func TestSelectHopsNeverReusesTheExitOrAHop(t *testing.T) {
	cand := []relayHop{
		{id: "exit", dial: "127.0.0.1:1", pairable: true},
		{id: "a", dial: "127.0.0.1:2", pairable: true},
		{id: "b", dial: "127.0.0.1:3"},
	}
	got, err := selectHops(cand, 2, "exit")
	if err != nil {
		t.Fatalf("selectHops: %v", err)
	}
	seen := map[string]bool{}
	for _, h := range got {
		if h.id == "exit" {
			t.Error("the chain routed through its own exit")
		}
		if seen[h.id] {
			t.Errorf("hop %q used twice in one chain", h.id)
		}
		seen[h.id] = true
	}
}

// TestSelectHopsHeadMustBePairable pins why the head is special: it is reached by
// being named in connect{ExitID}, so it has to be a node the coordinator can pair
// a client with. A directory whose only exit-registered node is excluded cannot
// produce a chain at all — and says so rather than returning an unusable one.
func TestSelectHopsHeadMustBePairable(t *testing.T) {
	cand := []relayHop{
		{id: "a", dial: "127.0.0.1:2"}, // relay-only: fine as a later hop, never the head
		{id: "b", dial: "127.0.0.1:3"},
	}
	if _, err := selectHops(cand, 1, ""); err == nil {
		t.Fatal("selected a chain head the coordinator cannot pair a client to; want an error")
	}
}

// ---------- configuration ----------

// TestSetupRelayChainingRefusesHalfConfiguration checks that every combination
// which would leave a node silently not doing what it was told is a construction
// error. A node that will not chain, or will not forward, must refuse to start
// and say why — the operator otherwise has no way to find out.
func TestSetupRelayChainingRefusesHalfConfiguration(t *testing.T) {
	client := map[string]bool{RoleClient: true}
	relay := map[string]bool{RoleRelay: true}
	now := time.Now()

	// Each case names the substring its OWN check produces. Asserting only "some
	// error" is what let the relay-role check be deleted with this test still green:
	// the case then failed later, inside loadRelayDirectory on an empty MeshPubKey,
	// and passed for a reason that had nothing to do with what it claims to pin.
	cases := map[string]struct {
		cfg   Config
		roles map[string]bool
		want  string
	}{
		"chaining with no directory":     {Config{RelayHops: 2}, client, "needs a signed relay directory"},
		"depth above the ceiling":        {Config{RelayHops: 5, RelayDirectory: []byte("x"), MeshPubKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}, client, "exceeds RelayHopsMax"},
		"ingress with no directory":      {Config{RelayIngress: "127.0.0.1:0", ExitKeyHex: testExitKeyHex}, relay, "requires RelayDirectory"},
		"ingress without the relay role": {Config{RelayIngress: "127.0.0.1:0", RelayDirectory: []byte("x")}, client, "requires the relay role"},
		"ingress with an ephemeral id":   {Config{RelayIngress: "127.0.0.1:0", RelayDirectory: []byte("x")}, relay, "requires ExitKeyHex"},
		"directory with no signing key":  {Config{RelayHops: 2, RelayDirectory: []byte("x")}, client, "snapshot public key"},
		"directory that does not verify": {Config{RelayHops: 2, RelayDirectory: []byte("not a snapshot"), MeshPubKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}, client, "relay directory"},
	}
	for name, c := range cases {
		_, err := setupRelayChaining(c.cfg, c.roles, now)
		if err == nil {
			t.Errorf("%s: started anyway; want a construction error so the operator finds out", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: refused with %q, want it to name %q — a case that fails for a different reason than it claims pins nothing", name, err, c.want)
		}
	}

	// And the case that must stay silent: a node doing neither.
	dir, err := setupRelayChaining(Config{}, client, now)
	if err != nil || dir != nil {
		t.Errorf("a node that neither chains nor forwards got (%v, %v); want (nil, nil) — today's fleet must be unaffected", dir, err)
	}
}

// testExitKeyHex is a fixed 32-byte X25519 private key for fixtures that need a
// STABLE node identity rather than a fresh one. It is a synthetic all-0x11 key that
// secures nothing and appears only in tests.
const testExitKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"

// TestChainDepthNormalizesTheFloorOnly pins what chainDepth does and — as much to
// the point — what it no longer does.
//
// 0 and 1 both mean today's single hop. Nothing is clamped DOWNWARD here any more:
// the RelayHopsMax ceiling is a refusal at construction (see
// TestNewRefusesAChainDeeperThanTheCeiling), because reducing a depth the operator
// asked for is the silent downgrade this feature must never produce. The old
// version of this test derived its expectation from RelayHopsMax itself, so raising
// the ceiling from 4 to 400 left it passing.
func TestChainDepthNormalizesTheFloorOnly(t *testing.T) {
	for in, want := range map[int]int{-5: 1, 0: 1, 1: 1, 2: 2, 3: 3, 4: 4} {
		if got := chainDepth(in); got != want {
			t.Errorf("chainDepth(%d) = %d, want %d", in, got, want)
		}
	}
	if got := chainDepth(9); got != 9 {
		t.Errorf("chainDepth(9) = %d, want 9 — chainDepth must not clamp; the ceiling is enforced once, at construction", got)
	}
}

// TestLoadRelayDirectoryRejectsExpired pins the freshness rule. Unlike the
// mesh-walk proof of prior contact — which is legitimately stale — a hop
// directory names nodes that are supposed to answer a dial right now, so an
// expired one is an error rather than a set of hops that will simply fail.
func TestLoadRelayDirectoryRejectsExpired(t *testing.T) {
	pub, priv := testSnapKeys(t)
	signed, err := coldstart.Sign(priv, coldstart.Snapshot{
		Version:   coldstart.SnapshotVersion,
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
		Entries:   []coldstart.Entry{{Role: "exit", ID: hex.EncodeToString(make([]byte, 32)), Addr: "127.0.0.1:1"}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := loadRelayDirectory(signed, pub, "", time.Now()); err == nil {
		t.Fatal("accepted an expired relay directory; hop selection against dead nodes only builds chains that fail")
	}
}

// TestLoadRelayDirectorySkipsUnusableEntries checks the indexing rules: a node
// whose id is not an X25519 key cannot be authenticated as a hop, and one with no
// dialable address cannot be reached — both are skipped rather than producing a
// hop that would fail mid-chain. Their addresses still join the forwarding
// allow-list, because they are legitimately part of the mesh.
func TestLoadRelayDirectorySkipsUnusableEntries(t *testing.T) {
	pub, priv := testSnapKeys(t)
	// Distinct ids. The unreachable entry used to reuse goodID, so "the surviving hop
	// is goodID" was satisfiable by keeping the WRONG entry — the assertion could not
	// tell the two apart.
	goodID := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	unreachableID := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	signed, err := coldstart.Sign(priv, coldstart.Snapshot{
		Version: coldstart.SnapshotVersion, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Entries: []coldstart.Entry{
			{Role: "exit", ID: goodID, Addr: "127.0.0.1:1"},
			{Role: "relay", ID: "not-a-key", Ingress: "127.0.0.1:2"}, // unauthenticatable
			{Role: "relay", ID: unreachableID},                       // no ingress: not reachable
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	dir, err := loadRelayDirectory(signed, pub, "", time.Now())
	if err != nil {
		t.Fatalf("loadRelayDirectory: %v", err)
	}
	if len(dir.hops) != 1 || dir.hops[0].id != goodID {
		t.Errorf("hops = %+v, want only the one entry that is both authenticatable and reachable", dir.hops)
	}
	if !dir.dialable["127.0.0.1:2"] {
		t.Error("an entry unusable as a HOP was dropped from the forwarding allow-list too; it is still a mesh node")
	}
}

// ---------- Start wiring: the ingress listener and what it advertises ----------

// TestRelayIngressIsBoundAndActuallyServed drives the real New+Start path for a
// relay that opted into carrying onion layers: the ingress listener must bind, the
// register must carry the port a hop's upstream will dial, and — the part its
// predecessor did not check — the port must be SERVED.
//
// It proves that by completing a real Noise_NK handshake against the advertised
// port and watching the layer come out the other side at the next hop. A bare
// net.Dial cannot: the kernel completes a TCP connection into a bound listener's
// accept backlog whether or not anything ever calls Accept, so binding the
// listener and never starting serveExit passed the old assertion unchanged.
func TestRelayIngressIsBoundAndActuallyServed(t *testing.T) {
	coord := fakeCoordinator(t)
	pub, priv := testSnapKeys(t)

	// The node this hop will be asked to splice to. A plain listener is enough: what
	// is under test is whether the hop forwards at all, not what the next node does.
	next, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("next-hop listen: %v", err)
	}
	defer next.Close()
	spliced := make(chan struct{}, 1)
	go func() {
		c, err := next.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
		spliced <- struct{}{}
	}()

	signed := signTestSnapshot(t, priv, []coldstart.Entry{
		{Role: "exit", ID: hex.EncodeToString(make([]byte, 32)), Addr: next.Addr().String()},
	})

	eng, err := New(Config{
		Coordinators:      []string{coord.LocalAddr().String()},
		Roles:             []string{"relay"},
		RelayIngress:      "127.0.0.1:0", // any free port, as an operator may ask for
		RelayDirectory:    signed,
		RelayDirectoryKey: pub,
		ExitKeyHex:        testExitKeyHex, // a hop needs a stable identity; see setupRelayChaining
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	m := readRegister(t, coord, 3*time.Second)
	if m.IngressPort == 0 {
		t.Fatal("a relay serving an onion ingress advertised no port; the coordinator cannot list it as a hop and no chain can ever use it")
	}
	// A relay hop's id must be its X25519 public key, or a client cannot run
	// Noise_NK against it and the hop is unauthenticatable (ADR-0038 §4.3).
	hopPub, err := hex.DecodeString(m.ID)
	if err != nil || len(hopPub) != 32 {
		t.Fatalf("relay hop id = %q, want a 64-hex X25519 public key", m.ID)
	}

	// Dial the ADVERTISED port — not the configured 0, and not the listener value —
	// and peel a layer at it exactly as an upstream hop would.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(m.IngressPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("advertised ingress port %d is not accepting connections: %v", m.IngressPort, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientHandshake(conn, hopPub, hopTargetPrefix+next.Addr().String(), nil); err != nil {
		t.Fatalf("the advertised ingress port is bound but not served: %v", err)
	}
	select {
	case <-spliced:
	case <-time.After(3 * time.Second):
		t.Fatal("the hop completed a handshake but never spliced onward to the next hop")
	}
}

// TestRelayIngressIdentityIsStableAcrossRestarts pins the other half of a hop's
// identity: it must not be regenerated per process.
//
// A hop's node id IS the key clients authenticate it against, and it is published
// in a signed directory clients cache. An identity derived fresh on each start
// would make the node unreachable as a hop until a new snapshot propagated — a
// node that looks intermittently broken rather than misconfigured. Two New() calls
// with the same config must produce the same id.
func TestRelayIngressIdentityIsStableAcrossRestarts(t *testing.T) {
	pub, priv := testSnapKeys(t)
	signed := signTestSnapshot(t, priv, []coldstart.Entry{
		{Role: "exit", ID: hex.EncodeToString(make([]byte, 32)), Addr: "203.0.113.9:20001"},
	})
	cfg := Config{
		Coordinators:      []string{"127.0.0.1:1"},
		Roles:             []string{"relay"},
		RelayIngress:      "127.0.0.1:0",
		RelayDirectory:    signed,
		RelayDirectoryKey: pub,
		ExitKeyHex:        testExitKeyHex,
	}
	first, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, err := New(cfg)
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	if first.cfg.ID != second.cfg.ID {
		t.Errorf("a forwarding relay's id changed across a restart (%s -> %s); every client holding a cached directory would fail its handshake against this node until a fresh snapshot propagated",
			shortID(first.cfg.ID), shortID(second.cfg.ID))
	}
}

// TestRelayWithoutIngressAdvertisesNoPort is the other half of opt-in: a relay
// that did not ask to carry onion layers sends exactly the register it sent
// before this feature existed, and opens no port. Today's fleet is untouched.
func TestRelayWithoutIngressAdvertisesNoPort(t *testing.T) {
	coord := fakeCoordinator(t)
	eng, err := New(Config{Coordinators: []string{coord.LocalAddr().String()}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	m := readRegister(t, coord, 3*time.Second)
	if m.IngressPort != 0 {
		t.Errorf("register IngressPort = %d, want 0 for a relay that opted into nothing", m.IngressPort)
	}
	// And its id stays the opaque random one, so no existing relay's identity moves.
	if raw, err := hex.DecodeString(m.ID); err == nil && len(raw) == 32 {
		t.Errorf("a plain relay's id became an X25519 key (%q); existing relay identities must not change", m.ID)
	}
}
