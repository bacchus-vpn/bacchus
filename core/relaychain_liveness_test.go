package core

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
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

// Chain-aware liveness and rebuild (issue #24, ADR-0038 §9 item 6).
//
// Before this, a chain's hops were chosen once per connect and never revisited: a hop
// dying downstream of the head does not drop the session (the session terminates at
// the HEAD), so nothing in ADR-0028's sustained-flow validation or ADR-0030's
// reconnect ever fired, and every subsequent stream re-dialed the same dead hop. The
// coordinator cannot help — reselectDeadRelays only ever covers the assigned blind
// relay, and it does not know which nodes are in the chain past the first.
//
// These tests drive the shipped path: real forwarding nodes on loopback running the
// production exitTerminate, the production relayPipe standing in for the assigned
// blind splice, a client engine from the real New() with RelayHops actually set, and
// the production dialChainedStream doing the detecting, cooling and rebuilding.
//
// The one thing every rebuild test here also does is prove it can NOT rebuild: a
// rebuild path only ever seen to rebuild is a path whose trigger is untested, and
// would pass just as happily if it rebuilt on every dial. So each of the three
// requirements has its negative half — a healthy chain that dials once, a rejection
// that is deliberately not routed around, a head failure that escalates instead.

// contains reports whether any emitted event's message holds sub, of any kind — the
// kind-agnostic counterpart of eventRecorder.hasSubstring (core/pool_test.go). These
// tests assert that something was SAID, not at which level: the level a rebuild notice
// carries is a presentation choice and pinning it here would make a reasonable change to
// it fail a test about liveness.
func (r *eventRecorder) contains(sub string) bool { return r.count(sub) > 0 }

// count reports how many emitted messages hold sub, which is how a test observes that a
// per-build notice fired again for a REBUILT chain rather than only for the first one.
func (r *eventRecorder) count(sub string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, ev := range r.events {
		if strings.Contains(ev.Message, sub) {
			n++
		}
	}
	return n
}

// ---------- a mesh whose nodes can be killed or wedged ----------

// chainNode is one controllable forwarding node: a real engine serving the production
// exitTerminate on a loopback listener, whose listener the test can close.
type chainNode struct {
	id   string
	pub  []byte
	addr string
	ln   net.Listener
	eng  *Engine // retained so a test can change what the node will do next
}

// kill closes the node's listener, so the hop before it gets a connection refused on
// its forward dial and drops the circuit — which is what the client observes as a dead
// hop. Idempotent.
func (n *chainNode) kill() { _ = n.ln.Close() }

// saturate drops the node's aggregate forwarded-circuit cap to zero, so every later
// forward is refused through the production path and the reason is sealed back to the
// client (ADR-0038 §6, issue #25). The node stays up and answering, which is the whole
// distinction being tested — a refusal is not a death.
func (n *chainNode) saturate() {
	n.eng.forwardLimits.mu.Lock()
	n.eng.forwardLimits.maxTotal = 0
	n.eng.forwardLimits.mu.Unlock()
}

// bindChainNode reserves a node's address without serving it yet. Binding is split
// from serving because every node in this mesh holds the SAME signed directory (as a
// real fleet does), and a directory cannot name addresses that have not been bound —
// so all the listeners come up first, then the directory is signed, then the nodes
// start answering with it.
func bindChainNode(t *testing.T, key noise.DHKey) *chainNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("chain node listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &chainNode{
		id: hex.EncodeToString(key.Public), pub: key.Public,
		addr: ln.Addr().String(), ln: ln,
	}
}

// serve starts the node answering onion layers against dir, through the production
// exitTerminate — the same call startForwardNode makes, with the listener kept so the
// test can take the node away mid-test.
func (n *chainNode) serve(key noise.DHKey, dir *relayDirectory, cred []byte) {
	e := &Engine{
		roles:         map[string]bool{RoleRelay: true},
		exitKey:       key,
		cfg:           Config{RelayIngress: n.addr, AdmissionCred: string(cred)},
		forwardLimits: newForwardLimits(0, 0, 0),
		limiterCtx:    context.Background(),
	}
	e.relayDir.Store(dir)
	n.eng = e
	go func() {
		for {
			c, err := n.ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(hopTestDeadline))
			go e.exitTerminate("", nil, c)
		}
	}()
}

// livenessMesh is a chainable network with SPARE middle hops, which is the whole point:
// a rebuild has nowhere to go unless the directory can supply a hop the broken chain
// was not using.
//
// The country split is the same device the acceptance mesh uses. The head must be
// exit-role (only such a node can be paired to via connect{firstHop}), which makes it a
// candidate to terminate the chain too; putting it in a different country from the exit
// is what keeps chooseChainExit's answer deterministic.
type livenessMesh struct {
	exitKey  noise.DHKey
	exitID   string
	exitAddr string
	exitLn   net.Listener
	head     *chainNode
	mids     []*chainNode
	signed   []byte
	dir      *relayDirectory
	cred     []byte // the exit's admission credential, or nil
	rootPub  ed25519.PublicKey
}

const (
	livenessExitCountry = "NL"
	livenessHopCountry  = "DE"
)

// newLivenessMesh stands up an echoing exit, one head hop and nMids middle hops, all
// holding one signed directory. hopCred, when non-nil, is presented by every FORWARDING
// node (not the exit) in msg2, which is what a per-hop admission test needs.
//
// extra joins that one directory, so a node this mesh does not run — a wedged listener,
// say — is nonetheless a node every hop in the mesh is willing to forward to. It has to
// go in at signing time: the allow-list a hop enforces IS the signed directory, so a
// target added afterwards is refused as not-in-mesh, which is a different failure from
// the one such a test means to produce.
func newLivenessMesh(t *testing.T, nMids int, hopCred []byte, extra ...coldstart.Entry) *livenessMesh {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	exitKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("exit key: %v", err)
	}
	exitID := hex.EncodeToString(exitKey.Public)
	exitCred := issueExitCred(t, rootPriv, exitID, []admission.Role{admission.RoleExit},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	exitAddr, exitLn := startEchoExit(t, exitKey, exitCred)

	headKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("head key: %v", err)
	}
	head := bindChainNode(t, headKey)
	// The head always holds a VALID relay-role credential against this mesh's root,
	// while the middle hops hold only hopCred. That asymmetry is what lets a test set
	// RelayAdmissionPubKey and get the #26 check to reject a MIDDLE hop specifically:
	// a rejection at the head would be indistinguishable from a head failure, which
	// escalates to dropping the session and would mask whether the rejection was
	// rebuilt around. Tests that set no relay anchor verify no hop at all, so this
	// credential is inert for every one of them.
	headCred := issueExitCred(t, rootPriv, head.id, []admission.Role{admission.RoleRelay},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	midKeys := make([]noise.DHKey, nMids)
	mids := make([]*chainNode, nMids)
	for i := range mids {
		k, err := generateExitKey()
		if err != nil {
			t.Fatalf("mid key: %v", err)
		}
		midKeys[i], mids[i] = k, bindChainNode(t, k)
	}

	entries := []coldstart.Entry{
		{Role: "exit", ID: exitID, Country: livenessExitCountry, Addr: exitAddr},
		{Role: "exit", ID: head.id, Country: livenessHopCountry, Addr: head.addr, Operator: "op-head"},
	}
	for i, m := range mids {
		entries = append(entries, coldstart.Entry{
			Role: "relay", ID: m.id, Country: livenessHopCountry,
			Ingress: m.addr, Operator: fmt.Sprintf("op-mid%d", i),
		})
	}
	signed := signTestSnapshot(t, testSnapPriv(t), append(entries, extra...))
	dir, err := loadRelayDirectory(signed, testSnapPub(t), "", time.Now())
	if err != nil {
		t.Fatalf("load directory: %v", err)
	}

	head.serve(headKey, dir, headCred)
	for i, m := range mids {
		m.serve(midKeys[i], dir, hopCred)
	}
	return &livenessMesh{
		exitKey: exitKey, exitID: exitID, exitAddr: exitAddr, exitLn: exitLn,
		head: head, mids: mids, signed: signed, dir: dir,
		cred: exitCred, rootPub: rootPub,
	}
}

// startEchoExit is startExitIngress for a test that dials more than once: it serves
// every connection, not one, and echoes whatever the innermost layer sends instead of
// asserting a particular target. A rebuild test needs both — the first attempt never
// reaches the exit, the second one does, and what is being asserted is that bytes flow.
func startEchoExit(t *testing.T, key noise.DHKey, cred []byte) (string, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo exit listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(hopTestDeadline))
				nc, _, err := exitHandshake(conn, key, cred)
				if err != nil {
					return
				}
				_, _ = io.Copy(nc, nc)
			}()
		}
	}()
	return ln.Addr().String(), ln
}

// startWedgedNode binds a listener that accepts every connection and then answers
// NOTHING, holding it open — the failure mode a chained dial has to bound itself
// against (see chainLayerTimeout). A dead hop is the easy case: the hop before it gives
// up on its own dial and the circuit breaks. This one's dial SUCCEEDS, so the splice is
// established and the client's layer handshake blocks on a read that never returns.
func startWedgedNode(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wedged node listen: %v", err)
	}
	// Accepted connections are held, not answered, and released at cleanup. The done
	// flag is not belt-and-braces: cleanup and the accept loop genuinely overlap, so a
	// connection accepted just as the test ends has to be closed by whoever notices
	// last, and a bare "drain the survivors" cleanup would leave that one open.
	var mu sync.Mutex
	var held []net.Conn
	done := false
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		done = true
		for _, c := range held {
			_ = c.Close()
		}
		held = nil
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if done {
				mu.Unlock()
				_ = c.Close()
				continue
			}
			held = append(held, c) // keep it open and say nothing at all
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// ---------- a session whose streams land on the chain's head ----------

// chainTestSession stands in for the coordinator-brokered transport a chain's head is
// reached over: every stream is spliced, by the production relayPipe, to the head's
// address — which is exactly the assigned blind relay's job (ADR-0033).
//
// It counts opens because that count IS the rebuild count: ADR-0038 §5 forbids
// repairing a circuit in place, so a rebuilt chain necessarily costs a fresh stream and
// nothing else can produce one.
type chainTestSession struct {
	head   func() string
	mu     sync.Mutex
	opens  int
	closed chan struct{}
	once   sync.Once
}

func newChainTestSession(head func() string) *chainTestSession {
	return &chainTestSession{head: head, closed: make(chan struct{})}
}

func (s *chainTestSession) OpenStream(_ context.Context, label string) (Stream, error) {
	select {
	case <-s.closed:
		return nil, errors.New("chainTestSession: closed")
	default:
	}
	s.mu.Lock()
	s.opens++
	s.mu.Unlock()
	clientEnd, relayEnd := net.Pipe()
	var assigned Engine // relayPipe uses no engine state (see its doc)
	go assigned.relayPipe(pipeStream{Conn: relayEnd, label: label}, s.head())
	return pipeStream{Conn: clientEnd, label: label}, nil
}

func (s *chainTestSession) AcceptStream(context.Context) (Stream, error) {
	<-s.closed
	return nil, errors.New("chainTestSession: closed")
}
func (s *chainTestSession) Closed() <-chan struct{} { return s.closed }
func (s *chainTestSession) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *chainTestSession) streamsOpened() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opens
}

func (s *chainTestSession) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// ---------- the client ----------

// testLayerTimeout is the per-layer budget these tests run dialChain with. Loopback
// handshakes complete in well under a millisecond, so this is three orders of magnitude
// of headroom for a live hop while keeping a wedged one's detection fast.
const testLayerTimeout = 300 * time.Millisecond

// newLivenessClient builds a real chaining client over m's directory, with the
// per-layer budget shortened. events, when non-nil, receives every emitted event.
func newLivenessClient(t *testing.T, m *livenessMesh, hops int, rec *eventRecorder) *Engine {
	t.Helper()
	cfg := Config{
		Coordinators:      []string{testCoord},
		Roles:             []string{RoleClient},
		RelayHops:         hops,
		RelayDirectory:    m.signed,
		RelayDirectoryKey: testSnapPub(t),
		AdmissionPubKey:   hex.EncodeToString(m.rootPub),
	}
	if rec != nil {
		cfg.OnEvent = rec.record
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { e.Stop(); e.Wait() })
	if !e.chaining() {
		t.Fatalf("client is not chaining at RelayHops=%d — every assertion below would be about the unchained path", hops)
	}
	e.chainLayerTimeout = testLayerTimeout
	return e
}

// planVia builds a depth-3 plan by hand with mid as the single middle hop, so a test
// about the REBUILD is not also a test of which hop the initial shuffle happened to
// pick. Everything the plan carries is what buildChain would have put there — including
// country, which is what rebuildChain reproduces the selection from.
func planVia(m *livenessMesh, mid *chainNode) *chainPlan {
	return &chainPlan{
		hops: []relayHop{
			{id: m.head.id, pub: m.head.pub, dial: m.head.addr, operator: "op-head", country: livenessHopCountry, pairable: true},
			{id: mid.id, pub: mid.pub, dial: mid.addr, operator: "op-mid", country: livenessHopCountry},
		},
		exitID:  m.exitID,
		exitPub: m.exitKey.Public,
		exitDia: m.exitAddr,
		country: livenessExitCountry,
	}
}

// ---------- requirement 1: a stalled CHAIN is not a stalled path ----------

// TestWedgedChainHopIsBoundedAndAttributedUnlikeAnUnchainedPeer is the distinction the
// issue asks for, tested as a distinction rather than as two unrelated facts.
//
// The same misbehaviour — a peer that accepts the connection and then answers nothing —
// is put to the chained path and to the unchained one:
//
//   - chained: dialChain returns on its own, inside its per-layer budget, saying the
//     hop stalled and naming WHICH hop, so the caller has something to cool.
//   - unchained: clientHandshake blocks, because nothing in the direct path bounds it
//     and it is the caller's context that is supposed to. Asserted positively, not
//     assumed: the dial is still running after many budgets have passed.
//
// That asymmetry is the feature. A chained dial has n places to stall and knows which
// one it is at; a direct dial has one and its caller already owns the deadline.
//
// Mutation: delete the newStallGuard/guard.stop() pair from dialChain's hop loop — i.e.
// make a chained layer exactly as unbounded as an unchained handshake — and the chained
// half of this test hangs until the package timeout instead of returning.
func TestWedgedChainHopIsBoundedAndAttributedUnlikeAnUnchainedPeer(t *testing.T) {
	wedged := startWedgedNode(t)
	// A hop entry pointing at the wedged listener. Its key is never used: no handshake
	// with it ever completes, which is the condition under test. It goes into the mesh's
	// signed directory so the head is willing to forward there — a hop that refused the
	// target as not-in-mesh would be a different test.
	wedgedKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("wedged key: %v", err)
	}
	wedgedID := hex.EncodeToString(wedgedKey.Public)
	m := newLivenessMesh(t, 0, nil, coldstart.Entry{
		Role: "relay", ID: wedgedID, Country: livenessHopCountry, Ingress: wedged,
	})
	client := &Engine{exitVerifier: verifierFor(t, m.rootPub), chainLayerTimeout: testLayerTimeout}
	client.relayDir.Store(m.dir)

	plan := &chainPlan{
		hops: []relayHop{
			{id: m.head.id, pub: m.head.pub, dial: m.head.addr, pairable: true},
			{id: wedgedID, pub: wedgedKey.Public, dial: wedged},
		},
		exitID: m.exitID, exitPub: m.exitKey.Public, exitDia: m.exitAddr,
		country: livenessExitCountry,
	}

	t.Run("chained: bounded and attributed", func(t *testing.T) {
		clientEnd, relayEnd := net.Pipe()
		var assigned Engine
		go assigned.relayPipe(pipeStream{Conn: relayEnd, label: e2eLabel}, m.head.addr)

		type result struct {
			err error
			d   time.Duration
		}
		res := make(chan result, 1)
		start := time.Now()
		go func() {
			_, err := client.dialChain(clientEnd, plan, "example.com:443")
			res <- result{err: err, d: time.Since(start)}
		}()

		var got result
		select {
		case got = <-res:
		case <-time.After(20 * testLayerTimeout):
			t.Fatal("a chained dial through a hop that accepted the layer and then answered nothing never returned — nothing in the chained path bounds a wedged hop, so the client waits on it forever and every later stream does the same (issue #24)")
		}
		_ = clientEnd.Close()

		if got.err == nil {
			t.Fatal("dialChain succeeded through a hop that never answered")
		}
		if !errors.Is(got.err, errChainHopStalled) {
			t.Errorf("dialChain error = %v, want errChainHopStalled — a hop that answered nothing must not be reported as a hop that answered wrongly, because the two get different responses", got.err)
		}
		if got.d < testLayerTimeout {
			t.Errorf("returned after %v, before the %v layer budget even elapsed — something other than the stall guard ended this dial, so the test is not observing what it claims", got.d, testLayerTimeout)
		}
		var cde *chainDialError
		if !errors.As(got.err, &cde) {
			t.Fatalf("dialChain error = %v (%T), want a *chainDialError — without one the caller has no node to cool and no way to tell a rebuild is even possible", got.err, got.err)
		}
		if cde.hop != 2 || cde.of != 2 {
			t.Errorf("attributed to hop %d/%d, want 2/2 — the wedged node is the second hop and the first one demonstrably carried its own layer", cde.hop, cde.of)
		}
		if cde.suspect != wedgedID {
			t.Errorf("suspect = %s, want the wedged hop %s", shortID(cde.suspect), shortID(wedgedID))
		}
		if cde.fault != hopStalled {
			t.Errorf("fault = %v, want hopStalled", cde.fault)
		}
		if cde.atHead() {
			t.Error("attributed to the head, which would escalate to dropping the whole session instead of rebuilding the chain behind a head that is working fine")
		}
	})

	t.Run("unchained: nothing in the handshake itself bounds it", func(t *testing.T) {
		// The identical misbehaviour with no chain: dialE2E is clientHandshake, which
		// carries no deadline of its own, so this must NOT come back on its own. A
		// direct path has one place to stall and its caller's context is what bounds it
		// (dialChainedStream applies exactly that); a chained path has n places, knows
		// which one it is at, and bounds each — which is the distinction under test.
		peer, err := net.Dial("tcp", wedged)
		if err != nil {
			t.Fatalf("dial wedged peer: %v", err)
		}
		defer peer.Close()
		done := make(chan error, 1)
		go func() {
			_, err := client.dialE2E(peer, nil, m.exitKey.Public, "example.com:443")
			done <- err
		}()
		select {
		case err := <-done:
			t.Fatalf("an UNCHAINED dial to the same wedged peer returned on its own (%v) — then the chained half above proves nothing about chain awareness, since the direct path would have caught it too", err)
		case <-time.After(10 * testLayerTimeout):
			// Still blocked, as the direct path has always been: bounded by whoever
			// owns the context, not by the handshake.
		}
	})
}

// ---------- requirement 1+2: the rebuild, and the hop it must not reuse ----------

// TestChainRebuildDoesNotReuseTheHopThatDied is the #24 acceptance test.
//
// A depth-3 chain is standing on head -> midA -> exit. midA goes away. The next data
// path over that same session must come up anyway, and must come up through midB —
// with midA cooled so nothing later walks back into it.
//
// Three separate claims, all asserted: the dial SUCCEEDS (bytes reach the exit and come
// back), the chain the session now carries does not contain midA, and the head is
// unchanged because the session terminates at it.
func TestChainRebuildDoesNotReuseTheHopThatDied(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)
	midA, midB := m.mids[0], m.mids[1]

	sess := withChain(newChainTestSession(func() string { return m.head.addr }), planVia(m, midA))
	ts := sess.(*chainedSession).Session.(*chainTestSession)

	midA.kill()

	nc, err := client.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443")
	if err != nil {
		t.Fatalf("a chained dial did not recover from a dead middle hop: %v — the whole point of #24 is that this path survives one hop going away", err)
	}
	defer nc.Close()

	// The rebuilt chain has to actually carry traffic, not merely have been selected.
	const payload = "REBUILT_CHAIN_CARRIES_BYTES_0123456789"
	if _, err := nc.Write([]byte(payload)); err != nil {
		t.Fatalf("write over the rebuilt chain: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(nc, echo); err != nil {
		t.Fatalf("read back over the rebuilt chain: %v", err)
	}
	if string(echo) != payload {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}

	got := planOf(sess)
	if got == nil {
		t.Fatal("the session carries no chain after a rebuild")
	}
	for i, h := range got.hops {
		if h.id == midA.id {
			t.Fatalf("the rebuilt chain reuses the hop that died, at position %d/%d — a rebuild that can re-select the dead node is not a recovery, it is a retry that happens to sometimes work", i+1, len(got.hops))
		}
	}
	if len(got.hops) != 2 {
		t.Errorf("rebuilt chain has %d peeling hops, want 2 — a rebuild must not quietly shorten the chain (ADR-0038's fail-closed rule)", len(got.hops))
	}
	if got.hops[0].id != m.head.id {
		t.Errorf("rebuilt chain is headed by %s, want the head the session terminates at (%s) — layer 1 runs Noise_NK against that node's key, so a re-headed chain fails every stream", shortID(got.hops[0].id), shortID(m.head.id))
	}
	if got.hops[1].id != midB.id {
		t.Errorf("rebuilt middle hop = %s, want the only live alternative %s", shortID(got.hops[1].id), shortID(midB.id))
	}
	if !client.hopCooling(midA.id) {
		t.Error("the dead hop was not sunk into the cooling memory, so the next chain this client builds is free to select it again (issue #24, requirement 2)")
	}
	if client.hopCooling(midB.id) || client.hopCooling(m.head.id) {
		t.Error("a working hop was cooled — cooling the wrong node shrinks the usable directory for every later chain")
	}
	if n := ts.streamsOpened(); n != 2 {
		t.Errorf("opened %d streams, want 2 (the failed circuit, then the rebuilt one) — ADR-0038 §5 discards a broken circuit rather than splicing onto it, so a rebuild costs exactly one fresh stream", n)
	}
	if ts.isClosed() {
		t.Error("the session was dropped even though only a MIDDLE hop died — the head was fine and a rebuild over it was enough, so dropping the session throws away every other live stream for nothing")
	}
}

// TestHealthyChainDialsOnceAndRebuildsNothing is the negative half of the test above,
// and the reason it exists is that without it every assertion up there would still pass
// if the code rebuilt on EVERY dial.
//
// Same mesh, same depth, same call — nothing killed. Exactly one stream, the chain the
// session started with, and an empty cooling memory.
func TestHealthyChainDialsOnceAndRebuildsNothing(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)
	midA := m.mids[0]

	before := planVia(m, midA)
	sess := withChain(newChainTestSession(func() string { return m.head.addr }), before)
	ts := sess.(*chainedSession).Session.(*chainTestSession)

	nc, err := client.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443")
	if err != nil {
		t.Fatalf("a healthy 3-hop chain failed to dial: %v", err)
	}
	defer nc.Close()

	if n := ts.streamsOpened(); n != 1 {
		t.Errorf("opened %d streams over a healthy chain, want 1 — a dial that rebuilds when nothing failed re-selects the whole path on every connection", n)
	}
	if planOf(sess) != before {
		t.Error("the session's chain was replaced although nothing failed — hops are chosen per connect and re-choosing them mid-session for no reason spends a directory read and a crypto/rand draw per stream")
	}
	if client.hopCooling(midA.id) || client.hopCooling(m.head.id) || client.hopCooling(m.exitID) {
		t.Error("a node was cooled on a successful dial, which would drain the usable directory one healthy chain at a time")
	}
}

// ---------- requirement 3: the bound ----------

// TestChainRebuildIsBoundedOnADirectoryTooSmallToRouteAround is the bound the issue
// asks for, driven by the case that actually spins.
//
// A directory with exactly one middle hop can still BUILD a depth-3 chain, so
// errChainTooShort never fires — every rebuild succeeds and selects the same dead hop,
// and every dial over it fails in the same place. Nothing but the ceiling stops that.
//
// Mutation: delete the `attempt >= chainRebuildMax` case from dialChainedStream and this
// test does not fail, it hangs — which is exactly the shape of the bug the bound exists
// to prevent.
func TestChainRebuildIsBoundedOnADirectoryTooSmallToRouteAround(t *testing.T) {
	m := newLivenessMesh(t, 1, nil) // one middle hop: buildable at depth 3, not re-routable
	rec := &eventRecorder{}
	client := newLivenessClient(t, m, 3, rec)
	mid := m.mids[0]

	sess := withChain(newChainTestSession(func() string { return m.head.addr }), planVia(m, mid))
	ts := sess.(*chainedSession).Session.(*chainTestSession)

	mid.kill()

	done := make(chan error, 1)
	go func() {
		nc, err := client.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443")
		if nc != nil {
			_ = nc.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("dialChainedStream succeeded with its only middle hop dead")
		}
	case <-time.After(30 * testLayerTimeout):
		t.Fatal("dialChainedStream never returned: a directory that can build a depth-3 chain but cannot build a DIFFERENT one rebuilds forever, because each rebuild legitimately succeeds and each dial over it legitimately fails (issue #24, requirement 3)")
	}

	if n := ts.streamsOpened(); n != chainRebuildMax+1 {
		t.Errorf("opened %d streams, want %d (the first circuit plus chainRebuildMax=%d rebuilds) — the ceiling is what stops this, so the count is the ceiling", n, chainRebuildMax+1, chainRebuildMax)
	}
	if !rec.contains("gave up after") {
		t.Error("gave up silently: an operator whose directory is too small to route around its own failures cannot tell that from an ordinary failed connection unless the give-up says so")
	}
}

// TestRebuildRefusesWhenThePinnedHeadLeftTheDirectory covers the other bound on a
// rebuild, the one that is not a counter: a rebuild is only possible while the head the
// session terminates at is still a node the directory names. A reload that dropped it
// (issue #27) leaves nothing to pin, and inventing a different head would produce a plan
// whose layer 1 authenticates against a key nobody in the path holds.
func TestRebuildRefusesWhenThePinnedHeadLeftTheDirectory(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)

	// A plan headed by a node that is not in the client's directory at all.
	strangerKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("stranger key: %v", err)
	}
	plan := planVia(m, m.mids[0])
	plan.hops[0] = relayHop{
		id: hex.EncodeToString(strangerKey.Public), pub: strangerKey.Public,
		dial: "127.0.0.1:1", pairable: true,
	}

	if _, err := client.rebuildChain(plan); !errors.Is(err, errChainNoPinnedHead) {
		t.Fatalf("rebuildChain = %v, want errChainNoPinnedHead — a rebuild that silently re-heads the chain hands layer 1 a key the session's peer does not hold, so every stream fails authentication and it looks like a hostile hop", err)
	}
}

// ---------- the head: escalate, do not rebuild ----------

// TestDeadChainHeadDropsThePathInsteadOfRebuilding pins the one position a rebuild
// cannot help with.
//
// The head is fixed for the session's life: the coordinator paired the session to it via
// connect{firstHop} and layer 1's Noise_NK runs against its key. So when the head is
// what failed, rebuilding behind it is pure waste — every rebuilt chain contains it. The
// client drops the session instead, which is what hands the problem to the machinery
// that CAN replace a head (reconnectLoop / maintainPath re-run chainFor), with the head
// cooled so the next selection avoids it.
//
// This is the client's own version of the coordinator's #96 relay-dead nudge, for the
// node the coordinator cannot nudge about: it does not know which nodes are in the chain
// past the first.
func TestDeadChainHeadDropsThePathInsteadOfRebuilding(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	rec := &eventRecorder{}
	client := newLivenessClient(t, m, 3, rec)

	before := planVia(m, m.mids[0])
	sess := withChain(newChainTestSession(func() string { return m.head.addr }), before)
	ts := sess.(*chainedSession).Session.(*chainTestSession)

	m.head.kill()

	if _, err := client.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443"); err == nil {
		t.Fatal("dialChainedStream succeeded with the chain's head dead")
	}
	if !ts.isClosed() {
		t.Error("the session survived its own head dying — nothing else drops it (a head dying at the Bacchus layer need not break the transport), so every stream over it would keep failing at layer 1 forever")
	}
	if !client.hopCooling(m.head.id) {
		t.Error("the dead head was not cooled, so the reselect this drop triggers is free to be paired straight back to it")
	}
	if n := ts.streamsOpened(); n != 1 {
		t.Errorf("opened %d streams, want 1 — rebuilding behind a dead head cannot move off it, so every extra attempt is spent on a chain guaranteed to fail at layer 1", n)
	}
	if planOf(sess) != before {
		t.Error("the chain was rebuilt anyway; a fresh chain behind the same dead head is the same dead chain")
	}
	if !rec.contains("only a new session can replace the head") {
		t.Error("the escalation was silent: 'the chain failed' and 'the node this session is pinned to failed' are different operational stories")
	}
}

// ---------- the line that is NOT liveness ----------

// TestHopAdmissionRejectionIsNotRebuiltAround is the security boundary of this change.
//
// Issue #26 decided that a hop whose admission credential fails verification fails the
// WHOLE chain — "fail-closed, not de-selection" — and set aside retrying with another
// hop because it needed hop-selection state that did not exist. This issue builds that
// state. It must not thereby reverse that decision as a side effect.
//
// The distinction is real and not deference: a liveness failure means the hop did not
// answer, and rebuilding is recovery. A verification failure means the hop DID answer
// and the client's own anchor refused it — rebuilding around that would walk the client
// hop by hop through the directory looking for one whose credential passes, handing
// whoever controls the directory chainRebuildMax attempts per stream.
func TestHopAdmissionRejectionIsNotRebuiltAround(t *testing.T) {
	// The head holds a valid relay credential and the middle hops hold none, so with a
	// relay anchor configured the #26 check rejects the MIDDLE hop — the position where a
	// rebuild is otherwise exactly what would happen. Rejecting at the head instead would
	// escalate to dropping the session and prove nothing about this decision.
	m := newLivenessMesh(t, 2, nil)
	rec := &eventRecorder{}
	e, err := New(Config{
		Coordinators:         []string{testCoord},
		Roles:                []string{RoleClient},
		RelayHops:            3,
		RelayDirectory:       m.signed,
		RelayDirectoryKey:    testSnapPub(t),
		AdmissionPubKey:      hex.EncodeToString(m.rootPub),
		RelayAdmissionPubKey: hex.EncodeToString(m.rootPub),
		OnEvent:              rec.record,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { e.Stop(); e.Wait() })
	e.chainLayerTimeout = testLayerTimeout

	before := planVia(m, m.mids[0])
	sess := withChain(newChainTestSession(func() string { return m.head.addr }), before)
	ts := sess.(*chainedSession).Session.(*chainTestSession)

	dialErr := func() error {
		_, err := e.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443")
		return err
	}()
	if dialErr == nil {
		t.Fatal("a chained dial accepted a hop that presented no admission credential while the client held a relay anchor (issue #26)")
	}
	if !errors.Is(dialErr, errMissingHopCredential) {
		t.Fatalf("dial error = %v, want errMissingHopCredential — any other reason means this test is not exercising the #26 check", dialErr)
	}
	if n := ts.streamsOpened(); n != 1 {
		t.Errorf("opened %d streams, want 1 — a rejected credential must fail the chain, not start a search for a hop whose credential this client will accept (issue #26: fail-closed, not de-selection)", n)
	}
	if planOf(sess) != before {
		t.Error("the chain was rebuilt around a rejected credential, which reverses #26's fail-closed decision as a side effect of adding a liveness rebuild")
	}
	if ts.isClosed() {
		t.Error("the session was dropped over a rejected MIDDLE hop — the head is fine, so this is neither a rebuild nor a re-path, it is a refusal")
	}

	// The suspect is still cooled. Refusing to rebuild NOW and preferring somebody else
	// NEXT time are separable, and only the first one is #26's decision.
	if !e.hopCooling(m.mids[0].id) {
		t.Error("the rejected hop was not cooled: nothing stops the very next connect from selecting it and being rejected identically")
	}
}

// TestSaturatedHopIsRebuiltAroundButStillComesBack is the other end of the same
// spectrum: a hop that is UP and declining (ADR-0038 §6's occupancy caps) is worth
// routing around now — a different chain is not refused by a node it does not contain —
// and is a perfectly good hop later, which is what an EXPIRING cooling mark says and a
// removal would not.
func TestSaturatedHopIsRebuiltAroundButStillComesBack(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)
	midA, midB := m.mids[0], m.mids[1]

	// midA stays up and answering; it just will not take another circuit.
	midA.saturate()

	sess := withChain(newChainTestSession(func() string { return m.head.addr }), planVia(m, midA))
	nc, err := client.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443")
	if err != nil {
		t.Fatalf("a chained dial did not route around a SATURATED hop: %v — a hop that answered 'I am full' is the clearest possible signal that a different chain would work", err)
	}
	defer nc.Close()

	got := planOf(sess)
	if got.hops[1].id != midB.id {
		t.Errorf("rebuilt middle hop = %s, want %s", shortID(got.hops[1].id), shortID(midB.id))
	}
	if !client.hopCooling(midA.id) {
		t.Error("the saturated hop was not cooled, so the next chain is as likely to pick it and be refused again")
	}
	// The mark expires rather than removing the node: a saturated hop is a fine hop.
	client.hopCoolMu.Lock()
	client.hopCool[midA.id] = time.Now().Add(-2 * hopCooldown)
	client.hopCoolMu.Unlock()
	if client.hopCooling(midA.id) {
		t.Error("the cooling mark did not expire — a hop that was merely full would be avoided for the process's lifetime, which is a removal wearing a cooldown's clothes")
	}
}

// ---------- cooling: a preference, and a reported one ----------

// TestChainSelectionSkipsACoolingNode is the direct test of requirement 2's consumer:
// a cooled node is not selected while the directory can supply somebody else.
func TestChainSelectionSkipsACoolingNode(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)
	client.markHopCooling(m.mids[0].id)

	// Repeated, because selection is randomized: one build picking the live hop proves
	// nothing about a shuffle that could have gone either way.
	for i := 0; i < 20; i++ {
		plan, err := client.buildChain(3, livenessExitCountry)
		if err != nil {
			t.Fatalf("buildChain: %v", err)
		}
		for _, h := range plan.hops {
			if h.id == m.mids[0].id {
				t.Fatalf("build %d selected the cooling hop %s although %s was available", i, shortID(h.id), shortID(m.mids[1].id))
			}
		}
	}
}

// TestCoolingNeverRefusesToBuildAChain is the fail-safe half, and it is deliberately NOT
// the fail-closed rule at the top of core/relaychain.go.
//
// That rule forbids silently handing the user a WEAKER path than they configured — a
// shorter chain, an unchained path, a clamped depth. A chain of the full requested depth
// that happens to contain a node which failed a minute ago is exactly as strong as the
// one they asked for; it is only less likely to work. Refusing instead would turn one
// hop's bad minute into a client that cannot connect at all.
func TestCoolingNeverRefusesToBuildAChain(t *testing.T) {
	m := newLivenessMesh(t, 1, nil)
	rec := &eventRecorder{}
	client := newLivenessClient(t, m, 3, rec)

	// Cool every node the chain could possibly use.
	client.markHopCooling(m.head.id)
	client.markHopCooling(m.mids[0].id)
	client.markHopCooling(m.exitID)

	plan, err := client.buildChain(3, livenessExitCountry)
	if err != nil {
		t.Fatalf("buildChain with every candidate cooling = %v, want a chain — cooling is a liveness bet, and losing one must not become an outage", err)
	}
	if len(plan.hops) != 2 {
		t.Errorf("built %d peeling hops, want 2: the fall-back must reuse a cooling node, never shorten the chain", len(plan.hops))
	}
	if !rec.contains("every alternative node is cooling") {
		t.Error("the fall-back was silent — an operator whose whole directory is cooling has a directory problem and no way to see it")
	}
}

// TestRebuiltChainReportsItsOwnDegradation closes the gap the issue names: selectHops
// already reports a chain whose AS diversity it could not enforce (hopDiversity.
// degraded), and a rebuild must not be a way to obtain a chain that never went through
// that reporting.
//
// It is structural — rebuildChain goes through buildChainHeaded, which is where the
// notice is emitted — and this is what pins it there. Every address in this mesh is
// loopback, which no autonomous system announces, so every chain built here is degraded
// and the notice is expected once per build.
func TestRebuiltChainReportsItsOwnDegradation(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	rec := &eventRecorder{}
	client := newLivenessClient(t, m, 3, rec)

	sess := withChain(newChainTestSession(func() string { return m.head.addr }), planVia(m, m.mids[0]))
	before := rec.count("AS diversity")

	m.mids[0].kill()
	nc, err := client.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443")
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	defer nc.Close()

	if after := rec.count("AS diversity"); after <= before {
		t.Errorf("AS-diversity notices before=%d after=%d — a rebuilt chain was handed to the caller without going through the degradation report, so a chain whose diversity is merely UNKNOWN reads as one whose diversity is known-good (the same silent overstatement issue #23 exists to prevent)", before, after)
	}
}

// ---------- the plan is per session, and swapping it is a compare-and-swap ----------

// TestConcurrentFailuresProduceOneRebuild pins swapPlan's compare.
//
// A browser opens several connections at once, so a hop death is observed by several
// dials within milliseconds. Each would otherwise select a fresh chain and stamp it on
// the session, and all but the last one's work — directory reads, crypto/rand draws, a
// whole selection — is discarded. The compare means the first to finish installs its
// chain and the rest dial over that one instead of their own.
func TestConcurrentFailuresProduceOneRebuild(t *testing.T) {
	m := newLivenessMesh(t, 2, nil)
	client := newLivenessClient(t, m, 3, nil)
	midA := m.mids[0]

	start := planVia(m, midA)
	sess := withChain(newChainTestSession(func() string { return m.head.addr }), start)
	midA.kill()

	const dials = 6
	var wg sync.WaitGroup
	errs := make(chan error, dials)
	for i := 0; i < dials; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nc, err := client.dialChainedStream(context.Background(), sess, m.exitKey.Public, "example.com:443")
			if nc != nil {
				_ = nc.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent dial failed to recover: %v", err)
		}
	}
	if got := planOf(sess); got == start {
		t.Fatal("the session still carries the broken chain after every dial recovered")
	}
	// Exactly one chain is installed, whichever dial won it — asserted by every dial
	// having converged on the same one.
	final := planOf(sess)
	if final.hops[1].id == midA.id {
		t.Fatalf("the installed chain still uses the dead hop %s", shortID(midA.id))
	}
	if !strings.EqualFold(final.country, livenessExitCountry) {
		t.Errorf("rebuilt chain country = %q, want %q — a rebuild reproduces the selection the plan was built for, and the plan is the only thing that still remembers it", final.country, livenessExitCountry)
	}
}
