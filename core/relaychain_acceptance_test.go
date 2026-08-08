package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// Known-answer vectors for the peer-relay tag derivation (issue #56). They are
// LITERALS, computed once, and the identical three lines appear in
// cmd/coordinator's TestRelayTagWireContract. Two independent copies of a
// derivation pinned to the same constants is the only arrangement in which drift
// between them fails a test; a vector either side recomputed with sha256 would
// agree with any mutation of its own copy.
const (
	relayTagVectorEmpty   = "bbd6b36f34c5b540"
	relayTagVectorABC     = "5bef601c5a2e76aa"
	relayTagVectorBacchus = "2500892b4984d747"
)

// Relay chaining, end to end through the production wiring (issue #142, ADR-0038).
//
// Every other test in relaychain_test.go proves the ALGORITHM: it calls dialChain
// with a hand-built &chainPlan{}, on an &Engine{} literal whose cfg.RelayHops is
// zero. That leaves the whole path a real client takes to REACH dialChain unpinned
// — chainFor, chaining(), the mode ladder, firstHopID, withChain, planOf, dialE2E's
// plan branch — and a mutation switching any one of them off in production keeps
// every one of those tests green.
//
// So these are built the other way round. Nothing here constructs a chainPlan, a
// relayHop, or an Engine literal. The engine comes from the real New() with
// Config.RelayHops actually set, the traffic goes in through the real SOCKS
// listener that real Connect bound, and the only fakes are the two things a unit
// test cannot have: a coordinator (a loopback UDP socket speaking the wire) and the
// peer relay's transport (a loopback TCP session standing in for the blind splice).
// Everything between them is shipped code.

// ---------- the mesh ----------

// acceptanceMesh is a whole chainable network on loopback: a terminating exit, a
// head hop, a middle hop, and the signed directory that names all three.
//
// The two egress-country tags are load-bearing rather than decoration. The head has
// to be exit-ROLE — that is the only kind of node a coordinator can pair a client to
// (see relayHop.pairable) — which makes it a candidate to TERMINATE the chain too.
// Putting it in a different country from the exit is what makes chooseChainExit's
// answer, and therefore this test, deterministic: only one exit is in the country
// the client asks for, so the head is the only pairable node left for selectHops.
type acceptanceMesh struct {
	dirSigned []byte
	headID    string // exit-role, forwards; the node the coordinator pairs us to
	midID     string // relay-role, forwards
	exitID    string // exit-role, terminates
	headAddr  string
	exitDone  <-chan error
}

const (
	acceptanceExitCountry = "NL"
	acceptanceHopCountry  = "DE"
)

// newAcceptanceMesh stands up the three nodes and signs the directory. target and
// payload are what the exit asserts it received: the exit fails the test from its
// own goroutine if the innermost layer carried anything else, which is how "the
// destination reached the exit and only the exit" is observed rather than assumed.
func newAcceptanceMesh(t *testing.T, target, payload string) *acceptanceMesh {
	t.Helper()

	exitKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("exit key: %v", err)
	}
	done := make(chan error, 1)
	exitAddr := startExitIngress(t, exitKey, nil, target, payload, done)

	headKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("head key: %v", err)
	}
	midKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("mid key: %v", err)
	}

	// Built inner-to-outer: each forwarding node needs a directory that already
	// names everything it may be asked to dial, and a node cannot appear in its own
	// directory before it has bound a port.
	midDir := loadTestDirectory(t, []coldstart.Entry{
		{Role: "exit", ID: hex.EncodeToString(exitKey.Public), Country: acceptanceExitCountry, Addr: exitAddr},
	})
	midAddr := startForwardNode(t, midKey, midDir)

	headDir := loadTestDirectory(t, []coldstart.Entry{
		{Role: "relay", ID: hex.EncodeToString(midKey.Public), Country: acceptanceHopCountry, Ingress: midAddr},
	})
	headAddr := startForwardNode(t, headKey, headDir)

	return &acceptanceMesh{
		dirSigned: signTestSnapshot(t, testSnapPriv(t), []coldstart.Entry{
			{Role: "exit", ID: hex.EncodeToString(exitKey.Public), Country: acceptanceExitCountry, Addr: exitAddr},
			{Role: "exit", ID: hex.EncodeToString(headKey.Public), Country: acceptanceHopCountry, Addr: headAddr, Operator: "op-head"},
			{Role: "relay", ID: hex.EncodeToString(midKey.Public), Country: acceptanceHopCountry, Ingress: midAddr, Operator: "op-mid"},
		}),
		headID:   hex.EncodeToString(headKey.Public),
		midID:    hex.EncodeToString(midKey.Public),
		exitID:   hex.EncodeToString(exitKey.Public),
		headAddr: headAddr,
		exitDone: done,
	}
}

// loadTestDirectory signs entries and parses them back through the production
// loader, so a forwarding node's allow-list is built the way a real one's is.
func loadTestDirectory(t *testing.T, entries []coldstart.Entry) *relayDirectory {
	t.Helper()
	d, err := loadRelayDirectory(signTestSnapshot(t, testSnapPriv(t), entries), testSnapPub(t), "", time.Now())
	if err != nil {
		t.Fatalf("load directory: %v", err)
	}
	return d
}

// ---------- the two fakes ----------

// blindRelaySession is a Session whose every stream is a fresh TCP connection to
// one address. That IS what the coordinator's assigned peer relay is from the
// client's side (ADR-0033 relayPipe): a pipe to the node the coordinator wired,
// carrying bytes the relay cannot read. Standing it up as TCP rather than as an
// in-memory pipe matters, because the chain's first peeling hop is reached by a
// real dial and answers on a real listener.
type blindRelaySession struct {
	addr   string
	closed chan struct{}
	once   sync.Once

	mu    sync.Mutex
	conns []net.Conn
}

type blindRelayStream struct {
	net.Conn
	label string
}

func (s blindRelayStream) Label() string { return s.label }

func (s *blindRelaySession) OpenStream(ctx context.Context, label string) (Stream, error) {
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
	return blindRelayStream{Conn: c, label: label}, nil
}

func (s *blindRelaySession) AcceptStream(ctx context.Context) (Stream, error) {
	<-s.closed
	return nil, errors.New("blind relay: closed")
}

func (s *blindRelaySession) Closed() <-chan struct{} { return s.closed }

func (s *blindRelaySession) Close() error {
	s.once.Do(func() {
		close(s.closed)
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	return nil
}

// blindRelayTransport hands back blindRelaySessions pointed at addr.
type blindRelayTransport struct{ addr string }

func (t *blindRelayTransport) Name() string { return "blind-relay" }

func (t *blindRelayTransport) Dial(ctx context.Context, sig Signaler) (Session, error) {
	return &blindRelaySession{addr: t.addr, closed: make(chan struct{})}, nil
}

func (t *blindRelayTransport) Accept(ctx context.Context, sig Signaler) (Session, error) {
	return nil, errors.New("blind relay: accept unused")
}

// chainCoordinator is a loopback coordinator that records every connect it is sent
// and answers it with reply. Recording is the point: what a chaining client does
// and does not put on the wire is half of what this feature claims, and the only
// place to observe it is here, where a real coordinator would.
func chainCoordinator(t *testing.T, reply func(m wire) (wire, bool)) (addr string, seen func() []wire) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("coordinator listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	var mu sync.Mutex
	var got []wire
	peer := servePeer(t, pc)
	go func() {
		var seq int
		for {
			raw, src, err := peer.ReadFrom()
			if err != nil {
				return
			}
			var m wire
			if json.Unmarshal(raw, &m) != nil || m.Type != "connect" {
				continue
			}
			mu.Lock()
			got = append(got, m)
			mu.Unlock()
			seq++
			out, ok := reply(m)
			if !ok {
				continue
			}
			if out.Type == "session" && out.Session == "" {
				out.Session = fmt.Sprintf("chain-s%d", seq)
			}
			b, _ := json.Marshal(out)
			_, _ = peer.WriteTo(b, src)
		}
	}()
	return pc.LocalAddr().String(), func() []wire {
		mu.Lock()
		defer mu.Unlock()
		return append([]wire(nil), got...)
	}
}

// mintPeerRelay answers every connect with a peer-relay session. The tag names a
// node that is in no chain, which is what an honest coordinator produces.
func mintPeerRelay(wire) (wire, bool) {
	return wire{Type: "session", Relay: relayPeer, RelayTag: relayTagFor("a-relay-in-nobodys-chain")}, true
}

// ---------- the engine under test ----------

// newChainingClient builds a CHAINING client through the real New(), with
// RelayHops genuinely set, and points its transport at the chain's head.
//
// The transport substitution is the whole of what is faked on the client side.
// Config, directory verification, hop selection, exit selection, the mode ladder,
// pairing and the telescoping dial are all the shipped ones.
func newChainingClient(t *testing.T, coord string, mesh *acceptanceMesh, hops int) *Engine {
	t.Helper()
	eng, err := New(Config{
		Coordinators:   []string{coord},
		Roles:          []string{RoleClient},
		SocksAddr:      "127.0.0.1:0",
		Geo:            acceptanceExitCountry,
		RelayHops:      hops,
		RelayDirectory: mesh.dirSigned,
		MeshPubKey:     testSnapPub(t),
	})
	if err != nil {
		t.Fatalf("New (RelayHops=%d): %v", hops, err)
	}
	eng.transport = &blindRelayTransport{addr: mesh.headAddr}
	eng.directTimeout = 3 * time.Second
	eng.relayTimeout = 3 * time.Second
	return eng
}

// socksAddr is where the SOCKS listener Connect bound actually landed. A
// client-only engine has exactly one listener, which is that one.
func socksAddr(t *testing.T, e *Engine) string {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.listeners) != 1 {
		t.Fatalf("expected exactly one listener (SOCKS) on a client-only engine, got %d", len(e.listeners))
	}
	return e.listeners[0].Addr().String()
}

// socksConnect performs a real SOCKS5 CONNECT to target through addr and returns
// the open connection, ready for payload.
func socksConnect(t *testing.T, addr, host string, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial SOCKS: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := c.Write([]byte{5, 1, 0}); err != nil { // VER, NMETHODS, NO-AUTH
		t.Fatalf("SOCKS greeting: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatalf("SOCKS greeting reply: %v", err)
	}
	if greet[0] != 5 || greet[1] != 0 {
		t.Fatalf("SOCKS greeting reply = %v, want [5 0]", greet)
	}

	req := []byte{5, 1, 0, 3, byte(len(host))} // CONNECT, ATYP=DOMAIN
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("SOCKS request: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("SOCKS reply: %v", err)
	}
	if resp[1] != 0 {
		t.Fatalf("SOCKS CONNECT refused with status %d — the chained path did not come up", resp[1])
	}
	return c
}

// ---------- the acceptance ----------

// TestChainingClientCarriesTrafficThroughItsOwnChain is issue #142's acceptance.
//
// A client the real New() built with RelayHops=3 connects, binds SOCKS, and carries
// a real request to a real exit across a chain it assembled itself out of the signed
// directory: blind relay -> head hop -> middle hop -> exit. The exit asserts, from
// its own goroutine, that the destination and payload arrived intact — so the onion
// was peeled exactly the right number of times by exactly the right nodes.
//
// This is the test the five off-switch mutations fail. Turning chaining off in
// production — chainFor returning no plan, chaining() returning false, withChain
// leaving the session untagged, dialE2E ignoring its plan — all end the same way:
// the client runs a single Noise_NK handshake against a key that is not the key of
// the node its transport actually reaches, and nothing gets through.
func TestChainingClientCarriesTrafficThroughItsOwnChain(t *testing.T) {
	const host, port = "example.com", 443
	const payload = "ACCEPTANCE_THROUGH_THE_REAL_ENTRY_POINT"
	target := fmt.Sprintf("%s:%d", host, port)

	mesh := newAcceptanceMesh(t, target, payload)
	coord, seen := chainCoordinator(t, mintPeerRelay)
	eng := newChainingClient(t, coord, mesh, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Connect(ctx); err != nil {
		t.Fatalf("Connect at RelayHops=3: %v", err)
	}

	c := socksConnect(t, socksAddr(t, eng), host, port)
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload through the chain: %v", err)
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(c, ack); err != nil {
		t.Fatalf("read the exit's return-path ack back through the chain: %v", err)
	}
	if err := <-mesh.exitDone; err != nil {
		t.Fatalf("exit side (blind relay + 2 peeling hops): %v", err)
	}

	// And the wire half of the claim, on the same run: what the coordinator was
	// actually told. Asserted here rather than in a test of its own so that a build
	// which carried the traffic by NOT chaining could not pass either half.
	connects := seen()
	if len(connects) == 0 {
		t.Fatal("coordinator saw no connect at all")
	}
	for i, m := range connects {
		if m.FirstHop != mesh.headID {
			t.Errorf("connect %d named firstHop %q, want the chain head %q", i, shortID(m.FirstHop), shortID(mesh.headID))
		}
		if m.FirstHop == mesh.exitID {
			t.Errorf("connect %d named the TERMINATING EXIT as its first hop — the coordinator now knows where this client egresses", i)
		}
		if m.ExitID != "" {
			t.Errorf("connect %d carried exitId %q; a client names no exit at all under ADR-0042 §2", i, m.ExitID)
		}
		if m.Country != "" {
			t.Errorf("connect %d carried country %q; a chained connect omits it, because the coordinator picks no exit and the field would hand it the user's egress jurisdiction", i, m.Country)
		}
		if m.Mode != modeRelay {
			t.Errorf("connect %d used mode %q, want %q — a chaining client offers no direct tier", i, m.Mode, modeRelay)
		}
	}
}

// TestChainingClientNeverNamesItsExitOnAnyAttempt is the privacy claim stated
// negatively, over a connect that FAILS and is retried — the case the happy path
// above cannot cover.
//
// It is the regression test for the specific defect that parked this branch: the
// mode ladder offered direct before relay, and the direct attempt put the real exit
// id on the wire, three times, before any chained attempt happened. A client that
// reaches the coordinator repeatedly must never name its exit on ANY of those
// attempts, not merely on the one that succeeds.
func TestChainingClientNeverNamesItsExitOnAnyAttempt(t *testing.T) {
	mesh := newAcceptanceMesh(t, "example.com:443", "unused")
	// Refuse everything, so the client exhausts its whole ladder and we see every
	// attempt it is willing to make.
	coord, seen := chainCoordinator(t, func(wire) (wire, bool) {
		return wire{Type: "error", Reason: "country-busy"}, true
	})
	eng := newChainingClient(t, coord, mesh, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Connect(ctx); err == nil {
		t.Fatal("Connect succeeded against a coordinator that refused every request")
	}

	connects := seen()
	if len(connects) == 0 {
		t.Fatal("client made no attempt at all, so this proves nothing")
	}
	for i, m := range connects {
		if m.ExitID == mesh.exitID || m.FirstHop == mesh.exitID || m.Country != "" {
			t.Errorf("attempt %d leaked the egress choice: exitId=%q firstHop=%q country=%q",
				i, shortID(m.ExitID), shortID(m.FirstHop), m.Country)
		}
		if m.Mode == modeDirect {
			t.Errorf("attempt %d was mode %q; a chaining client must not offer a direct tier, because a direct path carries no chain and taking one would be a silent downgrade", i, modeDirect)
		}
	}
}

// TestChainingClientRefusesARelayThatIsAlsoOneOfItsHops pins verifyChainDisjoint
// through the production connect path.
//
// The coordinator answers with a relay tag that belongs to a node the client put in
// its own chain. R1 sees the client and the last hop sees the exit, so one node in
// both roles holds both ends — and an honest coordinator can produce exactly this by
// accident, since pickRelay excludes only the node it paired. The attempt must fail
// rather than come up weaker than it claims.
func TestChainingClientRefusesARelayThatIsAlsoOneOfItsHops(t *testing.T) {
	mesh := newAcceptanceMesh(t, "example.com:443", "unused")
	coord, _ := chainCoordinator(t, func(m wire) (wire, bool) {
		// Whatever hop the client named as its head, hand that same node back as the
		// assigned relay.
		return wire{Type: "session", Relay: relayPeer, RelayTag: relayTagFor(m.FirstHop)}, true
	})
	eng := newChainingClient(t, coord, mesh, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Connect(ctx); err == nil {
		t.Fatal("client accepted a peer relay that is also a hop in its own chain; want the path refused")
	}
}

// TestChainingClientRefusesTheTURNFallback replaces a test that asserted only that
// a package-level errors.New was non-nil and that two distinct constants differ —
// which reached no production code at all, so deleting the gate it named left the
// suite green.
//
// The rule: a chained path needs a genuine peer relay in front of it. On the TURN
// disposition the coordinator wires the client straight to the node it named, so
// that node would see the client's own address AND, one layer in, the next hop —
// and at depth 2 the exit. Failing is the fail-closed rule; connecting anyway would
// hand the user an assurance they do not have.
func TestChainingClientRefusesTheTURNFallback(t *testing.T) {
	mesh := newAcceptanceMesh(t, "example.com:443", "unused")
	coord, seen := chainCoordinator(t, func(wire) (wire, bool) {
		return wire{Type: "session", Relay: relayTURN}, true
	})
	eng := newChainingClient(t, coord, mesh, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Connect(ctx); err == nil {
		t.Fatal("client built a chain over the TURN fallback; want the attempt failed")
	}
	if len(seen()) == 0 {
		t.Fatal("client never reached the coordinator, so the TURN gate is not what stopped it")
	}
}

// TestUnchainedClientStillNamesNoHopAndKeepsItsCountry is the zero-regression half:
// the same construction with RelayHops left at its default puts a country on the
// wire, no firstHop, and still offers the direct tier first.
//
// Without it, a mutation that made EVERY client behave as a chaining one would pass
// all of the above.
func TestUnchainedClientStillNamesNoHopAndKeepsItsCountry(t *testing.T) {
	mesh := newAcceptanceMesh(t, "example.com:443", "unused")
	coord, seen := chainCoordinator(t, func(wire) (wire, bool) {
		return wire{Type: "error", Reason: "country-busy"}, true
	})
	// Default depth, and deliberately still given the directory: "default 1 ==
	// today" has to hold for a client that HAS a directory, not only for one that
	// lacks the config.
	eng := newChainingClient(t, coord, mesh, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	_ = eng.Connect(ctx) // refused by design; the wire is what is under test

	connects := seen()
	if len(connects) == 0 {
		t.Fatal("client made no attempt at all")
	}
	sawDirect := false
	for i, m := range connects {
		if m.FirstHop != "" {
			t.Errorf("attempt %d named firstHop %q at the default depth; an unchained connect must be byte-identical to a pre-#142 one", i, m.FirstHop)
		}
		if m.Country != acceptanceExitCountry {
			t.Errorf("attempt %d carried country %q, want %q — an unchained connect is how the coordinator is told where to egress", i, m.Country, acceptanceExitCountry)
		}
		if m.Mode == modeDirect {
			sawDirect = true
		}
	}
	if !sawDirect {
		t.Error("an unchained client never offered the direct tier; the chaining gate has leaked into the default path")
	}
}

// TestNewRefusesAChainDeeperThanTheCeiling pins ADR-0038 §6's bound, and pins it as
// a REFUSAL rather than as a clamp.
//
// The depths are written out rather than derived from RelayHopsMax, deliberately.
// Its predecessor computed the expected depth from the very constant it was meant
// to bound, so raising the ceiling from 4 to 400 left it passing. Naming 4 and 5
// means either edit to the constant breaks one of these two cases.
func TestNewRefusesAChainDeeperThanTheCeiling(t *testing.T) {
	mesh := newAcceptanceMesh(t, "example.com:443", "unused")
	cfg := func(hops int) Config {
		return Config{
			Coordinators:   []string{"127.0.0.1:1"},
			Roles:          []string{RoleClient},
			SocksAddr:      "127.0.0.1:0",
			Geo:            acceptanceExitCountry,
			RelayHops:      hops,
			RelayDirectory: mesh.dirSigned,
			MeshPubKey:     testSnapPub(t),
		}
	}
	if _, err := New(cfg(4)); err != nil {
		t.Errorf("New(RelayHops=4) = %v, want it accepted — 4 is the documented ceiling", err)
	}
	if _, err := New(cfg(5)); err == nil {
		t.Error("New(RelayHops=5) was accepted; a depth above the ceiling must be refused, not silently shortened to one the user did not ask for")
	}
}

// TestRelayTagWireContract pins core's relayTagFor against cmd/coordinator's
// relayTag, which is the value it is compared with on the wire.
//
// The two binaries deliberately do not import each other (see wire's doc), so the
// derivation is duplicated — and a duplicated derivation that drifts would silently
// disable verifyChainDisjoint rather than fail anything. The expected digests are
// literals: computing them with sha256 here would be recomputing the function under
// test and would agree with any mutation of it.
func TestRelayTagWireContract(t *testing.T) {
	cases := []struct{ id, want string }{
		{"", relayTagVectorEmpty},
		{"abc", relayTagVectorABC},
		{"bacchus", relayTagVectorBacchus},
	}
	for _, tc := range cases {
		if got := relayTagFor(tc.id); got != tc.want {
			t.Errorf("relayTagFor(%q) = %s, want %s — core and cmd/coordinator must derive the same tag or verifyChainDisjoint silently stops matching", tc.id, got, tc.want)
		}
	}
}

// TestRelayForwardRefusesToDialItself pins the self-dial guard.
//
// A node's own addresses are in the directory it checks targets against, so
// "hop:<my own ingress>" passes the allow-list. Splicing it would hand the layer
// back to this same node, which would peel it and forward it again — one attacker
// socket becoming two, then four. It is the cheap half of #25, whose other half —
// the per-previous-hop and aggregate caps that bound a RING rather than a self-dial
// — is pinned in relay_forward_limits_test.go.
//
// Driven through relayForward with a real directory rather than through a unit call
// on the predicate, so a build that removed the CALL (and not just the function)
// fails too.
func TestRelayForwardRefusesToDialItself(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	selfID := hex.EncodeToString(key.Public)

	// A listener that must never be dialed. If the guard is gone, relayForward
	// connects to it and the test sees the accept.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	selfAddr := ln.Addr().String()
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
		accepted <- struct{}{}
	}()

	signed := signTestSnapshot(t, testSnapPriv(t), []coldstart.Entry{
		{Role: "relay", ID: selfID, Country: acceptanceHopCountry, Ingress: selfAddr},
	})
	dir, err := loadRelayDirectory(signed, testSnapPub(t), selfID, time.Now())
	if err != nil {
		t.Fatalf("load directory: %v", err)
	}
	// Premise: the address IS in the allow-list, so only the self check can refuse
	// it. Without this the test would pass for the wrong reason.
	if !dir.dialable[selfAddr] {
		t.Fatal("fixture is wrong: the node's own ingress is not in the forwarding allow-list, so this proves nothing")
	}

	e := &Engine{
		roles:   map[string]bool{RoleRelay: true},
		exitKey: key,
		cfg:     Config{ID: selfID, RelayIngress: selfAddr},
	}
	e.relayDir.Store(dir)
	e.relayForward(nil, selfAddr)

	select {
	case <-accepted:
		t.Fatal("the node dialed its own ingress; one attacker socket amplifies to two at every pass")
	case <-time.After(300 * time.Millisecond):
	}
}
