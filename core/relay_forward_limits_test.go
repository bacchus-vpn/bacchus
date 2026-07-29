package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// Relay-side DoS controls for onion forwarding (issue #25, ADR-0038 §6).
//
// Two things are under test and they fail in different ways, so they are proven
// differently:
//
//   - The CAPS are arithmetic over a shared map. Their sharp edges (the key, the
//     interaction between the two caps, the map's lifetime) are unit-tested
//     directly on forwardLimits, because driving them through a socket would prove
//     "something refused" without proving which rule did it.
//   - The REFUSAL is a wire behaviour. It is driven through the production
//     exitTerminate/relayForward on a real listener, because the thing that would
//     silently break is the wiring — a cap that counts perfectly while relayForward
//     forgets to consult it, or a signal written to a channel nobody reads.
//
// The dialChain-with-a-hand-built-plan shape appears below, and deliberately: the
// audit recorded in relaychain_acceptance_test.go rejected that shape for proving
// the CLIENT assembles chains, which it cannot prove. Here the client's selection
// is not what is under test — the relay's refusal is, and the client is present
// only to observe it, so the plan is a fixture rather than the thing being dodged.

// ---------- the caps themselves ----------

// TestForwardLimitsCapOnePreviousHop pins the per-previous-hop cap: one neighbour
// runs out of budget while another, with the same node, still gets served.
//
// The second half is the point. A cap that refused everybody once ANY peer hit the
// per-peer ceiling would pass an assertion that only checked the first half, and it
// would be an aggregate cap wearing the per-peer cap's name.
func TestForwardLimitsCapOnePreviousHop(t *testing.T) {
	f := newForwardLimits(2, 100, 0)

	for i := range 2 {
		if _, _, _, err := f.acquire("198.51.100.7"); err != nil {
			t.Fatalf("circuit %d from a peer under its cap was refused: %v", i+1, err)
		}
	}
	_, _, first, err := f.acquire("198.51.100.7")
	if !errors.Is(err, errForwardPeerBusy) {
		t.Fatalf("third circuit from a peer capped at 2 = %v, want errForwardPeerBusy", err)
	}
	if !first {
		t.Error("the first refusal of an episode did not report itself as the edge; the operator gets no log at all")
	}
	if _, _, again, _ := f.acquire("198.51.100.7"); again {
		t.Error("a second refusal in the same episode reported itself as an edge; the log this drives would repeat once per refused circuit, at a rate the attacker chooses")
	}

	if _, _, _, err := f.acquire("198.51.100.8"); err != nil {
		t.Fatalf("a DIFFERENT peer was refused because the first one is full: %v — the per-peer cap has collapsed into an aggregate one, and one neighbour can now deny the node to every other", err)
	}
}

// TestForwardLimitsCapTheNodeInAggregate pins the aggregate cap, isolated from the
// per-peer one by setting the per-peer ceiling high enough that it cannot be what
// refuses.
func TestForwardLimitsCapTheNodeInAggregate(t *testing.T) {
	f := newForwardLimits(50, 3, 0)

	for i := range 3 {
		if _, _, _, err := f.acquire("198.51.100.9"); err != nil {
			t.Fatalf("circuit %d below the aggregate of 3 was refused: %v", i+1, err)
		}
	}
	// A fresh peer, well under the per-peer ceiling of 50: only the aggregate can
	// refuse this, which is what makes the assertion attributable.
	if _, _, _, err := f.acquire("198.51.100.10"); !errors.Is(err, errForwardNodeBusy) {
		t.Fatalf("a new peer at a full node = %v, want errForwardNodeBusy — nothing bounds what this node carries in total", err)
	}
}

// TestForwardLimitsReleaseReturnsTheSlot pins that occupancy is occupancy and not a
// lifetime counter: a node that only ever counted up would refuse everything
// forever after its first busy minute.
func TestForwardLimitsReleaseReturnsTheSlot(t *testing.T) {
	f := newForwardLimits(1, 100, 0)

	_, release, _, err := f.acquire("203.0.113.5")
	if err != nil {
		t.Fatalf("first circuit: %v", err)
	}
	if _, _, _, err := f.acquire("203.0.113.5"); !errors.Is(err, errForwardPeerBusy) {
		t.Fatalf("second circuit at a per-peer cap of 1 = %v, want errForwardPeerBusy", err)
	}
	refused, ended := release()
	if !ended {
		t.Error("the release that ended a saturation episode did not report it; the operator sees the node start shedding and never sees it stop")
	}
	if refused != 1 {
		t.Errorf("episode reported %d refused circuits, want 1", refused)
	}
	if _, _, _, err := f.acquire("203.0.113.5"); err != nil {
		t.Fatalf("a circuit after a release was refused: %v — slots are never coming back, so a node degrades permanently after one busy moment", err)
	}
}

// TestForwardPeerKeyIgnoresThePort is the one that keeps every other cap honest.
//
// A previous hop dials a fresh ephemeral port for every circuit it hands over, so
// keying occupancy on host:port would file each circuit under its own peer and the
// per-peer cap would never bind — while every test that merely counted refusals
// against ONE synthetic key kept passing. The cap would ship inert.
func TestForwardPeerKeyIgnoresThePort(t *testing.T) {
	first := forwardPeerKey(&noiseConn{raw: fakeRemoteConn{addr: "198.51.100.20:40001"}})
	second := forwardPeerKey(&noiseConn{raw: fakeRemoteConn{addr: "198.51.100.20:40002"}})
	if first != second {
		t.Fatalf("two circuits from one peer keyed as %q and %q — the per-peer cap counts each circuit under its own key and therefore bounds nothing", first, second)
	}
	if first != "198.51.100.20" {
		t.Errorf("peer key = %q, want the bare host", first)
	}
	if other := forwardPeerKey(&noiseConn{raw: fakeRemoteConn{addr: "198.51.100.21:40001"}}); other == first {
		t.Error("two DIFFERENT peers share one key; the cap has become aggregate-only")
	}
	// A conn with nothing to key on is one key, not no key: the alternative is a
	// forward that skips the caps entirely.
	if k := forwardPeerKey(&noiseConn{raw: addrlessConn{}}); k != "" {
		t.Errorf("unaddressable peer key = %q, want the empty shared key", k)
	}
	// relayForward's earliest refusals run before there is a channel at all, so the
	// first thing past them must not be a panic.
	if k := forwardPeerKey(nil); k != "" {
		t.Errorf("nil-channel peer key = %q, want the empty shared key", k)
	}
}

// TestForwardLimitsClampPerPeerToAggregate pins the construction guard. A per-peer
// ceiling above the aggregate is not a stricter configuration, it is a silently
// disabled one — the aggregate would always refuse first and one neighbour could
// hold every slot the node has.
func TestForwardLimitsClampPerPeerToAggregate(t *testing.T) {
	f := newForwardLimits(500, 4, 0)
	if f.maxPerPeer > f.maxTotal {
		t.Fatalf("per-peer cap %d left above the aggregate %d; one neighbour can take the whole node", f.maxPerPeer, f.maxTotal)
	}
	if f := newForwardLimits(0, 0, 0); f.maxPerPeer != defaultForwardMaxPerPeer || f.maxTotal != defaultForwardMaxTotal {
		t.Errorf("unset caps built %d/%d, want the defaults %d/%d — zero must mean the default, never unlimited",
			f.maxPerPeer, f.maxTotal, defaultForwardMaxPerPeer, defaultForwardMaxTotal)
	}
}

// TestForwardLimitsForgetIdlePeers pins that the peer map is bounded by live
// occupancy rather than by how many source addresses an attacker can dial from. A
// map that outlived its entries would be a memory DoS inside the type that exists
// to prevent one.
func TestForwardLimitsForgetIdlePeers(t *testing.T) {
	f := newForwardLimits(4, 100, 0)
	releases := make([]func() (uint64, bool), 0, 20)
	for i := range 20 {
		_, release, _, err := f.acquire(net.JoinHostPort(fmt.Sprintf("203.0.113.%d", i), "0"))
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		releases = append(releases, release)
	}
	if got := len(f.peers); got != 20 {
		t.Fatalf("live peers = %d, want 20", got)
	}
	for _, release := range releases {
		release()
	}
	if got := len(f.peers); got != 0 {
		t.Errorf("peers still tracked after every circuit closed = %d, want 0 — the map grows with every address an attacker dials from and is never reclaimed", got)
	}
	// Refusing a peer must not create an entry for it either, or the same growth
	// arrives through the refusal path instead of the admission path.
	full := newForwardLimits(1, 1, 0)
	if _, _, _, err := full.acquire("203.0.113.1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	for i := range 20 {
		_, _, _, _ = full.acquire(net.JoinHostPort(fmt.Sprintf("198.51.100.%d", i), "0"))
	}
	if got := len(full.peers); got != 1 {
		t.Errorf("peers tracked after 20 REFUSED circuits = %d, want 1 (only the admitted one)", got)
	}
}

// ---------- the refusal, as bytes ----------

// TestHopRefusalFrameRoundTrips pins the encoding both ends depend on, and — the
// half that matters — that a real handshake reply is not mistaken for one. The
// client checks these bytes at exactly the position a Noise msg2 arrives at, so a
// false positive would turn a working hop into a reported refusal.
func TestHopRefusalFrameRoundTrips(t *testing.T) {
	for _, reason := range []string{refusedPeerBusy, refusedNodeBusy, refusedNotInMesh, refusedSelfTarget, refusedForwardingOff} {
		got, ok := parseHopRefusal(hopRefusalFrame(reason))
		if !ok || got != reason {
			t.Errorf("round trip of %q = (%q, %v)", reason, got, ok)
		}
	}
	// msg2 is a 32-byte X25519 ephemeral followed by an AEAD tag. Random bytes of
	// that shape stand in for it: the magic must not be reachable by chance.
	for range 200 {
		msg2 := make([]byte, 2+48)
		if _, err := rand.Read(msg2); err != nil {
			t.Fatalf("rand: %v", err)
		}
		msg2[0], msg2[1] = 0, 48
		if reason, ok := parseHopRefusal(msg2); ok {
			t.Fatalf("a handshake-shaped frame parsed as the refusal %q; a working hop would be reported as one that refused", reason)
		}
	}
	// Short and truncated inputs must not panic or match.
	for _, b := range [][]byte{nil, {}, {0}, {0, 200, 1, 2}} {
		if _, ok := parseHopRefusal(b); ok {
			t.Errorf("parseHopRefusal(%v) matched", b)
		}
	}
}

// TestRefusalSnifferReadsWhatAHopWrote pins the two halves against each other
// across a real Noise channel: the hop seals a refusal with signalHopRefused, and
// the client recovers it from the sniffer wrapped around the same stream.
//
// The framing is written by hand on the relay side and re-parsed by hand on the
// client side, so it is the one place the two copies can drift. This is what
// catches that.
func TestRefusalSnifferReadsWhatAHopWrote(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	hopEnd, clientEnd := net.Pipe()
	deadline(t, hopEnd, clientEnd)

	go func() {
		nc, _, err := exitHandshake(hopEnd, key, nil)
		if err != nil {
			return
		}
		signalHopRefused(nc, refusedPeerBusy)
	}()

	sniffer := newRefusalSniffer(clientEnd)
	nc, err := clientHandshake(sniffer, key.Public, hopTargetPrefix+"198.51.100.1:20000", nil)
	if err != nil {
		t.Fatalf("handshake with the hop: %v", err)
	}
	// The refusal arrives on the channel the NEXT layer would have been read from,
	// so read it the way the next layer's handshake would.
	buf := make([]byte, 64)
	if _, err := nc.Read(buf); err != nil {
		t.Fatalf("read the hop's refusal: %v", err)
	}
	reason, ok := parseHopRefusal(buf)
	if !ok {
		t.Fatalf("what the hop sealed did not parse as a refusal; the relay half and the client half have drifted apart")
	}
	if reason != refusedPeerBusy {
		t.Errorf("reason = %q, want %q", reason, refusedPeerBusy)
	}
}

// ---------- the caps, through the production forwarding path ----------

// TestForwardingHopRefusesOverPerPeerCap drives a real forwarding node past its
// per-previous-hop cap over a real socket, and asserts three separate things that
// can each break alone: the second circuit is refused, the next hop is never
// dialed for it, and the client is TOLD rather than left with a dead socket.
func TestForwardingHopRefusesOverPerPeerCap(t *testing.T) {
	sink, sinkAddr := startSink(t)
	hop, hopAddr, hopKey := startCappedHop(t, sinkAddr, 1, 100, 0)

	// Circuit one: admitted, held open, and the hop is now at its per-peer cap.
	held := dialForward(t, hopAddr, hopKey, sinkAddr)
	defer held.Close()
	waitForwardCount(t, hop, "127.0.0.1", 1)
	if got := sink.accepted(); got != 1 {
		t.Fatalf("the admitted circuit reached the next hop %d times, want 1", got)
	}

	// Circuit two, from the same peer: refused.
	second := dialForward(t, hopAddr, hopKey, sinkAddr)
	defer second.Close()

	reason := readRefusal(t, second)
	if reason != refusedPeerBusy {
		t.Fatalf("refusal reason = %q, want %q", reason, refusedPeerBusy)
	}
	if got, total := hop.forwardLimits.counts("127.0.0.1"); got != 1 || total != 1 {
		t.Errorf("occupancy after a refusal = (%d peer, %d total), want (1, 1) — a refused circuit took a slot anyway", got, total)
	}
	// A refused forward must cost this node no outbound connection: the whole point
	// is to stop spending resources on it, and a dial is the most expensive thing
	// here after the splice itself.
	if got := sink.accepted(); got != 1 {
		t.Errorf("the next hop was dialed %d times, want 1 — the refusal happens after the dial, so a full node still pays for every circuit it turns away", got)
	}
}

// TestForwardingHopRefusesOverAggregateCap is the same drive against the aggregate,
// with the per-peer ceiling set high enough that it cannot be what refuses. Without
// this, one test would cover both caps and removing either would leave the other
// one's test green.
func TestForwardingHopRefusesOverAggregateCap(t *testing.T) {
	_, sinkAddr := startSink(t)
	hop, hopAddr, hopKey := startCappedHop(t, sinkAddr, 50, 1, 0)

	held := dialForward(t, hopAddr, hopKey, sinkAddr)
	defer held.Close()
	waitForwardCount(t, hop, "127.0.0.1", 1)

	second := dialForward(t, hopAddr, hopKey, sinkAddr)
	defer second.Close()
	if reason := readRefusal(t, second); reason != refusedNodeBusy {
		t.Fatalf("refusal reason = %q, want %q — nothing bounds this node's total forwarding, only each neighbour's share of it", reason, refusedNodeBusy)
	}
}

// TestForwardingHopKeysOccupancyOnThePreviousHop pins the WIRING of the peer key,
// which the unit test on forwardPeerKey cannot: relayForward has to hand it the
// stream the previous hop dialed in on, and handing it anything else (the next
// hop's address, the target, a fresh string) would key every circuit under a
// constant and produce a cap that looks identical in every other test here.
func TestForwardingHopKeysOccupancyOnThePreviousHop(t *testing.T) {
	_, sinkAddr := startSink(t)
	hop, hopAddr, hopKey := startCappedHop(t, sinkAddr, 4, 100, 0)

	held := dialForward(t, hopAddr, hopKey, sinkAddr)
	defer held.Close()
	waitForwardCount(t, hop, "127.0.0.1", 1)

	// The previous hop here is this test process, dialing loopback. If occupancy
	// were filed under anything else, the count under the peer's own address is 0.
	if peer, total := hop.forwardLimits.counts("127.0.0.1"); peer != 1 || total != 1 {
		t.Errorf("occupancy under the previous hop's address = (%d, %d), want (1, 1) — the circuit is filed under some other key, so the per-peer cap does not bound the peer it names", peer, total)
	}
}

// TestForwardingHopPacesOnePreviousHop pins the third cap: the per-previous-hop
// byte pace (-relay-forward-peer-rate).
//
// It is the one cap that does NOT shed. A circuit already admitted is not worth
// destroying mid-copy to save bandwidth that pacing reclaims anyway — the same
// call ADR-0027 makes for the reality splice — so bytes are slowed instead. What
// this asserts is therefore that they ARE slowed: without the pacer the copy runs
// at loopback speed and finishes far inside the window.
//
// Timing assertions are usually a smell. This one is safe in the direction it can
// fail: the bucket's own arithmetic sets a FLOOR on elapsed time (a paced reader
// cannot go faster than its rate), so a loaded machine can only push the measured
// time up, never below the bound. The margin is 4x the floor regardless.
func TestForwardingHopPacesOnePreviousHop(t *testing.T) {
	// 800 kbit/s == 100 KB/s. The first 64 KB ride the bucket's burst for free, so
	// pushing 192 KB leaves 128 KB to be paced: ~1.28s of unavoidable wait.
	const (
		rate    = capacity.Rate(800_000)
		payload = 192 * 1024
		floor   = 300 * time.Millisecond
	)
	sink, sinkAddr := startSink(t)
	_, hopAddr, hopKey := startCappedHop(t, sinkAddr, 10, 100, rate)

	nc := dialForward(t, hopAddr, hopKey, sinkAddr)
	defer nc.Close()
	// The sink drains everything it is handed, so the only thing between this write
	// and loopback speed is the pace under test.
	<-sink.first

	start := time.Now()
	if _, err := nc.Write(make([]byte, payload)); err != nil {
		t.Fatalf("write through the paced hop: %v", err)
	}
	sink.waitBytes(t, payload, 30*time.Second)
	elapsed := time.Since(start)
	if elapsed < floor {
		t.Fatalf("%d KB crossed a hop paced at %s in %v, under the %v the bucket alone would take — the per-previous-hop pace is not applied, so one neighbour can take the whole uplink through circuits the count caps allow",
			payload/1024, rate, elapsed, floor)
	}
}

// ---------- the ring ----------

// TestRingOfForwardingNodesTerminates is the other half of issue #25, and the half
// the self-dial guard explicitly did not cover: A -> B -> C -> A, each node pointed
// at the next, with one attacker socket at the front.
//
// # What is actually being proven
//
// The chain does not self-extend — every lap costs the attacker another Noise_NK
// handshake driven through the whole chain built so far — so "spinning" is not the
// failure mode. The failure mode is OCCUPANCY: one socket holding a slot on every
// node of the ring, for as many laps as the attacker cares to pay for, with nothing
// in the code saying stop. That is what this bounds.
//
// The per-previous-hop cap is what bounds it, and the mechanism is worth stating
// because it is why no hop counter was added (see forwardLimits and the ADR-0038
// amendment): every REVISIT to a node in a ring arrives from the same predecessor,
// so laps past the first all draw on one per-peer budget and the ring runs out of
// them. The aggregate is set far above the layer budget here so that it cannot be
// what stops the loop — remove the per-peer cap and this test runs to the ceiling
// and fails.
//
// Loopback caveat, stated rather than papered over: every node here dials from
// 127.0.0.1, so all of them share one peer bucket. That makes the bound tighter
// than a real deployment's and does not exercise peer DISTINCTNESS, which is
// proven instead by TestForwardLimitsCapOnePreviousHop and
// TestForwardPeerKeyIgnoresThePort. What this test proves is that the ring
// terminates, that a cap is what terminates it, and that the node says so.
func TestRingOfForwardingNodesTerminates(t *testing.T) {
	const (
		perPeer  = 3
		maxLayer = 40 // far above 3*perPeer, far below anything slow
	)

	ring := startRing(t, perPeer, 1000)

	conn, err := net.DialTimeout("tcp", ring.addrs[0], 5*time.Second)
	if err != nil {
		t.Fatalf("dial the ring's head: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(hopTestDeadline))

	var cur io.ReadWriteCloser = conn
	depth := 0
	var refusal string
	for i := range maxLayer {
		sniffer := newRefusalSniffer(cur)
		next := ring.addrs[(i+1)%len(ring.addrs)]
		nc, err := clientHandshake(sniffer, ring.pubs[i%len(ring.pubs)], hopTargetPrefix+next, nil)
		if err != nil {
			refusal, _ = sniffer.refusal()
			break
		}
		cur = nc
		depth++
	}

	if depth >= maxLayer {
		t.Fatalf("a ring of %d nodes absorbed %d laps of onion layers without one of them refusing: one attacker socket now holds %d forwarding slots across the mesh and nothing bounds how many more it can take",
			len(ring.addrs), depth, depth)
	}
	if refusal == "" {
		t.Fatalf("the ring stopped at depth %d, but no hop said why — the client cannot tell this from a hop that simply died, which is the failure this issue also had to fix", depth)
	}
	if refusal != refusedPeerBusy && refusal != refusedNodeBusy {
		t.Fatalf("the ring stopped with reason %q, want a capacity refusal — something OTHER than the caps ended the loop, so this test is not proving what it claims", refusal)
	}
	t.Logf("ring of %d terminated at depth %d with %q (per-peer cap %d)", len(ring.addrs), depth, refusal, perPeer)
}

// ---------- what the client sees ----------

// TestClientTellsARefusingHopFromADeadOne is the failure-mode decision, driven
// end to end through the real dialChain.
//
// ADR-0038's fail-closed rule already settles what HAPPENS — the path fails and
// selection moves on, never a silent fall back to a shorter chain — so that is not
// what is at stake here. What is at stake is whether the client can tell the two
// apart, because they deserve opposite responses: a dead hop should be dropped, a
// full one is a good hop to come back to. Before this, both arrived as the same
// handshake failure.
func TestClientTellsARefusingHopFromADeadOne(t *testing.T) {
	t.Run("a full hop says so", func(t *testing.T) {
		_, sinkAddr := startSink(t)
		hop, hopAddr, hopKey := startCappedHop(t, sinkAddr, 1, 100, 0)

		held := dialForward(t, hopAddr, hopKey, sinkAddr)
		defer held.Close()
		waitForwardCount(t, hop, "127.0.0.1", 1)

		client := &Engine{}
		plan := &chainPlan{
			hops:    []relayHop{{id: hex.EncodeToString(hopKey.Public), pub: hopKey.Public, dial: hopAddr}},
			exitPub: hopKey.Public, // never reached: the hop refuses before the exit layer completes
			exitDia: sinkAddr,
		}
		conn, err := net.DialTimeout("tcp", hopAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(hopTestDeadline))

		_, err = client.dialChain(conn, plan, "example.com:443")
		if err == nil {
			t.Fatal("dialChain succeeded through a hop that was over its cap")
		}
		var refused *hopRefusedError
		if !errors.As(err, &refused) {
			t.Fatalf("dialChain error = %v (%T), want a hopRefusedError — a saturated hop is indistinguishable from a broken one and the client has no reason to ever come back to it", err, err)
		}
		if refused.reason != refusedPeerBusy {
			t.Errorf("reason = %q, want %q", refused.reason, refusedPeerBusy)
		}
		if !strings.Contains(err.Error(), "not down") {
			t.Errorf("the error text does not tell an operator the hop is alive: %q", err.Error())
		}
	})

	t.Run("a dead hop does not", func(t *testing.T) {
		// Same shape, but the hop's listener is closed before the client dials, so
		// the failure is a broken path rather than a decision. This must NOT come
		// back as a refusal, or the signal means nothing.
		key, err := generateExitKey()
		if err != nil {
			t.Fatalf("generateExitKey: %v", err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		deadAddr := ln.Addr().String()
		_ = ln.Close()

		client := &Engine{}
		plan := &chainPlan{
			hops:    []relayHop{{id: hex.EncodeToString(key.Public), pub: key.Public, dial: deadAddr}},
			exitPub: key.Public,
			exitDia: deadAddr,
		}
		conn, cliEnd := net.Pipe()
		deadline(t, conn, cliEnd)
		_ = conn.Close() // nothing is answering, exactly as a dead hop does not

		_, err = client.dialChain(cliEnd, plan, "example.com:443")
		if err == nil {
			t.Fatal("dialChain succeeded against a dead hop")
		}
		var refused *hopRefusedError
		if errors.As(err, &refused) {
			t.Fatalf("a dead hop was reported as a deliberate refusal (%v); the signal is worthless if a broken path can produce it", err)
		}
	})
}

// ---------- fixtures ----------

// startSink is the node a forwarding hop under test splices TO. It answers no
// handshake and speaks nothing: the hop only dials it and copies bytes, so a real
// peer would be more machinery for the same observation.
type sinkNode struct {
	ln    net.Listener
	count chan struct{}
	first chan struct{} // closed on the first accept, for tests that must not start timing early
	bytes atomic.Int64  // everything drained, so a pacing test can time ARRIVAL rather than a local write
}

// waitBytes blocks until at least n bytes have reached the sink. A client's Write
// returns as soon as the kernel buffers it, which on loopback is instant and says
// nothing about what crossed the hop — so anything timing the forwarding path has
// to wait here instead.
func (s *sinkNode) waitBytes(t *testing.T, n int64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if s.bytes.Load() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("only %d of %d bytes reached the next hop within %v", s.bytes.Load(), n, within)
}

func (s *sinkNode) accepted() int { return len(s.count) }

func startSink(t *testing.T) (*sinkNode, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sinkNode{ln: ln, count: make(chan struct{}, 64), first: make(chan struct{})}
	var once sync.Once
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case s.count <- struct{}{}:
			default:
			}
			once.Do(func() { close(s.first) })
			// Held, not closed: the hop's splice has to stay up so the circuit keeps
			// occupying a slot, which is the state every cap assertion reads.
			go func() {
				defer c.Close()
				_, _ = io.Copy(sinkCounter{s}, c)
			}()
		}
	}()
	return s, ln.Addr().String()
}

// startCappedHop is a real forwarding relay with the caps under test, whose
// directory names exactly one dialable next hop.
func startCappedHop(t *testing.T, nextAddr string, perPeer, total int, peerRate capacity.Rate) (*Engine, string, noise.DHKey) {
	t.Helper()
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	nextKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("next-hop key: %v", err)
	}
	dir := loadTestDirectory(t, []coldstart.Entry{
		{Role: "relay", ID: hex.EncodeToString(nextKey.Public), Ingress: nextAddr},
	})
	addr, e := startForwardNodeCapped(t, key, dir, perPeer, total, peerRate)
	return e, addr, key
}

// dialForward opens one onion forward through hopAddr toward next, and returns the
// client's end of the hop's own Noise channel — the channel a refusal arrives on.
func dialForward(t *testing.T, hopAddr string, hopKey noise.DHKey, next string) *noiseConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", hopAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial hop: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(hopTestDeadline))
	nc, err := clientHandshake(conn, hopKey.Public, hopTargetPrefix+next, nil)
	if err != nil {
		t.Fatalf("handshake with hop: %v", err)
	}
	return nc
}

// readRefusal reads the hop's sealed refusal off an established channel.
func readRefusal(t *testing.T, nc *noiseConn) string {
	t.Helper()
	buf := make([]byte, 128)
	n, err := nc.Read(buf)
	if err != nil {
		t.Fatalf("reading the hop's answer: %v — a refused client got a dead socket instead of a reason", err)
	}
	reason, ok := parseHopRefusal(buf[:n])
	if !ok {
		t.Fatalf("the hop sent %d bytes that are not a refusal; the client cannot tell this from a hop that died", n)
	}
	return reason
}

// waitForwardCount blocks until a circuit is actually accounted for. The client's
// handshake returns as soon as the hop answers, which is BEFORE relayForward has
// taken its slot, so asserting occupancy without this is a flake.
func waitForwardCount(t *testing.T, e *Engine, peer string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := e.forwardLimits.counts(peer); got == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	got, total := e.forwardLimits.counts(peer)
	t.Fatalf("occupancy for %s = %d (total %d), want %d", peer, got, total, want)
}

// ringMesh is n forwarding nodes each pointed at the next, closing a cycle.
type ringMesh struct {
	addrs []string
	pubs  [][]byte
}

// startRing wires the cycle. The nodes cannot be built in one pass — each one's
// directory has to name a node that does not exist yet, and the last one's has to
// name the first — so they are started against an empty directory and given the
// real one once every address is known.
func startRing(t *testing.T, perPeer, total int) *ringMesh {
	t.Helper()
	const n = 3

	// A directory has to name at least one usable hop to load at all, so the nodes
	// are seeded with one that is never dialed — a documentation address (RFC 5737),
	// replaced below by the real cycle once every port is known.
	seedKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}
	seed := loadTestDirectory(t, []coldstart.Entry{
		{Role: "relay", ID: hex.EncodeToString(seedKey.Public), Ingress: "198.51.100.1:20000"},
	})
	keys := make([]noise.DHKey, n)
	addrs := make([]string, n)
	engines := make([]*Engine, n)
	for i := range n {
		k, err := generateExitKey()
		if err != nil {
			t.Fatalf("ring key %d: %v", i, err)
		}
		keys[i] = k
		addrs[i], engines[i] = startForwardNodeCapped(t, k, seed, perPeer, total, 0)
	}

	entries := make([]coldstart.Entry, n)
	for i := range n {
		entries[i] = coldstart.Entry{Role: "relay", ID: hex.EncodeToString(keys[i].Public), Ingress: addrs[i]}
	}
	signed := signTestSnapshot(t, testSnapPriv(t), entries)
	pubs := make([][]byte, n)
	for i := range n {
		// Loaded per node with that node's own id, so each one still recognizes its
		// OWN address as a self-dial. The ring must be refused by the caps, not by
		// the self-dial guard tripping on a directory that forgot whose it is.
		dir, err := loadRelayDirectory(signed, testSnapPub(t), hex.EncodeToString(keys[i].Public), time.Now())
		if err != nil {
			t.Fatalf("ring directory %d: %v", i, err)
		}
		engines[i].relayDir.Store(dir)
		pubs[i] = keys[i].Public
	}
	return &ringMesh{addrs: addrs, pubs: pubs}
}

// sinkCounter tallies what actually arrived, so pacing is observed at the far end
// of the hop rather than at the near end of a socket buffer.
type sinkCounter struct{ s *sinkNode }

func (w sinkCounter) Write(p []byte) (int, error) {
	w.s.bytes.Add(int64(len(p)))
	return len(p), nil
}

// fakeRemoteConn is a stream whose only interesting property is the address it
// reports, for testing the peer key without a socket.
type fakeRemoteConn struct {
	addrlessConn
	addr string
}

func (f fakeRemoteConn) RemoteAddr() net.Addr { return fakeAddr(f.addr) }

type fakeAddr string

func (fakeAddr) Network() string  { return "tcp" }
func (a fakeAddr) String() string { return string(a) }

// addrlessConn stands in for a stream with no addressable remote — the case
// forwardPeerKey has to fold into the shared empty key rather than skip.
type addrlessConn struct{}

func (addrlessConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (addrlessConn) Write(p []byte) (int, error) { return len(p), nil }
func (addrlessConn) Close() error                { return nil }
