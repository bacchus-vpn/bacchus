package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// Per-connect idempotency (issue #1, ADR-0042 §2).
//
// Every failure here is SILENT in production — the pre-#1 coordinator answered every
// copy of a retransmitted connect perfectly well, it just answered each of them with a
// different exit — so each test below is written to fail when the mechanism is removed,
// not merely to pass while it is present. The load-bearing assertion is on the size of
// the `sessions` map, which is exactly the quantity the bug inflated.

// exitFleet registers n exits in one country, each with its own socket so a test can
// tell which one was paired and read what it was sent. Several exits in one country is
// the whole point: with one exit, resampling would return the same answer by accident
// and the difference the nonce makes would be invisible.
func exitFleet(t *testing.T, n int, country string) map[string]*net.UDPConn {
	t.Helper()
	fleet := make(map[string]*net.UDPConn, n)
	for i := 0; i < n; i++ {
		id := "fleet-exit-" + string(rune('a'+i))
		sock := fakePeer(t)
		registerExit(id, country, "10.0.0."+string(rune('1'+i))+":20000", sock)
		fleet[id] = sock
	}
	return fleet
}

func sessionCount() int {
	mu.Lock()
	defer mu.Unlock()
	return len(sessions)
}

// TestRetransmittedConnectIsOneAssignment is #1's headline, and the measurement
// ADR-0042 §2 recorded as an open residual: one Connect() minted six sessions across
// three distinct exits, because sendN's copies were each assigned independently.
//
// Three copies of ONE request, carrying one nonce, must produce one session against one
// exit — and every copy must be answered, since the copies exist to survive loss and a
// client that hears nothing back concludes the coordinator is blocked.
func TestRetransmittedConnectIsOneAssignment(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client := fakePeer(t)
	fleet := exitFleet(t, 3, "NL")

	nonce := randID()
	const copies = 3
	for i := 0; i < copies; i++ {
		dialConnect(wire{Country: "NL", Mode: "direct", Nonce: nonce}, client.LocalAddr().(*net.UDPAddr))
	}

	// One request, one assignment. This is the assertion the bug fails: without the
	// dedupe each copy runs its own randomized chooseExit and the map holds three.
	if got := sessionCount(); got != 1 {
		t.Fatalf("three copies of one connect minted %d sessions; want exactly 1 — one request must be one assignment (ADR-0042 §2)", got)
	}

	// And every copy is still answered, with the SAME answer. A client reading three
	// replies must not be able to choose among three exits.
	var replies []wire
	for i := 0; i < copies; i++ {
		replies = append(replies, recvWire(t, client, time.Second))
	}
	for i, r := range replies {
		if r.Type != "session" {
			t.Fatalf("copy %d was answered %+v; want a session reply — a retransmit must still be answered", i, r)
		}
		if r.Session != replies[0].Session || r.ExitID != replies[0].ExitID {
			t.Errorf("copy %d answered session=%q exit=%q; copy 0 answered session=%q exit=%q — the copies of one connect must return the same session AND the same exit",
				i, r.Session, r.ExitID, replies[0].Session, replies[0].ExitID)
		}
	}

	// The paired node hears the assign on every copy too, so a LOST assign is recovered
	// by the retransmit rather than by minting a second session against a different
	// exit — which is what the pre-#1 path did, leaving the client and the node it was
	// paired with holding different session ids.
	sock := fleet[replies[0].ExitID]
	if sock == nil {
		t.Fatalf("reply named exit %q, which is not in the fleet %v", replies[0].ExitID, fleet)
	}
	for i := 0; i < copies; i++ {
		if asg := recvWire(t, sock, time.Second); asg.Type != "assign" || asg.Session != replies[0].Session {
			t.Errorf("copy %d: exit got %+v; want an assign for session %q", i, asg, replies[0].Session)
		}
	}
}

// TestDistinctNoncesAreDistinctRequests is the non-vacuity half of the test above, and
// it is not optional: "always replay the first session this client was ever given" would
// satisfy that test completely while breaking every retry, every mode fallback and every
// reconnect. A genuinely new request must still be assigned.
func TestDistinctNoncesAreDistinctRequests(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client := fakePeer(t)
	exitFleet(t, 3, "NL")

	for i := 0; i < 3; i++ {
		dialConnect(wire{Country: "NL", Mode: "direct"}, client.LocalAddr().(*net.UDPAddr)) // fresh nonce each
	}
	if got := sessionCount(); got != 3 {
		t.Fatalf("three DIFFERENT requests minted %d sessions; want 3 — idempotency collapses copies of one request, never distinct requests", got)
	}
}

// TestNonceIsBoundToItsClient pins the (source address, nonce) key.
//
// Keyed on the nonce alone, a client that observed or guessed another's key would be
// handed that client's session — learning which exit it was given and, through
// ExcludeSessions, able to steer its own assignments around it. That is the same
// property excludedExits' src binding protects, and it matters most exactly where it is
// easiest to hit: several clients behind one NAT share a source address but not a port,
// so the full UDPAddr is what separates them.
func TestNonceIsBoundToItsClient(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	alice, bob := fakePeer(t), fakePeer(t)
	exitFleet(t, 3, "NL")

	shared := randID()
	dialConnect(wire{Country: "NL", Mode: "direct", Nonce: shared}, alice.LocalAddr().(*net.UDPAddr))
	dialConnect(wire{Country: "NL", Mode: "direct", Nonce: shared}, bob.LocalAddr().(*net.UDPAddr))

	if got := sessionCount(); got != 2 {
		t.Fatalf("two clients reusing one nonce got %d sessions; want 2 — a nonce is scoped to the client that sent it", got)
	}
	aliceReply, bobReply := recvWire(t, alice, time.Second), recvWire(t, bob, time.Second)
	if aliceReply.Session == bobReply.Session {
		t.Errorf("both clients were handed session %q — one client must never be given another's session by naming its nonce", aliceReply.Session)
	}
}

// TestConnectWithoutANonceIsRefused: the key is required, not advisory.
//
// This is the decision, not the plumbing. Falling back to per-datagram assignment for a
// connect that omits the field would hand the pre-#1 behaviour — several independent
// exit draws per request — to precisely the client that wants it, so the guard would
// bind only the honest. The refusal names the client's own malformed request and
// reveals nothing about the network.
func TestConnectWithoutANonceIsRefused(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client := fakePeer(t)
	exitFleet(t, 3, "NL")

	handle(wire{Type: "connect", Country: "NL", Mode: "direct"}, client.LocalAddr().(*net.UDPAddr))

	reply := recvWire(t, client, time.Second)
	if reply.Type != "error" || reply.Reason != string(refuseNoNonce) {
		t.Errorf("an unnonced connect was answered %+v; want an error reasoned %q", reply, refuseNoNonce)
	}
	if got := sessionCount(); got != 0 {
		t.Errorf("an unnonced connect minted %d session(s); want none", got)
	}
}

// TestOverlongNonceIsRefused covers the resource bound. It is refused rather than
// ignored for the same reason an absent one is: treating an unusable key as no key would
// let a client opt out of idempotency by sending something too long to store.
func TestOverlongNonceIsRefused(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client := fakePeer(t)
	exitFleet(t, 3, "NL")

	handle(wire{Type: "connect", Country: "NL", Mode: "direct", Nonce: strings.Repeat("a", maxNonceLen+1)},
		client.LocalAddr().(*net.UDPAddr))

	reply := recvWire(t, client, time.Second)
	if reply.Type != "error" || reply.Reason != string(refuseNoNonce) {
		t.Errorf("an over-long nonce was answered %+v; want an error reasoned %q", reply, refuseNoNonce)
	}
	if got := sessionCount(); got != 0 {
		t.Errorf("an over-long nonce minted %d session(s); want none", got)
	}
	// Non-vacuity: a nonce AT the bound is fine, so the check is a bound and not a
	// blanket rejection of anything longer than core happens to send.
	handle(wire{Type: "connect", Country: "NL", Mode: "direct", Nonce: strings.Repeat("a", maxNonceLen)},
		client.LocalAddr().(*net.UDPAddr))
	if got := recvWire(t, client, time.Second); got.Type != "session" {
		t.Errorf("a nonce exactly at the %d-byte bound was answered %+v; want a session", maxNonceLen, got)
	}
}

// TestMintedConnectRecordExpires: the dedupe memory is bounded, and a nonce reused past
// the window is simply a new request rather than a permanent claim on one session.
//
// The bound is what keeps this from being a new unbounded surface — one entry per
// answered connect, held for connectDedupeTTL and no longer.
func TestMintedConnectRecordExpires(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client := fakePeer(t)
	exitFleet(t, 3, "NL")

	nonce := randID()
	dialConnect(wire{Country: "NL", Mode: "direct", Nonce: nonce}, client.LocalAddr().(*net.UDPAddr))
	if got := mintedConnectCount(); got != 1 {
		t.Fatalf("setup: %d dedupe record(s) after one connect, want 1", got)
	}

	ageMintedConnects(connectDedupeTTL + time.Second)
	mu.Lock()
	prune(time.Now())
	mu.Unlock()
	if got := mintedConnectCount(); got != 0 {
		t.Errorf("%d dedupe record(s) survived past connectDedupeTTL; prune must expire them", got)
	}

	// And the expired key no longer replays: the same nonce is now an ordinary new
	// request. (Anything else would mean a client could hold a session id forever.)
	dialConnect(wire{Country: "NL", Mode: "direct", Nonce: nonce}, client.LocalAddr().(*net.UDPAddr))
	if got := sessionCount(); got != 2 {
		t.Errorf("reusing a nonce after its record expired produced %d session(s); want 2 — an expired key is not a live one", got)
	}
}

func mintedConnectCount() int {
	mu.Lock()
	defer mu.Unlock()
	return len(mintedConnects)
}

// ageMintedConnects backdates every dedupe record so a prune sweep sees it as expired,
// the same shape ageSession uses for the session map.
func ageMintedConnects(d time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	for _, mc := range mintedConnects {
		mc.at = time.Now().Add(-d)
	}
}

// TestHarvestedPeerRelaySessionIsReaped covers the second half of #1: peer-relay
// sessions are EXEMPT from prune's idle sweep, because their liveness is their relay's
// (#96/#105), and that exemption applied to sessions that were never brought up at all.
//
// So a client harvesting assignments through mode:"relay" accumulated entries no reaper
// would ever touch, while a direct-mode client's aged out in sessionTTL. The exits those
// sessions name stay resolvable in ExcludeSessions for as long as the entry lives, so
// what expires in two minutes on one path never expired on the other.
//
// The distinction drawn is "was it ever brought up", not "is it a relay session":
// TestReselectMonitorsPeerRelaySessionPastSessionTTL is the other half and pins that an
// established peer-relay session still survives indefinitely.
func TestHarvestedPeerRelaySessionIsReaped(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-1", relayP)

	// Paired and then abandoned — no transport handshake ever driven over it. This is
	// what a harvesting client produces: it wants the assignment, not the tunnel.
	connectRelay(reExitID, client)
	if asg := recvWire(t, relayP, time.Second); asg.Type != "assign" {
		t.Fatalf("setup: relay got %+v, want an assign", asg)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Relay != relayPeer {
		t.Fatalf("setup: got relay disposition %q, want %q", sess.Relay, relayPeer)
	}

	ageSession(sess.Session, sessionTTL+time.Minute)
	mu.Lock()
	prune(time.Now())
	mu.Unlock()

	if sessionExists(sess.Session) {
		t.Error("a peer-relay session that never saw a single handshake frame survived prune — it was minted and abandoned, and the exemption is for sessions that were brought up (issue #1)")
	}
}
