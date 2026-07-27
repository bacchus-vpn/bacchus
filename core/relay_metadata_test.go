package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// This file covers the coordinator relay-metadata lane on the core side:
//   - issue #97: a relay:"turn" reply is the DIRECT disposition (accurate
//     connected-via line + accounted like a direct session), while relay:"peer"
//     stays a relayed, unaccounted path; relayPipe surfaces a dial-to-exit
//     failure; and the relayPeer/relayTURN literals are pinned so they cannot
//     drift from the coordinator's copy.
//   - issue #56: the client remembers a peer relay whose dial failed this Connect
//     (by the coordinator's opaque tag) and skips a second pool member that
//     re-offers the same relay.
//
// The connect-path tests drive the real establish/connectVia/attemptWith ladder
// with the fake transport + fakeConnectCoordinator harness from
// reconnect_smoke_test.go, so the disposition and dedupe logic is exercised as
// shipped, not through a seam.

// dialCountTransport is a Transport that counts Dial calls and (optionally) fails
// them, so a test can prove how many transport dials a connect pass actually made
// — the observable that separates "skipped a known-bad relay" from "re-dialed it".
type dialCountTransport struct {
	mu    sync.Mutex
	dials int
	fail  bool
}

func (t *dialCountTransport) Name() string { return "fake" }

func (t *dialCountTransport) Dial(ctx context.Context, sig Signaler) (Session, error) {
	t.mu.Lock()
	t.dials++
	fail := t.fail
	t.mu.Unlock()
	if fail {
		return nil, errors.New("dialCountTransport: dial failed")
	}
	return newFakeSession(), nil
}

func (t *dialCountTransport) Accept(ctx context.Context, sig Signaler) (Session, error) {
	return nil, errors.New("dialCountTransport: accept unused")
}

func (t *dialCountTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dials
}

// newRelayMetaClient builds a client engine on the real single-transport connect
// path with accounting enabled, so a test can assert both the connected-via event
// and whether a counter was started (the two halves of issue #97's "treat turn as
// direct"). Fast timeouts keep it snappy; a long accounting interval keeps the
// receipt loop from ticking during the test.
func newRelayMetaClient(t *testing.T, coords []string, tr Transport) *Engine {
	t.Helper()
	eng, err := New(Config{
		Coordinators:    coords,
		Roles:           []string{RoleClient},
		SocksAddr:       "127.0.0.1:0",
		Geo:             "NL", // a connect names a country now (issue #146)
		AcctDir:         t.TempDir(),
		AcctIntervalSec: 3600, // don't let the client accounting loop tick mid-test
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.transport = tr // real establish/connectVia/attemptWith, fake transport under it
	eng.directTimeout = 1 * time.Second
	eng.relayTimeout = 1 * time.Second
	eng.reconnectBase = 20 * time.Millisecond
	eng.reconnectMax = 200 * time.Millisecond
	eng.reconnectHealthy = 0
	return eng
}

// refuseDirectMint returns a fakeConnectCoordinator reply func that refuses direct
// (so the client falls over to relay) and mints a relay-mode session stamped with
// the given disposition and tag.
//
// Every mint carries an ExitID, because a real coordinator's does and a client cannot
// use a session without one — an exit's id IS its Noise static key (issue #146,
// ADR-0009), so a mint that omits it is refused at the wire boundary. Omitting it here
// would make these tests exercise that refusal path instead of the relay-disposition
// behaviour they are about.
func refuseDirectMint(relay, tag string) func(string) (wire, bool) {
	return func(mode string) (wire, bool) {
		if mode == modeDirect {
			return wire{Type: "error"}, true
		}
		return wire{Type: "session", ExitID: testExitID, Relay: relay, RelayTag: tag}, true
	}
}

// TestConnectTurnFallbackIsDirectDisposition is issue #97's client half: a
// relay-mode connect that comes back relay:"turn" must report the DIRECT path
// (not "via RELAY") and be accounted like a direct session — the exit holds a
// session id to attribute bytes to, so there is a real counter to cosign.
func TestConnectTurnFallbackIsDirectDisposition(t *testing.T) {
	sink, snap := collectEvents()
	coord := fakeConnectCoordinator(t, refuseDirectMint(relayTURN, ""))
	eng := newRelayMetaClient(t, []string{coord}, &fakeTransport{})
	eng.cfg.OnEvent = sink

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	evs := snap()
	if !hasEventContaining(evs, EventConnected, "connected DIRECT to exit") {
		t.Fatalf("a TURN fallback must report the DIRECT disposition; got %+v", evs)
	}
	if hasEventContaining(evs, EventConnected, "via RELAY") {
		t.Fatalf("a TURN fallback must NOT report 'via RELAY'; got %+v", evs)
	}
	if _, ctr, _ := eng.activeReconnectSession(); ctr == nil {
		t.Fatal("a TURN fallback must start accounting (issue #97): counter is nil")
	}
}

// TestConnectPeerRelayIsRelayDisposition is the contrast case: a genuine
// relay:"peer" path reports "via RELAY" and is NOT accounted — a peer-relay
// splice carries no session id the exit can attribute bytes to (ADR-0021).
func TestConnectPeerRelayIsRelayDisposition(t *testing.T) {
	sink, snap := collectEvents()
	coord := fakeConnectCoordinator(t, refuseDirectMint(relayPeer, "aabbccddaabbccdd"))
	eng := newRelayMetaClient(t, []string{coord}, &fakeTransport{})
	eng.cfg.OnEvent = sink

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	evs := snap()
	if !hasEventContaining(evs, EventConnected, "via RELAY") {
		t.Fatalf("a peer relay must report the RELAY disposition; got %+v", evs)
	}
	if hasEventContaining(evs, EventConnected, "connected DIRECT to exit") {
		t.Fatalf("a peer relay must NOT report DIRECT; got %+v", evs)
	}
	if _, ctr, _ := eng.activeReconnectSession(); ctr != nil {
		t.Fatal("a peer-relay path must NOT be accounted (ADR-0021): counter is non-nil")
	}
}

// TestConnectSkipsRelayTagThatAlreadyFailed is issue #56: two pool members hand
// back the SAME peer relay (same opaque tag) and refuse direct. The transport dial
// fails, so the first member's relay tag is recorded; the second member's re-offer
// of that tag must be skipped, not re-dialed — one transport dial across the pass,
// not two.
func TestConnectSkipsRelayTagThatAlreadyFailed(t *testing.T) {
	const tag = "deadbeefdeadbeef"
	reply := refuseDirectMint(relayPeer, tag)
	c1 := fakeConnectCoordinator(t, reply)
	c2 := fakeConnectCoordinator(t, reply)
	tr := &dialCountTransport{fail: true}
	eng := newRelayMetaClient(t, []string{c1, c2}, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	// Every dial fails, so the initial connect returns an error; the dial count is
	// what the dedupe is about.
	if err := eng.Connect(ctx); err == nil {
		t.Fatal("Connect should fail when every relay dial fails")
	}
	if got := tr.count(); got != 1 {
		t.Fatalf("expected 1 transport dial (the second member's same-relay re-offer skipped), got %d", got)
	}
}

// TestConnectRetriesDistinctRelayTags is the non-vacuous companion: when the two
// members hand back DIFFERENT relays, no skip happens — both are dialed. This is
// what proves the skip above keys on the tag, not on "always skip the second
// member".
func TestConnectRetriesDistinctRelayTags(t *testing.T) {
	c1 := fakeConnectCoordinator(t, refuseDirectMint(relayPeer, "1111111111111111"))
	c2 := fakeConnectCoordinator(t, refuseDirectMint(relayPeer, "2222222222222222"))
	tr := &dialCountTransport{fail: true}
	eng := newRelayMetaClient(t, []string{c1, c2}, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	if err := eng.Connect(ctx); err == nil {
		t.Fatal("Connect should fail when every relay dial fails")
	}
	if got := tr.count(); got != 2 {
		t.Fatalf("distinct relays must both be dialed, got %d dials", got)
	}
}

// TestConnectDoesNotDedupTurnFallbackTag is issue #111: the rotation dedupe is
// gated on the relayPeer disposition, so a coordinator that (illegitimately) stamps
// a relay tag on a relay:"turn" reply must NOT cause a later pool member's same-tag
// TURN reply to be skipped. Both members' paths must be dialed — a hostile
// coordinator cannot poison a valid direct-over-TURN path by re-using a tag off the
// peer path. This is the adversarial contrast to TestConnectSkipsRelayTagThatAlreadyFailed:
// same shape, same tag, but relayTURN instead of relayPeer, so no skip may happen.
//
// Non-vacuous: revert the reply.relay == relayPeer gate in attemptWith and this
// asserts 1 dial (the poisoned skip) instead of 2, failing loudly.
func TestConnectDoesNotDedupTurnFallbackTag(t *testing.T) {
	const tag = "deadbeefdeadbeef"
	// Both members refuse direct and mint a relay:"turn" reply carrying the SAME
	// tag — the illegitimate stamp a hostile coordinator would use to trick the
	// client into skipping the second member's valid direct-over-TURN path.
	reply := refuseDirectMint(relayTURN, tag)
	c1 := fakeConnectCoordinator(t, reply)
	c2 := fakeConnectCoordinator(t, reply)
	tr := &dialCountTransport{fail: true}
	eng := newRelayMetaClient(t, []string{c1, c2}, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	if err := eng.Connect(ctx); err == nil {
		t.Fatal("Connect should fail when every relay dial fails")
	}
	// A turn-disposition tag is never deduped, so BOTH members are dialed. If the
	// gate regresses, the second member's identical tag is treated as a known-bad
	// peer relay and skipped, dropping this to 1.
	if got := tr.count(); got != 2 {
		t.Fatalf("a relay:%q tag must never be deduped (issue #111): expected 2 dials, got %d", relayTURN, got)
	}
}

// TestRelayDedup unit-tests the per-pass skip-set directly, including the nil and
// empty-tag no-ops the connect path relies on (the pool passes nil; direct and
// TURN-fallback replies carry no tag).
func TestRelayDedup(t *testing.T) {
	var nilD *relayDedup
	if nilD.seen("x") {
		t.Fatal("nil dedupe must never report seen")
	}
	nilD.fail("x") // must not panic

	d := newRelayDedup()
	if d.seen("x") {
		t.Fatal("a fresh dedupe sees nothing")
	}
	d.fail("") // empty tag is a no-op (direct / TURN-fallback / pre-#56 coordinator)
	if d.seen("") {
		t.Fatal("an empty tag must never be seen")
	}
	d.fail("relay-x")
	if !d.seen("relay-x") {
		t.Fatal("a recorded tag must be seen")
	}
	if d.seen("relay-y") {
		t.Fatal("an unrelated tag must not be seen")
	}
}

// TestRelayPipeEmitsErrorOnFailedDial is issue #97's fix (3): a relay that cannot
// reach its assigned exit must surface the failure, not swallow it.
func TestRelayPipeEmitsErrorOnFailedDial(t *testing.T) {
	sink, snap := collectEvents()
	e := &Engine{cfg: Config{OnEvent: sink}}

	// A guaranteed-refused loopback address: bind a port, then close it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()

	client, relayEnd := net.Pipe()
	deadline(t, client, relayEnd)
	e.relayPipe(pipeStream{Conn: relayEnd, label: e2eLabel}, dead)

	if !hasEventContaining(snap(), EventError, "dial exit") {
		t.Fatalf("relayPipe must emit an error on a failed dial-to-exit (issue #97); got %+v", snap())
	}
}

// TestRelayDispositionWireContract pins the relay disposition literals on the core
// side of the coordinator<->client wire. They are duplicated in
// cmd/coordinator/main.go (that binary does not import core); the coordinator test
// of the same name pins the identical bytes, so neither copy can drift without a
// test failing (issue #97).
func TestRelayDispositionWireContract(t *testing.T) {
	if relayPeer != "peer" || relayTURN != "turn" {
		t.Fatalf("relay disposition literals drifted: peer=%q turn=%q", relayPeer, relayTURN)
	}
	// The exact bytes a coordinator stamps must decode back to these consts.
	var m wire
	if err := json.Unmarshal([]byte(`{"type":"session","relay":"peer","relayTag":"abc123"}`), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Relay != relayPeer {
		t.Fatalf(`{"relay":"peer"} must decode to relayPeer, got %q`, m.Relay)
	}
	if m.RelayTag != "abc123" {
		t.Fatalf("relayTag must decode from the wire, got %q", m.RelayTag)
	}
}
