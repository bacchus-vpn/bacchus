package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/selection"
)

// Regression barriers for the per-path exit key (issue #4).
//
// The code is correct; what was missing is any test that fails if it is undone. Three
// mutations survived the whole ./core/... suite, and the cause was structural rather
// than a set of gaps: **every fake in the suite uses one constant exit id**
// (pool_test.go's testExitID, reconnect_smoke_test.go, relay_metadata_test.go, and
// cmd/node's midsession_recovery_test.go where exit2 deliberately shares exit1's
// identity). So no test ever had a coordinator assign a DIFFERENT exit across a
// reconnect or a reselect — which is the exact scenario country-only assignment (#146)
// created and the exact scenario that forced the key to become per-path.
//
// A suite built on one exit id cannot see the difference between per-path and
// per-engine state, because in that world they are the same value. These fixtures hand
// back a different exit on the second assignment.
//
// What the mutation costs in production is worth stating, because it is not a crash:
// the client runs clientHandshake against the PREVIOUS exit's static key, which fails as
// an authentication error. It looks like a hostile exit. The one thing it does not look
// like is the plumbing mistake it is.

// distinctExitID mints a well-formed 64-hex exit id (an X25519 public key), so the
// wire-boundary validation in attemptWith accepts it.
func distinctExitID(t *testing.T) (string, []byte) {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	return hex.EncodeToString(k[:]), k[:]
}

// TestReconnectSwapsTheExitKeyWhenTheCoordinatorReassigns is the single-transport half.
//
// setReconnectSession must swap rcExitPub along with the session. Keeping the first
// value — i.e. reverting to per-engine state — is a mutation the whole suite survived,
// because with one constant exit id in every fake there was nothing to swap TO.
func TestReconnectSwapsTheExitKeyWhenTheCoordinatorReassigns(t *testing.T) {
	e, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{RoleClient}, SocksAddr: "127.0.0.1:0", Geo: "NL"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Stop)

	firstID, firstPub := distinctExitID(t)
	secondID, secondPub := distinctExitID(t)

	e.setReconnectSession(connPath{sess: newFakeSession(), sid: "s1", exitID: firstID, exitPub: firstPub})
	if _, _, pub := e.activeReconnectSession(); hex.EncodeToString(pub) != firstID {
		t.Fatalf("setup: active exit key is %s, want %s", shortID(hex.EncodeToString(pub)), shortID(firstID))
	}

	// The reconnect lands on a DIFFERENT exit in the same country — which the
	// coordinator is free to do on every reconnect, since the client no longer names one.
	e.setReconnectSession(connPath{sess: newFakeSession(), sid: "s2", exitID: secondID, exitPub: secondPub})
	_, _, pub := e.activeReconnectSession()
	if hex.EncodeToString(pub) != secondID {
		t.Fatalf("after reconnecting to a different exit the active key is still %s, want %s — the key must travel with the path (issue #146); held per-engine, every stream on the new session runs its end-to-end handshake against the OLD exit's static key and fails as an authentication error that looks like a hostile exit",
			shortID(hex.EncodeToString(pub)), shortID(secondID))
	}
}

// TestReselectSwapsTheExitKeyWhenTheCoordinatorReassigns is the pooled half, and the
// same mutation: setActivePath keeping the first activeExitPub.
//
// The pooled path fails the same way with one extra step of indirection — the SOCKS
// accept loop reads activePath() per accepted connection, so the wrong key is picked up
// by every connection made after the failover rather than at failover time.
func TestReselectSwapsTheExitKeyWhenTheCoordinatorReassigns(t *testing.T) {
	e, err := New(Config{
		Coordinators:  []string{testCoord},
		Roles:         []string{RoleClient},
		SocksAddr:     "127.0.0.1:0",
		Geo:           "NL",
		TransportPool: []string{TransportWebRTC},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Stop)

	firstID, firstPub := distinctExitID(t)
	secondID, secondPub := distinctExitID(t)

	e.setActivePath(dialedPath{sess: newFakeSession(), exitID: firstID, exitPub: firstPub})
	if _, pub := e.activePath(); hex.EncodeToString(pub) != firstID {
		t.Fatalf("setup: active exit key is %s, want %s", shortID(hex.EncodeToString(pub)), shortID(firstID))
	}

	e.setActivePath(dialedPath{sess: newFakeSession(), exitID: secondID, exitPub: secondPub})
	if _, pub := e.activePath(); hex.EncodeToString(pub) != secondID {
		t.Fatalf("after a reselect onto a different exit the active key is still %s, want %s — a candidate names a COUNTRY, and which exit inside it the coordinator assigned is known only from the session reply, so the key has to come from the dialed path (issue #146)",
			shortID(hex.EncodeToString(pub)), shortID(secondID))
	}
}

// TestPoolRetryExcludesTheSessionThatFailedValidation pins the retry exclude: deleting
// `exclude = append(exclude, r.sid)` in dialCandidate survived the suite, leaving
// countryAttempts=2 unpinned end to end.
//
// Without it the retry is handed the same exit that just failed to carry traffic, so the
// second attempt is a re-run of the first and the retry budget buys nothing. The
// coordinator resolves a named SESSION to the exit it assigned (ADR-0042 §7, and sessions
// rather than exit ids so that excluding cannot be turned into pinning-by-complement) —
// which means an empty exclude list is not a weaker request, it is a different one.
func TestPoolRetryExcludesTheSessionThatFailedValidation(t *testing.T) {
	firstID, _ := distinctExitID(t)
	secondID, _ := distinctExitID(t)

	// A coordinator that assigns a DIFFERENT exit on each pairing and records what each
	// connect asked it to avoid. Two exits is the whole fixture the suite did not have:
	// with one constant id there is no second exit for a retry to land on, so there is
	// nothing for the exclusion to accomplish and nothing for its absence to break.
	var mu sync.Mutex
	var excludes [][]string
	assigned := []string{firstID, secondID}
	seq := 0

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	peer := servePeer(t, pc)
	go func() {
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
			// One record per REQUEST, not per datagram: the three copies of one connect
			// share a nonce (issue #1) and a real coordinator answers them as one.
			if seq == 0 || m.Nonce != lastNonce {
				lastNonce = m.Nonce
				seq++
				excludes = append(excludes, append([]string(nil), m.ExcludeSessions...))
			}
			which := seq
			mu.Unlock()
			if which > len(assigned) {
				which = len(assigned)
			}
			b, _ := json.Marshal(wire{Type: "session", Session: fmt.Sprintf("sess-%d", which), ExitID: assigned[which-1]})
			_, _ = peer.WriteTo(b, src)
		}
	}()

	e, err := New(Config{
		Coordinators:  []string{pc.LocalAddr().String()},
		Roles:         []string{RoleClient},
		SocksAddr:     "127.0.0.1:0",
		Geo:           "NL",
		TransportPool: []string{TransportWebRTC},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	// A transport whose dial always succeeds, so the pairing is what is under test and
	// not the WebRTC stack. Validation then fails over the fake session (no streams),
	// which is precisely the condition the retry exists for: paired fine, did not carry
	// traffic.
	e.transports = map[string]Transport{"fake": &fakeTransport{}}

	_, derr := e.dialAndValidate(ctx, selection.Candidate{Country: "NL", Transport: "fake", Mode: selection.ModeDirect})
	if derr == nil {
		t.Fatal("the candidate validated over a session with no streams — the fixture is not exercising the retry")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(excludes) < 2 {
		t.Fatalf("only %d pairing request(s) reached the coordinator; countryAttempts=%d means a failed validation must be retried against another exit", len(excludes), countryAttempts)
	}
	if len(excludes[0]) != 0 {
		t.Errorf("the FIRST connect already excluded %v; it has nothing to exclude yet", excludes[0])
	}
	var named bool
	for _, sid := range excludes[1] {
		if sid == "sess-1" {
			named = true
		}
	}
	if !named {
		t.Errorf("the retry named %v in ExcludeSessions; it must name sess-1, the session whose exit just failed to carry traffic — without it the coordinator is free to hand back that very exit and countryAttempts buys nothing (issue #4)", excludes[1])
	}
}

// lastNonce lets the fake coordinator above collapse the copies of one connect the way
// a real one does (issue #1), so `excludes` holds one entry per pairing REQUEST.
var lastNonce string

// TestConnectRefusesASessionWithoutAUsableExitID pins the wire-boundary validation:
// neutering the `hex.DecodeString` / `len != 32` check in attemptWith survived the suite
// (issue #4).
//
// The exit id on a session reply is not informational — an exit's id IS its Noise static
// public key (ADR-0009) — so a reply that omits it, or carries something that is not a
// key, describes a session the client cannot possibly use. Validating at the wire
// boundary is what turns that into a refusal here rather than an opaque handshake failure
// several layers down, where it reads as a hostile exit.
//
// It is also load-bearing for issue #5's distinction: a refusal sets allSilent = false,
// so a coordinator answering with malformed exit ids is not mistaken for an unreachable
// one and does not trigger mesh-walk.
func TestConnectRefusesASessionWithoutAUsableExitID(t *testing.T) {
	for name, exitID := range map[string]string{
		"absent":     "",
		"not hex":    "zzzz",
		"wrong size": hex.EncodeToString(make([]byte, 16)),
	} {
		t.Run(name, func(t *testing.T) {
			addr := fakeConnectCoordinator(t, func(string) (wire, bool) {
				return wire{Type: "session", ExitID: exitID}, true
			})
			e, err := New(Config{
				Coordinators: []string{addr},
				Roles:        []string{RoleClient},
				SocksAddr:    "127.0.0.1:0",
				Geo:          "NL",
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := e.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer e.Stop()
			e.transport = &fakeTransport{} // a dial that would succeed, so only the id is under test

			err = e.Connect(ctx)
			if err == nil {
				t.Fatalf("a session naming exit id %q was accepted — the client cannot bring up the end-to-end channel without a 32-byte key, so this is a session it will fail on later and blame the exit for", exitID)
			}
			// And specifically NOT as an unreachable coordinator: this member answered.
			if errors.Is(err, ErrNoCoordinatorReachable) {
				t.Errorf("a coordinator that answered with a malformed exit id was reported as unreachable (%v) — that is the mesh-walk trigger (issues #4/#5)", err)
			}
		})
	}
}

// TestCountryReplyWireContract is the test core/engine.go's wireCountry doc names.
//
// It did not exist anywhere in the repo — the comment asserted a pin that was not there,
// which is worse than no comment, because a reader checking whether the duplicated
// structs were covered would conclude they were (issue #4).
//
// The two copies are cmd/coordinator's countryInfo and core's wireCountry, deliberately
// duplicated because the binaries do not import each other. This pins core's half: the
// JSON field names a coordinator emits, decoded by the struct a client decodes with.
// PingMs is included specifically because it is the field with no other coverage — it is
// an unfed seam (ADR-0042 §6, always 0 and omitempty), so nothing else in the suite would
// notice if its tag drifted, and the whole point of shipping the seam is that a client
// can render it the moment it is fed.
func TestCountryReplyWireContract(t *testing.T) {
	const encoded = `{"type":"countries","countries":[{"country":"NL","exits":3,"available":1,"busy":false,"pingMs":42}]}`

	var m wire
	if err := json.Unmarshal([]byte(encoded), &m); err != nil {
		t.Fatalf("a countries reply in the coordinator's own encoding did not decode: %v", err)
	}
	if len(m.Countries) != 1 {
		t.Fatalf("decoded %d countries, want 1 — the `countries` field name has drifted", len(m.Countries))
	}
	got := m.Countries[0]
	want := wireCountry{Country: "NL", Exits: 3, Available: 1, Busy: false, PingMs: 42}
	if got != want {
		t.Errorf("decoded %+v, want %+v — a field name that drifts between the two copies decodes as a zero value rather than as an error, so a country would silently read as having no exits", got, want)
	}

	// Busy must survive as its own field rather than being re-derived: a country that
	// is present but full is the state #147 has to be able to say out loud, and Exits
	// alone cannot express it.
	const busyEncoded = `{"type":"countries","countries":[{"country":"SE","exits":2,"available":0,"busy":true}]}`
	var b wire
	if err := json.Unmarshal([]byte(busyEncoded), &b); err != nil {
		t.Fatalf("unmarshal busy reply: %v", err)
	}
	if !b.Countries[0].Busy || b.Countries[0].Exits != 2 {
		t.Errorf("a busy country decoded as %+v — busy must arrive as its own field, so two clients cannot derive it differently", b.Countries[0])
	}

	// And the round trip: what this client would encode is what a coordinator decodes.
	out, err := json.Marshal(wire{Type: "countries", Countries: []wireCountry{want}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back wire
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back.Countries[0] != want {
		t.Errorf("round trip produced %+v, want %+v", back.Countries[0], want)
	}
}
