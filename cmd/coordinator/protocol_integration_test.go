package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

// Country-assignment protocol conformance: the REAL coordinator against the REAL
// core client, over a real UDP socket (issues #146/#147, ADR-0042).
//
// # Why this file exists
//
// Every other test on either side of this wire talks to a hand-rolled fake of the
// other side, and that is precisely how the country protocol shipped in a state where
// no client in the repo could connect while the whole suite stayed green. The
// coordinator's tests called handle() and asserted on the wire struct it replied with;
// the client's tests answered `{"type":"exits"}` from a fake coordinator that no
// coordinator had sent since #146. Both sides were self-consistent, both were tested,
// and together they did not work. A fake on both sides of a protocol tests the fakes.
//
// So the rule this file establishes: at least one test must put the real coordinator's
// handler and the real core client on opposite ends of a real socket, with nothing
// hand-rolled in between. A protocol change that breaks the pairing must fail HERE
// even when both sides' unit tests still pass.
//
// # On importing core
//
// The coordinator's `wire` struct is deliberately a separate copy so the shipped
// BINARY does not link core and its transport stack (see wire's doc in main.go). A
// test-only import does not change what the binary links, and it is the only way to
// exercise the actual client. The duplication is still checked independently, by the
// wire-contract tests that pin the two copies field for field.

// coordinatorUnderTest runs the real packet loop — servePackets, the same function
// main() calls, with the DTLS mux installed — on a loopback socket, and returns the
// address a client should be pointed at.
//
// It is the production read path, not a reimplementation of it, and since #175 slice
// 2 that is not a nicety. Before, this file ran its own decode-and-dispatch loop that
// happened to match main()'s; a client now speaks an ICE connectivity check and then
// DTLS with NO cleartext fallback (ADR-0062), so a hand-rolled cleartext loop here
// would be a coordinator no client in this repository can reach — which is precisely
// the "a fake on both sides of a protocol tests the fakes" failure this file exists
// to prevent, arriving on the file that exists to prevent it.
func coordinatorUnderTest(t *testing.T) string {
	t.Helper()
	return signalingPortUnderTest(t).String()
}

// registerExitIn puts one exit in the registry with a real 64-hex id, as a register
// datagram would. The id must be a well-formed X25519 public key because the client
// decodes it off the session reply and refuses a malformed one — which is the
// behaviour under test, so the fixture must not sidestep it.
func registerExitIn(t *testing.T, country string) string {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	id := hex.EncodeToString(key[:])
	mu.Lock()
	defer mu.Unlock()
	exits[id] = &exitNode{
		id:            id,
		tcpAddr:       "198.51.100.7:20000",
		udp:           &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 20000},
		lastSeen:      time.Now(),
		country:       country,
		countrySource: countryObserved,
	}
	return id
}

// newRealClient builds a genuine core client engine pointed at addr, collecting its
// events so a test can assert on what the client actually concluded.
func newRealClient(t *testing.T, addr, geo string) (*core.Engine, func() []core.Event) {
	t.Helper()
	var mu sync.Mutex
	var events []core.Event
	eng, err := core.New(core.Config{
		Coordinators: []string{addr},
		Roles:        []string{core.RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          geo,
		OnEvent: func(ev core.Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		eng.Stop()
	})
	return eng, func() []core.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]core.Event(nil), events...)
	}
}

// TestRealClientReadsTheRealCountryList is the acceptance for the discovery half.
//
// It fails if the coordinator's reply type, the client's request type, or the client's
// inbox routing disagree by so much as a string — which is the exact three-way
// mismatch that shipped: coordinator answering "countries", client requiring "exits",
// and readLoop routing neither.
func TestRealClientReadsTheRealCountryList(t *testing.T) {
	resetRegistry(t)
	t.Cleanup(func() { resetRegistry(t) })
	addr := coordinatorUnderTest(t)
	registerExitIn(t, "NL")
	registerExitIn(t, "DE")

	eng, _ := newRealClient(t, addr, "")
	got, err := eng.ListCountries(context.Background(), 4*time.Second)
	if err != nil {
		t.Fatalf("the real client could not read the real coordinator's country list: %v", err)
	}

	seen := map[string]core.CountryInfo{}
	for _, c := range got {
		seen[c.Country] = c
	}
	for _, want := range []string{"NL", "DE"} {
		c, ok := seen[want]
		if !ok {
			t.Fatalf("country %s missing from what the client parsed: %+v", want, got)
		}
		if c.Exits != 1 || c.Available != 1 || c.Busy {
			t.Errorf("country %s parsed as %+v; want 1 exit, 1 available, not busy", want, c)
		}
	}
}

// TestRealClientPairsByCountryAndLearnsItsExit is the acceptance for the pairing half,
// and the one that pins the field a country-only client cannot work without.
//
// The client is given a country and nothing else. It must send a connect the
// coordinator accepts, and the coordinator's answer must carry the exit it chose — an
// exit's id IS its Noise static key, so without it the client has no way to bring up
// the end-to-end channel at all.
//
// The assertion is that the client emits a session event, which it does only after
// decoding the assigned exit id to a 32-byte key. That makes the test fail in every
// way this can break: a client that sent no country is refused; a coordinator that
// omitted the exit id has its reply rejected; a client that dropped the reply times
// out. The transport dial that follows cannot succeed against a fixture exit, and is
// deliberately not part of the assertion — the wire contract is complete by then.
func TestRealClientPairsByCountryAndLearnsItsExit(t *testing.T) {
	resetRegistry(t)
	t.Cleanup(func() { resetRegistry(t) })
	addr := coordinatorUnderTest(t)
	exitID := registerExitIn(t, "NL")

	eng, events := newRealClient(t, addr, "NL")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// Connect fails: the fixture exit is an address nothing answers on, so the
	// transport never comes up. The pairing that precedes it is the subject.
	_ = eng.Connect(ctx)

	// Count the DIRECT-mode pairings specifically, not just any session.
	//
	// The client falls through direct -> relay, and with no relay registered the relay
	// attempt lands on the TURN fallback — a different reply site on the coordinator. A
	// test that accepted any session would therefore still pass if the direct reply
	// stopped carrying an exit id, because the fallback would quietly rescue it. That
	// is not hypothetical: it is what an early version of this test did, found by
	// mutating the direct reply and watching nothing fail.
	var direct int
	var sessionEvents []core.Event
	for _, ev := range events() {
		if ev.Kind != core.EventSession {
			continue
		}
		sessionEvents = append(sessionEvents, ev)
		if strings.Contains(ev.Message, "[direct]") {
			direct++
		}
	}
	if len(sessionEvents) == 0 {
		t.Fatalf("the client never accepted a session from the real coordinator — it could not pair by country. events: %+v", events())
	}
	if direct == 0 {
		t.Fatalf("the client accepted %d session(s) but none on the DIRECT path — the direct reply is not usable. events: %+v", len(sessionEvents), events())
	}

	// The coordinator must have minted those sessions against the exit in the
	// requested country, and recorded it — that record is what exit ranking counts
	// and what an exclusion later resolves through.
	mu.Lock()
	defer mu.Unlock()
	if len(sessions) == 0 {
		t.Fatal("the coordinator minted no session")
	}
	for sid, s := range sessions {
		if s.exitID != exitID {
			t.Errorf("session %s recorded exit %q; want the NL exit %q", sid, s.exitID, exitID)
		}
	}
	// And the client must have been told which exit that was.
	for _, ev := range sessionEvents {
		if !strings.Contains(ev.Message, shortHex(exitID)) {
			t.Errorf("session event %q does not name the assigned exit %s — the client did not read the exit id off the reply", ev.Message, shortHex(exitID))
		}
	}
}

// TestRealConnectIsOneAssignmentPerRequest is #1's acceptance across the real wire, and
// the one that would have caught the bug in the first place.
//
// The measurement ADR-0042 §2 recorded: one Connect() minted SIX sessions across three
// distinct exits, because sendN sends each connect three times and connectVia does that
// once per mode. Both halves of that count are real — six datagrams — and only one of
// them is a decision. A request is a decision; a retransmission is not.
//
// So the invariant asserted here is not a number, it is a correspondence: the
// coordinator holds exactly as many sessions as it received distinct pairing REQUESTS.
// A number would have to be updated whenever the mode ladder changed; the
// correspondence holds regardless, and it is exactly what fails when the copies of one
// request are assigned independently again.
//
// Three exits in the country, deliberately: with one, resampling returns the same exit
// by construction and the whole failure is invisible.
func TestRealConnectIsOneAssignmentPerRequest(t *testing.T) {
	resetRegistry(t)
	t.Cleanup(func() { resetRegistry(t) })
	addr := coordinatorUnderTest(t)
	for i := 0; i < 3; i++ {
		registerExitIn(t, "NL")
	}

	eng, _ := newRealClient(t, addr, "NL")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Fails: the fixture exits are addresses nothing answers on, so no transport comes
	// up. What is under test is how many assignments the pairing that precedes it made.
	_ = eng.Connect(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(sessions) == 0 {
		t.Fatal("the client never paired at all — the fixture is broken")
	}
	if len(sessions) != len(mintedConnects) {
		t.Errorf("one Connect() minted %d session(s) from %d distinct pairing request(s) — a retransmitted copy must replay its request's answer, not draw a fresh exit (ADR-0042 §2)",
			len(sessions), len(mintedConnects))
	}
	// And the sharper statement of the same thing: whatever the ladder did, it cannot
	// have produced more assignments than it made requests, and each request's answer
	// is one exit. A client that saw several exits per request could keep the one it
	// wanted, which is the pin #146 removed.
	if len(sessions) > len(mintedConnects) {
		var got []string
		for _, s := range sessions {
			got = append(got, s.exitID)
		}
		t.Errorf("exits assigned across %d request(s): %v", len(mintedConnects), got)
	}
}

// TestRealClientSurfacesACountryRefusal is #147's acceptance across the real wire: a
// country the coordinator does not know must reach the client as a stated reason, not
// as silence. Before this, awaitSession discarded wire.Reason and both named refusals
// reached neither a log nor a user.
func TestRealClientSurfacesACountryRefusal(t *testing.T) {
	resetRegistry(t)
	t.Cleanup(func() { resetRegistry(t) })
	addr := coordinatorUnderTest(t)
	registerExitIn(t, "NL")

	eng, events := newRealClient(t, addr, "SE") // no exit in SE
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := eng.Connect(ctx); err == nil {
		t.Fatal("connecting to a country with no exit should fail")
	}

	for _, ev := range events() {
		if strings.Contains(ev.Message, string(refuseNoCountry)) {
			return
		}
	}
	t.Errorf("the coordinator's %q refusal never reached the client's events: %+v", refuseNoCountry, events())
}

// shortHex mirrors core's shortID for assertions about what the client logged.
func shortHex(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
