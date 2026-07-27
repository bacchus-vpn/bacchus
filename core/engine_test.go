package core

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/handshake"
)

// A coordinator address that resolves but has nothing listening. UDP dial does
// not connect, so Start succeeds without a live coordinator — enough to exercise
// construction and start/stop.
const testCoord = "127.0.0.1:65534"

func TestNewParsesRoles(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"client", " relay ", ""}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !eng.HasRole(RoleClient) || !eng.HasRole(RoleRelay) {
		t.Fatalf("expected client+relay roles, got %v", eng.roles)
	}
	if eng.HasRole(RoleExit) {
		t.Fatal("did not expect exit role")
	}
	if !eng.clientOn {
		t.Fatal("clientOn should be true when client role is present")
	}
}

func TestNewAutoID(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if eng.ID() == "" {
		t.Fatal("expected an auto-generated id")
	}

	eng2, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"relay"}, ID: "fixed"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if eng2.ID() != "fixed" {
		t.Fatalf("expected id %q, got %q", "fixed", eng2.ID())
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no coordinators", Config{Roles: []string{"client"}}},
		{"no roles", Config{Coordinators: []string{testCoord}}},
		{"unknown role", Config{Coordinators: []string{testCoord}, Roles: []string{"gateway"}}},
		{"exit without advertise", Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestExitAcceptsAdvertise(t *testing.T) {
	if _, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:20000"}); err != nil {
		t.Fatalf("exit with advertise should construct: %v", err)
	}
}

// waitStopped fails the test if the engine does not fully stop within d.
func waitStopped(t *testing.T, eng *Engine, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { eng.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("engine did not stop in time")
	}
}

func TestStartStop(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"client"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	eng.Stop()
	waitStopped(t, eng, 5*time.Second)
	// Stop is idempotent.
	eng.Stop()
}

func TestStartStopRelay(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"relay"}, ID: "r1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	eng.Stop()
	waitStopped(t, eng, 5*time.Second)
}

func TestContextCancelStops(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel()
	waitStopped(t, eng, 5*time.Second)
}

func TestDoubleStart(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Start(context.Background()); err == nil {
		t.Fatal("expected error on second Start")
	}
}

// TestStopClosesSessionRaceLoses proves Stop's session-teardown guarantee holds
// even when trackSession's own watcher goroutine wins its race with Stop's
// session-collection loop: the watcher reacts to the same close(e.stop) Stop
// starts with, and can delete sid from e.sessions before Stop ever reads the
// map — leaving Stop's snapshot without it, so Stop's own "close every session
// I found" loop never sees it. Removing sid from e.sessions before calling Stop
// deterministically reproduces exactly that outcome (Stop's loop truly cannot
// see this session), isolating the watcher's own responsibility: it alone must
// still close the session it is tracking, or the transport leaks past Stop
// returning — the failure mode a live WebRTC forwarder session first surfaced
// (see docs/adr/0037's amendment). Reverting the fix makes this fail
// deterministically, restoring it passes.
func TestStopClosesSessionRaceLoses(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"client"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	sess := newFakeSession()
	eng.trackSession("race-sid", sess, true)

	eng.sessMu.Lock()
	delete(eng.sessions, "race-sid")
	eng.sessMu.Unlock()

	eng.Stop()
	waitStopped(t, eng, 5*time.Second)

	select {
	case <-sess.Closed():
	default:
		t.Fatal("trackSession's watcher must close a session Stop's own loop never saw, or the transport leaks past Stop returning")
	}
}

func TestClientMethodsRequireClientRole(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := eng.ListCountries(context.Background(), time.Second); err == nil {
		t.Fatal("ListCountries should reject a non-client engine")
	}
	if err := eng.Connect(context.Background()); err == nil {
		t.Fatal("Connect should reject a non-client engine")
	}
}

func TestConnectRequiresExitID(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"client"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if err := eng.Connect(context.Background()); err == nil {
		t.Fatal("Connect should require ExitID")
	}
}

// fakeCoordinator binds a loopback UDP socket standing in for the coordinator,
// so tests can inspect what an engine sends first and drive replies back.
func fakeCoordinator(t *testing.T) *net.UDPConn {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// A forwarder greets every pool member at Start (a client instead greets
// lazily, only the member it rotates to), so use a relay here to assert the very
// first datagram on the wire is the version/capability hello.
func TestStartSendsHelloFirst(t *testing.T) {
	coord := fakeCoordinator(t)

	eng, err := New(Config{Coordinators: []string{coord.LocalAddr().String()}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	coord.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := coord.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("did not receive a hello: %v", err)
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal hello: %v", err)
	}
	if m.Type != "hello" {
		t.Fatalf("expected the first message on the channel to be a hello, got %q", m.Type)
	}
	if m.Magic != handshake.Magic || m.Version != handshake.ProtocolVersion {
		t.Fatalf("hello did not carry this build's handshake: %+v", m)
	}
}

func TestCoordinatorRejectEmitsErrorEvent(t *testing.T) {
	coord := fakeCoordinator(t)

	events := make(chan Event, 16)
	eng, err := New(Config{
		// A forwarder greets at Start, so the fake coordinator receives a hello
		// to reply "reject" to; the reject handling itself is role-agnostic.
		Coordinators: []string{coord.LocalAddr().String()},
		Roles:        []string{"relay"},
		OnEvent:      func(ev Event) { events <- ev },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	coord.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	_, src, err := coord.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("did not receive a hello: %v", err)
	}

	const reason = "peer protocol version 99 is newer than 1 — this side must update"
	b, err := json.Marshal(wire{Type: "reject", Reason: reason})
	if err != nil {
		t.Fatalf("marshal reject: %v", err)
	}
	if _, err := coord.WriteToUDP(b, src); err != nil {
		t.Fatalf("write reject: %v", err)
	}

	// Skip any unrelated startup events (e.g. the transport's dtls-fingerprint
	// info event) and wait for the error event the rejected handshake must emit.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Kind != EventError {
				continue
			}
			if !strings.Contains(ev.Message, reason) {
				t.Fatalf("expected the event message to carry the reject reason, got %q", ev.Message)
			}
			return
		case <-deadline:
			t.Fatal("did not receive an error event for the rejected handshake")
		}
	}
}
