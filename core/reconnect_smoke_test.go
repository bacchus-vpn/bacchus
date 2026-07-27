package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeTransport is a Transport whose Dial hands back a controllable fakeSession
// and ignores signaling. It lets the smoke tests exercise the *real* connect path
// — coordinator pairing over loopback UDP, session tracking, and the reconnect
// driver — without standing up a real WebRTC/Reality stack. The actual
// data-channel/ICE teardown that a live transport reports on a network change can
// only be confirmed on real infra; these tests prove the engine's reaction to a
// session drop, which is what issue #2 owns ("re-establish within the transport").
type fakeTransport struct {
	mu       sync.Mutex
	sessions []*fakeSession
}

func (f *fakeTransport) Name() string { return "fake" }

func (f *fakeTransport) Dial(ctx context.Context, sig Signaler) (Session, error) {
	s := newFakeSession()
	f.mu.Lock()
	f.sessions = append(f.sessions, s)
	f.mu.Unlock()
	return s, nil
}

func (f *fakeTransport) Accept(ctx context.Context, sig Signaler) (Session, error) {
	return nil, errors.New("fake: accept unused")
}

// fakeConnectCoordinator binds a loopback UDP socket that answers "connect"
// requests. reply decides, per requested mode, whether to mint a fresh session id
// ("session") or refuse ("error") — so a test can force the real establish ladder
// to fall over from direct to relay. The version hello is ignored silently, as a
// matching coordinator does. It returns the host:port to configure.
func fakeConnectCoordinator(t *testing.T, reply func(mode string) (wire, bool)) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 65535)
		var seq int
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var m wire
			if json.Unmarshal(buf[:n], &m) != nil || m.Type != "connect" {
				continue
			}
			seq++
			out, ok := reply(m.Mode)
			if !ok {
				continue // blackhole this mode
			}
			if out.Type == "session" && out.Session == "" {
				out.Session = fmt.Sprintf("s%d", seq) // unique per mint
			}
			b, _ := json.Marshal(out)
			_, _ = pc.WriteToUDP(b, src)
		}
	}()
	return pc.LocalAddr().String()
}

// mintAny answers every mode with a fresh session.
// mintAny answers every connect with a session, as a healthy coordinator does.
// The exit id is mandatory: it IS the exit's Noise static key (issue #146,
// ADR-0009), and a client refuses a mint without one.
func mintAny(string) (wire, bool) { return wire{Type: "session", ExitID: testExitID}, true }

// newSmokeClient wires a client engine to coord with the fake transport under the
// real connect path and fast reconnect timings.
func newSmokeClient(t *testing.T, coord string, tr Transport) *Engine {
	t.Helper()
	eng, err := New(Config{
		Coordinators: []string{coord},
		Roles:        []string{RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL", // a connect names a country, not an exit (issue #146)
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.transport = tr // real establish/connectVia/attemptWith path, fake transport under it
	eng.directTimeout = 1 * time.Second
	eng.relayTimeout = 1 * time.Second
	eng.reconnectBase = 20 * time.Millisecond
	eng.reconnectMax = 200 * time.Millisecond
	eng.reconnectHealthy = 0 // treat the deliberate kill as a genuine drop (fast retry)
	return eng
}

// TestReconnectSmoke_RecoversAfterMidSessionDrop is issue #2's acceptance over a
// loopback stack: a client connects through a real coordinator + the reconnect
// driver, and when the live session is killed mid-session the path is
// re-established automatically within a bounded time — no user action, and the
// SOCKS listener is never rebound.
func TestReconnectSmoke_RecoversAfterMidSessionDrop(t *testing.T) {
	sink, snap := collectEvents()
	coord := fakeConnectCoordinator(t, mintAny)
	eng := newSmokeClient(t, coord, &fakeTransport{})
	eng.cfg.OnEvent = sink

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	if err := eng.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sess0, _, _ := eng.activeReconnectSession()
	if sess0 == nil {
		t.Fatal("no active session after Connect")
	}

	_ = sess0.Close() // kill the live path mid-session

	if !waitFor(6*time.Second, func() bool {
		s, _, _ := eng.activeReconnectSession()
		return s != nil && s != sess0
	}) {
		t.Fatal("client did not auto-reconnect within the bounded time after the session dropped")
	}
	if !hasEventContaining(snap(), EventError, "connection lost") {
		t.Fatalf("expected a 'connection lost' event; got %+v", snap())
	}

	// Bound-once: exactly one SOCKS listener (a client-only node has no others)
	// survived the reconnect.
	eng.mu.Lock()
	nLn := len(eng.listeners)
	eng.mu.Unlock()
	if nLn != 1 {
		t.Fatalf("expected one SOCKS listener across the reconnect, got %d", nLn)
	}
}

// TestReconnectSmoke_FailsOverDirectToRelay drives the real establish ladder end
// to end: the coordinator refuses direct and mints only relay, so a connect must
// fall over from the direct hole-punch to the relayed path — and recover the same
// way after a mid-session drop.
func TestReconnectSmoke_FailsOverDirectToRelay(t *testing.T) {
	sink, snap := collectEvents()
	// Direct is refused; relay is minted.
	coord := fakeConnectCoordinator(t, func(mode string) (wire, bool) {
		if mode == modeDirect {
			return wire{Type: "error"}, true
		}
		return wire{Type: "session", ExitID: testExitID}, true
	})
	eng := newSmokeClient(t, coord, &fakeTransport{})
	eng.cfg.OnEvent = sink

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	if err := eng.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !hasEventContaining(snap(), EventConnected, "connected via RELAY") {
		t.Fatalf("expected the initial connect to fail over direct->relay; got %+v", snap())
	}
	sess0, _, _ := eng.activeReconnectSession()
	if sess0 == nil {
		t.Fatal("no active session after Connect")
	}

	_ = sess0.Close() // drop the relayed path

	if !waitFor(6*time.Second, func() bool {
		s, _, _ := eng.activeReconnectSession()
		return s != nil && s != sess0
	}) {
		t.Fatal("client did not re-establish the relayed path within the bounded time")
	}
}
