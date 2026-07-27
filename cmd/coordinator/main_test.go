package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/handshake"
	"github.com/pion/turn/v4"
)

// TestMergedTurnAndBootstrapListener is the regression check issue #30 asks
// for: a real pion/turn server and the cold-start bootstrap listener share
// one UDP socket via startTurnAndBootstrap, and none of (a) an authenticated
// cold-start bootstrap fetch, (b) an ordinary STUN Binding request, or (c) a
// real authenticated TURN allocation interferes with the others.
func TestMergedTurnAndBootstrapListener(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bootstrap.key")
	secretsPath := filepath.Join(dir, "secrets.json")

	priv, err := loadOrGenerateBootstrapKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrGenerateBootstrapKey: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", priv.Public())
	}

	secretID, secret, err := coldstart.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	store := coldstart.NewMemStore()
	store.Add(secretID, secret)
	if err := store.SaveFile(secretsPath); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	cfg := turnConfig{
		addr:     "127.0.0.1:0",
		publicIP: "127.0.0.1",
		realm:    "bacchus-test",
		user:     "testuser",
		pass:     "testpass",
	}
	addr, err := startTurnAndBootstrap(cfg, keyPath, secretsPath, "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("startTurnAndBootstrap: %v", err)
	}

	// Also covers waiting out the secrets-reload and snapshot-sign goroutines'
	// startup race: both run their first pass asynchronously right after
	// startTurnAndBootstrap returns.
	t.Run("authenticated bootstrap fetch", func(t *testing.T) {
		res := waitForBootstrap(t, addr, secretID, secret, pub)
		if len(res.Snapshot.Entries) == 0 {
			t.Fatalf("snapshot has no entries")
		}
		if got := res.Snapshot.Entries[0]; got.Role != "coordinator" || got.Addr != "127.0.0.1:8080" {
			t.Fatalf("snapshot coordinator entry = %+v, want role=coordinator addr=127.0.0.1:8080", got)
		}
	})

	t.Run("plain STUN binding still reaches pion/turn", func(t *testing.T) {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			t.Fatalf("resolve %s: %v", addr, err)
		}
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer conn.Close()

		client, err := turn.NewClient(&turn.ClientConfig{Conn: conn})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer client.Close()
		if err := client.Listen(); err != nil {
			t.Fatalf("Listen: %v", err)
		}

		if _, err := client.SendBindingRequestTo(raddr); err != nil {
			t.Fatalf("SendBindingRequestTo: %v", err)
		}
	})

	t.Run("real TURN allocation still works", func(t *testing.T) {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer conn.Close()

		client, err := turn.NewClient(&turn.ClientConfig{
			STUNServerAddr: addr,
			TURNServerAddr: addr,
			Username:       cfg.user,
			Password:       cfg.pass,
			Conn:           conn,
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer client.Close()
		if err := client.Listen(); err != nil {
			t.Fatalf("Listen: %v", err)
		}

		relayConn, err := client.Allocate()
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		defer relayConn.Close()
	})
}

// waitForBootstrap retries Bootstrap for a few seconds, absorbing the
// startup race against startTurnAndBootstrap's background secrets-reload and
// snapshot-sign goroutines (both run their first pass asynchronously).
func waitForBootstrap(t *testing.T, addr, secretID string, secret []byte, pub ed25519.PublicKey) *coldstart.Result {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		res, err := coldstart.Bootstrap(ctx, addr, secretID, secret, pub)
		cancel()
		if err == nil {
			return res
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("bootstrap never became ready: %v", lastErr)
	return nil
}

// setPC binds pc (the package-level send socket handle) to a fresh loopback
// UDP conn for the duration of the test, so handle's calls to send() have
// somewhere real to write. handle is otherwise a pure function of its
// arguments plus the registry globals, which this test does not touch.
func setPC(t *testing.T) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	pc = conn
}

// fakePeer binds a loopback UDP socket standing in for the node sending
// hello, so a test can read whatever handle() sends back to it.
func fakePeer(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestHelloMatchGetsNoReply(t *testing.T) {
	setPC(t)
	peer := fakePeer(t)

	handle(wire{Type: "hello", Magic: handshake.Magic, Version: handshake.ProtocolVersion}, peer.LocalAddr().(*net.UDPAddr))

	peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1024)
	if _, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Fatal("a matching hello should get no reply")
	}
}

func TestHelloVersionMismatchGetsReject(t *testing.T) {
	setPC(t)
	peer := fakePeer(t)

	handle(wire{Type: "hello", Magic: handshake.Magic, Version: handshake.ProtocolVersion + 1}, peer.LocalAddr().(*net.UDPAddr))

	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected a reject reply, got none: %v", err)
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if m.Type != "reject" {
		t.Fatalf("expected a reject, got %q", m.Type)
	}
	if !strings.Contains(m.Reason, "this side must update") {
		t.Fatalf("expected reason to point at the coordinator needing an update, got %q", m.Reason)
	}
}

func TestHelloBadMagicGetsReject(t *testing.T) {
	setPC(t)
	peer := fakePeer(t)

	handle(wire{Type: "hello", Magic: "not-bacchus", Version: handshake.ProtocolVersion}, peer.LocalAddr().(*net.UDPAddr))

	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected a reject reply, got none: %v", err)
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if m.Type != "reject" {
		t.Fatalf("expected a reject, got %q", m.Type)
	}
	if !strings.Contains(m.Reason, "magic") {
		t.Fatalf("expected reason to mention magic, got %q", m.Reason)
	}
}

// A rejected hello must never touch the relay/exit registry: it carries no
// role or id to register in the first place.
func TestHelloRejectDoesNotRegisterAnything(t *testing.T) {
	setPC(t)
	peer := fakePeer(t)

	mu.Lock()
	relays = map[string]*relayNode{}
	exits = map[string]*exitNode{}
	mu.Unlock()

	handle(wire{Type: "hello", Magic: handshake.Magic, Version: handshake.ProtocolVersion + 1}, peer.LocalAddr().(*net.UDPAddr))

	mu.Lock()
	defer mu.Unlock()
	if len(relays) != 0 || len(exits) != 0 {
		t.Fatalf("expected no registry entries from a hello, got relays=%v exits=%v", relays, exits)
	}
}

// TestPruneExpiresStalePeersAndSessions is the coordinator half of issue #3: a
// relay, exit, or session that has gone silent past its TTL must be dropped on
// the next sweep, while a freshly-seen one is kept. This is the registry-side
// guarantee behind the "vanished peer" acceptance — the mechanism whose absence
// caused the earlier "12s disconnect". Sessions in particular now expire on
// last-signaling (lastSeen), not creation age, so a vanished client that never
// heartbeats is reaped once its rendezvous state goes quiet.
func TestPruneExpiresStalePeersAndSessions(t *testing.T) {
	now := time.Now()

	mu.Lock()
	defer mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		relays = map[string]*relayNode{}
		exits = map[string]*exitNode{}
		sessions = map[string]*session{}
		mu.Unlock()
	})

	relays = map[string]*relayNode{
		"fresh": {lastSeen: now},
		"stale": {lastSeen: now.Add(-ttl - time.Second)},
	}
	exits = map[string]*exitNode{
		"fresh": {id: "fresh", lastSeen: now},
		"stale": {id: "stale", lastSeen: now.Add(-ttl - time.Second)},
	}
	sessions = map[string]*session{
		"active": {lastSeen: now},
		"quiet":  {lastSeen: now.Add(-sessionTTL - time.Second)},
	}

	prune(now)

	if _, ok := relays["stale"]; ok {
		t.Error("stale relay survived prune")
	}
	if _, ok := relays["fresh"]; !ok {
		t.Error("fresh relay was wrongly pruned")
	}
	if _, ok := exits["stale"]; ok {
		t.Error("stale exit survived prune")
	}
	if _, ok := exits["fresh"]; !ok {
		t.Error("fresh exit was wrongly pruned")
	}
	if _, ok := sessions["quiet"]; ok {
		t.Error("idle session survived prune (should expire on last-signaling TTL)")
	}
	if _, ok := sessions["active"]; !ok {
		t.Error("active session was wrongly pruned")
	}
}

// TestSignalingRefreshesSessionLastSeen checks the activity coupling: relaying a
// candidate for a session stamps its lastSeen fresh, so a session kept busy with
// signaling never ages out mid-handshake. It starts the session aged to half the
// TTL — old enough that a stale age is unmistakable, young enough to survive the
// prune handle runs first — and asserts the relay reset it to ~now.
func TestSignalingRefreshesSessionLastSeen(t *testing.T) {
	setPC(t)
	peer := fakePeer(t)
	other := fakePeer(t)

	mu.Lock()
	sessions = map[string]*session{
		"s": {client: peer.LocalAddr().(*net.UDPAddr), peer: other.LocalAddr().(*net.UDPAddr), lastSeen: time.Now().Add(-sessionTTL / 2)},
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		sessions = map[string]*session{}
		mu.Unlock()
	})

	handle(wire{Type: "candidate", Session: "s"}, peer.LocalAddr().(*net.UDPAddr))

	mu.Lock()
	s, ok := sessions["s"]
	mu.Unlock()
	if !ok {
		t.Fatal("session was pruned before its signaling could refresh it")
	}
	if time.Since(s.lastSeen) > time.Second {
		t.Fatalf("relaying signaling did not refresh lastSeen (age %s, want ~0)", time.Since(s.lastSeen))
	}
}
