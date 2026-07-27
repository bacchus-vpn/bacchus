package coldstart

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// startTestServer runs Serve on a loopback UDP socket and returns its
// address plus a stop func. snapshot may be swapped concurrently via the
// returned setter, mirroring how cmd/coordinator refreshes it periodically.
func startTestServer(t *testing.T, secrets SecretStore) (addr string, setSnapshot func([]byte)) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var current atomic.Pointer[[]byte]
	empty := []byte(nil)
	current.Store(&empty)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, pc, secrets, func() []byte { return *current.Load() })
	}()
	t.Cleanup(func() {
		cancel()
		_ = pc.Close()
		<-done
	})
	return pc.LocalAddr().String(), func(b []byte) { current.Store(&b) }
}

func TestBootstrapEndToEndAuthenticated(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secretID, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	store := NewMemStore()
	store.Add(secretID, secret)

	addr, setSnapshot := startTestServer(t, store)
	signed, err := Sign(priv, testSnapshot())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	setSnapshot(signed)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Bootstrap(ctx, addr, secretID, secret, pub)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(res.Snapshot.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(res.Snapshot.Entries))
	}

	cachePath := filepath.Join(t.TempDir(), "snap.cache")
	if err := SaveCache(cachePath, res.Signed); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}
	cached, err := LoadCache(cachePath)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if _, err := Verify(pub, cached); err != nil {
		t.Fatalf("Verify cached snapshot: %v", err)
	}
}

func TestBootstrapWrongSecretGetsNoSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	secretID, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	store := NewMemStore()
	store.Add(secretID, secret)

	addr, setSnapshot := startTestServer(t, store)
	signed, _ := Sign(priv, testSnapshot())
	setSnapshot(signed)

	_, wrongSecret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Bootstrap(ctx, addr, secretID, wrongSecret, pub); err != ErrNotAuthenticated {
		t.Fatalf("Bootstrap with wrong secret: err = %v, want ErrNotAuthenticated", err)
	}
}

func TestBootstrapUnknownSecretIDGetsNoSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	store := NewMemStore()
	addr, setSnapshot := startTestServer(t, store)
	signed, _ := Sign(priv, testSnapshot())
	setSnapshot(signed)

	_, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Bootstrap(ctx, addr, "0000000000000000", secret, pub); err != ErrNotAuthenticated {
		t.Fatalf("Bootstrap with unknown secret id: err = %v, want ErrNotAuthenticated", err)
	}
}

func TestBootstrapUnreachableTimesOut(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close() // nothing listening now

	secretID, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := Bootstrap(ctx, addr, secretID, secret, pub); err == nil {
		t.Fatalf("Bootstrap against a closed socket: want error, got nil")
	}
}

func TestLoadMemStoreRoundTrip(t *testing.T) {
	store := NewMemStore()
	id1, s1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	store.Add(id1, s1)
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := store.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	loaded, err := LoadMemStore(path)
	if err != nil {
		t.Fatalf("LoadMemStore: %v", err)
	}
	got, ok := loaded.Lookup(id1)
	if !ok || string(got) != string(s1) {
		t.Fatalf("Lookup after reload = %x, %v; want %x, true", got, ok, s1)
	}
}

func TestLoadMemStoreMissingFile(t *testing.T) {
	if _, err := LoadMemStore(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatalf("LoadMemStore on missing file: want error, got nil")
	}
}

func TestHandleRequestIgnoresGarbage(t *testing.T) {
	if _, ok := handleRequest([]byte("not stun"), netip.AddrPort{}, NewMemStore(), func() []byte { return nil }); ok {
		t.Fatalf("handleRequest on garbage input: want ok=false")
	}
}
