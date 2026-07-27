package core

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestE2ERoundTrip: a client and exit complete the Noise_NK handshake over a
// direct byte pipe; the exit recovers the target and echoed payload.
func TestE2ERoundTrip(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	const target = "example.com:443"

	type res struct {
		target string
		got    string
		err    error
	}
	done := make(chan res, 1)
	go func() {
		nc, tgt, err := exitHandshake(sConn, key, nil)
		if err != nil {
			done <- res{err: err}
			return
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(nc, buf)
		done <- res{target: tgt, got: string(buf), err: err}
	}()

	nc, err := clientHandshake(cConn, key.Public, target, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	if _, err := nc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("exit: %v", r.err)
	}
	if r.target != target {
		t.Fatalf("target = %q, want %q", r.target, target)
	}
	if r.got != "ping" {
		t.Fatalf("payload = %q, want %q", r.got, "ping")
	}
}

// TestE2ERelayIsBlind is the #12 acceptance test: with a logging relay in the
// path, the bytes it forwards are ciphertext — it recovers neither the
// destination nor the content — while the exit still terminates correctly.
func TestE2ERelayIsBlind(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	const target = "secret-host.example.com:8443"
	const payload = "TOPSECRET_PAYLOAD_1234567890"

	cConn, rClient := net.Pipe() // client <-> relay
	rExit, sConn := net.Pipe()   // relay  <-> exit
	deadline(t, cConn, rClient, rExit, sConn)

	var mu sync.Mutex
	var captured []byte
	// Relay: forward client->exit while capturing what crosses the box.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := rClient.Read(buf)
			if n > 0 {
				mu.Lock()
				captured = append(captured, buf[:n]...)
				mu.Unlock()
				if _, werr := rExit.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	// Relay: forward exit->client.
	go func() { _, _ = io.Copy(rClient, rExit) }()

	type res struct {
		target, data string
		err          error
	}
	done := make(chan res, 1)
	go func() {
		nc, tgt, err := exitHandshake(sConn, key, nil)
		if err != nil {
			done <- res{err: err}
			return
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(nc, buf); err != nil {
			done <- res{err: err}
			return
		}
		done <- res{target: tgt, data: string(buf)}
	}()

	nc, err := clientHandshake(cConn, key.Public, target, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	if _, err := nc.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("exit: %v", r.err)
	}
	if r.target != target {
		t.Fatalf("exit target = %q, want %q", r.target, target)
	}
	if r.data != payload {
		t.Fatalf("exit data = %q, want %q", r.data, payload)
	}

	mu.Lock()
	seen := append([]byte(nil), captured...)
	mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("relay captured nothing — test wiring bug")
	}
	if bytes.Contains(seen, []byte("secret-host.example.com")) {
		t.Fatal("relay recovered the destination in cleartext")
	}
	if bytes.Contains(seen, []byte(payload)) {
		t.Fatal("relay recovered the payload in cleartext")
	}
}

// TestE2EWrongExitKeyFails: a relay that substitutes its own static key (a MITM)
// cannot complete the handshake, because the client authenticates the exit by
// the public key it selected.
func TestE2EWrongExitKeyFails(t *testing.T) {
	realKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	mitmKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	go func() {
		_, _, _ = exitHandshake(sConn, mitmKey, nil) // wrong key
		_ = sConn.Close()
	}()

	if _, err := clientHandshake(cConn, realKey.Public, "x:1", nil); err == nil {
		t.Fatal("handshake must fail when the exit key does not match the selected exit id")
	}
}

// TestExitIDIsPublicKey: an exit's node id is the hex of its static public key.
func TestExitIDIsPublicKey(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:20000"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(eng.ID()) != 64 {
		t.Fatalf("exit id length = %d, want 64 hex chars", len(eng.ID()))
	}
	if eng.ID() != hex.EncodeToString(eng.exitKey.Public) {
		t.Fatal("exit id must equal its static public key")
	}
}

// TestExitKeyStableFromHex: the same private key yields the same exit identity.
func TestExitKeyStableFromHex(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	h := hex.EncodeToString(seed)
	a, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1", ExitKeyHex: h})
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1", ExitKeyHex: h})
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	if a.ID() == "" || a.ID() != b.ID() {
		t.Fatalf("same key must give same id: %q vs %q", a.ID(), b.ID())
	}
}

// TestExitRejectsBadKey: a malformed ExitKeyHex is a construction error.
func TestExitRejectsBadKey(t *testing.T) {
	if _, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1", ExitKeyHex: "not-hex"}); err == nil {
		t.Fatal("a malformed exit key should error")
	}
}

// deadline arms every pipe end with a test-wide deadline so a wiring bug fails
// fast instead of hanging.
func deadline(t *testing.T, conns ...net.Conn) {
	t.Helper()
	for _, c := range conns {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	}
}
