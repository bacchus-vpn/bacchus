package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// setAdmission installs a verifier for the given authority key and revocation
// oracle for the duration of a test, restoring the open (nil) default after so
// tests that expect the pre-#42 behavior are unaffected.
func setAdmission(t *testing.T, pub ed25519.PublicKey, revoked func(string) bool) {
	t.Helper()
	admissionVerifier = admission.NewVerifier(pub, revoked)
	t.Cleanup(func() { admissionVerifier = nil })
}

// resetRegistry clears the coordinator's global directory so one test's
// registrations don't leak into the next.
func resetRegistry(t *testing.T) {
	t.Helper()
	mu.Lock()
	relays = map[string]*relayNode{}
	exits = map[string]*exitNode{}
	sessions = map[string]*session{}
	// Per-connect idempotency records (issue #1). Cleared with the rest: a record left
	// behind would replay a previous test's session id into this one, and — because a
	// replay is answered exactly like a first assignment — it would do so invisibly.
	mintedConnects = map[string]*mintedConnect{}
	mu.Unlock()
}

// issueCred mints a credential valid for the next hour, bound to subject and
// authorizing roles. It returns both the Credential (for its serial) and the
// encoded string to put on the wire.
func issueCred(t *testing.T, priv ed25519.PrivateKey, subject string, roles ...admission.Role) (admission.Credential, string) {
	t.Helper()
	now := time.Now()
	c, enc, err := admission.Issue(priv, subject, roles, now.Add(-time.Minute), now.Add(time.Hour), "test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return c, enc
}

// readReply reads one datagram the coordinator sent back to peer, or reports
// ok=false on timeout (used to assert "no reply").
func readReply(t *testing.T, peer *net.UDPConn, timeout time.Duration) (wire, bool) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		return wire{}, false
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	return m, true
}

func TestRegisterAdmitsValidCredential(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	setAdmission(t, pub, nil)
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	id := "exit-1"
	_, cred := issueCred(t, priv, id, admission.RoleExit)
	handle(wire{Type: "register", Role: "exit", ID: id, Country: "nl", Addr: "1.2.3.4:20000", Cred: cred}, src)

	if m, ok := readReply(t, peer, 150*time.Millisecond); ok {
		t.Fatalf("a valid register should get no reply, got %q", m.Type)
	}
	mu.Lock()
	_, registered := exits[id]
	mu.Unlock()
	if !registered {
		t.Fatal("valid credentialed exit was not registered")
	}
}

func TestRegisterRejectsMissingCredential(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	setAdmission(t, pub, nil)
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	handle(wire{Type: "register", Role: "exit", ID: "exit-x", Addr: "1.2.3.4:20000"}, src) // no Cred

	m, ok := readReply(t, peer, time.Second)
	if !ok || m.Type != "reject" {
		t.Fatalf("expected a reject for an uncredentialed register, got %+v (ok=%v)", m, ok)
	}
	mu.Lock()
	_, registered := exits["exit-x"]
	mu.Unlock()
	if registered {
		t.Fatal("an uncredentialed exit must not be registered")
	}
}

// A credential valid for one id must not let a different id register: this is
// the subject binding that stops a leaked node credential from being replayed.
func TestRegisterRejectsWrongSubject(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	setAdmission(t, pub, nil)
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	_, cred := issueCred(t, priv, "exit-A", admission.RoleExit)
	handle(wire{Type: "register", Role: "exit", ID: "exit-B", Addr: "1.2.3.4:20000", Cred: cred}, src)

	m, ok := readReply(t, peer, time.Second)
	if !ok || m.Type != "reject" {
		t.Fatalf("expected a reject when a credential is replayed under another id, got %+v (ok=%v)", m, ok)
	}
	mu.Lock()
	_, registered := exits["exit-B"]
	mu.Unlock()
	if registered {
		t.Fatal("a mismatched-subject exit must not be registered")
	}
}

func TestRegisterRejectsRevokedCredential(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	revoked := map[string]bool{}
	setAdmission(t, pub, func(serial string) bool { return revoked[serial] })
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	id := "exit-r"
	c, cred := issueCred(t, priv, id, admission.RoleExit)
	revoked[c.Serial] = true // operator revoked it after issue

	handle(wire{Type: "register", Role: "exit", ID: id, Addr: "1.2.3.4:20000", Cred: cred}, src)

	m, ok := readReply(t, peer, time.Second)
	if !ok || m.Type != "reject" {
		t.Fatalf("expected a reject for a revoked credential, got %+v (ok=%v)", m, ok)
	}
	mu.Lock()
	_, registered := exits[id]
	mu.Unlock()
	if registered {
		t.Fatal("a revoked exit must not be registered")
	}
}

func TestListAdmitsClientAndRejectsUncredentialed(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	setAdmission(t, pub, nil)

	// Credentialed client gets the exits list.
	client := fakePeer(t)
	_, cred := issueCred(t, priv, "alice", admission.RoleClient)
	handle(wire{Type: "list", Cred: cred}, client.LocalAddr().(*net.UDPAddr))
	if m, ok := readReply(t, client, time.Second); !ok || m.Type != "countries" {
		t.Fatalf("expected an exits reply for a credentialed client, got %+v (ok=%v)", m, ok)
	}

	// Uncredentialed client is rejected.
	stranger := fakePeer(t)
	handle(wire{Type: "list"}, stranger.LocalAddr().(*net.UDPAddr))
	if m, ok := readReply(t, stranger, time.Second); !ok || m.Type != "reject" {
		t.Fatalf("expected a reject for an uncredentialed list, got %+v (ok=%v)", m, ok)
	}
}

func TestConnectRejectsMissingCredential(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	setAdmission(t, pub, nil)
	peer := fakePeer(t)

	dialConnect(wire{Country: "NL", Mode: "direct"}, peer.LocalAddr().(*net.UDPAddr))

	m, ok := readReply(t, peer, time.Second)
	if !ok || m.Type != "reject" {
		t.Fatalf("expected a reject for an uncredentialed connect, got %+v (ok=%v)", m, ok)
	}
	mu.Lock()
	n := len(sessions)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("an uncredentialed connect must not create a session, got %d", n)
	}
}

// With admission disabled (the default, no -admission-pubkey), the coordinator
// serves anyone — the pre-#42 behavior that keeps existing dev/smoke flows and
// a not-yet-credentialed fleet working.
func TestAdmissionDisabledServesAnyone(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	// Note: no setAdmission, so admissionVerifier is nil.
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	handle(wire{Type: "register", Role: "exit", ID: "open-exit", Addr: "1.2.3.4:20000"}, src)

	if m, ok := readReply(t, peer, 150*time.Millisecond); ok {
		t.Fatalf("admission disabled: register should get no reply, got %q", m.Type)
	}
	mu.Lock()
	_, registered := exits["open-exit"]
	mu.Unlock()
	if !registered {
		t.Fatal("admission disabled: an uncredentialed exit should register")
	}
}
