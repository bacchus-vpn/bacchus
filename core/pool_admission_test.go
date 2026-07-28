package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// The pooled path must bind an exit's admission credential to that exit's key
// (issue #29, ADR-0026).
//
// Noise_NK proves "this peer holds the id you dialed"; the credential proves "the
// admission root authorized that id". The binding — `subject == hex(exitPub)` — is what
// makes a credential non-transferable, and `core/admission.accept` treats an EMPTY
// subject as a bearer credential and skips the check:
//
//	if subject != "" && subject != c.Subject { return ErrSubjectMismatch }
//
// So a path that reaches the verifier without an exit key does not fail — it passes,
// accepting any valid exit-role credential from any exit. It fails OPEN toward
// accepting, which is why it is invisible: nothing errors, nothing disconnects, and the
// client routes through an exit the root never authorized for that identity.

// poolAdmissionEngine builds a POOLED client (TransportPool set, so Connect takes
// connectPooled) holding an admission anchor.
func poolAdmissionEngine(t *testing.T, rootPub ed25519.PublicKey) *Engine {
	t.Helper()
	e, err := New(Config{
		Coordinators:    []string{testCoord},
		Roles:           []string{RoleClient},
		SocksAddr:       "127.0.0.1:0",
		Geo:             "NL",
		TransportPool:   []string{TransportWebRTC},
		AdmissionPubKey: hex.EncodeToString(rootPub),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Stop)
	if !e.poolOn() {
		t.Fatal("fixture is not a pooled engine — this test would exercise the single-transport path instead")
	}
	if e.exitVerifier == nil {
		t.Fatal("fixture holds no admission anchor — the check under test would be fail-open and the test vacuous")
	}
	return e
}

// TestPooledClientRejectsACredentialIssuedToADifferentExit is the test issue #29 asks
// for.
//
// The exit is genuinely the one the client dialed — Noise_NK succeeds against its key —
// and it presents a credential that is real in every other way: root-signed, in its
// validity window, authorizing the exit role, not revoked. The only thing wrong with it
// is that the root issued it to a DIFFERENT exit. Exit A presenting exit B's credential
// must not pass.
//
// It drives the key the way the pooled SOCKS accept loop does — `e.activePath()`, the
// same call `bindPoolSocks` makes for every accepted connection — so the plumbing under
// test is the pooled plumbing and not a hand-carried value.
func TestPooledClientRejectsACredentialIssuedToADifferentExit(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	e := poolAdmissionEngine(t, rootPub)

	exitA, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitB, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	// Valid in every respect except whose it is. The window is against the WALL clock,
	// not the fixed admissionNow the pipe-level tests use: these drive the engine's own
	// verifier, which reads time.Now() by construction (exitVerifyFunc), so a fixed-clock
	// credential would be rejected as expired and the test would pass for the wrong reason.
	credForB := issueExitCred(t, rootPriv, hex.EncodeToString(exitB.Public),
		[]admission.Role{admission.RoleExit}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	e.setActivePath(dialedPath{sess: newFakeSession(), exitID: hex.EncodeToString(exitA.Public), exitPub: exitA.Public})
	sess, pub := e.activePath()
	if sess == nil || len(pub) == 0 {
		t.Fatalf("the pooled accept path has no session/key to work with (sess=%v key=%d bytes)", sess != nil, len(pub))
	}

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	go func() { _, _, _ = exitHandshake(sConn, exitA, credForB) }()

	_, err = e.dialE2E(cConn, planOf(sess), pub, "example.com:443")
	if err == nil {
		t.Fatal("a pooled client with an admission anchor accepted an exit presenting a credential issued to a DIFFERENT exit — the subject binding is not enforced on this path, so any valid exit-role credential admits any exit (issue #29, ADR-0026)")
	}
	if !errors.Is(err, admission.ErrSubjectMismatch) {
		t.Errorf("rejected with %v; want ErrSubjectMismatch — the credential is valid in every other respect, so any other reason means the test is passing for the wrong cause", err)
	}
}

// TestPooledClientAcceptsTheExitsOwnCredential is the non-vacuity half: the same pooled
// path, the same anchor, and a credential the root issued to the exit actually being
// talked to. Without it, a verifier that rejected everything would satisfy the test
// above.
func TestPooledClientAcceptsTheExitsOwnCredential(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	e := poolAdmissionEngine(t, rootPub)

	exitA, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	credForA := issueExitCred(t, rootPriv, hex.EncodeToString(exitA.Public),
		[]admission.Role{admission.RoleExit}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	e.setActivePath(dialedPath{sess: newFakeSession(), exitID: hex.EncodeToString(exitA.Public), exitPub: exitA.Public})
	sess, pub := e.activePath()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	go func() { _, _, _ = exitHandshake(sConn, exitA, credForA) }()

	if _, err := e.dialE2E(cConn, planOf(sess), pub, "example.com:443"); err != nil {
		t.Fatalf("a pooled client rejected the exit's own valid credential: %v", err)
	}
}

// TestEmptyExitKeyIsNeverABearerCredential closes the class rather than the instance.
//
// The subject binding is skipped whenever the verifier is handed an empty key, because
// `hex.EncodeToString(nil)` is `""` and an empty subject means "bearer" to
// `admission.accept`. That default is right for a CLIENT credential — a client has no
// coordinator-known id, so its credential genuinely is bearer — and it is wrong here, in
// a way no call site can see: forgetting to thread the key through does not produce an
// error, it produces a check that silently passes.
//
// Reaching this verifier at all means Noise_NK just authenticated some static key, so
// there is always one to bind to and an empty key is a plumbing bug rather than a
// legitimate state. It is refused, so the next path that forgets fails closed and loudly
// instead of open and silently.
func TestEmptyExitKeyIsNeverABearerCredential(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	exit, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	cred := issueExitCred(t, rootPriv, hex.EncodeToString(exit.Public),
		[]admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour))

	v := admission.NewVerifier(rootPub, nil)
	for name, key := range map[string][]byte{"nil": nil, "empty": {}} {
		if err := verifyExitCredential(v, key, cred, admissionNow); err == nil {
			t.Errorf("%s exit key: a perfectly valid exit credential was ACCEPTED with no key to bind it to — that is the bearer fallback, and on a client path it means any authorized exit admits any other (issue #29)", name)
		} else if !errors.Is(err, errUnboundExitKey) {
			t.Errorf("%s exit key: rejected with %v; want errUnboundExitKey so the cause is named as the plumbing bug it is", name, err)
		}
	}
	// Non-vacuity: with the real key the same credential is accepted, so this refuses
	// the missing-key case and not the credential.
	if err := verifyExitCredential(v, exit.Public, cred, admissionNow); err != nil {
		t.Errorf("the exit's own credential was rejected with its real key: %v", err)
	}
}

// TestPooledSocksRefusesToServeWithoutAnExitKey pins the guard at the accept loop.
//
// The single-transport accept path already refuses to serve a connection when it has no
// exit key (`sess == nil || len(exitPub) == 0`); the pooled one checked only the
// session. That asymmetry is exactly the shape of #29 — one path holding a guard the
// other does not — and an empty key there is what reaches the verifier as a bearer
// credential.
func TestPooledSocksRefusesToServeWithoutAnExitKey(t *testing.T) {
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	e := poolAdmissionEngine(t, rootPub)

	// A session with no exit key: the state the guard exists for.
	e.setActivePath(dialedPath{sess: newFakeSession(), exitID: "", exitPub: nil})
	if e.activePathServable() {
		t.Error("the pooled accept loop would serve a connection over a session whose exit key it does not hold — the end-to-end credential check then runs unbound and admits any authorized exit (issue #29)")
	}
	// Non-vacuity: a complete path is servable.
	exit, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	e.setActivePath(dialedPath{sess: newFakeSession(), exitID: hex.EncodeToString(exit.Public), exitPub: exit.Public})
	if !e.activePathServable() {
		t.Error("a complete pooled path was refused")
	}
}
