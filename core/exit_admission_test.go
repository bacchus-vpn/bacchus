package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// End-to-end exit-admission verification (issue #60). These tests drive the same
// layer core/e2e_test.go does — a raw net.Pipe standing in for one transport
// stream, exitHandshake on one end and clientHandshake on the other — and assert
// the client's decision to route or abort based on the admission credential the
// exit presents inside the Noise_NK handshake.

// admissionNow is a fixed clock so credential windows are deterministic.
var admissionNow = time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

// issueExitCred mints a root-signed credential and returns its encoded wire
// bytes — exactly what an exit presents in the handshake (the exit passes
// []byte(Config.AdmissionCred), which is this encoded string).
func issueExitCred(t *testing.T, root ed25519.PrivateKey, subject string, roles []admission.Role, nbf, exp time.Time) []byte {
	t.Helper()
	_, enc, err := admission.Issue(root, subject, roles, nbf, exp, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return []byte(enc)
}

// verifierBoundTo builds the client-side verify callback: a real verifier over
// rootPub, bound to exitPub, at the fixed test clock.
func verifierBoundTo(rootPub ed25519.PublicKey, exitPub []byte) func([]byte) error {
	v := admission.NewVerifier(rootPub, nil)
	return func(cred []byte) error { return verifyExitCredential(v, exitPub, cred, admissionNow) }
}

// TestE2EClientAcceptsAdmissionAuthorizedExit: an exit presenting a valid,
// root-signed, self-bound exit credential connects unchanged — the client
// verifies it end-to-end and routes normally.
func TestE2EClientAcceptsAdmissionAuthorizedExit(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitID := hex.EncodeToString(key.Public)
	cred := issueExitCred(t, rootPriv, exitID, []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour))

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	const target = "example.com:443"

	done := make(chan error, 1)
	go func() {
		nc, tgt, err := exitHandshake(sConn, key, cred)
		if err != nil {
			done <- err
			return
		}
		if tgt != target {
			done <- fmt.Errorf("exit target = %q, want %q", tgt, target)
			return
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(nc, buf)
		done <- err
	}()

	nc, err := clientHandshake(cConn, key.Public, target, verifierBoundTo(rootPub, key.Public))
	if err != nil {
		t.Fatalf("client rejected an admission-authorized exit: %v", err)
	}
	if _, err := nc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("exit side: %v", err)
	}
}

// TestE2EClientRejectsHostileExit is the #60 acceptance test: a hostile exit
// holds a self-consistent id (so it completes Noise_NK) but has no valid root
// credential binding that id to the exit role. Whatever it presents — nothing, a
// malformed blob, a credential for another exit, an expired one, a wrong-role
// one, or one signed by a coordinator's own rogue root — the client aborts
// before routing. This is the direct-mode case; the relay-mode case follows.
func TestE2EClientRejectsHostileExit(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, rogueRootPriv, err := ed25519.GenerateKey(nil) // a coordinator's own rogue admission root
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// The hostile exit's real key: self-consistent, completes Noise_NK.
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitID := hex.EncodeToString(key.Public)

	// A different, legitimately-credentialed exit whose credential the hostile
	// exit might try to replay.
	otherKey, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	otherID := hex.EncodeToString(otherKey.Public)

	inWindow := func() (time.Time, time.Time) { return admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour) }
	nbf, exp := inWindow()

	cases := []struct {
		name string
		cred []byte
	}{
		{"no credential presented", nil},
		{"malformed credential", []byte("bacchusc1:!!!not-valid-base64")},
		{"credential bound to another exit (replayed)", issueExitCred(t, rootPriv, otherID, []admission.Role{admission.RoleExit}, nbf, exp)},
		{"expired credential", issueExitCred(t, rootPriv, exitID, []admission.Role{admission.RoleExit}, admissionNow.Add(-2*time.Hour), admissionNow.Add(-time.Hour))},
		{"role not authorized (client-only)", issueExitCred(t, rootPriv, exitID, []admission.Role{admission.RoleClient}, nbf, exp)},
		{"signed by a rogue root", issueExitCred(t, rogueRootPriv, exitID, []admission.Role{admission.RoleExit}, nbf, exp)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cConn, sConn := net.Pipe()
			deadline(t, cConn, sConn)
			go func() { _, _, _ = exitHandshake(sConn, key, tc.cred) }()

			nc, err := clientHandshake(cConn, key.Public, "example.com:443", verifierBoundTo(rootPub, key.Public))
			_ = cConn.Close() // unblock the exit goroutine's target read
			if err == nil {
				_ = nc.Close()
				t.Fatal("client established a session with a hostile exit; want abort")
			}
		})
	}
}

// TestE2EHostileExitRejectedThroughRelay: the same rejection holds with a blind
// relay forwarding ciphertext in the path. Noise_NK — and the credential in its
// payload — is end-to-end, so a relay changes nothing: the client still refuses
// an exit that presents no valid credential.
func TestE2EHostileExitRejectedThroughRelay(t *testing.T) {
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}

	cConn, rClient := net.Pipe() // client <-> relay
	rExit, sConn := net.Pipe()   // relay  <-> exit
	deadline(t, cConn, rClient, rExit, sConn)

	// Blind relay: forward ciphertext both ways, learning nothing.
	go func() { _, _ = io.Copy(rExit, rClient) }()
	go func() { _, _ = io.Copy(rClient, rExit) }()

	go func() { _, _, _ = exitHandshake(sConn, key, nil) }() // presents no credential

	nc, err := clientHandshake(cConn, key.Public, "example.com:443", verifierBoundTo(rootPub, key.Public))
	_ = cConn.Close()
	if err == nil {
		_ = nc.Close()
		t.Fatal("client accepted a credential-less exit through a relay; want abort")
	}
}

// TestBuildExitVerifier: an empty key yields a nil verifier (fail-open); a valid
// key yields a verifier; a malformed key is an error (fail-loud).
func TestBuildExitVerifier(t *testing.T) {
	if v, _, err := buildExitVerifier("", "", "", false, admissionNow); err != nil || v != nil {
		t.Fatalf("empty key: got (%v, %v), want (nil, nil)", v, err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if v, _, err := buildExitVerifier(hex.EncodeToString(pub), "", "", false, admissionNow); err != nil || v == nil {
		t.Fatalf("valid key: got (%v, %v), want (non-nil, nil)", v, err)
	}
	if _, _, err := buildExitVerifier("not-hex", "", "", false, admissionNow); err == nil {
		t.Fatal("malformed hex must error")
	}
	if _, _, err := buildExitVerifier(hex.EncodeToString([]byte{1, 2, 3}), "", "", false, admissionNow); err == nil {
		t.Fatal("wrong-length key must error")
	}
}

// TestNewRejectsMalformedAdmissionPubKey: a client told to verify against an
// unusable key must fail construction, not silently fall through to trusting
// every exit.
func TestNewRejectsMalformedAdmissionPubKey(t *testing.T) {
	if _, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"client"}, AdmissionPubKey: "not-hex"}); err == nil {
		t.Fatal("a malformed AdmissionPubKey must be a construction error")
	}
}

// Client-side revocation oracle (issue #69): buildExitVerifier wires a signed
// CRL into a real revoked predicate instead of the nil (always-false) oracle
// #60 v1 shipped with. These are the acceptance tests: a CRL configured
// rejects a revoked-but-unexpired credential and still accepts a non-revoked
// one; no anchor/CRL at all is unchanged fail-open; a broken or stale CRL is a
// construction error, not a silent downgrade.

// TestBuildExitVerifierWithCRL: a configured CRL yields a verifier whose
// revoked predicate matches the bundle, and leaves a non-revoked serial alone.
func TestBuildExitVerifierWithCRL(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crl, err := admission.SignCRL(priv, []string{"deadbeef"}, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	v, _, err := buildExitVerifier(hex.EncodeToString(pub), crl, "", false, admissionNow)
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}
	_, enc, err := admission.Issue(priv, "exit-A", []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := v.Verify(enc, admissionNow, admission.RoleExit, "exit-A"); err != nil {
		t.Fatalf("non-revoked credential rejected: %v", err)
	}
}

// TestBuildExitVerifierRevokedCredentialRejected is the #69 acceptance case at
// the verifier layer: a credential whose serial appears in the configured CRL
// is rejected as ErrRevoked even though it is otherwise unexpired and
// well-formed.
func TestBuildExitVerifierRevokedCredentialRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, enc, err := admission.Issue(priv, "exit-A", []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	crl, err := admission.SignCRL(priv, []string{c.Serial}, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	v, _, err := buildExitVerifier(hex.EncodeToString(pub), crl, "", false, admissionNow)
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}
	if _, err := v.Verify(enc, admissionNow, admission.RoleExit, "exit-A"); !errors.Is(err, admission.ErrRevoked) {
		t.Fatalf("Verify err = %v, want ErrRevoked", err)
	}
}

// TestBuildExitVerifierNoCRLFailsOpenOnRevocation: with an anchor but no CRL
// (today's #60 v1 shape), a credential that would be revoked under some other
// bundle still verifies — matching admission.NewVerifier's nil-oracle default.
func TestBuildExitVerifierNoCRLFailsOpenOnRevocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, enc, err := admission.Issue(priv, "exit-A", []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v, _, err := buildExitVerifier(hex.EncodeToString(pub), "", "", false, admissionNow)
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}
	if _, err := v.Verify(enc, admissionNow, admission.RoleExit, "exit-A"); err != nil {
		t.Fatalf("no CRL configured must fail open on revocation: %v", err)
	}
}

// TestBuildExitVerifierUnconfiguredFailsOpen: no anchor and no CRL is
// unchanged fail-open — the client accepts any exit, exactly as before #69.
func TestBuildExitVerifierUnconfiguredFailsOpen(t *testing.T) {
	v, _, err := buildExitVerifier("", "", "", false, admissionNow)
	if err != nil || v != nil {
		t.Fatalf("unconfigured: got (%v, %v), want (nil, nil)", v, err)
	}
}

// TestBuildExitVerifierMalformedCRL covers issue #69's "malformed-CRL
// handling" requirement: a CRL that fails to parse, fails signature
// verification, or has already expired must all fail construction — never
// silently fall back to "nothing is revoked".
func TestBuildExitVerifierMalformedCRL(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	goodCRL, err := admission.SignCRL(priv, []string{"cafe"}, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	wrongRootCRL, err := admission.SignCRL(otherPriv, []string{"cafe"}, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	expiredCRL, err := admission.SignCRL(priv, []string{"cafe"}, admissionNow.Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}

	cases := []struct {
		name string
		crl  string
	}{
		{"garbage text", "not a crl at all"},
		{"missing prefix", "bacchusc1:AbCdEf"}, // a credential-shaped tag, not a CRL's
		{"truncated bacchusr1 payload", "bacchusr1:AbCd"},
		{"signed by a different root", wrongRootCRL},
		{"expired bundle", expiredCRL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := buildExitVerifier(hex.EncodeToString(pub), tc.crl, "", false, admissionNow); err == nil {
				t.Fatal("malformed/expired CRL must be a construction error")
			}
		})
	}

	// Sanity: the same "good" CRL that failed above under a mismatched root
	// succeeds when paired with the matching anchor, so the failures above are
	// really about the CRL, not an unrelated bug.
	if _, _, err := buildExitVerifier(hex.EncodeToString(pub), goodCRL, "", false, admissionNow); err != nil {
		t.Fatalf("well-formed CRL under the matching anchor must construct: %v", err)
	}
}

// TestBuildExitVerifierCRLWithoutAnchorErrors: a CRL is verified against the
// anchor, so configuring one without the other is a construction error, not a
// silent no-op — distinct from the "both empty" fail-open case.
func TestBuildExitVerifierCRLWithoutAnchorErrors(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crl, err := admission.SignCRL(priv, nil, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if _, _, err := buildExitVerifier("", crl, "", false, admissionNow); err == nil {
		t.Fatal("a CRL without an anchor must be a construction error")
	}
}

// Client CRL sourced from a file path, reloaded on an interval (issue #90).
// buildExitVerifier's crlPath handling mirrors its crlEncoded handling
// exactly — same construction-error posture — so these tests parallel the
// crlEncoded ones above; core/crl_reload_test.go covers the actual reload
// (Engine.reloadCRLLoop / reloadCRL) end to end.

// TestBuildExitVerifierCRLPathAndInlineBothSetErrors: AdmissionCRL and
// AdmissionCRLPath are alternate sources for the same state: configuring both
// at once is ambiguous, so it is a construction error rather than silently
// preferring one.
func TestBuildExitVerifierCRLPathAndInlineBothSetErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crl, err := admission.SignCRL(priv, nil, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if _, _, err := buildExitVerifier(hex.EncodeToString(pub), crl, "some/path", false, admissionNow); err == nil {
		t.Fatal("setting both AdmissionCRL and AdmissionCRLPath must be a construction error")
	}
}

// TestBuildExitVerifierCRLPath: a well-formed bundle at crlPath is read,
// verified, and wired into the verifier's revoked predicate exactly like an
// inline crlEncoded bundle.
func TestBuildExitVerifierCRLPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, enc, err := admission.Issue(priv, "exit-A", []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	crl, err := admission.SignCRL(priv, []string{c.Serial}, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "revocations.crl")
	if err := os.WriteFile(path, []byte(crl), 0o600); err != nil {
		t.Fatalf("write CRL file: %v", err)
	}

	v, cc, err := buildExitVerifier(hex.EncodeToString(pub), "", path, false, admissionNow)
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}
	if cc == nil {
		t.Fatal("an anchor was configured; ClientCRL must be non-nil")
	}
	if _, err := v.Verify(enc, admissionNow, admission.RoleExit, "exit-A"); !errors.Is(err, admission.ErrRevoked) {
		t.Fatalf("Verify err = %v, want ErrRevoked (bundle loaded from path)", err)
	}
}

// TestBuildExitVerifierCRLPathMissingFileErrors: crlPath pointing at a
// nonexistent file is a construction error, matching a malformed inline
// bundle — an operator who points -admission-crl at a typo'd path must not
// have the client silently start fail-open.
func TestBuildExitVerifierCRLPathMissingFileErrors(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist.crl")
	if _, _, err := buildExitVerifier(hex.EncodeToString(pub), "", missing, false, admissionNow); err == nil {
		t.Fatal("a missing AdmissionCRLPath file must be a construction error")
	}
}

// TestBuildExitVerifierCRLPathMalformedErrors: the path-sourced bundle goes
// through the same VerifyCRL as the inline one, so a bad signature or an
// already-expired bundle at the path is equally a construction error.
func TestBuildExitVerifierCRLPathMalformedErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	expired, err := admission.SignCRL(priv, []string{"cafe"}, admissionNow.Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "revocations.crl")
	if err := os.WriteFile(path, []byte(expired), 0o600); err != nil {
		t.Fatalf("write CRL file: %v", err)
	}
	if _, _, err := buildExitVerifier(hex.EncodeToString(pub), "", path, false, admissionNow); err == nil {
		t.Fatal("an expired bundle at AdmissionCRLPath must be a construction error")
	}
}

// Opt-in require-CRL mode (issue #91): "anchor present, CRL absent" becomes a
// construction error instead of the default fail-open. These are the #91
// acceptance tests.

// TestBuildExitVerifierRequireCRLDefaultUnchanged proves the default
// (requireCRL=false, the zero value of Config.AdmissionRequireCRL) is
// byte-for-byte the pre-#91 behavior: an anchor with no CRL still
// constructs and still fails open on revocation. This is the test that would
// catch a regression flipping the default.
func TestBuildExitVerifierRequireCRLDefaultUnchanged(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	v, _, err := buildExitVerifier(hex.EncodeToString(pub), "", "", false, admissionNow)
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}
	_, enc, err := admission.Issue(priv, "exit-A", []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := v.Verify(enc, admissionNow, admission.RoleExit, "exit-A"); err != nil {
		t.Fatalf("default (requireCRL=false) must still fail open with no CRL: %v", err)
	}
}

// TestBuildExitVerifierRequireCRLAnchorNoCRLErrors is the #91 acceptance
// case: an anchor configured, requireCRL on, and no CRL of either kind — the
// exact "hostile coordinator stripped the CRL from the invite" shape — must
// be a hard construction error, not a silent fail-open.
func TestBuildExitVerifierRequireCRLAnchorNoCRLErrors(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, _, err := buildExitVerifier(hex.EncodeToString(pub), "", "", true, admissionNow); err == nil {
		t.Fatal("requireCRL with an anchor but no CRL must be a construction error")
	}
}

// TestBuildExitVerifierRequireCRLNoAnchorErrors: requireCRL with no anchor at
// all has nothing to enforce, so it too is a construction error rather than
// a quiet no-op an operator could mistake for protection.
func TestBuildExitVerifierRequireCRLNoAnchorErrors(t *testing.T) {
	if _, _, err := buildExitVerifier("", "", "", true, admissionNow); err == nil {
		t.Fatal("requireCRL with no AdmissionPubKey must be a construction error")
	}
}

// TestBuildExitVerifierRequireCRLSatisfied: requireCRL imposes no extra
// constraint once a CRL is actually configured, whether inline or via path.
func TestBuildExitVerifierRequireCRLSatisfied(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crl, err := admission.SignCRL(priv, nil, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if _, _, err := buildExitVerifier(hex.EncodeToString(pub), crl, "", true, admissionNow); err != nil {
		t.Fatalf("requireCRL with an inline CRL configured must succeed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "revocations.crl")
	if err := os.WriteFile(path, []byte(crl), 0o600); err != nil {
		t.Fatalf("write CRL file: %v", err)
	}
	if _, _, err := buildExitVerifier(hex.EncodeToString(pub), "", path, true, admissionNow); err != nil {
		t.Fatalf("requireCRL with a path CRL configured must succeed: %v", err)
	}
}

// TestE2EClientRejectsRevokedExit is the #69 acceptance test run through the
// actual handshake path (mirrors TestE2EClientRejectsHostileExit): an exit
// presents a credential that is signed, self-bound, in its validity window —
// everything #60 v1 checks — but its serial is in the client's configured
// CRL. The client aborts instead of routing.
func TestE2EClientRejectsRevokedExit(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitID := hex.EncodeToString(key.Public)
	c, enc, err := admission.Issue(rootPriv, exitID, []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	crl, err := admission.SignCRL(rootPriv, []string{c.Serial}, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	v, _, err := buildExitVerifier(hex.EncodeToString(rootPub), crl, "", false, admissionNow)
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	go func() { _, _, _ = exitHandshake(sConn, key, []byte(enc)) }()

	nc, err := clientHandshake(cConn, key.Public, "example.com:443", func(cred []byte) error {
		return verifyExitCredential(v, key.Public, cred, admissionNow)
	})
	_ = cConn.Close()
	if err == nil {
		_ = nc.Close()
		t.Fatal("client established a session with a revoked exit; want abort")
	}
	if !errors.Is(err, admission.ErrRevoked) {
		t.Fatalf("err = %v, want wrapping admission.ErrRevoked", err)
	}
}

// TestE2EClientAcceptsNonRevokedExitWithCRLConfigured: with the same CRL
// configured, a different, non-revoked credential from the same root still
// connects normally — a configured CRL must not over-reject.
func TestE2EClientAcceptsNonRevokedExitWithCRLConfigured(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitID := hex.EncodeToString(key.Public)
	_, enc, err := admission.Issue(rootPriv, exitID, []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// The CRL revokes some unrelated serial, never this credential's.
	crl, err := admission.SignCRL(rootPriv, []string{"some-other-serial"}, admissionNow, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	v, _, err := buildExitVerifier(hex.EncodeToString(rootPub), crl, "", false, admissionNow)
	if err != nil {
		t.Fatalf("buildExitVerifier: %v", err)
	}

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	const target = "example.com:443"
	done := make(chan error, 1)
	go func() {
		nc, tgt, err := exitHandshake(sConn, key, []byte(enc))
		if err != nil {
			done <- err
			return
		}
		if tgt != target {
			done <- fmt.Errorf("exit target = %q, want %q", tgt, target)
			return
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(nc, buf)
		done <- err
	}()

	nc, err := clientHandshake(cConn, key.Public, target, func(cred []byte) error {
		return verifyExitCredential(v, key.Public, cred, admissionNow)
	})
	if err != nil {
		t.Fatalf("client rejected a non-revoked exit with a CRL configured: %v", err)
	}
	if _, err := nc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("exit side: %v", err)
	}
}

// TestClientWithoutAnchorFailsOpen: no configured anchor means no verify
// callback — the client accepts any exit it can complete Noise_NK with, matching
// the coordinator's fail-open when -admission-pubkey is unset (#42).
func TestClientWithoutAnchorFailsOpen(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"client"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if eng.exitVerifyFunc(nil) != nil {
		t.Fatal("a client with no admission anchor must yield a nil verify func (fail-open)")
	}
}

// TestVerifyExitCredentialMissingIsRejected: once a client holds an anchor, an
// exit that presents no credential is rejected, not admitted.
func TestVerifyExitCredentialMissingIsRejected(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	v := admission.NewVerifier(pub, nil)
	if err := verifyExitCredential(v, make([]byte, 32), nil, admissionNow); !errors.Is(err, errMissingExitCredential) {
		t.Fatalf("empty credential: got %v, want errMissingExitCredential", err)
	}
}
