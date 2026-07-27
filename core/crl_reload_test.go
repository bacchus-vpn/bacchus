package core

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// Client CRL hot-reload (issue #90): the engine re-reads Config.AdmissionCRLPath
// on an interval and swaps a freshly verified bundle into the exit-admission
// verifier's revocation oracle, so a long-lived client picks up an operator's
// rotated CRL without a restart — the client-side mirror of
// cmd/coordinator's reloadRevocationsLoop.
//
// Unlike exit_admission_test.go's buildExitVerifier tests, these drive a real
// *Engine via New, whose construction-time CRL load (like AdmissionCRL's) is
// checked against the real wall clock, not a fixed one — New has no clock
// seam, matching production (only reloadCRL itself takes an explicit now, so
// a reload proper can be driven deterministically once the engine exists).
// So every test here mints its fixtures relative to a locally captured
// time.Now(), rather than the fixed admissionNow shared by
// exit_admission_test.go.

// newCRLReloadEngine builds a client-role engine, without starting it, whose
// AdmissionCRLPath points at path — which must already hold a bundle valid
// right now, since New's construction-time load is just as fail-loud as
// AdmissionCRL's. No coordinator dial happens until Start, so this needs no
// real network I/O (mirrors newReaperEngine).
func newCRLReloadEngine(t *testing.T, pubHex, path string) *Engine {
	t.Helper()
	e, err := New(Config{
		Coordinators:     []string{testCoord},
		Roles:            []string{RoleClient},
		AdmissionPubKey:  pubHex,
		AdmissionCRLPath: path,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { e.Stop(); e.Wait() })
	return e
}

// writeCRLFile writes encoded to a fresh temp file and returns its path.
func writeCRLFile(t *testing.T, encoded string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revocations.crl")
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("write CRL file: %v", err)
	}
	return path
}

// TestReloadCRLPicksUpNewRevocation is the #90 acceptance test: a credential
// that verifies against the client's initially loaded (non-revoking) CRL is
// rejected once the operator rotates the file to a bundle that revokes it and
// a reload runs — without restarting the client.
func TestReloadCRLPicksUpNewRevocation(t *testing.T) {
	now := time.Now()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, enc, err := admission.Issue(rootPriv, "exit-A", []admission.Role{admission.RoleExit}, now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	initial, err := admission.SignCRL(rootPriv, nil, now, time.Hour) // revokes nothing yet
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	path := writeCRLFile(t, initial)

	e := newCRLReloadEngine(t, hex.EncodeToString(rootPub), path)
	if _, err := e.exitVerifier.Verify(enc, now, admission.RoleExit, "exit-A"); err != nil {
		t.Fatalf("credential must verify against the initial (non-revoking) CRL: %v", err)
	}

	// The operator rotates the file to a fresh bundle revoking this exact
	// credential's serial.
	rotated, err := admission.SignCRL(rootPriv, []string{c.Serial}, now, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if err := os.WriteFile(path, []byte(rotated), 0o600); err != nil {
		t.Fatalf("rewrite CRL file: %v", err)
	}

	e.reloadCRL(now)

	if _, err := e.exitVerifier.Verify(enc, now, admission.RoleExit, "exit-A"); !errors.Is(err, admission.ErrRevoked) {
		t.Fatalf("after reload, err = %v, want ErrRevoked", err)
	}
}

// TestReloadCRLKeepsPreviousOnFailure covers the fail-safe half of #90: a
// reload that cannot read or cannot verify the file must not blind the
// client — the previously loaded bundle keeps being enforced, and the client
// must not crash or panic.
func TestReloadCRLKeepsPreviousOnFailure(t *testing.T) {
	now := time.Now()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, enc, err := admission.Issue(rootPriv, "exit-A", []admission.Role{admission.RoleExit}, now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	good, err := admission.SignCRL(rootPriv, []string{c.Serial}, now, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}

	t.Run("file deleted", func(t *testing.T) {
		path := writeCRLFile(t, good)
		e := newCRLReloadEngine(t, hex.EncodeToString(rootPub), path)
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove CRL file: %v", err)
		}
		e.reloadCRL(now) // must not panic
		if _, err := e.exitVerifier.Verify(enc, now, admission.RoleExit, "exit-A"); !errors.Is(err, admission.ErrRevoked) {
			t.Fatalf("a failed reload must keep enforcing the previous bundle: err = %v, want ErrRevoked", err)
		}
	})

	t.Run("file corrupted", func(t *testing.T) {
		path := writeCRLFile(t, good)
		e := newCRLReloadEngine(t, hex.EncodeToString(rootPub), path)
		if err := os.WriteFile(path, []byte("not a crl at all"), 0o600); err != nil {
			t.Fatalf("corrupt CRL file: %v", err)
		}
		e.reloadCRL(now)
		if _, err := e.exitVerifier.Verify(enc, now, admission.RoleExit, "exit-A"); !errors.Is(err, admission.ErrRevoked) {
			t.Fatalf("a failed reload must keep enforcing the previous bundle: err = %v, want ErrRevoked", err)
		}
	})

	t.Run("file expired", func(t *testing.T) {
		path := writeCRLFile(t, good)
		e := newCRLReloadEngine(t, hex.EncodeToString(rootPub), path)
		// Lapsed, and would un-revoke c.Serial if it took effect.
		expired, err := admission.SignCRL(rootPriv, nil, now.Add(-2*time.Hour), time.Hour)
		if err != nil {
			t.Fatalf("SignCRL: %v", err)
		}
		if err := os.WriteFile(path, []byte(expired), 0o600); err != nil {
			t.Fatalf("rewrite CRL file: %v", err)
		}
		e.reloadCRL(now)
		if _, err := e.exitVerifier.Verify(enc, now, admission.RoleExit, "exit-A"); !errors.Is(err, admission.ErrRevoked) {
			t.Fatalf("an expired reload must keep enforcing the previous bundle: err = %v, want ErrRevoked", err)
		}
	})
}

// TestReloadCRLLoopStopsOnEngineStop drives reloadCRLLoop directly (mirroring
// core/reaper_test.go's TestReaperDrainsHalfOpenSessions pattern for
// reapLoop): with a short interval it must tick and return promptly once
// e.stop closes, leaving no goroutine behind.
func TestReloadCRLLoopStopsOnEngineStop(t *testing.T) {
	now := time.Now()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crl, err := admission.SignCRL(rootPriv, nil, now, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	path := writeCRLFile(t, crl)
	e := newCRLReloadEngine(t, hex.EncodeToString(rootPub), path)
	e.crlReloadInterval = 2 * time.Millisecond

	e.wg.Add(1)
	go e.reloadCRLLoop()

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // let a few ticks happen
	e.Stop()                          // idempotent; t.Cleanup's e.Stop() is a harmless no-op afterward

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reloadCRLLoop did not exit after Stop")
	}
}

// TestStartReloadsCRLOnInterval is the full end-to-end wiring proof: a real
// Start (no manual reloadCRL call) picks up a rotated bundle through the
// actual ticker, for a genuinely running engine.
func TestStartReloadsCRLOnInterval(t *testing.T) {
	now := time.Now()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, enc, err := admission.Issue(rootPriv, "exit-A", []admission.Role{admission.RoleExit}, now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	initial, err := admission.SignCRL(rootPriv, nil, now, time.Hour) // revokes nothing yet
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	path := writeCRLFile(t, initial)

	e, err := New(Config{
		Coordinators:     []string{testCoord},
		Roles:            []string{RoleClient},
		AdmissionPubKey:  hex.EncodeToString(rootPub),
		AdmissionCRLPath: path,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.crlReloadInterval = 20 * time.Millisecond
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { e.Stop(); e.Wait() }()

	if _, err := e.exitVerifier.Verify(enc, time.Now(), admission.RoleExit, "exit-A"); err != nil {
		t.Fatalf("credential must verify against the initial (non-revoking) CRL: %v", err)
	}

	rotated, err := admission.SignCRL(rootPriv, []string{c.Serial}, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if err := os.WriteFile(path, []byte(rotated), 0o600); err != nil {
		t.Fatalf("rewrite CRL file: %v", err)
	}

	if !waitFor(2*time.Second, func() bool {
		_, err := e.exitVerifier.Verify(enc, time.Now(), admission.RoleExit, "exit-A")
		return errors.Is(err, admission.ErrRevoked)
	}) {
		t.Fatal("Start's reload loop never picked up the rotated CRL")
	}
}
