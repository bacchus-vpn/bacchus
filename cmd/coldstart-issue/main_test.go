package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// The tests here are the second half of issue #178: not the torn file, which
// core/coldstart's own tests cover, but the LOST ENTRY — two issuers each
// writing a complete file, the second without the first's secret.
//
// Nothing here calls coldstart.GenerateSecret. Every fixture is a counter, so no
// value in this file or in any temporary file it writes could be mistaken for,
// or reused as, a real bootstrap secret.

// synthSecret builds an obviously-fake secret of the right length: byte i
// repeated. A real one is 32 bytes from crypto/rand.
func synthSecret(i int) []byte { return bytes.Repeat([]byte{byte(i)}, coldstart.SecretLen) }

// synthID is the matching secret ID. Readable rather than hex — the ID is an
// opaque key to the file format, and a failure message that names "issued-0003"
// can be checked by eye.
func synthID(i int) string { return fmt.Sprintf("issued-%04d", i) }

func TestAddSecretCreatesTheSecretsFileOnTheFirstMint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-secrets.json")
	if err := addSecret(path, synthID(0), synthSecret(0)); err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	store, err := coldstart.LoadMemStore(path)
	if err != nil {
		t.Fatalf("LoadMemStore: %v", err)
	}
	if _, ok := store.Lookup(synthID(0)); !ok {
		t.Error("the first mint did not land in the file it created")
	}
	assertNoLockLeftBehind(t, path)
}

// TestAddSecretKeepsEverySecretAlreadyIssued is the read-modify-write contract,
// asserted directly. Every entry in this file is an invite already in somebody's
// hands, so a mint that drops one is not a lost update — it is a person who can
// no longer bootstrap and cannot be told apart from an attacker.
func TestAddSecretKeepsEverySecretAlreadyIssued(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-secrets.json")
	const mints = 5
	for i := 0; i < mints; i++ {
		if err := addSecret(path, synthID(i), synthSecret(i)); err != nil {
			t.Fatalf("addSecret %d: %v", i, err)
		}
	}
	store, err := coldstart.LoadMemStore(path)
	if err != nil {
		t.Fatalf("LoadMemStore: %v", err)
	}
	for i := 0; i < mints; i++ {
		got, ok := store.Lookup(synthID(i))
		if !ok {
			t.Errorf("%s is gone after %d mints", synthID(i), mints)
			continue
		}
		if !bytes.Equal(got, synthSecret(i)) {
			t.Errorf("%s came back as a different secret", synthID(i))
		}
	}
	assertNoLockLeftBehind(t, path)
}

// TestAddSecretRefusesWhileAnotherIssuerHoldsTheLock: the refusal is the whole
// mechanism, and it must be identifiable rather than merely loud — an operator
// who cannot tell "somebody else is minting" from "the write failed" learns the
// wrong lesson from it.
func TestAddSecretRefusesWhileAnotherIssuerHoldsTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-secrets.json")
	release, err := lockSecrets(path)
	if err != nil {
		t.Fatalf("lockSecrets: %v", err)
	}

	err = addSecret(path, synthID(1), synthSecret(1))
	if !errors.Is(err, errLockHeld) {
		t.Fatalf("addSecret while locked = %v, want errLockHeld", err)
	}
	// The message has to be actionable: a lock left by a killed issuer is
	// cleared by hand, so it must say which file to remove.
	if lock := path + ".lock"; !bytes.Contains([]byte(err.Error()), []byte(lock)) {
		t.Errorf("the refusal does not name %s, so an operator cannot clear a stale lock from it:\n%v", lock, err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("a refused mint touched the secrets file")
	}

	release()
	if err := addSecret(path, synthID(1), synthSecret(1)); err != nil {
		t.Fatalf("addSecret after the lock was released: %v", err)
	}
	assertNoLockLeftBehind(t, path)
}

// TestAddSecretReleasesTheLockWhenTheMintFails is the failure this refactor
// exists to make impossible. Every exit from addSecret runs through one deferred
// release; the shape it replaced reached log.Fatalf directly, which calls
// os.Exit and runs no deferred function at all — so a bad secrets file would
// have left a lock behind and turned one loud error into a permanently wedged
// tool.
func TestAddSecretReleasesTheLockWhenTheMintFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-secrets.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed a malformed file: %v", err)
	}
	err := addSecret(path, synthID(0), synthSecret(0))
	if err == nil {
		t.Fatal("addSecret over an unparseable secrets file succeeded; it must refuse rather than overwrite entries it could not read")
	}
	if errors.Is(err, errLockHeld) {
		t.Fatalf("addSecret = %v, want a load failure rather than a lock failure", err)
	}
	assertNoLockLeftBehind(t, path)
}

// TestConcurrentIssuersNeverSilentlyDropASecret is the property the lock is for,
// and it is stated as an implication rather than as "they all succeed":
// SUCCEEDING MEANS BEING IN THE FILE. An issuer may lose the race and refuse —
// that is fine and visible, and the operator re-runs — but an issuer that
// returns nil has already printed an invite, and there is no acceptable world in
// which that secret is not on disk.
//
// The retries stand in for that operator re-running the tool. Without the lock
// the retries change nothing and the assertion still fails, because the losers do
// not know they lost.
func TestConcurrentIssuersNeverSilentlyDropASecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-secrets.json")

	const issuers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded []int
	)
	for i := 0; i < issuers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for attempt := 0; attempt < 200; attempt++ {
				err := addSecret(path, synthID(i), synthSecret(i))
				if errors.Is(err, errLockHeld) {
					time.Sleep(time.Millisecond)
					continue
				}
				if err != nil {
					t.Errorf("issuer %d: %v", i, err)
					return
				}
				mu.Lock()
				succeeded = append(succeeded, i)
				mu.Unlock()
				return
			}
		}(i)
	}
	wg.Wait()

	if len(succeeded) == 0 {
		t.Fatal("no issuer got through at all, so this test asserted nothing")
	}
	store, err := coldstart.LoadMemStore(path)
	if err != nil {
		t.Fatalf("LoadMemStore after %d concurrent issuers: %v", len(succeeded), err)
	}
	for _, i := range succeeded {
		if _, ok := store.Lookup(synthID(i)); !ok {
			t.Errorf("issuer %d was told its mint succeeded and printed an invite, but %s is not in the file: another issuer wrote a complete file over it", i, synthID(i))
		}
	}
	t.Logf("%d of %d issuers completed a mint; every one of them is in the file", len(succeeded), issuers)
	assertNoLockLeftBehind(t, path)
}

// assertNoLockLeftBehind checks that a run which returned leaves nothing for the
// next one to trip over. A stale lock is this design's one real cost and it must
// only ever be produced by a process that DIED, never by one that returned.
func assertNoLockLeftBehind(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Errorf("%s.lock survived a run that returned; the next mint would refuse for no reason", path)
	}
}
