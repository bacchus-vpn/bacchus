package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestLoadOrGenerateAdmissionKey_KeyOnDiskIsTheKeyReturned is issue #189's
// invariant for the highest-value of the three seeds: the ADMISSION ROOT signing
// key, whose public half an operator pastes into a coordinator as
// -admission-pubkey.
//
// This is the writer the card calls live, because it is a CLI: `xargs -P` over a
// batch of subjects against one fresh -key path is an ordinary thing for an
// operator to type. Read-then-write is a TOCTOU, so before #189 both invocations
// generated a root key, the second os.WriteFile silently overwrote the first,
// and every credential the loser signed in between verifies against nothing
// anybody holds.
func TestLoadOrGenerateAdmissionKey_KeyOnDiskIsTheKeyReturned(t *testing.T) {
	const rounds, racers = 60, 8
	for round := 0; round < rounds; round++ {
		path := filepath.Join(t.TempDir(), "secrets", "admission.key")

		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			mu    sync.Mutex
			keys  []ed25519.PrivateKey
			errs  []error
		)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				k, err := loadOrGenerateAdmissionKey(path)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
					return
				}
				keys = append(keys, k)
			}()
		}
		close(start)
		wg.Wait()

		want, err := readSeedKey(t, path)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if len(keys) == 0 {
			t.Fatalf("round %d: every invocation failed; the winner must succeed (errors: %v)", round, errs)
		}
		for _, k := range keys {
			if !bytes.Equal(k, want) {
				t.Fatalf("round %d: an invocation was handed a root key that is NOT the key at %s — "+
					"whatever it signed verifies against a key nobody holds", round, path)
			}
		}
		for _, err := range errs {
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("round %d: refusal does not name the path: %v", round, err)
			}
		}
	}
}

// TestLoadOrGenerateAdmissionKey_RefusesWhenTheFileAppearsMidGeneration drives
// the refusal deterministically. A dangling symlink at the key path reads as
// ErrNotExist, so the generate branch is entered, and then fails O_EXCL with
// EEXIST — the shape of losing the race, without needing one. It also pins that
// the seed is not written THROUGH the symlink, which os.WriteFile did.
func TestLoadOrGenerateAdmissionKey_RefusesWhenTheFileAppearsMidGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs Developer Mode or elevation; " +
			"the racing test above covers the same refusal on every platform")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "admission.key")
	target := filepath.Join(dir, "elsewhere.key")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	key, err := loadOrGenerateAdmissionKey(path)
	if err == nil {
		t.Fatal("a key file that appears between the read and the create must be REFUSED, not " +
			"written through and not silently re-read — the root key in memory is not the one on disk")
	}
	if key != nil {
		t.Fatalf("a refusal must return no key, got %d bytes", len(key))
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("refusal does not name the path it refused: %v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatalf("the root seed was written THROUGH the symlink to %s — a signing key must never "+
			"land at a path the operator did not name", target)
	}
}

// TestLoadOrGenerateAdmissionKey_PersistsTheWholeSeedBeforeReturning is #189's
// flush half at the level a test in this process can observe: when the call
// returns, path holds the complete seed of the key it handed back — and the
// caller has already had -admission-pubkey printed at it by then. fsync's own
// guarantee, that those bytes survive an unclean shutdown, is a kernel property
// no in-process test can witness.
func TestLoadOrGenerateAdmissionKey_PersistsTheWholeSeedBeforeReturning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "admission.key")
	key, err := loadOrGenerateAdmissionKey(path)
	if err != nil {
		t.Fatalf("loadOrGenerateAdmissionKey: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if want := hex.EncodeToString(key.Seed()); string(b) != want {
		t.Fatalf("persisted seed is %q (%d bytes), want the returned key's seed %q (%d bytes)",
			b, len(b), want, len(want))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key perm = %o, want 0600", perm)
	}
}

// TestLoadOrGenerateAdmissionKey_ExistingKeyIsLoadedNotRegenerated keeps the
// ordinary path honest: #189 must not turn a second run into a refusal. Only a
// file that appears AFTER this run decided to generate is a race.
func TestLoadOrGenerateAdmissionKey_ExistingKeyIsLoadedNotRegenerated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admission.key")
	first, err := loadOrGenerateAdmissionKey(path)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := loadOrGenerateAdmissionKey(path)
	if err != nil {
		t.Fatalf("second run must load the existing key, not refuse: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("a second run must return the SAME root key the first generated")
	}
}

func readSeedKey(t *testing.T, path string) (ed25519.PrivateKey, error) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, os.ErrInvalid
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
