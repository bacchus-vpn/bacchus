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

// TestLoadOrGenerateBootstrapKey_KeyOnDiskIsTheKeyReturned is issue #189's
// invariant for the snapshot signing key. One coordinator per host makes this
// the weakest of the three races — and it costs one flag to close, which is why
// it is closed. What the test pins is the property rather than the flag: no
// caller is ever handed a key that is not the key at path. A coordinator signing
// snapshots under a key an operator will not read back out is #178's
// "already travelled out of band" failure by a shorter route — every invite
// carrying the logged pubkey fails snapshot verification.
func TestLoadOrGenerateBootstrapKey_KeyOnDiskIsTheKeyReturned(t *testing.T) {
	const rounds, racers = 60, 8
	for round := 0; round < rounds; round++ {
		path := filepath.Join(t.TempDir(), "secrets", "bootstrap.key")

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
				k, err := loadOrGenerateBootstrapKey(path)
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

		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("round %d: no key was persisted at all: %v", round, err)
		}
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("round %d: persisted key is not a %d-byte hex seed: %q", round, ed25519.SeedSize, b)
		}
		want := ed25519.NewKeyFromSeed(seed)

		if len(keys) == 0 {
			t.Fatalf("round %d: every caller failed; the winner must succeed (errors: %v)", round, errs)
		}
		for _, k := range keys {
			if !bytes.Equal(k, want) {
				t.Fatalf("round %d: a caller was handed a signing key that is NOT the key at %s — "+
					"the pubkey it logs for invites would not be the one snapshots verify against", round, path)
			}
		}
		for _, err := range errs {
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("round %d: refusal does not name the path: %v", round, err)
			}
		}
	}
}

// TestLoadOrGenerateBootstrapKey_RefusesWhenTheFileAppearsMidGeneration drives
// the refusal deterministically. A dangling symlink at the key path reads as
// ErrNotExist, so the generate branch is entered, and then fails O_EXCL with
// EEXIST. It also pins that the seed is not written THROUGH the symlink — which
// os.WriteFile did, and which matters here because secrets/ is a directory an
// operator manages by hand.
func TestLoadOrGenerateBootstrapKey_RefusesWhenTheFileAppearsMidGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs Developer Mode or elevation; " +
			"the racing test above covers the same refusal on every platform")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.key")
	target := filepath.Join(dir, "elsewhere.key")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	key, err := loadOrGenerateBootstrapKey(path)
	if err == nil {
		t.Fatal("a key file that appears between the read and the create must be REFUSED, not " +
			"written through and not silently re-read — the key in memory is not the key on disk")
	}
	if key != nil {
		t.Fatalf("a refusal must return no key, got %d bytes", len(key))
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("refusal does not name the path it refused: %v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatalf("the seed was written THROUGH the symlink to %s — a signing key must never land "+
			"at a path the operator did not name", target)
	}
}

// TestLoadOrGenerateBootstrapKey_PersistsTheWholeSeedBeforeReturning is #189's
// flush half at the level a test in this process can observe: when the call
// returns, path holds the complete seed of the key it handed back — and the log
// line that puts that pubkey in front of an operator to bake into invites has
// already run. fsync's own guarantee, that those bytes survive an unclean
// shutdown, is a kernel property no in-process test can witness.
func TestLoadOrGenerateBootstrapKey_PersistsTheWholeSeedBeforeReturning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "bootstrap.key")
	key, err := loadOrGenerateBootstrapKey(path)
	if err != nil {
		t.Fatalf("loadOrGenerateBootstrapKey: %v", err)
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

// TestLoadOrGenerateBootstrapKey_ExistingKeyIsLoadedNotRegenerated keeps the
// ordinary path honest: a coordinator restart must load its key, not refuse.
// Only a file that appears AFTER this process decided to generate is a race.
func TestLoadOrGenerateBootstrapKey_ExistingKeyIsLoadedNotRegenerated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.key")
	first, err := loadOrGenerateBootstrapKey(path)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	second, err := loadOrGenerateBootstrapKey(path)
	if err != nil {
		t.Fatalf("a restart must load the existing key, not refuse: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("a restart must return the SAME signing key the first start generated")
	}
}
