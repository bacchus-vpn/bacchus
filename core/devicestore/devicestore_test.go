package devicestore

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

func TestLoadOrGenerateKey_EphemeralWhenDirEmpty(t *testing.T) {
	k1, err := LoadOrGenerateKey("")
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	k2, err := LoadOrGenerateKey("")
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("two ephemeral keys must not be equal — each call with dir=\"\" must generate a fresh identity")
	}
	if len(k1) != ed25519.PrivateKeySize {
		t.Fatalf("key length = %d, want %d", len(k1), ed25519.PrivateKeySize)
	}
}

func TestLoadOrGenerateKey_GeneratesThenPersists(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "device")

	k1, err := LoadOrGenerateKey(sub)
	if err != nil {
		t.Fatalf("first LoadOrGenerateKey: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sub, keyFileName)); err != nil {
		t.Fatalf("expected a key file to be written: %v", err)
	}
	info, err := os.Stat(sub)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir perm = %o, want 0700", perm)
	}

	k2, err := LoadOrGenerateKey(sub)
	if err != nil {
		t.Fatalf("second LoadOrGenerateKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("a second load must return the SAME key the first call generated, not a fresh one")
	}
}

func TestLoadOrGenerateKey_CorruptFileIsHardError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("not hex at all"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, err := LoadOrGenerateKey(dir); err == nil {
		t.Fatal("a present but corrupt key file must be a hard error, never a silent regeneration")
	}
}

func TestLoadOrGenerateKey_WrongLengthSeedIsHardError(t *testing.T) {
	dir := t.TempDir()
	// Valid hex, wrong length — plausible operator mistake (e.g. pasted the
	// wrong file), must not be treated as "no key here".
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("deadbeef"), 0o600); err != nil {
		t.Fatalf("seed short file: %v", err)
	}
	if _, err := LoadOrGenerateKey(dir); err == nil {
		t.Fatal("a wrong-length seed must be a hard error")
	}
}

// TestLoadOrGenerateKey_KeyOnDiskIsTheKeyReturned is issue #189's invariant, and
// it is the one that matters rather than any statement about flags: a caller is
// NEVER handed a key that is not the key persisted at path. Racing callers on a
// fresh directory is how that gets broken — read-then-write is a TOCTOU, so
// before #189 every racer generated its own key and the last os.WriteFile won,
// leaving every other caller holding a key the file does not contain. A device
// that enrols under one and reloads under another is locked out of the
// credential it just obtained.
//
// The loop is not decoration. One race is a coin toss; sixty fresh directories
// with eight racers apiece is how a window this narrow is made to show itself.
func TestLoadOrGenerateKey_KeyOnDiskIsTheKeyReturned(t *testing.T) {
	const rounds, racers = 60, 8
	for round := 0; round < rounds; round++ {
		dir := filepath.Join(t.TempDir(), "device")

		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			mu    sync.Mutex
			keys  = make([]ed25519.PrivateKey, 0, racers)
			errs  = make([]error, 0, racers)
		)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				k, err := LoadOrGenerateKey(dir)
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

		onDisk, err := os.ReadFile(filepath.Join(dir, keyFileName))
		if err != nil {
			t.Fatalf("round %d: no key was persisted at all: %v", round, err)
		}
		seed, err := hex.DecodeString(strings.TrimSpace(string(onDisk)))
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("round %d: persisted key is not a %d-byte hex seed: %q",
				round, ed25519.SeedSize, onDisk)
		}
		want := ed25519.NewKeyFromSeed(seed)

		if len(keys) == 0 {
			t.Fatalf("round %d: every racer failed; at least the winner must succeed (errors: %v)", round, errs)
		}
		for _, k := range keys {
			if !bytes.Equal(k, want) {
				t.Fatalf("round %d: a caller was handed a key that is NOT the key at %s — "+
					"it would enrol under one identity and reload under another", round, dir)
			}
		}
		// A loser must refuse, and must say which path it lost.
		for _, err := range errs {
			if !strings.Contains(err.Error(), dir) {
				t.Fatalf("round %d: refusal does not name the path: %v", round, err)
			}
		}
	}
}

// TestLoadOrGenerateKey_RefusesWhenTheFileAppearsMidGeneration drives the same
// refusal deterministically. A dangling symlink at the key path reads as
// ErrNotExist — so the generate branch is entered — and then fails O_EXCL with
// EEXIST, which is exactly the shape of losing the race, without needing one.
//
// It also pins a second consequence #189 does not name: os.WriteFile FOLLOWS
// that symlink and writes the seed to wherever it points. O_EXCL refuses to, so
// the target is never created.
func TestLoadOrGenerateKey_RefusesWhenTheFileAppearsMidGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs Developer Mode or elevation; " +
			"the racing test above covers the same refusal on every platform")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.key")
	if err := os.Symlink(target, filepath.Join(dir, keyFileName)); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	key, err := LoadOrGenerateKey(dir)
	if err == nil {
		t.Fatal("a key file that appears between the read and the create must be REFUSED, " +
			"not written through and not silently re-read — the key in memory is not the key on disk")
	}
	if key != nil {
		t.Fatalf("a refusal must return no key, got %d bytes", len(key))
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, keyFileName)) {
		t.Fatalf("refusal does not name the path it refused: %v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatalf("the seed was written THROUGH the symlink to %s — a key must never land at a path "+
			"the caller did not name", target)
	}
}

// TestLoadOrGenerateKey_PersistsTheWholeSeedBeforeReturning is the flush half of
// #189, asserted at the level a test in this process can actually observe: when
// the call returns, path holds the complete 64-character seed of the key it
// handed back, not a prefix of it. fsync's own guarantee — that those bytes
// survive an unclean shutdown — is a kernel property no in-process test can
// witness; what this pins is that nothing returns before the write and Close
// have both completed, which is the precondition for the Sync to have meant
// anything.
func TestLoadOrGenerateKey_PersistsTheWholeSeedBeforeReturning(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if want := hex.EncodeToString(key.Seed()); string(b) != want {
		t.Fatalf("persisted seed is %q (%d bytes), want the returned key's seed %q (%d bytes)",
			b, len(b), want, len(want))
	}
	info, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key perm = %o, want 0600", perm)
	}
}
