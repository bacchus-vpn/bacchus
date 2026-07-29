package devicestore

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
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
