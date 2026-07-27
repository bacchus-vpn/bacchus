package coldstart

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.cache")
	want := []byte("opaque signed snapshot bytes")
	if err := SaveCache(path, want); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}
	got, err := LoadCache(path)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("LoadCache = %q, want %q", got, want)
	}
}

func TestLoadCacheMissingFile(t *testing.T) {
	if _, err := LoadCache(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("LoadCache on missing file: want error, got nil")
	}
}
