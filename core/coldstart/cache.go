package coldstart

import (
	"fmt"
	"os"
)

// SaveCache writes a signed snapshot (as produced by [Sign] or returned by
// [Bootstrap]) to path, so a client that has bootstrapped once can start
// from a cached snapshot on its next launch instead of re-authenticating
// cold (design doc §4.2.3, first-launch parse-and-refresh). The file is
// opaque signed bytes; callers still need the coordinator's public key to
// use it, same as any freshly fetched snapshot.
func SaveCache(path string, signed []byte) error {
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		return fmt.Errorf("coldstart: save cache: %w", err)
	}
	return nil
}

// LoadCache reads back a snapshot saved by [SaveCache]. The caller must
// still verify it with [Verify] before trusting it — a stale or expired
// cache is a normal condition (fall through to a fresh [Bootstrap]), not a
// corruption.
func LoadCache(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("coldstart: load cache: %w", err)
	}
	return b, nil
}
