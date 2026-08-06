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
//
// The write is atomic (issue #178), and unlike [MemStore.SaveFile] that is a
// judgement rather than a requirement, so the reasoning is worth having.
//
// A torn cache is genuinely recoverable: the bytes carry a signature, so a short
// file fails [Verify] and the caller falls through to a fresh [Bootstrap] — the
// LoadCache doc below already treats a corrupt cache as a normal condition. What
// makes it worth closing anyway is WHERE the fallback leads. This file is the
// offline-start path, and the thing it falls back to is a network fetch to a
// coordinator — which, for the users this protocol exists for, is exactly what
// may be unreachable at the moment the client launches. A client that owned a
// good snapshot and starts holding a truncated one is meaningfully worse off,
// and the fix is one call to a helper this package already has.
func SaveCache(path string, signed []byte) error {
	if err := writeFileAtomic(path, signed); err != nil {
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
