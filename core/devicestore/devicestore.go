// Package devicestore holds a client's own half of the account service's
// two-tier entitlement chain (core/devicecred, ADR-0045, ADR-0046): the
// on-device keypair that never leaves the device, and the device credential,
// issuer cert and admission credential the account service issued for it.
//
// The third of those is under a different authority and answers a different
// gate (core/admission, ADR-0023) — it is here because the account service mints
// it in the SAME response over the SAME window as the other two, so keeping it
// anywhere else means two writes, two files and two expiries that have to be
// kept in step by care rather than by construction. bacchus#166 is what happens
// when they are not.
//
// It is deliberately not core/devicecred. That package verifies the chain — the
// coordinator's job — and its doc asks that nobody hold a second implementation
// of the framing it owns. This package never verifies a signature; it generates
// a key, and it stores and retrieves the opaque envelope strings devicecred
// already knows how to encode and decode. The one exception, Expiry, is called
// out explicitly below as exactly that: an exception, not a verifier.
package devicestore

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keyFileName is the on-device keypair's filename within a store directory.
const keyFileName = "device.key"

// LoadOrGenerateKey loads the on-device ed25519 keypair from dir, generating and
// persisting a fresh one the first time dir holds none.
//
// dir == "" is a deliberate opt-out: it generates an in-memory keypair and
// persists nothing, so every restart binds a new device identity. That is the
// right behavior for a test or an embedder that has its own storage story, and
// the wrong one for a real client — see the package doc on why this is a
// generate-once, not a cache.
//
// A MISSING file is generated fresh: mkdir -p the directory (0700), write the
// seed (0600), and return the new key. A PRESENT but corrupt or unreadable file
// is a hard error, never a silent regeneration — the whole reason this exists is
// that DevicePub is what the issued credential binds, so quietly minting a new
// key would silently strand whatever credential this device already holds,
// invisibly to the caller. See cmd/coordinator's loadOrGenerateBootstrapKey for
// the same shape applied to a different key.
func LoadOrGenerateKey(dir string) (ed25519.PrivateKey, error) {
	if dir == "" {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("devicestore: generate ephemeral device key: %w", err)
		}
		return priv, nil
	}

	path := filepath.Join(dir, keyFileName)
	b, err := os.ReadFile(path)
	if err == nil {
		seed, decErr := hex.DecodeString(strings.TrimSpace(string(b)))
		if decErr != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("devicestore: malformed device key at %s", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("devicestore: read device key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("devicestore: generate device key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("devicestore: create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, fmt.Errorf("devicestore: write device key %s: %w", path, err)
	}
	return priv, nil
}
