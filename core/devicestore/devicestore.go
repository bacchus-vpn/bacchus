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
// A MISSING file is generated fresh: mkdir -p the directory (0700), create the
// file exclusively (0600), write the seed, flush it, and return the new key. A
// PRESENT but corrupt or unreadable file is a hard error, never a silent
// regeneration — the whole reason this exists is that DevicePub is what the
// issued credential binds, so quietly minting a new key would silently strand
// whatever credential this device already holds, invisibly to the caller. See
// cmd/coordinator's loadOrGenerateBootstrapKey for the same shape applied to a
// different key.
//
// The create is O_EXCL and the flush is not optional; bacchus#189 is both. The
// read above and the write below are a TOCTOU, so two processes that both see no
// file both generate — and an O_CREATE without O_EXCL lets the loser overwrite
// the winner's key with no error at all, reaching the silent-regeneration
// outcome the paragraph above forbids through a door it does not look at. EEXIST
// therefore REFUSES rather than re-reading: the key this call holds in memory is
// not the key now on disk, and a caller handed a key that does not match the
// file would enrol under one identity and reload under another. The flush is
// because the public half of this key leaves the machine almost immediately —
// the account service records DevicePub at enrolment — so an unclean shutdown in
// the several seconds os.WriteFile leaves the bytes unsynced strands a
// credential bound to a key the device no longer has.
//
// A write that fails partway leaves a SHORT file on purpose. It is caught loudly
// on the next read by the malformed-key check above, which is fail-closed;
// removing it would hand the next run a missing file and a silent fresh key,
// which is the failure this function exists to refuse.
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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("devicestore: device key %s was created by another process while this one was generating: "+
				"refusing, because the key this call holds is not the key on disk", path)
		}
		return nil, fmt.Errorf("devicestore: create device key %s: %w", path, err)
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return nil, fmt.Errorf("devicestore: write device key %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("devicestore: flush device key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("devicestore: close device key %s: %w", path, err)
	}
	return priv, nil
}
