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

	"github.com/bacchus-vpn/bacchus/core/atomicfile"
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
// The DIRECTORY is flushed too, which is #215's half of the same argument. A
// file's own Sync makes the bytes durable and says nothing about the entry
// naming them, so a power loss right after a first-run generation can come back
// with no key file at all — and the branch above then treats that as a cold
// start and mints a second key, silently, after the first one's public half has
// already gone to the account service. ADR-0066 §5's rule puts this on the
// durable side without hesitation: a first-run create is the definition of a
// write nothing re-emits, and its polarity is worse than a replacing writer's,
// where a lost rename at least restores a complete older file. It cannot go
// through atomicfile.Write — O_EXCL on the real path is what stops two processes
// both believing they generated the key, and a stage-and-rename cannot express
// that — so atomicfile.SyncDir is called directly, which is why that function is
// exported.
//
// ON WINDOWS THAT CALL DOES NOTHING, and this is the client's connect path, so
// Windows is where it runs most (issue #228). What is established about it, and
// what is not, is worth stating here rather than one indirection away:
//
//   - The flush above is not a weaker version of what Linux does — it is the
//     only lever Windows documents. FlushFileBuffers, which is what Sync calls,
//     is documented to write the file's data AND metadata and to synchronize the
//     underlying storage's cache; the alternative Win32 names is opening the
//     file FILE_FLAG_WRITE_THROUGH, which is the same guarantee taken earlier.
//     There is no second, stronger call being skipped here.
//   - What Microsoft does not say is whether "the file's metadata" includes the
//     entry in the file's PARENT directory, which is the whole question: losing
//     that entry is what leaves no key file at all. Issue #238 is the power-loss
//     run that answers it, and #228 stays open until it does.
//
// So the create is durable on Linux, and on Windows it is durable to the extent
// that a documented file flush covers a directory entry, which is unestablished.
// The consequence if it does not is the reason the card exists: a power loss
// right after a first-run generation comes back with no key file, the branch
// above reads that as a cold start and mints a SECOND key, and the enrolment
// that bound the first one has already gone to the account service and spent a
// one-shot claim code that clients/fyne has already erased. Nothing here is a
// regression — it is the gap issue #215 closed on Linux and could not close
// there — and nothing about it is fixed by inventing a call, which is why this
// is a comment and not a syscall.
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
	// Reported rather than swallowed, and reported BEFORE the key is handed
	// back. The file is on disk either way, so the next call reads it and this
	// is a legible one-off failure rather than a lost key; what must not happen
	// is a caller told it holds a durable device identity, enrolling that
	// identity with the account service, and finding no key file after a power
	// loss.
	if err := atomicfile.SyncDir(dir); err != nil {
		return nil, fmt.Errorf("devicestore: flush the directory holding %s: %w", path, err)
	}
	return priv, nil
}
