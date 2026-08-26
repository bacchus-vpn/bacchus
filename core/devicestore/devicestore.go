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

// CredFileName is the credential file's name within the SAME directory —
// what core.DeviceCredPath joins onto a DeviceCredDir, exported here so that
// there is one definition of it rather than two.
//
// It lives in this package rather than in core because LoadOrGenerateKey now
// reads it: a device key missing beside a surviving credential is not a cold
// start (issue #244), and a check keyed on a filename the other side is free to
// change independently would go inert the day it changed, silently, with every
// test still green. core.DeviceCredPath composes this constant, so the two
// cannot drift; TestDeviceCredPathIsEmptyForAnEmptyDir pins the composition.
const CredFileName = "credential.json"

// LoadOrGenerateKey loads the on-device ed25519 keypair from dir, generating and
// persisting a fresh one the first time dir holds none.
//
// dir == "" is a deliberate opt-out: it generates an in-memory keypair and
// persists nothing, so every restart binds a new device identity. That is the
// right behavior for a test or an embedder that has its own storage story, and
// the wrong one for a real client — see the package doc on why this is a
// generate-once, not a cache.
//
// A MISSING file is generated fresh ONLY when the directory holds no credential
// either: mkdir -p the directory (0700), create the file exclusively (0600),
// write the seed, flush it, and return the new key. A PRESENT but corrupt or
// unreadable file is a hard error, never a silent regeneration — the whole
// reason this exists is that DevicePub is what the issued credential binds, so
// quietly minting a new key would silently strand whatever credential this
// device already holds, invisibly to the caller. See cmd/coordinator's
// loadOrGenerateBootstrapKey for the same shape applied to a different key.
//
// A missing key beside a SURVIVING credential gets that same refusal, and issue
// #244 is why it took a second pass to get there. CredFileName lives in this
// directory too, so "no key file" and "no credential file" are two different
// facts and only the second of them means first run. Minting on the first alone
// produced the worst outcome this package can produce: a device that signs the
// coordinator's challenge with a key the credential it presents does not bind,
// refused on every connect for a reason that names nothing about the cause, and
// unable to re-enrol because the claim code that bought the credential is
// one-shot and clients/fyne has already erased it. Nothing logs anything at the
// moment it becomes true. The causes are ordinary — a partial restore from
// backup, an antivirus quarantine, a profile synced one file at a time, a user
// clearing half a directory, or #228's power loss — and the check is one Stat.
//
// Deleting device.key on purpose is a legitimate way to reset a device, and it
// is now refused, so the refusal has to say what to remove instead of merely
// reporting that a file is missing: that is ErrOrphanedCredential's message, and
// TestLoadOrGenerateKey_MissingKeyBesideACredentialNamesBothFiles pins it. The
// Stat is deliberately the same follow-symlinks read Open would do, so the
// question answered here is "would Open find a credential", not "is there an
// entry with that name".
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
// with no key file at all — and before #244 the branch above then treated that
// as a cold start and minted a second key, silently, after the first one's
// public half had already gone to the account service. ADR-0066 §5's rule puts
// this on the durable side without hesitation: a first-run create is the
// definition of a write nothing re-emits, and its polarity is worse than a
// replacing writer's, where a lost rename at least restores a complete older
// file. It cannot go through atomicfile.Write — O_EXCL on the real path is what
// stops two processes both believing they generated the key, and a
// stage-and-rename cannot express that — so atomicfile.SyncDir is called
// directly, which is why that function is exported.
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
// right after a first-run generation comes back with no key file, and the
// enrolment that bound the first one has already gone to the account service and
// spent a one-shot claim code that clients/fyne has already erased. Nothing here
// is a regression — it is the gap issue #215 closed on Linux and could not close
// there — and nothing about it is fixed by inventing a call, which is why this
// is a comment and not a syscall.
//
// The LAST step of that sequence is the one #244 took away, and its answer owes
// nothing to any platform: the credential this key would strand lives in the
// same directory, so a missing device.key beside a present CredFileName is not a
// cold start and this function refuses instead of minting. What that does NOT do
// is close #228 — a device whose key is durable is still a device whose key is
// durable, and this changes nothing about whether the entry survives. What it
// changes is the failure: the same power loss now stops at construction with a
// message naming both files, instead of proceeding into a lockout nothing
// reports. It also stops short of the case where BOTH entries are lost, which
// reads as a genuine cold start from every angle available here and still costs
// a claim code that is already gone. #238 is the run that measures whether that
// happens at all, and #228 stays open until it has.
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
	if err := refuseIfCredentialSurvives(dir, path); err != nil {
		return nil, err
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

// ErrOrphanedCredential is what LoadOrGenerateKey returns instead of minting a
// second key: the device key is gone and the credential that binds it is not.
//
// It is a sentinel rather than a bare string because the only way out of this
// state is an action a HUMAN takes on the two files, so a caller that wants to
// offer that action — a desktop client with a "reset this device" affordance, a
// provisioning script deciding between "retry" and "stop" — has to be able to
// recognize it without matching on prose. Nothing in this repository branches on
// it yet; the message below is written to be read by a person either way.
//
// Kept short because it is a PREFIX, not the message: callers stack their own
// ("device credential: …"), and the wrapped text below already states the whole
// situation. A sentinel that restated it would read as the same sentence twice
// before the operator reaches the part that says what to do.
var ErrOrphanedCredential = errors.New("devicestore: device key missing beside its credential")

// refuseIfCredentialSurvives answers the one question that separates a first run
// from a damaged device: does this directory already hold a credential?
//
// Called only on the missing-key path, and only for a real directory. A present
// credential means some earlier run of this device generated a key, enrolled it,
// and persisted the result — so the key is not absent, it is LOST, and issue
// #244 is everything that follows from confusing the two.
//
// A Stat that fails for any reason OTHER than "not there" is also a refusal.
// The question is whether generating here would strand a credential, and an
// unreadable directory entry does not answer it; guessing "no" is guessing in
// the direction whose failure is invisible and unrecoverable, which is the one
// direction this function exists to rule out.
func refuseIfCredentialSurvives(dir, keyPath string) error {
	credPath := filepath.Join(dir, CredFileName)
	_, err := os.Stat(credPath)
	switch {
	case err == nil:
		return fmt.Errorf("%w: %s is gone but %s is still here, so this is not a first run. "+
			"A new key would not match the credential on disk, every connect would be refused for a reason that names none of this, "+
			"and re-enrolling needs a claim code that has already been spent. "+
			"To recover, restore %s from wherever the credential came from. "+
			"To reset this device deliberately, delete BOTH %s and %s — an empty directory is a first run, and it will need an unspent claim code",
			ErrOrphanedCredential, keyPath, credPath, keyPath, keyPath, credPath)
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("devicestore: cannot tell whether %s holds a credential, so it is unknown whether generating a device key at %s would strand one: %w",
			credPath, keyPath, err)
	}
}
