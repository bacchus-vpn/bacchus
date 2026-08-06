// coldstart-issue is the operator-side half of the cold-start bootstrap
// (issue #18): it mints a fresh per-user secret, appends it to the
// coordinator's secrets file (hot-reloaded by cmd/coordinator, no restart
// needed), and prints a copy-pasteable invite string carrying that secret —
// the "signed invite bundle" of docs/design/rendezvous-cold-start.md §4.2.2,
// minus signing (see that doc and the package doc for why the invite itself
// doesn't need a signature).
//
// The invite is handed to the new user out of band (mainstream messenger,
// QR code in person) — never through a channel the app itself controls,
// since that channel is exactly what a censor can also read.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

func main() {
	secretsPath := flag.String("secrets", "secrets/bootstrap-secrets.json", "coordinator's bootstrap secrets file (created if missing)")
	coordinator := flag.String("coordinator", "", "coordinator bootstrap host:port the recipient should dial (required)")
	pubKeyHex := flag.String("pubkey", "", "coordinator's bootstrap public key, hex (required; logged by cmd/coordinator on first run)")
	admissionPubKeyHex := flag.String("admission-pubkey", "", "optional: the admission authority's public key, hex (issue #60). When set it is embedded in the invite so the recipient verifies exits against it end-to-end (a v2 invite); when empty a v1 invite is minted and the recipient must obtain the anchor another way")
	admissionCRLPath := flag.String("admission-crl", "", "optional: path to a signed revocation bundle from cmd/admission-issue -crl (issue #69). Requires -admission-pubkey; embeds it in the invite (a v3 invite) so the recipient rejects a revoked exit with no extra setup")
	flag.Parse()

	if *coordinator == "" || *pubKeyHex == "" {
		fmt.Fprintln(os.Stderr, "usage: coldstart-issue -coordinator HOST:PORT -pubkey HEX [-admission-pubkey HEX] [-admission-crl path] [-secrets path]")
		os.Exit(2)
	}
	pub, err := hex.DecodeString(*pubKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		log.Fatalf("bad -pubkey: expected %d hex-encoded bytes", ed25519.PublicKeySize)
	}
	// The admission anchor (issue #60) is optional; when supplied it must be a
	// well-formed ed25519 public key so a typo fails here rather than shipping an
	// invite the recipient can't verify against.
	var admissionKey ed25519.PublicKey
	if *admissionPubKeyHex != "" {
		ak, err := hex.DecodeString(*admissionPubKeyHex)
		if err != nil || len(ak) != ed25519.PublicKeySize {
			log.Fatalf("bad -admission-pubkey: expected %d hex-encoded bytes", ed25519.PublicKeySize)
		}
		admissionKey = ed25519.PublicKey(ak)
	}
	// The revocation bundle (issue #69) rides alongside the anchor and is
	// unverifiable without it.
	if *admissionCRLPath != "" && admissionKey == nil {
		log.Fatal("-admission-crl requires -admission-pubkey")
	}
	var crl []byte
	if *admissionCRLPath != "" {
		b, err := os.ReadFile(*admissionCRLPath)
		if err != nil {
			log.Fatalf("read -admission-crl %s: %v", *admissionCRLPath, err)
		}
		encoded := strings.TrimSpace(string(b))
		// Sanity-check now, against the anchor we're about to embed, so a bad
		// signature/format fails here rather than shipping an invite the
		// recipient can't verify (mirrors the -admission-pubkey shape check) —
		// and check expiry too (VerifyCRL, not just ParseCRL), so an operator
		// who fat-fingers a stale bundle path finds out at mint time, not by
		// puzzling over a client that silently never enforced revocation
		// (issue #90: an expired CRL is a construction error on the client
		// exactly as it is here).
		if _, err := admission.VerifyCRL(admissionKey, encoded, time.Now()); err != nil {
			log.Fatalf("bad -admission-crl %s: %v", *admissionCRLPath, err)
		}
		crl = []byte(encoded)
	}

	secretID, secret, err := coldstart.GenerateSecret()
	if err != nil {
		log.Fatalf("generate secret: %v", err)
	}
	if err := addSecret(*secretsPath, secretID, secret); err != nil {
		log.Fatal(err)
	}

	invite, err := coldstart.EncodeInvite(coldstart.Invite{
		Coordinator:  *coordinator,
		SecretID:     secretID,
		Secret:       secret,
		PublicKey:    ed25519.PublicKey(pub),
		AdmissionKey: admissionKey,
		CRL:          crl,
	})
	if err != nil {
		log.Fatalf("encode invite: %v", err)
	}

	anchor := "no admission anchor (v1 invite)"
	if admissionKey != nil {
		anchor = "admission anchor embedded (v2 invite)"
	}
	if crl != nil {
		anchor = "admission anchor + revocation bundle embedded (v3 invite)"
	}
	fmt.Fprintf(os.Stderr, "issued secret id %s, appended to %s; %s\n", secretID, *secretsPath, anchor)
	fmt.Println(invite)
}

// addSecret adds one freshly minted secret to the secrets file at path, creating
// the file if this is the first mint against it.
//
// This is READ-MODIFY-WRITE over the whole store — load every secret already
// issued, add one, write all of them back — and issue #178 is about both halves
// of what that needs. They are not the same half and neither covers the other.
//
// [coldstart.MemStore.SaveFile]'s atomic install is the first: whatever this
// leaves on disk is a WHOLE file, so a mint killed part-way through cannot
// destroy every secret ever issued.
//
// The lock is the second, and atomicity does nothing for it. Two issuers running
// at once both load the same store, each adds its own secret, and each writes
// back a complete, well-formed file — the second landing without the first's
// entry. Nothing about that file is torn, so nothing anywhere notices. The
// loser's invite has already been printed by then and is on its way to somebody
// for whom it will simply never work, indistinguishable at the coordinator from
// an attacker guessing.
//
// The generated secret is passed in rather than minted here so that the locked
// region holds only the file work: nothing that can block on entropy runs while
// another operator is waiting.
func addSecret(path, secretID string, secret []byte) error {
	release, err := lockSecrets(path)
	if err != nil {
		return err
	}
	defer release()

	store, err := coldstart.LoadMemStore(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load %s: %w", path, err)
		}
		store = coldstart.NewMemStore()
	}
	store.Add(secretID, secret)
	if err := store.SaveFile(path); err != nil {
		return fmt.Errorf("save %s: %w", path, err)
	}
	return nil
}

// errLockHeld is what [addSecret] returns when another issuer is mid-mint. Its
// own error rather than a string so a caller — today only this package's tests —
// can tell "somebody else is writing" apart from "the write failed".
var errLockHeld = errors.New("another coldstart-issue is writing the secrets file")

// lockSecrets takes an exclusive lock covering one read-modify-write of the
// secrets file, and returns the function that drops it.
//
// O_EXCL on a sidecar file rather than flock(2), and the reason is portability:
// this tool builds for every platform this repository builds for, flock has no
// portable form, and O_CREATE|O_EXCL is one atomic create everywhere.
//
// What that choice costs is worth stating rather than discovering. The kernel
// does not release this lock when the process holding it dies, so an issuer
// killed mid-mint — or interrupted at the terminal, which does not run deferred
// functions — leaves the file behind and the next run refuses until somebody
// removes it. The refusal says exactly that and names the file. The trade is
// deliberate: a lock that fails closed and tells you how to clear it is a much
// better failure than a silently lost invite, which is the thing it is standing
// in front of and which nobody can detect at all.
//
// The lock lives beside the secrets file rather than in a temp directory so that
// it is scoped to the file being mutated — an operator maintaining two
// coordinators from one machine is minting into two different files and should
// not be serialised across them.
func lockSecrets(path string) (release func(), err error) {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf(`%w (%s exists)

Two issuers that load, add and save at the same time each write a complete file,
and the second lands without the first one's secret. The lost invite has already
been printed and would simply never work for whoever received it, so this refuses
rather than races.

If no other coldstart-issue is running, this lock was left by one that was
killed: remove %s and run again.`, errLockHeld, lockPath, lockPath)
	}
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", lockPath, err)
	}
	return func() {
		_ = f.Close()
		_ = os.Remove(lockPath)
	}, nil
}
