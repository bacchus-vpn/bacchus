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

	store, err := coldstart.LoadMemStore(*secretsPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("load %s: %v", *secretsPath, err)
		}
		store = coldstart.NewMemStore()
	}

	secretID, secret, err := coldstart.GenerateSecret()
	if err != nil {
		log.Fatalf("generate secret: %v", err)
	}
	store.Add(secretID, secret)
	if err := store.SaveFile(*secretsPath); err != nil {
		log.Fatalf("save %s: %v", *secretsPath, err)
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
