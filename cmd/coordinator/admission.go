package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// admissionVerifier gates who may join the network (issue #42). Nil means
// admission is DISABLED — the coordinator serves anyone, the pre-#42 behavior,
// which main() warns about loudly at startup. Non-nil means every register
// (nodes) and every list/connect (clients) must carry a credential this
// verifier accepts. It is set once in main before the read loop starts and is
// read-only thereafter, so handle() needs no extra lock for it; the revocation
// list it closes over is the only part that changes, and that is swapped
// atomically by reloadRevocationsLoop.
var admissionVerifier *admission.Verifier

// revocationsReload is how often the revoked-serials file is re-read, matching
// the bootstrap secrets reload cadence.
const revocationsReload = 30 * time.Second

// setupAdmission builds the admission verifier from the operator's configured
// public key and starts the revocation-list reload loop. An empty pubKeyHex
// disables admission and returns a nil verifier (the caller warns). A malformed
// key is a hard error — a coordinator told to enforce admission with an
// unusable key must not fall through to serving everyone.
func setupAdmission(ctx context.Context, pubKeyHex, revocationsPath string) (*admission.Verifier, error) {
	if pubKeyHex == "" {
		return nil, nil
	}
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("admission: bad -admission-pubkey: want %d hex-encoded bytes", ed25519.PublicKeySize)
	}

	var revocations atomic.Pointer[admission.RevocationList]
	revocations.Store(admission.NewRevocationList())
	go reloadRevocationsLoop(ctx, revocationsPath, &revocations)

	return admission.NewVerifier(ed25519.PublicKey(pub), func(serial string) bool {
		return revocations.Load().Revoked(serial)
	}), nil
}

// admit reports whether a credential-bearing message m may proceed. When
// admission is disabled (nil verifier) everything is admitted, preserving the
// pre-#42 open behavior. Otherwise it verifies m.Cred for the given role and
// subject binding (subject "" for clients, the node id for nodes); on rejection
// it replies to src with a reject naming the reason — admission errors carry
// only protocol facts, never a secret, so they are safe to send and log — and
// returns false, on which the caller stops handling m (nothing is registered,
// listed, or paired).
func admit(m wire, src *net.UDPAddr, want admission.Role, subject string) bool {
	if admissionVerifier == nil {
		return true
	}
	if _, err := admissionVerifier.Verify(m.Cred, time.Now(), want, subject); err != nil {
		log.Printf("admission: reject %s from %s: %v", want, src, err)
		send(src, wire{Type: "reject", Reason: err.Error()})
		return false
	}
	return true
}

// reloadRevocationsLoop (re)loads the revocation file into a fresh
// RevocationList and swaps it in atomically, so an operator can revoke a leaked
// or rotated credential without restarting the coordinator. A missing file is
// not an error — it just means nothing is revoked yet — but any other
// read/parse failure is logged and the previous list is kept (fail-safe: a
// malformed file must not silently un-revoke everyone). An empty path disables
// revocation entirely.
func reloadRevocationsLoop(ctx context.Context, path string, current *atomic.Pointer[admission.RevocationList]) {
	if path == "" {
		return
	}
	load := func() {
		rl, err := admission.LoadRevocationList(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("admission: reload revocations from %s: %v", path, err)
			}
			return
		}
		current.Store(rl)
	}
	load()
	t := time.NewTicker(revocationsReload)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			load()
		}
	}
}
