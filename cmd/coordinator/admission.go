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
	"strings"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// admissionVerifier gates who may join the network (issue #42). Nil means
// admission is DISABLED — the coordinator serves anyone, the pre-#42 behavior,
// which main() warns about loudly at startup. Non-nil means every register
// (nodes) and every list/connect (clients) must carry a credential this
// verifier accepts, from an authority anchored for the role being taken (issue
// #64). It is set once in main before the read loop starts and is read-only
// thereafter, so handle() needs no extra lock for it; the revocation list it
// closes over is the only part that changes, and that is swapped atomically by
// reloadRevocationsLoop.
var admissionVerifier *admission.Verifier

// revocationsReload is how often the revoked-serials file is re-read, matching
// the bootstrap secrets reload cadence.
const revocationsReload = 30 * time.Second

// authorityFlags collects the repeatable -admission-authority flag (issue #64).
// Each occurrence is one role-scoped anchor, "role[,role...]:hexkey", and they
// accumulate in the order given.
type authorityFlags []string

func (f *authorityFlags) String() string { return strings.Join(*f, " ") }

func (f *authorityFlags) Set(v string) error { *f = append(*f, v); return nil }

// parseAuthority parses one -admission-authority value, "role[,role...]:hexkey"
// — e.g. "relay,exit:<operator hex>" or "client:<account service hex>".
//
// The roles come FIRST and the key last because the key contains no colon and
// the roles cannot, so splitting on the first colon is unambiguous however many
// roles are listed.
//
// Every malformed part is an error rather than a skipped anchor: this runs once
// at startup, where a fatal error is a line in the operator's terminal, and the
// alternative is a coordinator that came up looking configured while quietly
// trusting a different set of keys than the unit file names.
func parseAuthority(spec string) (admission.Authority, error) {
	roleList, keyHex, ok := strings.Cut(strings.TrimSpace(spec), ":")
	if !ok {
		return admission.Authority{}, fmt.Errorf("admission: bad -admission-authority %q: want role[,role...]:hexkey", spec)
	}
	var roles []admission.Role
	for _, name := range strings.Split(roleList, ",") {
		r := admission.Role(strings.TrimSpace(name))
		if !r.Known() {
			return admission.Authority{}, fmt.Errorf("admission: bad -admission-authority %q: unknown role %q (want %v)", spec, r, admission.AllRoles())
		}
		roles = append(roles, r)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return admission.Authority{}, fmt.Errorf("admission: bad -admission-authority %q: key must be %d hex-encoded bytes", spec, ed25519.PublicKeySize)
	}
	return admission.Authority{Pub: ed25519.PublicKey(pub), Roles: roles}, nil
}

// setupAdmission builds the admission verifier from the operator's configured
// anchors and starts the revocation-list reload loop. Admission is DISABLED —
// nil verifier, the caller warns — only when BOTH pubKeyHex and authoritySpecs
// are empty. A malformed anchor is a hard error: a coordinator told to enforce
// admission with an unusable key must not fall through to serving everyone.
//
// The two flags compose, and that is the migration path (issue #64). pubKeyHex
// is -admission-pubkey and keeps exactly the meaning it had: ONE authority,
// EVERY role. An operator who changes nothing therefore sees no behaviour
// change. Splitting the account service off is then additive — keep
// -admission-pubkey on the operator key and add
// "-admission-authority client:<account key>" — and narrowing the operator key
// afterwards is dropping -admission-pubkey for
// "-admission-authority relay,exit:<operator key>".
//
// Anchors are flags and not a file, unlike the revocation list next to them,
// because they change only across a restart: nothing here is reloaded, and
// nothing should be. The revocation list is a file precisely because an
// operator must be able to kill a leaked credential in seconds without a
// restart; a trust anchor hot-reloaded from disk would mean a bad write could
// silently widen who may join the network, which is the one direction this
// package exists to prevent. Keeping anchors in the unit file also keeps them
// reviewable in the same place as -device-root-pubkey and -policy-root-pubkey.
//
// The anchored set is returned alongside the verifier purely so main can log
// what it anchored (describeAuthorities), matching setupDeviceCred's shape; the
// verifier keeps its own copy and does not read this one again.
func setupAdmission(ctx context.Context, pubKeyHex string, authoritySpecs []string, revocationsPath string) (*admission.Verifier, []admission.Authority, error) {
	var authorities []admission.Authority
	if pubKeyHex != "" {
		pub, err := hex.DecodeString(pubKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("admission: bad -admission-pubkey: want %d hex-encoded bytes", ed25519.PublicKeySize)
		}
		authorities = append(authorities, admission.Authority{Pub: ed25519.PublicKey(pub), Roles: admission.AllRoles()})
	}
	for _, spec := range authoritySpecs {
		a, err := parseAuthority(spec)
		if err != nil {
			return nil, nil, err
		}
		authorities = append(authorities, a)
	}
	if len(authorities) == 0 {
		return nil, nil, nil
	}

	revocations := new(atomic.Pointer[admission.RevocationList])
	revocations.Store(admission.NewRevocationList())
	// Construct before starting the reload loop, so a rejected anchor set
	// returns an error without having left a goroutine behind polling a file
	// for a coordinator that is about to log.Fatal.
	v, err := admission.NewAuthoritySetVerifier(authorities, func(serial string) bool {
		return revocations.Load().Revoked(serial)
	})
	if err != nil {
		return nil, nil, err
	}
	go reloadRevocationsLoop(ctx, revocationsPath, revocations)
	return v, authorities, nil
}

// describeAuthorities renders the anchored set for the startup log, as
// "role,role=<first 8 hex of key>" per authority. It logs a key PREFIX and not
// the key: an admission public key is not a secret, but a log line an operator
// pastes into an issue should carry enough to tell two anchors apart and no
// more. Roles are listed because a wrong scope is the misconfiguration this
// flag makes newly possible, and it is invisible in every other log line.
//
// It runs on the set setupAdmission already built a verifier from, so every key
// here is a validated ed25519 public key and the prefix slice is safe.
func describeAuthorities(authorities []admission.Authority) string {
	out := make([]string, 0, len(authorities))
	for _, a := range authorities {
		roles := make([]string, 0, len(a.Roles))
		for _, r := range a.Roles {
			roles = append(roles, string(r))
		}
		out = append(out, fmt.Sprintf("%s=%s…", strings.Join(roles, ","), hex.EncodeToString(a.Pub)[:8]))
	}
	return strings.Join(out, " ")
}

// admit reports whether a credential-bearing message m may proceed, and returns
// the credential it verified. When admission is disabled (nil verifier)
// everything is admitted, preserving the pre-#42 open behavior. Otherwise it
// verifies m.Cred for the given role and subject binding (subject "" for
// clients, the node id for nodes); on rejection it replies to src with a reject
// naming the reason — admission errors carry only protocol facts, never a
// secret, so they are safe to send and log — and returns false, on which the
// caller stops handling m (nothing is registered, listed, or paired).
//
// The returned Credential is the VERIFIED one, and it is meaningful only when ok
// is true. On the disabled path it is the zero value, which is not a credential
// that said nothing — it is the absence of one, and a caller reading standing off
// it must distinguish the two by checking admissionVerifier itself. resolveTier
// (tier.go) is the caller that does, and its case 3 says why the difference
// matters.
//
// It returns the credential rather than being called twice because standing now
// rides it: issue #58's (trust, plan) pair indexes the signed policy's tiers
// table, and re-verifying to read a field the gate above already parsed would
// spend a second ed25519 verification per connect on the hot path and, worse,
// leave two call sites that could disagree about which credential they read.
func admit(m wire, src *net.UDPAddr, want admission.Role, subject string) (admission.Credential, bool) {
	if admissionVerifier == nil {
		return admission.Credential{}, true
	}
	cred, err := admissionVerifier.Verify(m.Cred, time.Now(), want, subject)
	if err != nil {
		log.Printf("admission: reject %s from %s: %v", want, src, err)
		send(src, wire{Type: "reject", Reason: err.Error()})
		return admission.Credential{}, false
	}
	return cred, true
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
