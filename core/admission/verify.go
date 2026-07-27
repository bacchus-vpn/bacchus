package admission

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// ClockSkew is the tolerance applied to a credential's NotBefore so a node
// whose clock runs slightly ahead of the coordinator's isn't rejected the
// instant it is issued. It is intentionally applied only to the lower bound:
// being lenient about when a credential *starts* is harmless, but being lenient
// about when it *expires* would extend a revoked/rotated credential's life, so
// NotAfter is checked strictly. Two minutes matches the order of magnitude of
// unsynchronized consumer clocks without meaningfully widening the window.
const ClockSkew = 2 * time.Minute

// Verifier holds the admission authority's public key and a revocation oracle,
// and turns an encoded credential from the wire into an accept/reject decision.
// It is safe for concurrent use as long as the revoked func is (a
// *RevocationList swapped via atomic.Pointer, as the coordinator does, is).
type Verifier struct {
	pub     ed25519.PublicKey
	revoked func(serial string) bool
}

// NewVerifier builds a Verifier for the given admission public key. revoked
// reports whether a serial has been revoked; pass nil when there is no
// revocation list (nothing is revoked). The coordinator passes a closure over
// its hot-reloaded RevocationList.
func NewVerifier(pub ed25519.PublicKey, revoked func(serial string) bool) *Verifier {
	if revoked == nil {
		revoked = func(string) bool { return false }
	}
	return &Verifier{pub: pub, revoked: revoked}
}

// Verify decodes and checks an encoded wire credential and returns the
// validated Credential, or an error naming why it failed (safe to log/return).
// want is the role the peer is trying to take right now (RoleClient for a
// list/connect, the registering role for a node). subject is the identity the
// credential must be bound to — the node id on a register — or "" to skip the
// binding check, which is how a client credential (bearer, no coordinator-known
// id) is verified. now is passed in rather than read here so tests use a fixed
// clock and the caller controls the time source.
func (v *Verifier) Verify(encoded string, now time.Time, want Role, subject string) (Credential, error) {
	signed, err := Decode(encoded)
	if err != nil {
		return Credential{}, err
	}
	c, err := parse(v.pub, signed)
	if err != nil {
		return Credential{}, err
	}
	if err := accept(c, now, want, subject, v.revoked); err != nil {
		return Credential{}, err
	}
	return c, nil
}

// accept applies the admission policy to an already signature-verified
// Credential and returns nil to admit or a sentinel error to reject. Everything
// cryptographic is done by the time we get here — parse has verified the
// ed25519 signature over c and confirmed the format version — so this is pure
// policy over trusted fields.
//
// The checks run revocation-first: an explicitly revoked credential is the
// freshest, most decisive operator signal, so it is rejected before the static
// window/role/subject checks and surfaces ErrRevoked even when the credential
// has also expired (the operator killed it — that is the more actionable
// reason). The validity window then applies ClockSkew tolerance to the lower
// bound only and is strict on expiry (see ClockSkew's doc for why the
// asymmetry). Finally the role must be authorized, and a node credential
// (subject != "") must be bound to the id presenting it; a client credential
// (subject == "") is bearer and skips the binding check.
func accept(c Credential, now time.Time, want Role, subject string, revoked func(serial string) bool) error {
	if revoked(c.Serial) {
		return ErrRevoked
	}
	if now.Before(c.NotBefore.Add(-ClockSkew)) {
		return ErrNotYetValid
	}
	if !now.Before(c.NotAfter) {
		return ErrExpired
	}
	if !c.HasRole(want) {
		return ErrRoleNotAuthorized
	}
	if subject != "" && subject != c.Subject {
		return ErrSubjectMismatch
	}
	return nil
}

// RevocationList is a set of revoked credential serials. The coordinator loads
// it from disk and hot-reloads it (like the bootstrap secrets file) so an
// operator can revoke a leaked or rotated credential without a restart. The
// zero value is not usable; construct with NewRevocationList or
// LoadRevocationList.
type RevocationList struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// revocationFile is the on-disk JSON shape: a version tag and a flat list of
// revoked serials. A plain list keeps it hand-editable by an operator in a
// pinch.
type revocationFile struct {
	Version int      `json:"version"`
	Revoked []string `json:"revoked"`
}

const revocationFileVersion = 1

// NewRevocationList returns an empty list (nothing revoked).
func NewRevocationList() *RevocationList {
	return &RevocationList{set: map[string]struct{}{}}
}

// LoadRevocationList reads and parses the revocation file at path. A missing
// file is reported as os.ErrNotExist (wrapped) so the caller can decide whether
// that means "nothing revoked yet" or a hard failure — a security-relevant
// choice the coordinator makes explicitly rather than this package guessing.
func LoadRevocationList(path string) (*RevocationList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("admission: read revocation list %s: %w", path, err)
	}
	var f revocationFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("admission: parse revocation list %s: %w", path, err)
	}
	if f.Version != revocationFileVersion {
		return nil, fmt.Errorf("admission: revocation list %s: unsupported version %d", path, f.Version)
	}
	rl := NewRevocationList()
	for _, s := range f.Revoked {
		rl.set[s] = struct{}{}
	}
	return rl, nil
}

// Revoked reports whether serial is in the list.
func (r *RevocationList) Revoked(serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.set[serial]
	return ok
}

// Revoke adds serial to the list (used by the issuer tool).
func (r *RevocationList) Revoke(serial string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.set[serial] = struct{}{}
}

// Serials returns every revoked serial, sorted for a stable, diff-friendly
// order (used by SaveFile and by cmd/admission-issue -crl to sign the current
// set as a distributable CRL, issue #69).
func (r *RevocationList) Serials() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	serials := make([]string, 0, len(r.set))
	for s := range r.set {
		serials = append(serials, s)
	}
	sort.Strings(serials)
	return serials
}

// SaveFile writes the list to path as the revocationFile JSON shape, creating
// or truncating it. Serials are written in a stable sorted order so the file is
// diff-friendly across issuer runs.
func (r *RevocationList) SaveFile(path string) error {
	serials := r.Serials()
	b, err := json.MarshalIndent(revocationFile{Version: revocationFileVersion, Revoked: serials}, "", "  ")
	if err != nil {
		return fmt.Errorf("admission: marshal revocation list: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("admission: write revocation list %s: %w", path, err)
	}
	return nil
}
