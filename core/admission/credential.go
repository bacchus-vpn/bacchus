package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Role is a network role a Credential authorizes its Subject to take. The
// values match the role strings already used on the coordinator wire
// (register's Role, the client's implicit role) so a credential check composes
// with the existing handlers without translation.
type Role string

const (
	RoleClient Role = "client"
	RoleRelay  Role = "relay"
	RoleExit   Role = "exit"
)

// AllRoles returns every role this build understands, in a fixed order. It is
// also what a single anchored authority is trusted for — NewVerifier, and the
// coordinator's -admission-pubkey, both mean "this one key, every role" (issue
// #64).
//
// ADDING A ROLE MEANS ADDING IT HERE. A role left out of this list is one that
// a single-key deployment silently stops admitting, and the omission would show
// up as an unexplained rejection rather than as a build failure.
//
// It returns a fresh slice each call so no caller can edit the canonical set out
// from under another.
func AllRoles() []Role { return []Role{RoleClient, RoleRelay, RoleExit} }

// Known reports whether r is a role this build understands. The coordinator's
// flag parser uses it to reject a typo at startup rather than anchoring an
// authority for a role string nothing will ever ask for — an authority scoped to
// "exists" would look configured and admit nothing.
func (r Role) Known() bool {
	for _, k := range AllRoles() {
		if r == k {
			return true
		}
	}
	return false
}

// CredentialVersion is the wire/format version of a Credential's signed body.
// Bump it on any breaking change to the field set; parse rejects anything else
// so an old coordinator never silently misreads a newer credential.
const CredentialVersion = 1

// serialLen sizes the random per-credential Serial (hex-encoded on the wire).
// The serial exists only to name a credential for revocation, so it needs to be
// unique, not secret.
const serialLen = 8

// Credential is a signed statement of network membership. The admission
// authority (the operator root key, ADR-0015) attests that Subject may act in
// Roles during [NotBefore, NotAfter]. It carries no secret: it is an
// authorization to present, not a key to protect, so a client credential is
// delivered out of band exactly like a coldstart invite (core/coldstart) and a
// node credential is baked into the node's config.
//
// JSON tags are short and fixed because the marshaled form is the signed body:
// two peers must produce byte-identical JSON for a signature to verify, and
// Go's encoding/json emits struct fields in declaration order, so the field
// order below is load-bearing — do not reorder without bumping CredentialVersion.
type Credential struct {
	Version   int       `json:"v"`
	Serial    string    `json:"serial"`         // hex, unique; names this credential for revocation
	Subject   string    `json:"sub"`            // node id (exit: its X25519 pubkey) or a client/user id
	Roles     []Role    `json:"roles"`          // roles this credential authorizes
	NotBefore time.Time `json:"nbf"`            // validity start (UTC)
	NotAfter  time.Time `json:"exp"`            // validity end (UTC)
	Note      string    `json:"note,omitempty"` // free-form operator label (e.g. who it was issued to); not security-relevant

	// Vouched marks a credential issued to an account a real person vouched for, the
	// signal issue #157's two-rating capacity decision turns on: only a vouched
	// attester may feed a node's TRUSTED capacity estimate (design §8.1.1). It is the
	// seam between capacity measurement (this public repo, which the coordinator reads)
	// and the account/vouch trust-graph (the private productization design, §5), which
	// the coordinator cannot import — so vouched-ness has to ride the credential the
	// coordinator already verifies. It is stamped by the account service, NOT by any
	// issuer in this repo: cmd/admission-issue never sets it, so in this build every
	// credential is unvouched and the trusted stream stays empty until the account
	// service issues vouched credentials. Additive and omitempty: a credential that
	// leaves it false is byte-identical to one from before #157, and an older verifier
	// that does not know the field ignores it and reads false — never a spurious vouch.
	Vouched bool `json:"vouched,omitempty"`
}

// IsVouched reports whether this credential was issued to a vouched account (issue
// #157). The coordinator uses it to route a capacity attestation to a node's trusted vs.
// untrusted estimate. See the Vouched field: nothing in this repo sets it, so it is
// always false here — the seam is defined, the account service will feed it.
func (c Credential) IsVouched() bool { return c.Vouched }

// Sentinel errors returned by Decode, parse, and a Verifier. Every one names
// only protocol/credential facts — never key material or a secret — so all are
// safe to log and safe to hand back to a rejected peer as a reason.
var (
	ErrMalformed          = errors.New("admission: malformed credential")
	ErrBadSignature       = errors.New("admission: credential signature invalid")
	ErrUnsupportedVersion = errors.New("admission: unsupported credential version")
	ErrNotYetValid        = errors.New("admission: credential not yet valid")
	ErrExpired            = errors.New("admission: credential expired")
	ErrRoleNotAuthorized  = errors.New("admission: credential does not authorize this role")
	ErrSubjectMismatch    = errors.New("admission: credential subject does not match node id")
	ErrRevoked            = errors.New("admission: credential revoked")
	ErrNoAuthorityForRole = errors.New("admission: no anchored authority admits this role")
)

// signedLen is the fixed ed25519 signature size; Sign appends exactly this many
// bytes and parse splits them off the end, matching core/coldstart's envelope.
const signedLen = ed25519.SignatureSize

// Sign encodes c as canonical JSON and appends an ed25519 signature over those
// bytes, producing the wire/disk form (pass to Encode for the string form).
// priv is the admission authority's private key.
func Sign(priv ed25519.PrivateKey, c Credential) ([]byte, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("admission: marshal credential: %w", err)
	}
	sig := ed25519.Sign(priv, body)
	return append(body, sig...), nil
}

// parse checks signed against pub and returns the decoded Credential. It
// verifies only the signature and the format version — the time window, role,
// subject, and revocation checks are policy and live in accept, so a caller
// that needs the raw fields (a debugging tool, an issuer re-reading its own
// output) can get them without imposing an admission decision.
func parse(pub ed25519.PublicKey, signed []byte) (Credential, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Credential{}, fmt.Errorf("%w: bad public key length", ErrMalformed)
	}
	if len(signed) <= signedLen {
		return Credential{}, ErrMalformed
	}
	body := signed[:len(signed)-signedLen]
	sig := signed[len(signed)-signedLen:]
	if !ed25519.Verify(pub, body, sig) {
		return Credential{}, ErrBadSignature
	}
	var c Credential
	if err := json.Unmarshal(body, &c); err != nil {
		return Credential{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if c.Version != CredentialVersion {
		return Credential{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, c.Version)
	}
	return c, nil
}

// credPrefix tags the string form so a credential is self-describing in a
// config file or an invite, distinct from a coldstart invite ("bacchus1:").
const credPrefix = "bacchusc1:"

// Encode packs a signed credential into a compact, copy-pasteable string for a
// config file or an out-of-band handoff. Decode reverses it.
func Encode(signed []byte) string {
	return credPrefix + base64.RawURLEncoding.EncodeToString(signed)
}

// Decode reverses Encode, returning the signed bytes for parse. It validates
// only the envelope (prefix + base64); the signature is checked by parse.
func Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, credPrefix) {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrMalformed, credPrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(s[len(credPrefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return b, nil
}

// Issue mints a fresh credential: it generates a random Serial, stamps the
// window in UTC, signs with the admission private key, and returns both the
// Credential (for the issuer to log/record) and its Encode-d string (to hand
// out). It is the operator-side half used by cmd/admission-issue, analogous to
// coldstart.GenerateSecret.
func Issue(priv ed25519.PrivateKey, subject string, roles []Role, notBefore, notAfter time.Time, note string) (Credential, string, error) {
	if len(roles) == 0 {
		return Credential{}, "", errors.New("admission: a credential must authorize at least one role")
	}
	serial, err := newSerial()
	if err != nil {
		return Credential{}, "", err
	}
	c := Credential{
		Version:   CredentialVersion,
		Serial:    serial,
		Subject:   subject,
		Roles:     roles,
		NotBefore: notBefore.UTC(),
		NotAfter:  notAfter.UTC(),
		Note:      note,
	}
	signed, err := Sign(priv, c)
	if err != nil {
		return Credential{}, "", err
	}
	return c, Encode(signed), nil
}

// newSerial returns a fresh random hex serial.
func newSerial() (string, error) {
	b := make([]byte, serialLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("admission: generate serial: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HasRole reports whether c authorizes want.
func (c Credential) HasRole(want Role) bool {
	for _, r := range c.Roles {
		if r == want {
			return true
		}
	}
	return false
}
