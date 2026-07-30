// Package delegation verifies the offline root's leaf delegations to its
// operational signing keys — the `bacchus/delegation/v1` object.
//
// # Why this package exists separately
//
// One offline root signs in several contexts. It delegates "may sign network
// policy" to a policy signer that a coordinator verifies, "may sign forced-update
// manifests" to an update signer that a client verifies, and in time other roles
// besides. All of those delegations are the SAME object with the same shape and
// the same root signature; they differ only by the `role` string inside the
// signed body.
//
// That makes the role check load-bearing rather than cosmetic, and it makes this
// a general verifier rather than one owned by whichever consumer landed first.
// A policy-private copy would have to be written a second time the moment a
// client needs the update role, and a second copy of a signature check is exactly
// the kind of thing that drifts silently: both copies keep verifying, and only one
// of them keeps checking the role.
//
// # What is verified, and against what
//
// A verifier holds only the root PUBLIC key. It never contacts whoever minted the
// cert — that is the property the offline root buys, not an optimisation. The
// private half of this format (the ceremony that signs these certs) lives outside
// this repository and cannot be imported here, so the wire format is the contract
// and the frozen conformance fixtures are what keep the two implementations
// agreeing.
//
// # Framing
//
// Every signed object here is body || sig, where sig covers tag || 0x00 || body
// rather than body alone. The tag is ASCII and contains no 0x00, so the framing
// is unambiguous and a signature produced in one context can never be replayed in
// another. The tag registry is in this one file deliberately: domain separation is
// a property of the SET of tags, and it is only auditable while every tag this
// repository verifies is visible together. A signed object whose SCHEMA lives in
// another package still registers its tag here — core/policy's document does, and
// so do both tiers of core/devicecred's device chain.
//
// The body travels verbatim and is verified as received. Nothing here ever
// re-marshals a body to check it, so JSON field order, whitespace and escaping are
// deliberately not part of the contract.
package delegation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the format version of the signed bodies in this package. It is
// checked EXACTLY, not as a minimum: a verifier that does not know a format
// refuses it rather than reading the subset it recognises, so an old coordinator
// never silently misreads a newer cert.
const Version = 1

// Domain-separation tags. Every signature covers tag || 0x00 || body and every
// verifier accepts exactly one tag, so a signature made in one context cannot be
// replayed in another.
//
// These are namespaced "bacchus/" rather than after whichever service mints them:
// they are network objects this repository verifies, and the minting service
// merely happens to produce them.
//
// A tag is registered here even when another package owns the SCHEMA of the object
// it names. The split is deliberate — this package signs and opens the BYTES, the
// owning package decides what the bytes mean — and it keeps a second implementation
// of tag || 0x00 || body from existing:
//
//   - TagPolicyDoc: core/policy owns the document.
//   - TagIssuerCert and TagDeviceCred: core/devicecred owns both tiers of the
//     account service's device chain (ADR-0045). They were declared in that package
//     when it landed and moved here by #54, which is the precedent worth naming —
//     a new verifier registers its tag here rather than beside its own schema, or
//     this file stops being the one place the whole set can be read.
//
// The values are wire contract, not naming preference: each matches its signer's
// byte for byte, and the frozen conformance vectors fail loudly if any drifts.
const (
	TagDelegationCert = "bacchus/delegation/v1"
	TagPolicyDoc      = "bacchus/policy/v1"
	TagIssuerCert     = "bacchus/issuer-cert/v1"
	TagDeviceCred     = "bacchus/device-cred/v1"
)

// ClockSkew is the tolerance applied to a NotBefore so a verifier whose clock
// runs slightly behind the signer's does not reject a cert the instant it is
// minted.
//
// It is applied to the LOWER bound only. Being lenient about when something
// starts is harmless; being lenient about when it expires would extend a revoked
// or rotated delegation past the point an operator believes it is dead. Two
// minutes matches the order of magnitude of unsynchronized clocks without
// meaningfully widening the window, and matches admission.ClockSkew — the two
// objects travel the same network between the same parties, and a verifier
// lenient about one and strict about the other would be a difference nobody
// could explain.
const ClockSkew = 2 * time.Minute

// Role names the operational key a delegation cert authorizes. It is part of the
// signed body and is checked EXACTLY at verification — VerifyDelegationCert takes
// the role it expects — so a delegation cut for one role is cryptographically
// useless as another.
//
// This is the whole reason the role is not a hint. The roles differ by nothing but
// these bytes: same root signature, same shape, same window. A verifier that read
// the role without enforcing it would accept an update-signer cert as a policy
// signer, and there would be no signature failure anywhere to notice.
//
// Adding a role is a deliberate act in both implementations — mint the value, add
// it here, and land the verifier that consumes it. A role is never inferred from
// context.
type Role string

const (
	// RolePolicy delegates "may sign signed-policy blobs", verified offline by a
	// coordinator (core/policy).
	RolePolicy Role = "policy"
	// RoleUpdate delegates "may sign forced-update manifests", verified offline by
	// a client. Registered here because this verifier is general: the update path
	// consumes the same object against the same root, and building it inside the
	// policy consumer would mean porting this twice.
	RoleUpdate Role = "update"
)

// Known reports whether r is a role this build recognises. It is not consulted by
// VerifyDelegationCert, which compares against the single role its caller asked
// for — an unknown role in a cert therefore fails there anyway. It exists for
// operator tooling that wants to describe a cert rather than admit it.
func (r Role) Known() bool {
	switch r {
	case RolePolicy, RoleUpdate:
		return true
	default:
		return false
	}
}

// Cert is a leaf delegation from the offline root to an operational signing key
// for one Role. It caps nothing below it: the delegation WINDOW is the
// medium-lived bound the root controls, and whatever the delegated key goes on to
// sign carries its own validity.
//
// The marshaled form is the signed body, and verification is always over the
// bytes as received, so this struct may be reordered freely. What IS the contract:
// the json tag names below, the domain tag, the Role string values, and Version.
// Renaming a json tag does not break a signature — it silently changes which field
// a peer reads, and a field the peer cannot find arrives as a zero value.
type Cert struct {
	Version   int       `json:"v"`
	Serial    string    `json:"serial"`         // hex, unique; names this cert for revocation
	Role      Role      `json:"role"`           // checked exactly at verify
	Pub       []byte    `json:"pub"`            // ed25519 pubkey being delegated to
	NotBefore time.Time `json:"nbf"`            // validity start (UTC)
	NotAfter  time.Time `json:"exp"`            // validity end (UTC)
	Note      string    `json:"note,omitempty"` // operator label; never load-bearing
}

// Sentinel errors. Every one names a protocol fact only — never key material,
// never anything operator- or account-scoped — so all are safe to log and safe to
// report back to whoever supplied the object.
var (
	ErrMalformed          = errors.New("delegation: malformed object")
	ErrUnsupportedVersion = errors.New("delegation: unsupported version")
	ErrBadSignature       = errors.New("delegation: signature invalid")
	ErrNotYetValid        = errors.New("delegation: not yet valid")
	ErrExpired            = errors.New("delegation: expired")
	ErrRevoked            = errors.New("delegation: revoked")
	ErrWrongRole          = errors.New("delegation: role mismatch")
	ErrNoRoot             = errors.New("delegation: no root public key configured")
)

// sigLen is the fixed ed25519 signature size, split off the end of a signed
// object.
const sigLen = ed25519.SignatureSize

// signingMessage builds the domain-separated bytes a signature actually covers.
// The 0x00 separator cannot occur in a tag, so no body can be crafted to make one
// tag's message equal another's.
func signingMessage(tag string, body []byte) []byte {
	msg := make([]byte, 0, len(tag)+1+len(body))
	msg = append(msg, tag...)
	msg = append(msg, 0x00)
	return append(msg, body...)
}

// OpenSigned splits body || sig, checks the signature against pub under tag, and
// returns the body bytes it covers. It is the one implementation of this framing
// in this repository.
//
// tag must be one of the registered tags above. Passing an unregistered string
// would verify perfectly well and mean nothing — domain separation is only a
// property of a set whose members are all accounted for.
//
// It checks the signature and nothing else. No window, no role, no schema: those
// are decisions belonging to whoever knows what the bytes are for. The returned
// body is a copy, so a caller keeping it is not holding a window onto signed's
// backing array.
func OpenSigned(pub ed25519.PublicKey, tag string, signed []byte) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: bad public key length", ErrMalformed)
	}
	if len(signed) <= sigLen {
		return nil, ErrMalformed
	}
	body, sig := signed[:len(signed)-sigLen], signed[len(signed)-sigLen:]
	if !ed25519.Verify(pub, signingMessage(tag, body), sig) {
		return nil, ErrBadSignature
	}
	return bytes.Clone(body), nil
}

// ParseCert verifies a signed delegation cert against the root public key and
// returns it. It checks the signature, the version, and the delegated key length
// only — the role match and the validity window are decisions and belong to
// VerifyDelegationCert, so operator tooling can read a cert's fields (which role,
// which window) without imposing an admission decision.
//
// The signature is checked before the body is unmarshaled, so untrusted bytes
// never reach the decoder.
func ParseCert(rootPub ed25519.PublicKey, signed []byte) (Cert, error) {
	body, err := OpenSigned(rootPub, TagDelegationCert, signed)
	if err != nil {
		return Cert{}, err
	}
	var c Cert
	if err := json.Unmarshal(body, &c); err != nil {
		return Cert{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if c.Version != Version {
		return Cert{}, fmt.Errorf("%w: delegation cert version %d", ErrUnsupportedVersion, c.Version)
	}
	if len(c.Pub) != ed25519.PublicKeySize {
		return Cert{}, fmt.Errorf("%w: delegation cert carries a %d-byte key", ErrMalformed, len(c.Pub))
	}
	return c, nil
}

// VerifyDelegationCert decides whether a delegation is live right now for the
// role the caller was built for. It holds nothing but the root public key and
// never contacts the service that minted the cert.
//
// The order is normative and matches the credential chain's: signature, then
// role, then revocation, then window. Revocation comes before the window so a
// cert the root explicitly killed reports ErrRevoked even when it has also
// expired — the operator killed it, and that is the more actionable reason.
//
// expect is matched EXACTLY. Because the comparison is `c.Role != expect`, a cert
// carrying an empty or unknown role fails here too: a verifier only ever asks for
// a role it knows. Drop this check and an update-signer cert verifies as a policy
// signer.
//
// revoked reports whether a serial has been revoked; pass nil when no revocation
// list is configured, meaning nothing is revoked.
//
// It fails CLOSED on a missing root. A verifier with no trust anchor cannot
// verify anything, and the only other option is admitting everything.
func VerifyDelegationCert(rootPub ed25519.PublicKey, signed []byte, expect Role, now time.Time, revoked func(serial string) bool) (Cert, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return Cert{}, ErrNoRoot
	}
	c, err := ParseCert(rootPub, signed)
	if err != nil {
		return Cert{}, err
	}
	if c.Role != expect {
		return Cert{}, fmt.Errorf("%w: cert is %q, expected %q", ErrWrongRole, c.Role, expect)
	}
	if revoked != nil && revoked(c.Serial) {
		return Cert{}, ErrRevoked
	}
	if now.Before(c.NotBefore.Add(-ClockSkew)) {
		return Cert{}, ErrNotYetValid
	}
	if !now.Before(c.NotAfter) {
		return Cert{}, ErrExpired
	}
	return c, nil
}

// certPrefix tags the copy-pasteable string form of a delegation cert. "g"
// because "i" and "d" are already taken by the issuer cert and device credential
// of the same family.
//
// The prefix is convenience for config files and out-of-band handoff. It is NOT
// covered by any signature, so it is never what keeps one object from being read
// as another — the domain tag is.
const certPrefix = "bacchusg1:"

// EncodeCert packs a signed delegation cert into its string form.
func EncodeCert(signed []byte) string {
	return certPrefix + base64.RawURLEncoding.EncodeToString(signed)
}

// DecodeCert reverses EncodeCert, validating only the envelope; the signature is
// checked by ParseCert.
func DecodeCert(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, certPrefix) {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrMalformed, certPrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(s[len(certPrefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return b, nil
}
