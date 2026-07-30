// Package devicecred verifies the account service's two-tier device credential
// at connect time, offline.
//
//	root key ---signs---> issuer cert ---delegates---> issuer key
//	  (offline; this                 (ipub, window,           |
//	   repository holds only          max_cred_ttl)        signs
//	   its PUBLIC half)                                       |
//	                                                          v
//	                                                  device credential
//	                                               (dpub, epoch, window)
//
// A device presents credential || issuer cert || assertion(challenge) and a
// coordinator verifies the whole chain without contacting anyone. That is the
// load-bearing property rather than an optimisation: the open network never
// depends on, and never leaks to, the closed account service, so matchmaking
// keeps working when that service is unreachable and learns nothing about who is
// connecting when it is. The cost is revocation latency, bought back by short
// credential lifetimes — "stop renewing" is most of revocation.
//
// # This is not core/admission, and does not replace it
//
// The two credentials answer different questions and both are asked. core/admission
// is the NETWORK's own membership credential: one tier, bearer, anchored to the
// operator's admission key, carrying client/relay/exit roles and the Vouched
// marker, and it answers "may this party be on the network at all?". This package
// is the ACCOUNT SERVICE's: two tiers, challenge-bound, anchored to an offline
// root the operator does not hold, carrying an entitlement bound to one device,
// and it answers "does this device hold a live entitlement right now?".
//
// A connect passes admission first and this second. Neither subsumes the other:
// admission cannot express "this device, this account generation, until Tuesday"
// and this cannot express "this node may serve as an exit". See ADR-0045.
//
// # What a credential deliberately does not carry
//
// A DeviceCredential carries DevicePub, Epoch, a window and a Serial — and
// nothing else. No account id, no label, no note, no role. Every additional field
// would be a fingerprinting surface the coordinator sees on every connect, and the
// account is deliberately not derivable from anything on the wire.
//
// DevicePub is stable across renewals, so a coordinator can link one device's
// connects over time. That residual is known and accepted; closing it is a change
// to how the credential is signed, not to this protocol.
//
// # The wire format is frozen and owned elsewhere
//
// The signer — the ceremony that mints these certs and credentials — lives outside
// this repository and cannot be imported here. The wire format is therefore the
// contract, and testdata's frozen conformance vectors are what keep the two
// implementations agreeing rather than merely both compiling. Those files are
// copies; a change to either is a deliberate format change made where the signer
// lives, and arrives here as a copy.
//
// # Framing
//
// Every signature covers tag || 0x00 || body, never body alone, and every verifier
// here accepts exactly one tag — so a signature produced in one context can never
// be replayed in another. The framing itself is core/delegation's OpenSigned; this
// package does not carry a second copy of it, because a second implementation of a
// signature check is exactly the kind of thing that drifts silently.
//
// The body travels verbatim and is verified as received. Nothing here re-marshals
// a body to check it, so JSON field order, whitespace and escaping are deliberately
// not part of the contract.
package devicecred

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
)

// Version is the format version of every signed body in this package. It is
// checked EXACTLY, not as a minimum: a verifier that does not know a format
// refuses it rather than reading the subset it recognises, so an old coordinator
// never silently misreads a newer credential.
const Version = 1

// The domain-separation tags for this chain's two signed objects are
// delegation.TagIssuerCert and delegation.TagDeviceCred, registered in
// core/delegation with every other tag this repository verifies (#54). They are not
// re-exported here: a second name for one tag is a second place to change it, and
// domain separation is a property of the whole SET, only auditable while the set is
// readable in one file.
//
// This package still owns what the objects MEAN — the structs below, the descent in
// verify.go, the errors. core/delegation owns the framing and the tag values.

// IssuerCert is tier one: the offline root delegating "may issue device
// credentials" to the account service's issuer key, for a window, with a cap on
// what that key may mint. The root signs it and this repository never holds the
// root's private half.
//
// It is the clean interface between the open network and the closed account
// service — the network needs only "valid if it chains to the root", never how
// billing works.
//
// The marshaled form is the signed body and verification is always over the bytes
// as received, so this struct may be reordered freely. What IS the contract: the
// json tag names below, the domain tag, and Version. Renaming a json tag does not
// break a signature — it silently changes which field a peer reads, and a field
// the peer cannot find arrives as a zero value.
type IssuerCert struct {
	Version    int           `json:"v"`
	Serial     string        `json:"serial"`         // hex, unique; names this cert for revocation
	IssuerPub  []byte        `json:"ipub"`           // ed25519 pubkey of the delegated issuer key
	NotBefore  time.Time     `json:"nbf"`            // validity start (UTC)
	NotAfter   time.Time     `json:"exp"`            // validity end (UTC)
	MaxCredTTL time.Duration `json:"mttl"`           // hard cap on a device credential's lifetime
	Note       string        `json:"note,omitempty"` // operator label; never load-bearing
}

// DeviceCredential is tier two: the issuer key attesting that whoever holds
// DevicePub may connect until NotAfter. It is short-lived by design.
//
// The field set is minimal and every field is justified, because a coordinator
// sees all of it on every connect: DevicePub is the identity being proven, Epoch
// is the account generation that destructive recovery bumps, NotBefore/NotAfter
// are the window, and Serial names it for the short revocation window.
//
// The json tag names are the contract, for the same reason as IssuerCert.
type DeviceCredential struct {
	Version   int       `json:"v"`
	Serial    string    `json:"serial"` // hex, unique per issuance; fresh on every renewal
	DevicePub []byte    `json:"dpub"`   // ed25519 pubkey the device generated locally
	Epoch     uint64    `json:"epoch"`  // account credential generation; recovery increments it
	NotBefore time.Time `json:"nbf"`    // validity start (UTC)
	NotAfter  time.Time `json:"exp"`    // validity end (UTC)
}

// Sentinel errors. Every one names a protocol fact only — never key material,
// never anything account-scoped — so all are safe to log and safe to hand back to
// a rejected peer as a reason.
//
// They are this package's rather than core/delegation's because a caller wants one
// vocabulary for the connect path. delegation's equivalents are translated at the
// one place they can arrive, in openSigned.
var (
	ErrMalformed          = errors.New("devicecred: malformed object")
	ErrUnsupportedVersion = errors.New("devicecred: unsupported version")
	ErrBadSignature       = errors.New("devicecred: signature invalid")
	ErrNotYetValid        = errors.New("devicecred: not yet valid")
	ErrExpired            = errors.New("devicecred: expired")
	ErrRevoked            = errors.New("devicecred: revoked")
	ErrCredTTLTooLong     = errors.New("devicecred: credential lifetime exceeds the issuer cert's cap")
	ErrBadAssertion       = errors.New("devicecred: device assertion invalid")
	ErrNoRoot             = errors.New("devicecred: no root public key configured")
)

// openSigned splits body || sig and checks the signature against pub under tag,
// returning the body bytes it covers.
//
// It is a thin translation over delegation.OpenSigned — the framing lives there
// and exists once — and its whole job is to re-express that package's sentinels as
// this one's, so a caller on the connect path matches against one set of errors.
func openSigned(pub ed25519.PublicKey, tag string, signed []byte) ([]byte, error) {
	body, err := delegation.OpenSigned(pub, tag, signed)
	if err != nil {
		switch {
		case errors.Is(err, delegation.ErrBadSignature):
			return nil, ErrBadSignature
		case errors.Is(err, delegation.ErrMalformed):
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		default:
			return nil, err
		}
	}
	return body, nil
}

// Envelope prefixes for the copy-pasteable string form, distinct from each other
// and from this repository's coldstart invite ("bacchus1:"), admission credential
// ("bacchusc1:") and delegation cert ("bacchusg1:").
//
// These are a convenience for config files and out-of-band handoff only. They are
// NOT covered by any signature — an attacker strips or swaps them freely — so they
// are never what keeps one object from being read as another. The domain tag is.
const (
	issuerCertPrefix = "bacchusi1:"
	deviceCredPrefix = "bacchusd1:"
)

// EncodeIssuerCert packs a signed issuer cert into its string form.
func EncodeIssuerCert(signed []byte) string { return encode(issuerCertPrefix, signed) }

// EncodeDeviceCredential packs a signed device credential into its string form.
func EncodeDeviceCredential(signed []byte) string { return encode(deviceCredPrefix, signed) }

// DecodeIssuerCert reverses EncodeIssuerCert, validating only the envelope; the
// signature is checked by ParseIssuerCert.
func DecodeIssuerCert(s string) ([]byte, error) { return decode(issuerCertPrefix, s) }

// DecodeDeviceCredential reverses EncodeDeviceCredential, validating only the
// envelope; the signature is checked by ParseCredential.
func DecodeDeviceCredential(s string) ([]byte, error) { return decode(deviceCredPrefix, s) }

func encode(prefix string, signed []byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(signed)
}

func decode(prefix, s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrMalformed, prefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return b, nil
}
