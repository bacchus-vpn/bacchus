package devicecred

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
)

// ClockSkew is the tolerance applied to a NotBefore so a verifier whose clock runs
// slightly behind the signer's does not reject a credential the instant it is
// issued.
//
// It is applied to the LOWER bound only. Being lenient about when something starts
// is harmless; being lenient about when it expires would extend a revoked or
// rotated credential past the point an operator believes it is dead, and expiry is
// most of how revocation works here. NotAfter is therefore strict.
//
// It is delegation.ClockSkew rather than a second constant. These objects travel
// the same network between the same parties as the delegation certs and admission
// credentials, and a verifier lenient about one and strict about another would be
// a difference nobody could explain.
const ClockSkew = delegation.ClockSkew

// checkWindow applies a validity window with skew on the lower bound only.
func checkWindow(notBefore, notAfter, now time.Time) error {
	if now.Before(notBefore.Add(-ClockSkew)) {
		return ErrNotYetValid
	}
	if !now.Before(notAfter) {
		return ErrExpired
	}
	return nil
}

// ParseIssuerCert verifies a signed issuer cert against the root public key and
// returns it. It checks the signature, the version and the delegated key length
// only — revocation and the validity window are decisions and belong to
// VerifyIssuerCert, so operator tooling can read a cert's fields without imposing
// an admission decision.
//
// The signature is checked before the body is unmarshaled, so untrusted bytes
// never reach the decoder.
func ParseIssuerCert(rootPub ed25519.PublicKey, signed []byte) (IssuerCert, error) {
	body, err := openSigned(rootPub, delegation.TagIssuerCert, signed)
	if err != nil {
		return IssuerCert{}, err
	}
	var c IssuerCert
	if err := json.Unmarshal(body, &c); err != nil {
		return IssuerCert{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if c.Version != Version {
		return IssuerCert{}, fmt.Errorf("%w: issuer cert version %d", ErrUnsupportedVersion, c.Version)
	}
	if len(c.IssuerPub) != ed25519.PublicKeySize {
		return IssuerCert{}, fmt.Errorf("%w: issuer cert carries a %d-byte issuer key", ErrMalformed, len(c.IssuerPub))
	}
	return c, nil
}

// VerifyIssuerCert verifies a signed issuer cert against the root and reports
// whether it is live at now. It is tier one factored out of Verify so there is
// exactly one issuer-cert verifier: the device chain calls it, and so does any
// operator tool that checks a cert on its own.
//
// Revocation is checked before the window, matching Verify, so a cert the root
// explicitly killed reports ErrRevoked even when it has also expired — the
// operator killed it, and that is the more actionable reason.
//
// revoked reports whether a serial has been revoked; pass nil when no revocation
// list is configured, meaning nothing is revoked.
//
// It fails CLOSED on a missing root: a verifier with no trust anchor cannot verify
// anything, and the only other option is admitting everything.
func VerifyIssuerCert(rootPub ed25519.PublicKey, signed []byte, now time.Time, revoked func(serial string) bool) (IssuerCert, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return IssuerCert{}, ErrNoRoot
	}
	cert, err := ParseIssuerCert(rootPub, signed)
	if err != nil {
		return IssuerCert{}, err
	}
	if revoked != nil && revoked(cert.Serial) {
		return IssuerCert{}, ErrRevoked
	}
	if err := checkWindow(cert.NotBefore, cert.NotAfter, now); err != nil {
		return IssuerCert{}, err
	}
	return cert, nil
}

// VerifyIssuerCert is [VerifyIssuerCert] against the root and revocation list this
// verifier already holds — tier one on its own, without the credential and
// assertion the full descent needs.
//
// It exists because a coordinator now receives the issuer cert a round trip BEFORE
// the connect that spends it (issue #206, ADR-0062): the cert rides the "challenge"
// so the connect need not carry 362 bytes that are identical for every device from
// one issuer. Something has to decide whether those bytes are worth keeping, and the
// only honest answer is the root's — anything else stores an attacker-chosen string
// keyed on a spoofable UDP source.
//
// It is deliberately NOT a substitute for [Verifier.Verify]. The connect re-verifies
// the whole chain against the clock and revocation list AT CONNECT TIME, so a cert
// revoked inside the challenge's lifetime is still refused; this call only decides
// what may be held in the meantime.
func (v *Verifier) VerifyIssuerCert(signed []byte, now time.Time) (IssuerCert, error) {
	return VerifyIssuerCert(v.rootPub, signed, now, v.revoked)
}

// Presentation is what a device sends to prove it may connect: its short-lived
// credential, the issuer cert that credential chains through, and an assertion
// proving it holds the matching private key.
//
// There is deliberately NO separate device public key field. The key is already
// inside Credential, which is signed, and a second copy is a live footgun: the
// assertion must be checked against the CREDENTIAL's key, and an implementation
// that reached for a presented copy instead would happily accept any forged
// pairing of someone else's credential with the attacker's key. Making that
// unrepresentable is cheaper than documenting the rule.
type Presentation struct {
	Credential []byte // signed device credential (body || sig), from the issuer
	IssuerCert []byte // signed issuer cert (body || sig), from the root
	Assertion  []byte // PurposeConnect signature over this verifier's challenge
}

// ParsePresentation decodes the three wire values a device sends — the two
// envelope strings and the raw assertion bytes — into a Presentation.
//
// It validates envelopes only; every signature is checked by Verify. A missing or
// malformed envelope is refused here rather than becoming a confusing signature
// failure later, and reports ErrMalformed, which is also what an empty value
// produces.
func ParsePresentation(credential, issuerCert string, assertion []byte) (Presentation, error) {
	cred, err := DecodeDeviceCredential(credential)
	if err != nil {
		return Presentation{}, fmt.Errorf("credential: %w", err)
	}
	cert, err := DecodeIssuerCert(issuerCert)
	if err != nil {
		return Presentation{}, fmt.Errorf("issuer cert: %w", err)
	}
	if len(assertion) == 0 {
		return Presentation{}, fmt.Errorf("%w: empty assertion", ErrMalformed)
	}
	return Presentation{Credential: cred, IssuerCert: cert, Assertion: assertion}, nil
}

// Verifier turns a Presentation into an admit/refuse decision using nothing but
// the root public key, the current time, and the audience and challenge it chose
// itself. It never contacts the account service — that is the whole point — so it
// is usable by a coordinator that has no route to that service at all, and cannot
// leak to one.
//
// It is safe for concurrent use as long as revoked is.
type Verifier struct {
	rootPub ed25519.PublicKey
	revoked func(serial string) bool
}

// NewVerifier builds a Verifier for the given root public key. revoked reports
// whether a serial has been revoked; pass nil when no revocation list is
// configured, meaning nothing is revoked.
//
// A missing or malformed root key is a hard error: constructing a Verifier fails
// CLOSED. A chain verifier with no trust anchor cannot verify anything, so
// returning one that admitted everything would only ever be a silent hole — the
// caller would hold an object named "Verifier" that verified nothing.
//
// This is a narrower statement than "the connect gate fails closed", and the two
// must not be conflated. Whether a coordinator with no root CONFIGURED runs the
// gate at all is the deployment's decision, not this package's, and it is made the
// other way: an unconfigured anchor disables the gate rather than darkening every
// connect. See ADR-0045 for why the direction differs from signed policy's — in
// short, a coordinator failing closed on policy sheds to its peers because clients
// rotate, while every coordinator in the pool reads the same configuration posture,
// so an unconfigured anchor has nothing to shed to. What does NOT differ: once a
// root IS configured, a failed verification refuses that connect, with no fallback.
func NewVerifier(rootPub ed25519.PublicKey, revoked func(serial string) bool) (*Verifier, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return nil, ErrNoRoot
	}
	if revoked == nil {
		revoked = func(string) bool { return false }
	}
	return &Verifier{rootPub: rootPub, revoked: revoked}, nil
}

// Verify checks the whole chain offline and returns the validated credential.
//
// audience is this verifier's own identity and challenge is the fresh random nonce
// it just sent. BOTH must be the ones this verifier chose, or the assertion check
// is theatre: the audience is what stops a hostile member of the coordinator pool
// relaying someone else's chain as its own, and the challenge is what stops a
// captured assertion being replayed at a later connect. They are security-critical
// rather than parameters — see assertionMessage.
//
// now is passed in rather than read here, so tests use a fixed clock and the caller
// owns its time source.
//
// The descent is strictly tier by tier and THE ORDERING IS LOAD-BEARING:
//
//  1. The issuer cert is fully verified against the anchored root — signature,
//     version, revocation, window — before cert.IssuerPub is used for ANYTHING.
//     Until the root's signature over it verifies, that key is just bytes whoever
//     connected supplied.
//  2. Only then is the credential's own signature checked, under that key.
//  3. Only then is the body decoded, so untrusted bytes never reach the decoder.
//  4. Then structure, then the TTL bound, then freshness, then the challenge-bound
//     assertion against the credential's device key.
//
// Within a tier, revocation is checked before the window, so an explicitly revoked
// object reports ErrRevoked even when it has also expired.
//
// Every signature is checked over the bytes AS RECEIVED. Nothing here re-marshals a
// body to verify it: whoever presented the credential supplied every part of it, and
// a verifier that re-marshaled would be checking a signature over bytes it invented
// rather than bytes it was given.
//
// Every returned error names a protocol fact only, and the assertion failures never
// distinguish "wrong key" from "wrong challenge", so a rejected peer learns nothing
// it can probe with.
func (v *Verifier) Verify(p Presentation, now time.Time, audience string, challenge []byte) (DeviceCredential, error) {
	// Tier 1: does this issuer cert chain to our root, and is it live right now?
	cert, err := VerifyIssuerCert(v.rootPub, p.IssuerCert, now, v.revoked)
	if err != nil {
		return DeviceCredential{}, err
	}

	// Tier 2: was this credential signed by the key that cert delegates to? Only
	// now is cert.IssuerPub trustworthy.
	body, err := openSigned(cert.IssuerPub, delegation.TagDeviceCred, p.Credential)
	if err != nil {
		return DeviceCredential{}, err
	}
	var cred DeviceCredential
	if err := json.Unmarshal(body, &cred); err != nil {
		return DeviceCredential{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if cred.Version != Version {
		return DeviceCredential{}, fmt.Errorf("%w: credential version %d", ErrUnsupportedVersion, cred.Version)
	}
	// Redundant with VerifyAssertion's own length check, and JOINTLY LOAD-BEARING
	// with it: either alone can go, but with both gone ed25519.Verify panics on a
	// short key — a remote crash on every coordinator that verifies the credential.
	// Reachable exactly under the stolen-issuer-key model, since a forged credential
	// can carry any dpub at all.
	if len(cred.DevicePub) != ed25519.PublicKeySize {
		return DeviceCredential{}, fmt.Errorf("%w: credential carries a %d-byte device key", ErrMalformed, len(cred.DevicePub))
	}
	if v.revoked(cred.Serial) {
		return DeviceCredential{}, ErrRevoked
	}
	if err := checkWindow(cred.NotBefore, cred.NotAfter, now); err != nil {
		return DeviceCredential{}, err
	}
	// The cap binds at VERIFICATION, not only at issuance: an issuer key in the
	// wrong hands mints whatever it likes, and the only party that can constrain it
	// is the offline root, through this field. Checking it only where credentials
	// are minted would put the constraint inside the thing being constrained.
	if cred.NotAfter.Sub(cred.NotBefore) > cert.MaxCredTTL {
		return DeviceCredential{}, ErrCredTTLTooLong
	}

	// Leaf: does the presenter actually hold the credential's device key, for THIS
	// verifier and THIS connect? This is what makes a stolen credential worthless.
	if err := VerifyAssertion(cred.DevicePub, PurposeConnect, audience, challenge, p.Assertion); err != nil {
		return DeviceCredential{}, err
	}
	return cred, nil
}
