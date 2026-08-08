package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
)

// clockSkew is the tolerance applied to Issued, so a peer whose clock runs
// slightly behind the signer's does not refuse a manifest the instant it is
// published.
//
// It is delegation.ClockSkew rather than a second constant, for the reason
// core/policy gives about the same borrowing: the objects travel the same network
// between the same parties, and a verifier lenient about one and strict about the
// other would be a difference nobody could explain.
//
// Applied to the LOWER bound only. Expires stays strict. There is no grace here to
// spend leniency in — see Manifest.Expires.
const clockSkew = delegation.ClockSkew

// Bundle is what a peer fetches: the signed manifest and the delegation cert
// authorizing the key that signed it.
//
// Both members are verified independently against the root, so the wrapper itself
// is not signed and does not need to be — tampering with it can only produce a
// bundle that fails.
type Bundle struct {
	// Manifest is the signed manifest, body || sig, signed by the update signer.
	Manifest []byte `json:"manifest"`
	// Cert is the signed delegation cert, body || sig, signed by the offline root,
	// with role "update".
	Cert []byte `json:"cert"`
}

// ParseBundle decodes the fetch format: a JSON object with two standard-base64
// members. A bundle missing either member is refused here rather than producing a
// confusing signature failure later.
func ParseBundle(data []byte) (Bundle, error) {
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("%w: bundle: %v", ErrMalformed, err)
	}
	if len(b.Manifest) == 0 || len(b.Cert) == 0 {
		return Bundle{}, fmt.Errorf("%w: bundle is missing the manifest or the delegation cert", ErrMalformed)
	}
	return b, nil
}

// Marshal renders a bundle in the fetch format.
func (b Bundle) Marshal() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// Verifier turns a Bundle into an apply/refuse decision using nothing but the root
// public key, the current time, and the highest sequence it has already accepted.
// It never contacts whoever signed the manifest — that is what the offline root
// buys — so it works on a node whose coordinators are all unreachable, which is
// precisely the node most likely to be running the release being replaced.
//
// It is safe for concurrent use as long as revoked is.
type Verifier struct {
	rootPub ed25519.PublicKey
	revoked func(serial string) bool
}

// NewVerifier builds a Verifier for the given root public key. revoked reports
// whether a delegation cert's serial has been revoked; pass nil when no revocation
// list is configured, meaning nothing is revoked.
//
// A missing or malformed root key is a hard error: this fails CLOSED, and there is
// no direction to argue about. core/policy's NewVerifier explains its own
// fail-closed choice by whether the failure is sheddable; here the question does
// not arise, because the alternative to refusing is applying executable bytes
// nobody vouched for. A build with no anchor does not update. It keeps running.
func NewVerifier(rootPub ed25519.PublicKey, revoked func(serial string) bool) (*Verifier, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return nil, delegation.ErrNoRoot
	}
	if revoked == nil {
		revoked = func(string) bool { return false }
	}
	return &Verifier{rootPub: rootPub, revoked: revoked}, nil
}

// Verify checks a bundle offline and returns the manifest it is safe to act on.
//
// minSeq is the highest Seq this peer has ever accepted; pass 0 on a cold start.
// Persisting it across restarts is the caller's job and it matters: a peer that
// forgets its floor on every restart can be walked back onto a burned release by
// anyone who can make it restart, using a manifest that is genuinely signed,
// correctly delegated and nowhere near expiry. See State.
//
// now is passed in rather than read here, so tests use a fixed clock and the
// caller owns its time source.
//
// The descent is strictly tier by tier and THE ORDERING IS LOAD-BEARING:
//
//  1. The delegation cert is fully verified against the root for the UPDATE role —
//     signature, role, revocation, window — before cert.Pub is used for anything.
//     Until the root's signature over it verifies, that key is just bytes whoever
//     served the bundle chose. A cert cut for the policy role fails here: the role
//     is bound into the signed body and matched exactly, which is the property that
//     makes a policy signer cryptographically useless as an update signer.
//  2. Only then is the manifest's own signature checked, under that key.
//  3. Only then is the body decoded, so untrusted bytes never reach the decoder.
//  4. Structure, then freshness, then rollback.
//
// Every signature is checked over the bytes AS RECEIVED. Nothing here re-marshals
// a body to verify it; whoever served the bundle supplied both halves, and a
// verifier that re-marshaled would be checking a signature over bytes it invented
// rather than bytes it was given.
//
// What this does NOT check is the artifact. Tier 4 is Stage, over the complete
// downloaded file, and it is a separate call because it happens later against
// bytes this one never sees.
func (v *Verifier) Verify(b Bundle, now time.Time, minSeq uint64) (Manifest, error) {
	// Tier 1.
	//
	// This re-runs on EVERY verification and its result is never cached, which is
	// what bounds a manifest's life: a release can never outlive the authorization of
	// the key that signed it.
	cert, err := delegation.VerifyDelegationCert(v.rootPub, b.Cert, delegation.RoleUpdate, now, v.revoked)
	if err != nil {
		return Manifest{}, fmt.Errorf("update: delegation: %w", err)
	}

	// Tier 2. Only now is cert.Pub trustworthy.
	//
	// A structurally broken MANIFEST reports this package's ErrMalformed rather than
	// the delegation package's, so a caller has one vocabulary for the update path
	// instead of two sentinels meaning the same protocol fact. The line is
	// core/policy's: errors about the DELEGATION are the delegation package's
	// (ErrWrongRole, ErrExpired and ErrRevoked have no update-side equivalent),
	// errors about the MANIFEST are this package's.
	body, err := delegation.OpenSigned(cert.Pub, delegation.TagUpdateManifest, b.Manifest)
	if err != nil {
		if errors.Is(err, delegation.ErrMalformed) {
			return Manifest{}, fmt.Errorf("%w: manifest: %v", ErrMalformed, err)
		}
		return Manifest{}, fmt.Errorf("update: manifest: %w", err)
	}

	// Tier 3.
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	// Unknown fields are IGNORED here, unlike at authoring time where the signer
	// refuses them (see cmd/release-sign). The asymmetry is core/policy's and holds
	// for the same reason: refusing them at the signer catches an operator's typo
	// before it is signed, while refusing them here would mean any additive field
	// bricked every peer that had not shipped yet. Version is the gate for a change
	// an old peer must not misread, and Validate checks it first.
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}

	// Freshness. Not-yet-issued is reported separately from expired because they are
	// different operator errors — a clock wrong in one direction versus a release
	// nobody re-signed — and a peer that reported one for the other would send its
	// operator looking in the wrong place.
	if now.Before(m.Issued.Add(-clockSkew)) {
		return Manifest{}, fmt.Errorf("%w: issued %s, now %s", ErrNotYetIssued, m.Issued.UTC(), now.UTC())
	}
	if !now.Before(m.Expires) {
		return Manifest{}, fmt.Errorf("%w: exp %s, now %s", ErrExpired, m.Expires.UTC(), now.UTC())
	}

	// Rollback. A manifest from an older generation is genuinely signed, correctly
	// role-delegated, and may be nowhere near expiry — every cryptographic check
	// above passes. This is the only thing that refuses it, and without it an
	// attacker who can serve bytes could walk a fleet back onto a burned release that
	// was once legitimately signed (ADR-0052 §7).
	//
	// The comparison is `<`, not `<=`: re-accepting the SAME seq is required, not
	// merely tolerated, because a peer re-reads the same manifest on every check.
	if m.Seq < minSeq {
		return Manifest{}, fmt.Errorf("%w: seq %d below the accepted floor %d", ErrRollback, m.Seq, minSeq)
	}
	return m, nil
}

// VerifyArtifact hashes r to its end and checks the result against a's declared
// size and digest. It returns the number of bytes read.
//
// It reads the COMPLETE stream before comparing anything, and it is the only
// artifact check in this package. Never stream-verify and never verify
// incrementally into a live path: a hash checked as bytes arrive has already let
// unverified bytes exist somewhere they could be executed (ADR-0052 §3).
//
// The size is checked first because it is the cheap half and because a mismatch
// there names a different failure than a digest mismatch does — a truncated
// download versus bytes that are not the release.
//
// The digest comparison is constant-time. There is no secret in a public digest
// and no realistic oracle here; it is subtle.ConstantTimeCompare because a
// comparison of authentication material that is sometimes timing-safe and
// sometimes not is a habit worth not having.
func VerifyArtifact(a Artifact, r io.Reader) (int64, error) {
	h := sha256.New()
	// One byte past the declared size, so a source serving MORE than it promised is
	// caught by the read rather than by the hash of an unbounded download.
	n, err := io.Copy(h, io.LimitReader(r, a.Size+1))
	if err != nil {
		return n, fmt.Errorf("update: read artifact: %w", err)
	}
	if n != a.Size {
		return n, fmt.Errorf("%w: got %d bytes, manifest says %d", ErrSizeMismatch, n, a.Size)
	}
	sum := h.Sum(nil)
	if subtle.ConstantTimeCompare(sum, a.SHA256) != 1 {
		return n, fmt.Errorf("%w: %s/%s %s", ErrHashMismatch, a.OS, a.Arch, a.Role)
	}
	return n, nil
}
