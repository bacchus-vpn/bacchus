package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
)

// clockSkew is the tolerance applied to Issued, so an enforcer whose clock runs
// slightly behind the signer's does not reject a policy the instant it is
// published.
//
// It is delegation.ClockSkew rather than a second constant: the two objects travel
// the same network between the same parties, and a verifier lenient about one and
// strict about the other would be a difference nobody could explain.
//
// Applied to the LOWER bound only. Expires stays strict, and Grace — not skew — is
// where any leniency past expiry is spent, because that leniency is the operator's
// to grant and is signed.
const clockSkew = delegation.ClockSkew

// Bundle is what an enforcer fetches: the signed policy document and the
// delegation cert authorizing the key that signed it.
//
// Both members are verified independently against the root, so the wrapper itself
// is not signed and does not need to be — tampering with it can only produce a
// bundle that fails.
type Bundle struct {
	// Doc is the signed policy document, body || sig, signed by the policy signer.
	Doc []byte `json:"policy"`
	// Cert is the signed delegation cert, body || sig, signed by the offline root,
	// with role "policy".
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
	if len(b.Doc) == 0 || len(b.Cert) == 0 {
		return Bundle{}, fmt.Errorf("%w: bundle is missing the policy document or the delegation cert", ErrMalformed)
	}
	return b, nil
}

// Verifier turns a Bundle into an enforce/refuse decision using nothing but the
// root public key, the current time, and the highest sequence it has already
// accepted. It never contacts the service that signed the policy — that is the
// point — so it is usable by a coordinator with no route to that service at all.
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
// A missing or malformed root key is a hard error: this fails CLOSED. A policy
// verifier with no trust anchor cannot verify anything, and one that returned
// success anyway would be a coordinator enforcing numbers it accepted from whoever
// asked — precisely the arrangement this whole mechanism exists to make
// impossible.
//
// Note this is the opposite direction from -admission-pubkey and
// -min-serving-version, which fail OPEN when unset. The direction follows from
// whether the failure is sheddable: coordinators are a pool with client rotation,
// so one failing closed sheds to its peers rather than darkening the network,
// while the admission gate and the version fence are single points with nothing to
// shed to.
func NewVerifier(rootPub ed25519.PublicKey, revoked func(serial string) bool) (*Verifier, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return nil, delegation.ErrNoRoot
	}
	if revoked == nil {
		revoked = func(string) bool { return false }
	}
	return &Verifier{rootPub: rootPub, revoked: revoked}, nil
}

// Verify checks a bundle offline and returns the policy it is safe to enforce.
//
// minSeq is the highest Seq this enforcer has ever accepted; pass 0 on a cold
// start. Persisting it across restarts is the enforcer's job and it matters: an
// enforcer that forgets its floor on every restart can be rolled back by anyone who
// can make it restart. See Cache.
//
// now is passed in rather than read here, so tests use a fixed clock and the caller
// owns its time source.
//
// The descent is strictly tier by tier and THE ORDERING IS LOAD-BEARING:
//
//  1. The delegation cert is fully verified against the root for the POLICY role —
//     signature, role, revocation, window — before cert.Pub is used for anything.
//     Until the root's signature over it verifies, that key is just bytes whoever
//     served the bundle chose.
//  2. Only then is the document's own signature checked, under that key.
//  3. Only then is the body decoded, so untrusted bytes never reach the decoder.
//  4. Structure, then freshness, then rollback.
//
// Every signature is checked over the bytes AS RECEIVED. Nothing here re-marshals a
// body to verify it; whoever served the bundle supplied both halves, and a verifier
// that re-marshaled would be checking a signature over bytes it invented rather
// than bytes it was given.
//
// Freshness accepts through Expires+Grace, not through Expires. A caller that must
// distinguish the two asks Fresh; a caller that does not still cannot enforce a
// document past its grace, because this refuses it.
func (v *Verifier) Verify(b Bundle, now time.Time, minSeq uint64) (Policy, error) {
	// Tier 1: did the offline root authorize this key for the policy role, and is
	// that authorization live right now? A cert cut for the update role fails here —
	// the role is bound into the signed body and matched exactly — so an update
	// signer is cryptographically useless as a policy signer.
	//
	// This re-runs on EVERY verification and its result is never cached, which is
	// what bounds grace: a policy can never outlive the authorization of the key
	// that signed it, whatever its own grace says.
	cert, err := delegation.VerifyDelegationCert(v.rootPub, b.Cert, delegation.RolePolicy, now, v.revoked)
	if err != nil {
		return Policy{}, fmt.Errorf("policy: delegation: %w", err)
	}

	// Tier 2: was the document signed by the key that cert delegates to? Only now is
	// cert.Pub trustworthy.
	//
	// A structurally broken DOCUMENT reports this package's ErrMalformed rather than
	// the delegation package's, so a caller has one vocabulary for the policy path
	// instead of two sentinels meaning the same protocol fact. The line is: errors
	// about the DELEGATION are the delegation package's (ErrWrongRole, ErrExpired and
	// ErrRevoked have no policy-side equivalent), errors about the DOCUMENT are this
	// package's.
	body, err := delegation.OpenSigned(cert.Pub, delegation.TagPolicyDoc, b.Doc)
	if err != nil {
		if errors.Is(err, delegation.ErrMalformed) {
			return Policy{}, fmt.Errorf("%w: document: %v", ErrMalformed, err)
		}
		return Policy{}, fmt.Errorf("policy: document: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(body, &p); err != nil {
		return Policy{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	// Unknown fields are IGNORED here, unlike at authoring time where the signer
	// refuses them. The asymmetry is deliberate: refusing them at the signer catches
	// an operator's typo before it is signed, while refusing them here would mean any
	// additive field bricked every enforcer that had not shipped yet. Version is the
	// gate for a change an old enforcer must not misread, and Validate checks it
	// first.
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}

	// Freshness. Not-yet-issued is reported separately from stale because they are
	// different operator errors — a clock wrong in one direction versus a re-sign
	// that did not happen — and an enforcer that reported one for the other would
	// send its operator looking in the wrong place.
	if now.Before(p.Issued.Add(-clockSkew)) {
		return Policy{}, fmt.Errorf("%w: issued %s, now %s", ErrNotYetIssued, p.Issued.UTC(), now.UTC())
	}
	if !now.Before(p.Deadline()) {
		return Policy{}, fmt.Errorf("%w: exp %s + grace %s, now %s", ErrStale, p.Expires.UTC(), p.Grace, now.UTC())
	}

	// Rollback. A document from an older generation is genuinely signed, correctly
	// role-delegated, and may be nowhere near expiry — every cryptographic check
	// above passes. This is the only thing that refuses it.
	//
	// The comparison is `<`, not `<=`: re-accepting the SAME seq is required, not
	// merely tolerated, because an enforcer re-fetches the same document on every
	// refresh.
	if p.Seq < minSeq {
		return Policy{}, fmt.Errorf("%w: seq %d below the accepted floor %d", ErrRollback, p.Seq, minSeq)
	}
	return p, nil
}
