package revocation

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
)

// Verifier turns a Bundle into an accept/refuse decision using nothing but the
// root public key, the current time, and the newest AsOf it has already
// accepted for the namespace being checked. It never contacts whoever signed or
// published the bundle — that is the point (ADR-0017 decision C, "C3") — so it
// is usable by a coordinator with no route to the account-service side at all.
//
// One Verifier serves BOTH namespaces (device, admission): the root that
// authorizes a revocations signer is the same for both (ADR-0017 decision 2 —
// "the ceremony mints one role, not two"), and the floor that separates them is
// a Verify argument, not state this type holds. See
// cmd/coordinator/revocations.go for the per-namespace fetch/cache loop built on
// top of this.
//
// It is safe for concurrent use as long as revoked is.
type Verifier struct {
	rootPub ed25519.PublicKey
	revoked func(serial string) bool
}

// NewVerifier builds a Verifier for the given root public key. revoked reports
// whether a delegation cert's serial has been revoked; pass nil when no
// revocation-of-the-DELEGATION list is configured, meaning nothing is revoked —
// this is about revoking the delegation (the signer's own authority), which is
// unrelated to the document's own Revoked serial list.
//
// A missing or malformed root key is a hard error: this fails CLOSED, matching
// delegation.VerifyDelegationCert and core/policy.NewVerifier. A verifier with no
// trust anchor cannot verify anything, and one that returned success anyway
// would be a coordinator enforcing a revoked-serials list from whoever asked —
// precisely the arrangement C3 exists to make impossible.
func NewVerifier(rootPub ed25519.PublicKey, revoked func(serial string) bool) (*Verifier, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return nil, delegation.ErrNoRoot
	}
	if revoked == nil {
		revoked = func(string) bool { return false }
	}
	return &Verifier{rootPub: rootPub, revoked: revoked}, nil
}

// Verify checks a bundle offline and returns the document it is safe to enforce.
//
// minAsOf is the newest AsOf this verifier has ever accepted FOR THIS NAMESPACE;
// pass the zero time.Time on a cold start, when nothing has been accepted yet.
// Persisting it across restarts is the caller's job — see Cache — exactly as
// persisting minSeq is core/policy's caller's job, and for the identical reason:
// an enforcer that forgets its floor on every restart can be rolled back by
// anyone who can make it restart.
//
// now is passed in rather than read here, so tests use a fixed clock and the
// caller owns its time source.
//
// The descent is strictly tier by tier and mirrors policy.Verifier.Verify:
//
//  1. The delegation cert is fully verified against the root for the
//     REVOCATIONS role — signature, role, revocation, window — before cert.Pub
//     is used for anything. Until the root's signature over it verifies, that
//     key is just bytes whoever served the bundle chose.
//  2. Only then is the document's own signature checked, under that key.
//  3. Only then is the body decoded, so untrusted bytes never reach the
//     decoder.
//  4. Structure, then rollback.
func (v *Verifier) Verify(b Bundle, now time.Time, minAsOf time.Time) (Doc, error) {
	// Tier 1: did the offline root authorize this key for the revocations role,
	// and is that authorization live right now? A cert cut for policy or update
	// fails here — the role is bound into the signed body and matched exactly —
	// so a policy signer's cert is cryptographically useless as a revocations
	// signer.
	cert, err := delegation.VerifyDelegationCert(v.rootPub, b.Cert, delegation.RoleRevocations, now, v.revoked)
	if err != nil {
		return Doc{}, fmt.Errorf("revocation: delegation: %w", err)
	}

	// Tier 2: was the document signed by the key that cert delegates to? Only
	// now is cert.Pub trustworthy.
	//
	// A structurally broken DOCUMENT reports this package's ErrMalformed rather
	// than the delegation package's, mirroring policy.Verify's identical split:
	// errors about the DELEGATION are the delegation package's, errors about the
	// DOCUMENT are this package's.
	body, err := delegation.OpenSigned(cert.Pub, delegation.TagRevocationsDoc, b.Revocations)
	if err != nil {
		if errors.Is(err, delegation.ErrMalformed) {
			return Doc{}, fmt.Errorf("%w: document: %v", ErrMalformed, err)
		}
		return Doc{}, fmt.Errorf("revocation: document: %w", err)
	}

	var d Doc
	if err := json.Unmarshal(body, &d); err != nil {
		return Doc{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	// Unknown fields are ignored, matching policy.Verify's asymmetry with the
	// authoring side: an additive field must not brick an enforcer that has not
	// shipped it yet. Version is the gate for a change an old enforcer must not
	// misread.
	if d.Version != Version {
		return Doc{}, fmt.Errorf("%w: revocations document version %d", ErrUnsupportedVersion, d.Version)
	}

	// Rollback. A document from an older sync tick is genuinely signed,
	// correctly role-delegated, and — unlike a policy document — nowhere near
	// any window, because this format has none. Every check above passes such a
	// document; this is the only one that refuses it.
	//
	// The comparison is strictly-before, not before-or-equal: re-accepting the
	// SAME as_of is required, not merely tolerated, because a healthy fetch loop
	// re-verifies the unchanged bundle on every tick.
	if d.AsOf.Before(minAsOf) {
		return Doc{}, fmt.Errorf("%w: as_of %s below the accepted floor %s", ErrRollback, d.AsOf.UTC(), minAsOf.UTC())
	}
	return d, nil
}
