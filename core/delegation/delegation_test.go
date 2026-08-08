package delegation_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
)

// The wire format's own spec notes there are no frozen negative vectors for a
// delegation cert on its own. The instruction it gives instead is to implement the
// four rules and test them ADVERSARIALLY: one positive control, then a negative
// case per rule, each mutating exactly one field of a cert proven to verify a
// moment earlier.
//
// That shape is what these tests follow. A negative case built from scratch can
// fail for a reason the author did not intend — a typo in the fixture rather than
// the rule under test — and would still look green. Mutating a cert that just
// verified means the ONLY difference is the field named in the test.
//
// core/policy's frozen fixtures cover the wrong-role, lapsed, revoked and tampered
// cases in the policy context, which narrows this gap without closing it: those
// vectors say nothing about the update role, and nothing about a cert this
// repository mints itself.

// signCert produces a signed delegation cert, mirroring what the offline root's
// ceremony tool emits. It lives in the test rather than the package because
// SIGNING a delegation is the root holder's operation and never this repository's:
// a public coordinator that could mint delegations would defeat the entire
// arrangement. It exists here only so these tests can build the object they then
// try to break.
func signCert(t *testing.T, rootPriv ed25519.PrivateKey, c delegation.Cert) []byte {
	t.Helper()
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	msg := append([]byte(delegation.TagDelegationCert), 0x00)
	msg = append(msg, body...)
	sig := ed25519.Sign(rootPriv, msg)
	return append(body, sig...)
}

// liveCert is the positive control every negative case below mutates one field of.
func liveCert(t *testing.T) (rootPub ed25519.PublicKey, rootPriv ed25519.PrivateKey, cert delegation.Cert, signed []byte, now time.Time) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	signerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	cert = delegation.Cert{
		Version:   delegation.Version,
		Serial:    "a1b2c3d4e5f60718",
		Role:      delegation.RolePolicy,
		Pub:       signerPub,
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
		Note:      "test policy signer",
	}
	return rootPub, rootPriv, cert, signCert(t, rootPriv, cert), now
}

// TestVerifyDelegationCertAcceptsALiveCert is the control. Every negative case
// below is this cert with exactly one thing changed, so a failure there is
// attributable to that one change.
func TestVerifyDelegationCertAcceptsALiveCert(t *testing.T) {
	rootPub, _, want, signed, now := liveCert(t)

	got, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RolePolicy, now, nil)
	if err != nil {
		t.Fatalf("VerifyDelegationCert() = %v, want accept", err)
	}
	if got.Serial != want.Serial {
		t.Errorf("Serial = %q, want %q", got.Serial, want.Serial)
	}
	if got.Role != delegation.RolePolicy {
		t.Errorf("Role = %q, want %q", got.Role, delegation.RolePolicy)
	}
	if string(got.Pub) != string(want.Pub) {
		t.Error("delegated pubkey does not round-trip")
	}
}

// TestVerifyDelegationCertRejectsAForeignRoot covers rule 1. A cert signed by some
// other key is not a cert.
func TestVerifyDelegationCertRejectsAForeignRoot(t *testing.T) {
	_, _, _, signed, now := liveCert(t)
	foreignPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate foreign root: %v", err)
	}

	_, err = delegation.VerifyDelegationCert(foreignPub, signed, delegation.RolePolicy, now, nil)
	if !errors.Is(err, delegation.ErrBadSignature) {
		t.Fatalf("VerifyDelegationCert() = %v, want ErrBadSignature", err)
	}
}

// TestVerifyDelegationCertRejectsATamperedBody covers rule 1 from the other side:
// the signature is over the bytes as received, so flipping one byte of the body
// must break it.
func TestVerifyDelegationCertRejectsATamperedBody(t *testing.T) {
	rootPub, _, _, signed, now := liveCert(t)

	tampered := append([]byte(nil), signed...)
	tampered[0] ^= 0xff

	_, err := delegation.VerifyDelegationCert(rootPub, tampered, delegation.RolePolicy, now, nil)
	if !errors.Is(err, delegation.ErrBadSignature) {
		t.Fatalf("VerifyDelegationCert() = %v, want ErrBadSignature", err)
	}
}

// TestVerifyDelegationCertRejectsTheWrongRole covers rule 2, and it is the case
// this whole package exists to get right.
//
// The cert is genuinely signed by the real root, is inside its window, and is not
// revoked. It differs from the control by four bytes of role string. A verifier
// that read the role without enforcing it would accept an update signer as a policy
// signer, with no signature failure anywhere to notice.
func TestVerifyDelegationCertRejectsTheWrongRole(t *testing.T) {
	rootPub, rootPriv, cert, _, now := liveCert(t)

	cert.Role = delegation.RoleUpdate
	signed := signCert(t, rootPriv, cert)

	// Sanity: it is a perfectly valid UPDATE delegation. The refusal below is about
	// the role asked for, not about the cert being broken.
	if _, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RoleUpdate, now, nil); err != nil {
		t.Fatalf("the update cert should verify AS an update cert: %v", err)
	}

	_, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RolePolicy, now, nil)
	if !errors.Is(err, delegation.ErrWrongRole) {
		t.Fatalf("VerifyDelegationCert(update cert, want policy) = %v, want ErrWrongRole", err)
	}
}

// TestVerifyDelegationCertAcceptsARevocationsRoleCert pins that RoleRevocations
// (issue #199, ADR-0017, ADR-0063) is a live role by the same general verifier
// used for policy and update, not a value that merely exists in the type. Part 1
// of #199 is inert without this: Known() is advisory only, and this is the check
// that actually admits — or refuses — a cert cut for this role.
func TestVerifyDelegationCertAcceptsARevocationsRoleCert(t *testing.T) {
	rootPub, rootPriv, cert, _, now := liveCert(t)

	cert.Role = delegation.RoleRevocations
	signed := signCert(t, rootPriv, cert)

	if _, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RoleRevocations, now, nil); err != nil {
		t.Fatalf("VerifyDelegationCert() = %v, want accept for a revocations-role cert asked for as revocations", err)
	}
	if _, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RolePolicy, now, nil); !errors.Is(err, delegation.ErrWrongRole) {
		t.Fatalf("VerifyDelegationCert(revocations cert, want policy) = %v, want ErrWrongRole", err)
	}
}

// TestVerifyDelegationCertRejectsAnUnknownRole is the same rule at its edge: a role
// nobody has minted yet must not slip through by not matching any known value. The
// check compares against the ONE role the caller asked for, so this falls out —
// this test pins that it does.
func TestVerifyDelegationCertRejectsAnUnknownRole(t *testing.T) {
	rootPub, rootPriv, cert, _, now := liveCert(t)

	for _, role := range []delegation.Role{"", "relay", "POLICY", "policy "} {
		cert.Role = role
		signed := signCert(t, rootPriv, cert)
		_, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RolePolicy, now, nil)
		if !errors.Is(err, delegation.ErrWrongRole) {
			t.Errorf("role %q: VerifyDelegationCert() = %v, want ErrWrongRole", role, err)
		}
	}
}

// TestVerifyDelegationCertRejectsARevokedSerial covers rule 3.
func TestVerifyDelegationCertRejectsARevokedSerial(t *testing.T) {
	rootPub, _, cert, signed, now := liveCert(t)

	revoked := func(serial string) bool { return serial == cert.Serial }

	_, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RolePolicy, now, revoked)
	if !errors.Is(err, delegation.ErrRevoked) {
		t.Fatalf("VerifyDelegationCert() = %v, want ErrRevoked", err)
	}
}

// TestRevocationIsCheckedBeforeTheWindow pins the ORDER of rules 3 and 4. A cert
// the root explicitly killed reports revoked even when it has also expired, because
// the kill is the more actionable reason for an operator reading a log.
func TestRevocationIsCheckedBeforeTheWindow(t *testing.T) {
	rootPub, rootPriv, cert, _, now := liveCert(t)

	cert.NotAfter = now.Add(-time.Hour) // also expired
	signed := signCert(t, rootPriv, cert)
	revoked := func(serial string) bool { return serial == cert.Serial }

	_, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RolePolicy, now, revoked)
	if !errors.Is(err, delegation.ErrRevoked) {
		t.Fatalf("a revoked AND expired cert reported %v, want ErrRevoked (revocation is the more actionable reason)", err)
	}
}

// TestVerifyDelegationCertRejectsAClosedWindow covers rule 4 in both directions,
// and pins the skew asymmetry: lenient on the lower bound, strict on expiry.
func TestVerifyDelegationCertRejectsAClosedWindow(t *testing.T) {
	rootPub, rootPriv, base, _, now := liveCert(t)

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      error
	}{
		{
			name:      "not yet valid, beyond skew",
			notBefore: now.Add(delegation.ClockSkew + time.Minute),
			notAfter:  now.Add(24 * time.Hour),
			want:      delegation.ErrNotYetValid,
		},
		{
			name:      "expired",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(-time.Nanosecond),
			want:      delegation.ErrExpired,
		},
		{
			name: "expiry is strict: exactly at NotAfter is already expired",
			// Being lenient here would extend a rotated delegation past the point an
			// operator believes it is dead, which is why skew applies to nbf only.
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now,
			want:      delegation.ErrExpired,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.NotBefore, c.NotAfter = tc.notBefore, tc.notAfter
			_, err := delegation.VerifyDelegationCert(rootPub, signCert(t, rootPriv, c), delegation.RolePolicy, now, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyDelegationCert() = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifyDelegationCertToleratesSkewOnTheLowerBound is the counterpart: a cert
// minted seconds ago by a signer whose clock runs slightly ahead must still verify.
func TestVerifyDelegationCertToleratesSkewOnTheLowerBound(t *testing.T) {
	rootPub, rootPriv, cert, _, now := liveCert(t)

	cert.NotBefore = now.Add(delegation.ClockSkew - time.Second)
	signed := signCert(t, rootPriv, cert)

	if _, err := delegation.VerifyDelegationCert(rootPub, signed, delegation.RolePolicy, now, nil); err != nil {
		t.Fatalf("VerifyDelegationCert() = %v, want accept inside the skew tolerance", err)
	}
}

// TestVerifyDelegationCertFailsClosedWithoutARoot pins the fail-closed posture. A
// verifier with no trust anchor cannot verify anything, so the only alternative to
// refusing is admitting everything.
func TestVerifyDelegationCertFailsClosedWithoutARoot(t *testing.T) {
	_, _, _, signed, now := liveCert(t)

	for _, root := range []ed25519.PublicKey{nil, {}, make([]byte, 16)} {
		_, err := delegation.VerifyDelegationCert(root, signed, delegation.RolePolicy, now, nil)
		if !errors.Is(err, delegation.ErrNoRoot) {
			t.Errorf("root len %d: VerifyDelegationCert() = %v, want ErrNoRoot", len(root), err)
		}
	}
}

// TestVerifyDelegationCertRejectsAnUnsupportedVersion pins that the version is
// checked exactly rather than as a minimum.
func TestVerifyDelegationCertRejectsAnUnsupportedVersion(t *testing.T) {
	rootPub, rootPriv, cert, _, now := liveCert(t)

	for _, v := range []int{0, 2, 99} {
		c := cert
		c.Version = v
		_, err := delegation.VerifyDelegationCert(rootPub, signCert(t, rootPriv, c), delegation.RolePolicy, now, nil)
		if !errors.Is(err, delegation.ErrUnsupportedVersion) {
			t.Errorf("version %d: VerifyDelegationCert() = %v, want ErrUnsupportedVersion", v, err)
		}
	}
}

// TestVerifyDelegationCertRejectsABadKeyLength stops a cert delegating to something
// that is not an ed25519 key from reaching a caller that would then use it.
func TestVerifyDelegationCertRejectsABadKeyLength(t *testing.T) {
	rootPub, rootPriv, cert, _, now := liveCert(t)

	for _, n := range []int{0, 16, 31, 33} {
		c := cert
		c.Pub = make([]byte, n)
		_, err := delegation.VerifyDelegationCert(rootPub, signCert(t, rootPriv, c), delegation.RolePolicy, now, nil)
		if !errors.Is(err, delegation.ErrMalformed) {
			t.Errorf("pub len %d: VerifyDelegationCert() = %v, want ErrMalformed", n, err)
		}
	}
}

// TestVerifyDelegationCertRejectsTruncation covers an object too short to hold a
// signature at all, which must not index out of range.
func TestVerifyDelegationCertRejectsTruncation(t *testing.T) {
	rootPub, _, _, signed, now := liveCert(t)

	for _, n := range []int{0, 1, 63, 64} {
		_, err := delegation.VerifyDelegationCert(rootPub, signed[:min(n, len(signed))], delegation.RolePolicy, now, nil)
		if !errors.Is(err, delegation.ErrMalformed) {
			t.Errorf("truncated to %d: VerifyDelegationCert() = %v, want ErrMalformed", n, err)
		}
	}
}

// TestDomainSeparationBlocksCrossTagReplay is the property the 0x00-framed tag
// buys. A signature made over one object's tag must not verify as another's, or
// the root's signature on a policy document could be replayed as a delegation.
func TestDomainSeparationBlocksCrossTagReplay(t *testing.T) {
	rootPub, rootPriv, cert, _, _ := liveCert(t)

	body, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Same body, same key, signed under the POLICY DOCUMENT tag instead.
	msg := append([]byte(delegation.TagPolicyDoc), 0x00)
	msg = append(msg, body...)
	crossSigned := append(append([]byte(nil), body...), ed25519.Sign(rootPriv, msg)...)

	if _, err := delegation.ParseCert(rootPub, crossSigned); !errors.Is(err, delegation.ErrBadSignature) {
		t.Fatalf("ParseCert() on a policy-doc-tagged signature = %v, want ErrBadSignature", err)
	}
	// And it does verify under the tag it was actually made for, proving the refusal
	// above is the domain separation working rather than a broken signature.
	if _, err := delegation.OpenSigned(rootPub, delegation.TagPolicyDoc, crossSigned); err != nil {
		t.Fatalf("OpenSigned() under its own tag = %v, want accept", err)
	}
}

// TestEncodeDecodeCertRoundTrip covers the copy-paste envelope, which is
// convenience only and carries no signature of its own.
func TestEncodeDecodeCertRoundTrip(t *testing.T) {
	_, _, _, signed, _ := liveCert(t)

	got, err := delegation.DecodeCert(delegation.EncodeCert(signed))
	if err != nil {
		t.Fatalf("DecodeCert: %v", err)
	}
	if string(got) != string(signed) {
		t.Error("round trip changed the signed bytes")
	}
	if _, err := delegation.DecodeCert("bacchusi1:AAAA"); !errors.Is(err, delegation.ErrMalformed) {
		t.Errorf("DecodeCert(wrong prefix) = %v, want ErrMalformed", err)
	}
}

// TestRoleKnown pins the advisory helper, which deliberately does NOT gate
// verification — a verifier compares against the single role it was built for.
func TestRoleKnown(t *testing.T) {
	for _, r := range []delegation.Role{delegation.RolePolicy, delegation.RoleUpdate, delegation.RoleRevocations} {
		if !r.Known() {
			t.Errorf("Role(%q).Known() = false, want true", r)
		}
	}
	for _, r := range []delegation.Role{"", "relay", "issuer"} {
		if r.Known() {
			t.Errorf("Role(%q).Known() = true, want false", r)
		}
	}
}
