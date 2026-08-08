package admission

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestSignVerifyCRLRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded, err := SignCRL(priv, []string{"babe", "cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	c, err := VerifyCRL(pub, encoded, base)
	if err != nil {
		t.Fatalf("VerifyCRL: %v", err)
	}
	if !c.Revoked("cafe") || !c.Revoked("babe") {
		t.Fatal("signed serials not reported revoked")
	}
	if c.Revoked("f00d") {
		t.Fatal("unrelated serial reported revoked")
	}
}

// TestSignCRLSortsSerials: the signed body is deterministic regardless of
// input order, mirroring RevocationList.SaveFile's diff-friendly guarantee.
func TestSignCRLSortsSerials(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	a, err := SignCRL(priv, []string{"cafe", "babe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	b, err := SignCRL(priv, []string{"babe", "cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if a != b {
		t.Fatalf("SignCRL not order-independent: %q != %q", a, b)
	}
}

// TestVerifyCRLExpired: a bundle is rejected once now reaches its ExpiresAt,
// even though its signature is perfectly valid — the whole point of a
// short-TTL bundle is that staleness itself is disqualifying.
func TestVerifyCRLExpired(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded, err := SignCRL(priv, []string{"cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if _, err := VerifyCRL(pub, encoded, base.Add(time.Hour)); !errors.Is(err, ErrCRLExpired) {
		t.Fatalf("at expiry: err = %v, want ErrCRLExpired", err)
	}
	if _, err := VerifyCRL(pub, encoded, base.Add(59*time.Minute)); err != nil {
		t.Fatalf("just before expiry: err = %v, want admit", err)
	}
}

// TestVerifyCRLBadSignature: a bundle verified against a different key than
// signed it is rejected — the property that makes a CRL trustworthy
// independent of whoever relayed it.
func TestVerifyCRLBadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded, err := SignCRL(otherPriv, []string{"cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if _, err := ParseCRL(pub, encoded); !errors.Is(err, ErrCRLBadSignature) {
		t.Fatalf("err = %v, want ErrCRLBadSignature", err)
	}
}

// TestParseCRLMalformed covers old #69's malformed-CRL requirement directly
// against the admission package: every shape of bad input is rejected, none
// panics.
func TestParseCRLMalformed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	goodBody, err := SignCRL(priv, []string{"cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}

	cases := []struct {
		name    string
		encoded string
		wantErr error // nil means "just assert non-nil"
	}{
		{"empty string", "", nil},
		{"no prefix at all", "not-a-crl", nil},
		{"credential's prefix, not a CRL's", "bacchusc1:AbCdEf", nil},
		{"prefix but garbage base64", "bacchusr1:!!!not-valid-base64", nil},
		{"prefix but too short to hold a signature", "bacchusr1:AbCd", nil},
		{"well-formed but truncated one byte", goodBody[:len(goodBody)-1], nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCRL(pub, tc.encoded)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestParseCRLUnsupportedVersion: a version this build doesn't understand is
// rejected rather than mis-parsed, mirroring Credential's parse.
func TestParseCRLUnsupportedVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Sign a body by hand with a bogus version, since SignCRL always stamps
	// the current CRLVersion.
	body := []byte(`{"v":99,"iat":"2026-07-03T12:00:00Z","exp":"2026-07-03T13:00:00Z","revoked":[]}`)
	sig := ed25519.Sign(priv, body)
	encoded := crlPrefix + base64.RawURLEncoding.EncodeToString(append(body, sig...))
	if _, err := ParseCRL(pub, encoded); !errors.Is(err, ErrCRLUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrCRLUnsupportedVersion", err)
	}
}

// TestCRLEmptyBundleRevokesNothing: a freshly-signed, empty bundle ("nothing
// revoked as of now") is well-formed and simply revokes nothing — the shape
// cmd/admission-issue -crl emits before any -revoke has ever run.
func TestCRLEmptyBundleRevokesNothing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded, err := SignCRL(priv, nil, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	c, err := VerifyCRL(pub, encoded, base)
	if err != nil {
		t.Fatalf("VerifyCRL: %v", err)
	}
	if c.Revoked("anything") {
		t.Fatal("empty bundle must revoke nothing")
	}
}

// ClientCRL (old #90): the mutable, atomically-swapped bundle a background
// reload keeps fresh. These are unit tests at the admission-package layer;
// core/exit_admission_test.go and core/crl_reload_test.go cover it wired into
// buildExitVerifier and Engine.reloadCRLLoop end to end.

// TestClientCRLFailsOpenBeforeFirstSet: a freshly constructed ClientCRL with
// no bundle loaded yet reports every serial not-revoked — the same fail-open
// shape as admission.NewVerifier's nil-oracle default, so a client between
// construction and its first successful load never over-rejects.
func TestClientCRLFailsOpenBeforeFirstSet(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c := NewClientCRL(pub)
	if c.Revoked("anything") {
		t.Fatal("a ClientCRL with nothing ever Set must fail open")
	}
}

// TestClientCRLSetAndRevoked: after a successful Set, Revoked reflects
// exactly the bundle's serials.
func TestClientCRLSetAndRevoked(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded, err := SignCRL(priv, []string{"cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	c := NewClientCRL(pub)
	if err := c.Set(encoded, base); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !c.Revoked("cafe") {
		t.Fatal("revoked serial reported not-revoked")
	}
	if c.Revoked("babe") {
		t.Fatal("unrelated serial reported revoked")
	}
}

// TestClientCRLSetReplacesNotMerges: a second successful Set fully replaces
// the active bundle rather than accumulating into it — the same "load
// current file state, don't merge with memory" semantics as the
// coordinator's own reloadRevocationsLoop. A reload that dropped a prior
// serial (the operator un-revoked it) must actually stop being enforced.
func TestClientCRLSetReplacesNotMerges(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	first, err := SignCRL(priv, []string{"cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	c := NewClientCRL(pub)
	if err := c.Set(first, base); err != nil {
		t.Fatalf("Set(first): %v", err)
	}
	if !c.Revoked("cafe") {
		t.Fatal("setup: first bundle should revoke cafe")
	}

	second, err := SignCRL(priv, []string{"babe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if err := c.Set(second, base); err != nil {
		t.Fatalf("Set(second): %v", err)
	}
	if c.Revoked("cafe") {
		t.Fatal("second Set must replace the first bundle, not merge with it: cafe should no longer be revoked")
	}
	if !c.Revoked("babe") {
		t.Fatal("second bundle's own revocation must take effect")
	}
}

// TestClientCRLSetRejectsBadSignatureKeepsPrevious: a Set that fails
// signature verification is rejected and leaves the previously active bundle
// untouched — the reload-time mirror of buildExitVerifier's construction-time
// invariant that a broken bundle never silently degrades enforcement.
func TestClientCRLSetRejectsBadSignatureKeepsPrevious(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	good, err := SignCRL(priv, []string{"cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	c := NewClientCRL(pub)
	if err := c.Set(good, base); err != nil {
		t.Fatalf("Set(good): %v", err)
	}

	bad, err := SignCRL(otherPriv, []string{"babe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if err := c.Set(bad, base); !errors.Is(err, ErrCRLBadSignature) {
		t.Fatalf("Set(bad signature) err = %v, want ErrCRLBadSignature", err)
	}
	if !c.Revoked("cafe") {
		t.Fatal("a rejected reload must not un-revoke the previously active bundle")
	}
	if c.Revoked("babe") {
		t.Fatal("a rejected reload must not apply any part of the bad bundle")
	}
}

// TestClientCRLSetRejectsExpiredKeepsPrevious: same as above, for a reload
// bundle that parses and verifies but has already lapsed — an operator late
// to rotate a CRL must not blind the client, just freeze it at the last
// known-good bundle.
func TestClientCRLSetRejectsExpiredKeepsPrevious(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	good, err := SignCRL(priv, []string{"cafe"}, base, time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	c := NewClientCRL(pub)
	if err := c.Set(good, base); err != nil {
		t.Fatalf("Set(good): %v", err)
	}

	expired, err := SignCRL(priv, []string{"babe"}, base.Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	if err := c.Set(expired, base); !errors.Is(err, ErrCRLExpired) {
		t.Fatalf("Set(expired) err = %v, want ErrCRLExpired", err)
	}
	if !c.Revoked("cafe") {
		t.Fatal("a rejected (expired) reload must not un-revoke the previously active bundle")
	}
}
