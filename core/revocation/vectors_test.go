package revocation_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/revocation"
)

// The two files in testdata are FROZEN conformance fixtures, copied verbatim
// from bacchus-payment/internal/revocation/testdata — the private repository
// that owns the signer and the reference verifier for this format (ADR-0017,
// bacchus-payment#77). That repository cannot be imported here, so the wire
// format is the contract and these bytes are what keep the two implementations
// agreeing, exactly as core/policy/vectors_test.go already does for the signed
// policy blob.
//
// They are not regenerated on this side. A change to either file is a
// deliberate format change made where the signer lives, and arrives here as a
// copy — `go test ./internal/revocation -update` there, then a copy back.
//
// Every key in them is a published throwaway rooted in bacchus-payment's
// development root, whose private key is derived from a constant printed in its
// own source. TestVectorsUseAThrowawayRoot below re-proves that here rather than
// trusting the note in the file, because these bytes live in a public repository
// and "the fixture says it is a test key" is exactly what a leaked real key
// would also look like.
const (
	positiveVectors = "testdata/vectors.json"
	negativeVectors = "testdata/negative_vectors.json"
)

// devRootSeedPhrase is the published constant bacchus-payment's development
// root key is derived from (internal/devroot.SeedPhrase) — the SAME root every
// other cross-repo fixture in this repository chains to (core/policy's own
// vectors, core/accountclient's). Reproduced here so this repository can PROVE
// the trust anchor in its testdata is the throwaway one, without importing the
// private module.
const devRootSeedPhrase = "BACCHUS DEVELOPMENT ROOT - PUBLIC THROWAWAY KEY - NOT A REAL ROOT - DO NOT USE IN PRODUCTION"

type posVectors struct {
	Note    string          `json:"note"`
	Now     string          `json:"now"`
	RootPub string          `json:"root_pub"`
	Bundle  json.RawMessage `json:"bundle"`

	// SignerSeed regenerates the document bytes and is an input to
	// REGENERATION only, never to verification — a verifier learns the
	// signer's key from the delegation cert. Unused here (this side never
	// regenerates), kept so the struct decodes the file without error.
	SignerSeed string `json:"signer_seed"`

	ExpectAsOf             string   `json:"expect_as_of"`
	ExpectRevoked          []string `json:"expect_revoked"`
	ExpectSignerPub        string   `json:"expect_signer_pub"`
	ExpectDelegationSerial string   `json:"expect_delegation_serial"`
}

// negCase is one frozen refusal.
type negCase struct {
	Name   string          `json:"name"`
	Bundle json.RawMessage `json:"bundle"`
	Now    string          `json:"now"`
	// MinAsOf is the newest as_of the verifier has already accepted, which is
	// the only thing that catches a rollback.
	MinAsOf string `json:"min_as_of"`
	// RevokedSerial, when set, is the delegation serial the verifier's
	// revocation predicate must report revoked.
	RevokedSerial string `json:"revoked_serial,omitempty"`
	ExpectError   string `json:"expect_error"`
}

type negVectors struct {
	Note    string    `json:"note"`
	RootPub string    `json:"root_pub"`
	Cases   []negCase `json:"cases"`
}

// negTokenErr maps the stable token in expect_error to the sentinel it names.
// The file holds tokens rather than Go error strings so a port in another
// language can consume it, and so a reworded message is not a fixture change.
//
// Two tokens map into the delegation package and the rest into this one — the
// same split core/policy/vectors_test.go documents: an error about the
// DELEGATION is a delegation-package fact, one about the DOCUMENT is this
// package's.
func negTokenErr(token string) (error, bool) {
	switch token {
	case "bad_signature":
		return delegation.ErrBadSignature, true
	case "wrong_role":
		return delegation.ErrWrongRole, true
	case "delegation_expired":
		return delegation.ErrExpired, true
	case "delegation_revoked":
		return delegation.ErrRevoked, true
	case "no_root":
		return delegation.ErrNoRoot, true
	case "delegation_malformed":
		return delegation.ErrMalformed, true
	case "rollback":
		return revocation.ErrRollback, true
	case "unsupported_version":
		return revocation.ErrUnsupportedVersion, true
	case "malformed":
		return revocation.ErrMalformed, true
	default:
		return nil, false
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return b
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return ts
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPositiveWireVectors is the acceptance half of conformance: the frozen
// bundle must be ACCEPTED, at its own `now` and a cold-start (zero) floor, by a
// verifier holding root_pub alone, and every expect_* value in the file must be
// what this port reads out of it.
func TestPositiveWireVectors(t *testing.T) {
	var pv posVectors
	readJSON(t, positiveVectors, &pv)

	rootPub := unb64(t, pv.RootPub)
	now := mustTime(t, pv.Now)

	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	bundle, err := revocation.ParseBundle(pv.Bundle)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	// minAsOf zero (time.Time{}) is a cold start: nothing has been accepted yet.
	d, err := v.Verify(bundle, now, time.Time{})
	if err != nil {
		t.Fatalf("Verify() REFUSED the frozen positive bundle: %v", err)
	}

	if got := d.AsOf.UTC().Format(time.RFC3339); got != pv.ExpectAsOf {
		t.Errorf("AsOf = %s, want %s", got, pv.ExpectAsOf)
	}
	if !equalStrings(d.Revoked, pv.ExpectRevoked) {
		t.Errorf("Revoked = %v, want %v", d.Revoked, pv.ExpectRevoked)
	}

	// The delegation the bundle carries must be the one the fixture names,
	// verified against the root for the revocations role specifically.
	cert, err := delegation.VerifyDelegationCert(rootPub, bundle.Cert, delegation.RoleRevocations, now, nil)
	if err != nil {
		t.Fatalf("VerifyDelegationCert: %v", err)
	}
	if cert.Serial != pv.ExpectDelegationSerial {
		t.Errorf("delegation serial = %q, want %q", cert.Serial, pv.ExpectDelegationSerial)
	}
	if got := base64.StdEncoding.EncodeToString(cert.Pub); got != pv.ExpectSignerPub {
		t.Errorf("signer pub = %q, want %q", got, pv.ExpectSignerPub)
	}

	// Re-verifying at the SAME as_of as the floor must still accept — a
	// steady-state reload of an unchanged bundle is not a replay.
	if _, err := v.Verify(bundle, now, d.AsOf); err != nil {
		t.Errorf("Verify() at a floor equal to the bundle's own as_of = %v, want accept", err)
	}
	// And strictly past it must refuse.
	if _, err := v.Verify(bundle, now, d.AsOf.Add(time.Nanosecond)); !errors.Is(err, revocation.ErrRollback) {
		t.Errorf("Verify() at a floor one ns past the bundle's as_of = %v, want ErrRollback", err)
	}
}

// TestNegativeWireVectors is the half that makes conformance mean something.
// Each frozen bundle must be REFUSED by a verifier built from root_pub alone,
// with the error its expect_error names.
//
// A verifier that accepts everything passes every positive vector there is and
// dies here. Matching the specific error matters as much as refusing: a port
// that collapsed every refusal into one sentinel would leave an operator unable
// to tell a revoked delegation from a rollback.
func TestNegativeWireVectors(t *testing.T) {
	var nv negVectors
	readJSON(t, negativeVectors, &nv)

	rootPub := unb64(t, nv.RootPub)
	if len(nv.Cases) == 0 {
		t.Fatal("no negative cases in the fixture")
	}

	for _, c := range nv.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want, ok := negTokenErr(c.ExpectError)
			if !ok {
				t.Fatalf("case names an unknown expect_error %q", c.ExpectError)
			}
			now := mustTime(t, c.Now)
			minAsOf := mustTime(t, c.MinAsOf)

			var revoked func(string) bool
			if c.RevokedSerial != "" {
				revoked = func(serial string) bool { return serial == c.RevokedSerial }
			}
			v, err := revocation.NewVerifier(rootPub, revoked)
			if err != nil {
				t.Fatalf("build verifier: %v", err)
			}
			bundle, err := revocation.ParseBundle(c.Bundle)
			if err != nil {
				// A bundle this malformed never reaches Verify. That is still a
				// refusal, and only the malformed token may claim it.
				if errors.Is(err, want) {
					return
				}
				t.Fatalf("ParseBundle() = %v, want %v", err, want)
			}
			got, err := v.Verify(bundle, now, minAsOf)
			if err == nil {
				t.Fatalf("Verify() ACCEPTED a bundle that must be refused (parsed as_of %s)", got.AsOf)
			}
			if !errors.Is(err, want) {
				t.Fatalf("Verify() = %v, want %v", err, want)
			}
		})
	}
}

// TestNegativeVectorsCoverEveryRefusalToken guards the fixture itself: if a
// future copy silently dropped, say, every rollback case, the suite above would
// still pass with nothing to say about rollback. This asserts the set of tokens
// actually exercised, so a thinned fixture is a test failure rather than a
// quiet gap.
func TestNegativeVectorsCoverEveryRefusalToken(t *testing.T) {
	var nv negVectors
	readJSON(t, negativeVectors, &nv)

	seen := map[string]int{}
	for _, c := range nv.Cases {
		seen[c.ExpectError]++
	}
	for _, token := range []string{
		"bad_signature", "wrong_role", "delegation_expired", "delegation_revoked",
		"delegation_malformed", "rollback", "unsupported_version", "malformed",
	} {
		if seen[token] == 0 {
			t.Errorf("no negative case exercises %q", token)
		}
	}
	if len(nv.Cases) < 15 {
		t.Errorf("negative fixture has %d cases, expected at least the frozen 15", len(nv.Cases))
	}
}

// TestVectorsUseAThrowawayRoot proves the trust anchor in testdata is the
// published development root and not a real one.
//
// This is a PUBLIC repository. The fixtures carry a root public key and a note
// claiming it is a throwaway — a note is exactly what a leaked real key would
// also carry, so this recomputes the development root from its published seed
// phrase and requires the fixture to match it. If a future fixture copy ever
// chains to a root whose private key is not public, this fails, loudly, in CI,
// before the bytes are trusted.
func TestVectorsUseAThrowawayRoot(t *testing.T) {
	seed := sha256.Sum256([]byte(devRootSeedPhrase))
	devRootPub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	want := base64.StdEncoding.EncodeToString(devRootPub)

	var pv posVectors
	readJSON(t, positiveVectors, &pv)
	if pv.RootPub != want {
		t.Errorf("%s is rooted in %q, which is NOT the published development root — a real root key must never reach this repository", positiveVectors, pv.RootPub)
	}

	var nv negVectors
	readJSON(t, negativeVectors, &nv)
	if nv.RootPub != want {
		t.Errorf("%s is rooted in %q, which is NOT the published development root", negativeVectors, nv.RootPub)
	}
}
