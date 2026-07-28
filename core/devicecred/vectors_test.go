package devicecred_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// The two files in testdata are FROZEN conformance fixtures, copied verbatim from
// the private repository that owns the signer and the reference verifier. That
// repository cannot be imported here, so the wire format is the contract and these
// bytes are what keep two independent implementations agreeing rather than merely
// both compiling.
//
// They are not regenerated on this side. A change to either file is a deliberate
// format change made where the signer lives, and arrives here as a copy.
//
// Every key in them is a published throwaway rooted in the private repository's
// development root, whose private key is derived from a constant printed in its own
// source. TestVectorsUseAThrowawayRoot re-proves that here rather than trusting the
// note in the file, because these bytes live in a PUBLIC repository and "the fixture
// says it is a test key" is exactly what a leaked real key would also look like.
const (
	positiveVectors = "testdata/vectors.json"
	negativeVectors = "testdata/negative_vectors.json"
)

// devRootSeedPhrase is the published constant the fixtures' root key is derived
// from. It is reproduced here so this repository can PROVE the trust anchor in its
// testdata is the throwaway one, without importing the private module.
const devRootSeedPhrase = "BACCHUS DEVELOPMENT ROOT - PUBLIC THROWAWAY KEY - NOT A REAL ROOT - DO NOT USE IN PRODUCTION"

type posVectors struct {
	Note    string `json:"note"`
	Now     string `json:"now"`
	RootPub string `json:"root_pub"`

	IssuerCert string `json:"issuer_cert"`
	DeviceCred string `json:"device_cred"`
	DeviceSeed string `json:"device_seed"`
	Audience   string `json:"audience"`
	Challenge  string `json:"challenge"`
	Assertion  string `json:"assertion"`

	ExpectDevicePub  string `json:"expect_device_pub"`
	ExpectEpoch      uint64 `json:"expect_epoch"`
	ExpectSerial     string `json:"expect_serial"`
	ExpectCertSerial string `json:"expect_cert_serial"`
}

// negCase is one frozen refusal.
type negCase struct {
	Name       string `json:"name"`
	Now        string `json:"now"`
	IssuerCert string `json:"issuer_cert"`
	DeviceCred string `json:"device_cred"`
	Assertion  string `json:"assertion"`
	Audience   string `json:"audience"`
	Challenge  string `json:"challenge"`
	// RevokedSerial, when set, is the serial the verifier's revocation predicate
	// must report revoked.
	RevokedSerial string `json:"revoked_serial,omitempty"`
	ExpectError   string `json:"expect_error"`
}

type negVectors struct {
	Note    string    `json:"note"`
	RootPub string    `json:"root_pub"`
	Cases   []negCase `json:"cases"`
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func mustB64(t *testing.T, what, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s: %v", what, err)
	}
	return b
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return ts
}

// TestVectorsUseAThrowawayRoot proves the trust anchor in both fixture files is
// the published development root, by deriving that root here from the seed phrase
// its own source file prints and comparing public keys.
//
// This is not a formality. These fixtures live in a public repository, and the one
// thing that makes publishing them safe is that their root's private half is a
// published constant rather than a secret. A note in a JSON file asserting that is
// exactly what a leaked real key would also carry, so the claim is checked rather
// than read.
func TestVectorsUseAThrowawayRoot(t *testing.T) {
	seed := sha256.Sum256([]byte(devRootSeedPhrase))
	want := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)

	var pos posVectors
	readJSON(t, positiveVectors, &pos)
	var neg negVectors
	readJSON(t, negativeVectors, &neg)

	for _, f := range []struct{ path, rootPub string }{
		{positiveVectors, pos.RootPub},
		{negativeVectors, neg.RootPub},
	} {
		got := mustB64(t, "root_pub", f.rootPub)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: root_pub is NOT the published development root.\n"+
				"This fixture must never be committed to a public repository until that is explained.\n"+
				"got  %x\nwant %x", f.path, got, want)
		}
	}
}

// TestPositiveVectors is the acceptance test: the frozen chain must verify at the
// fixture's own clock, yield exactly the fields the fixture names, and — the part
// that makes this conformance rather than a smoke test — the device-side signer
// must reproduce the frozen assertion BYTE FOR BYTE.
//
// The assertion is where two implementations most easily diverge while both
// "work": a verifier and signer that agree with each other but disagree with the
// spec's framing would pass every test either side wrote alone.
func TestPositiveVectors(t *testing.T) {
	var v posVectors
	readJSON(t, positiveVectors, &v)

	rootPub := ed25519.PublicKey(mustB64(t, "root_pub", v.RootPub))
	now := mustTime(t, v.Now)
	challenge := mustB64(t, "challenge", v.Challenge)
	wantAssertion := mustB64(t, "assertion", v.Assertion)

	// The device half: re-sign the fixture's own challenge with the fixture's own
	// device seed and require the exact frozen bytes back.
	seed := mustB64(t, "device_seed", v.DeviceSeed)
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("device_seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	devPriv := ed25519.NewKeyFromSeed(seed)
	gotAssertion, err := devicecred.SignAssertion(devPriv, devicecred.PurposeConnect, v.Audience, challenge)
	if err != nil {
		t.Fatalf("SignAssertion: %v", err)
	}
	if !bytes.Equal(gotAssertion, wantAssertion) {
		t.Fatalf("assertion not reproduced byte for byte:\ngot  %x\nwant %x", gotAssertion, wantAssertion)
	}

	// The verifier half, against the FROZEN assertion rather than the one just
	// produced, so a signer that drifted in lockstep with the verifier is still
	// caught by the comparison above and this stays an independent check.
	p, err := devicecred.ParsePresentation(v.DeviceCred, v.IssuerCert, wantAssertion)
	if err != nil {
		t.Fatalf("ParsePresentation: %v", err)
	}
	ver, err := devicecred.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cred, err := ver.Verify(p, now, v.Audience, challenge)
	if err != nil {
		t.Fatalf("Verify rejected the frozen positive chain: %v", err)
	}

	if got := base64.StdEncoding.EncodeToString(cred.DevicePub); got != v.ExpectDevicePub {
		t.Errorf("device pub = %s, want %s", got, v.ExpectDevicePub)
	}
	if cred.Epoch != v.ExpectEpoch {
		t.Errorf("epoch = %d, want %d", cred.Epoch, v.ExpectEpoch)
	}
	if cred.Serial != v.ExpectSerial {
		t.Errorf("serial = %q, want %q", cred.Serial, v.ExpectSerial)
	}

	cert, err := devicecred.VerifyIssuerCert(rootPub, p.IssuerCert, now, nil)
	if err != nil {
		t.Fatalf("VerifyIssuerCert rejected the frozen issuer cert: %v", err)
	}
	if cert.Serial != v.ExpectCertSerial {
		t.Errorf("cert serial = %q, want %q", cert.Serial, v.ExpectCertSerial)
	}
}

// negErrors maps each expect_error name in the negative fixture to the sentinel
// this package must report. A case naming an error absent from this table fails
// loudly rather than being skipped — an unmapped name is a fixture that grew a
// case this verifier has never been shown to handle.
var negErrors = map[string]error{
	"bad_assertion":       devicecred.ErrBadAssertion,
	"bad_signature":       devicecred.ErrBadSignature,
	"cred_ttl_too_long":   devicecred.ErrCredTTLTooLong,
	"expired":             devicecred.ErrExpired,
	"malformed":           devicecred.ErrMalformed,
	"not_yet_valid":       devicecred.ErrNotYetValid,
	"revoked":             devicecred.ErrRevoked,
	"unsupported_version": devicecred.ErrUnsupportedVersion,
}

// TestNegativeVectors is the file that decides whether this is a verifier. Every
// case must be REFUSED, and refused with the error its case names — a verifier
// that accepts everything passes every positive vector there is, and one that
// refuses everything for the wrong reason is not much better, because the reason
// is what an operator acts on.
func TestNegativeVectors(t *testing.T) {
	var v negVectors
	readJSON(t, negativeVectors, &v)
	if len(v.Cases) == 0 {
		t.Fatal("negative vectors file carries no cases")
	}
	rootPub := ed25519.PublicKey(mustB64(t, "root_pub", v.RootPub))

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want, ok := negErrors[c.ExpectError]
			if !ok {
				t.Fatalf("fixture names error %q, which this test does not map to a sentinel", c.ExpectError)
			}

			revoked := func(string) bool { return false }
			if c.RevokedSerial != "" {
				serial := c.RevokedSerial
				revoked = func(s string) bool { return s == serial }
			}
			ver, err := devicecred.NewVerifier(rootPub, revoked)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			// An envelope that will not decode IS the refusal — the empty-object cases
			// arrive this way — so it is matched against the same expectation rather
			// than being treated as a broken fixture.
			p, err := devicecred.ParsePresentation(c.DeviceCred, c.IssuerCert, mustB64(t, "assertion", c.Assertion))
			if err == nil {
				_, err = ver.Verify(p, mustTime(t, c.Now), c.Audience, mustB64(t, "challenge", c.Challenge))
			}
			if err == nil {
				t.Fatalf("ACCEPTED a chain that must be refused (want %v)", want)
			}
			if !errors.Is(err, want) {
				t.Fatalf("refused with the wrong reason:\ngot  %v\nwant %v", err, want)
			}
		})
	}
}

// TestNegativeVectorsCoverEveryRefusalPath guards the fixture itself: every
// sentinel this package can report on the connect path must be exercised by at
// least one frozen case. Without it, a case set could quietly lose its only
// revocation or TTL case and the suite would still be green.
func TestNegativeVectorsCoverEveryRefusalPath(t *testing.T) {
	var v negVectors
	readJSON(t, negativeVectors, &v)

	seen := map[string]int{}
	for _, c := range v.Cases {
		seen[c.ExpectError]++
	}
	for name := range negErrors {
		if seen[name] == 0 {
			t.Errorf("no frozen case exercises %q", name)
		}
	}
	t.Logf("%d cases across %d refusal paths: %v", len(v.Cases), len(seen), seen)
}
