package update_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/update"
)

// The two files in testdata are FROZEN conformance fixtures for the
// `bacchus/update-manifest/v1` object.
//
// They are NOT the same kind of fixture as core/policy's and core/revocation's,
// and the difference is worth stating rather than inheriting. Those formats are
// signed by a private repository this module cannot import, so their vectors
// arrive as a copy and this side never regenerates them. This one's signer is
// cmd/release-sign, in this repository, so these bytes are minted here — which
// removes the cross-repo copy and does NOT remove what the fixtures are for:
//
//   - they pin the wire format against a change nobody meant to make. A field
//     renamed, a tag altered, a digest re-encoded: all of those keep every
//     round-trip test in this package green, because a suite that signs and then
//     verifies with the same build agrees with itself about anything.
//   - they are what an independent implementation — a rebuilder checking a release,
//     a second verifier in another language — consumes. The whole argument for
//     content addressing is that anyone may hold and check these bytes.
//
// Regenerate with `go test ./core/update -update`, and expect a diff ONLY when the
// format was meant to change. Everything is derived from fixed seeds and fixed
// timestamps, so an unrelated run produces byte-identical files.
const (
	positiveVectors = "testdata/vectors.json"
	negativeVectors = "testdata/negative_vectors.json"
)

var updateVectors = flag.Bool("update", false, "regenerate the frozen conformance vectors in testdata")

// Fixed inputs. Every key here is a published throwaway derived from a constant in
// this file, and TestVectorsUseAThrowawayRoot re-proves that the anchor is the
// development root rather than trusting the note in the file — these bytes live in
// a PUBLIC repository, and "the fixture says it is a test key" is exactly what a
// leaked real key would also say.
const (
	vectorSignerPhrase = "BACCHUS UPDATE MANIFEST CONFORMANCE SIGNER - PUBLIC THROWAWAY"
	vectorOtherPhrase  = "BACCHUS UPDATE MANIFEST CONFORMANCE OUTSIDER - PUBLIC THROWAWAY"
	vectorSerial       = "0f1e2d3c4b5a6978"
	vectorOtherSerial  = "99887766"
)

var (
	vectorNow     = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	vectorIssued  = vectorNow.Add(-2 * time.Hour)
	vectorExpires = vectorNow.Add(60 * 24 * time.Hour)
	vectorNbf     = vectorNow.Add(-24 * time.Hour)
	vectorNaf     = vectorNow.Add(365 * 24 * time.Hour)
)

type posVectors struct {
	Note    string          `json:"note"`
	Now     string          `json:"now"`
	RootPub string          `json:"root_pub"`
	Bundle  json.RawMessage `json:"bundle"`

	// SignerSeed regenerates the manifest bytes and is an input to REGENERATION
	// only, never to verification — a verifier learns the signer's key from the
	// delegation cert.
	SignerSeed string `json:"signer_seed"`

	ExpectRelease          string `json:"expect_release"`
	ExpectSeq              uint64 `json:"expect_seq"`
	ExpectArtifacts        int    `json:"expect_artifacts"`
	ExpectNodeDigest       string `json:"expect_node_digest"`
	ExpectSignerPub        string `json:"expect_signer_pub"`
	ExpectDelegationSerial string `json:"expect_delegation_serial"`
}

type negCase struct {
	Name          string          `json:"name"`
	Bundle        json.RawMessage `json:"bundle"`
	Now           string          `json:"now"`
	MinSeq        uint64          `json:"min_seq"`
	RevokedSerial string          `json:"revoked_serial,omitempty"`
	ExpectError   string          `json:"expect_error"`
}

type negVectors struct {
	Note    string    `json:"note"`
	RootPub string    `json:"root_pub"`
	Cases   []negCase `json:"cases"`
}

// negTokenErr maps the stable token in expect_error to the sentinel it names. The
// file holds tokens rather than Go error strings so a port in another language can
// consume it, and so a reworded message is not a fixture change.
//
// The split is core/policy's and core/revocation's: an error about the DELEGATION
// is a delegation-package fact, one about the MANIFEST is this package's.
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
		return update.ErrRollback, true
	case "unsupported_version":
		return update.ErrUnsupportedVersion, true
	case "malformed":
		return update.ErrMalformed, true
	case "invalid":
		return update.ErrInvalid, true
	case "expired":
		return update.ErrExpired, true
	case "not_yet_issued":
		return update.ErrNotYetIssued, true
	default:
		return nil, false
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

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

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("regenerated %s", path)
}

// vectorManifest is the one manifest both fixtures are built from. Two artifacts,
// so a fixture that silently lost a row is visible in expect_artifacts.
func vectorManifest() update.Manifest {
	node := sha256.Sum256([]byte("BACCHUS CONFORMANCE ARTIFACT: linux/amd64 node"))
	client := sha256.Sum256([]byte("BACCHUS CONFORMANCE ARTIFACT: windows/amd64 client"))
	return update.Manifest{
		Version: update.Version,
		Seq:     42,
		Release: "1.2.3",
		Issued:  vectorIssued,
		Expires: vectorExpires,
		Note:    "conformance fixture; not a release",
		Artifacts: []update.Artifact{
			{OS: "linux", Arch: "amd64", Role: update.RoleNode, Size: 20_918_272, SHA256: node[:]},
			{OS: "windows", Arch: "amd64", Role: update.RoleClient, Size: 41_285_632, SHA256: client[:]},
		},
	}
}

func regenerate(t *testing.T) {
	t.Helper()
	root := devRootKey()
	rootPub := root.Public().(ed25519.PublicKey)
	signer := keyFromPhrase(vectorSignerPhrase)
	signerPub := signer.Public().(ed25519.PublicKey)
	other := keyFromPhrase(vectorOtherPhrase)
	otherPub := other.Public().(ed25519.PublicKey)

	cert := mintCert(t, root, signerPub, delegation.RoleUpdate, vectorSerial, vectorNbf, vectorNaf)
	m := vectorManifest()
	signed, err := update.Sign(signer, m)
	if err != nil {
		t.Fatalf("sign the fixture manifest: %v", err)
	}
	good := update.Bundle{Manifest: signed, Cert: cert}
	goodRaw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}

	writeJSON(t, positiveVectors, posVectors{
		Note: "FROZEN conformance vector for bacchus/update-manifest/v1 (issue #34, ADR-0052, ADR-0065). " +
			"Every key here is a PUBLIC THROWAWAY: the root is bacchus-payment's published development root and " +
			"the signer is derived from signer_seed. No real key material appears in this repository.",
		Now:                    vectorNow.Format(time.RFC3339),
		RootPub:                b64(rootPub),
		Bundle:                 goodRaw,
		SignerSeed:             vectorSignerPhrase,
		ExpectRelease:          m.Release,
		ExpectSeq:              m.Seq,
		ExpectArtifacts:        len(m.Artifacts),
		ExpectNodeDigest:       m.Artifacts[0].Name(),
		ExpectSignerPub:        b64(signerPub),
		ExpectDelegationSerial: vectorSerial,
	})

	raw := func(b update.Bundle) json.RawMessage {
		j, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	// A body signed by hand, for the cases update.Sign would refuse to produce.
	handSign := func(mm update.Manifest, key ed25519.PrivateKey, tag string) []byte {
		body, err := json.Marshal(mm)
		if err != nil {
			t.Fatal(err)
		}
		return signObject(t, key, tag, body)
	}

	tamperedBody := append([]byte(nil), signed...)
	tamperedBody[10] ^= 0x01
	tamperedSig := append([]byte(nil), signed...)
	tamperedSig[len(tamperedSig)-1] ^= 0x01

	badVersion := m
	badVersion.Version = 99
	dup := m
	dup.Artifacts = []update.Artifact{m.Artifacts[0], m.Artifacts[0]}
	badRelease := m
	badRelease.Release = "1.2"

	cases := []negCase{
		{Name: "tampered_manifest_body", Bundle: raw(update.Bundle{Manifest: tamperedBody, Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "bad_signature"},
		{Name: "tampered_manifest_signature", Bundle: raw(update.Bundle{Manifest: tamperedSig, Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "bad_signature"},
		{Name: "unsigned_manifest_body", Bundle: raw(update.Bundle{Manifest: mustMarshal(t, m), Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "bad_signature"},
		{Name: "signed_by_an_undelegated_key", Bundle: raw(update.Bundle{Manifest: handSign(m, other, delegation.TagUpdateManifest), Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "bad_signature"},
		{Name: "signed_under_the_policy_tag", Bundle: raw(update.Bundle{Manifest: handSign(m, signer, delegation.TagPolicyDoc), Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "bad_signature"},
		{Name: "cert_for_the_policy_role", Bundle: raw(update.Bundle{Manifest: signed, Cert: mintCert(t, root, signerPub, delegation.RolePolicy, vectorSerial, vectorNbf, vectorNaf)}), Now: vectorNow.Format(time.RFC3339), ExpectError: "wrong_role"},
		{Name: "cert_for_the_revocations_role", Bundle: raw(update.Bundle{Manifest: signed, Cert: mintCert(t, root, signerPub, delegation.RoleRevocations, vectorSerial, vectorNbf, vectorNaf)}), Now: vectorNow.Format(time.RFC3339), ExpectError: "wrong_role"},
		{Name: "cert_from_another_root", Bundle: raw(update.Bundle{Manifest: signed, Cert: mintCert(t, other, signerPub, delegation.RoleUpdate, vectorOtherSerial, vectorNbf, vectorNaf)}), Now: vectorNow.Format(time.RFC3339), ExpectError: "bad_signature"},
		{Name: "expired_delegation", Bundle: raw(update.Bundle{Manifest: signed, Cert: mintCert(t, root, signerPub, delegation.RoleUpdate, vectorSerial, vectorNow.Add(-72*time.Hour), vectorNow.Add(-time.Hour))}), Now: vectorNow.Format(time.RFC3339), ExpectError: "delegation_expired"},
		{Name: "revoked_delegation", Bundle: raw(good), Now: vectorNow.Format(time.RFC3339), RevokedSerial: vectorSerial, ExpectError: "delegation_revoked"},
		{Name: "malformed_delegation", Bundle: raw(update.Bundle{Manifest: signed, Cert: []byte("not a cert")}), Now: vectorNow.Format(time.RFC3339), ExpectError: "delegation_malformed"},
		{Name: "rollback_below_the_floor", Bundle: raw(good), Now: vectorNow.Format(time.RFC3339), MinSeq: m.Seq + 1, ExpectError: "rollback"},
		{Name: "expired_manifest", Bundle: raw(good), Now: vectorExpires.Add(time.Second).Format(time.RFC3339), ExpectError: "expired"},
		{Name: "manifest_from_the_future", Bundle: raw(good), Now: vectorIssued.Add(-time.Hour).Format(time.RFC3339), ExpectError: "not_yet_issued"},
		{Name: "unknown_format_version", Bundle: raw(update.Bundle{Manifest: handSign(badVersion, signer, delegation.TagUpdateManifest), Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "unsupported_version"},
		{Name: "two_rows_for_one_build", Bundle: raw(update.Bundle{Manifest: handSign(dup, signer, delegation.TagUpdateManifest), Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "invalid"},
		{Name: "release_that_is_not_semver", Bundle: raw(update.Bundle{Manifest: handSign(badRelease, signer, delegation.TagUpdateManifest), Cert: cert}), Now: vectorNow.Format(time.RFC3339), ExpectError: "invalid"},
		{Name: "bundle_missing_the_cert", Bundle: json.RawMessage(`{"manifest":"` + b64(signed) + `"}`), Now: vectorNow.Format(time.RFC3339), ExpectError: "malformed"},
	}

	writeJSON(t, negativeVectors, negVectors{
		Note: "FROZEN refusals for bacchus/update-manifest/v1. A verifier that accepts everything passes " +
			"vectors.json and dies here. Matching the SPECIFIC token matters as much as refusing: a port that " +
			"collapsed every refusal into one sentinel would leave an operator unable to tell a revoked " +
			"delegation from a rollback.",
		RootPub: b64(rootPub),
		Cases:   cases,
	})
	_ = otherPub
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRegenerateVectors(t *testing.T) {
	if !*updateVectors {
		t.Skip("pass -update to regenerate the frozen vectors")
	}
	regenerate(t)
}

// TestPositiveWireVector is the acceptance half: the frozen bundle must be
// ACCEPTED, at its own `now` and a cold-start floor, by a verifier holding
// root_pub alone, and every expect_* value must be what this build reads out of it.
func TestPositiveWireVector(t *testing.T) {
	var pv posVectors
	readJSON(t, positiveVectors, &pv)

	rootPub := unb64(t, pv.RootPub)
	now, err := time.Parse(time.RFC3339, pv.Now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := update.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	b, err := update.ParseBundle(pv.Bundle)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	m, err := v.Verify(b, now, 0)
	if err != nil {
		t.Fatalf("Verify REFUSED the frozen positive bundle: %v", err)
	}
	if m.Release != pv.ExpectRelease {
		t.Errorf("release = %q, want %q", m.Release, pv.ExpectRelease)
	}
	if m.Seq != pv.ExpectSeq {
		t.Errorf("seq = %d, want %d", m.Seq, pv.ExpectSeq)
	}
	if len(m.Artifacts) != pv.ExpectArtifacts {
		t.Fatalf("artifacts = %d, want %d", len(m.Artifacts), pv.ExpectArtifacts)
	}
	node, err := m.Find("linux", "amd64", update.RoleNode)
	if err != nil {
		t.Fatalf("Find(linux/amd64 node): %v", err)
	}
	if node.Name() != pv.ExpectNodeDigest {
		t.Errorf("node artifact digest = %s, want %s", node.Name(), pv.ExpectNodeDigest)
	}

	cert, err := delegation.VerifyDelegationCert(rootPub, b.Cert, delegation.RoleUpdate, now, nil)
	if err != nil {
		t.Fatalf("VerifyDelegationCert: %v", err)
	}
	if cert.Serial != pv.ExpectDelegationSerial {
		t.Errorf("delegation serial = %q, want %q", cert.Serial, pv.ExpectDelegationSerial)
	}
	if got := b64(cert.Pub); got != pv.ExpectSignerPub {
		t.Errorf("signer pub = %q, want %q", got, pv.ExpectSignerPub)
	}
}

// TestNegativeWireVectors is the half that makes conformance mean something.
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
			now, err := time.Parse(time.RFC3339, c.Now)
			if err != nil {
				t.Fatal(err)
			}
			var revoked func(string) bool
			if c.RevokedSerial != "" {
				revoked = func(serial string) bool { return serial == c.RevokedSerial }
			}
			v, err := update.NewVerifier(rootPub, revoked)
			if err != nil {
				t.Fatalf("build verifier: %v", err)
			}
			b, err := update.ParseBundle(c.Bundle)
			if err != nil {
				// A bundle this malformed never reaches Verify. That is still a refusal,
				// and only the malformed token may claim it.
				if errors.Is(err, want) {
					return
				}
				t.Fatalf("ParseBundle = %v, want %v", err, want)
			}
			m, err := v.Verify(b, now, c.MinSeq)
			if err == nil {
				t.Fatalf("Verify ACCEPTED a bundle that must be refused (parsed release %s)", m.Release)
			}
			if !errors.Is(err, want) {
				t.Fatalf("Verify = %v, want %v", err, want)
			}
		})
	}
}

// TestNegativeVectorsCoverEveryRefusalToken guards the fixture itself: a future
// regeneration that silently dropped every rollback case would leave the suite
// above green with nothing to say about rollback.
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
		"invalid", "expired", "not_yet_issued",
	} {
		if seen[token] == 0 {
			t.Errorf("no negative case exercises %q", token)
		}
	}
	if len(nv.Cases) < 18 {
		t.Errorf("negative fixture has %d cases, expected at least the frozen 18", len(nv.Cases))
	}
}

// TestVectorsUseAThrowawayRoot proves the trust anchor in testdata is the
// published development root and not a real one.
//
// This is a PUBLIC repository. The fixtures carry a root public key and a note
// claiming it is a throwaway — a note is exactly what a leaked real key would also
// carry — so this recomputes the development root from its published seed phrase
// and requires the fixture to match it. If a future fixture ever chains to a root
// whose private key is not public, this fails, loudly, in CI, before the bytes are
// trusted.
func TestVectorsUseAThrowawayRoot(t *testing.T) {
	want := b64(devRootKey().Public().(ed25519.PublicKey))

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
	// The signer too: its seed phrase is in the file, so anyone can re-derive it and
	// confirm the key it names is the one that signed.
	if pv.SignerSeed != vectorSignerPhrase {
		t.Errorf("the fixture's signer_seed is not the published phrase")
	}
	if got := b64(keyFromPhrase(pv.SignerSeed).Public().(ed25519.PublicKey)); got != pv.ExpectSignerPub {
		t.Errorf("the fixture's signer key is not derivable from its own published seed phrase")
	}
}
