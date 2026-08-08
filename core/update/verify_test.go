package update_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/update"
)

var testNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func mustVerifier(t *testing.T, rootPub ed25519.PublicKey, revoked func(string) bool) *update.Verifier {
	t.Helper()
	v, err := update.NewVerifier(rootPub, revoked)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerifyAcceptsASignedManifest(t *testing.T) {
	c := newChain(t, testNow)
	m := sampleManifest("0.5.0", 7, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("binary")))
	b := c.bundle(t, m)

	got, err := mustVerifier(t, c.rootPub, nil).Verify(b, testNow, 0)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Release != "0.5.0" || got.Seq != 7 || len(got.Artifacts) != 1 {
		t.Fatalf("Verify returned %+v", got)
	}
}

// The refusals. A verifier that accepts everything passes the test above and dies
// here, which is the only reason that one means anything.
func TestVerifyRefusals(t *testing.T) {
	c := newChain(t, testNow)
	good := sampleManifest("0.5.0", 7, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("binary")))

	// A second, unrelated root: the "signed by the wrong key" case the card names.
	otherPub, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPub

	cases := []struct {
		name    string
		bundle  func(t *testing.T) update.Bundle
		now     time.Time
		minSeq  uint64
		revoked func(string) bool
		want    error
	}{
		{
			name: "a flipped byte in the manifest body",
			bundle: func(t *testing.T) update.Bundle {
				b := c.bundle(t, good)
				b.Manifest[0] ^= 0x01
				return b
			},
			now:  testNow,
			want: delegation.ErrBadSignature,
		},
		{
			name: "a flipped byte in the signature",
			bundle: func(t *testing.T) update.Bundle {
				b := c.bundle(t, good)
				b.Manifest[len(b.Manifest)-1] ^= 0x01
				return b
			},
			now:  testNow,
			want: delegation.ErrBadSignature,
		},
		{
			name: "signed by a key the root never delegated to",
			bundle: func(t *testing.T) update.Bundle {
				signed, err := update.Sign(otherPriv, good)
				if err != nil {
					t.Fatal(err)
				}
				return update.Bundle{Manifest: signed, Cert: c.cert}
			},
			now:  testNow,
			want: delegation.ErrBadSignature,
		},
		{
			name: "a cert for the POLICY role, not update",
			bundle: func(t *testing.T) update.Bundle {
				cert := mintCert(t, c.root, c.signerPub, delegation.RolePolicy, "p1", testNow.Add(-time.Hour), testNow.Add(time.Hour))
				b := c.bundle(t, good)
				b.Cert = cert
				return b
			},
			now:  testNow,
			want: delegation.ErrWrongRole,
		},
		{
			name: "a cert signed by a different root",
			bundle: func(t *testing.T) update.Bundle {
				cert := mintCert(t, otherPriv, c.signerPub, delegation.RoleUpdate, "x1", testNow.Add(-time.Hour), testNow.Add(time.Hour))
				b := c.bundle(t, good)
				b.Cert = cert
				return b
			},
			now:  testNow,
			want: delegation.ErrBadSignature,
		},
		{
			name: "an expired delegation",
			bundle: func(t *testing.T) update.Bundle {
				cert := mintCert(t, c.root, c.signerPub, delegation.RoleUpdate, "e1", testNow.Add(-48*time.Hour), testNow.Add(-time.Hour))
				b := c.bundle(t, good)
				b.Cert = cert
				return b
			},
			now:  testNow,
			want: delegation.ErrExpired,
		},
		{
			name:    "a revoked delegation",
			bundle:  func(t *testing.T) update.Bundle { return c.bundle(t, good) },
			now:     testNow,
			revoked: func(serial string) bool { return serial == c.serial },
			want:    delegation.ErrRevoked,
		},
		{
			name:   "a manifest below the accepted sequence floor",
			bundle: func(t *testing.T) update.Bundle { return c.bundle(t, good) },
			now:    testNow,
			minSeq: 8,
			want:   update.ErrRollback,
		},
		{
			name:   "an expired manifest",
			bundle: func(t *testing.T) update.Bundle { return c.bundle(t, good) },
			now:    testNow.Add(31 * 24 * time.Hour),
			want:   update.ErrExpired,
		},
		{
			name:   "a manifest from the future",
			bundle: func(t *testing.T) update.Bundle { return c.bundle(t, good) },
			now:    testNow.Add(-time.Hour),
			want:   update.ErrNotYetIssued,
		},
		{
			name: "a manifest at an unknown format version",
			bundle: func(t *testing.T) update.Bundle {
				m := good
				m.Version = 2
				// Sign refuses an invalid manifest, so this one is framed by hand.
				body, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				return update.Bundle{Manifest: signObject(t, c.signer, delegation.TagUpdateManifest, body), Cert: c.cert}
			},
			now:  testNow,
			want: update.ErrUnsupportedVersion,
		},
		{
			name: "a manifest with two rows for one build",
			bundle: func(t *testing.T) update.Bundle {
				m := good
				m.Artifacts = []update.Artifact{
					artifactOf("linux", "amd64", update.RoleNode, []byte("one")),
					artifactOf("linux", "amd64", update.RoleNode, []byte("two")),
				}
				body, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				return update.Bundle{Manifest: signObject(t, c.signer, delegation.TagUpdateManifest, body), Cert: c.cert}
			},
			now:  testNow,
			want: update.ErrInvalid,
		},
		{
			// Reached only by a caller that built a Bundle in Go; over the wire
			// ParseBundle refuses this first (TestParseBundleRefusesAnIncompleteBundle).
			// The sentinel is the DELEGATION package's, because an absent cert is a fact
			// about the delegation and not about the manifest.
			name: "a bundle with no cert",
			bundle: func(t *testing.T) update.Bundle {
				b := c.bundle(t, good)
				b.Cert = nil
				return b
			},
			now:  testNow,
			want: delegation.ErrMalformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.bundle(t)
			v := mustVerifier(t, c.rootPub, tc.revoked)
			got, err := v.Verify(b, tc.now, tc.minSeq)
			if err == nil {
				t.Fatalf("Verify ACCEPTED a manifest that must be refused (release %s seq %d)", got.Release, got.Seq)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// A bundle with an empty member never reaches Verify; ParseBundle refuses it, and
// only the malformed sentinel may claim that refusal.
func TestParseBundleRefusesAnIncompleteBundle(t *testing.T) {
	for _, raw := range []string{
		`{"manifest":"","cert":"AAAA"}`,
		`{"cert":"AAAA"}`,
		`{"manifest":"AAAA"}`,
		`not json`,
		`{}`,
	} {
		if _, err := update.ParseBundle([]byte(raw)); !errors.Is(err, update.ErrMalformed) {
			t.Errorf("ParseBundle(%q) = %v, want ErrMalformed", raw, err)
		}
	}
}

func TestNewVerifierFailsClosedWithoutARoot(t *testing.T) {
	for _, pub := range []ed25519.PublicKey{nil, make([]byte, 16)} {
		if _, err := update.NewVerifier(pub, nil); !errors.Is(err, delegation.ErrNoRoot) {
			t.Errorf("NewVerifier(%d-byte key) = %v, want ErrNoRoot", len(pub), err)
		}
	}
}

// Re-reading the SAME manifest is the steady state and must not be a rollback: a
// peer that checks twice has not been attacked.
func TestVerifyAcceptsTheSameSequenceTwice(t *testing.T) {
	c := newChain(t, testNow)
	b := c.bundle(t, sampleManifest("0.5.0", 7, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("x"))))
	v := mustVerifier(t, c.rootPub, nil)
	if _, err := v.Verify(b, testNow, 7); err != nil {
		t.Fatalf("Verify at a floor equal to the manifest's own seq = %v, want accept", err)
	}
	if _, err := v.Verify(b, testNow, 8); !errors.Is(err, update.ErrRollback) {
		t.Fatalf("Verify one past the manifest's seq = %v, want ErrRollback", err)
	}
}

// The property the tag registry exists for: a signature made over one object class
// must not verify as another. A policy document body signed by a key delegated for
// the update role must still not open as an update manifest.
func TestManifestSignatureIsNotReplayableAcrossTags(t *testing.T) {
	c := newChain(t, testNow)
	m := sampleManifest("0.5.0", 7, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("x")))
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// The very same body, signed under the POLICY document's tag by the very same
	// update key.
	crossSigned := signObject(t, c.signer, delegation.TagPolicyDoc, body)
	b := update.Bundle{Manifest: crossSigned, Cert: c.cert}
	if _, err := mustVerifier(t, c.rootPub, nil).Verify(b, testNow, 0); !errors.Is(err, delegation.ErrBadSignature) {
		t.Fatalf("a manifest signed under the policy tag verified as an update manifest: %v", err)
	}
	// And the same bytes under the right tag do verify, so the case above failed for
	// the tag and not for some unrelated reason.
	if _, err := mustVerifier(t, c.rootPub, nil).Verify(update.Bundle{Manifest: signObject(t, c.signer, delegation.TagUpdateManifest, body), Cert: c.cert}, testNow, 0); err != nil {
		t.Fatalf("the same body under the update tag = %v, want accept", err)
	}
}

// Sign and Verify must agree about the framing byte for byte. Sign reproduces
// core/delegation's signing message because that package exports only the opening
// half; this is what pins the copy.
func TestSignedManifestOpensUnderTheDelegationFraming(t *testing.T) {
	c := newChain(t, testNow)
	m := sampleManifest("0.5.0", 1, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("x")))
	signed, err := update.Sign(c.signer, m)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	body, err := delegation.OpenSigned(c.signerPub, delegation.TagUpdateManifest, signed)
	if err != nil {
		t.Fatalf("OpenSigned on a manifest this package signed: %v", err)
	}
	var round update.Manifest
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("the opened body is not a manifest: %v", err)
	}
	if round.Release != m.Release || round.Seq != m.Seq {
		t.Fatalf("round trip changed the manifest: %+v", round)
	}
}

// The signer refuses what the verifier tolerates. An unknown field is an
// operator's typo at authoring time and an additive field at verifying time.
func TestSignRefusesAnUnknownField(t *testing.T) {
	c := newChain(t, testNow)
	m := sampleManifest("0.5.0", 1, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("x")))
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	withExtra := bytes.Replace(body, []byte(`{"v":`), []byte(`{"sha_256":"typo","v":`), 1)
	if _, err := update.SignBody(c.signer, withExtra); !errors.Is(err, update.ErrInvalid) {
		t.Fatalf("SignBody on a body with an unknown field = %v, want ErrInvalid", err)
	}
	// And the verifier accepts the same shape, because refusing it there would brick
	// every peer that had not shipped the new field yet.
	signedWithExtra := signObject(t, c.signer, delegation.TagUpdateManifest, withExtra)
	if _, err := mustVerifier(t, c.rootPub, nil).Verify(update.Bundle{Manifest: signedWithExtra, Cert: c.cert}, testNow, 0); err != nil {
		t.Fatalf("Verify refused an additive field: %v", err)
	}
}

// SignBody signs the bytes it was given, unchanged. The offline procedure authors
// a manifest and then signs it; re-marshaling would put this code between what was
// reviewed and what was signed.
func TestSignBodySignsTheBytesItWasGiven(t *testing.T) {
	c := newChain(t, testNow)
	m := sampleManifest("0.5.0", 1, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("x")))
	pretty, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := update.SignBody(c.signer, pretty)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}
	if !bytes.HasPrefix(signed, pretty) {
		t.Fatal("SignBody re-marshaled the body instead of signing it verbatim")
	}
	if _, err := mustVerifier(t, c.rootPub, nil).Verify(update.Bundle{Manifest: signed, Cert: c.cert}, testNow, 0); err != nil {
		t.Fatalf("Verify on an indented body: %v", err)
	}
}

func TestValidateRejectsAPathInAnArtifactField(t *testing.T) {
	for _, bad := range []string{"../../etc", "lin/ux", "LINUX", "lin ux", ""} {
		m := sampleManifest("0.5.0", 1, testNow, artifactOf(bad, "amd64", update.RoleNode, []byte("x")))
		if err := m.Validate(); !errors.Is(err, update.ErrInvalid) {
			t.Errorf("Validate with os=%q = %v, want ErrInvalid", bad, err)
		}
	}
	// And the artifact's name never contains one whatever the row said, because it is
	// hex of a digest.
	a := artifactOf("linux", "amd64", update.RoleNode, []byte("x"))
	if strings.ContainsAny(a.Name(), "/\\.") {
		t.Fatalf("artifact name %q is not pure hex", a.Name())
	}
}

func TestValidateRejectsAnUnknownRole(t *testing.T) {
	m := sampleManifest("0.5.0", 1, testNow, artifactOf("linux", "amd64", "shell", []byte("x")))
	if err := m.Validate(); !errors.Is(err, update.ErrInvalid) {
		t.Fatalf("Validate with an unknown role = %v, want ErrInvalid", err)
	}
}

func TestValidateRejectsABadRelease(t *testing.T) {
	for _, bad := range []string{"", "1.0", "1.0.0-rc1", "v1.0.0", "1.0.01", "1.0.x"} {
		m := sampleManifest(bad, 1, testNow, artifactOf("linux", "amd64", update.RoleNode, []byte("x")))
		if err := m.Validate(); !errors.Is(err, update.ErrInvalid) {
			t.Errorf("Validate with release %q = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestFindPicksTheRowForThisBuild(t *testing.T) {
	m := sampleManifest("0.5.0", 1, testNow,
		artifactOf("linux", "amd64", update.RoleNode, []byte("linux-node")),
		artifactOf("windows", "amd64", update.RoleClient, []byte("windows-client")),
	)
	a, err := m.Find("windows", "amd64", update.RoleClient)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if a.Size != int64(len("windows-client")) {
		t.Fatalf("Find returned the wrong row: %+v", a)
	}
	if _, err := m.Find("darwin", "arm64", update.RoleClient); !errors.Is(err, update.ErrNoArtifact) {
		t.Fatalf("Find for a build the manifest omits = %v, want ErrNoArtifact", err)
	}
}
