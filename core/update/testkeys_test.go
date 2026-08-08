package update_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/update"
)

// The signing side of a delegation cert is the offline root's and lives outside
// this repository — core/delegation's own doc says so, and its test explains why:
// "a public coordinator that could mint delegations would defeat the entire
// arrangement." These helpers mint certs for TESTS only, from keys generated in
// the test process, which is the same thing core/policy's and core/revocation's
// suites do.
//
// Nothing here is a key handling procedure and none of it appears outside _test
// files.

// devRootSeedPhrase is the published constant bacchus-payment's development root
// key is derived from (internal/devroot.SeedPhrase) — the same throwaway root
// core/policy's and core/revocation's frozen vectors chain to. Reproduced here so
// the frozen vectors in testdata can be PROVED to chain to a root whose private
// half is public, which is the only kind of anchor that may appear in a public
// repository.
const devRootSeedPhrase = "BACCHUS DEVELOPMENT ROOT - PUBLIC THROWAWAY KEY - NOT A REAL ROOT - DO NOT USE IN PRODUCTION"

func devRootKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(devRootSeedPhrase))
	return ed25519.NewKeyFromSeed(seed[:])
}

// keyFromPhrase derives a deterministic throwaway ed25519 key from a phrase, so
// the frozen vectors regenerate byte-identically.
func keyFromPhrase(phrase string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(phrase))
	return ed25519.NewKeyFromSeed(seed[:])
}

// signObject signs body under tag with priv, producing the body || sig framing
// core/delegation.OpenSigned checks.
func signObject(t *testing.T, priv ed25519.PrivateKey, tag string, body []byte) []byte {
	t.Helper()
	msg := make([]byte, 0, len(tag)+1+len(body))
	msg = append(msg, tag...)
	msg = append(msg, 0x00)
	msg = append(msg, body...)
	return append(append([]byte(nil), body...), ed25519.Sign(priv, msg)...)
}

// mintCert mints a delegation cert for role, signed by root.
func mintCert(t *testing.T, root ed25519.PrivateKey, signerPub ed25519.PublicKey, role delegation.Role, serial string, nbf, exp time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(delegation.Cert{
		Version:   delegation.Version,
		Serial:    serial,
		Role:      role,
		Pub:       signerPub,
		NotBefore: nbf,
		NotAfter:  exp,
		Note:      "test",
	})
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	return signObject(t, root, delegation.TagDelegationCert, body)
}

// chain is a complete test signing setup: a root, an update signer, and the cert
// binding them.
type chain struct {
	root      ed25519.PrivateKey
	rootPub   ed25519.PublicKey
	signer    ed25519.PrivateKey
	signerPub ed25519.PublicKey
	cert      []byte
	serial    string
}

func newChain(t *testing.T, now time.Time) chain {
	t.Helper()
	rootPub, root, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	signerPub, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	c := chain{root: root, rootPub: rootPub, signer: signer, signerPub: signerPub, serial: "a1b2c3"}
	c.cert = mintCert(t, root, signerPub, delegation.RoleUpdate, c.serial, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	return c
}

// bundle signs m under the chain's update key and wraps it with the chain's cert.
func (c chain) bundle(t *testing.T, m update.Manifest) update.Bundle {
	t.Helper()
	signed, err := update.Sign(c.signer, m)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	return update.Bundle{Manifest: signed, Cert: c.cert}
}

// sampleManifest is a valid manifest for one artifact of the given bytes.
func sampleManifest(release string, seq uint64, now time.Time, artifacts ...update.Artifact) update.Manifest {
	return update.Manifest{
		Version:   update.Version,
		Seq:       seq,
		Release:   release,
		Issued:    now.Add(-time.Minute),
		Expires:   now.Add(30 * 24 * time.Hour),
		Note:      "test release",
		Artifacts: artifacts,
	}
}

// artifactOf describes payload as an artifact row.
func artifactOf(goos, goarch, role string, payload []byte) update.Artifact {
	sum := sha256.Sum256(payload)
	return update.Artifact{OS: goos, Arch: goarch, Role: role, Size: int64(len(payload)), SHA256: sum[:]}
}
