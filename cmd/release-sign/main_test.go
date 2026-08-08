package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/update"
)

// The whole path, in one test: generate an update key, mint the delegation the
// root's ceremony would mint for it, author a manifest from real files, sign it,
// verify it, publish a source layout, and then have an Updater apply it to a
// target — asserting on the bytes at that target.
//
// It is one test rather than five because the failures this catches are all
// SEAMS: a signer and a verifier that disagree, a plan whose digest encoding the
// signer cannot read, a bundle nothing can consume. Each half passes its own unit
// test while the pair is broken.
func TestSignedReleaseIsProducedAndApplied(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "update.key")

	// 1. The update signing key. In production this happens on the air-gapped
	// machine and its public half goes to the root ceremony.
	if err := keygen([]string{"-out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("the signing key was written mode %#o, want 0600", mode)
	}
	priv, err := readKey(keyPath)
	if err != nil {
		t.Fatalf("readKey: %v", err)
	}

	// 2. The delegation the root would mint. Test-only: the root's private half
	// never exists in this repository outside a test process.
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "update.cert")
	writeCert(t, certPath, rootPriv, priv.Public().(ed25519.PublicKey), delegation.RoleUpdate, "beef01", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	rootHex := hex.EncodeToString(rootPub)

	// 3. The artifacts CI produced.
	nodeBytes := []byte("ELF-ish bytes for the node binary\n")
	nodePath := filepath.Join(dir, "bacchus-node")
	if err := os.WriteFile(nodePath, nodeBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	// 4. Author the manifest offline.
	bodyPath := filepath.Join(dir, "body.json")
	if err := plan([]string{
		"-artifact", "linux/amd64/node=" + nodePath,
		"-release", "1.2.3", "-seq", "5", "-days", "30",
		"-out", bodyPath,
	}); err != nil {
		t.Fatalf("plan: %v", err)
	}

	// 5. Sign it.
	bundlePath := filepath.Join(dir, update.ManifestName)
	if err := sign([]string{
		"-body", bodyPath, "-key", keyPath, "-cert", certPath,
		"-root", rootHex, "-out", bundlePath,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// 6. Publish the source layout and verify it the way a mirror operator would.
	src := filepath.Join(dir, "source")
	if err := os.MkdirAll(filepath.Join(src, update.BlobDir), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, update.ManifestName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := update.ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	v, err := update.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := v.Verify(b, time.Now(), 0)
	if err != nil {
		t.Fatalf("the signed bundle does not verify: %v", err)
	}
	a, err := m.Find("linux", "amd64", update.RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, update.BlobDir, a.Name()), nodeBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verify([]string{"-bundle", bundlePath, "-root", rootHex, "-dir", src}); err != nil {
		t.Fatalf("verify -dir: %v", err)
	}

	// 7. A node applies it. The target starts out holding something else, and the
	// assertion is on its bytes afterwards.
	target := filepath.Join(t.TempDir(), "bacchus-node")
	if err := os.WriteFile(target, []byte("the previous release\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	u, err := update.NewUpdater(update.Config{
		Root: rootPub, Source: update.NewDirSource(src), Target: target,
		Role: update.RoleNode, OS: "linux", Arch: "amd64",
		StatePath:      filepath.Join(t.TempDir(), "state.json"),
		CurrentRelease: "1.2.2",
		Log:            func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !out.Applied || out.Release != "1.2.3" {
		t.Fatalf("Check = %+v", out)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(nodeBytes) {
		t.Fatalf("the applied binary is %q, want the artifact bytes", got)
	}
}

// The two mistakes that would otherwise produce a perfectly formed release the
// whole fleet refuses, discovered after the ceremony by the fleet.
func TestSignRefusesAMismatchedDelegation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "update.key")
	if err := keygen([]string{"-out", keyPath}); err != nil {
		t.Fatal(err)
	}
	priv, err := readKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootHex := hex.EncodeToString(rootPub)

	nodePath := filepath.Join(dir, "bin")
	if err := os.WriteFile(nodePath, []byte("bytes\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(dir, "body.json")
	if err := plan([]string{"-artifact", "linux/amd64/node=" + nodePath, "-release", "1.0.0", "-seq", "1", "-out", bodyPath}); err != nil {
		t.Fatal(err)
	}

	t.Run("a cert for the policy role", func(t *testing.T) {
		certPath := filepath.Join(dir, "policy.cert")
		writeCert(t, certPath, rootPriv, priv.Public().(ed25519.PublicKey), delegation.RolePolicy, "p1", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		err := sign([]string{"-body", bodyPath, "-key", keyPath, "-cert", certPath, "-root", rootHex, "-out", filepath.Join(dir, "out1.json")})
		if err == nil || !strings.Contains(err.Error(), "role mismatch") {
			t.Fatalf("sign under a policy cert = %v, want a role mismatch", err)
		}
	})

	t.Run("a cert delegating to a different key", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		certPath := filepath.Join(dir, "other.cert")
		writeCert(t, certPath, rootPriv, otherPub, delegation.RoleUpdate, "o1", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		err = sign([]string{"-body", bodyPath, "-key", keyPath, "-cert", certPath, "-root", rootHex, "-out", filepath.Join(dir, "out2.json")})
		if err == nil || !strings.Contains(err.Error(), "delegates to a different key") {
			t.Fatalf("sign with a cert naming another key = %v, want a refusal", err)
		}
	})

	t.Run("an expired delegation", func(t *testing.T) {
		certPath := filepath.Join(dir, "expired.cert")
		writeCert(t, certPath, rootPriv, priv.Public().(ed25519.PublicKey), delegation.RoleUpdate, "x1", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
		err := sign([]string{"-body", bodyPath, "-key", keyPath, "-cert", certPath, "-root", rootHex, "-out", filepath.Join(dir, "out3.json")})
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("sign under an expired cert = %v, want a refusal", err)
		}
	})
}

// A world-readable signing key is refused. This key's compromise is a fleet-wide
// code push; the cheapest possible mistake is worth one stat.
func TestReadKeyRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loose.key")
	seed := make([]byte, ed25519.SeedSize)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(path); err == nil || !strings.Contains(err.Error(), "readable by anyone") {
		t.Fatalf("readKey on a 0644 key = %v, want a refusal", err)
	}
}

func TestKeygenRefusesToOverwriteAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if err := keygen([]string{"-out", path}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := keygen([]string{"-out", path}); err == nil {
		t.Fatal("keygen overwrote an existing signing key")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the existing key was modified")
	}
}

// plan refuses a manifest that could never be applied, at the last moment a
// mistake is free.
func TestPlanRefusesAnUnusableManifest(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"-artifact", "linux/amd64/node=" + bin, "-release", "1.0", "-seq", "1", "-out", filepath.Join(dir, "a.json")},
		{"-artifact", "linux/amd64/shell=" + bin, "-release", "1.0.0", "-seq", "1", "-out", filepath.Join(dir, "b.json")},
		{"-artifact", "linux/amd64/node=" + bin, "-release", "1.0.0", "-seq", "0", "-out", filepath.Join(dir, "c.json")},
		{"-release", "1.0.0", "-seq", "1", "-out", filepath.Join(dir, "d.json")},
	}
	for i, args := range cases {
		if err := plan(args); err == nil {
			t.Errorf("case %d: plan accepted a manifest that cannot be applied", i)
		}
	}
}

// The -from path: the offline machine authors from CI's rows and never needs the
// artifacts themselves.
func TestPlanFromAnArtifactList(t *testing.T) {
	dir := t.TempDir()
	list := artifactList{Release: "2.0.0", Artifacts: []artifactRow{
		{OS: "linux", Arch: "amd64", Role: update.RoleNode, Size: 1234, SHA256: strings.Repeat("ab", 32)},
		{OS: "windows", Arch: "amd64", Role: update.RoleClient, Size: 4321, SHA256: strings.Repeat("cd", 32)},
	}}
	b, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	listPath := filepath.Join(dir, "artifacts.json")
	if err := os.WriteFile(listPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(dir, "body.json")
	if err := plan([]string{"-from", listPath, "-seq", "2", "-out", bodyPath}); err != nil {
		t.Fatalf("plan -from: %v", err)
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	var m update.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m.Release != "2.0.0" || len(m.Artifacts) != 2 {
		t.Fatalf("plan -from produced %+v", m)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("the planned manifest does not validate: %v", err)
	}
}

// writeCert mints a delegation cert. TEST ONLY: the root's private half is the
// offline ceremony's and never exists outside a test process here.
func writeCert(t *testing.T, path string, root ed25519.PrivateKey, pub ed25519.PublicKey, role delegation.Role, serial string, nbf, naf time.Time) {
	t.Helper()
	body, err := json.Marshal(delegation.Cert{
		Version: delegation.Version, Serial: serial, Role: role, Pub: pub,
		NotBefore: nbf, NotAfter: naf, Note: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := append([]byte(delegation.TagDelegationCert), 0x00)
	msg = append(msg, body...)
	signed := append(append([]byte(nil), body...), ed25519.Sign(root, msg)...)
	if err := os.WriteFile(path, []byte(delegation.EncodeCert(signed)), 0o600); err != nil {
		t.Fatal(err)
	}
}
