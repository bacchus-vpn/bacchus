package devicestore

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// fakeCredential builds a syntactically valid "bacchusd1:" envelope carrying the
// given expiry, with a 64-byte trailing signature Expiry never checks (it only
// ever looks at the body). It exists to test Expiry/NeedsRenewal in isolation,
// without minting a whole issuer-cert/root chain a scheduling-only reader has no
// business verifying anyway.
func fakeCredential(t *testing.T, notAfter time.Time) string {
	t.Helper()
	body, err := json.Marshal(struct {
		V         int       `json:"v"`
		Serial    string    `json:"serial"`
		DevicePub []byte    `json:"dpub"`
		Epoch     uint64    `json:"epoch"`
		NotBefore time.Time `json:"nbf"`
		NotAfter  time.Time `json:"exp"`
	}{V: 1, Serial: "test", DevicePub: make([]byte, ed25519.PublicKeySize), NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter})
	if err != nil {
		t.Fatalf("marshal fake credential body: %v", err)
	}
	signed := append(body, make([]byte, ed25519.SignatureSize)...)
	return devicecred.EncodeDeviceCredential(signed)
}

func TestStore_OpenEmptyPathIsInMemoryOnly(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, _, ok := s.Get(); ok {
		t.Fatal("a fresh store must report ok=false")
	}
	if err := s.Put("cred", "cert"); err != nil {
		t.Fatalf("Put on an in-memory store must not error: %v", err)
	}
	cred, cert, ok := s.Get()
	if !ok || cred != "cred" || cert != "cert" {
		t.Fatalf("Get after Put = (%q, %q, %v), want (\"cred\", \"cert\", true)", cred, cert, ok)
	}
}

func TestStore_OpenMissingFileIsEmpty(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "nope", "credential.json"))
	if err != nil {
		t.Fatalf("Open on a missing file must not error: %v", err)
	}
	if _, _, ok := s.Get(); ok {
		t.Fatal("expected an empty store")
	}
}

func TestStore_OpenCorruptFileIsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("a damaged credential cache must never stop a client connecting, got error: %v", err)
	}
	if _, _, ok := s.Get(); ok {
		t.Fatal("expected an empty store from a corrupt file")
	}
}

func TestStore_PutPersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device", "credential.json")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s1.Put("bacchusd1:cred", "bacchusi1:cert"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat persisted file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm = %o, want 0600", perm)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	cred, cert, ok := s2.Get()
	if !ok || cred != "bacchusd1:cred" || cert != "bacchusi1:cert" {
		t.Fatalf("Get after re-Open = (%q, %q, %v), want the persisted pair", cred, cert, ok)
	}
}

func TestStore_GetIsFalseOnPartialPair(t *testing.T) {
	s, _ := Open("")
	if err := s.Put("cred-only", ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, ok := s.Get(); ok {
		t.Fatal("a credential with no issuer cert is not presentable and must report ok=false")
	}
}

func TestExpiry_ReadsClaimedNotAfter(t *testing.T) {
	want := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	got, ok := Expiry(fakeCredential(t, want))
	if !ok {
		t.Fatal("expected Expiry to decode the fake credential")
	}
	if !got.Equal(want) {
		t.Fatalf("Expiry = %v, want %v", got, want)
	}
}

func TestExpiry_FalseOnMalformedEnvelope(t *testing.T) {
	for _, s := range []string{"", "not-an-envelope", "bacchusd1:not-base64!!"} {
		if _, ok := Expiry(s); ok {
			t.Fatalf("Expiry(%q) reported ok=true, want false", s)
		}
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	margin := 6 * time.Hour

	cases := []struct {
		name string
		cred string
		want bool
	}{
		{"unknown expiry -> due", "garbage", true},
		{"far from expiry -> not due", fakeCredential(t, now.Add(48*time.Hour)), false},
		{"inside margin -> due", fakeCredential(t, now.Add(3*time.Hour)), true},
		{"already expired -> due", fakeCredential(t, now.Add(-time.Hour)), true},
		{"exactly at margin boundary -> due", fakeCredential(t, now.Add(margin)), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NeedsRenewal(c.cred, now, margin); got != c.want {
				t.Fatalf("NeedsRenewal = %v, want %v", got, c.want)
			}
		})
	}
}
