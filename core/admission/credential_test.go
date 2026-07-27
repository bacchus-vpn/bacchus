package admission

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// testCred issues a credential valid for the next hour, failing the test on
// error. It returns the authority keypair, the Credential, and its encoded form.
func testCred(t *testing.T, subject string, roles ...Role) (ed25519.PublicKey, ed25519.PrivateKey, Credential, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	c, enc, err := Issue(priv, subject, roles, now.Add(-time.Minute), now.Add(time.Hour), "test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return pub, priv, c, enc
}

func TestSignParseRoundTrip(t *testing.T) {
	pub, _, c, enc := testCred(t, "exit-abc", RoleExit)
	signed, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got, err := parse(pub, signed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Serial != c.Serial || got.Subject != c.Subject || got.Version != c.Version {
		t.Fatalf("parsed credential mismatch: got %+v want %+v", got, c)
	}
	if !got.NotBefore.Equal(c.NotBefore) || !got.NotAfter.Equal(c.NotAfter) {
		t.Fatalf("parsed window mismatch: got [%v,%v] want [%v,%v]", got.NotBefore, got.NotAfter, c.NotBefore, c.NotAfter)
	}
	if len(got.Roles) != 1 || got.Roles[0] != RoleExit {
		t.Fatalf("parsed roles = %v, want [exit]", got.Roles)
	}
}

func TestParseRejectsTamperedBody(t *testing.T) {
	pub, _, _, enc := testCred(t, "exit-abc", RoleExit)
	signed, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	signed[0] ^= 0xff // flip a byte in the JSON body
	if _, err := parse(pub, signed); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("parse(tampered) err = %v, want ErrBadSignature", err)
	}
}

func TestParseRejectsWrongKey(t *testing.T) {
	_, _, _, enc := testCred(t, "exit-abc", RoleExit)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed, _ := Decode(enc)
	if _, err := parse(other, signed); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("parse(wrong key) err = %v, want ErrBadSignature", err)
	}
}

func TestParseRejectsUnsupportedVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Sign a credential with a future/unknown version directly (Issue always
	// stamps CredentialVersion, so we build the struct by hand).
	c := Credential{Version: 99, Serial: "deadbeef", Subject: "x", Roles: []Role{RoleClient}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	signed, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := parse(pub, signed); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("parse(v99) err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, enc, err := Issue(priv, "sub", []Role{RoleClient}, time.Now(), time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(enc, credPrefix) {
		t.Fatalf("encoded credential %q missing prefix %q", enc, credPrefix)
	}
	if _, err := Decode(enc); err != nil {
		t.Fatalf("Decode(own output): %v", err)
	}
	// Surrounding whitespace (a credential pasted from a file with a trailing
	// newline) must still decode.
	if _, err := Decode("  " + enc + "\n"); err != nil {
		t.Fatalf("Decode(padded): %v", err)
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	cases := []string{
		"",
		"no-prefix-here",
		"bacchus1:abc",            // coldstart invite prefix, not a credential
		credPrefix + "not!base64", // bad base64 after the prefix
	}
	for _, c := range cases {
		if _, err := Decode(c); !errors.Is(err, ErrMalformed) {
			t.Errorf("Decode(%q) err = %v, want ErrMalformed", c, err)
		}
	}
}

func TestIssueUniqueSerials(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c, _, err := Issue(priv, "sub", []Role{RoleClient}, time.Now(), time.Now().Add(time.Hour), "")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[c.Serial] {
			t.Fatalf("duplicate serial %q on iteration %d", c.Serial, i)
		}
		seen[c.Serial] = true
	}
}

func TestIssueRejectsNoRoles(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, _, err := Issue(priv, "sub", nil, time.Now(), time.Now().Add(time.Hour), ""); err == nil {
		t.Fatal("Issue with no roles succeeded, want error")
	}
}
