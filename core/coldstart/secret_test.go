package coldstart

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestGenerateSecretIsUniqueAndSized(t *testing.T) {
	id1, s1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	id2, s2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("two calls produced the same secret id")
	}
	if len(id1) != SecretIDLen*2 {
		t.Fatalf("secret id len = %d, want %d (hex-encoded)", len(id1), SecretIDLen*2)
	}
	if len(s1) != SecretLen || len(s2) != SecretLen {
		t.Fatalf("secret len = %d/%d, want %d", len(s1), len(s2), SecretLen)
	}
}

func TestInviteEncodeDecodeRoundTrip(t *testing.T) {
	id, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	inv := Invite{
		Coordinator: "203.0.113.1:3478",
		SecretID:    id,
		Secret:      secret,
		PublicKey:   pub,
	}
	s, err := EncodeInvite(inv)
	if err != nil {
		t.Fatalf("EncodeInvite: %v", err)
	}
	got, err := DecodeInvite(s)
	if err != nil {
		t.Fatalf("DecodeInvite: %v", err)
	}
	if got.Coordinator != inv.Coordinator || got.SecretID != inv.SecretID {
		t.Fatalf("decoded invite mismatch: %+v", got)
	}
	if string(got.Secret) != string(inv.Secret) || string(got.PublicKey) != string(inv.PublicKey) {
		t.Fatalf("decoded invite key material mismatch")
	}
	if got.AdmissionKey != nil {
		t.Fatalf("a v1 invite (no admission anchor) must decode with a nil AdmissionKey, got %x", got.AdmissionKey)
	}
}

// TestInviteWithAdmissionKeyRoundTrip: a v2 invite carries the admission anchor
// (old #60) through encode/decode alongside the snapshot-signing key.
func TestInviteWithAdmissionKeyRoundTrip(t *testing.T) {
	id, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	snapPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate snapshot key: %v", err)
	}
	admPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate admission key: %v", err)
	}
	inv := Invite{
		Coordinator:  "203.0.113.1:3478",
		SecretID:     id,
		Secret:       secret,
		PublicKey:    snapPub,
		AdmissionKey: admPub,
	}
	s, err := EncodeInvite(inv)
	if err != nil {
		t.Fatalf("EncodeInvite: %v", err)
	}
	got, err := DecodeInvite(s)
	if err != nil {
		t.Fatalf("DecodeInvite: %v", err)
	}
	if got.Coordinator != inv.Coordinator || got.SecretID != inv.SecretID {
		t.Fatalf("decoded invite mismatch: %+v", got)
	}
	if string(got.Secret) != string(inv.Secret) || string(got.PublicKey) != string(snapPub) {
		t.Fatalf("decoded invite key material mismatch")
	}
	if string(got.AdmissionKey) != string(admPub) {
		t.Fatalf("decoded admission key = %x, want %x", got.AdmissionKey, admPub)
	}
}

// TestEncodeInviteRejectsBadAdmissionKey: a non-empty admission key that is not a
// full ed25519 public key is an encode error, not a silently-truncated invite.
func TestEncodeInviteRejectsBadAdmissionKey(t *testing.T) {
	id, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	snapPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	inv := Invite{
		Coordinator:  "203.0.113.1:3478",
		SecretID:     id,
		Secret:       secret,
		PublicKey:    snapPub,
		AdmissionKey: []byte{1, 2, 3}, // too short to be an ed25519 public key
	}
	if _, err := EncodeInvite(inv); err == nil {
		t.Fatal("EncodeInvite must reject a malformed admission key")
	}
}

func TestDecodeInviteRejectsBadInput(t *testing.T) {
	cases := []string{
		"",
		"not-an-invite-at-all",
		"bacchus1:not-valid-base64!!!",
	}
	for _, c := range cases {
		if _, err := DecodeInvite(c); err == nil {
			t.Errorf("DecodeInvite(%q) succeeded, want error", c)
		}
	}
}

// TestInviteWithCRLRoundTrip: a v3 invite (old #69) carries the revocation
// bundle through encode/decode alongside the admission anchor and snapshot key.
func TestInviteWithCRLRoundTrip(t *testing.T) {
	id, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	snapPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate snapshot key: %v", err)
	}
	admPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate admission key: %v", err)
	}
	crl := []byte("bacchusr1:this-is-an-opaque-signed-bundle-to-coldstart")
	inv := Invite{
		Coordinator:  "203.0.113.1:3478",
		SecretID:     id,
		Secret:       secret,
		PublicKey:    snapPub,
		AdmissionKey: admPub,
		CRL:          crl,
	}
	s, err := EncodeInvite(inv)
	if err != nil {
		t.Fatalf("EncodeInvite: %v", err)
	}
	got, err := DecodeInvite(s)
	if err != nil {
		t.Fatalf("DecodeInvite: %v", err)
	}
	if got.Coordinator != inv.Coordinator || got.SecretID != inv.SecretID {
		t.Fatalf("decoded invite mismatch: %+v", got)
	}
	if string(got.Secret) != string(inv.Secret) || string(got.PublicKey) != string(snapPub) {
		t.Fatalf("decoded invite key material mismatch")
	}
	if string(got.AdmissionKey) != string(admPub) {
		t.Fatalf("decoded admission key = %x, want %x", got.AdmissionKey, admPub)
	}
	if string(got.CRL) != string(crl) {
		t.Fatalf("decoded CRL = %q, want %q", got.CRL, crl)
	}
}

// TestEncodeInviteRejectsCRLWithoutAnchor: a CRL is unverifiable without the
// admission anchor beside it, so encoding one without the other is an error,
// not a silently-dropped bundle.
func TestEncodeInviteRejectsCRLWithoutAnchor(t *testing.T) {
	id, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	snapPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	inv := Invite{
		Coordinator: "203.0.113.1:3478",
		SecretID:    id,
		Secret:      secret,
		PublicKey:   snapPub,
		CRL:         []byte("bacchusr1:orphaned-bundle"),
	}
	if _, err := EncodeInvite(inv); err == nil {
		t.Fatal("EncodeInvite must reject a CRL without an admission anchor")
	}
}

// TestDecodeInviteRejectsTruncatedCRL: a v3 invite whose declared CRL length
// overruns the bytes actually present is rejected, not a panic — the bounds
// check a hand-crafted or corrupted length prefix needs to hit.
func TestDecodeInviteRejectsTruncatedCRL(t *testing.T) {
	id, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	snapPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	admPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	idBytes, err := hex.DecodeString(id)
	if err != nil {
		t.Fatalf("decode secret id: %v", err)
	}
	buf := []byte{inviteV3}
	buf = append(buf, idBytes...)
	buf = append(buf, secret...)
	buf = append(buf, snapPub...)
	buf = append(buf, admPub...)
	var lenPrefix [crlLenPrefixSize]byte
	binary.BigEndian.PutUint16(lenPrefix[:], 9000) // declares far more than actually follows
	buf = append(buf, lenPrefix[:]...)
	buf = append(buf, []byte("nowhere-near-9000-bytes")...)
	buf = append(buf, []byte("203.0.113.1:3478")...)

	s := "bacchus1:" + base64.RawURLEncoding.EncodeToString(buf)
	if _, err := DecodeInvite(s); err == nil {
		t.Fatal("DecodeInvite must reject a CRL length that overruns the buffer, not panic")
	}
}
