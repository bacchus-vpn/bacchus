//go:build windows

package main

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// testInvite mints a well-formed but throwaway v1 invite string, the same
// shape cmd/coldstart-issue would print, for exercising canonicalizeInvite
// and inviteQRImage without any real secrets or network access.
func testInvite(t *testing.T) string {
	t.Helper()
	secretID, secret, err := coldstart.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := coldstart.EncodeInvite(coldstart.Invite{
		Coordinator: "203.0.113.10:51820", // TEST-NET-3 (RFC 5737): never a real Bacchus endpoint
		SecretID:    secretID,
		Secret:      secret,
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatalf("EncodeInvite: %v", err)
	}
	return s
}

func TestCanonicalizeInvite(t *testing.T) {
	valid := testInvite(t)

	cases := []struct {
		name    string
		pasted  string
		want    string
		wantErr bool
	}{
		{name: "valid invite is unchanged", pasted: valid, want: valid},
		{name: "surrounding whitespace and newlines are trimmed", pasted: "  \n" + valid + "\n\t", want: valid},
		{name: "empty input", pasted: "", wantErr: true},
		{name: "whitespace-only input", pasted: "   ", wantErr: true},
		{name: "garbage is rejected", pasted: "not-an-invite", wantErr: true},
		// Short enough to cut into the fixed-width id/secret/pubkey fields
		// (73 raw bytes for a v1 invite, ~98+ base64 chars) rather than just
		// the free-length Coordinator suffix DecodeInvite doesn't otherwise
		// constrain — see TestCanonicalizeInviteRejectsAddresslessInvite for
		// that boundary specifically.
		{name: "truncated invite is rejected", pasted: valid[:30], wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalizeInvite(tc.pasted)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("canonicalizeInvite(%q) = %q, nil; want an error", tc.pasted, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalizeInvite(%q) unexpected error: %v", tc.pasted, err)
			}
			if got != tc.want {
				t.Fatalf("canonicalizeInvite(%q) = %q, want %q", tc.pasted, got, tc.want)
			}
		})
	}
}

func TestCanonicalizeInviteRejectsAddresslessInvite(t *testing.T) {
	// EncodeInvite itself doesn't reject an empty Coordinator (confirmed by
	// this test constructing one successfully) — the "at least one address
	// byte" rule lives in DecodeInvite instead. canonicalizeInvite must still
	// end up rejecting the round trip, not silently produce a QR for an
	// invite with no coordinator to bootstrap against.
	secretID, secret, err := coldstart.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	addressless, err := coldstart.EncodeInvite(coldstart.Invite{
		Coordinator: "",
		SecretID:    secretID,
		Secret:      secret,
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatalf("EncodeInvite with an empty Coordinator: %v", err)
	}
	if _, err := canonicalizeInvite(addressless); err == nil {
		t.Fatal("canonicalizeInvite accepted an invite with no coordinator address")
	}
}

func TestInviteQRImage(t *testing.T) {
	valid := testInvite(t)
	img, err := inviteQRImage(valid)
	if err != nil {
		t.Fatalf("inviteQRImage: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != qrPixels || b.Dy() != qrPixels {
		t.Fatalf("inviteQRImage size = %dx%d, want %dx%d", b.Dx(), b.Dy(), qrPixels, qrPixels)
	}
}

func TestDecodePNGRejectsGarbage(t *testing.T) {
	// Proves decodePNG's error path actually fires (rather than inviteQRImage's
	// success case being the only thing exercised) — otherwise a change that
	// made it silently ignore a decode failure would go unnoticed.
	if _, err := decodePNG([]byte("not a png")); err == nil {
		t.Fatal("decodePNG accepted non-PNG bytes without error")
	}
}

func TestTestInviteHasExpectedPrefix(t *testing.T) {
	if valid := testInvite(t); !strings.HasPrefix(valid, "bacchus1:") {
		t.Fatalf("testInvite produced %q, want a bacchus1: prefix", valid)
	}
}
