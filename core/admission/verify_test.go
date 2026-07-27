package admission

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// base is a fixed clock so the validity-window cases are deterministic: every
// credential window and the now passed to Verify are expressed relative to it.
var base = time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

func TestVerifyPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cases := []struct {
		name     string
		roles    []Role
		subject  string    // credential's Subject
		nbf, exp time.Time // credential window
		revoke   bool      // revoke the credential's serial before verifying

		want     Role   // role the peer is taking now
		vSubject string // subject passed to Verify ("" == client/no binding)
		wantErr  error  // nil == admit
	}{
		{
			name:  "valid exit node, subject bound",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: nil,
		},
		{
			name:  "valid client, no subject binding",
			roles: []Role{RoleClient}, subject: "user-7", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleClient, vSubject: "", wantErr: nil,
		},
		{
			name:  "multi-role credential used for one of its roles",
			roles: []Role{RoleRelay, RoleExit}, subject: "node-M", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleRelay, vSubject: "node-M", wantErr: nil,
		},
		{
			name:  "expired",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-2 * time.Hour), exp: base.Add(-time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: ErrExpired,
		},
		{
			name:  "not yet valid beyond skew",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(10 * time.Minute), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: ErrNotYetValid,
		},
		{
			name:  "not yet valid but within clock skew is admitted",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(time.Minute), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: nil,
		},
		{
			name:  "role not authorized",
			roles: []Role{RoleClient}, subject: "user-7", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "user-7", wantErr: ErrRoleNotAuthorized,
		},
		{
			name:  "subject mismatch (credential replayed by another node)",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-B", wantErr: ErrSubjectMismatch,
		},
		{
			name:  "revoked",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			revoke: true,
			want:   RoleExit, vSubject: "exit-A", wantErr: ErrRevoked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, enc, err := Issue(priv, tc.subject, tc.roles, tc.nbf, tc.exp, "")
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			rl := NewRevocationList()
			if tc.revoke {
				rl.Revoke(c.Serial)
			}
			v := NewVerifier(pub, rl.Revoked)

			got, err := v.Verify(enc, base, tc.want, tc.vSubject)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify err = %v, want admit", err)
				}
				if got.Serial != c.Serial {
					t.Fatalf("admitted credential serial = %q, want %q", got.Serial, c.Serial)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A verifier with no revocation oracle (nil) must treat nothing as revoked.
func TestNewVerifierNilRevokedIsSafe(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, enc, err := Issue(priv, "exit-A", []Role{RoleExit}, base.Add(-time.Hour), base.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v := NewVerifier(pub, nil)
	if _, err := v.Verify(enc, base, RoleExit, "exit-A"); err != nil {
		t.Fatalf("Verify with nil revoked oracle err = %v, want admit", err)
	}
}

func TestRevocationListRoundTrip(t *testing.T) {
	rl := NewRevocationList()
	rl.Revoke("cafe")
	rl.Revoke("babe")
	if !rl.Revoked("cafe") || !rl.Revoked("babe") {
		t.Fatal("Revoke did not record serials")
	}
	if rl.Revoked("f00d") {
		t.Fatal("unrevoked serial reported revoked")
	}

	path := filepath.Join(t.TempDir(), "revocations.json")
	if err := rl.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	loaded, err := LoadRevocationList(path)
	if err != nil {
		t.Fatalf("LoadRevocationList: %v", err)
	}
	if !loaded.Revoked("cafe") || !loaded.Revoked("babe") || loaded.Revoked("f00d") {
		t.Fatal("loaded revocation list does not match saved")
	}
}

func TestLoadRevocationListMissingFileIsErrNotExist(t *testing.T) {
	_, err := LoadRevocationList(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadRevocationList(missing) err = %v, want wrapped os.ErrNotExist", err)
	}
}

// TestRevocationListSerialsSorted: Serials returns every revoked serial in a
// stable sorted order regardless of insertion order — cmd/admission-issue -crl
// (issue #69) signs exactly this slice, so its output must be deterministic.
func TestRevocationListSerialsSorted(t *testing.T) {
	rl := NewRevocationList()
	if got := rl.Serials(); len(got) != 0 {
		t.Fatalf("empty list Serials() = %v, want empty", got)
	}
	rl.Revoke("cafe")
	rl.Revoke("babe")
	rl.Revoke("dead")
	got := rl.Serials()
	want := []string{"babe", "cafe", "dead"}
	if len(got) != len(want) {
		t.Fatalf("Serials() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Serials() = %v, want %v", got, want)
		}
	}
}
