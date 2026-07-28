//go:build windows

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/admission"
)

// TestValidateRelayChainConfig is the client-side-validation proof for issue
// #28: 2+ hops with no directory (or no key) is a core.New construction
// error today (core/relaychain.go's setupRelayChaining), which connect()
// would otherwise only discover at Connect time. validateRelayChainConfig
// catches exactly the "wants to chain, can't" combination before Save lets
// it out — mirroring validateAdmissionConfig's shape (issue #130), including
// trimming both string inputs before persisting them.
func TestValidateRelayChainConfig(t *testing.T) {
	cases := []struct {
		name              string
		hops              int
		dirPath, dirKey   string
		wantErr           bool
		wantPath, wantKey string
	}{
		{name: "1 hop needs neither field", hops: 1, dirPath: "", dirKey: "", wantErr: false},
		{name: "0 hops (unset) needs neither field", hops: 0, dirPath: "", dirKey: "", wantErr: false},
		{name: "2 hops with both set is valid", hops: 2, dirPath: "dir.bin", dirKey: "abcd", wantErr: false, wantPath: "dir.bin", wantKey: "abcd"},
		{name: "2 hops with no directory is rejected", hops: 2, dirPath: "", dirKey: "abcd", wantErr: true},
		{name: "2 hops with no key is rejected", hops: 2, dirPath: "dir.bin", dirKey: "", wantErr: true},
		{name: "2 hops with neither is rejected", hops: 2, dirPath: "", dirKey: "", wantErr: true},
		{name: "4 hops (the ceiling) with both set is valid", hops: 4, dirPath: "dir.bin", dirKey: "abcd", wantErr: false, wantPath: "dir.bin", wantKey: "abcd"},
		{name: "surrounding whitespace is trimmed from both on success", hops: 2, dirPath: "  dir.bin  ", dirKey: "  abcd  ", wantErr: false, wantPath: "dir.bin", wantKey: "abcd"},
		{name: "whitespace-only directory at 2 hops is rejected exactly like blank", hops: 2, dirPath: "   ", dirKey: "abcd", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPath, gotKey, err := validateRelayChainConfig(tc.hops, tc.dirPath, tc.dirKey)
			if tc.wantErr && err == nil {
				t.Fatalf("validateRelayChainConfig(%d, %q, %q) = nil, want an error", tc.hops, tc.dirPath, tc.dirKey)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateRelayChainConfig(%d, %q, %q) = %v, want nil", tc.hops, tc.dirPath, tc.dirKey, err)
			}
			if !tc.wantErr && (gotPath != tc.wantPath || gotKey != tc.wantKey) {
				t.Fatalf("validateRelayChainConfig(%d, %q, %q) = (%q, %q), want (%q, %q)",
					tc.hops, tc.dirPath, tc.dirKey, gotPath, gotKey, tc.wantPath, tc.wantKey)
			}
		})
	}
}

// TestNormalizeRelayHops pins the NumberEdit display normalization: 0 (a
// fresh Config's zero value, or an older pre-#28 settings file) reads as 1
// hop, matching core/relaychain.go's chainDepth exactly, and a value already
// above the ceiling (only reachable by hand-editing the config file) is
// clamped for display — core.New's own construction-time refusal, not this
// function, is what actually enforces the ceiling for real.
func TestNormalizeRelayHops(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{name: "zero (unset) normalizes to 1", in: 0, want: 1},
		{name: "negative normalizes to 1", in: -3, want: 1},
		{name: "1 is unchanged", in: 1, want: 1},
		{name: "mid-range is unchanged", in: 3, want: 3},
		{name: "the ceiling is unchanged", in: core.RelayHopsMax, want: core.RelayHopsMax},
		{name: "above the ceiling is clamped", in: core.RelayHopsMax + 5, want: core.RelayHopsMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeRelayHops(tc.in); got != tc.want {
				t.Fatalf("normalizeRelayHops(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizePoolOrder(t *testing.T) {
	// reality is now an allowed pool transport (issue #109): its underlay
	// address is excluded late, on the dial path, so the full-device tunnel can
	// carry it. sanitizePoolOrder therefore keeps reality (in the user's chosen
	// order) and still drops only genuinely unknown/duplicate entries.
	cases := []struct {
		name  string
		order []string
		want  []string
	}{
		{name: "nil", order: nil, want: []string{}},
		{name: "keeps reality then webrtc, in order", order: []string{"reality", "webrtc"}, want: []string{"reality", "webrtc"}},
		{name: "keeps webrtc then reality, in order", order: []string{"webrtc", "reality"}, want: []string{"webrtc", "reality"}},
		{name: "webrtc alone", order: []string{"webrtc"}, want: []string{"webrtc"}},
		{name: "reality alone", order: []string{"reality"}, want: []string{"reality"}},
		{name: "dedups webrtc", order: []string{"webrtc", "webrtc"}, want: []string{"webrtc"}},
		{name: "dedups reality", order: []string{"reality", "reality"}, want: []string{"reality"}},
		{name: "drops unknown, keeps both known", order: []string{"bogus", "reality", "webrtc"}, want: []string{"reality", "webrtc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizePoolOrder(tc.order)
			if len(got) != len(tc.want) || (len(got) > 0 && !reflect.DeepEqual(got, tc.want)) {
				t.Fatalf("sanitizePoolOrder(%v) = %v, want %v", tc.order, got, tc.want)
			}
		})
	}
}

func TestMoveLadderItem(t *testing.T) {
	base := []string{"a", "b", "c"}
	cases := []struct {
		name string
		idx  int
		dir  int
		want []string
	}{
		{name: "move middle up", idx: 1, dir: -1, want: []string{"b", "a", "c"}},
		{name: "move middle down", idx: 1, dir: 1, want: []string{"a", "c", "b"}},
		{name: "move first up is inert", idx: 0, dir: -1, want: []string{"a", "b", "c"}},
		{name: "move last down is inert", idx: 2, dir: 1, want: []string{"a", "b", "c"}},
		{name: "negative index is inert", idx: -1, dir: 1, want: []string{"a", "b", "c"}},
		{name: "out-of-range index is inert", idx: 5, dir: -1, want: []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]string(nil), base...)
			got := moveLadderItem(in, tc.idx, tc.dir)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("moveLadderItem(%v, %d, %d) = %v, want %v", base, tc.idx, tc.dir, got, tc.want)
			}
			if !reflect.DeepEqual(in, base) {
				t.Fatalf("moveLadderItem mutated its input slice: got %v, want unchanged %v", in, base)
			}
		})
	}
}

// TestResetLearnedPathsWiresAdmissionCRLPath is a config-wiring proof for issue
// #116: it does not mock core.New, so it only passes if snap.AdmissionPubKey /
// snap.AdmissionCRLPath actually reach the core.Config literal resetLearnedPaths
// builds (settings.go) — exactly the wiring connect() and listExits() (main.go)
// share. An already-expired revocation bundle at AdmissionCRLPath is a
// construction error (core/exit_admission.go, mirroring
// TestBuildExitVerifierCRLPathMalformedErrors in core's own test suite); if
// resetLearnedPaths dropped either field on the floor, core.New would see no
// admission anchor at all, fail open, and this would observe a nil error
// instead. Coordinators is a TEST-NET-3 address (RFC 5737): construction fails
// on the malformed CRL before any network I/O or coordinator reachability is
// needed.
func TestResetLearnedPathsWiresAdmissionCRLPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Signed 2h ago with a 1h TTL: already expired "now".
	expired, err := admission.SignCRL(priv, []string{"deadbeef"}, time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "revocations.crl")
	if err := os.WriteFile(path, []byte(expired), 0o600); err != nil {
		t.Fatalf("write CRL file: %v", err)
	}

	snap := Config{
		Coordinators:     []string{"203.0.113.10:51820"},
		AdmissionPubKey:  hex.EncodeToString(pub),
		AdmissionCRLPath: path,
	}
	if err := resetLearnedPaths(snap); err == nil {
		t.Fatal("resetLearnedPaths with an expired AdmissionCRLPath succeeded, want a construction error — AdmissionPubKey/AdmissionCRLPath are not reaching core.Config")
	}
}

func TestMoveLadderItemSingleElement(t *testing.T) {
	got := moveLadderItem([]string{"only"}, 0, 1)
	if !reflect.DeepEqual(got, []string{"only"}) {
		t.Fatalf("moveLadderItem on a single-element list = %v, want unchanged", got)
	}
}

// TestCountryItemLabel pins what a picker row says, including the busy case (#147):
// a full country stays in the list, labelled, rather than silently vanishing — there
// is otherwise no way to tell the user "that country is busy" when the country is not
// there to label.
func TestCountryItemLabel(t *testing.T) {
	if got := (countryItem{code: "NL", exits: 3, available: 2}).label(); got != "NL  —  2/3 available" {
		t.Errorf("available label = %q", got)
	}
	if got := (countryItem{code: "NL", exits: 3, busy: true}).label(); got != "NL  —  busy" {
		t.Errorf("busy label = %q", got)
	}
}

// TestValidateAdmissionConfig is the client-side-validation proof for issue
// #123a: core (core/exit_admission.go's buildExitVerifier) rejects "CRL path
// set, pubkey blank" as a construction error, which today reaches the user
// only as connect()'s raw "requires AdmissionPubKey" or listExits() silently
// returning no exits. validateAdmissionConfig must catch exactly that
// combination before either field reaches core.Config, and only that one —
// both blank (admission off) and pubkey alone (verify, skip revocation) are
// legitimate configs core accepts.
//
// The whitespace-only-pubkey cases guard issue #130 (post-#123a): a bare " "
// used to pass this check (it's != ""), so the pubkey reached core.Config
// unexamined, and only core's own TrimSpace-then-reject (buildExitVerifier,
// core/exit_admission.go) turned it into the raw "requires AdmissionPubKey"
// error this dialog exists to replace. Trimming here, the same way core
// does, closes that gap — and the surrounding-whitespace cases confirm the
// *returned* values are what actually gets persisted, not the raw widget
// text, so a config saved via this dialog can never itself carry the stray
// whitespace back in.
func TestValidateAdmissionConfig(t *testing.T) {
	cases := []struct {
		name                    string
		pubKey, crlPath         string
		wantErr                 bool
		wantPubKey, wantCRLPath string
	}{
		{name: "both blank is valid (admission off)", pubKey: "", crlPath: "", wantErr: false},
		{name: "pubkey alone is valid (verify, skip revocation)", pubKey: "abcd", crlPath: "", wantErr: false, wantPubKey: "abcd"},
		{name: "both set is valid", pubKey: "abcd", crlPath: `C:\crl.bin`, wantErr: false, wantPubKey: "abcd", wantCRLPath: `C:\crl.bin`},
		{name: "CRL path without pubkey is rejected", pubKey: "", crlPath: `C:\crl.bin`, wantErr: true},
		{name: "whitespace-only pubkey is rejected exactly like blank (issue #130)", pubKey: " ", crlPath: `C:\crl.bin`, wantErr: true},
		{name: "whitespace-only pubkey and blank CRL path is valid (both effectively off)", pubKey: "  ", crlPath: "", wantErr: false},
		{name: "surrounding whitespace is trimmed from both on success", pubKey: "  abcd  ", crlPath: "  C:\\crl.bin  ", wantErr: false, wantPubKey: "abcd", wantCRLPath: `C:\crl.bin`},
		{name: "whitespace-only CRL path trims to blank, leaving pubkey-alone (valid)", pubKey: "abcd", crlPath: "   ", wantErr: false, wantPubKey: "abcd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPubKey, gotCRLPath, err := validateAdmissionConfig(tc.pubKey, tc.crlPath)
			if tc.wantErr && err == nil {
				t.Fatalf("validateAdmissionConfig(%q, %q) = nil, want an error", tc.pubKey, tc.crlPath)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateAdmissionConfig(%q, %q) = %v, want nil", tc.pubKey, tc.crlPath, err)
			}
			if !tc.wantErr && (gotPubKey != tc.wantPubKey || gotCRLPath != tc.wantCRLPath) {
				t.Fatalf("validateAdmissionConfig(%q, %q) = (%q, %q), want (%q, %q)",
					tc.pubKey, tc.crlPath, gotPubKey, gotCRLPath, tc.wantPubKey, tc.wantCRLPath)
			}
		})
	}
}

func TestLadderDisplayOrder(t *testing.T) {
	cases := []struct {
		name  string
		saved []string
		want  []string
	}{
		{name: "nothing saved shows every known transport", saved: nil, want: []string{"webrtc", "reality"}},
		{name: "saved entry kept first, missing ones appended", saved: []string{"reality"}, want: []string{"reality", "webrtc"}},
		{name: "already complete is unchanged", saved: []string{"webrtc", "reality"}, want: []string{"webrtc", "reality"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ladderDisplayOrder(tc.saved)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ladderDisplayOrder(%v) = %v, want %v", tc.saved, got, tc.want)
			}
		})
	}
}
