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

	"github.com/bacchus-vpn/bacchus/core/admission"
)

func TestGeoOptions(t *testing.T) {
	cases := []struct {
		name      string
		countries []countryItem
		want      []string
	}{
		{
			name:      "nothing offered",
			countries: nil,
			want:      []string{geoAny},
		},
		{
			name: "dedups and sorts, skips blank country",
			countries: []countryItem{
				{code: "us"},
				{code: "de"},
				{code: "us"},
				{code: ""},
			},
			want: []string{geoAny, "de", "us"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := geoOptions(tc.countries)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("geoOptions() = %v, want %v", got, tc.want)
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

// TestValidateMeshConfig is issue #129's dialog-side validation proof: it
// mirrors cmd/node's loadMeshRecovery (courier.go) — all-or-nothing on the
// peers/proof-path/pubkey triad, and a real ed25519-sized hex check on the
// pubkey — without reading proofPath's file (that's meshRecoveryFields'
// job, main.go, at connect/switch time; see this function's own doc for
// why the split).
func TestValidateMeshConfig(t *testing.T) {
	validHex := hex.EncodeToString(make([]byte, ed25519.PublicKeySize))
	peers := []string{"203.0.113.1:9000"}

	cases := []struct {
		name                         string
		peers                        []string
		proofPath, pubKeyHex         string
		wantErr                      bool
		wantProofPath, wantPubKeyHex string
	}{
		{name: "all blank is valid (recovery off)", wantErr: false},
		{name: "peers alone is rejected", peers: peers, wantErr: true},
		{name: "proof path alone is rejected", proofPath: "/tmp/proof.bin", wantErr: true},
		{name: "pubkey alone is rejected", pubKeyHex: validHex, wantErr: true},
		{name: "peers+proof without pubkey is rejected", peers: peers, proofPath: "/tmp/proof.bin", wantErr: true},
		{
			name: "all three set is valid", peers: peers, proofPath: "/tmp/proof.bin", pubKeyHex: validHex,
			wantErr: false, wantProofPath: "/tmp/proof.bin", wantPubKeyHex: validHex,
		},
		{name: "malformed hex is rejected", peers: peers, proofPath: "/tmp/proof.bin", pubKeyHex: "not-hex", wantErr: true},
		{name: "wrong-length hex is rejected", peers: peers, proofPath: "/tmp/proof.bin", pubKeyHex: "abcd", wantErr: true},
		{
			name:  "surrounding whitespace is trimmed from both on success",
			peers: peers, proofPath: "  /tmp/proof.bin  ", pubKeyHex: "  " + validHex + "  ",
			wantErr: false, wantProofPath: "/tmp/proof.bin", wantPubKeyHex: validHex,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotProofPath, gotPubKeyHex, err := validateMeshConfig(tc.peers, tc.proofPath, tc.pubKeyHex)
			if tc.wantErr && err == nil {
				t.Fatalf("validateMeshConfig(%v, %q, %q) = nil, want an error", tc.peers, tc.proofPath, tc.pubKeyHex)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateMeshConfig(%v, %q, %q) = %v, want nil", tc.peers, tc.proofPath, tc.pubKeyHex, err)
			}
			if !tc.wantErr && (gotProofPath != tc.wantProofPath || gotPubKeyHex != tc.wantPubKeyHex) {
				t.Fatalf("validateMeshConfig(%v, %q, %q) = (%q, %q), want (%q, %q)",
					tc.peers, tc.proofPath, tc.pubKeyHex, gotProofPath, gotPubKeyHex, tc.wantProofPath, tc.wantPubKeyHex)
			}
		})
	}
}

func TestSplitJoinMeshPeers(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{name: "empty", text: "", want: nil},
		{name: "single entry", text: "203.0.113.1:9000", want: []string{"203.0.113.1:9000"}},
		{
			name: "multiple entries, blank lines and whitespace dropped",
			text: "203.0.113.1:9000\n\n  198.51.100.9:9000  \n",
			want: []string{"203.0.113.1:9000", "198.51.100.9:9000"},
		},
		{
			// issue #129: Win32's native multi-line edit control reports the
			// user's own typed line breaks as "\r\n", not a bare "\n" — the
			// trailing "\r" must not leak into the parsed address.
			name: "CRLF line endings (what walk.TextEdit actually reports)",
			text: "203.0.113.1:9000\r\n198.51.100.9:9000\r\n",
			want: []string{"203.0.113.1:9000", "198.51.100.9:9000"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitMeshPeers(tc.text)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitMeshPeers(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}

	// joinMeshPeers must join on "\r\n", not a bare "\n" (issue #129): a
	// manual visual check found that Win32's native multi-line edit control
	// only renders a bare "\n" as a line break when the user types Enter,
	// not when the text is set programmatically — a bare-"\n" join rendered
	// every peer run together on one line in the actual dialog.
	peers := []string{"203.0.113.1:9000", "198.51.100.9:9000"}
	joined := joinMeshPeers(peers)
	if want := "203.0.113.1:9000\r\n198.51.100.9:9000"; joined != want {
		t.Fatalf("joinMeshPeers(%v) = %q, want %q (CRLF-joined)", peers, joined, want)
	}
	if got := splitMeshPeers(joined); !reflect.DeepEqual(got, peers) {
		t.Fatalf("splitMeshPeers(joinMeshPeers(%v)) = %v, want %v", peers, got, peers)
	}
}

// TestValidateMeshConfigRejectsAnEmptyProofFile pins the guard added in the
// #183 review: the dialog used to save a triad whose proof file was zero
// bytes, and core.Engine's meshRecoveryConfigured requires
// len(MeshProof) > 0, so recovery was off for the whole session with nothing
// telling the user. cmd/node rejects the same file outright at startup
// ("-mesh-proof %s is empty"), and the two surfaces have to agree about what
// "configured" means.
//
// A *missing* file stays acceptable here, deliberately: a path can be set
// before the proof is downloaded, and meshRecoveryFields fails on it at
// connect/switch time. It is the file that exists and cannot work that must
// not pass silently.
func TestValidateMeshConfigRejectsAnEmptyProofFile(t *testing.T) {
	validHex := hex.EncodeToString(make([]byte, ed25519.PublicKeySize))
	peers := []string{"203.0.113.1:9000"}
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.snapshot")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty proof: %v", err)
	}
	if _, _, err := validateMeshConfig(peers, empty, validHex); err == nil {
		t.Error("a zero-byte proof file was accepted — recovery would be silently off for the whole session")
	}

	full := filepath.Join(dir, "full.snapshot")
	if err := os.WriteFile(full, []byte("snapshot-bytes"), 0o600); err != nil {
		t.Fatalf("write proof: %v", err)
	}
	if _, _, err := validateMeshConfig(peers, full, validHex); err != nil {
		t.Errorf("a non-empty proof file was rejected: %v", err)
	}

	absent := filepath.Join(dir, "not-here-yet.snapshot")
	if _, _, err := validateMeshConfig(peers, absent, validHex); err != nil {
		t.Errorf("a not-yet-present proof path was rejected at save time: %v — configuring the path before fetching the file has to stay possible", err)
	}
}
