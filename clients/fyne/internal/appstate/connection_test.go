package appstate

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core"
)

// testDirKey is a syntactically valid ed25519 public key: 32 bytes of hex.
// Never key material — LoadRelayDirectory checks the SHAPE (hex, right
// length) and hands the bytes to core, which is what verifies the signature.
var testDirKey = strings.Repeat("ab", ed25519.PublicKeySize)

// TestNormalizeRelayHopsClampsBothEnds pins the clamp at each end and the
// 0-means-1 rule core/relaychain.go's chainDepth applies server-side. 0 is not
// a hypothetical: it is a fresh Config's zero value and what every settings
// file written before issue #93 carries, so reading it as "no relay at all"
// rather than "one relay" is the realistic way to get this wrong.
//
// Mutation check: changing `hops < 1` to `hops < 0` makes the 0 and "fresh
// Config zero value" cases go red; dropping the upper `if` makes the
// above-ceiling cases go red. Neither passes both before and after.
func TestNormalizeRelayHopsClampsBothEnds(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"a fresh Config's zero value is one relay", 0, 1},
		{"negative is floored, not passed through", -1, 1},
		{"deeply negative is floored too", -9999, 1},
		{"one is already in range", 1, 1},
		{"two is a chain and is left alone", 2, 2},
		{"the ceiling itself is in range", core.RelayHopsMax, core.RelayHopsMax},
		{"one above the ceiling is clamped for display", core.RelayHopsMax + 1, core.RelayHopsMax},
		{"a hand-edited absurdity is clamped for display", 1 << 20, core.RelayHopsMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeRelayHops(tc.in); got != tc.want {
				t.Fatalf("NormalizeRelayHops(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestRelayHopChoicesCoversExactlyTheAcceptedRange checks the control cannot
// offer a depth core would refuse at construction (core/relaychain.go rejects
// above RelayHopsMax rather than clamping), and cannot omit one it would
// accept. Derived from the ceiling rather than written out, so this stays true
// if RelayHopsMax moves — which is the point of deriving it.
//
// Mutation check: an off-by-one in either loop bound — starting at 0, or
// stopping at RelayHopsMax-1 — fails the length assertion and the endpoint
// assertions. Writing the list out as a literal {"1","2","3","4"} passes today
// and fails the moment RelayHopsMax changes, which is the drift this guards.
func TestRelayHopChoicesCoversExactlyTheAcceptedRange(t *testing.T) {
	got := RelayHopChoices()
	if len(got) != core.RelayHopsMax {
		t.Fatalf("RelayHopChoices() has %d entries, want RelayHopsMax=%d: %v", len(got), core.RelayHopsMax, got)
	}
	if got[0] != "1" {
		t.Errorf("first choice = %q, want \"1\" — a chain of 0 hops is not a thing core accepts", got[0])
	}
	if last, want := got[len(got)-1], strconv.Itoa(core.RelayHopsMax); last != want {
		t.Errorf("last choice = %q, want %q", last, want)
	}
	// Every entry must survive the display -> value round trip unchanged,
	// which is what makes ParseRelayHops the exact inverse of the control.
	for i, s := range got {
		if n := ParseRelayHops(s); n != i+1 {
			t.Errorf("ParseRelayHops(%q) = %d, want %d", s, n, i+1)
		}
	}
}

// TestParseRelayHopsFallsBackRatherThanErroring pins the display layer's
// inverse on input it should never receive: an unset Select is "", and a
// hand-edited value is anything. Neither may produce a 0, which core would
// read as "unset" — the same answer as 1 today, but by accident rather than by
// this function's decision.
//
// Mutation check: returning 0 instead of 1 from the error branch, or dropping
// the NormalizeRelayHops call so "9" passes through, makes these go red.
func TestParseRelayHopsFallsBackRatherThanErroring(t *testing.T) {
	cases := map[string]int{
		"":             1,
		"   ":          1,
		"not a number": 1,
		"2":            2,
		"  3  ":        3, // trimmed, matching the trim every other input path applies
		"999":          core.RelayHopsMax,
		"0":            1,
		"-4":           1,
		"2.5":          1, // Atoi rejects it rather than truncating to 2
	}
	for in, want := range cases {
		if got := ParseRelayHops(in); got != want {
			t.Errorf("ParseRelayHops(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestValidateRelayChainConfigRequiresTheDirectoryPairTogether is the
// required-together rule: at 2+ hops core needs BOTH a directory to select
// hops from and a key to verify it, and either alone is refused at
// construction. Below 2 hops neither is needed, so a stale path left in the
// file must not block a save.
//
// Mutation check: changing the `||` to `&&` lets "path, no key" and "key, no
// path" through — both go red here. Changing `hops >= 2` to `hops > 2` lets a
// bare 2-hop chain save with no directory, which the 2-hop rows catch.
func TestValidateRelayChainConfigRequiresTheDirectoryPairTogether(t *testing.T) {
	cases := []struct {
		name    string
		hops    int
		path    string
		key     string
		wantErr bool
	}{
		{"one hop needs nothing", 1, "", "", false},
		{"unset hops needs nothing", 0, "", "", false},
		{"one hop tolerates a stale path left in the file", 1, "/etc/bacchus/relays.json", "", false},
		{"two hops with both is fine", 2, "/etc/bacchus/relays.json", testDirKey, false},
		{"the ceiling with both is fine", core.RelayHopsMax, "/etc/bacchus/relays.json", testDirKey, false},
		{"two hops with no directory at all", 2, "", "", true},
		{"two hops with a path but no key", 2, "/etc/bacchus/relays.json", "", true},
		{"two hops with a key but no path", 2, "", testDirKey, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPath, gotKey, err := ValidateRelayChainConfig(tc.hops, tc.path, tc.key)
			if tc.wantErr {
				if !errors.Is(err, ErrRelayChainConfig) {
					t.Fatalf("err = %v, want ErrRelayChainConfig", err)
				}
				// A rejected config must return nothing the caller could
				// mistake for validated values and persist anyway.
				if gotPath != "" || gotKey != "" {
					t.Errorf("rejected config still returned (%q, %q), want empty", gotPath, gotKey)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPath != strings.TrimSpace(tc.path) || gotKey != strings.TrimSpace(tc.key) {
				t.Errorf("got (%q, %q), want (%q, %q)", gotPath, gotKey, tc.path, tc.key)
			}
		})
	}
}

// TestValidateRelayChainConfigTrimsBeforeDeciding is the whitespace case the
// walk client's own doc calls out: a key that is only spaces is BLANK as far
// as core is concerned, so deciding before trimming accepts a config core then
// refuses — the exact confusing-late-error this validation exists to replace.
//
// Mutation check: move the two TrimSpace calls below the `if` and the
// whitespace rows go red while every row in the test above still passes. That
// is precisely why this is a separate test.
func TestValidateRelayChainConfigTrimsBeforeDeciding(t *testing.T) {
	if _, _, err := ValidateRelayChainConfig(2, "/etc/bacchus/relays.json", "   "); !errors.Is(err, ErrRelayChainConfig) {
		t.Errorf("whitespace-only key at 2 hops: err = %v, want ErrRelayChainConfig", err)
	}
	if _, _, err := ValidateRelayChainConfig(2, "  \t ", testDirKey); !errors.Is(err, ErrRelayChainConfig) {
		t.Errorf("whitespace-only path at 2 hops: err = %v, want ErrRelayChainConfig", err)
	}
	// And the accepted values are the TRIMMED ones, so what gets persisted is
	// what was validated rather than the raw widget text.
	path, key, err := ValidateRelayChainConfig(2, "  /etc/bacchus/relays.json  ", "  "+testDirKey+"\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/etc/bacchus/relays.json" || key != testDirKey {
		t.Errorf("got (%q, %q), want the trimmed pair", path, key)
	}
}

// TestValidateAdmissionConfigRejectsRevocationWithoutAnAnchor mirrors core's
// buildExitVerifier: a CRL path is meaningless without the public key that
// verifies exits in the first place, and core makes New() fail on the pair.
// Both blank (admission off) and a key alone (verify, skip revocation) are
// valid postures and must save.
//
// Mutation check: dropping the `crlPath != ""` half rejects the perfectly
// valid both-blank config; dropping the `pubKey == ""` half accepts the pair
// core refuses. Each makes a different row go red.
func TestValidateAdmissionConfigRejectsRevocationWithoutAnAnchor(t *testing.T) {
	cases := []struct {
		name    string
		pubKey  string
		crlPath string
		wantErr bool
	}{
		{"both blank is admission off", "", "", false},
		{"key alone verifies but skips revocation", testDirKey, "", false},
		{"key and path is the full posture", testDirKey, "/etc/bacchus/revocations.crl", false},
		{"a CRL with no anchor is what core refuses", "", "/etc/bacchus/revocations.crl", true},
		{"a whitespace-only anchor is still no anchor", "   ", "/etc/bacchus/revocations.crl", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotPath, err := ValidateAdmissionConfig(tc.pubKey, tc.crlPath)
			if tc.wantErr {
				if !errors.Is(err, ErrAdmissionConfig) {
					t.Fatalf("err = %v, want ErrAdmissionConfig", err)
				}
				if gotKey != "" || gotPath != "" {
					t.Errorf("rejected config still returned (%q, %q), want empty", gotKey, gotPath)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotKey != strings.TrimSpace(tc.pubKey) || gotPath != strings.TrimSpace(tc.crlPath) {
				t.Errorf("got (%q, %q), want the trimmed inputs", gotKey, gotPath)
			}
		})
	}
}

// TestSanitizePoolOrderAdmitsOnlyTunnelSafeTransports is the gate that stops a
// hand-edited config file putting a transport into the pool this client's
// tunnel could not make safe. Order is a user preference and must survive;
// membership is not negotiable.
//
// Mutation check: dropping the `!allowed[t]` term admits "tor"; dropping
// `seen[t]` admits the duplicate; building `out` from allowedPoolTransports
// instead of from `order` returns the default order and fails the
// reversed-preference row.
func TestSanitizePoolOrderAdmitsOnlyTunnelSafeTransports(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil stays empty, which is the pool off", nil, []string{}},
		{"a reversed preference is preserved", []string{core.TransportReality, core.TransportWebRTC}, []string{core.TransportReality, core.TransportWebRTC}},
		{"an unknown transport is dropped", []string{"tor", core.TransportWebRTC}, []string{core.TransportWebRTC}},
		{"a duplicate is dropped, first position wins", []string{core.TransportWebRTC, core.TransportReality, core.TransportWebRTC}, []string{core.TransportWebRTC, core.TransportReality}},
		{"an all-unknown ladder collapses to the pool being off", []string{"tor", "i2p"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizePoolOrder(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("SanitizePoolOrder(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestLadderDisplayOrderShowsEveryKnownTransport: a never-configured ladder
// must still show what it could contain, or the pool looks like it has one
// option. A partially-configured one keeps the user's order and gains the rest.
//
// Mutation check: returning `saved` unchanged makes the nil and partial rows go
// red; appending unconditionally (dropping the `have` check) duplicates an
// already-listed transport and fails the full-ladder row.
func TestLadderDisplayOrderShowsEveryKnownTransport(t *testing.T) {
	t.Run("a never-configured ladder shows all of them", func(t *testing.T) {
		got := LadderDisplayOrder(nil)
		if len(got) != len(knownPoolTransports) {
			t.Fatalf("got %v, want every known transport %v", got, knownPoolTransports)
		}
	})
	t.Run("a partial ladder keeps its order and gains the rest", func(t *testing.T) {
		got := LadderDisplayOrder([]string{core.TransportReality})
		want := []string{core.TransportReality, core.TransportWebRTC}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("a full ladder is returned unchanged, not doubled", func(t *testing.T) {
		in := []string{core.TransportReality, core.TransportWebRTC}
		got := LadderDisplayOrder(in)
		if !reflect.DeepEqual(got, in) {
			t.Fatalf("got %v, want %v", got, in)
		}
	})
	t.Run("the returned slice does not alias the input", func(t *testing.T) {
		in := []string{core.TransportReality, core.TransportWebRTC}
		got := LadderDisplayOrder(in)
		got[0] = "mutated"
		if in[0] != core.TransportReality {
			t.Fatalf("LadderDisplayOrder aliased its input: in = %v", in)
		}
	})
}

// TestMoveLadderItemIsInertAtTheEdges pins that a click at either end does
// nothing at all — no wrap-around, no clamp-and-move-to-the-end — so repeated
// clicks are boring rather than surprising, and that the input slice is never
// mutated (settings.go reassigns the result and would otherwise corrupt the
// ladder it is displaying).
//
// Mutation check: dropping the `j < 0 || j >= len(out)` guard makes the two
// edge rows panic or wrap; returning `order` instead of the copy makes the
// aliasing subtest go red.
func TestMoveLadderItemIsInertAtTheEdges(t *testing.T) {
	base := []string{"a", "b", "c"}
	cases := []struct {
		name string
		idx  int
		dir  int
		want []string
	}{
		{"middle up", 1, -1, []string{"b", "a", "c"}},
		{"middle down", 1, 1, []string{"a", "c", "b"}},
		{"first up is inert", 0, -1, []string{"a", "b", "c"}},
		{"last down is inert", 2, 1, []string{"a", "b", "c"}},
		{"nothing selected is inert", -1, -1, []string{"a", "b", "c"}},
		{"index past the end is inert", 9, 1, []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]string(nil), base...)
			got := MoveLadderItem(in, tc.idx, tc.dir)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("MoveLadderItem(%v, %d, %d) = %v, want %v", base, tc.idx, tc.dir, got, tc.want)
			}
			if !reflect.DeepEqual(in, base) {
				t.Fatalf("MoveLadderItem mutated its input: %v, want %v", in, base)
			}
		})
	}
}

// TestLoadRelayDirectoryReadsNothingBelowTwoHops: the default path must not
// touch the disk. A stale directory path in the config file is common (the
// user tried a chain, went back to one hop) and must not turn every connect
// into a file-not-found failure.
//
// Mutation check: changing `hops < 2` to `hops < 1`, or removing the early
// return, makes these go red with a read error on a path that does not exist.
func TestLoadRelayDirectoryReadsNothingBelowTwoHops(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	for _, hops := range []int{0, 1} {
		dir, key, err := LoadRelayDirectory(hops, missing, "not even hex")
		if err != nil {
			t.Fatalf("hops=%d: unexpected error: %v", hops, err)
		}
		if dir != nil || key != nil {
			t.Errorf("hops=%d: got (%v, %v), want both nil", hops, dir, key)
		}
	}
}

// TestLoadRelayDirectoryDecodesTheSignedPair covers the happy path and both
// failure shapes at 2+ hops. These fail HERE, named, rather than as core's
// "relay chaining needs a signed relay directory" from a field the user cannot
// tell was the cause — which is the entire reason this is not left to core.
//
// Mutation check: dropping the `len(k) != ed25519.PublicKeySize` term accepts
// the short key; dropping the `err != nil` term accepts the non-hex one;
// returning the raw string instead of the decoded bytes fails the length
// assertion in the happy path.
func TestLoadRelayDirectoryDecodesTheSignedPair(t *testing.T) {
	dirPath := filepath.Join(t.TempDir(), "relays.json")
	body := []byte(`{"snapshot":"opaque to this client — core verifies it"}`)
	if err := os.WriteFile(dirPath, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("a readable file and a well-formed key decode", func(t *testing.T) {
		gotDir, gotKey, err := LoadRelayDirectory(2, dirPath, testDirKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(gotDir, body) {
			t.Errorf("directory bytes = %q, want %q", gotDir, body)
		}
		if len(gotKey) != ed25519.PublicKeySize {
			t.Errorf("key length = %d, want %d", len(gotKey), ed25519.PublicKeySize)
		}
		want, _ := hex.DecodeString(testDirKey)
		if !reflect.DeepEqual([]byte(gotKey), want) {
			t.Errorf("key = %x, want %x", gotKey, want)
		}
	})

	t.Run("surrounding whitespace on the key is tolerated", func(t *testing.T) {
		if _, _, err := LoadRelayDirectory(2, dirPath, "  "+testDirKey+"\n"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("a missing file is named as a read failure", func(t *testing.T) {
		_, _, err := LoadRelayDirectory(2, filepath.Join(t.TempDir(), "absent.json"), testDirKey)
		if err == nil || !strings.Contains(err.Error(), "read relay directory") {
			t.Fatalf("err = %v, want a read-relay-directory error", err)
		}
		// Wrapped, so a caller can still ask what kind of read failure it was.
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("err does not unwrap to os.ErrNotExist: %v", err)
		}
	})

	t.Run("a malformed key is rejected before core sees it", func(t *testing.T) {
		for _, bad := range []string{
			"not hex at all",
			strings.Repeat("ab", ed25519.PublicKeySize-1), // right shape, one byte short
			strings.Repeat("ab", ed25519.PublicKeySize+1), // one byte long
			"",
		} {
			if _, _, err := LoadRelayDirectory(2, dirPath, bad); err == nil {
				t.Errorf("key %q was accepted, want a rejection", bad)
			}
		}
	})
}

// TestNewConfigFieldsUseTheWalkClient'sJSONKeys — the two clients read each
// other's documentation and their config files are compared by hand; a key
// that differs by a letter is a setting that silently does not load. These are
// asserted against literal strings rather than against clients/windows's
// struct, which is package main behind a windows build tag and importable from
// nowhere.
//
// Mutation check: rename any json tag (relayHops -> relay_hops, say) and the
// corresponding row goes red. A test that marshalled and unmarshalled through
// the same struct would pass under any renaming, which is why the expected
// keys are written out.
func TestNewConfigFieldsUseTheWalkClientsJSONKeys(t *testing.T) {
	b, err := json.Marshal(Config{
		TransportPool:      []string{core.TransportWebRTC},
		RelayHops:          2,
		RelayDirectoryPath: "/etc/bacchus/relays.json",
		RelayDirectoryKey:  testDirKey,
		AdmissionPubKey:    testDirKey,
		AdmissionCRLPath:   "/etc/bacchus/revocations.crl",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{
		"transportPool",
		"relayHops",
		"relayDirectoryPath",
		"relayDirectoryKey",
		"admissionPubKey",
		"admissionCrlPath",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("config JSON has no %q key; got %v", key, sortedKeys(raw))
		}
	}
}

// TestConfigRoundTripsTheNewFields is the load/save half: a value set in the
// dialog must survive being written and read back, including the slice, which
// is the field most likely to be dropped by a shallow copy.
//
// Mutation check: remove any of the six json tags and its field round-trips to
// its zero value, failing the comparison.
func TestConfigRoundTripsTheNewFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bacchus-fyne.config.json")
	want := Config{
		Coordinators:       []string{"203.0.113.10:8080"}, // TEST-NET-3 (RFC 5737): never a real Bacchus endpoint
		TransportPool:      []string{core.TransportReality, core.TransportWebRTC},
		RelayHops:          3,
		RelayDirectoryPath: "/etc/bacchus/relays.json",
		RelayDirectoryKey:  testDirKey,
		AdmissionPubKey:    testDirKey,
		AdmissionCRLPath:   "/etc/bacchus/revocations.crl",
	}
	if err := SaveConfig(path, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got Config
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed the config:\n got %+v\nwant %+v", got, want)
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
