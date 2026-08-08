package revocation_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/revocation"
)

// TestParseBundleRequiresBothMembers mirrors core/policy's identical test:
// ParseBundle refuses a bundle missing either member here rather than
// producing a confusing signature failure downstream.
func TestParseBundleRequiresBothMembers(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"empty object", `{}`},
		{"document only", `{"revocations":"AAAA"}`},
		{"delegation only", `{"cert":"AAAA"}`},
		{"null members", `{"revocations":null,"cert":null}`},
		{"not an object", `[]`},
		{"not JSON", `nope`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := revocation.ParseBundle([]byte(tc.raw)); !errors.Is(err, revocation.ErrMalformed) {
				t.Fatalf("ParseBundle(%s) = %v, want ErrMalformed", tc.raw, err)
			}
		})
	}
}

// TestNewVerifierFailsClosedWithoutARoot pins the direction of failure. This
// mirrors core/policy.NewVerifier exactly, for the identical reason: a
// coordinator with no trust anchor cannot verify anything, and returning
// success anyway would enforce a revoked-serials list from whoever asked.
func TestNewVerifierFailsClosedWithoutARoot(t *testing.T) {
	for _, root := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if _, err := revocation.NewVerifier(root, nil); err == nil {
			t.Errorf("NewVerifier(root len %d) succeeded, want a refusal", len(root))
		}
	}
}

// TestDocRoundTripsAnEmptyRevokedList pins that "nothing is revoked" is an
// ordinary Doc rather than a special case: a fresh deployment or a fully-aged-
// out list must marshal and unmarshal like any other, matching
// bacchus-payment/internal/revocation's own "explicit empty-list" fixture case.
func TestDocRoundTripsAnEmptyRevokedList(t *testing.T) {
	d := revocation.Doc{Version: revocation.Version, AsOf: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC), Revoked: []string{}}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back revocation.Doc
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Version != d.Version || !back.AsOf.Equal(d.AsOf) || len(back.Revoked) != 0 {
		t.Fatalf("round trip changed an empty-revoked Doc: got %+v", back)
	}
}

// TestBundleFieldsAreStandardBase64OnTheWire pins the JSON encoding of
// Bundle's two []byte members, which is the entire reason they are typed
// []byte rather than string: encoding/json base64-encodes a []byte with
// STANDARD (padded) encoding by default, matching the frozen vectors' "bundle"
// object and bacchus-payment's identical Bundle shape byte for byte.
func TestBundleFieldsAreStandardBase64OnTheWire(t *testing.T) {
	b := revocation.Bundle{Revocations: []byte("hello"), Cert: []byte("world!")}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("unmarshal to raw: %v", err)
	}
	if raw["revocations"] != "aGVsbG8=" {
		t.Errorf(`"revocations" = %q, want standard base64 "aGVsbG8="`, raw["revocations"])
	}
	if raw["cert"] != "d29ybGQh" {
		t.Errorf(`"cert" = %q, want standard base64 "d29ybGQh"`, raw["cert"])
	}

	parsed, err := revocation.ParseBundle(out)
	if err != nil {
		t.Fatalf("ParseBundle round trip: %v", err)
	}
	if string(parsed.Revocations) != "hello" || string(parsed.Cert) != "world!" {
		t.Fatalf("ParseBundle round trip changed the bytes: %+v", parsed)
	}
}
