package accountclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// This file is the public half of a cross-repo conformance check, and it exists
// because everything else in this package's tests is a conversation this package
// is having with itself.
//
// client_test.go's fake service answers with JSON this package wrote. That
// proves the client is internally consistent and proves nothing about whether
// the account service would accept a single byte of it — the exact failure Wave
// 21 found one repository over, where two lanes each implemented the same wire
// format internally consistently and every check passed.
//
// testdata/wire_vectors.json is the answer: it is a recording of the REAL
// account-service handlers talking to THIS client, captured by a harness that
// imports both repositories from a throwaway module with replace directives.
// Neither repository gains a dependency on the other — bacchus cannot import
// bacchus-payment, which is private, and doing so would end this repository's
// publishability. What crosses the boundary is bytes.
//
// The two directions this file checks are different and both matter:
//
//   - RESPONSES: this client must parse what the service really sends. A test
//     against self-authored fixtures cannot fail on a field the service spells
//     differently.
//   - REQUESTS: what this client sends must keep the field set the service
//     really accepted. Renaming device_pub would pass every other test in this
//     package and be rejected by the service on the first real enrollment.

type frozenExchange struct {
	Verb     string          `json:"verb"`
	Request  json.RawMessage `json:"request"`
	Status   int             `json:"status"`
	Response json.RawMessage `json:"response"`
}

type frozenVectors struct {
	Note      string           `json:"note"`
	Audience  string           `json:"audience"`
	Exchanges []frozenExchange `json:"exchanges"`
}

func loadVectors(t *testing.T) frozenVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/wire_vectors.json")
	if err != nil {
		t.Fatalf("read frozen vectors: %v", err)
	}
	var v frozenVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode frozen vectors: %v", err)
	}
	if len(v.Exchanges) == 0 {
		t.Fatal("the frozen vectors are empty")
	}
	return v
}

func firstExchange(t *testing.T, v frozenVectors, verb string, status int) frozenExchange {
	t.Helper()
	for _, e := range v.Exchanges {
		if e.Verb == verb && e.Status == status {
			return e
		}
	}
	t.Fatalf("no frozen %s exchange with status %d", verb, status)
	return frozenExchange{}
}

func keysOf(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode object: %v", err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestFrozenResponsesFromTheRealServiceParse replays the account service's own
// bytes at this client and asserts it comes away with the credential.
func TestFrozenResponsesFromTheRealServiceParse(t *testing.T) {
	v := loadVectors(t)

	challenge := firstExchange(t, v, "/v1/challenge", 200)
	var ch challengeResponse
	if err := json.Unmarshal(challenge.Response, &ch); err != nil {
		t.Fatalf("this client cannot parse the real /v1/challenge response: %v", err)
	}
	// The assertion this client is about to sign rests on the challenge being
	// unpredictable, and both signer and verifier enforce a floor of 16 bytes.
	if len(ch.Challenge) < 16 {
		t.Fatalf("the real service's challenge decoded to %d bytes; the signer refuses anything under 16", len(ch.Challenge))
	}
	if ch.ExpiresAt.IsZero() || ch.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expires_at = %v; the wire convention is RFC 3339 UTC", ch.ExpiresAt)
	}

	for _, verb := range []string{"/v1/enroll", "/v1/credential"} {
		e := firstExchange(t, v, verb, 200)
		var got credentialsResponse
		if err := json.Unmarshal(e.Response, &got); err != nil {
			t.Fatalf("this client cannot parse the real %s response: %v", verb, err)
		}
		if !strings.HasPrefix(got.Device, "bacchusd1:") {
			t.Fatalf("%s device = %q, want a bacchusd1: envelope", verb, got.Device)
		}
		if !strings.HasPrefix(got.IssuerCert, "bacchusi1:") {
			t.Fatalf("%s issuer_cert = %q, want a bacchusi1: envelope", verb, got.IssuerCert)
		}
		// The service under this recording had an admission key, so this half
		// of the response is present. A deployment without one omits it and
		// that is a real deployment — TestAdmissionAbsentIsNotAnError covers
		// the other side.
		if !strings.HasPrefix(got.Admission, "bacchusc1:") {
			t.Fatalf("%s admission = %q, want a bacchusc1: envelope", verb, got.Admission)
		}
	}
}

// TestFrozenErrorsFromTheRealServiceDecode: the error envelope is the thing a
// client branches on, and this pins that the real one decodes into the closed
// vocabulary rather than into an unrecognized token.
func TestFrozenErrorsFromTheRealServiceDecode(t *testing.T) {
	v := loadVectors(t)
	want := map[string]Code{
		"/v1/enroll":     CodeClaimRejected, // a claim code spent by an earlier enrollment
		"/v1/credential": CodeBadAssertion,  // a device that was never enrolled
	}
	for verb, wantCode := range want {
		e := firstExchange(t, v, verb, 403)
		err := decodeError(verb, e.Status, e.Response)
		code, ok := CodeOf(err)
		if !ok {
			t.Fatalf("the real %s refusal did not decode as a coded refusal: %v", verb, err)
		}
		if code != wantCode {
			t.Fatalf("%s refusal = %q, want %q", verb, code, wantCode)
		}
		var typed *Error
		if !errors.As(err, &typed) || !typed.Recognized {
			t.Fatalf("%s returned a code this build does not recognize: %v", verb, err)
		}
		// The envelope carries a code and, on these two, nothing else. A
		// message field is what would leak the thing the code was chosen to
		// withhold, so its absence is a property worth failing over.
		if k := keysOf(t, e.Response); len(k) != 1 || k[0] != "error" {
			t.Fatalf("%s error body has keys %v, want exactly [error]", verb, k)
		}
		var body map[string]map[string]any
		if err := json.Unmarshal(e.Response, &body); err != nil {
			t.Fatal(err)
		}
		if _, leaked := body["error"]["message"]; leaked {
			t.Fatalf("%s error body carries a message field", verb)
		}
	}
}

// TestThisClientsRequestsMatchWhatTheServiceAccepted is the direction that
// self-authored fixtures cannot check. The frozen requests are the bodies the
// real handler actually served; this rebuilds them from this package's own
// types and compares the field sets.
func TestThisClientsRequestsMatchWhatTheServiceAccepted(t *testing.T) {
	v := loadVectors(t)

	cases := []struct {
		verb  string
		build func() any
	}{
		{"/v1/enroll", func() any {
			return enrollRequest{Claim: "x", DevicePub: make([]byte, 32), Label: "l", Challenge: make([]byte, 32), Sig: make([]byte, 64)}
		}},
		{"/v1/credential", func() any {
			return credentialRequest{DevicePub: make([]byte, 32), Challenge: make([]byte, 32), Sig: make([]byte, 64)}
		}},
	}
	for _, tc := range cases {
		frozen := firstExchange(t, v, tc.verb, 200)
		mine, err := json.Marshal(tc.build())
		if err != nil {
			t.Fatal(err)
		}
		got, want := keysOf(t, mine), keysOf(t, frozen.Request)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s request fields = %v, but the real service was sent and accepted %v", tc.verb, got, want)
		}
	}

	// And the encodings, checked on the frozen bytes rather than on this
	// package's own output: raw byte fields are PADDED standard base64 and the
	// key is 32 bytes, which is the one encoding decision that spans this
	// document and the signed bodies it carries.
	enroll := firstExchange(t, v, "/v1/enroll", 200)
	var raw map[string]any
	if err := json.Unmarshal(enroll.Request, &raw); err != nil {
		t.Fatal(err)
	}
	for field, wantLen := range map[string]int{"device_pub": 32, "sig": 64} {
		s, ok := raw[field].(string)
		if !ok {
			t.Fatalf("%s is not a string in the frozen request", field)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("%s is not padded standard base64: %v", field, err)
		}
		if len(b) != wantLen {
			t.Fatalf("%s decoded to %d bytes, want %d", field, len(b), wantLen)
		}
	}
	if ch, ok := raw["challenge"].(string); !ok {
		t.Fatal("challenge is not a string")
	} else if b, err := base64.StdEncoding.DecodeString(ch); err != nil || len(b) < 16 {
		t.Fatalf("challenge decoded to %d bytes (err %v); the floor is 16", len(b), err)
	}
	if _, ok := raw["claim"].(string); !ok {
		t.Fatal("claim is not a string in the frozen request")
	}
	// The two fields the seam carries but the wire must not: the service
	// resolves the account by public key and has no parameter for them.
	credReq := firstExchange(t, v, "/v1/credential", 200)
	for _, forbidden := range []string{"current_cred", "cred", "issuer_cert"} {
		if strings.Contains(string(credReq.Request), forbidden) {
			t.Fatalf("the frozen /v1/credential request carries %q", forbidden)
		}
	}
}

// TestFrozenVectorsCarryNoLiveSecret is a publishability check, not a protocol
// one. This repository is public and must hold zero credentials at every commit;
// the vectors are throwaway by construction, and the one field shaped like a
// live bearer secret is redacted before freezing. This fails if that ever stops
// being true.
func TestFrozenVectorsCarryNoLiveSecret(t *testing.T) {
	b, err := os.ReadFile("testdata/wire_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v frozenVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, e := range v.Exchanges {
		var m map[string]any
		if json.Unmarshal(e.Request, &m) != nil {
			continue
		}
		claim, ok := m["claim"].(string)
		if !ok {
			continue
		}
		if !strings.Contains(claim, "REDACTED") {
			t.Fatalf("a claim code reached the committed vectors: the harness's redaction step is not running")
		}
	}
	// A recovery token would be a live secret too, and no verb this package
	// speaks returns one — so finding the prefix here means something other
	// than these three verbs was recorded.
	if strings.Contains(string(b), "BR1-") {
		t.Fatal("a recovery token prefix appears in the committed vectors")
	}
}
