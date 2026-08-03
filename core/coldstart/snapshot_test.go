package coldstart

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func testSnapshot() Snapshot {
	return Snapshot{
		Version:   SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []Entry{
			{Role: "coordinator", ID: "coord-1", Addr: "203.0.113.1:3478"},
			{Role: "exit", ID: "exit-1", Country: "RS", Addr: "203.0.113.2:20000"},
		},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	snap := testSnapshot()
	signed, err := Sign(priv, snap)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Verify(pub, signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.Entries) != len(snap.Entries) || got.Entries[0].ID != snap.Entries[0].ID {
		t.Fatalf("verified snapshot entries mismatch: %+v", got)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	signed, err := Sign(priv, testSnapshot())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(otherPub, signed); err != ErrBadSignature {
		t.Fatalf("Verify with wrong key: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed, err := Sign(priv, testSnapshot())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed[0] ^= 0xFF
	if _, err := Verify(pub, signed); err != ErrBadSignature {
		t.Fatalf("Verify tampered: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	snap := testSnapshot()
	snap.ExpiresAt = time.Now().Add(-time.Minute)
	signed, err := Sign(priv, snap)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(pub, signed); err != ErrSnapshotExpired {
		t.Fatalf("Verify expired: err = %v, want ErrSnapshotExpired", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(pub, []byte("too short")); err != ErrMalformedSnapshot {
		t.Fatalf("Verify malformed: err = %v, want ErrMalformedSnapshot", err)
	}
}

// relaySnapshot is a snapshot whose sole relay entry advertises an onion-forward
// ingress and an operator tag (issue #124) — the directory metadata the relay-chaining
// epic (#76) gates on. Addr (the observed signaling address) is deliberately a DIFFERENT
// host from Ingress so a test can tell the two fields apart.
func relaySnapshot() Snapshot {
	return Snapshot{
		Version:   SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []Entry{
			{Role: "coordinator", ID: "coord-1", Addr: "203.0.113.1:3478"},
			{
				Role: "relay", ID: "relay-1", Addr: "198.51.100.7:20000",
				Ingress: "203.0.113.7:8443", Operator: "op-acme-subtree",
			},
		},
	}
}

// TestVerifyCoversRelayFields is the load-bearing signing test for #124: the new
// ingress and operator fields round-trip through Sign/Verify, AND each is inside the
// signed body — mutating its bytes after signing makes Verify reject, and restoring
// them makes it accept again. The restore step is what makes the test non-vacuous: it
// proves the rejection was caused by tampering THAT field, not by an already-broken blob.
func TestVerifyCoversRelayFields(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed, err := Sign(priv, relaySnapshot())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Baseline: the fields survive a clean round-trip.
	got, err := Verify(pub, signed)
	if err != nil {
		t.Fatalf("baseline Verify: %v", err)
	}
	relay := got.Entries[1]
	if relay.Ingress != "203.0.113.7:8443" || relay.Operator != "op-acme-subtree" {
		t.Fatalf("round-trip dropped a relay field: %+v", relay)
	}

	// Each field is covered by the signature: an equal-length in-place edit (which keeps
	// the JSON well-formed and the signature offset stable) is rejected; restoring it is
	// accepted.
	for _, tc := range []struct{ name, from, to string }{
		{"ingress", "203.0.113.7:8443", "203.0.113.9:8443"},
		{"operator", "op-acme-subtree", "op-evil-subtree"},
	} {
		if len(tc.from) != len(tc.to) {
			t.Fatalf("%s: test bug, mutation must preserve length", tc.name)
		}
		i := bytes.Index(signed, []byte(tc.from))
		if i < 0 {
			t.Fatalf("%s: value %q not found in signed blob", tc.name, tc.from)
		}
		copy(signed[i:], tc.to)
		if _, err := Verify(pub, signed); err != ErrBadSignature {
			t.Fatalf("%s tampered: err = %v, want ErrBadSignature", tc.name, err)
		}
		copy(signed[i:], tc.from)
		if _, err := Verify(pub, signed); err != nil {
			t.Fatalf("%s restored: err = %v, want nil", tc.name, err)
		}
	}
}

// TestSnapshotBackwardCompatible proves the addition is wire-compatible both ways, so
// it needs no version bump: a pre-#124 snapshot (no ingress/operator keys) verifies
// under the current parser, and a #124 snapshot decodes under a parser that predates
// the fields.
func TestSnapshotBackwardCompatible(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Direction 1 — pre-#124 wire, current parser. A relay that advertises no ingress
	// and no operator marshals to JSON with NEITHER key (omitempty), byte-identical to a
	// coordinator predating #124. It still verifies, and its relay is simply not
	// relay-eligible.
	old := Snapshot{
		Version:   SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries:   []Entry{{Role: "relay", ID: "relay-1", Addr: "198.51.100.7:20000"}},
	}
	signed, err := Sign(priv, old)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	body := signed[:len(signed)-signedLen]
	if bytes.Contains(body, []byte("ingress")) || bytes.Contains(body, []byte("operator")) {
		t.Fatalf("an ingress-less/operator-less snapshot must carry neither key: %s", body)
	}
	got, err := Verify(pub, signed)
	if err != nil {
		t.Fatalf("Verify pre-field snapshot: %v", err)
	}
	if got.Entries[0].RelayEligible() {
		t.Fatal("a relay advertising no ingress must not be relay-eligible")
	}

	// Direction 2 — #124 wire, pre-#124 parser. A snapshot carrying the new fields still
	// decodes under a struct that predates them; the unknown keys are ignored and every
	// field an old client knows survives.
	newSigned, err := Sign(priv, relaySnapshot())
	if err != nil {
		t.Fatalf("Sign new: %v", err)
	}
	type oldEntry struct {
		Role    string `json:"role"`
		ID      string `json:"id"`
		Country string `json:"country,omitempty"`
		Addr    string `json:"addr"`
	}
	type oldSnapshot struct {
		Version   int        `json:"version"`
		IssuedAt  time.Time  `json:"issuedAt"`
		ExpiresAt time.Time  `json:"expiresAt"`
		Entries   []oldEntry `json:"entries"`
	}
	var parsed oldSnapshot
	if err := json.Unmarshal(newSigned[:len(newSigned)-signedLen], &parsed); err != nil {
		t.Fatalf("pre-field parser must decode a #124 snapshot: %v", err)
	}
	if len(parsed.Entries) != 2 || parsed.Entries[1].ID != "relay-1" || parsed.Entries[1].Addr != "198.51.100.7:20000" {
		t.Fatalf("pre-field parser lost a known field: %+v", parsed.Entries)
	}
}

// TestRelayEligible pins the directory-side eligibility gate the acceptance names:
// a node is a candidate hop only if it is a relay AND advertises a forwarding ingress.
func TestRelayEligible(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    Entry
		want bool
	}{
		{"relay with ingress", Entry{Role: "relay", ID: "r", Ingress: "203.0.113.7:8443"}, true},
		{"relay without ingress", Entry{Role: "relay", ID: "r"}, false},
		{"exit with an ingress value", Entry{Role: "exit", ID: "e", Ingress: "203.0.113.7:8443"}, false},
		{"coordinator", Entry{Role: "coordinator", ID: "c", Addr: "203.0.113.1:3478"}, false},
	} {
		if got := tc.e.RelayEligible(); got != tc.want {
			t.Errorf("%s: RelayEligible() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// declaredSnapshot is a snapshot whose exit declares a country that DISAGREES with the
// one the coordinator published for it (issue #113) — the ordinary shape on cloud
// address space, where a provider's block is registered to its home country whatever
// datacentre the instance runs in.
func declaredSnapshot() Snapshot {
	return Snapshot{
		Version:   SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []Entry{
			{Role: "coordinator", ID: "coord-1", Addr: "203.0.113.1:3478"},
			{
				Role: "exit", ID: "exit-1", Addr: "203.0.113.2:20000",
				Country: "US", CountrySource: CountryObserved, DeclaredCountry: "DE",
			},
		},
	}
}

// TestDeclaredCountryIsSignedAndAdditive is the wire half of issue #113: the node's own
// declaration travels in the SIGNED directory beside the derived country, and adding it
// moved nothing.
//
// Both halves matter. A field outside the signature would be a self-report an attacker
// on the path could edit at will — worse than not carrying it, since it would arrive
// wearing the coordinator's authority. And a field that shifted the wire would force
// SnapshotVersion, which is what omitempty and the Ingress/Operator pattern exist to
// avoid.
func TestDeclaredCountryIsSignedAndAdditive(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// The version did not move. Stated as an assertion rather than left to a reader,
	// because it is the whole claim the additive shape is buying.
	if SnapshotVersion != 1 {
		t.Errorf("SnapshotVersion = %d; #113 is additive and must not move it", SnapshotVersion)
	}

	signed, err := Sign(priv, declaredSnapshot())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Verify(pub, signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Entries[1].DeclaredCountry != "DE" || got.Entries[1].Country != "US" {
		t.Fatalf("round trip lost a country claim: %+v", got.Entries[1])
	}

	// Inside the signature: an equal-length in-place edit is rejected, and restoring it
	// is accepted — the restore is what makes the rejection about THIS field rather
	// than about an already-broken blob.
	i := bytes.Index(signed, []byte(`"declaredCountry":"DE"`))
	if i < 0 {
		t.Fatalf("declaredCountry missing from the signed blob: %s", signed)
	}
	copy(signed[i:], []byte(`"declaredCountry":"RU"`))
	if _, err := Verify(pub, signed); err != ErrBadSignature {
		t.Fatalf("declaredCountry tampered: err = %v, want ErrBadSignature — the declaration must be covered by the signature", err)
	}
	copy(signed[i:], []byte(`"declaredCountry":"DE"`))
	if _, err := Verify(pub, signed); err != nil {
		t.Fatalf("declaredCountry restored: err = %v, want nil", err)
	}
}

// TestPreDeclarationSnapshotIsByteIdentical is the compatibility claim stated exactly:
// an entry from a coordinator predating #113 — one that declares nothing — marshals with
// NO declaredCountry key at all, so the bytes a pre-change coordinator signed are the
// bytes this one signs. And a #113 snapshot still decodes under a parser that predates
// the field.
func TestPreDeclarationSnapshotIsByteIdentical(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	old := Snapshot{
		Version:   SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []Entry{
			{Role: "exit", ID: "exit-1", Country: "NL", CountrySource: CountryObserved, Addr: "203.0.113.2:20000"},
		},
	}
	signed, err := Sign(priv, old)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	body := signed[:len(signed)-signedLen]
	if bytes.Contains(body, []byte("declaredCountry")) {
		t.Fatalf("an entry with no declaration must carry no declaredCountry key: %s", body)
	}
	if _, err := Verify(pub, signed); err != nil {
		t.Fatalf("Verify pre-declaration snapshot: %v", err)
	}

	// A pre-#113 parser reading a #113 snapshot: the unknown key is ignored and every
	// field it does know survives, including the country it selects on.
	newSigned, err := Sign(priv, declaredSnapshot())
	if err != nil {
		t.Fatalf("Sign new: %v", err)
	}
	type oldEntry struct {
		Role          string `json:"role"`
		ID            string `json:"id"`
		Country       string `json:"country,omitempty"`
		CountrySource string `json:"countrySource,omitempty"`
		Addr          string `json:"addr"`
	}
	type oldSnapshot struct {
		Version int        `json:"version"`
		Entries []oldEntry `json:"entries"`
	}
	var parsed oldSnapshot
	if err := json.Unmarshal(newSigned[:len(newSigned)-signedLen], &parsed); err != nil {
		t.Fatalf("pre-#113 parser must decode a #113 snapshot: %v", err)
	}
	if parsed.Version != SnapshotVersion {
		t.Errorf("version = %d, want %d — the addition must not need a bump", parsed.Version, SnapshotVersion)
	}
	if parsed.Entries[1].Country != "US" || parsed.Entries[1].CountrySource != CountryObserved {
		t.Errorf("pre-#113 parser lost a known field: %+v", parsed.Entries[1])
	}
}

// TestDeclaredCountryIsNotElidedWhenItAgrees pins the decision NOT to drop the field
// when the node's declaration matches what the coordinator derived.
//
// Eliding would save bytes and destroy the distinction between "declared nothing" and
// "declared, and it checked out" — the exact collapse ADR-0042's #2 amendment closed for
// the advertised endpoint, where treating "made no claim" as "made a claim that checks
// out" is what let the check be bypassed by omission.
func TestDeclaredCountryIsNotElidedWhenItAgrees(t *testing.T) {
	e := Entry{Role: "exit", ID: "e", Addr: "203.0.113.2:20000", Country: "DE", CountrySource: CountryObserved, DeclaredCountry: "DE"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"declaredCountry":"DE"`)) {
		t.Errorf("an agreeing declaration was elided: %s — a consumer must be able to tell it from a node that declared nothing", b)
	}
	if e.DeclaredCountryDiffers() {
		t.Error("an agreeing declaration reported itself as differing")
	}
}

// TestDeclaredCountryDiffers pins the observation predicate, including both cases where
// there is nothing to observe.
func TestDeclaredCountryDiffers(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    Entry
		want bool
	}{
		{"disagree", Entry{Country: "US", DeclaredCountry: "DE"}, true},
		{"agree", Entry{Country: "DE", DeclaredCountry: "DE"}, false},
		{"declared nothing", Entry{Country: "US"}, false},
		{"no country published", Entry{DeclaredCountry: "DE", CountrySource: CountryNoEndpoint}, false},
		{"neither", Entry{}, false},
		// The comparison is against the PUBLISHED country, so under an admin override it
		// reports the node's claim against the admin's correction.
		{"against an override", Entry{Country: "US", CountrySource: CountryAdminOverride, DeclaredCountry: "DE"}, true},
	} {
		if got := tc.e.DeclaredCountryDiffers(); got != tc.want {
			t.Errorf("%s: DeclaredCountryDiffers() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestCountryContradictedDoesNotLearnTheDeclaration is the trap issue #113 names, pinned
// so nobody walks into it later.
//
// CountryContradicted is FAIL-CLOSED: core/relaychain refuses a contradicted entry as a
// terminating exit. What it names is the coordinator's own two OBSERVATIONS disagreeing.
// A node's DECLARATION disagreeing with an observation is a different thing and the
// ordinary case — the fleet that found #113 disagreed on two exits out of three — so
// folding it in here would refuse most of a cloud fleet and stop a client chaining at
// all against a coordinator behaving exactly as it always has.
func TestCountryContradictedDoesNotLearnTheDeclaration(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    Entry
		want bool
	}{
		{"declaration disagrees with an observed country", Entry{Country: "US", CountrySource: CountryObserved, DeclaredCountry: "DE"}, false},
		{"declaration disagrees with a hinted country", Entry{Country: "US", CountrySource: CountryHinted, DeclaredCountry: "DE"}, false},
		{"declaration disagrees under an admin override", Entry{Country: "US", CountrySource: CountryAdminOverride, DeclaredCountry: "DE"}, false},
		// Non-vacuity: the one case that IS contradicted still is, declaration or no.
		{"the observed split still contradicts", Entry{Country: "NL", CountrySource: CountrySignalingOnly, DeclaredCountry: "NL"}, true},
	} {
		if got := tc.e.CountryContradicted(); got != tc.want {
			t.Errorf("%s: CountryContradicted() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
