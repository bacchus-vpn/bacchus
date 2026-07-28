package policy_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/policy"
)

// The two files in testdata are FROZEN conformance fixtures, copied verbatim from
// the private repository that owns the signer and the reference verifier. That
// repository cannot be imported here, so the wire format is the contract and these
// bytes are what keep two independent implementations agreeing.
//
// They are not regenerated on this side. A change to either file is a deliberate
// format change made where the signer lives, and arrives here as a copy.
//
// Every key in them is a published throwaway rooted in the private repository's
// development root, whose private key is derived from a constant printed in its own
// source. TestVectorsUseAThrowawayRoot below re-proves that here rather than
// trusting the note in the file, because these bytes live in a public repository
// and "the fixture says it is a test key" is exactly what a leaked real key would
// also look like.
const (
	positiveVectors = "testdata/vectors.json"
	negativeVectors = "testdata/negative_vectors.json"
)

// devRootSeedPhrase is the published constant the fixtures' root key is derived
// from. It is reproduced here so this repository can PROVE the trust anchor in its
// testdata is the throwaway one, without importing the private module.
const devRootSeedPhrase = "BACCHUS DEVELOPMENT ROOT - PUBLIC THROWAWAY KEY - NOT A REAL ROOT - DO NOT USE IN PRODUCTION"

type posVectors struct {
	Note    string          `json:"note"`
	Now     string          `json:"now"`
	RootPub string          `json:"root_pub"`
	Bundle  json.RawMessage `json:"bundle"`

	ExpectSeq                uint64 `json:"expect_seq"`
	ExpectSignerPub          string `json:"expect_signer_pub"`
	ExpectDelegationSerial   string `json:"expect_delegation_serial"`
	ExpectMinMeasuredBps     uint64 `json:"expect_min_measured_bps"`
	ExpectMinDeclaredQuota   uint64 `json:"expect_min_declared_quota_bytes"`
	ExpectMinServingVersion  string `json:"expect_min_serving_version"`
	ExpectMinCountryHeadroom uint64 `json:"expect_min_country_headroom_bps"`
	ExpectVouchK             int    `json:"expect_vouch_k"`
	ExpectVouchBudget        int    `json:"expect_vouch_budget"`
	ExpectVouchPeriodNanos   int64  `json:"expect_vouch_period_nanos"`
	ExpectStableProSpeedCap  uint64 `json:"expect_stable_pro_speed_cap_bps"`
	ExpectStableProPriority  int    `json:"expect_stable_pro_priority"`
	ExpectDeadline           string `json:"expect_deadline"`
}

// negCase is one frozen refusal.
type negCase struct {
	Name   string          `json:"name"`
	Bundle json.RawMessage `json:"bundle"`
	Now    string          `json:"now"`
	// MinSeq is the highest sequence the verifier has already accepted, which is the
	// only thing that catches a rollback.
	MinSeq uint64 `json:"min_seq"`
	// RevokedSerial, when set, is the delegation serial the verifier's revocation
	// predicate must report revoked.
	RevokedSerial string `json:"revoked_serial,omitempty"`
	ExpectError   string `json:"expect_error"`
}

type negVectors struct {
	Note    string    `json:"note"`
	RootPub string    `json:"root_pub"`
	Cases   []negCase `json:"cases"`
}

// negTokenErr maps the stable token in expect_error to the sentinel it names. The
// file holds tokens rather than Go error strings so a port in another language can
// consume it, and so a reworded message is not a fixture change.
//
// Note that two tokens map into the delegation package and the rest into this one.
// That split is the contract, not an accident of layering: an error about the
// DELEGATION is a delegation-package fact, and one about the DOCUMENT is a policy
// fact. A port that collapsed them into one sentinel would pass every case here
// while being unable to tell an operator whether the cert or the document was the
// problem.
func negTokenErr(token string) (error, bool) {
	switch token {
	case "bad_signature":
		return delegation.ErrBadSignature, true
	case "wrong_role":
		return delegation.ErrWrongRole, true
	case "delegation_expired":
		return delegation.ErrExpired, true
	case "delegation_revoked":
		return delegation.ErrRevoked, true
	case "no_root":
		return delegation.ErrNoRoot, true
	case "delegation_malformed":
		return delegation.ErrMalformed, true
	case "stale":
		return policy.ErrStale, true
	case "not_yet_issued":
		return policy.ErrNotYetIssued, true
	case "rollback":
		return policy.ErrRollback, true
	case "unsupported_version":
		return policy.ErrUnsupportedVersion, true
	case "invalid":
		return policy.ErrInvalid, true
	case "malformed":
		return policy.ErrMalformed, true
	default:
		return nil, false
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return b
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return ts
}

// TestPositiveWireVectors is the acceptance half of conformance: the frozen bundle
// must be ACCEPTED at its own `now` by a verifier holding root_pub alone, and every
// expect_* value in the file must be what this port reads out of it.
//
// Parsing the values rather than merely accepting the bundle is what catches a port
// that verifies correctly and then misreads the payload — most importantly the
// duration encoding, which is an integer nanosecond count and is the single easiest
// thing to get wrong by a factor of a billion.
func TestPositiveWireVectors(t *testing.T) {
	var pv posVectors
	readJSON(t, positiveVectors, &pv)

	rootPub := unb64(t, pv.RootPub)
	now := mustTime(t, pv.Now)

	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	bundle, err := policy.ParseBundle(pv.Bundle)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	// minSeq 0 is a cold start: nothing has been accepted yet.
	p, err := v.Verify(bundle, now, 0)
	if err != nil {
		t.Fatalf("Verify() REFUSED the frozen positive bundle: %v", err)
	}

	if p.Seq != pv.ExpectSeq {
		t.Errorf("Seq = %d, want %d", p.Seq, pv.ExpectSeq)
	}
	if got := p.ServeFloor.MinMeasuredBps; got != pv.ExpectMinMeasuredBps {
		t.Errorf("MinMeasuredBps = %d, want %d", got, pv.ExpectMinMeasuredBps)
	}
	if got := p.ServeFloor.MinDeclaredQuotaBytes; got != pv.ExpectMinDeclaredQuota {
		t.Errorf("MinDeclaredQuotaBytes = %d, want %d", got, pv.ExpectMinDeclaredQuota)
	}
	if got := p.ServeFloor.MinServingVersion; got != pv.ExpectMinServingVersion {
		t.Errorf("MinServingVersion = %q, want %q", got, pv.ExpectMinServingVersion)
	}
	if got := p.Backpressure.MinCountryHeadroomBps; got != pv.ExpectMinCountryHeadroom {
		t.Errorf("MinCountryHeadroomBps = %d, want %d", got, pv.ExpectMinCountryHeadroom)
	}
	if got := p.Vouch.K; got != pv.ExpectVouchK {
		t.Errorf("Vouch.K = %d, want %d", got, pv.ExpectVouchK)
	}
	if got := p.Vouch.Budget; got != pv.ExpectVouchBudget {
		t.Errorf("Vouch.Budget = %d, want %d", got, pv.ExpectVouchBudget)
	}

	// The factor-of-a-billion check. Period is an integer NANOSECOND count on the
	// wire; a port that read it as seconds passes every other assertion here.
	if got := p.Vouch.Period.Nanoseconds(); got != pv.ExpectVouchPeriodNanos {
		t.Errorf("Vouch.Period = %d ns (%s), want %d ns (%s)",
			got, p.Vouch.Period, pv.ExpectVouchPeriodNanos, time.Duration(pv.ExpectVouchPeriodNanos))
	}

	// Tier lookup is exact, and the fixture pins the (stable, "pro") row.
	lim, err := p.Limits(policy.TrustStable, "pro")
	if err != nil {
		t.Fatalf("Limits(stable, pro): %v", err)
	}
	if lim.SpeedCapBps != pv.ExpectStableProSpeedCap {
		t.Errorf("stable/pro SpeedCapBps = %d, want %d", lim.SpeedCapBps, pv.ExpectStableProSpeedCap)
	}
	if lim.Priority != pv.ExpectStableProPriority {
		t.Errorf("stable/pro Priority = %d, want %d", lim.Priority, pv.ExpectStableProPriority)
	}

	// Deadline is exp + grace, and the fixture pins it independently so a port that
	// dropped grace entirely is caught here rather than by an availability surprise
	// two days after an operator misses a re-sign.
	if got, want := p.Deadline().UTC(), mustTime(t, pv.ExpectDeadline).UTC(); !got.Equal(want) {
		t.Errorf("Deadline() = %s, want %s", got, want)
	}

	// The document must be FRESH at the fixture's now — not merely inside grace.
	if !p.Fresh(now) {
		t.Errorf("Fresh(%s) = false, want true (exp %s)", now, p.Expires.UTC())
	}

	// The delegation the bundle carries must be the one the fixture names, verified
	// against the root for the policy role specifically.
	cert, err := delegation.VerifyDelegationCert(rootPub, bundle.Cert, delegation.RolePolicy, now, nil)
	if err != nil {
		t.Fatalf("VerifyDelegationCert: %v", err)
	}
	if cert.Serial != pv.ExpectDelegationSerial {
		t.Errorf("delegation serial = %q, want %q", cert.Serial, pv.ExpectDelegationSerial)
	}
	if got := base64.StdEncoding.EncodeToString(cert.Pub); got != pv.ExpectSignerPub {
		t.Errorf("signer pub = %q, want %q", got, pv.ExpectSignerPub)
	}
}

// TestNegativeWireVectors is the half that makes conformance mean something. Each
// frozen bundle must be REFUSED by a verifier built from root_pub alone, with the
// error its expect_error names.
//
// A verifier that accepts everything passes every positive vector there is and dies
// here. Matching the specific error matters as much as refusing: a port that
// collapsed every refusal into one sentinel would leave an operator unable to tell
// a revoked delegation from a clock problem.
func TestNegativeWireVectors(t *testing.T) {
	var nv negVectors
	readJSON(t, negativeVectors, &nv)

	rootPub := unb64(t, nv.RootPub)
	if len(nv.Cases) == 0 {
		t.Fatal("no negative cases in the fixture")
	}

	for _, c := range nv.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want, ok := negTokenErr(c.ExpectError)
			if !ok {
				t.Fatalf("case names an unknown expect_error %q", c.ExpectError)
			}
			now := mustTime(t, c.Now)

			var revoked func(string) bool
			if c.RevokedSerial != "" {
				revoked = func(serial string) bool { return serial == c.RevokedSerial }
			}
			v, err := policy.NewVerifier(rootPub, revoked)
			if err != nil {
				t.Fatalf("build verifier: %v", err)
			}
			bundle, err := policy.ParseBundle(c.Bundle)
			if err != nil {
				// A bundle this malformed never reaches Verify. That is still a refusal, and
				// only the malformed token may claim it.
				if errors.Is(err, want) {
					return
				}
				t.Fatalf("ParseBundle() = %v, want %v", err, want)
			}
			got, err := v.Verify(bundle, now, c.MinSeq)
			if err == nil {
				t.Fatalf("Verify() ACCEPTED a bundle that must be refused (parsed seq %d)", got.Seq)
			}
			if !errors.Is(err, want) {
				t.Fatalf("Verify() = %v, want %v", err, want)
			}
		})
	}
}

// TestNegativeVectorsCoverEveryRefusalToken guards the fixture itself: if a future
// copy silently dropped, say, every rollback case, the suite above would still pass
// with nothing to say about rollback. This asserts the set of tokens actually
// exercised, so a thinned fixture is a test failure rather than a quiet gap.
func TestNegativeVectorsCoverEveryRefusalToken(t *testing.T) {
	var nv negVectors
	readJSON(t, negativeVectors, &nv)

	seen := map[string]int{}
	for _, c := range nv.Cases {
		seen[c.ExpectError]++
	}
	for _, token := range []string{
		"bad_signature", "wrong_role", "delegation_expired", "delegation_revoked",
		"delegation_malformed", "stale", "not_yet_issued", "rollback",
		"unsupported_version", "invalid", "malformed",
	} {
		if seen[token] == 0 {
			t.Errorf("no negative case exercises %q", token)
		}
	}
	if len(nv.Cases) < 26 {
		t.Errorf("negative fixture has %d cases, expected at least the frozen 26", len(nv.Cases))
	}
}

// TestVectorsUseAThrowawayRoot proves the trust anchor in testdata is the published
// development root and not a real one.
//
// This is a PUBLIC repository. The fixtures carry a root public key and, in the
// positive file, a policy signer's private seed — and a note claiming both are
// throwaways. A note is exactly what a leaked real key would also carry, so this
// recomputes the development root from its published seed phrase and requires the
// fixture to match it. If a future fixture copy ever chains to a root whose private
// key is not public, this fails, loudly, in CI, before the bytes are trusted.
func TestVectorsUseAThrowawayRoot(t *testing.T) {
	seed := sha256.Sum256([]byte(devRootSeedPhrase))
	devRootPub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	want := base64.StdEncoding.EncodeToString(devRootPub)

	var pv posVectors
	readJSON(t, positiveVectors, &pv)
	if pv.RootPub != want {
		t.Errorf("%s is rooted in %q, which is NOT the published development root — a real root key must never reach this repository", positiveVectors, pv.RootPub)
	}

	var nv negVectors
	readJSON(t, negativeVectors, &nv)
	if nv.RootPub != want {
		t.Errorf("%s is rooted in %q, which is NOT the published development root", negativeVectors, nv.RootPub)
	}
}
