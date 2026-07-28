package policy_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/policy"
)

// validPolicy is a structurally sound document every case below breaks one field
// of. Same discipline as the delegation tests: a negative built from scratch can
// fail for a reason the author did not intend and still look green.
func validPolicy() policy.Policy {
	issued := time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC)
	return policy.Policy{
		Version: policy.Version,
		Seq:     42,
		Issued:  issued,
		Expires: issued.Add(30 * 24 * time.Hour),
		Grace:   48 * time.Hour,
		ServeFloor: policy.ServeFloor{
			MinMeasuredBps:        25_000_000,
			MinDeclaredQuotaBytes: 100_000_000_000,
			MinServingVersion:     "0.2.0",
		},
		Backpressure: policy.Backpressure{
			MinCountryHeadroomBps: 50_000_000,
			MinNodeHeadroomBps:    5_000_000,
		},
		Vouch: policy.Vouch{
			K:                 3,
			Budget:            6,
			Period:            365 * 24 * time.Hour,
			Tenure:            182 * 24 * time.Hour,
			AdmitCapPerPeriod: 10_000,
		},
		Tiers: []policy.TierLimit{
			{Trust: policy.TrustEphemeral, Plan: "", SpeedCapBps: 10_000_000, Priority: 1, EndpointQuality: 1},
			{Trust: policy.TrustStable, Plan: "pro", SpeedCapBps: 200_000_000, Priority: 9, EndpointQuality: 3},
		},
	}
}

func TestValidateAcceptsASoundDocument(t *testing.T) {
	if err := validPolicy().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// TestValidateRejects covers the structural invariants. Each case changes exactly
// one field of the control above.
func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*policy.Policy)
		want error
	}{
		{"version 0", func(p *policy.Policy) { p.Version = 0 }, policy.ErrUnsupportedVersion},
		{"version 2", func(p *policy.Policy) { p.Version = 2 }, policy.ErrUnsupportedVersion},
		{"seq 0 is the never-loaded sentinel", func(p *policy.Policy) { p.Seq = 0 }, policy.ErrInvalid},
		{"zero issued", func(p *policy.Policy) { p.Issued = time.Time{} }, policy.ErrInvalid},
		{"zero exp", func(p *policy.Policy) { p.Expires = time.Time{} }, policy.ErrInvalid},
		{"empty window", func(p *policy.Policy) { p.Expires = p.Issued }, policy.ErrInvalid},
		{"inverted window", func(p *policy.Policy) { p.Expires = p.Issued.Add(-time.Hour) }, policy.ErrInvalid},
		{"negative grace", func(p *policy.Policy) { p.Grace = -time.Second }, policy.ErrInvalid},
		{"vouch k below 1", func(p *policy.Policy) { p.Vouch.K = 0 }, policy.ErrInvalid},
		{"negative vouch budget", func(p *policy.Policy) { p.Vouch.Budget = -1 }, policy.ErrInvalid},
		{"zero vouch period", func(p *policy.Policy) { p.Vouch.Period = 0 }, policy.ErrInvalid},
		{"negative vouch period", func(p *policy.Policy) { p.Vouch.Period = -time.Hour }, policy.ErrInvalid},
		{"negative tenure", func(p *policy.Policy) { p.Vouch.Tenure = -time.Hour }, policy.ErrInvalid},
		{"negative admit cap", func(p *policy.Policy) { p.Vouch.AdmitCapPerPeriod = -1 }, policy.ErrInvalid},
		{"no tiers", func(p *policy.Policy) { p.Tiers = nil }, policy.ErrInvalid},
		{"empty tier list", func(p *policy.Policy) { p.Tiers = []policy.TierLimit{} }, policy.ErrInvalid},
		{
			"unknown trust tier",
			func(p *policy.Policy) { p.Tiers[0].Trust = "platinum" },
			policy.ErrInvalid,
		},
		{
			"duplicate tier row",
			func(p *policy.Policy) { p.Tiers = append(p.Tiers, p.Tiers[0]) },
			policy.ErrInvalid,
		},
		{
			"negative priority",
			func(p *policy.Policy) { p.Tiers[0].Priority = -1 },
			policy.ErrInvalid,
		},
		{
			"negative endpoint quality",
			func(p *policy.Policy) { p.Tiers[0].EndpointQuality = -1 },
			policy.ErrInvalid,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			tc.mut(&p)
			err := p.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestValidateAcceptsADuplicatePlanUnderADifferentTrust pins that duplicate
// detection compares the PAIR. Two rows sharing a plan name but differing in trust
// are distinct keys and must be allowed, or an operator could not price the same
// plan differently across tiers.
func TestValidateAcceptsADuplicatePlanUnderADifferentTrust(t *testing.T) {
	p := validPolicy()
	p.Tiers = []policy.TierLimit{
		{Trust: policy.TrustEphemeral, Plan: "pro", SpeedCapBps: 10_000_000},
		{Trust: policy.TrustStable, Plan: "pro", SpeedCapBps: 200_000_000},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil (same plan, different trust is a distinct key)", err)
	}
}

// TestMinServingVersionStrictness pins the deliberate extra strictness over
// core/version.Parse. Everything accepted here parses identically there; what is
// removed are readings an independent implementation could disagree about.
func TestMinServingVersionStrictness(t *testing.T) {
	accept := []string{"0.0.0", "0.2.0", "1.0.0", "10.20.30", "2147483647.0.0"}
	for _, s := range accept {
		p := validPolicy()
		p.ServeFloor.MinServingVersion = s
		if err := p.Validate(); err != nil {
			t.Errorf("min_serving_version %q rejected: %v", s, err)
		}
	}

	reject := []string{
		"",               // must say 0.0.0 rather than reach "fence nobody" by omission
		"1.0",            // not three components
		"1.0.0.0",        // four
		"01.0.0",         // leading zero: octal to some parsers, decimal to others
		"1.00.0",         // same, in another position
		"1.0.-1",         // no sign
		"+1.0.0",         // no sign
		"1.0.x",          // non-digit
		"v1.0.0",         // no prefix
		"1..0",           // empty component
		" 1.0.0",         // no surrounding space
		"1.0.0 ",         //
		"4294967296.0.0", // beyond a positive int32
	}
	for _, s := range reject {
		p := validPolicy()
		p.ServeFloor.MinServingVersion = s
		if err := p.Validate(); !errors.Is(err, policy.ErrInvalid) {
			t.Errorf("min_serving_version %q: Validate() = %v, want ErrInvalid", s, err)
		}
	}
}

// TestFreshAndDeadline pins the three-state reading of a document's own clock:
// fresh, on grace, and stale. The middle state is the one an enforcer must be able
// to see, because it is the operator's only warning before a hard stop.
func TestFreshAndDeadline(t *testing.T) {
	p := validPolicy()

	if want := p.Expires.Add(p.Grace); !p.Deadline().Equal(want) {
		t.Errorf("Deadline() = %s, want %s", p.Deadline(), want)
	}

	tests := []struct {
		name      string
		now       time.Time
		wantFresh bool
	}{
		{"inside the window", p.Issued.Add(time.Hour), true},
		{"just inside skew before issue", p.Issued.Add(-time.Minute), true},
		{"beyond skew before issue", p.Issued.Add(-10 * time.Minute), false},
		{"one instant before expiry", p.Expires.Add(-time.Nanosecond), true},
		{"exactly at expiry is no longer fresh", p.Expires, false},
		{"on grace", p.Expires.Add(time.Hour), false},
		{"past the deadline", p.Deadline().Add(time.Nanosecond), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Fresh(tc.now); got != tc.wantFresh {
				t.Errorf("Fresh(%s) = %v, want %v", tc.now, got, tc.wantFresh)
			}
		})
	}
}

// TestZeroGraceIsAHardExpiry pins that grace 0 means the deadline IS expiry, with
// no tolerance either side of it.
func TestZeroGraceIsAHardExpiry(t *testing.T) {
	p := validPolicy()
	p.Grace = 0
	if !p.Deadline().Equal(p.Expires) {
		t.Errorf("Deadline() = %s, want exp %s", p.Deadline(), p.Expires)
	}
}

// TestLimitsIsAnExactLookup pins that an unknown pair is an error rather than a
// default. A permissive default would be a hole that opens exactly when someone
// ships a new plan and forgets the policy.
func TestLimitsIsAnExactLookup(t *testing.T) {
	p := validPolicy()

	got, err := p.Limits(policy.TrustStable, "pro")
	if err != nil {
		t.Fatalf("Limits(stable, pro) = %v", err)
	}
	if got.SpeedCapBps != 200_000_000 {
		t.Errorf("SpeedCapBps = %d, want 200000000", got.SpeedCapBps)
	}

	// The empty plan is a real plan name, not the absence of one.
	if _, err := p.Limits(policy.TrustEphemeral, ""); err != nil {
		t.Errorf(`Limits(ephemeral, "") = %v, want the free-tier row`, err)
	}

	for _, tc := range []struct {
		trust policy.Trust
		plan  string
	}{
		{policy.TrustStable, "enterprise"}, // plan not in the table
		{policy.TrustEphemeral, "pro"},     // right plan, wrong trust
		{"platinum", "pro"},                // tier that does not exist
	} {
		if _, err := p.Limits(tc.trust, tc.plan); !errors.Is(err, policy.ErrUnknownTier) {
			t.Errorf("Limits(%q, %q) = %v, want ErrUnknownTier", tc.trust, tc.plan, err)
		}
	}
}

// TestParseBundleRequiresBothMembers pins that a half-bundle is refused up front
// rather than producing a confusing signature failure later. An enforcer must not
// be able to be handed a document with no delegation and reach a code path that
// evaluates it.
func TestParseBundleRequiresBothMembers(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"empty object", `{}`},
		{"document only", `{"policy":"AAAA"}`},
		{"delegation only", `{"cert":"AAAA"}`},
		{"null members", `{"policy":null,"cert":null}`},
		{"not an object", `[]`},
		{"not JSON", `nope`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := policy.ParseBundle([]byte(tc.raw)); !errors.Is(err, policy.ErrMalformed) {
				t.Fatalf("ParseBundle(%s) = %v, want ErrMalformed", tc.raw, err)
			}
		})
	}
}

// TestNewVerifierFailsClosedWithoutARoot pins the direction of failure. This is the
// opposite of the admission gate and the version fence, which fail open when unset,
// and the asymmetry is deliberate: a coordinator is one of a pool with client
// rotation, so one failing closed sheds to its peers.
func TestNewVerifierFailsClosedWithoutARoot(t *testing.T) {
	for _, root := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if _, err := policy.NewVerifier(root, nil); err == nil {
			t.Errorf("NewVerifier(root len %d) succeeded, want a refusal", len(root))
		}
	}
}
