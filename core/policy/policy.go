// Package policy verifies and applies the signed network policy document — the
// `bacchus/policy/v1` object.
//
// # The property this exists to create
//
// The coordinator ENFORCES policy but cannot AUTHOR it. Every number it applies —
// the serve floor, the version fence, the backpressure reserves — arrives inside
// bytes signed by a key it does not have and cannot obtain. A hostile or
// compromised coordinator can refuse to serve, or lie about capacity, but it
// cannot lower the serve floor to admit Sybils, raise its own accounts' limits, or
// loosen the vouch parameters.
//
// This is the same posture the admission gate has (it enforces credentials it
// cannot forge) and the signed directory has (it serves snapshots it cannot
// forge). What is new here is that the numbers themselves become signed data
// rather than constants the coordinator chose.
//
// # Why it expires
//
// A coordinator that simply stopped refreshing would have AUTHORED policy by
// omission: it would have pinned the network at the most permissive generation it
// ever held, with no signature violated anywhere. Expiry is what makes "cannot
// author" true over time rather than at one instant, which is why a stale policy
// fails closed rather than being enforced forever. See the Deadline and Fresh
// methods, and the enforcement side in cmd/coordinator.
//
// # What this package is not
//
// It does not fetch, cache, or apply anything. Verify turns bytes into a Policy or
// an error, and Cache persists what an enforcer must not forget across a restart.
// Which gates the numbers feed is the coordinator's business, recorded in
// docs/adr/0043.
//
// The signer, the schema's authoring half, and the reference verifier live in a
// private repository this module cannot import, so the wire format is the contract
// and the two frozen fixtures in testdata are what keep the implementations
// agreeing. See vectors_test.go.
package policy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Version is the format version of the policy document. It is checked EXACTLY, so
// an enforcer that does not know a format refuses it rather than reading the
// subset it recognises.
//
// That refusal is fleet-wide, which makes the rule for bumping narrow: bump only
// when a verifier that does not know a new field would enforce DIFFERENTLY. A
// field whose absence changes no decision may be added without a bump, which is
// why Verify ignores unknown fields. Roll a bump by updating the enforcers first
// and signing at the new version second; signing first strands the fleet.
const Version = 1

// Sentinel errors. Every one names a protocol fact only — no key material, no
// operator identity, nothing account-scoped — so all are safe to log and safe to
// report to whoever handed over the document.
var (
	ErrUnsupportedVersion = errors.New("policy: unsupported version")
	ErrMalformed          = errors.New("policy: malformed document")
	ErrInvalid            = errors.New("policy: document fails validation")
	ErrNotYetIssued       = errors.New("policy: not yet issued")
	ErrStale              = errors.New("policy: stale (past expiry and grace)")
	ErrRollback           = errors.New("policy: sequence went backwards")
	ErrUnknownTier        = errors.New("policy: no limits for this trust/plan pair")
)

// Trust is the trust tier an identity has reached on the ephemeral->stable ladder.
// It is protocol vocabulary — the network and the account service must mean the
// same thing by it — so it is a closed allowlist, and adding a tier is a
// deliberate act in both implementations rather than a string that appears in a
// policy file one day.
//
// Plan, its partner in a tier key, is deliberately NOT closed; see TierLimit.Plan.
type Trust string

const (
	// TrustEphemeral is the untrusted entry tier every identity starts on. Paying
	// lands an identity here, not above it.
	TrustEphemeral Trust = "ephemeral"
	// TrustStable is the earned tier — vouched or granted.
	TrustStable Trust = "stable"
)

func (t Trust) valid() bool {
	switch t {
	case TrustEphemeral, TrustStable:
		return true
	default:
		return false
	}
}

// Policy is the signed document. Every field is a network tunable with a named
// consumer.
//
// The marshaled form is the signed body and verification is always over the bytes
// as received, so field order and whitespace are not part of the contract. The
// json tag names, the domain tag, the Trust string values, and Version are.
type Policy struct {
	Version int    `json:"v"`
	Seq     uint64 `json:"seq"`

	// Issued and Expires bound the document's own life, signed by the operator
	// rather than chosen by the enforcer.
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"exp"`

	// Grace is how long past Expires an enforcer may keep enforcing this document
	// before it must fail closed. It rides INSIDE the signed body precisely so an
	// enforcer cannot extend its own licence to run on a stale policy: the operator
	// makes the availability-versus-freshness trade per generation. Zero means hard
	// expiry at Expires.
	//
	// Marshaled as an integer NANOSECOND count. This is the single easiest thing
	// for a port to get wrong by a factor of a billion, which is why the positive
	// fixture pins a duration explicitly.
	Grace time.Duration `json:"grace"`

	// Note is an operator label. Never load-bearing, never parsed.
	Note string `json:"note,omitempty"`

	ServeFloor   ServeFloor   `json:"serve_floor"`
	Backpressure Backpressure `json:"backpressure"`
	Vouch        Vouch        `json:"vouch"`

	// Tiers is a LIST of (Trust, Plan) -> limits rows, not a map keyed by a
	// composite string.
	//
	// A JSON object's behaviour on DUPLICATE keys is implementation-defined — Go
	// keeps the last, other decoders keep the first — so a map would let two
	// verifiers of the same signed bytes enforce different limits with no signature
	// failure anywhere. A list makes a duplicate representable, which lets Validate
	// reject it outright. A composite key would also need a delimiter, which needs
	// an escaping rule the moment a plan name contains it; a pair of fields needs
	// neither.
	Tiers []TierLimit `json:"tiers"`
}

// ServeFloor is the serve-eligibility gate, read by the COORDINATOR.
//
// These are policy and not constants because the right answer changes with how
// starved the network is: a 2 Mbit exit is worthless in a well-served region and
// precious where it is the only one. Being re-signable rather than re-deployable
// is the entire point.
//
// A node below either floor is client-only: it may use the service, it just may
// not serve. That is also the Sybil cost lever — a swarm of tiny throwaway nodes
// stops qualifying, so every fake node must be a real, non-trivial pipe.
type ServeFloor struct {
	// MinMeasuredBps is the attested measured throughput a node must reach to join
	// the serve pool, in BITS per second — the unit an operator reads off their line
	// contract, matching capacity.Rate. Zero disables this floor.
	MinMeasuredBps uint64 `json:"min_measured_bps"`

	// MinDeclaredQuotaBytes is the monthly traffic quota a node must declare, in
	// BYTES — the unit an ISP writes a cap in, matching capacity.Bytes. The unit
	// split against MinMeasuredBps is deliberate and mirrors the operator's own
	// paperwork rather than being internally uniform. Zero disables this floor.
	MinDeclaredQuotaBytes uint64 `json:"min_declared_quota_bytes"`

	// MinServingVersion is the release floor of the version fence, as
	// MAJOR.MINOR.PATCH. Moving it here is the point of putting the fence under
	// policy at all: raising the floor after a countermeasure ships becomes a
	// re-sign instead of a coordinator restart with a new flag.
	//
	// "0.0.0" disables the fence, matching the -min-serving-version default. The
	// empty string is NOT that — it is invalid, because a policy that means "fence
	// nobody" must say so rather than reach it by omission.
	MinServingVersion string `json:"min_serving_version"`
}

// Backpressure holds the admission-control thresholds read by the COORDINATOR.
//
// The rule behind them is "when every node in a country is at capacity, refuse new
// assignments there". A literal zero-capacity trigger fires too late — the last
// megabit is handed out and then everyone is wedged — so the tunable is a reserve
// the operator can widen when the network is thrashing.
type Backpressure struct {
	// MinCountryHeadroomBps is the free capacity a country must retain for the
	// coordinator to keep admitting new sessions there; below it the client is told
	// the country is busy. Zero means admit until genuinely full.
	MinCountryHeadroomBps uint64 `json:"min_country_headroom_bps"`

	// MinNodeHeadroomBps is the same reserve per node: an exit with less free
	// capacity than this is not a candidate for a new assignment even when its
	// country has room. Zero means any node with a spare bit is a candidate.
	MinNodeHeadroomBps uint64 `json:"min_node_headroom_bps"`
}

// Vouch holds the social-vouch parameters, read by the ACCOUNT SERVICE.
//
// The coordinator receives these fields and has NO use for either them or Tiers:
// it never scores trust and never sees the vouch graph. They are parsed and
// validated here because they are part of the signed document and a malformed one
// must be refused whole — not because anything in this repository reads them.
// Deliberately no lookup helper is built for them on this side.
type Vouch struct {
	// K is the number of distinct stable vouchers required to admit one new member.
	K int `json:"k"`

	// Budget is the vouch budget per member per Period.
	Budget int `json:"v"`

	// Period is what Budget is measured over, in NANOSECONDS. Explicit because the
	// same budget monthly instead of annually is a five-times-per-year tier, so a
	// period that had to be inferred would be a factor-of-twelve mistake waiting to
	// happen.
	Period time.Duration `json:"period"`

	// Tenure is how long after promotion a member must wait before it may vouch at
	// all, in NANOSECONDS. It sets a generation time on any Sybil tree: the censor
	// advances one layer per Tenure regardless of how much budget it holds.
	Tenure time.Duration `json:"tenure"`

	// AdmitCapPerPeriod is the global cap on promotions to stable per Period across
	// the whole network — the circuit breaker that holds when the other levers are
	// mis-set. Zero means uncapped.
	AdmitCapPerPeriod int `json:"admit_cap"`
}

// TierLimit maps one (Trust, Plan) pair to the limits the account service stamps
// into a credential, read by the ACCOUNT SERVICE.
//
// The limits are computed there and stamped; they are never computed by the
// network. The coordinator enforces a number it is handed and never learns how it
// was derived.
type TierLimit struct {
	// Trust is the earned tier. Closed vocabulary — see Trust.
	Trust Trust `json:"trust"`

	// Plan is the purchased plan, an opaque operator label. Deliberately NOT closed,
	// unlike Trust: plans are commercial, change without any protocol change, and
	// never reach the network. The empty string is a legitimate plan name meaning
	// "no paid plan", spelled explicitly rather than being the absence of a row.
	Plan string `json:"plan"`

	// SpeedCapBps is the per-session cap the exit shapes to, in bits per second.
	// Zero means uncapped.
	SpeedCapBps uint64 `json:"speed_cap_bps"`

	// Priority is the scheduling weight under congestion; higher wins.
	Priority int `json:"priority"`

	// EndpointQuality is the minimum endpoint class this tier may be assigned to;
	// higher is better, and 0 admits anything.
	EndpointQuality int `json:"endpoint_quality"`
}

// TierKey is the (Trust, Plan) pair a TierLimit is keyed by. It exists so
// duplicate detection compares the pair as a unit rather than a joined string that
// would need an escaping rule.
type TierKey struct {
	Trust Trust
	Plan  string
}

// Limits looks up the effective limits for a (trust, plan) pair.
//
// An unknown pair is an ERROR, never a default. There is deliberately no fallback
// row: a permissive default would be a hole that opens exactly when someone ships
// a new plan and forgets the policy, and a restrictive default would be an outage
// nobody could diagnose. The error names the missing pair, and both failure modes
// become one loud one.
//
// Nothing in this repository calls this — the coordinator never resolves a tier.
// It exists because the lookup rule is part of the format, and a porter reading
// only this package should not have to infer that an unknown pair is fatal.
func (p Policy) Limits(trust Trust, plan string) (TierLimit, error) {
	for _, t := range p.Tiers {
		if t.Trust == trust && t.Plan == plan {
			return t, nil
		}
	}
	return TierLimit{}, fmt.Errorf("%w: trust %q plan %q", ErrUnknownTier, trust, plan)
}

// Fresh reports whether p is inside its own window at now — that is, whether it is
// being enforced normally rather than on the Grace extension.
//
// Verify accepts a document through the end of its grace, so this is how an
// enforcer tells the two apart. A false here is not a failure; it is the operator
// having missed a re-sign, and it is meant to be loud, because the window it opens
// closes into a hard stop with no further warning.
func (p Policy) Fresh(now time.Time) bool {
	return !now.Before(p.Issued.Add(-clockSkew)) && now.Before(p.Expires)
}

// Deadline is the instant p stops being enforceable at all: the end of its grace.
// Past it Verify refuses and the enforcer must fail closed.
func (p Policy) Deadline() time.Time { return p.Expires.Add(p.Grace) }

// Validate checks the document's structural invariants.
//
// It checks only what makes a document impossible to enforce coherently — an empty
// window, a threshold of zero where zero has no meaning, a duplicate tier row. It
// deliberately does NOT judge whether a floor is SENSIBLE: which floor is right is
// the operator's call and the entire reason these are tunables, so a verifier that
// second-guessed it would fence the operator out of their own control plane.
// Bounding what a compromised signer can do is the delegation window's job and the
// revocation list's, not this function's.
func (p Policy) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, p.Version)
	}
	if p.Seq == 0 {
		return fmt.Errorf("%w: seq must be at least 1 (0 is the never-loaded sentinel)", ErrInvalid)
	}
	if p.Issued.IsZero() || p.Expires.IsZero() {
		return fmt.Errorf("%w: issued and exp are both required", ErrInvalid)
	}
	if !p.Issued.Before(p.Expires) {
		return fmt.Errorf("%w: empty window (issued %s >= exp %s)", ErrInvalid, p.Issued.UTC(), p.Expires.UTC())
	}
	if p.Grace < 0 {
		return fmt.Errorf("%w: negative grace %s", ErrInvalid, p.Grace)
	}
	if err := checkServingVersion(p.ServeFloor.MinServingVersion); err != nil {
		return err
	}
	if p.Vouch.K < 1 {
		return fmt.Errorf("%w: vouch k must be at least 1, got %d", ErrInvalid, p.Vouch.K)
	}
	if p.Vouch.Budget < 0 {
		return fmt.Errorf("%w: negative vouch budget %d", ErrInvalid, p.Vouch.Budget)
	}
	if p.Vouch.Period <= 0 {
		return fmt.Errorf("%w: vouch period must be positive, got %s", ErrInvalid, p.Vouch.Period)
	}
	if p.Vouch.Tenure < 0 {
		return fmt.Errorf("%w: negative vouch tenure %s", ErrInvalid, p.Vouch.Tenure)
	}
	if p.Vouch.AdmitCapPerPeriod < 0 {
		return fmt.Errorf("%w: negative admission cap %d", ErrInvalid, p.Vouch.AdmitCapPerPeriod)
	}
	if len(p.Tiers) == 0 {
		return fmt.Errorf("%w: no tier limits (the account service could stamp nothing)", ErrInvalid)
	}
	seen := make(map[TierKey]struct{}, len(p.Tiers))
	for _, t := range p.Tiers {
		if !t.Trust.valid() {
			return fmt.Errorf("%w: unknown trust tier %q", ErrInvalid, t.Trust)
		}
		if t.Priority < 0 {
			return fmt.Errorf("%w: negative priority for %s/%q", ErrInvalid, t.Trust, t.Plan)
		}
		if t.EndpointQuality < 0 {
			return fmt.Errorf("%w: negative endpoint quality for %s/%q", ErrInvalid, t.Trust, t.Plan)
		}
		k := TierKey{Trust: t.Trust, Plan: t.Plan}
		if _, dup := seen[k]; dup {
			// Two rows for one pair means the document does not say what the limits ARE,
			// and a verifier that took the first would enforce differently from one that
			// took the last. Refusing is the only reading both can share.
			return fmt.Errorf("%w: duplicate tier row for %s/%q", ErrInvalid, t.Trust, t.Plan)
		}
		seen[k] = struct{}{}
	}
	return nil
}

// checkServingVersion rejects a MAJOR.MINOR.PATCH the enforcer's own parser could
// not read. Signing an unparseable floor would leave a coordinator choosing
// between fencing the whole fleet and fencing none of it, and neither is a
// decision it should have to invent.
//
// It is deliberately STRICTER than core/version.Parse, which accepts anything
// strconv.Atoi does: exactly three runs of ASCII digits, no sign, no leading
// zeros, each fitting a positive int32. Everything this accepts parses identically
// there; the extra strictness removes readings — a leading zero is octal to some
// parsers and decimal to others — that a document verified by an independent
// implementation cannot afford to leave open.
func checkServingVersion(s string) error {
	if s == "" {
		return fmt.Errorf("%w: min_serving_version is required (use \"0.0.0\" to disable the fence)", ErrInvalid)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: min_serving_version %q is not MAJOR.MINOR.PATCH", ErrInvalid, s)
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("%w: min_serving_version %q has an empty component", ErrInvalid, s)
		}
		if len(p) > 1 && p[0] == '0' {
			return fmt.Errorf("%w: min_serving_version %q has a leading zero in %q", ErrInvalid, s, p)
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return fmt.Errorf("%w: min_serving_version %q has a non-digit in %q", ErrInvalid, s, p)
			}
		}
		if _, err := strconv.ParseUint(p, 10, 31); err != nil {
			return fmt.Errorf("%w: min_serving_version %q component %q out of range", ErrInvalid, s, p)
		}
	}
	return nil
}
