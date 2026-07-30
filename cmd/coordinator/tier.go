package main

import (
	"fmt"
	"log"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/policy"
)

// Tier-limit enforcement (issue #58, ADR-0048). This is the consumer half of
// ADR-0043's issue #67 amendment: the signed policy carries the limits, the
// admission credential carries only the (trust, plan) pair that indexes them, and
// the network resolves one against the other.
//
// The coordinator enforces two of the three numbers — priority and endpoint
// quality, both assignment decisions — and forwards the third, speed_cap_bps, to
// the exit on the assignment so shaping happens in the data path this coordinator
// is deliberately not in (ADR-0009, ADR-0033).
//
// The posture is the serve floor's (#15, policyMeasuredFloor): a number read out of
// a document verified against the policy root, applied to a quantity this
// coordinator OBSERVED itself, with no constant default anywhere. A coordinator
// that could fall back to a constant would have authored policy, which is the one
// thing signed policy exists to prevent.

// tierLimits is the entitlement resolved for one connecting account, or the zero
// value when no tier applies at all.
//
// The zero value is safe by arithmetic rather than by a flag: every field of an
// unset policy.TierLimit means "no restriction" at the points below (a zero
// SpeedCapBps is no cap, a zero Priority takes the network floor unchanged, a zero
// EndpointQuality admits anything). That is the same reading that makes an unknown
// pair dangerous — see resolveTier — so it is spelled out here: the zero value is
// only ever produced deliberately, by a path that decided no tier applies, and
// never as a fallback for a lookup that failed.
type tierLimits struct {
	policy.TierLimit
}

// exitClass is the coordinator's endpoint-class oracle: the observed class of a
// node, and whether one is known at all. Nil — as it ships — means no class source
// exists, so no exit has a class and the endpoint-quality floor withholds nobody.
//
// It is a seam and not a computation because there is nothing honest to compute
// yet. An endpoint class is a QUALITY judgement (latency, jitter, loss — the
// companion feed design §8.4 and issue #161 describe), and ADR-0040 §8.4 is
// explicit that capacity is not quality: deriving a class from a node's measured
// throughput would be inventing the number rather than reading it, and it would
// rank a 100 Mbit node with 5% loss above a clean one.
//
// A DECLARED class is not an option either, and the asymmetry with -max-speed is
// the reason. ADR-0040 accepts a self-reported speed cap because that claim is only
// ever binding downward — a node that lies about it lies itself out of traffic. A
// self-reported endpoint class binds UPWARD: it is a claim to be assigned premium
// sessions, which is exactly what a node profits from inflating, so it is the
// self-report that cannot be taken.
//
// A var rather than a const nil so a test can feed it and prove the floor really
// denies (TestEndpointQualityFloorWithholdsALowClassExit); production never sets it.
var exitClass func(nodeID string) (class int, known bool)

// resolveTier resolves the connecting account's (trust, plan) pair against the
// policy this coordinator holds, and returns what that pair is entitled to.
//
// The refusal it returns is refuseNone on success. It is an assignRefusal rather
// than an error because every caller's answer to a failure is the same: name it to
// the client and assign nothing.
//
// # The three cases, and why they answer differently
//
// These are genuinely different questions and ADR-0043 §3 already warns that
// neighbouring gates in this file reached opposite answers on the same sheddability
// test — ADR-0043 fails closed, ADR-0045 fails open — so none of them is a template
// for the others.
//
//  1. NO POLICY CONFIGURED. No tier applies; the connect is assigned unshaped,
//     exactly as it is today. This is -policy-root-pubkey's existing direction and
//     changing it here would mean this lane silently turned signed policy from
//     opt-in into mandatory. A deployment that has not adopted policy has not opted
//     out of tier limits; it has not opted into the mechanism that carries them.
//
//  2. POLICY CONFIGURED, PAIR UNKNOWN. Refused, loudly. This is ADR-0006 decision
//     5, now load-bearing: a zero TierLimit reads as UNCAPPED on two of its three
//     fields, so a permissive fallback hands full speed and unrestricted endpoint
//     access to precisely the credential nobody signed a row for — and it opens at
//     the moment someone ships a plan and forgets to re-sign the policy, which is
//     the failure that looks like success. A restrictive fallback is refused for the
//     mirror reason: it would enforce a number that appears nowhere in the signed
//     document, so an operator debugging it would be looking for a value that does
//     not exist. Both substitutions are refused; the pair is named instead.
//
//     This is the case an operator actually hits, and it is worth being concrete
//     about how: every credential minted before #58 carries an empty Trust, and the
//     policy's tier rows are keyed by a closed vocabulary that has no empty member
//     (policy.Trust.valid), so no signable policy can admit them. Turning policy on
//     ahead of re-issuing the fleet's credentials therefore refuses every connect,
//     by design and with the pair in the log line.
//
//  3. POLICY CONFIGURED, ADMISSION DISABLED. No tier applies; assigned unshaped.
//     There is no credential on an open network, so there is no pair — this is not
//     an unknown key, it is no key, and the two must not be conflated. Refusing here
//     would take a coordinator that works today and stop it dead over a feature it
//     is not configured for, which is exactly the undiagnosable outage case 2
//     refuses a restrictive fallback to avoid. It is announced rather than left to
//     be found: warnTierEnforcementIsOff logs it at startup, next to the warning
//     main() already prints for admission being off at all.
//
// The fourth state — policy configured and none currently held — cannot produce an
// assignment at all: policyAllowsAssignment already refuses every connect while it
// holds (ADR-0043 §3's fail-closed drain). It is handled here anyway, and refused,
// because the country list does NOT go through that gate and must not answer with
// an availability figure it computed under limits it could not resolve.
func resolveTier(cred admission.Credential) (tierLimits, assignRefusal) {
	if !policyEnabled() {
		return tierLimits{}, refuseNone // case 1
	}
	if admissionVerifier == nil {
		return tierLimits{}, refuseNone // case 3
	}
	p, held := currentPolicy()
	if !held {
		log.Printf("tier: no policy held — cannot resolve any (trust, plan) pair; this coordinator is already refusing to assign (ADR-0043 §3)")
		return tierLimits{}, refuseUnknownTier
	}
	limit, err := p.Limits(policy.Trust(cred.Trust), cred.Plan)
	if err != nil {
		// Loud, and naming the pair, because this is an operator's mistake and the
		// operator is the only party who can fix it. The pair is the credential's own
		// claim about itself and the policy is a signed document its holder can read,
		// so naming it back reveals nothing the client did not already hold.
		log.Printf("tier: REFUSING assignment — policy seq %d has no row for (trust %q, plan %q): %v. Sign a policy covering this pair before issuing credentials for it (ADR-0006 decision 5, ADR-0048)",
			p.Seq, cred.Trust, cred.Plan, err)
		return tierLimits{}, refuseUnknownTier
	}
	return tierLimits{TierLimit: limit}, refuseNone
}

// tierMinShare is the fullness floor one session must clear, scaled by the tier's
// priority — the whole of what `priority` means at assignment (issue #58).
//
// minShare is the network-wide floor: the smallest bandwidth share an exit must be
// able to offer a new session before capacity.Full calls it full. Dividing it by the
// tier's priority turns it into a RESERVE: as an exit fills, it stops accepting the
// lowest-priority sessions first and keeps accepting the highest, which is what
// "scheduling weight under congestion, higher wins" means when the only scheduling
// decision this coordinator makes is whether to assign at all.
//
// Priority 0 — an unset field, or a tier the operator chose to give no weight —
// takes the network floor unchanged rather than an infinite one. A tier gets relief
// by being named in a signed row, never by omission.
//
// It is INERT today and says so out loud: minShare ships at zero (see its doc for
// why it must, and on what condition it lifts), and zero divided by any priority is
// zero, so every tier clears every exit. That is the same "live machinery with the
// gate off" state #145's serve floor is in, and it lifts on the same condition — a
// fed trusted rating stream. TestPriorityAdmitsWhereALowerTierIsRefused flips
// minShare to prove the mechanism is real rather than dead code.
func tierMinShare(l tierLimits) capacity.Rate {
	if l.Priority <= 1 {
		return minShare
	}
	return minShare / capacity.Rate(l.Priority)
}

// meetsEndpointQuality reports whether an exit's observed class clears the tier's
// minimum, with a safe-to-log reason when it does not (issue #58).
//
// It mirrors meetsMeasuredFloor's shape deliberately, including the part that most
// looks like a hole: a node with NO known class is not withheld. An unclassified
// endpoint is not a bad endpoint, exactly as design §5.3's unmeasured node is not a
// slow node — and the alternative is worse than permissive, it is total. The frozen
// policy fixtures both repositories test against carry endpoint_quality 1, 2 and 3
// on every row, so treating "no class" as class 0 would refuse every connect in the
// fleet the first time anyone signed a realistic policy. A floor whose only possible
// effect is a fleet-wide outage is not enforcement.
//
// So this is live machinery over an unfed input: with exitClass nil, as it ships, it
// withholds nobody, and it starts biting the moment a class source exists, with no
// change here.
func meetsEndpointQuality(nodeID string, l tierLimits) (reason string, ok bool) {
	if l.EndpointQuality <= 0 {
		return "", true // 0 admits anything (policy.TierLimit.EndpointQuality)
	}
	if exitClass == nil {
		return "", true
	}
	class, known := exitClass(nodeID)
	if !known {
		return "", true
	}
	if class < l.EndpointQuality {
		return fmt.Sprintf("endpoint class %d is below this tier's minimum of %d", class, l.EndpointQuality), false
	}
	return "", true
}

// capNote renders the per-session cap for the session log line: " capped at N bps"
// when a tier resolved one, and nothing at all when it did not.
//
// Empty rather than "uncapped" for the zero case so an unpoliced deployment's logs
// stay byte-identical to what they were before #58 — there is a lot of tooling
// pointed at these lines, and a new word on every session is a diff for every
// operator who gained nothing from this change.
//
// The number and not the tier: a log line naming which plan a client is on turns
// the operator's log into an account-linkability record keyed by source address,
// which is the correlation this whole lane is arranged to avoid handing anyone (see
// sessionPace in core/forwarder.go). The cap is a network fact; the plan is not.
func capNote(bps uint64) string {
	if bps == 0 {
		return ""
	}
	return fmt.Sprintf(" capped at %d bps", bps)
}

// warnTierEnforcementIsOff announces, at startup, a configuration in which tier
// limits are signed but cannot be enforced: policy is configured and admission is
// not, so no connect carries the (trust, plan) pair the tiers table is indexed by.
//
// This exists because resolveTier's case 3 assigns unshaped, and a hole that is
// silent at the point it opens has to be loud somewhere. Startup is where an
// operator reads configuration warnings and where main() already prints the
// admission-disabled notice this sits beside.
func warnTierEnforcementIsOff() {
	if !policyEnabled() || admissionVerifier != nil {
		return
	}
	log.Printf("tier limits NOT ENFORCED: signed policy is configured but admission is not, so no connect carries the (trust, plan) pair the policy's tiers table is indexed by. Every session is assigned unshaped. Anchor an admission authority to enforce tiers (issue #58, ADR-0048)")
}
