// Package capacity models what a Bacchus node will carry: the limits its
// operator declares (issue #143) and the rate the network observes it actually
// delivering (issue #144).
//
//	usable = min(declared, measured)
//
// so a node can neither be over-used (its declared cap binds) nor over-promise
// (the measured rate binds). The full methodology, its gaming-resistance
// argument, and — importantly — the hole that argument does not close are in
// docs/design/node-capacity.md and ADR-0040. This doc comment states the part a
// reader of the code has to hold in their head.
//
// # The trust asymmetry
//
// The two numbers have opposite trust properties, and the whole package layout
// follows from that:
//
//   - Declared (Limits, Quota) is SELF-REPORTED and safe. A node declaring less
//     than it has only reduces what it is given — the operator's right, and the
//     point of #143. A node declaring MORE than it has gains nothing, because the
//     measured term of the min() binds. The only effective direction of the lie is
//     self-limiting, which is exactly the condition under which a self-report can
//     be trusted, so declared limits ride the register wire with no verification.
//
//   - Measured (Estimator) is NEVER self-reported. Lying upward here works
//     directly — it is the term that would otherwise bind. So the measured rate is
//     coordinator-side state, derived from observation, and it never appears on the
//     register wire in any direction.
//
// This mirrors the rule the tree already holds elsewhere: a self-report is
// trusted exactly when lying cannot benefit the reporter. Compare
// core/coldstart.Entry, where Operator is coordinator-side truth ("a Sybil
// operator would fabricate diversity") and Ingress trusts a self-reported port
// only because it is paired with a coordinator-OBSERVED IP.
//
// # What is measured, precisely
//
// The Estimator tracks the rate a SATURATED session gets from this node — not the
// node's aggregate capacity. That is a deliberate, load-aware choice: a node with
// eight busy clients legitimately gives each less, and a node that is throttling
// gives each less, and the correct action in both cases is identical (route less
// here). The estimator therefore never has to attribute blame, only to track
// delivery — a much weaker requirement than detecting malice, and the reason this
// works at all. Aggregate willingness is the declared cap's job (Limits), enforced
// by the node itself.
//
// # There is no tester
//
// Nothing here probes anything. An active speed test fails four ways at once (see
// the design note §6.1): the tester is identifiable and gets whitelisted, it
// measures the wrong path, its traffic shape is self-identifying, and it burns the
// very quota #143 exists to protect. Instead, measurement IS serving: a node's
// rate is defined by what it delivers to real clients under real load, so there is
// no separate thing for a node to be fast at, and there is no steady-state
// measurement cost at all.
//
// # Determinism
//
// Estimator and Quota never read the clock: every entry point that needs a time
// takes it as an argument, matching the coordinator's prune(now)/pickRelay
// convention. That is what lets the adversarial simulations in estimator_test.go
// pin the gaming-resistance bounds exactly rather than approximately — the claims
// in the design note are tests, not prose.
//
// Limiter is the exception and cannot be otherwise: it is a token bucket, so it
// reads the clock inside x/time/rate. Its tests are therefore wall-clock-gated and
// assert loosely on the upper bound and tightly on the lower one — finishing too
// FAST is the failure that matters, because it means the cap did not hold.
package capacity
