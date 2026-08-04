package accountclient

import (
	"errors"
	"fmt"
	"time"
)

// Code is a token from the account service's closed error vocabulary. A client
// switches on this and on nothing else — in particular never on the HTTP status,
// which the transport specification calls "a coarse class for proxies and
// dashboards" and explicitly forbids distinguishing two outcomes by.
//
// Only the codes reachable from the three verbs this package speaks are named.
// The operator surface's codes are not here because nothing here can receive
// one, and a constant for an unreachable condition is a constant somebody will
// eventually branch on.
type Code string

// The reachable vocabulary. Every one of these can arrive at one of the three
// verbs below; see each constant for which.
const (
	// CodeMalformedRequest — this client sent something the service could not
	// parse. Always a bug here, never a user's problem: nothing a user types
	// reaches the wire unvalidated.
	CodeMalformedRequest Code = "malformed_request"
	// CodeMalformedSecret — the claim code is not shaped like a claim code. The
	// service decides this without consulting any account state, which is why it
	// is a distinct answer at all, and why it is safe to tell a user "check what
	// you typed" on it and on nothing else.
	CodeMalformedSecret Code = "malformed_secret"
	// CodeUnknownChallenge — the challenge was never issued, has expired, or has
	// already been spent. The remedy is a fresh challenge, and it is the one
	// error here that this package retries on its own (see doRetryableExchange).
	CodeUnknownChallenge Code = "unknown_challenge"
	// CodeBadAssertion — the signature did not verify, OR this device is not
	// enrolled. Deliberately one code: a distinct "unknown device" would tell a
	// caller who has proven nothing whether a given public key is enrolled
	// anywhere, and /v1/challenge hands out the nonce needed to ask. Do not try
	// to split it; the service does not draw the line either, and it verifies
	// before it resolves an account specifically so the two are not separable by
	// timing.
	CodeBadAssertion Code = "bad_assertion"
	// CodeClaimRejected — the claim code is wrong, or already spent. Not
	// distinguishable, and not by restraint: spending a claim code erases the
	// hash rather than flagging it, so the service holds no record that any
	// particular value was ever live.
	CodeClaimRejected Code = "claim_rejected"
	// CodeEntitlementExpired — the account behind this claim code or device has
	// lapsed. The only error here whose remedy is "pay".
	CodeEntitlementExpired Code = "entitlement_expired"
	// CodeNoSlots — the account's device cap is spent. Enrollment only.
	CodeNoSlots Code = "no_slots"
	// CodeDeviceRevoked — this device was revoked. Renewal only; a revoked device
	// keeps working until its current credential expires and then stops.
	CodeDeviceRevoked Code = "device_revoked"
	// CodeAlreadyEnrolled — this device's public key is already enrolled. The
	// answer is not to enroll again, it is to collect the credential that already
	// exists (see Collect).
	CodeAlreadyEnrolled Code = "already_enrolled"
	// CodeChallengesFull — the service's global challenge cap is reached. A
	// coarse bound, not a statement about this caller, and never rate_limited.
	CodeChallengesFull Code = "challenges_full"
	// CodeUnknownVerb — this deployment does not implement the path. It arrives
	// ONLY as a well-formed error body with a 404; a bare 404 is interference and
	// is reported as such (see decodeError).
	CodeUnknownVerb Code = "unknown_verb"
	// CodeMethodNotAllowed — a bug here.
	CodeMethodNotAllowed Code = "method_not_allowed"
	// CodePayloadTooLarge — a bug here; nothing this package sends approaches the
	// 8 KiB cap.
	CodePayloadTooLarge Code = "payload_too_large"
	// CodeRateLimited — too many requests, or too many consecutive bad
	// assertions from this device key. Carries a retry hint.
	CodeRateLimited Code = "rate_limited"
	// CodeInternal — the service failed. Carries no detail, ever, by design.
	CodeInternal Code = "internal"
	// CodeUnavailable — the service is shedding or not ready. Carries a retry
	// hint.
	CodeUnavailable Code = "unavailable"
)

// known is every code this package recognizes. Anything else is treated as the
// generic failure for its status class, which is what lets the service's
// vocabulary grow without breaking a deployed client: a client that refused an
// unrecognized code would make adding one a flag day.
var known = map[Code]bool{
	CodeMalformedRequest:   true,
	CodeMalformedSecret:    true,
	CodeUnknownChallenge:   true,
	CodeBadAssertion:       true,
	CodeClaimRejected:      true,
	CodeEntitlementExpired: true,
	CodeNoSlots:            true,
	CodeDeviceRevoked:      true,
	CodeAlreadyEnrolled:    true,
	CodeChallengesFull:     true,
	CodeUnknownVerb:        true,
	CodeMethodNotAllowed:   true,
	CodePayloadTooLarge:    true,
	CodeRateLimited:        true,
	CodeInternal:           true,
	CodeUnavailable:        true,
}

// Error is a coded refusal from the account service: the service was reached, it
// understood the request, and it declined it.
//
// It is deliberately distinct from a transport failure. The difference decides
// whether a caller should stop or keep going — a coded refusal about a claim
// code will say the same thing forever, while "could not reach the service" is a
// statement about right now — and a client that flattened them would either
// retry a spent claim code or give up on a network blip.
type Error struct {
	// Code is the service's token, verbatim, including one this build does not
	// recognize. Compare against the constants above; do not parse it.
	Code Code
	// Status is the HTTP status the code arrived with. Recorded for diagnostics
	// and never branched on: the specification requires a client not to
	// distinguish two outcomes by status alone.
	Status int
	// RetryAfter is the service's own hint, present only on the codes that carry
	// one. Zero elsewhere, and zero is not "retry immediately" — it means the
	// service offered no hint.
	RetryAfter time.Duration
	// Recognized is false when Code is outside this build's vocabulary, so a
	// caller can say "the service refused for a reason this version does not
	// understand" rather than printing a token at a user.
	Recognized bool
	// Verb is the path the refusal came from, for a diagnostic that names which
	// leg of a multi-call exchange failed.
	Verb string
}

func (e *Error) Error() string {
	if !e.Recognized {
		return fmt.Sprintf("account service refused %s: unrecognized code %q (HTTP %d)", e.Verb, string(e.Code), e.Status)
	}
	return fmt.Sprintf("account service refused %s: %s", e.Verb, string(e.Code))
}

// Is lets errors.Is(err, ErrRefused) match any coded refusal, so a caller that
// only needs "the service said no" does not have to type-assert.
func (e *Error) Is(target error) bool { return target == ErrRefused }

// ErrRefused matches any coded refusal. errors.As to an *Error for the code.
var ErrRefused = errors.New("account service refused the request")

// ErrUnreachable wraps every failure that is NOT a coded refusal: a dial that
// failed, a TLS handshake that failed, a timeout, a truncated body, a response
// this client could not parse.
//
// The specification is explicit that these must not be read as "this deployment
// does not implement the verb": an old server and a censor's blackhole look
// alike from inside a tunnel, and only a well-formed unknown_verb body means the
// former. A client that permanently disabled a feature on a timeout would let an
// interfering middlebox turn a transient block into a persistent one.
var ErrUnreachable = errors.New("could not reach the account service")

// CodeOf returns the service's code for err, and whether err was a coded refusal
// at all. It is the accessor callers should use rather than reaching for
// errors.As on every branch.
func CodeOf(err error) (Code, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Code, true
	}
	return "", false
}

// Terminal reports whether err will say the same thing however many times it is
// asked, so a caller knows whether to stop or to wait.
//
// A coded refusal about a secret, an entitlement or a device is terminal: no
// amount of retrying turns a spent claim code back into a live one. Rate
// limiting, capacity and service failures are not terminal, and neither is
// anything wrapped in ErrUnreachable. An unrecognized code is NOT terminal,
// which is the safe direction: treating an unknown refusal as permanent would
// let one added code strand every deployed client, and treating it as transient
// costs a retry.
func Terminal(err error) bool {
	code, ok := CodeOf(err)
	if !ok {
		return false
	}
	switch code {
	case CodeMalformedSecret, CodeClaimRejected, CodeEntitlementExpired,
		CodeNoSlots, CodeDeviceRevoked, CodeAlreadyEnrolled, CodeBadAssertion,
		CodeMalformedRequest, CodeMethodNotAllowed, CodePayloadTooLarge, CodeUnknownVerb:
		return true
	default:
		return false
	}
}
