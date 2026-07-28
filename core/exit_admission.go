package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// Client-side end-to-end admission verification (issue #60). Node admission
// (#42, ADR-0023) is enforced only at the coordinator: an honest coordinator
// refuses to advertise an exit without a valid credential. But Noise_NK
// (core/e2e.go, ADR-0009) only proves "this peer holds the id you asked for",
// not "this id is admission-authorized" — so a hostile or compromised
// coordinator (explicitly in docs/threat-model.md, and with the #6 coordinator
// pool a client already rotates across members any one of which could be
// hostile) can advertise a hostile exit whose id it legitimately controls,
// complete Noise_NK, and route the client's traffic through it. This file closes
// that gap: the exit presents its admission credential inside the Noise_NK
// exchange and the client verifies it end-to-end against the admission root,
// rejecting an exit the root never authorized even when a dishonest coordinator
// vouched for it. #42 makes an honest coordinator reject hostile exits; this
// makes a client reject them even via a dishonest coordinator — defense in depth.

// errMissingExitCredential is returned when a client that requires admission (it
// holds an anchor) reaches an exit that presented no credential — an old,
// un-credentialed, or stripped exit. It names only a protocol fact, so it is
// safe to log and to surface to the user as the abort reason.
var errMissingExitCredential = errors.New("core: exit presented no admission credential")

// buildExitVerifier constructs the client-side admission verifier from the
// configured admission root public key (issue #60) and an optional signed
// revocation bundle (issue #69, core/admission.CRL), sourced either as inline
// content (crlEncoded) or a file path re-read on an interval (crlPath, issue
// #90) — at most one of the two may be set. An empty key returns a nil
// verifier and a nil ClientCRL: the client does not verify exit credentials
// and accepts any exit it can complete Noise_NK with (fail-open, matching the
// coordinator's behavior when -admission-pubkey is unset, #42). A malformed
// key is a construction error — a client told to verify against an unusable
// key must not silently fall through to trusting every exit.
//
// A CRL (either source) is meaningless without pubKeyHex — verifying its
// signature needs the anchor — so supplying one without the other is also a
// construction error rather than a silent no-op; the "unconfigured"
// fail-open path is specifically both empty. When pubKeyHex is set and a CRL
// source is too, it must parse, verify against the anchor, and be unexpired
// as of now, or construction fails: an operator who turned revocation
// checking on must not have it silently degrade to "nothing is revoked" on a
// stale or corrupt bundle.
//
// Leaving both CRL sources empty (anchor-only, matching #60 v1) keeps
// today's fail-open-on-revocation behavior — every serial reports
// not-revoked — unless requireCRL is set (issue #91), in which case that
// specific combination becomes a construction error too: an operator who
// opted into requiring a CRL must not have a hostile coordinator strip one
// from a coldstart invite and silently fall back to fail-open. requireCRL
// with no anchor at all is also an error rather than a quiet no-op, since
// there would be nothing for it to enforce.
//
// now is passed in rather than read here so tests use a fixed clock,
// matching verifyExitCredential; New passes the wall clock.
func buildExitVerifier(pubKeyHex, crlEncoded, crlPath string, requireCRL bool, now time.Time) (*admission.Verifier, *admission.ClientCRL, error) {
	pubKeyHex = strings.TrimSpace(pubKeyHex)
	crlEncoded = strings.TrimSpace(crlEncoded)
	crlPath = strings.TrimSpace(crlPath)
	if crlEncoded != "" && crlPath != "" {
		return nil, nil, errors.New("core: set at most one of AdmissionCRL, AdmissionCRLPath")
	}

	if pubKeyHex == "" {
		if crlEncoded != "" || crlPath != "" {
			return nil, nil, errors.New("core: AdmissionCRL/AdmissionCRLPath requires AdmissionPubKey (a revocation bundle is verified against the admission anchor)")
		}
		if requireCRL {
			return nil, nil, errors.New("core: AdmissionRequireCRL requires AdmissionPubKey (nothing to verify a revocation bundle against)")
		}
		return nil, nil, nil
	}
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("core: AdmissionPubKey must be %d hex-encoded bytes (the ed25519 admission root public key)", ed25519.PublicKeySize)
	}

	crl := admission.NewClientCRL(ed25519.PublicKey(pub))
	switch {
	case crlEncoded != "":
		if err := crl.Set(crlEncoded, now); err != nil {
			return nil, nil, fmt.Errorf("core: AdmissionCRL invalid: %w", err)
		}
	case crlPath != "":
		encoded, err := readCRLFile(crlPath)
		if err != nil {
			return nil, nil, fmt.Errorf("core: AdmissionCRLPath invalid: %w", err)
		}
		if err := crl.Set(encoded, now); err != nil {
			return nil, nil, fmt.Errorf("core: AdmissionCRLPath invalid: %w", err)
		}
	case requireCRL:
		return nil, nil, errors.New("core: AdmissionRequireCRL set but no AdmissionCRL/AdmissionCRLPath configured (refusing to silently fail open on revocation)")
	}

	return admission.NewVerifier(ed25519.PublicKey(pub), crl.Revoked), crl, nil
}

// readCRLFile reads and trims the CRL file at path, without parsing or
// verifying it — the caller (construction or a reload tick) does that against
// its own anchor and clock.
func readCRLFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// verifyExitCredential is the client-side admission predicate (issue #60): given
// the admission verifier, the exit static public key the Noise_NK handshake just
// authenticated, and the credential bytes the exit presented in that handshake,
// it decides whether to route through the exit. It admits only when the
// credential is signed by the admission root, names this exact exit key as its
// subject (the binding that makes a credential non-transferable — a hostile exit
// cannot replay another exit's credential to pass), authorizes the exit role,
// and is within its validity window. now is passed in so tests drive a fixed
// clock.
//
// An empty credential is a rejection, not a pass: reaching here means the client
// holds an admission anchor and therefore requires one. The verifier's error is
// returned verbatim — admission errors carry only protocol facts (never key
// material), so they are safe to surface as the user-visible abort reason.
//
// An empty exitPub is a rejection too, and that guard is the structural half of issue
// #29. hex.EncodeToString(nil) is "", and admission.accept reads an empty subject as a
// BEARER credential and skips the binding check:
//
//	if subject != "" && subject != c.Subject { return ErrSubjectMismatch }
//
// That default is correct where it comes from — a client has no coordinator-known id, so
// its own credential genuinely is bearer — and it is exactly wrong here. It means a
// caller that fails to thread the exit's key through does not get an error; it gets a
// check that silently passes, so any exit may present any authorized exit's credential.
// It fails OPEN toward accepting, which is why #29 was invisible: nothing errors,
// nothing disconnects, and the client routes through an exit the root never authorized
// under that identity.
//
// Reaching this function means clientHandshake just authenticated a static key, so there
// is always one to bind to and an empty one is a plumbing bug rather than a state the
// protocol can produce. Refusing it makes the next path that forgets fail closed and
// loudly instead of open and silently — which is worth more than the one call site that
// prompted it, since the failure mode has no other symptom.
func verifyExitCredential(v *admission.Verifier, exitPub, cred []byte, now time.Time) error {
	if len(exitPub) == 0 {
		return errUnboundExitKey
	}
	if len(cred) == 0 {
		return errMissingExitCredential
	}
	_, err := v.Verify(string(cred), now, admission.RoleExit, hex.EncodeToString(exitPub))
	return err
}

// errUnboundExitKey is returned when the client-side admission check is reached with no
// exit static key to bind the credential to (issue #29). It names a plumbing bug rather
// than a network condition — an exit cannot cause it — so it is worded for whoever has
// to find it, and it is deliberately distinct from errMissingExitCredential, which is
// something an exit really can do to us.
var errUnboundExitKey = errors.New("core: exit admission check reached with no exit key to bind the credential to — an unbound check would accept any authorized exit's credential")

// exitVerifyFunc returns the per-handshake callback clientHandshake runs on the
// credential an exit presents, or nil when this client has no admission anchor
// (fail-open). The callback closes over exitPub — the authenticated static key of the
// exit this particular handshake is against — and the wall clock.
//
// exitPub is a PARAMETER rather than engine state, and that is load-bearing under
// country-only assignment (issue #146). The client no longer selects one exit for the
// engine's lifetime: the coordinator chooses, per session, and may choose differently
// on any reconnect or reselection. A callback closing over engine state would verify
// the presented credential against whichever exit was current when the engine was
// built, so a credential legitimately belonging to the exit we are actually talking to
// would be rejected — and, worse, a credential for the OLD exit would be accepted.
// Taking the key here means every caller necessarily verifies against the same key it
// hands clientHandshake, because it has only one to give.
func (e *Engine) exitVerifyFunc(exitPub []byte) func(cred []byte) error {
	if e.exitVerifier == nil {
		return nil
	}
	return func(cred []byte) error {
		return verifyExitCredential(e.exitVerifier, exitPub, cred, time.Now())
	}
}

// admissionCRLReloadInterval is the default cadence reloadCRLLoop re-reads
// Config.AdmissionCRLPath at (issue #90), mirroring cmd/coordinator's own
// admission.reloadRevocationsLoop. CRLs are minted short-lived by design
// (cmd/admission-issue -crl-ttl defaults to 24h) so a revoked credential is
// cut off within one distribution cycle even if a client never reloaded; this
// interval only needs to stay comfortably under that TTL so a long-lived
// client picks up an operator's freshly rotated bundle well before the
// previous one lapses, without polling the filesystem needlessly often.
const admissionCRLReloadInterval = 5 * time.Minute

// reloadCRLLoop re-reads Config.AdmissionCRLPath on an interval and, when it
// parses, verifies, and is unexpired, swaps it into e.clientCRL — so a
// long-lived client picks up an operator's newly rotated revocation bundle
// without a restart (issue #90), the client-side mirror of
// cmd/coordinator's reloadRevocationsLoop. Runs only when a path is
// configured (e.clientCRL != nil and cfg.AdmissionCRLPath != "", checked by
// the caller) and only for the client role, since exitVerifier is read
// solely by the client's exit-connect path (see Start). Exits on Stop.
//
// A read, parse, signature, or expiry failure is logged as a non-fatal event
// and the previously loaded bundle is kept — the same fail-safe posture as
// the coordinator's own loop: a transient misread (an operator mid-write) or
// an operator late to rotate a lapsed bundle must not silently degrade an
// active revocation check to fail-open, and must not take down an otherwise
// healthy connection either.
func (e *Engine) reloadCRLLoop() {
	defer e.wg.Done()
	t := time.NewTicker(e.crlReloadInterval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			e.reloadCRL(time.Now())
		}
	}
}

// reloadCRL performs a single reload attempt against clock now; split out
// from reloadCRLLoop, and parameterized on now rather than reading
// time.Now() itself, so a test can drive it deterministically without a
// ticker and with a fixed clock (matching verifyExitCredential/accept
// elsewhere in this package).
func (e *Engine) reloadCRL(now time.Time) {
	encoded, err := readCRLFile(e.cfg.AdmissionCRLPath)
	if err != nil {
		e.emit(EventError, "", "admission: reload CRL from %s: %v", e.cfg.AdmissionCRLPath, err)
		return
	}
	if err := e.clientCRL.Set(encoded, now); err != nil {
		e.emit(EventError, "", "admission: reload CRL from %s: %v", e.cfg.AdmissionCRLPath, err)
		return
	}
	e.emit(EventInfo, "", "admission: reloaded CRL from %s", e.cfg.AdmissionCRLPath)
}
