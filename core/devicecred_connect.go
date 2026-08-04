package core

// The client half of the account service's connect-time entitlement chain
// (issue #50/#51, ADR-0045, ADR-0046). #51 landed the coordinator's gate; this
// file is what answers it: fetching a per-connect challenge, signing it with the
// on-device key, and carrying the result on the connect that attemptWith already
// builds. core/devicestore owns what is generated and stored; this file owns
// when it is used and how it goes on the wire.
//
// A client with no device credential is unaffected byte for byte: every field
// this adds is empty, exactly the pre-#50 connect.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// deviceChallengeTimeout bounds how long one attempt waits for a coordinator's
// reply to a "challenge" request. It is a small slice of the overall per-mode
// budget (directTimeout/relayTimeout, both several seconds) — one UDP round trip
// plus processing — so a coordinator that is slow or silent on this leg still
// leaves the rest of the budget for awaitSession rather than starving it.
const deviceChallengeTimeout = 5 * time.Second

// deviceConnectFields are the four wire fields a connect carries to answer the
// coordinator's device-credential gate. The zero value carries none of them —
// json:"...,omitempty" on every one means splicing a zero value into a connect
// is byte-identical to a build that predates #50.
type deviceConnectFields struct {
	challenge  string // echoed back, standard base64 — the coordinator's own encoding
	cred       string // "bacchusd1:" envelope
	issuerCert string // "bacchusi1:" envelope
	assert     string // standard base64 signature
}

// presentDeviceCredential answers coordinator link l's device-credential gate
// for one connect attempt, or reports ok=false when there is nothing useful to
// send — no local device credential, or no usable challenge — in which case the
// caller proceeds with a plain connect exactly as it would have before #50/#51
// existed. That is a deliberate degrade, not a failure: an unenforced gate and a
// momentarily slow one look identical from here (issueDeviceChallenge answers
// both with an empty challenge — see cmd/coordinator/devicecred.go), and a
// connect the coordinator's own gate then refuses is a legible, already-handled
// outcome (pairRefused), not a reason to abort the attempt before it is sent.
//
// audience is l.raw — the address THIS client dialled, byte for byte — never
// anything the coordinator says about itself. Bacchus runs a pool, and an
// audience taken from the coordinator's own reply would let a hostile member
// announce an honest one's identity, relay the challenge, and spend this
// device's entitlement itself (ADR-0045 §4). The challenge is fetched fresh on
// every call and never cached: it is per-coordinator and single-use, so a
// rotation or a retried attempt must not reuse one from a prior link or a prior
// call here.
func (e *Engine) presentDeviceCredential(ctx context.Context, l *coordLink, timeout time.Duration) (deviceConnectFields, bool) {
	if e.deviceStore == nil {
		return deviceConnectFields{}, false
	}
	cred, issuerCert, ok := e.deviceStore.Get()
	if !ok {
		return deviceConnectFields{}, false
	}

	// A single send, deliberately not sendN. issueDeviceChallenge REPLACES
	// whatever challenge this source already holds on every call (a client that
	// asks twice is retrying — cmd/coordinator/devicecred.go's challengeStore.issue),
	// so three copies would mint three different nonces and reply with three
	// different values, only the last of which is still live server-side by the
	// time this attempt tried to spend whichever one it acted on. sendN is correct
	// for "connect" because the coordinator collapses its copies onto one request
	// by nonce; there is no equivalent collapse here, so retransmitting this
	// request would race against itself. Loss of this one datagram is instead
	// handled the same way any other silent leg is: the deadline below expires and
	// the caller falls back to a plain connect.
	l.send(wire{Type: "challenge", Cred: e.cfg.AdmissionCred})

	budget := deviceChallengeTimeout
	if budget > timeout {
		budget = timeout
	}
	challenge, ok := e.awaitChallenge(ctx, l, budget)
	if !ok {
		return deviceConnectFields{}, false
	}

	sig, err := devicecred.SignAssertion(e.deviceKey, devicecred.PurposeConnect, l.raw, challenge)
	if err != nil {
		// Reachable only if the coordinator's challenge were shorter than
		// devicecred.MinChallenge, which issueDeviceChallenge never produces (a
		// fixed 32 bytes) — belt and braces, not a path this build expects to take.
		e.emit(EventError, "", "device credential: could not sign connect assertion: %v", err)
		return deviceConnectFields{}, false
	}

	return deviceConnectFields{
		challenge:  base64.StdEncoding.EncodeToString(challenge),
		cred:       cred,
		issuerCert: issuerCert,
		assert:     base64.StdEncoding.EncodeToString(sig),
	}, true
}

// awaitChallenge waits for member l to answer a "challenge" request. ok is
// false on timeout, cancellation, shutdown, an empty challenge (the gate is off
// or the coordinator's store is at capacity — cmd/coordinator deliberately
// reports both the same way), or a value that fails to decode.
//
// Any other reply type is ignored rather than treated as an answer — a stray
// buffered "session"/"countries"/"error" left over from something else on this
// link is not a challenge, and awaitSession affords the same courtesy to a
// stray "challenge" it wasn't expecting.
func (e *Engine) awaitChallenge(ctx context.Context, l *coordLink, timeout time.Duration) ([]byte, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			return nil, false
		case <-e.stop:
			return nil, false
		case <-deadline:
			return nil, false
		case m, ok := <-l.msgCh:
			if !ok {
				return nil, false
			}
			if m.Type != "challenge" {
				continue
			}
			if m.Challenge == "" {
				return nil, false
			}
			raw, err := base64.StdEncoding.DecodeString(m.Challenge)
			if err != nil {
				return nil, false
			}
			return raw, true
		}
	}
}

// purposeRenew is bacchus/assert-renew/v1 (bacchus-payment's
// docs/design/credential-wire.md §4): a device proving possession of its OWN key
// to the account service when re-upping a credential before it expires, as
// opposed to PurposeConnect's proof to a coordinator. core/devicecred does not
// declare it — its own doc says only the purposes a COORDINATOR verifies belong
// there, and a coordinator never verifies a renewal (account-model.md §5 point
// 5). devicecred.Purpose is just a string type, so using this tag needs no
// change to that package: SignAssertion already takes any Purpose, and the
// account service is what actually checks it.
const purposeRenew devicecred.Purpose = "bacchus/assert-renew/v1"

// DeviceRenewRequest is what Config.DeviceRenew is called with: enough to renew
// without ever handing the caller this device's private key. Sign produces a
// PurposeRenew assertion over whatever audience and challenge the account
// service's protocol asks for. That endpoint exists now, and this package still
// does not bind itself to the exchange around it: knowing a path is specified is
// not knowing where a client's challenge comes from or what audience string binds
// it (ADR-0046's 2026-08-04 update). So the caller supplies both and gets back
// only the signature.
type DeviceRenewRequest struct {
	DevicePub         ed25519.PublicKey
	CurrentCred       string // the "bacchusd1:" envelope about to expire
	CurrentIssuerCert string
	Sign              func(audience string, challenge []byte) ([]byte, error)
}

// deviceRenewCallTimeout bounds a single Config.DeviceRenew invocation, so a
// caller-supplied transport that hangs delays shutdown by at most this long
// rather than wedging deviceRenewLoop's goroutine (and Stop's wg.Wait) forever.
const deviceRenewCallTimeout = 30 * time.Second

// deviceRenewCheckInterval is how often deviceRenewLoop checks whether the
// stored credential needs renewing. It does not itself decide urgency — that is
// devicestore.NeedsRenewal's margin, generous relative to this interval so a
// transient DeviceRenew failure just waits for the next tick.
const deviceRenewCheckInterval = 10 * time.Minute

// defaultDeviceRenewMargin is used when Config.DeviceRenewMargin is zero.
// Comfortably inside even the SHORTER end of the 24-72h credential lifetime
// account-model.md §5 describes, so a client that is up for a while gets many
// checks, each a cheap retry, before renewal is genuinely urgent.
const defaultDeviceRenewMargin = 6 * time.Hour

func (e *Engine) deviceRenewMargin() time.Duration {
	if e.cfg.DeviceRenewMargin > 0 {
		return e.cfg.DeviceRenewMargin
	}
	return defaultDeviceRenewMargin
}

// deviceRenewLoop periodically checks whether the stored device credential
// needs renewing and, when Config.DeviceRenew is set, asks it for a fresh one.
// Mirrors reloadCRLLoop's shape (ticker + e.stop select, the actual work
// factored out and parameterized on now for tests).
func (e *Engine) deviceRenewLoop() {
	defer e.wg.Done()
	t := time.NewTicker(deviceRenewCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), deviceRenewCallTimeout)
			e.maybeRenewDeviceCred(ctx, time.Now())
			cancel()
		}
	}
}

// maybeRenewDeviceCred renews the stored credential when it is due, at clock
// now. Split out from deviceRenewLoop so a test can drive it deterministically
// without a ticker, matching reloadCRL elsewhere in this package.
func (e *Engine) maybeRenewDeviceCred(ctx context.Context, now time.Time) {
	if e.cfg.DeviceRenew == nil || e.deviceStore == nil {
		return
	}
	cred, issuerCert, ok := e.deviceStore.Get()
	if !ok {
		return // nothing enrolled yet — out of this lane's scope; see ADR-0046
	}
	if !devicestore.NeedsRenewal(cred, now, e.deviceRenewMargin()) {
		return
	}

	req := DeviceRenewRequest{
		DevicePub:         e.deviceKey.Public().(ed25519.PublicKey),
		CurrentCred:       cred,
		CurrentIssuerCert: issuerCert,
		Sign: func(audience string, challenge []byte) ([]byte, error) {
			return devicecred.SignAssertion(e.deviceKey, purposeRenew, audience, challenge)
		},
	}
	newCred, newIssuerCert, err := e.cfg.DeviceRenew(ctx, req)
	if err != nil {
		e.emit(EventError, "", "device credential: renewal failed, will retry at the next check: %v", err)
		return
	}
	if err := e.deviceStore.Put(newCred, newIssuerCert); err != nil {
		e.emit(EventError, "", "device credential: renewed but could not persist the fresh credential: %v", err)
		return
	}
	e.emit(EventInfo, "", "device credential: renewed")
}

// setupDeviceCredential builds this client's on-device keypair and credential
// store. Called from New before the engine exists, for the same reason
// exitVerifier and relayDir are built there: a client told to hold a device
// identity it cannot load must fail at construction, not discover it mid-connect.
//
// Only the client role gets one; a pure forwarder returns (nil, nil, nil) and
// never presents this chain. Config.DeviceCredDir may legitimately be empty even
// for a client — that is in-memory-only mode (see the Config field doc), not a
// construction error.
func setupDeviceCredential(cfg Config, roles map[string]bool) (ed25519.PrivateKey, *devicestore.Store, error) {
	if !roles[RoleClient] {
		return nil, nil, nil
	}
	key, err := devicestore.LoadOrGenerateKey(cfg.DeviceCredDir)
	if err != nil {
		return nil, nil, fmt.Errorf("device credential: %w", err)
	}
	credPath := ""
	if cfg.DeviceCredDir != "" {
		credPath = filepath.Join(cfg.DeviceCredDir, "credential.json")
	}
	store, err := devicestore.Open(credPath)
	if err != nil {
		return nil, nil, fmt.Errorf("device credential: %w", err)
	}
	return key, store, nil
}
