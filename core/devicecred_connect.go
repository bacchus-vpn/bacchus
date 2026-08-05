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
	held, ok := e.deviceStore.Get()
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
	l.send(wire{Type: "challenge", Cred: e.admissionCred()})

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
		cred:       held.Device,
		issuerCert: held.IssuerCert,
		assert:     base64.StdEncoding.EncodeToString(sig),
	}, true
}

// admissionCred is the admission credential this node presents — on a client's
// list/connect/challenge, on a forwarder's register, and inside an exit's msg2.
//
// Config.AdmissionCred is the answer whenever it is set, so nothing an operator
// configured changes meaning: cmd/node's -admission-cred still wins, and a
// deployment with no account service is byte-identical to one predating
// bacchus#166. What is new is the fallback: when that field is empty and the
// account service minted an admission credential for this DEVICE alongside its
// device credential, the device store is holding it, and this is where it
// reaches the wire.
//
// It is a function rather than a field read for the reason bacchus#166 exists:
// renewal rewrites the stored value underneath a running engine, and every
// caller of this must see the fresh one. A value snapshotted at construction —
// which is what an embedder reading the file itself and setting
// Config.AdmissionCred could only ever produce — is stale from the first renewal
// onward, and stale in the specific way that expires exactly when membership was
// supposed to be extended.
//
// Nothing here verifies it. This node holds no admission anchor for its own
// credential and has no business holding one; the credential is opaque to its
// bearer and meaningful only to the peer that checks it.
func (e *Engine) admissionCred() string {
	if e.cfg.AdmissionCred != "" {
		return e.cfg.AdmissionCred
	}
	if e.deviceStore == nil {
		return ""
	}
	held, _ := e.deviceStore.Get()
	// Deliberately not gated on ok. A device holding an admission credential but
	// no presentable device credential is an odd state, and refusing to present
	// the one it does hold would answer that oddity by disconnecting the node
	// from a network it is still admitted to.
	return held.Admission
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

// purposeEnroll is bacchus/assert-enroll/v1: a device proving possession of the
// key it is asking the account service to bind, on the one call that spends a
// claim code. It is the third of the four tags in the wire format's assertion
// table (see purposeConnect's home in core/devicecred and purposeRenew above);
// the fourth, sibling approval, is not spoken by anything here.
//
// It is unexported for the same reason purposeRenew is, and the reason is not
// symmetry. core/devicecred deliberately declares only the purpose a COORDINATOR
// verifies, because a coordinator has no business holding a verifier for the
// others. This tag is verified by the account service and by nothing in this
// repository, so the only thing this repository needs is the ability to SIGN
// under it — which DeviceEnrollment.SignEnroll below is, and which is
// deliberately the only way out.
const purposeEnroll devicecred.Purpose = "bacchus/assert-enroll/v1"

// DeviceEnrollment is a device's own half of enrollment: the key a credential
// will be bound to, a signer scoped to exactly the enrollment purpose, and the
// store the engine will read the result back out of.
//
// It exists because enrollment happens BEFORE there is an Engine. Config.DeviceRenew
// is handed a DeviceRenewRequest by a running engine that already loaded the key;
// a device that has never enrolled has no credential, so nothing has started, and
// the caller has to be able to reach the same key and the same store on its own.
// This is that reach, and it is deliberately narrow: the private key is not a
// field, Sign is not a parameter, and the purpose is not a caller's choice.
//
// That last part is the whole argument ADR-0046 §6 makes for keeping the
// ed25519.Sign call in this repository rather than handing a caller the raw key
// and trusting it to remember the tag. A key that signs in four contexts is only
// safe if nothing outside the intended context can produce its output, and an
// enrollment signer that could be asked for a connect assertion — or worse, a
// sibling approval — would hand a hostile or merely careless embedder the exact
// substitution the purpose tag was invented to make impossible.
//
// core itself never constructs one of these and never calls any of its methods.
// It is here rather than in the enrollment client because of what it holds, not
// because of who uses it.
type DeviceEnrollment struct {
	key   ed25519.PrivateKey
	store *devicestore.Store
	dir   string
}

// OpenDeviceEnrollment loads (or generates, on first run) the on-device keypair
// in deviceCredDir and opens the credential store beside it — the same key and
// the same file New would use for a Config with that DeviceCredDir, via the same
// two calls, so a device cannot enroll under one identity and connect under
// another.
//
// deviceCredDir == "" is devicestore's documented in-memory mode: a fresh key
// that persists nowhere. It is useful in a test and useless in a client, because
// the credential an enrollment buys is bound to a key the next start will not
// have. Callers that mean to enroll a real device pass a real directory.
func OpenDeviceEnrollment(deviceCredDir string) (*DeviceEnrollment, error) {
	key, err := devicestore.LoadOrGenerateKey(deviceCredDir)
	if err != nil {
		return nil, fmt.Errorf("device enrollment: %w", err)
	}
	store, err := devicestore.Open(DeviceCredPath(deviceCredDir))
	if err != nil {
		return nil, fmt.Errorf("device enrollment: %w", err)
	}
	return &DeviceEnrollment{key: key, store: store, dir: deviceCredDir}, nil
}

// DevicePub is the public half of the on-device key — what an enrollment binds a
// credential to, and what an account service resolves an account by afterwards.
func (d *DeviceEnrollment) DevicePub() ed25519.PublicKey {
	return d.key.Public().(ed25519.PublicKey)
}

// Dir is the directory this enrollment's key and credential live in, so a caller
// that keeps its own adjacent state has one answer for where it goes rather than
// re-deriving a path the engine also computes. Empty for an in-memory enrollment.
func (d *DeviceEnrollment) Dir() string { return d.dir }

// Enrolled reports whether this device already holds a credential — the question
// a caller must ask BEFORE spending a claim code, because a claim code is spent
// exactly once and the second spend does not fail safely, it fails
// unrecoverably.
func (d *DeviceEnrollment) Enrolled() bool {
	_, ok := d.store.Get()
	return ok
}

// Current returns everything this device holds, matching devicestore.Store.Get.
// It is what a caller renews FROM.
func (d *DeviceEnrollment) Current() (devicestore.Credential, bool) {
	return d.store.Get()
}

// SignEnroll produces a bacchus/assert-enroll/v1 assertion over audience and
// challenge. audience is the account service's own identity, pinned out of band
// by whoever configured the service's address — never a value read out of the
// response being signed against, which would let the responder choose the
// binding.
//
// This is the only enrollment signature this repository can produce, and it can
// produce no other kind: the purpose is a constant here, not an argument.
func (d *DeviceEnrollment) SignEnroll(audience string, challenge []byte) ([]byte, error) {
	return devicecred.SignAssertion(d.key, purposeEnroll, audience, challenge)
}

// SignRenew produces a bacchus/assert-renew/v1 assertion, the same signature
// Config.DeviceRenew's seam hands out — offered here as well because the
// renewal verb is also how a device RECOVERS a credential whose enrollment
// response it failed to read, and that recovery happens on the enrollment path,
// before any engine exists to supply the seam.
func (d *DeviceEnrollment) SignRenew(audience string, challenge []byte) ([]byte, error) {
	return devicecred.SignAssertion(d.key, purposeRenew, audience, challenge)
}

// Put persists what an issuing verb returned, exactly as devicestore.Store.Put
// does — all of it in one write, because a client that wrote the parts in
// separate steps could persist a fresh credential against a stale companion.
func (d *DeviceEnrollment) Put(c devicestore.Credential) error {
	return d.store.Put(c)
}

// DeviceRenewRequest is what Config.DeviceRenew is called with: enough to renew
// without ever handing the caller this device's private key. Sign produces a
// PurposeRenew assertion over whatever audience and challenge the account
// service's protocol asks for. That endpoint exists now, and this package still
// does not bind itself to the exchange around it: knowing a path is specified is
// not knowing where a client's challenge comes from or what audience string binds
// it (ADR-0046's 2026-08-04 update). So the caller supplies both and gets back
// only the signature.
type DeviceRenewRequest struct {
	DevicePub ed25519.PublicKey
	// Current is what this device holds right now — what it is renewing FROM.
	// Not sent to the account service by anything that speaks the specified
	// exchange (the service resolves the account by public key and has no
	// parameter for it); it is here because the seam's CALLER needs it, for the
	// renewal-due check that decided to call at all.
	Current devicestore.Credential
	Sign    func(audience string, challenge []byte) ([]byte, error)
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
	current, ok := e.deviceStore.Get()
	if !ok {
		return // nothing enrolled yet — out of this lane's scope; see ADR-0046
	}
	if !devicestore.NeedsRenewal(current.Device, now, e.deviceRenewMargin()) {
		return
	}

	req := DeviceRenewRequest{
		DevicePub: e.deviceKey.Public().(ed25519.PublicKey),
		Current:   current,
		Sign: func(audience string, challenge []byte) ([]byte, error) {
			return devicecred.SignAssertion(e.deviceKey, purposeRenew, audience, challenge)
		},
	}
	fresh, err := e.cfg.DeviceRenew(ctx, req)
	if err != nil {
		e.emit(EventError, "", "device credential: renewal failed, will retry at the next check: %v", err)
		return
	}
	if !fresh.Presentable() {
		// A seam that answers with no error and half a credential is a seam that
		// would otherwise ERASE a working one. Refusing here keeps a filler's bug
		// from costing this device its access, and the retry at the next check
		// costs nothing.
		e.emit(EventError, "", "device credential: renewal returned an incomplete credential; keeping the one this device already holds")
		return
	}
	if fresh.Admission == "" {
		// Carried forward rather than cleared. A deployment with no admission
		// authority mints none, and a response that omitted it is not evidence
		// that the credential this device already holds has been withdrawn —
		// withdrawal is what the revocation list is for. Clearing here would take
		// a client off an admission-enforcing network on the strength of a field
		// that was never populated in the first place.
		fresh.Admission = current.Admission
	}
	if err := e.deviceStore.Put(fresh); err != nil {
		e.emit(EventError, "", "device credential: renewed but could not persist the fresh credential: %v", err)
		return
	}
	e.emit(EventInfo, "", "device credential: renewed")
}

// DeviceCredPath is where a DeviceCredDir keeps the credential + issuer cert
// pair, and it is exported because an enroller and the engine MUST agree on it.
//
// Before enrollment existed in this repository the join was invisible: one
// function computed the path, opened the store, and read it. Now two packages
// touch the same directory — an enrollment client writes the first credential a
// device ever holds, and New reads it back — and if they disagreed about the
// filename, enrollment would report success, the file would be on disk, and the
// engine would present nothing on every connect thereafter. Nothing would log an
// error, because from each side the operation succeeded. One definition, read by
// both, makes that disagreement unrepresentable rather than merely unlikely.
//
// An empty dir returns an empty path, which devicestore.Open reads as its
// documented in-memory mode rather than as an error.
func DeviceCredPath(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "credential.json")
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
	store, err := devicestore.Open(DeviceCredPath(cfg.DeviceCredDir))
	if err != nil {
		return nil, nil, fmt.Errorf("device credential: %w", err)
	}
	return key, store, nil
}
