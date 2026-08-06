package accountclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// signer is the pair every issuing verb needs: the key a credential binds, and
// a signature over (pinned audience, service challenge) under exactly one
// purpose.
//
// It is an interface over a closure rather than an ed25519.PrivateKey on
// purpose. This package never holds a device private key and cannot be made to
// sign under a purpose its caller did not intend: core owns both signers, each
// with its tag fixed at the call site, and hands out only the result.
type signer struct {
	pub  ed25519.PublicKey
	sign func(audience string, challenge []byte) ([]byte, error)
}

// Enroll redeems a claim code for this device's first credential:
//
//  1. POST /v1/challenge for a fresh nonce.
//  2. Sign it with bacchus/assert-enroll/v1 over the pinned audience.
//  3. POST /v1/enroll — ONCE — with the claim code, this device's public key,
//     the label, the challenge and the signature.
//  4. Persist the device credential, the issuer cert and — when the deployment
//     mints one — the admission credential, in one write.
//
// label is what the account's owner will see this device called. It travels in
// the clear to the service and is stored there, so it should be something a user
// chose or a generic device name — never a hostname, a username, or anything
// else the machine knows about its owner that they did not decide to share.
//
// # Step 3 happens exactly once, whatever goes wrong
//
// The claim code and the challenge are both single-use, and a claim code spent by
// a request whose response was lost is GONE: the service erases a spent claim
// hash rather than flagging it, so there is nothing left for a second attempt to
// match. A retry answers claim_rejected and cannot recover the credential. For a
// paying customer that is their access destroyed by a helpful-looking retry loop.
//
// So this function retries nothing about /v1/enroll — not on a timeout, not on a
// connection reset, and not on unknown_challenge. The last one deserves saying
// out loud because it is the case where a retry would in fact be safe today: the
// service consumes the challenge before it resolves the claim code, so a
// challenge miss provably costs the holder nothing. That ordering is a property
// of the current implementation, not a promise in the transport specification,
// and the failure mode if it ever changed is the one failure this whole
// paragraph exists to prevent. Depending on it would buy one saved round trip on
// a rare path and stake a customer's access on a guarantee nobody wrote down.
//
// # What happens when the response is lost anyway
//
// If /v1/enroll cannot be completed — the send failed, the read failed, the body
// did not parse — the outcome is genuinely unknown: the service may have enrolled
// this device and spent the claim code. That is the one case where this function
// makes a second call, and it is deliberately a DIFFERENT call: Collect, which
// asks /v1/credential for a credential using the device key this process still
// holds. If it answers, the enrollment had succeeded and the credential is
// recovered; if it does not, the original failure is returned unchanged.
//
// already_enrolled takes the same recovery path for the same reason — the key is
// enrolled somewhere, so there is a credential to collect — with one difference
// worth knowing: the claim code is NOT spent in that case, because the service
// checks enrollment before it spends anything. It remains usable for a different
// device.
//
// claim_rejected does NOT take that path. It is the answer to a typo as much as
// to a spent code, and a failed Collect returns bad_assertion, which counts
// toward a per-device-key cooldown on the service. Probing after each typo would
// let a user lock their own device key out for the length of that cooldown while
// they hunt for the code they mistyped — turning a fixable mistake into a wait.
func (c *Client) Enroll(ctx context.Context, dev *core.DeviceEnrollment, claim, label string) (devicestore.Credential, error) {
	if dev == nil {
		return devicestore.Credential{}, errors.New("accountclient: Enroll needs a device enrollment")
	}
	if claim == "" {
		return devicestore.Credential{}, errors.New("accountclient: Enroll needs a claim code")
	}
	// Asked before anything is spent. A device that already holds a credential
	// has nothing to buy with a claim code, and enrolling again would either be
	// refused as already_enrolled or — if the key had somehow changed — spend
	// the code to bind an identity the engine will not present.
	if dev.Enrolled() {
		return devicestore.Credential{}, ErrAlreadyHaveCredential
	}

	s := signer{pub: dev.DevicePub(), sign: dev.SignEnroll}

	// The rotation over configured addresses (bacchus#192) is written out here
	// rather than run through overExchanges, and the difference is the whole
	// paragraph above: an address may be tried only until the moment /v1/enroll
	// is sent to it. A challenge costs nothing, so an address that cannot mint one
	// is skipped; the instant the enroll request goes out, that address is the
	// only address, whatever it answers or fails to answer. Recovery from an
	// ambiguous outcome is Collect, which is safe to repeat and may rotate freely.
	var (
		challenge []byte
		err       error
		base      string
	)
	for _, candidate := range c.baseOrder() {
		challenge, _, err = c.challengeFrom(ctx, candidate)
		if err == nil {
			base = candidate
			break
		}
		if !errors.Is(err, ErrUnreachable) {
			return devicestore.Credential{}, err
		}
		c.markUnreachable(candidate)
	}
	if base == "" {
		return devicestore.Credential{}, err
	}
	sig, err := s.sign(c.audience, challenge)
	if err != nil {
		return devicestore.Credential{}, fmt.Errorf("accountclient: sign enrollment assertion: %w", err)
	}

	var resp credentialsResponse
	err = c.post(ctx, base, "/v1/enroll", enrollRequest{
		Claim:     claim,
		DevicePub: s.pub,
		Label:     label,
		Challenge: challenge,
		Sig:       sig,
	}, &resp)

	switch {
	case err == nil:
		return c.persist(dev, resp)

	case errors.Is(err, ErrUnreachable):
		// Ambiguous: the request may have been served. Recover rather than
		// retry.
		if res, rerr := c.Collect(ctx, dev); rerr == nil {
			return res, nil
		}
		return devicestore.Credential{}, fmt.Errorf("%w (the claim code may have been spent; this device holds no credential)", err)

	default:
		if code, ok := CodeOf(err); ok && code == CodeAlreadyEnrolled {
			if res, rerr := c.Collect(ctx, dev); rerr == nil {
				return res, nil
			}
		}
		return devicestore.Credential{}, err
	}
}

// ErrAlreadyHaveCredential is Enroll's refusal to spend a claim code for a
// device that already holds a credential. It is not a failure of anything — the
// caller wanted a credential and there is one — so a caller may reasonably
// ignore it, which is why it is a sentinel rather than a generic error.
var ErrAlreadyHaveCredential = errors.New("accountclient: this device already holds a device credential")

// Collect asks POST /v1/credential for a credential using the device key alone,
// with no claim code. It is three things at once, and they are one call because
// the service treats them as one:
//
//   - the recovery path when an enrollment response was lost,
//   - how a device that was enrolled elsewhere picks up its first credential,
//   - the recovery half of renewal (see Renew, which is this exchange with the
//     seam's plumbing and the store left to its caller).
//
// It spends nothing but a challenge, so unlike Enroll it is safe to call again,
// and this function retries itself once on unknown_challenge — the one coded
// failure a fresh nonce actually fixes, and the one that a service restart
// produces, since live challenges are held in memory.
//
// bad_assertion here means EITHER the signature was wrong OR this device is not
// enrolled anywhere. Those are one answer by design and must not be presented to
// a user as two: telling a caller which one it was would answer "is this public
// key enrolled" for a caller who has proven nothing.
func (c *Client) Collect(ctx context.Context, dev *core.DeviceEnrollment) (devicestore.Credential, error) {
	if dev == nil {
		return devicestore.Credential{}, errors.New("accountclient: Collect needs a device enrollment")
	}
	resp, err := c.issueCredential(ctx, signer{pub: dev.DevicePub(), sign: dev.SignRenew})
	if err != nil {
		return devicestore.Credential{}, err
	}
	return c.persist(dev, resp)
}

// issueCredential is the /v1/credential exchange without any persistence, shared
// by Collect and by Renew — which persist to different places, and must not each
// hold their own copy of the exchange to get there.
//
// It is the exchange the configured addresses exist for (bacchus#192): this is
// what a device runs every ten minutes once it is inside its renewal margin, so
// an address that has gone away is discovered here and rotated past here. Both
// legs run against one address, and the unknown_challenge retry stays on that
// same address — a fresh nonce is what fixes that code, and a fresh nonce from
// somewhere else is not.
func (c *Client) issueCredential(ctx context.Context, s signer) (credentialsResponse, error) {
	var resp credentialsResponse
	err := c.overExchanges(func(base string) error {
		r, err := c.issueCredentialOnce(ctx, base, s)
		if code, ok := CodeOf(err); ok && code == CodeUnknownChallenge {
			r, err = c.issueCredentialOnce(ctx, base, s)
		}
		resp = r
		return err
	})
	return resp, err
}

func (c *Client) issueCredentialOnce(ctx context.Context, base string, s signer) (credentialsResponse, error) {
	var resp credentialsResponse
	challenge, _, err := c.challengeFrom(ctx, base)
	if err != nil {
		return resp, err
	}
	sig, err := s.sign(c.audience, challenge)
	if err != nil {
		return resp, fmt.Errorf("accountclient: sign renewal assertion: %w", err)
	}
	err = c.post(ctx, base, "/v1/credential", credentialRequest{
		DevicePub: s.pub,
		Challenge: challenge,
		Sig:       sig,
	}, &resp)
	return resp, err
}

// persist writes what an issuing verb returned into the device's own storage and
// returns it.
//
// All three values go in through ONE Put, because they are issued together over
// one window and a client that wrote them separately could persist a fresh
// credential against a stale companion. That used to be two writes to two
// places — core/devicestore held exactly two strings, so the admission
// credential went to a file of this package's own beside them. bacchus#166 gave
// it a slot, and the invariant is now the store's shape rather than this
// function's care.
//
// An empty Admission is not an error and does not clear a stored one. A service
// with no admission key mints none, and a deployment can gain an admission
// authority between two renewals but a single response that omitted it is not
// evidence the credential this device already holds has been withdrawn.
func (c *Client) persist(dev *core.DeviceEnrollment, resp credentialsResponse) (devicestore.Credential, error) {
	issued := resp.credential()
	if !issued.Presentable() {
		// A 200 missing either half is not a credential. Failing here rather
		// than storing what arrived keeps the store's invariant — the parts are
		// written together or not at all — true against a service that is
		// wrong, not merely against one that is right.
		return devicestore.Credential{}, fmt.Errorf("%w: issuing verb returned an incomplete credential", ErrUnreachable)
	}
	if issued.Admission == "" {
		if held, _ := dev.Current(); held.Admission != "" {
			issued.Admission = held.Admission
		}
	}
	if err := dev.Put(issued); err != nil {
		return devicestore.Credential{}, fmt.Errorf("accountclient: persist device credential: %w", err)
	}
	return issued, nil
}
