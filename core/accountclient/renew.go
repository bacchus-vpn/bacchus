package accountclient

import (
	"context"
	"fmt"

	"github.com/bacchus-vpn/bacchus/core"
)

// Renew satisfies core.Config.DeviceRenew exactly, so an embedder wires it with
//
//	cfg.DeviceRenew = client.Renew
//
// and nothing in core learns this package exists. That direction is the whole
// design: the dependency runs from here to core and never back, so a deployment
// that runs no account service imports nothing, configures nothing, and is not
// degraded for it — and a downstream deployment substituting its own issuer
// replaces this one value.
//
// The exchange is the same /v1/credential call Collect makes; the difference is
// only where the result goes. core owns the device credential and the issuer
// cert, and receives them as this function's return values so its own store
// writes them. The admission credential has no return value to travel in and is
// written here instead — see the file this package keeps beside the credential,
// and ADR-0056 §7 for why that asymmetry exists rather than being fixed.
//
// req.CurrentCred and req.CurrentIssuerCert are deliberately NOT sent. The
// service resolves the account by public key and has no parameter for them; a
// field the service ignores is a field that will eventually be trusted by
// mistake. They are useful to the seam's CALLER, for the renewal-due check that
// decided to call at all.
func (c *Client) Renew(ctx context.Context, req core.DeviceRenewRequest) (cred, issuerCert string, err error) {
	cred, issuerCert, _, err = c.renew(ctx, req)
	return cred, issuerCert, err
}

// RenewInto is Renew with somewhere to put the admission credential: dir is the
// device-credential directory whose admission file this refreshes on success.
//
// It exists because Renew cannot do it. core.Config.DeviceRenew returns two
// strings and the response carries three, so the seam's shape decides that a
// renewal through it silently drops the admission credential the account service
// minted alongside — over the SAME window, so both expire on the same instant
// and only one of them is ever renewed. A client that ran for longer than a
// credential lifetime would keep its entitlement current and let its network
// membership lapse, and the coordinator refusing it would be right.
//
// An embedder that knows where its device-credential directory is should wire
// RenewInto(dir) rather than Renew. Renew stays because it is the seam's exact
// shape and an embedder with no admission story should not have to supply a path
// to get it.
func (c *Client) RenewInto(dir string) func(context.Context, core.DeviceRenewRequest) (string, string, error) {
	return func(ctx context.Context, req core.DeviceRenewRequest) (string, string, error) {
		cred, issuerCert, admission, err := c.renew(ctx, req)
		if err != nil {
			return "", "", err
		}
		if admission != "" && dir != "" {
			if err := saveAdmission(dir, admission); err != nil {
				// Logged, never returned. core.maybeRenewDeviceCred reads a
				// non-nil error as "renewal failed, retry at the next check"
				// and would throw away a perfectly good device credential over
				// an admission file it could not write. The device credential
				// is what the connect gate checks; it goes back.
				c.logf("renewal: device credential renewed, but the admission credential could not be stored: %v", err)
			}
		}
		return cred, issuerCert, nil
	}
}

// renew is the exchange both renewal entry points share, returning all three
// values so the one that has somewhere to put the third can.
func (c *Client) renew(ctx context.Context, req core.DeviceRenewRequest) (cred, issuerCert, admission string, err error) {
	if req.Sign == nil {
		return "", "", "", fmt.Errorf("accountclient: renewal request carries no signer")
	}
	resp, err := c.issueCredential(ctx, signer{pub: req.DevicePub, sign: req.Sign})
	if err != nil {
		return "", "", "", err
	}
	if resp.Device == "" || resp.IssuerCert == "" {
		return "", "", "", fmt.Errorf("%w: /v1/credential returned an incomplete credential", ErrUnreachable)
	}
	return resp.Device, resp.IssuerCert, resp.Admission, nil
}
