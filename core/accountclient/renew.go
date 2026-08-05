package accountclient

import (
	"context"
	"fmt"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
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
// only where the result goes. Collect persists it, because a caller collecting a
// credential outside a running engine has nowhere else to put it. This returns
// it, because the seam's caller owns the store and writes all three together
// (core/devicestore.Store.Put) the moment this returns.
//
// There used to be a second entry point here — RenewInto(dir), which took a
// directory so it had somewhere to put the admission credential the seam could
// not carry. bacchus#166 removed the reason for it: the seam carries everything
// one response carries, so an embedder that wired the workaround now wires this
// and an embedder that never noticed the gap no longer has it.
//
// req.Current is deliberately NOT sent. The service resolves the account by
// public key and has no parameter for any of it; a field the service ignores is
// a field that will eventually be trusted by mistake. It is useful to the seam's
// CALLER, for the renewal-due check that decided to call at all.
func (c *Client) Renew(ctx context.Context, req core.DeviceRenewRequest) (devicestore.Credential, error) {
	if req.Sign == nil {
		return devicestore.Credential{}, fmt.Errorf("accountclient: renewal request carries no signer")
	}
	resp, err := c.issueCredential(ctx, signer{pub: req.DevicePub, sign: req.Sign})
	if err != nil {
		return devicestore.Credential{}, err
	}
	cred := resp.credential()
	if !cred.Presentable() {
		return devicestore.Credential{}, fmt.Errorf("%w: /v1/credential returned an incomplete credential", ErrUnreachable)
	}
	return cred, nil
}
