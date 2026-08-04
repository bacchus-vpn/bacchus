// Package accountclient speaks the three account-service verbs a Bacchus client
// needs to obtain and keep a device credential: POST /v1/challenge, POST
// /v1/enroll, and POST /v1/credential.
//
// It is the first thing in this repository that dials the account service, and
// that is a cost ADR-0046 §6 priced before it was paid. Everything about the
// device-credential chain up to now has been offline: core/devicecred verifies,
// core/devicestore persists, core/devicecred_connect.go presents. None of it
// contacts anything. Enrollment cannot be done that way — a claim code has to be
// redeemed somewhere — so this package exists, in a package of its own, imported
// by embedders and by nothing in core. ADR-0056 records why that boundary is
// where it is.
//
// # What it is not
//
// It is not a general client for the account service's surface. Six of the nine
// client verbs are absent: the three sibling verbs, /v1/recover, /v1/device/revoke,
// and /v1/issuer-cert. Enrollment and renewal both return the issuer cert
// alongside the credential precisely so a client never needs a second call for
// it, so the fetch-the-cert verb has no caller here; the rest belong to flows
// this repository does not implement. A verb with no caller is a verb whose first
// caller inherits an untested implementation.
//
// # The one call that cannot be retried
//
// POST /v1/enroll spends the claim code and the challenge, both single-use. A
// retry after a response the caller failed to read answers claim_rejected and
// CANNOT return the credential — the account service erases a spent claim hash
// rather than flagging it, so there is nothing left to match against. A client
// that retries this call naively destroys a paying customer's access with no way
// back.
//
// So Enroll sends it exactly once, and the recovery path for an unread response
// is POST /v1/credential with the device key the caller still holds. Collect is
// that call, Enroll uses it automatically on an ambiguous outcome, and the
// reasoning about which outcomes qualify is in enroll.go rather than here
// because it is the subtle part.
//
// # What is pinned, and why it cannot come from the service
//
// Two values reach this package from configuration and never from a response:
// the audience string an assertion binds to, and the TLS identity of the server.
//
// The audience is what makes an assertion mean "for this service and no other".
// A caller that learned it from the same response it is about to sign against
// would let the responder choose the binding, which is the assertion-harvesting
// failure the wire format's audience field exists to prevent, one layer out. The
// service's own transport specification forbids putting it in a response, and
// this package would have nowhere to read it from even if it were there.
//
// The TLS identity is pinned because the account service is reached through a
// camouflaged front under a name chosen to be unremarkable, and requiring a
// publicly-trusted certificate for a name a censor is watching is a reachability
// liability rather than a security gain. Config.ServerCAFile is therefore
// REQUIRED and the public root pool is never consulted: see New.
//
// # Direction of failure
//
// Every error here is legible and none of them is fatal to connecting. A device
// that cannot reach this service keeps whatever credential it already holds until
// that credential expires, and a coordinator with its gate on then refuses the
// connect with its own reason. That is the designed degradation, not a gap: the
// tolerable outage is the credential's lifetime less the renewal margin, and it
// is an availability budget rather than an accident.
package accountclient
