// Package coldstart implements the cold-start rendezvous bootstrap: a
// per-user-secret-authenticated fetch of a coordinator-signed directory
// snapshot, carried on a STUN-shaped UDP exchange (RFC 5389 message framing
// and attribute layout, reusing the standard USERNAME/MESSAGE-INTEGRITY
// attribute *shape* for credential-bearing requests so the wire traffic is
// indistinguishable, to a shape-based observer, from a real ICE connectivity
// check).
//
// This resolves open question #3 of docs/design/rendezvous-cold-start.md: a
// request without a valid per-user secret gets exactly the same plain
// Binding Success Response a public STUN server would send (principle #4,
// "authenticated first packet" — no proxy-shaped response leaks to a
// prober). Only a request that authenticates gets the signed snapshot
// attribute appended to that same response.
//
// See docs/design/bootstrap-protocol.md for the concrete byte layout and
// docs/adr/0013-bootstrap-wire-protocol.md for the decision record.
package coldstart
