// Package admission enforces network membership in cryptography: who may join
// the Bacchus network at all, independent of how the code is licensed.
//
// Nothing in the wire protocol otherwise stops an unauthorized client or a
// hostile node from joining — anyone who can reach the coordinator and speak
// the protocol can register as a relay/exit (and then see traffic routed
// through them) or connect as a client (and enumerate the network). That is an
// authentication problem, not a licensing one: a permissive or a proprietary
// license does nothing here (issue #42). This package is the piece that
// actually enforces membership.
//
// A Credential is a signed statement by the operator's admission authority —
// the same trust root that signs releases on the forced-update channel
// (ADR-0015) — that a Subject may act in some Roles for a validity window. It
// is signed with Sign, carried opaquely on the coordinator wire (Encode), and
// checked with a Verifier at the one place that already gates matchmaking: the
// coordinator's register (nodes) and list/connect (clients) handlers.
//
// A Verifier anchors a SET of authorities, each scoped to the roles it may admit
// (issue #64, ADR-0047), because two structurally different issuers mint this
// format: the operator by hand (cmd/admission-issue, relay/exit credentials
// bound to a node id — low volume, offline, deliberate) and the account service
// automatically (client credentials — bearer, short-lived, reissued on every
// renewal, always online). With one anchor those two would have to share a
// private key, putting the credentials that admit a host as forwarding
// infrastructure behind the busiest and most exposed issuer. Anchoring the
// account service for RoleClient alone closes that: the roles inside a
// credential are chosen by whoever holds the signing key, but the roles an
// authority may admit are not reachable from any signing key at all.
//
// The set is filtered by the requested role BEFORE any signature is verified, so
// a client authority's signature is never even a candidate for an exit check —
// the scoping is structural rather than a check that follows verification and
// could be reordered away. A single anchored authority trusted for every role
// (NewVerifier) is the coordinator's pre-#64 behaviour exactly, and remains the
// client's shape: it needs only the authority that mints exits.
//
// The signature envelope mirrors core/coldstart byte-for-byte — canonical JSON
// followed by a fixed-length ed25519 signature — so the coordinator, a small
// dependency-light binary, can verify credentials exactly like it already
// verifies snapshots, without importing the transport stack. Like
// core/coldstart and core/handshake, this package depends only on the standard
// library.
//
// Threat-model note (docs/threat-model.md): node admission is what stops the
// "malicious node operator" (a censor joining as a volunteer exit to observe
// traffic, or Sybil-flooding the mesh); client admission is what stops the
// censor "posing as an ordinary user to enumerate the network." It is also what
// prevents a code fork from simply pointing at and joining our live network.
package admission
