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
