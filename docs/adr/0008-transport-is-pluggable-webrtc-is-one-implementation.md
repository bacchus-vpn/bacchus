# 8. Transport is pluggable; WebRTC is one implementation, not the foundation

- Status: accepted
- Date: 2026-07-02

## Context

Early design notes (`own-stack.md`) treated pion/WebRTC as camouflage as well
as NAT traversal — reasoning that DTLS "looks like WebRTC media" and would
therefore blend in. That assumption doesn't hold as a durable property:
Snowflake uses the same approach and was fingerprinted and blocked in
Russia. Testing also shows no single transport works everywhere in Russia
— censorship is decentralized and enforced per-operator (see
`docs/threat-model.md`).

## Decision

`core/` defines a `Transport` interface. WebRTC (pion) is the first
implementation, valued for its built-in ICE/STUN/TURN NAT traversal, not
trusted as camouflage by default — its DTLS fingerprint is randomized
separately (tracked in issue #14). Additional transports (starting with an
obfuscated UDP / Reality-XHTTP variant, issue #16) implement the same
interface and run behind a client-side transport pool with automatic
per-user failover (issue #15).

## Consequences

- Adding or swapping a transport does not require re-architecting the node
  or client — it implements `Transport` and joins the pool.
- No transport is assumed censorship-resistant on its own; resistance comes
  from the pool (coverage = union of many partial transports), not from any
  single transport's properties.
- WebRTC's NAT-traversal value (ICE/STUN/TURN, CGNAT hole-punching) is kept;
  its camouflage value is not assumed and must be actively maintained
  (fingerprint randomization) rather than treated as free.
