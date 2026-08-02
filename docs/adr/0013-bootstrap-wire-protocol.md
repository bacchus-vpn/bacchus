# 13. Cold-start bootstrap wire protocol

- Status: accepted
- Date: 2026-07-03

## Context

ADR-0012 decided cold-start rendezvous blends with STUN/WebRTC and is
authenticated by per-user secrets, but left the concrete wire scheme as
design doc open question #3. `old #18`'s acceptance criterion — a
documented, tested bootstrap a cold client completes with no operator
pre-screening — needs a real implementation of that scheme, not just the
design.

## Decision

1. **Reuse RFC 5389 STUN framing and standard attribute type codes**
   (`USERNAME`, `MESSAGE-INTEGRITY`, `XOR-MAPPED-ADDRESS`, `FINGERPRINT`) for
   shape-compatibility with real ICE connectivity checks, without
   implementing RFC 5389 in full (no SASLprep, no error responses, no
   third-party interop goal — see `docs/design/bootstrap-protocol.md`).
2. **Single round trip.** One authenticated Binding Request, one Binding
   Success Response. The response is byte-identical whether or not the
   request authenticates, except for one added comprehension-optional
   attribute (`SNAPSHOT`, `0xC001`) that only appears when
   `MESSAGE-INTEGRITY` validates. This is `core/coldstart`'s answer to
   design principle #4 (authenticated first packet, no proxy-shaped
   response to an unauthenticated prober).
3. **Snapshot = JSON + trailing Ed25519 signature**, no length prefix needed
   (fixed 64-byte signature size). Coordinator re-signs from its live
   exit/relay registry every 10s with a 5-minute expiry.
4. **Per-user secret = 8-byte ID (the wire `USERNAME`, hex) + 32-byte HMAC
   key**, minted by a new operator tool `cmd/coldstart-issue`, stored in a
   flat JSON file the coordinator hot-reloads every 30s (no restart to add
   a user).
5. **Invite = an unsigned, packed, copy-pasteable string** (`bacchus1:` +
   base64url of `version‖secretID‖secret‖coordinator-pubkey‖coordinator-addr`),
   not a signed bundle: the secret itself is the thing that must stay
   confidential, and only becomes useful against a coordinator that already
   knows it, so a bare (unsigned) invite carries no forgeable authority — its
   integrity comes from the out-of-band channel it travels over, not
   cryptographic signing on the invite itself.
6. **The bootstrap listener is a second, independent UDP socket**
   (`cmd/coordinator -bootstrap-addr`, default `:3479`), not literally the
   same process/port as the STUN/TURN server (`cmd/turn`, pion/turn). True
   same-port blending would require hooking pion/turn's message pipeline for
   a custom attribute, which it doesn't expose; tracked as a follow-on
   issue rather than blocking this implementation.

## Consequences

- `old #18`'s acceptance criterion is met: `core/coldstart` is a tested,
  documented, per-user-secret-authenticated fetch of a coordinator-signed
  snapshot, runnable end-to-end via `cmd/coldstart-issue` +
  `cmd/coldstart-bootstrap` (verified live, loopback, real OS UDP sockets
  between separate processes, 2026-07-03).
- The wire protocol is intentionally not RFC 5389-complete; it must not be
  treated as interoperable with third-party STUN/ICE tooling.
- Running bootstrap on a separate port from the real STUN/TURN service is a
  known gap versus the design's "blend with our own STUN server" goal — a
  DPI system keying on port number as well as shape would still distinguish
  it. Follow-on issue tracks closing this gap.

  > **Update (2026-07-03):** closed by [ADR-0017](0017-blend-bootstrap-onto-shared-stun-turn-port.md)
  > (issue #30) — a socket-level demux now blends bootstrap onto the same UDP
  > port/process as the real STUN/TURN server. Point 6 above and this bullet
  > describe the original, superseded arrangement; kept for the historical
  > record rather than rewritten.
- The Binding Success Response did not carry `FINGERPRINT`, unlike pion/turn's
  own — invisible while bootstrap ran on its own port, but a live shape-parity
  gap once ADR-0017 put both response shapes on the same one, observable by
  any censor doing shape analysis on that port.

  > **Update (2026-07-04):** closed by issue #46 — `buildResponse` now always
  > appends `FINGERPRINT` as the last attribute, reusing the same two-pass
  > length-then-hash construction `buildRequest` already used for its own
  > `FINGERPRINT`. Pinned byte-for-byte against pion/stun's own construction
  > (not a hand-rolled reimplementation of it) by
  > `core/coldstart/wire_test.go`'s `TestBuildResponseMatchesPionTurnShape`.
  > See `docs/design/bootstrap-protocol.md` §3.
- The secrets file has no vouch/trust gating yet; every operator-issued
  secret is equally trusted, appropriate only for the design doc's curated
  private-seed launch phase (§5.8), not the eventual public-front-door
  phase.
