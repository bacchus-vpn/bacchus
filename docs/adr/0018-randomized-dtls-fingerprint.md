# 18. Randomize the WebRTC DTLS ClientHello fingerprint

- Status: accepted
- Date: 2026-07-03

## Context

WebRTC is kept for NAT traversal, not camouflage (ADR-0008). By default pion
emits a stable, published DTLS ClientHello — a fixed cipher-suite list and
extension order, no GREASE — which is a single-feature distinguisher for "this
is pion-webrtc, not a browser." Russia fingerprinted and blocked Snowflake by
exactly this kind of static DTLS signature, and the mid-2026 censor auto-blocks
nodes case-by-case on protocol signature. A static fingerprint on our transport
is one signature push from fleet-wide detection; ADR-0008 already flagged that
WebRTC's DTLS fingerprint "must be actively maintained (fingerprint
randomization) rather than treated as free," and issue #14 was raised to P0.

Full obfuscation is explicitly *not* the goal here — a DataChannel bulk tunnel
still doesn't match a real call's traffic shape over time. That is the second
transport's job (#16). This decision addresses only the static-signature class.

## Decision

Reshape the DTLS ClientHello inside the WebRTC transport to resemble a
mainstream browser's, via pion's `SetDTLSClientHelloMessageHook` (plus
`SetDTLSCipherSuites` / `SetDTLSEllipticCurves`). pion hashes the rewritten bytes
into the handshake transcript, so the change is transparent to the handshake
between two of our nodes.

Two browser-informed profiles: **chrome** (RFC 8701 GREASE in ciphers, groups,
and extensions, plus per-connection extension permutation — both authentic
Chrome behaviors) and **firefox** (no GREASE, fixed browser-like cipher and
extension order). `Config.DTLSFingerprint` / `-dtls-fp` selects `auto` (default;
each node picks a profile at startup, so the fleet is a *mix*), `chrome`,
`firefox`, or `off` (pion default, for debugging/interop only). Default behavior
is on.

Safety between our own nodes rests on conforming-peer tolerance: injected GREASE
and browser-only cipher IDs are advertised but never selected (the real
`ECDHE_ECDSA` suite is always retained), GREASE/unknown extensions are skipped by
pion's parser, and a GREASE supported-group is filtered out on parse — while the
peer hashes the raw received bytes, so nothing desyncs the transcript.

## Consequences

- No single static rule matches our WebRTC handshake: both profiles differ from
  the pion default in cipher list and extension order, and `auto` + Chrome's
  per-connection permutation remove any one stable signature. Before/after is
  documented and tested in [dtls-fingerprint.md](../design/dtls-fingerprint.md).
- This is mitigation, not a guarantee of indistinguishability. The profiles are
  browser-*informed*, not byte-exact clones, and residual ICE tells remain
  (fixed ufrag/pwd length, raw-IP host candidates instead of mDNS, an
  un-reshaped DTLS ServerHello) — reviewed and filed as follow-ups, not fixed
  here.

  > **Update (2026-07-04):** the ICE credential shape, host candidates, and
  > ServerHello extension order were resolved by #49/ADR-0022. A fourth,
  > subtler residual — found *while doing* #49, so not listed above at the
  > time — stayed open as issue #57: pion's `Random.Populate()` stamps a real
  > `gmt_unix_time` into the first 4 bytes of the 32-byte handshake `Random`,
  > in *both* the ClientHello and the ServerHello, where modern browsers send
  > 32 fully random bytes. It is now closed, but it could not be reached the
  > way this ADR reaches the cipher list and extension order. This ADR's
  > `SetDTLSClientHelloMessageHook`/`SetDTLSServerHelloMessageHook` only change
  > the bytes of the *message pion marshals onto the wire* — safe there
  > because pion also hashes exactly those rewritten bytes into the handshake
  > transcript, so both peers agree. The handshake `Random` is different: pion
  > separately hashes `state.localRandom` straight into the master-secret PRF
  > (`state.go`), completely bypassing whatever a hook returns. Stripping the
  > timestamp only inside the hook would have made our own wire bytes look
  > clean while our own key derivation still used the real timestamp — and the
  > peer, having parsed our clean wire bytes as its `remoteRandom`, would
  > derive a master secret our side never matches. Same mistake either
  > direction: a client-side-only or server-side-only hook fix would clean the
  > bytes we send but never touch the `state.localRandom` our own side reads
  > back for its own PRF input.
  >
  > The fix instead patches pion itself, since `state.localRandom` has to
  > carry no timestamp in the first place for the wire value and the PRF input
  > to agree. A minimal vendored fork (`third_party/pion-dtls/`, wired in via
  > `go.mod`'s `replace github.com/pion/dtls/v3`, containing only the packages
  > bacchus imports) changes `Random.Populate()` to fill all 32 bytes with
  > `crypto/rand` and derive `GMTUnixTime` from 4 of them, rather than the real
  > clock — the existing `GMTUnixTime`/`RandomBytes` struct shape and
  > `MarshalFixed`/`UnmarshalFixed` are untouched, so every caller keeps
  > working and the upstream diff is one function. Both flight0handler.go
  > (ServerHello) and flight1handler.go (ClientHello) call this same method, so
  > the one patch covers both sides. `TestHandshakeRandomHasNoTimestamp`
  > (`core/dtls_fingerprint_test.go`) proves the tell is gone;
  > `TestHandshakeCompletesAfterRandomPatch` is the regression guard against
  > the hook-only mistake above — confirmed, before shipping, that it actually
  > fails that way when only the wire hook strips the timestamp.
- Traffic-analysis resistance is unchanged and out of scope; it depends on the
  second transport (#16) and the transport pool (#15), consistent with ADR-0008
  ("resistance comes from the pool, not any single transport").
- The censorship arms race is ongoing: a profile is a maintenance surface. If a
  profile itself gets fingerprinted, it is updated the way Snowflake and
  AmneziaWG update theirs — the hook makes that a data change, not a re-architecture.
