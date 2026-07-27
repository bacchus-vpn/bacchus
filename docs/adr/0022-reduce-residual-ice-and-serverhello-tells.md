# 22. Reduce residual WebRTC ICE and DTLS-ServerHello tells

- Status: accepted
- Date: 2026-07-03

## Context

ADR-0018 (issue #14) reshaped the DTLS **ClientHello** — the richest fingerprint
— but explicitly left three residual "pion-ish" tells, listed in its own
Consequences and filed as issue #49:

1. **ICE ufrag/pwd shape.** pion draws a fixed ufrag=16 / pwd=32 from a
   letters-only alphabet; a browser draws a short ufrag and a pwd from the full
   RFC 5245 ice-char set (letters, digits, `+`, `/`).
2. **Host candidates.** pion advertises raw private-IP host candidates; browsers
   publish `.local` mDNS names, hiding the local IP.
3. **DTLS ServerHello.** Only the ClientHello was hooked; the answerer's
   ServerHello still emits pion's fixed extension order.

The same detection class motivates clearing them: the mid-2026 censor auto-blocks
nodes case-by-case on protocol signature, so any stable shape is a maintenance
liability. None is individually fleet-critical the way the static ClientHello
was, but together they keep a residual pion shape in the ICE/DTLS exchange.

A constraint shaped the design. pion exposes only a **global**
`SetICECredentials`, and the transport shared a single `webrtc.API`, so setting
credentials there would reuse one ufrag/pwd pair across every connection the node
makes — a *stronger, stable* fingerprint than pion's default, the opposite of the
goal. Per-connection credentials therefore require a per-connection API.

## Decision

Address the two low-risk tells and gate the connectivity-sensitive one:

1. **Per-connection browser ICE credentials.** Build a fresh `SettingEngine` +
   `webrtc.API` per `PeerConnection` (in `newPC`), and install freshly generated
   credentials on each: the uniform Chrome/libwebrtc shape (ufrag=4, pwd=24) over
   the base64 ice-char set, from `crypto/rand`. libwebrtc is the dominant WebRTC
   engine in the wild, so it is the most common real shape to blend with. The pwd
   is a real security value — it keys the STUN MESSAGE-INTEGRITY — so it must be
   cryptographically random, not camouflage. Applied only when a DTLS fingerprint
   profile is active; `off` keeps pion's defaults. The profile itself is still
   resolved once at startup, so a node keeps one consistent browser identity.

2. **DTLS ServerHello reshape.** Install `SetDTLSServerHelloMessageHook` and
   reorder the answerer's extensions into a browser-plausible order — a pure
   reorder, transcript-safe the same way the ClientHello hook is (both peers hash
   the marshalled hooked bytes). No GREASE or permutation: GREASE in a ServerHello
   is a client-side tolerance trick browsers do not use as a server, and a server
   does not permute. Lower signal than the ClientHello, but it clears the last
   fixed-order tell on the answer side.

3. **mDNS host candidates — behind a flag, default off.** `Config.ICEmDNS` /
   `-ice-mdns`. When enabled, pion emits `.local` mDNS host candidates instead of
   raw private IPs (`SetICEMulticastDNSMode(QueryAndGather)`). **Off by default:**
   `.local` candidates do not resolve between peers on different networks (mDNS is
   link-local), so for internet peers this is a connectivity trade-off, not a
   free win — the working path is carried by server-reflexive/relay candidates
   regardless — and mDNS multicast interacts with the full-device TUN client and
   the fail-closed kill-switch (ADR-0014) in ways that need their own validation.
   The flag ships the capability and this decision record now; turning it on is a
   deployment choice pending that testing.

## Consequences

- The credential and ServerHello axes of ADR-0018's residual shape are cleared;
  ICE credentials now vary per connection and match a browser shape, and the
  ServerHello no longer carries pion's fixed extension order. mDNS is available
  but off. Mechanism, before/after, and tests are in
  [dtls-fingerprint.md](../design/dtls-fingerprint.md).
- Building an API per dial/accept costs a little more than the previous shared
  API, but a DataChannel-only API is cheap to assemble, and it is what makes
  per-connection credentials possible at all.
- **Newly found, deliberately not fixed here:** pion stamps a real
  `gmt_unix_time` into the first 4 bytes of the handshake Random in *both* hellos,
  whereas modern browsers send 32 fully random bytes. It cannot be fixed via the
  message hooks — they change only the wire bytes, while `state.localRandom` still
  drives key derivation, so overwriting the timestamp there would desync the
  master secret. A correct fix needs a small pion patch (or `WithHelloRandom`-style
  support upstream); tracked as issue #57 rather than half-fixed.
- Same caveat as ADR-0018: these shapes are browser-*informed*, not byte-exact
  clones. A shape that itself gets fingerprinted is a data change (a length, an
  order), not a re-architecture. Traffic-analysis resistance is still out of scope
  and remains the second transport's job (#16).
