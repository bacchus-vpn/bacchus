# DTLS / WebRTC fingerprint randomization

Status: implemented (issue #14, ADR-0018; ICE/ServerHello residuals #49,
ADR-0022; handshake Random timestamp #57, amends ADR-0018). Lives in
[`core/dtls_fingerprint.go`](../../core/dtls_fingerprint.go) and
[`core/ice_fingerprint.go`](../../core/ice_fingerprint.go), behind the
`Transport` interface (ADR-0008); the pion patch for #57 lives in
[`third_party/pion-dtls/`](../../third_party/pion-dtls/).

## Problem

WebRTC (pion) buys NAT traversal, not camouflage (ADR-0008). Left alone, pion
emits a **stable, published DTLS ClientHello**: a fixed cipher-suite list in a
fixed order, a fixed extension order, and no GREASE. That shape is a
single-feature distinguisher — "this endpoint is pion-webrtc, not a browser
placing a real call."

This is not hypothetical. Russia fingerprinted and blocked Tor's Snowflake by
its (then fixed) DTLS handshake; Snowflake's response was to randomize it. The
mid-2026 censor auto-blocks nodes case-by-case on protocol signature — the same
mechanism that periodically knocks out AmneziaWG signatures. A static DTLS
fingerprint on our transport is one signature push away from fleet-wide
detection, which is why #14 was raised to **P0**.

Out of scope here: a full obfuscated transport. A DataChannel bulk tunnel does
not, over time, look like a real video call regardless of how the handshake is
shaped — that traffic-analysis gap is the job of the second transport (#16), not
this change. This change removes the *static-signature* class of detection.

## Approach

Reshape the DTLS ClientHello to look like a mainstream browser's WebRTC
handshake instead of pion's default, using two knobs pion already exposes and
plumbs into `pion/dtls`:

- `SettingEngine.SetDTLSCipherSuites` / `SetDTLSEllipticCurves` — change what we
  actually negotiate.
- `SettingEngine.SetDTLSClientHelloMessageHook` — rewrite the fully built
  ClientHello immediately before it is marshalled. **The rewritten bytes are what
  pion hashes into the handshake transcript** (`pion/dtls` pushes the marshalled
  hooked message to its handshake cache), so both peers stay in agreement and the
  Finished MAC checks out. This is the same extension point Snowflake uses.

Two profiles:

- **chrome** — GREASE (RFC 8701) in the cipher list, the supported-groups list,
  and the extension list (a leading empty GREASE extension, a trailing one-byte
  one), plus a **per-connection extension permutation**. Chrome genuinely
  permutes its ClientHello extensions (since v110) and sends fresh GREASE per
  connection, so this per-connection variation is *authentic browser behavior*,
  not an anomaly — and it means there is no single static order to fingerprint.
- **firefox** — no GREASE, a **fixed** browser-like cipher order and extension
  order. A stable, distinct-from-pion shape.

Mode is chosen by `Config.DTLSFingerprint` (`-dtls-fp` on `cmd/node`):
`auto` (default; each node picks chrome or firefox at startup), `chrome`,
`firefox`, or `off` (pion default — debugging/interop only). `auto` gives the
fleet a *mix* of shapes rather than one uniform "our-VPN" fingerprint.

## Why this is safe between two of our own nodes

Every value we inject for camouflage is ignored by a conforming peer, and both
ends are our own pion nodes:

- **Extra cipher IDs** (GREASE + browser suites pion doesn't implement) are
  parsed as opaque `uint16`s; the peer picks the first suite it *does* support.
  We keep the real `ECDHE_ECDSA` GCM suite pion negotiates in the advertised
  list, so a mutually supported suite always exists. (pion authenticates with a
  self-signed ECDSA P-256 cert, so the negotiated suite is always
  `ECDHE_ECDSA_*`; RSA suites are advertised for shape only.)
- **GREASE / unknown extensions** hit the `default:` no-op in pion's
  `extension.Unmarshal`, which skips them by their declared length — no error.
- **A GREASE supported-group** is filtered out on parse (pion's supported-groups
  unmarshal keeps only known curves) — the peer still negotiates X25519.

In every case the peer hashes the **raw received bytes**, not the reparsed
struct, so dropping GREASE on parse never desyncs the transcript. This is
covered by `TestPeerToleratesRewrittenExtensions` and proven end to end by
`TestWebRTCHandshakeAcrossFingerprints` (a real pion↔pion handshake over
loopback ICE, including a mixed chrome↔firefox pairing).

## Before / after (measured)

Captured from the ClientHello builder in tests (`0x…` = IANA code points; ext
list = extension types in wire order):

```
BEFORE (pion default)
  ciphers   c02b c02f cca9 cca8 c00a c014 c02c c030            (8, fixed order)
  ext order 000a 000b ff01 0017 0010                           (fixed, no GREASE)
  ~93 bytes

AFTER chrome (per connection; one sample)
  ciphers   1a1a c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035
            └GREASE, then browser order
  ext order 9a9a 000a ff01 0010 000b 0017 fafa
            └GREASE …permuted… GREASE
  ~114 bytes

AFTER firefox (stable)
  ciphers   c02b c02f cca9 cca8 c02c c030 c013 c014 009c 009d 002f 0035 000a
  ext order 0017 ff01 000a 000b 0010                           (fixed browser order)
  ~103 bytes
```

Both profiles change the cipher list *and* the extension order away from pion's
default, so a rule written against the "pion default" cipher/extension signature
no longer matches. Chrome additionally varies per connection.

## STUN / ICE review

Scope item 2 of #14 was to review STUN/ICE for obvious tells. Findings:

- **No `SOFTWARE` tell.** pion/ice does not attach a `SOFTWARE` attribute to its
  STUN Binding requests, and the requests are otherwise RFC 5389/8445-standard
  (USERNAME, MESSAGE-INTEGRITY, FINGERPRINT) — the same shape a browser sends and
  the same our coordinator STUN already speaks. No pion string leaks here.
- **Residual tells, deferred from #14 and since resolved in #49 (ADR-0022):** the
  ICE ufrag/pwd shape, raw-IP vs `.local` host candidates, and the un-reshaped
  DTLS ServerHello. Documented in
  [ICE / ServerHello residuals](#ice--serverhello-residuals-issue-49) below.

## ICE / ServerHello residuals (issue #49)

The three tells from the review above are handled in
[`core/ice_fingerprint.go`](../../core/ice_fingerprint.go) and a ServerHello hook
in `core/dtls_fingerprint.go` (ADR-0022).

- **Per-connection ICE credentials.** pion's only credential knob,
  `SetICECredentials`, is global, and the transport shared one `webrtc.API` — so
  using it would have stamped a *single* ufrag/pwd pair across every connection,
  a stronger and stable fingerprint, the opposite of the goal. The transport now
  builds a fresh `SettingEngine` + `API` per `PeerConnection` (`newPC`) and
  installs freshly generated credentials each time: the uniform Chrome/libwebrtc
  shape (ufrag=4, pwd=24) over the full base64 ice-char set, from `crypto/rand`
  (the pwd keys the STUN MESSAGE-INTEGRITY, so it must be unpredictable, not
  camouflage). Applied only when a DTLS profile is active; `off` keeps pion's
  16/32 letters-only default. The profile is still resolved once at startup, so a
  node keeps one consistent browser identity.

- **DTLS ServerHello.** `SetDTLSServerHelloMessageHook` reorders the answerer's
  extensions into a browser-plausible order — a pure reorder (no GREASE, no
  permutation: a server does neither), transcript-safe for the same reason the
  ClientHello rewrite is. The lightest of the three (the ServerHello selects one
  cipher and a handful of extensions), but it clears the last fixed-order tell on
  the answer side.

- **mDNS host candidates — behind `-ice-mdns`, default off.** When enabled, host
  candidates become `.local` mDNS names instead of raw private IPs
  (`SetICEMulticastDNSMode(QueryAndGather)`). Off by default: `.local` does not
  resolve between peers on different networks (mDNS is link-local), so for
  internet peers it is a connectivity trade-off rather than a free win — the
  working path is carried by server-reflexive/relay candidates regardless — and
  mDNS multicast interacts with the full-device TUN client and the fail-closed
  kill-switch (ADR-0014). The flag ships the capability pending that validation.

### Handshake Random timestamp (issue #57)

Found while doing #49: pion stamps a real `gmt_unix_time` into the first 4
bytes of the 32-byte handshake Random in *both* the ClientHello and
ServerHello, where modern browsers send 32 fully random bytes. It **cannot**
be fixed through the message hooks above — they change only the bytes of the
message pion marshals onto the wire, while pion separately hashes
`state.localRandom` straight into the master-secret PRF (`state.go`),
completely bypassing whatever a hook returns. Overwriting the timestamp only
in the hook would make our own wire bytes look clean while our own key
derivation still used the real one — and the peer, having parsed our
(hook-clean) wire bytes as its `remoteRandom`, would derive a master secret
our side never matches. Verified this is a real trap, not a hypothetical one:
simulating exactly that mistake (strip the timestamp in
`rewriteClientHello` only, leave pion's `Populate()` untouched) reliably broke
the handshake in testing before this fix shipped.

The fix instead patches pion itself, since `state.localRandom` has to carry no
timestamp in the first place for the wire value and the PRF input to agree — a
hook operating one level up can only ever see one side of that split. A
minimal vendored fork at
[`third_party/pion-dtls/`](../../third_party/pion-dtls/) (only the packages
bacchus actually imports, wired in via `go.mod`'s
`replace github.com/pion/dtls/v3`) changes
`(*handshake.Random).Populate()` to fill all 32 bytes with `crypto/rand` and
derive `GMTUnixTime` from 4 of them instead of the real clock. The
`GMTUnixTime`/`RandomBytes` struct shape and `MarshalFixed`/`UnmarshalFixed`
are untouched, so every existing caller keeps working, and the diff from
upstream is one function. Both `flight0handler.go` (ServerHello) and
`flight1handler.go` (ClientHello) call this same `Populate()`, so the one
patch covers both sides. Details and the re-sync procedure for a future pion
version bump are in
[`third_party/pion-dtls/PATCHES.md`](../../third_party/pion-dtls/PATCHES.md);
the decision is recorded as an in-place update to ADR-0018 (no new ADR number
— a follow-up to an existing decision, not a new one).

## Residual risk

- **Traffic analysis over time.** Handshake shape ≠ flow shape. A sustained
  DataChannel tunnel has bulk-transfer timing/volume unlike a real WebRTC call.
  Defeating that is the second transport's job (#16), not this change.
- **Imperfect mimicry.** The profiles are browser-*informed*, not byte-exact
  clones of a specific browser build (we don't ship captured ClientHellos). The
  firm guarantee is "no longer the static pion signature" and "shaped toward
  common browser handshakes," not "indistinguishable from Chrome N." The `auto`
  mix and Chrome's authentic per-connection permutation are what make a single
  blocking rule ineffective.
- **The ICE/ServerHello residuals** are resolved (#49, ADR-0022), and so is the
  handshake Random `gmt_unix_time` (#57, see above) — all four tells found
  during the #14/#49 review are now closed.

## Testing

`core/dtls_fingerprint_test.go`:

- Rewrite breaks the static pion cipher/extension signature; the result still
  marshals to valid wire bytes; a pion peer tolerates the GREASE/raw injections
  (known extensions survive, GREASE is skipped).
- Chrome varies per connection; Firefox is stable and ungreased; both preserve
  every negotiation-relevant extension.
- GREASE values are always RFC 8701 code points; the two bracket extensions
  differ.
- **Real pion↔pion handshake over loopback ICE** completes and round-trips a
  stream for chrome↔chrome, firefox↔firefox, chrome↔firefox, and off↔off; a
  concurrent variant runs several sessions through one shared transport pair
  (the hook keeps no shared mutable state, so it needs no lock). Because each
  session now builds its own API, this also exercises the per-connection ICE
  credentials and the ServerHello hook end to end.

`core/ice_fingerprint_test.go` (issue #49):

- Browser ICE credentials have the libwebrtc shape (4/24), draw from the full
  ice-char set (a long sample is wider than pion's letters-only alphabet), clear
  pion's insufficient-bits floor, and are fresh per call.
- Two `PeerConnection`s from one transport advertise *different* browser-shaped
  ufrag/pwd in their offer SDP (per-connection, not one reused pair); `off` keeps
  pion's 16/32 default.
- The ServerHello reshape reorders extensions to the browser order while
  preserving the whole set; a transport with mDNS enabled still builds a
  `PeerConnection`.

`core/dtls_fingerprint_test.go` (issue #57):

- `TestHandshakeRandomHasNoTimestamp` calls the patched
  `(*handshake.Random).Populate()` directly and checks the first 4 bytes of
  its wire form neither land near real wall-clock time nor advance by
  ~elapsed-seconds between two draws taken a real ~1.1s apart — the property
  a disguised `gmt_unix_time` would have and uniform randomness (bar
  astronomically unlikely chance) will not. One method covers both the
  ClientHello and ServerHello sides, since `flight0handler.go` and
  `flight1handler.go` both call it.
- `TestHandshakeCompletesAfterRandomPatch` is the regression guard against the
  hook-only mistake described above: a real WebRTC handshake, run twice with a
  real time gap. A master-secret desync fails the handshake outright, so a
  passing run proves the fix lives in `Populate()` itself and not a wire
  rewrite.
