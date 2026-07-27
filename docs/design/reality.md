# Reality transport — camouflage design notes

Design notes for the `reality` transport (`core/transport_reality.go`,
`core/reality_auth.go`, `core/reality_clienthello.go`). Decisions live in the ADRs;
this file is the implementation-level picture and the running list of residual tells.

- ADR-0024 — the transport itself (TCP :443, camouflage TLS, session model).
- ADR-0027 — the active-probing response (reverse-proxy a failed handshake).
- ADR-0032 — authenticate in the ClientHello; fork unauthenticated peers to the
  real origin (this is what removes the self-signed certificate tell).

## What an observer sees

A reality session is a set of ordinary-looking HTTPS connections to an exit's :443.
The censor's tools against it are two:

- **Passive DPI** — inspect handshakes in flight. The ClientHello is a real
  Chrome fingerprint (uTLS). The certificate is *not* a passive signal on the
  terminate path: in TLS 1.3 it rides the encrypted handshake (RFC 8446 §4.4), so
  a passive observer never sees it. It is camouflage only for a peer that actually
  terminates — our own client; a stranger is spliced to the real origin — which is
  why stealing the origin's bytes below is faithfulness, not a passive-DPI defence.
- **Active probing** — connect to the suspected endpoint and classify by its
  response. This is how RU/CN confirm and then kill an endpoint, and it is the axis
  ADR-0027 and ADR-0032 are built around.

## The ClientHello fork (ADR-0032)

The exit cannot tell a client from a prober after it has terminated TLS — by then
it has already presented a certificate. So it decides **before** terminating,
reading the first TLS record off the wire and parsing three fields from the
ClientHello (`peekClientHello`): the random, the `legacy_session_id`, and the
X25519 key share. Everything read is buffered for replay.

```
inbound :443
   │  peek ClientHello (no TLS termination yet)
   ▼
 authenticated?  ── no ─▶ raw-splice the whole TCP conn to the impersonated origin
   │ yes                    (prober/browser completes TLS *against the origin*;
   ▼                         origin unreachable → hold-and-drain; "off" → close)
 terminate TLS locally (mimic cert), read inner handshake
   │
   ├─ known token ─▶ attach the stream to its session   (normal client path)
   └─ bad/unknown ─▶ plaintext bridge to the origin      (ADR-0027, preserved)
```

The raw splice is the important half: a prober is unauthenticated by construction,
so it is spliced to the origin and validates the origin's genuine chain. The
plaintext bridge from ADR-0027 is preserved as the post-termination fallback for an
authenticated peer whose inner handshake fails (a replay, a client bug).

## Authenticating inside the ClientHello

The signal rides in the 32-byte `legacy_session_id`, where a TLS 1.3 client in
compatibility mode already sends 32 random-looking bytes.

- The exit has a static X25519 key pair, generated per listener. Its **public** half
  travels in the `answer` frame (`realityAnswer.Pub`), which is already delivered
  over the coordinator-authenticated channel — so no separate key distribution, and
  the key may rotate on restart.
- The client (`realityClientHandshake`) builds a Chrome uTLS ClientHello, reads the
  ephemeral X25519 key it put in the key share, computes
  `secret = ECDH(clientEphemeral, exitStatic)`, derives an AES-GCM key and nonce
  from `HKDF(secret, salt = ClientHello.random)`, seals a coarse timestamp with the
  **random as additional data**, and writes the 32-byte result as the session id.
- The exit (`authenticated`) recomputes `secret = ECDH(exitStatic, clientKeyShare)`,
  opens the seal, checks freshness, and runs the replay guard.

Two bindings matter. The seal is bound to the ClientHello random and to the client's
ephemeral key share, so a session id sniffed on the wire cannot be lifted onto any
other ClientHello. And only the exit's static private key opens it, so a stranger
cannot forge one. The auth is deliberately *decoupled* from the TLS key exchange:
it uses the plain X25519 key-share bytes regardless of whether TLS itself negotiates
X25519 or the X25519MLKEM768 hybrid.

## Terminate-path certificate

The client does not verify the outer certificate (trust is the Noise end-to-end
handshake, ADR-0009), so the terminate-path leaf matters only to a passive observer
of *our own* flows — but it is no longer a leaf we minted. The exit borrows the
impersonated origin's certificate chain once in the background (`warmMimicCert` →
`realityMimicTLS`), byte-for-byte (`x509.Certificate.Raw`, leaf plus any
intermediates), and presents those exact bytes instead of a self-signed leaf that
merely copies the origin's fields (issue #92). A prober never sees this at all —
strangers are spliced straight to the origin (above) and complete their own
handshake against it.

Presenting someone else's certificate bytes without their private key means the
exit's `CertificateVerify` signature cannot validate under that chain's public
key — there is no way around this short of holding the origin's key, which the
whole design deliberately never requires. So `realityClientHandshake` opts in to
one new, narrow uTLS config field, `InsecureSkipCertVerifySignature`, patched into
the vendored copy at `third_party/utls` (same vendoring pattern as the
`third_party/pion-dtls` DTLS-Random patch from issue #57 — see
`third_party/utls/PATCHES.md` for exactly what it does and why it's safe: the
check still runs, only a *failure* is tolerated, and only on this one call site).
It is not a substitute for `InsecureSkipVerify` above and must never be set
anywhere else — chain/hostname trust and "does the peer hold a matching private
key" are two different guarantees, and this transport's real trust boundary is
the Noise handshake and the ClientHello authenticator, not either of them.

The fresh signing key itself (`realityMatchingSigner`) is minted in the borrowed
leaf's own class — matching RSA bit length, or matching EC curve, or Ed25519 —
rather than always a fixed P-256 ECDSA key regardless of what the origin actually
uses (issue #98). Go's TLS stack picks the `CertificateVerify` signature scheme
from the *signing* key's type, not the leaf's, so a class mismatch (an RSA leaf
"signed" with an ECDSA scheme) would be a cheap, purely structural tell — visible
without even checking whether the signature validates — to anything that can
inspect that handshake message. This does not, and cannot, make the signature
itself validate; see residual 1 below for what is still open and why.

## Residual tells

Ordered roughly by who can see them.

1. **A credentialed insider (or a forced TLS 1.2 downgrade) that terminates and
   verifies the CertificateVerify signature.** The terminate-path chain is now
   the origin's real bytes (issue #92), but `CertificateVerify` is still signed
   by the exit, not the origin, since the exit never holds the origin's private
   key — that specific signature still does not validate under the leaf's public
   key, and nothing short of the origin's key closes it. This is *not* a
   passive-DPI tell under ordinary TLS 1.3: the certificate and
   `CertificateVerify` are both encrypted (RFC 8446 §4.4), so a passive observer
   sees neither, and an active prober is spliced to the real origin and never
   reaches this path. It reaches whoever completes the authenticated handshake
   and either forces TLS 1.2 (where this step rides in the clear) or terminates
   it themselves — our own client (which does not verify it; trust is Noise,
   ADR-0009) or an adversary holding a valid client credential. Before issue #98
   that observer only had to notice the signature *scheme* didn't match the
   leaf's declared key class — a cheap, purely structural check needing no
   cryptography at all. `realityMatchingSigner` closed that: the fresh signer is
   now minted in the leaf's own class (RSA bit length, or EC curve), so the
   scheme is always class-consistent and the observer must actually verify the
   signature bytes to find the mismatch. That is the same residual upstream
   Reality accepts, narrowed twice now — first from "the whole leaf is
   self-signed" (ADR-0032) to just this one signature (#92), and now from a
   structural class mismatch to a cryptographic one (#98).
2. **Origin-handshake RTT timing** (from ADR-0027). The splice and the plaintext
   bridge both add the origin's real round-trip to the observed handshake; an active
   prober measuring latency to a known-close origin could in principle see it.
3. **~30s silent hold on an unreachable origin** (from ADR-0027). When the origin
   cannot be dialed the exit holds the connection open and drains it up to the probe
   deadline rather than closing, to avoid reintroducing an instant-close tell; that
   ties up one goroutine per probe for the deadline's duration.
4. **In-window replay** is bounded by memory, not cryptography. The replay guard
   remembers session ids for one freshness window; a replay after eviction
   re-authenticates but then fails the inner handshake and falls through to the
   plaintext bridge (it still looks like the origin). A signed, longer-lived
   freshness proof is a possible follow-up.
5. **ClientHello currency.** The Chrome uTLS profile must be refreshed as real Chrome
   moves; a stale profile is itself a fingerprint. Profile rotation is a follow-up.

## Stop()/teardown drain-duration observability

Issue #65 added two `sync.WaitGroup`s so teardown actually waits for every
goroutine it owns to exit, rather than merely triggering the exit and hoping:
`realityTransport.close()` (`t.wg`, tracking `acceptLoop`/`warmMimicCert`/one
`serveInbound` per inbound connection/one `answer` per `Accept`) and
`realitySession.Close()` (`s.wg`, tracking `watchControl`, the control-conn
reader). `Engine.Stop()` calls both — directly on the transport, and transitively
through every live session it tears down — so both waits sit on its critical path.

Every goroutine either `wg` tracks is already bounded — by the listener closing,
`realityHSTimeout`, or `realityProbeTimeout` — but the transport-level bound is as
loose as `realityProbeTimeout` (30s): a `serveInbound` goroutine mid probe
response (`onProbe`/`holdAndDrain`) can hold `t.wg` open that long, so a single
stuck prober can make an exit's `Stop()` stall up to 30 seconds. There is no cheap
way to tighten that bound without truncating a probe response mid-flight —
reintroducing the instant-close tell ADR-0027/issue #62 exists to avoid — so issue
#98 instead makes the wait's actual duration observable: both `close()` and
`Close()` time their `wg.Wait()` and report it through the existing
`onEvent(kind, msg string)` channel once it returns —
`"reality: transport stop drained background goroutines in <duration>"` and
`"reality: session close drained control-conn goroutine in <duration>"`. This is
local, operator-facing logging only; nothing about it touches the wire, so it
carries none of the tell concerns above.

The session-level wait is ordinarily near-instant: `closeAndTeardown` closes the
tracked connections before `Close` waits on `s.wg`, so `watchControl`'s blocking
`Read` unblocks right away. It is timed and reported anyway, on the same
reasoning as the transport-level wait — an assumption about a `net.Conn`'s
Close/Read interaction is not a guarantee, and a silent stall is worse than a
logged one.

## Follow-ups

- Configured / long-lived exit static key for multi-process or reproducible exits
  (today it is per-listener, delivered in the answer).
- uTLS profile rotation as Chrome moves (residual 5).
- A TCP/Reality reachability probe from the RU vantage (ADR-0024) to measure the
  splice and mimic paths in the field, not just on loopback.
