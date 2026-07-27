# 32. Reality borrowed certificate: authenticate in the ClientHello and fork unauthenticated connections to the real origin

- Status: accepted
- Date: 2026-07-05

## Context

ADR-0024 shipped the `reality` transport and named a follow-up: the exit serves a
**self-signed** leaf for the camouflage SNI, so a prober that validates the TLS
chain sees an anomaly. ADR-0027 hardened the *behavioural* response (reverse-proxy
a failed inner handshake to a real origin) but explicitly left the certificate
tell open, and called out why it could not close it within that design:

> By the time a probe is detected, the exit has already presented its (self-signed)
> certificate. The response is therefore a plaintext bridge, not a raw splice.

That is the crux. Bacchus authenticates a session with a token carried in an
**inner** handshake that rides *inside* an already-terminated TLS session
(`serveInbound` completes `tls.Server(...).Handshake()` before it reads the token).
So the exit must present *some* certificate to *every* peer — prober included —
before it can tell a peer from a probe. A self-signed leaf is the only thing it
can present, and it is the dominant residual tell: a prober that validates the
chain classifies the endpoint *before* any of ADR-0027's behavioural cover matters.

Xray/VLESS Reality does not have this problem because it authenticates **in the
ClientHello**: a value derived from a shared secret is smuggled into the 32-byte
`legacy_session_id`, so the server decides *before* terminating TLS whether the
peer is an authenticated client or not. An unauthenticated peer is forwarded, raw,
to the real origin — it completes its handshake against the origin and sees the
origin's genuine certificate chain. There is nothing self-signed to catch.

Two options were weighed (see the issue #70 design fork):

- **(a) Xray-REALITY style** — authenticate in the ClientHello; fork
  unauthenticated connections to the real origin. Strongest camouflage: the
  endpoint is **unlinkable** (it borrows a major site's identity) and
  **un-blockable** without collateral damage (blocking it means blocking the
  impersonated site). Cost: it restructures the transport's handshake and needs a
  browser-fidelity ClientHello on the client (uTLS).
- **(b) A genuinely-issued certificate** for a domain we control. Simpler — load a
  real leaf + key and present it — but it **links** every exit to a registered
  domain that sits in Certificate Transparency logs and is therefore enumerable
  and blockable per-domain. This re-introduces the exact enumeration problem
  Reality exists to solve, and for a volunteer mesh it also imposes per-operator
  domain/cert operations that suppress the number of exits.

The owner chose **(a)**. Block-resistance and unlinkability are the point of this
transport in a high-censorship environment; a linkable, per-domain-blockable exit
is a weaker long-term posture even though it is cheaper to ship.

## Decision

Move Reality authentication into the ClientHello and fork on it. This is the first
increment of the (a) restructure; it delivers the property #70 asks for (an active
prober no longer sees a self-signed anomaly) and establishes the protocol the rest
of the hardening builds on.

### Wire protocol

- **Per-exit static key.** Each exit generates an X25519 key pair for its Reality
  listener at startup. Its public key rides in the `answer` frame
  (`realityAnswer.Pub`), which is already delivered over the
  coordinator-authenticated signaling channel — so, unlike vanilla Reality, no
  pre-shared static config is needed and the key can rotate freely on restart.
- **Authenticator in `legacy_session_id`.** The client builds a browser-fidelity
  ClientHello (uTLS, Chrome profile) that already carries a plain X25519 key share.
  It computes `secret = ECDH(clientKeyShareEphemeral, exitStaticPublic)`, derives an
  AEAD key and nonce from `HKDF(secret, salt = ClientHello.random)`, and seals a
  small freshness payload (a coarse timestamp) with the **ClientHello.random as
  additional data**. The 32-byte ciphertext-plus-tag replaces the 32 random bytes a
  TLS 1.3 client would otherwise put in `legacy_session_id`, so on the wire it is
  indistinguishable from an ordinary session id.
- **The exit verifies before terminating TLS.** It peeks the first TLS record,
  parses the ClientHello, extracts `random`, `legacy_session_id`, and the X25519
  key share, recomputes `secret = ECDH(exitStaticPrivate, clientKeyShare)`, and
  opens the sealed id. Binding the seal to `random` (unique per connection) and to
  the client's ephemeral key share means a `legacy_session_id` sniffed on the wire
  cannot be lifted onto any other ClientHello. A coarse timestamp window plus a
  bounded recently-seen set reject verbatim replays.

### The three-way fork (`serveInbound`)

1. **Authenticated and fresh → terminate locally.** The exit completes the TLS
   handshake itself (presenting the mimic certificate below), then reads the inner
   handshake exactly as before. A known token attaches the connection to its
   session; this is the normal client path, unchanged above the peek.
2. **Authenticated but the inner handshake fails (unknown token, replay that still
   opened, a client bug) → the ADR-0027 response, preserved.** TLS is already
   terminated, so the exit falls back to the **plaintext bridge**
   (`onProbe`/`bridge`) or hold-and-drain, exactly as ADR-0027 specified. #62 is
   not regressed; it becomes the post-termination fallback for this narrow branch.
3. **Unauthenticated → raw-splice to the real origin.** The exit never terminates
   TLS. It dials the origin (`RealityProbeOrigin`, defaulting to the SNI host on
   :443), replays the peeked ClientHello bytes, and splices the two raw TCP
   streams. The prober completes its handshake **against the origin** and sees the
   origin's genuine certificate chain. If the origin is unreachable the exit holds
   and drains (as ADR-0027), and if an operator sets `RealityProbeOrigin off` it
   gets the bare immediate close it opted into.

The impersonated origin and the ADR-0027 probe origin are now one concept: the
site the exit borrows its identity from, splices unauthenticated peers to, and
mimics the certificate of.

### Terminate-path certificate

On the authenticated path the client trusts the Noise end-to-end handshake above
the transport (ADR-0009) and does not validate the outer certificate, so this
certificate matters only to **passive** observers of our own flows. The exit mints
a leaf that copies the impersonated origin's certificate fields (subject, SANs,
validity window), fetched once and cached, rather than a bare self-signed leaf for
the SNI. It is still not a publicly-chaining certificate — see the residuals.

## Consequences

- **The self-signed anomaly is gone for the case #70 names.** An active prober is
  unauthenticated by construction (it cannot forge the ClientHello authenticator
  without the exit's static key), so it is raw-spliced to the origin and validates
  the origin's real chain. The endpoint is unlinkable and cannot be blocked without
  blocking the impersonated site.
- **#62 is preserved intact**, as branch 2 of the fork; its existing behaviour
  (plaintext bridge, hold-and-drain, `off` opt-out) is unchanged for the
  authenticated-but-failed case, and the unauthenticated case is now covered by a
  strictly stronger raw splice.
- **uTLS is a new dependency**, used to emit a Chrome-profile ClientHello and to
  control the `legacy_session_id` and read the ephemeral key share. This also
  advances the separate ADR-0024 "TLS fingerprint" follow-up: the client no longer
  emits Go's distinctive `crypto/tls` ClientHello.
- **Residuals** (documented, not closed here):
  - *Passive DPI on an authenticated flow.* The terminate-path certificate mimics
    the origin's fields but does not chain to a public CA and its `CertificateVerify`
    is signed by the exit, not the origin. A passive observer that fully validates
    every certificate it sees would flag our own client flows — not a prober, and
    the same accepted residual upstream Reality carries. Byte-for-byte certificate
    stealing is a follow-up.

    > **Update (2026-07-09):** narrowed by issue #92 — and the framing of the
    > residual above is corrected here. `realityMimicTLS` now wraps the
    > impersonated origin's certificate chain byte-for-byte
    > (`x509.Certificate.Raw`, leaf plus any intermediates, captured in the same
    > background warm as before) instead of re-minting a fresh self-signed leaf
    > that only copies its fields, so on our own authenticated flows the exit
    > presents the exact bytes the origin serves, matching the spliced
    > unauthenticated path this ADR already covered.
    >
    > This is faithfulness / parity / defence-in-depth, **not** the closing of a
    > passive-DPI hole: the residual above overstated what a passive observer can
    > see. The terminate path negotiates TLS 1.3, where `Certificate` and
    > `CertificateVerify` ride the *encrypted* handshake flight (RFC 8446 §4.4),
    > so a passive DPI box sees neither — and an active prober is spliced to the
    > real origin before it ever reaches this path. The only party that observes
    > the borrowed certificate is a peer that actually terminates: our own client,
    > which does not verify it (trust is the Noise handshake, ADR-0009). The steal
    > still earns its place — it removes any divergence between the terminate and
    > splice paths, and it is the correct behaviour if TLS 1.2 were ever forced
    > (there the certificate is sent in the clear) or against an adversary holding
    > a valid client credential who completes the terminate handshake.
    >
    > What is unchanged, and cannot change without the origin's private key: the
    > exit still signs `CertificateVerify` with a key of its own, so that
    > signature still does not validate under the stolen leaf's public key. Our
    > own client is told to tolerate that one, specific, already-expected failure
    > — `InsecureSkipCertVerifySignature`, a new opt-in field patched into the
    > vendored uTLS (`third_party/utls/PATCHES.md`, mirroring the
    > `third_party/pion-dtls` precedent from issue #57) — rather than to skip
    > certificate verification generally; `InsecureSkipVerify` above is
    > unaffected and still governs chain/hostname checks only. Set in exactly
    > one place, `realityClientHandshake`. A peer that both terminates and
    > cross-checks the `CertificateVerify` signature against the leaf's public-key
    > type would still see the mismatch — but that is a credentialed insider, not
    > passive DPI, and it is the same trade-off upstream Reality itself accepts.
    >
    > The warm is still once-at-startup, same cadence as before this issue: the
    > borrowed chain's own `NotBefore`/`NotAfter` are whatever the origin's real
    > certificate carried at warm time, not re-fetched as it nears expiry. Not a
    > new limitation — the field-copying version had the same cadence — and not
    > addressed here.
    >
    > **Update (2026-07-09, issue #98):** narrows the one thing the update above
    > left unchanged. The fresh key signing `CertificateVerify` was always a
    > P-256 ECDSA key, regardless of the borrowed leaf's own key class. Go's TLS
    > stack selects the `CertificateVerify` signature scheme from the *signing*
    > key's type (`signatureSchemesForCertificate` inspects `cert.PrivateKey`,
    > never `cert.Leaf`), so an RSA-leafed origin impersonated with a fixed ECDSA
    > signer produced a structurally inconsistent handshake: a class mismatch
    > visible to anything that can inspect the signature scheme actually used —
    > cheaper to notice than checking whether the signature validates, since it
    > needs no cryptographic verification at all, just comparing two algorithm
    > identifiers. `realityMatchingSigner` mints the fresh key in the leaf's own
    > class instead — matching RSA bit length, matching EC curve, or Ed25519 — so
    > the negotiated scheme is now always class-consistent with what the leaf
    > declares.
    >
    > This narrows, it does not close: the exit still cannot hold the origin's
    > private key, so `CertificateVerify` still does not *validate* under the
    > stolen leaf's public key, for the same reason and the same reach as the
    > update above (a forced TLS 1.2 downgrade, where this handshake step rides
    > in the clear rather than TLS 1.3's encrypted flight, or a credentialed
    > insider who terminates and checks the signature bytes themselves — not
    > passive DPI). What's gone is the free, structural version of that check.
    >
    > **Update (2026-07-10, issue #104):** narrows the #98 update immediately
    > above, which minted the fresh signer on the borrowed leaf's *exact* curve
    > unconditionally. For a P-521 origin leaf that still mints successfully —
    > but the terminate handshake then fails outright: TLS 1.3 binds each ECDSA
    > signature scheme to one specific curve (RFC 8446 §4.2.3), and the
    > mimicked ClientHello (`utls.HelloChrome_Auto`, a real Chrome profile)
    > never offers `ecdsa_secp521r1_sha512` — confirmed directly against
    > `third_party/utls/u_parrots.go`'s Chrome profile spec. That failure lands
    > past the point where `warmMimicCert`'s existing error handling can fall
    > back to the self-signed terminate config, which the #98 update above
    > claims happens for any unmintable key class; P-521 minted fine and only
    > failed later, so it silently bypassed that fallback instead of
    > triggering it.
    >
    > `realityMatchingSigner`'s ECDSA branch now mints only on
    > `elliptic.P256()` or `elliptic.P384()` — the two curves Chrome's
    > ClientHello actually offers a scheme for — and treats any other curve
    > (P-521, or any future one) the same as an unmintable key class: an error,
    > which sends the caller through the same self-signed fallback the #98
    > update above describes. P-256 and P-384 origins are unaffected.
    >
    > The same failure hid in a *third* state the #98 model didn't name:
    > *mintable, but its scheme still isn't offered*. Ed25519 is exactly that —
    > an Ed25519 origin leaf minted an Ed25519 signer with no error, but Chrome's
    > ClientHello offers no `ed25519` scheme (`0x0807`) any more than it offers
    > P-521's, so it broke the terminate handshake the same way, one key class
    > over. The `ed25519` branch now errors for the same reason and takes the
    > same self-signed fallback. RSA is genuinely unaffected — Chrome offers
    > `rsa_pss_rsae_*`, so an RSA leaf both mints and verifies.
    >
    > The prior structural tests (`TestRealityMimicTLSMatchesSignerKeyType` /
    > `...MatchesSignerCurve`) only checked that the minted signer's class/curve
    > matched the origin leaf's — never that a scheme for that curve actually
    > exists in the mimicked ClientHello, which is why they passed even though
    > P-521 was broken. `TestRealityMatchingSignerSchemeIsChromeSupported`
    > closes that gap: it reads `utls.HelloChrome_Auto`'s actual
    > `supported_signature_algorithms` extension (not a hardcoded assumption
    > about its contents) and checks every key class `realityMatchingSigner`
    > might see an origin leaf use — each ECDSA curve, RSA, and Ed25519 —
    > against it, asserting each mints if and only if a scheme for it is offered.
  - *Origin-handshake RTT timing* (ADR-0027) and the *~30s silent hold* when the
    origin is unreachable both remain: the raw-splice path adds the origin's real
    round-trip to the observed handshake, and hold-and-drain still ties up one
    goroutine per probe up to the bounded probe deadline.
  - *ClientHello currency.* The Chrome profile must be refreshed as real Chrome
    moves; a stale profile is itself a fingerprint. Profile rotation is a follow-up.
  - *Static-key distribution.* The exit key is per-listener and delivered in the
    answer; a configured long-lived key (for multi-process or reproducible exits)
    is a follow-up.
- Reachability must still be **measured**, not assumed: a TCP/Reality probe from
  the RU vantage (ADR-0024) gates leaning on this axis, and now on the fidelity of
  both the spliced and the mimic paths.
