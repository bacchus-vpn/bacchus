# 27. Reality active-probing response: reverse-proxy unknown connections to a real origin

- Status: accepted
- Date: 2026-07-04

## Context

ADR-0024 shipped the `reality` transport (TCP :443, camouflage TLS) but named
its active-probing response as an explicit follow-up (issue #62). The exit closed
any connection that failed the inner handshake immediately (`onProbe`). That is
the least-information response, but it is not the most camouflaged one: a real
:443 web server completes the TLS handshake and then **serves a page**, so
"completes a TLS handshake, then instantly closes on unrecognized bytes" is a
behaviour an active prober can measure. Active probing — connect to a suspected
endpoint, send probe bytes, classify by the response — is how Russia and China
confirm and then kill a circumvention endpoint; it is decentralized and
per-operator, so the endpoint's own behaviour is the whole signal.

One architectural constraint shapes the response. Xray/VLESS Reality peeks at the
raw ClientHello and, for an unauthenticated client, forwards the **raw TCP** to
the origin so the origin performs the TLS handshake and the prober sees the
origin's genuine certificate. Bacchus cannot do that: its session token is
delivered out of band (over the coordinator-authenticated signaling channel) and
checked in an inner handshake that rides **inside an already-terminated TLS
session** (`serveInbound` completes `tls.Server(...).Handshake()` before reading
the inner handshake). By the time a probe is detected, the exit has already
presented its (self-signed) certificate. The response is therefore a **plaintext
bridge**, not a raw splice: terminate TLS on both sides and shuttle the decrypted
bytes between the prober and a real origin.

## Decision

On a failed inner handshake, reverse-proxy the connection to a real origin so the
prober sees an ordinary website's response, behind the single `onProbe` seam
ADR-0024 carved. No change above the `Transport` interface.

- **On by default.** The fallback origin (`Config.RealityProbeOrigin`,
  `-reality-probe-origin`) defaults to the SNI host on :443 when unset, so every
  exit is probe-resistant out of the box. The sentinel `off` restores the bare
  immediate close; an explicit `host:port` overrides the target.
- **Plaintext bridge.** Terminate TLS with the prober and, separately, with the
  origin, then splice the two decrypted streams. The prober's opening bytes —
  already read off the wire to detect the probe — are recorded and replayed to
  the origin so the proxied request is not truncated. The dial to the origin
  wears the same SNI and the **same ALPN** we negotiated with the prober, so the
  relayed conversation speaks one dialect end to end. The origin certificate is
  not verified: we borrow its bytes for cover, not its identity for trust.
- **Unreachable origin → hold open and drain.** If the origin cannot be reached,
  keep the connection open and discard what the prober sends rather than closing,
  so a momentarily-down origin does not reintroduce the instant-close tell. A
  bounded probe deadline caps the resource a flood of probes can tie up.
- **Pre-termination failures still close.** A connection whose outer TLS handshake
  never completes is rejected outright — there is no plaintext stream to bridge,
  and a real :443 server likewise errors on non-TLS bytes, so a close there is not
  the post-handshake tell this ADR addresses.

## Consequences

- The instant-close tell is gone for the common case (a probe that completes TLS
  then sends unrecognized bytes): a prober measuring behaviour sees an ordinary
  website. This is the difference ADR-0024 named between "reality endpoint
  survives probing" and "reality endpoint is trivially confirmable."
- The camouflage is still **partial, by design**. The exit serves a self-signed
  leaf, so a prober that validates the certificate chain sees an anomaly *before*
  the behavioural response matters. The borrowed-certificate work (a named,
  still-open ADR-0024 follow-up) hardens that separate layer; the two should
  eventually land together for the response to be fully convincing.

  > **Update (2026-07-05):** superseded by ADR-0032 (issue #70). This bullet
  > described the exit's *only* certificate story at the time: every peer,
  > prober included, got the self-signed leaf above. ADR-0032 forks on the
  > ClientHello before terminating TLS at all, so an unauthenticated prober is
  > raw-spliced to the real origin and validates *the origin's own chain* — it
  > never reaches a self-signed leaf of ours, and the "anomaly before the
  > behavioural response matters" this bullet warned about no longer applies to
  > a prober. The plaintext bridge this ADR decided stays exactly as designed,
  > as the fallback for an authenticated-but-failed-inner-handshake connection
  > (ADR-0032's fork, branch 2).
  >
  > **Update (2026-07-09):** further narrowed by issue #92. The residual this
  > bullet described was really two: what a *prober* sees (closed by ADR-0032,
  > above) and what a passive observer of *our own authenticated flows* sees —
  > which, until #92, was still a field-copying self-signed leaf. #92 (see
  > ADR-0032's own residuals) presents the origin's real certificate bytes on
  > that path too. What's left is narrower still and is tracked there, not
  > here: the exit's `CertificateVerify` signature over that borrowed chain is
  > its own, not the origin's, and our client is told to tolerate exactly that
  > one check failing.
- On by default has a cost: every exit now makes an outbound TLS connection to
  the SNI host whenever it is probed (bandwidth, and a faint "exit → SNI host on
  probe" traffic pattern). Accepted for out-of-the-box probe resistance; an
  operator opts out with `-reality-probe-origin off`.
- Hold-and-drain ties up one goroutine per probe while the origin is unreachable,
  bounded by the probe deadline; the origin is the SNI host precisely because it
  is reliably reachable, so this path is rare.
- Reachability must still be **measured**, not assumed: a TCP/Reality probe from
  the RU vantage (ADR-0024) gates leaning on this axis, and now on the fidelity
  of the proxied response.

> **Update (2026-07-22, issue #163): the splice is now metered, and the argument is
> in this ADR's terms (camouflage fidelity), not #143's (billing).** ADR-0040 (issue
> #143) gives an operator a declared monthly quota and speed cap and promises the cap
> is *never exceeded* — but the splice paths this ADR decided (`rawSplice`, `bridge`,
> `holdAndDrain`) reverse-proxy unauthenticated connections **unmetered**, so on a
> reality node that promise was false. Worse than a bill: an attacker who spends a
> volunteer's quota gets the node **evicted** (#143 stops assigning to an exhausted
> node), anonymously, for half what it costs the volunteer (2× amplification), from a
> single uplink in ~4.4 hours (design §8.7). #163 closes it, and the design tension is
> real: the forwarder's meter tears a session down the instant the cap is spent, but
> **truncating a probe response mid-flight is the exact "origin stops mid-response"
> tell this ADR exists to erase.** So metering the splice is not "cut it".
>
> The decision is option **(c) plus per-IP limits** (the shapes the issue named):
> - **Meter, never cut.** The copy legs count every byte against the quota — both link
>   crossings for a reverse-proxy leg, one for a drain (design §8.7) — and pace it to
>   the speed cap, but the reader **never** returns `ErrQuotaExhausted`. An in-flight
>   splice always runs to completion.
> - **Refuse NEW splices once exhausted, at admission (option c).** When the quota is
>   spent, a new unauthenticated connection is **drained instead of reverse-proxied** —
>   and a drain is the *same* no-instant-close response this ADR already blesses for an
>   unreachable origin. A prober cannot distinguish "node exhausted, holding" from
>   "origin momentarily unreachable, holding": both are inside this ADR's accepted
>   envelope. The instant-close/mid-response tell is never reintroduced.
> - **Per-IP + global rate gate bounds concurrent amplification, not time-to-exhaust.**
>   A per-source-IP rate limit on *new* splices plus a global concurrency cap bounds how
>   many amplifying legs run at once, and the per-IP connection churn (and gate memory) a
>   flood costs. An ordinary active prober, which probes one address slowly, is never
>   throttled. It does **not** stop a single uplink from reaching exhaustion — see the
>   correction below.
>
> **Correction (2026-07-25, issue #168): the gate's efficacy was overstated above and in
> ADR-0040/design §8.7.** Those said the per-IP gate means "a single uplink can no longer
> evict a node". It does not, whenever the operator declares a speed cap. The splice
> limiter is **aggregate and shared** with the forwarder's, so one active reverse-proxy
> splice already saturates the entire declared speed; and the per-IP rate (1/sec, against
> a 30 s `realityProbeTimeout` splice lifetime) trivially keeps one splice alive
> continuously. Time-to-exhaust is therefore `quota / (2 × speedCap)` — the *same* formula
> design §8.7 already used for the unmetered case — **independent of how many source
> addresses the volume comes from**. One machine can still spend an honest node's whole
> cycle quota and get it evicted.
>
> What #163 actually bought is intact and is the part worth stating: option (c) means the
> spend is now **bounded by the declared cap and accounted for**, instead of running at
> line rate unmetered. *Never exceeded* became true. "One machine cannot do it" never was.
> Corrected in `core/transport_reality_meter.go`, ADR-0040 and design §8.7.
>
> **Residual, in this ADR's terms.** A censor probing an *exhausted* node sees a drain
> (a hold), not the origin's page — a state change from "serves microsoft.com" to
> "holds" that is a *weak* signal, and strictly weaker than the instant-close tell it
> replaces; the alternative (keep amplifying past the cap) breaks #143's promise, so the
> trade is taken. And the eviction attack is *priced, not closed*: an attacker can still
> spend the quota — and per the correction above, a **single** uplink suffices; no
> distribution is required — the same "priced, not closed" posture as the estimator's
> Sybil hole (ADR-0040/ADR-0041). The full argument
> and the metering shape live in ADR-0041 and design §8.7; ADR-0040's Bad/open list is
> updated to match.
