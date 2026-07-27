# 24. A second transport: Reality over TCP :443, behind the Transport interface

- Status: accepted
- Date: 2026-07-03

## Context

ADR-0008 made `core`'s `Transport` an interface and shipped WebRTC (pion) as
the first implementation, valued for NAT traversal, not trusted as camouflage.
It named the point of a second transport: resistance is the *union* of many
partial transports, so we need at least one that fails on a **different axis**
than WebRTC. WebRTC is UDP/DTLS; where an operator throttles UDP or blocks
DataChannels it dies everywhere at once (issue #16).

The field data points the other way for TCP. Our earlier "TCP is blocked from
RU" result was a datacenter-IP exit on a raw port getting frozen — the
IP-classification / destination axis, not a verdict on TCP the protocol (all of
RU banking and Gosuslugi ride TCP :443). The surviving TCP shape is
Reality/XHTTP: :443, a borrowed real-looking TLS handshake, a whitelisted SNI,
no distinct fingerprint to freeze on.

## Decision

Add `reality`, a TCP transport implementing the same `Transport` interface, with
no changes above the interface:

- **Outer layer — camouflage TLS on :443.** The exit is a TLS server; the client
  a TLS client presenting a configurable SNI and HTTP ALPN (`h2`, `http/1.1`).
  On the wire a session is an ordinary HTTPS connection to :443.
- **Rendezvous over the existing signaler.** The client sends `offer`; the exit
  replies `answer` carrying `{addr, token, sni}` — only coordinator-relayed
  frame kinds, so the coordinator is unchanged. The client then dials that
  address directly (no ICE/STUN/TURN: TCP needs no hole-punching).
- **Session model mirrors WebRTC onto TCP.** A session is a set of TLS
  connections to the exit; each stream is one connection, labelled in an inner
  handshake (`magic ‖ token ‖ label`) that rides *inside* the TLS session. One
  `control` connection (the same `ctrlLabel` the WebRTC path uses) carries no
  data and exists to prove the path is usable and to signal teardown. One TLS
  connection per stream keeps reliability on TCP, where it belongs, and reads
  like a browser opening many parallel HTTPS connections.
- **Trust is not the outer certificate.** The client does not verify the outer
  cert (`InsecureSkipVerify`), exactly as Reality does. Authentication is the
  one-time token, minted over the coordinator-authenticated signaling channel,
  plus the Noise end-to-end handshake that already sits *above* the transport
  (ADR-0009). The outer TLS is camouflage and confidentiality for the first hop,
  not the trust anchor.
- **Selection is config-driven.** `Config.Transport` (`webrtc` default, or
  `reality`) picks one via a `newTransport` factory; `cmd/node` exposes
  `-transport` and `-reality-*` flags. This is the seam the client-side pool
  (issue #15) will drive to race the two per user; until then it selects one.

## Consequences

- Coverage now spans two axes: UDP/DTLS (WebRTC) and TCP/:443/TLS (reality). A
  network that kills one need not kill the other; the pool (#15) can fail over.
- Adding the transport required no change above the interface — the engine dials
  and accepts through the same `Dial`/`Accept`/`Session` it always did,
  validating ADR-0008's abstraction.
- The camouflage is intentionally partial in this first cut, and these are the
  named follow-ups:
  - **Active-probing response.** An inbound connection with a bad/unknown token
    is closed immediately (`onProbe`). That is the least-information response but
    not the most camouflaged: a real :443 server would serve a page. Proxying
    unknown connections to a genuine origin for the SNI is the hardened policy
    and lives behind that one seam (issue #62).
  - **Borrowed certificate.** The exit serves a self-signed leaf for the SNI.
    Real Reality borrows a genuine certificate/handshake from a fronted site.
  - **Connection reuse.** One TLS handshake per stream is simple and good cover
    but costs latency for many short streams; amortizing it (pooling or a
    multiplexer) is an optimization, not a correctness need.
  - **TLS fingerprint.** Go's `crypto/tls` ClientHello is not a browser's;
    uTLS-style mimicry parallels the WebRTC DTLS work (ADR-0018).
- Reachability must be *measured*, not assumed: a TCP/Reality probe from the RU
  vantage (the TCP analogue of `coldstart-probe`) gates leaning on this axis.
