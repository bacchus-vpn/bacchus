# 34. General UDP relay forwarding rides the same E2E channel as CONNECT, via a target sentinel

- Status: accepted
- Date: 2026-07-09

## Context

Issue #41: only TCP flows and DNS (UDP/53, via a DNS-over-TCP special case)
went through the tunnel — every other UDP flow was dropped. That breaks
QUIC/HTTP3, VoIP, games, and any other UDP application while connected;
browsers fall back to TCP so the web still works, but the perf/breakage gap
grows as QUIC becomes the default.

The task was originally scoped to `clients/windows/` only: extend
`tun2socks.go`'s UDP handling to forward general UDP "via SOCKS UDP-associate"
against the *existing* local SOCKS server, no core changes. Investigation
before writing any code found that framing is impossible to satisfy as
stated:

- `core/client.go`'s `handleSocks` — shared by both the single-transport
  Connect path and the pool's `bindPoolSocks` — hard-rejected any SOCKS
  command but CONNECT (reply code 7, "command not supported").
- `core/transport.go`'s `Session`/`Stream` is a byte-stream-only abstraction
  (`OpenStream`/`AcceptStream`); there is no datagram-carrying primitive
  anywhere in `core`.
- `core/forwarder.go`'s `exitTerminate` only ever dials TCP to the target —
  the exit had no way to originate real UDP on the client's behalf at all.

This is exactly the "new core forward path" collision the task's own
instructions anticipated and called out as a stop condition (flagged against
issue #17, peer-relay-vs-TURN preference, since both would touch the same
session/forwarding surface). The owner's call, once flagged: expand scope to
core+client in one coordinated PR, designed so the new relay is a *consumer*
of whatever `Session` the transport/pool layer already established — never a
modifier of *how* that `Session` gets chosen — so it doesn't foreclose #17.

## Decision

**Sentinel-based target dispatch, not a new wire message.** The client sends
`"udp:" + host:port` (`udpTargetPrefix`, `core/e2e.go`) as the E2E `target`
string instead of a bare `host:port` — the same trick `acctSentinel` and
`probeSentinel` already use to branch `exitTerminate`/`clientHandshake` after
an *identical* Noise_NK handshake, with zero changes to the handshake or its
framing. `exitTerminate` strips the prefix and calls `exitTerminateUDP`
(`core/udprelay.go`) instead of dialing TCP. This means the new path gets
E2E encryption, exit authentication, and admission/revocation verification
for free, unchanged — and both the single-transport path and the pool get it
automatically, since they share one `handleSocks`.

**Two framing layers, not one:**

- **Client-facing SOCKS boundary**: genuine RFC 1928 SOCKS5 UDP ASSOCIATE
  (CMD=3) on the *same* local SOCKS server CONNECT already uses
  (`handleSocksUDPAssociate`, `core/client.go`'s dispatch). `clients/windows`
  stays a boring generic SOCKS5 client with zero tunnel-internal knowledge —
  the same relationship `dialSOCKS` already has with this server for
  CONNECT. FRAG must be 0; this project never fragments.
- **Internal client-core↔exit hop, over the E2E stream**: a plain
  2-byte-length-prefixed payload (`writeUDPFrame`/`readUDPFrame`), no
  repeated address header — the destination is already fixed by the E2E
  target string for the stream's whole lifetime, learned once and never
  renegotiated.

**One destination per association**, not full RFC 1928 multi-destination
multiplexing: the exit dials one connected UDP socket per flow, and
`handleSocksUDPAssociate` learns the association's one fixed destination from
the *first* datagram it relays. Safe because this project controls both SOCKS
ends — `clients/windows` opens exactly one association per captured 5-tuple
flow (one gVisor `ForwarderRequest`) and never sends to more than one
destination on it by construction. A generic third-party SOCKS5 UDP client
that did multiplex would not be correctly served by this exit; that's an
accepted, deliberate v1 scope cut, not an oversight.

**45s idle timeout**, primarily client-driven: `clients/windows/udprelay.go`'s
`pumpUDP` tracks activity on both the gVisor-side flow and the relay, and
closes both after 45s of silence — closing the SOCKS control connection,
which the core side detects and uses to tear its own side down, cascading to
the exit closing its dialed UDP socket. `core/engine.go`'s new
`Engine.udpIdleTimeout` field (same 45s default) is a backstop on the exit
side and the SOCKS-facing hop, for when that client-driven signal never
arrives — same rationale as issue #3's idle-session reaper (ADR-0031): don't
leak resources forever if the peer vanished without a clean signal. Both are
fields/vars, not bare constants, so tests don't sleep 45 real seconds.

**Split tunnelling**: `handleGeneralUDP` (`tun2socks.go`) consults
`policy.direct(dst)` exactly as `handleTCP` already does — same function, no
new policy surface, same caveat that "direct" only actually leaves the
machine when an exclusion route already exists for it (splittunnel.go).

**Kill-switch requires no changes.** Verified, not assumed: the only things
that ever leave the machine for a tunnelled UDP flow are (a) loopback traffic
— the SOCKS control connection and the relay socket, already covered by the
kill-switch's `127.0.0.0/8` allow rule — and (b) the already-established
WebRTC/Reality session to an already-allowlisted control-plane endpoint. The
new relay opens no new sockets to any new remote host; it only carries more
kinds of payload over a session/socket the kill-switch already accounts for.

**DNS stays separate for this PR.** The issue's own scope explicitly allowed
either keeping the DNS-over-TCP special case or folding it into the new
general path once proven reliable; this PR keeps DNS as-is (smaller, safer
diff, and DNS-over-TCP is simpler and already proven) and defers the fold-in.

Rejected alternatives:

- **A brand-new datagram-carrying wire message/primitive on `Session`,
  independent of the existing stream+target-sentinel mechanism.** This is
  what the original issue text described ("carry UDP datagrams over the
  WebRTC data channel"). Rejected in favor of reuse: a new primitive would
  duplicate the Noise handshake, exit authentication, and admission
  verification `clientHandshake`/`exitHandshake` already provide, for no
  behavioral gain — the sentinel approach gets identical security properties
  by construction, not by re-implementing them.
- **Emulating UDP with the DNS-over-TCP trick** (`resolveDNSOverTCP`,
  `tun2socks.go`): dial a TCP CONNECT per query, frame the payload, close.
  Rejected — that trick only works for DNS because DNS-over-TCP is a
  well-defined single request/response protocol. QUIC/VoIP/game traffic has
  no equivalent TCP-shaped fallback: it's a long-lived, bidirectional,
  out-of-order datagram stream to one fixed peer, which is exactly what the
  chosen design (one E2E stream, one connected UDP socket, framed datagrams)
  provides and a per-query CONNECT cannot.
- **Full RFC 1928 multi-destination multiplexing** (one association serving
  datagrams to many destinations, demuxed by the header on every packet, both
  at the SOCKS boundary and the exit). Rejected for this v1: this project's
  own client never needs it (see "one destination per association" above),
  and building the exit-side multi-destination NAT table it implies is
  meaningfully more complex for no exercised benefit yet.

## Consequences

- `core/client.go`'s `handleSocks` now dispatches on the SOCKS command byte
  (extracted `handleSocksConnect`/new `handleSocksUDPAssociate`, a shared
  `readSOCKSAddr` helper); both `serveReconnectSocks` (single-transport) and
  `bindPoolSocks` (pool, issue #15/#28) get UDP ASSOCIATE support with no
  changes of their own, since both already call the shared `handleSocks`.
- New `core/udprelay.go`: the internal framing helpers, `exitTerminateUDP`,
  `handleSocksUDPAssociate`/`serveSOCKSUDPAssociate`, and the shared
  `startIdleReaper` helper both use.
- New `clients/windows/udprelay.go`: `dialSOCKSUDPAssociate` (the RFC 1928
  client-side framing), the `udpRelay` interface, `dialDirectUDP`, `pumpUDP`.
  `tun2socks.go`'s `handleUDP` now dispatches DNS (`handleDNSUDP`, unchanged
  logic, renamed) vs. general UDP (`handleGeneralUDP`, new).
- Accounting (issue #20/ADR-0021): UDP relay bytes are counted through the
  same `accounting.Counter` CONNECT already uses, at both the exit side
  (`exitTerminateUDP`) and the client-core SOCKS-facing side
  (`handleSocksUDPAssociate`) — counting decoded payload bytes, not
  framing/header overhead, consistent with how CONNECT counts already.
- **Fixed (issue #99):** the known limitation originally recorded here — a
  hostile or unusual SOCKS5 UDP client sending to more than one destination
  per association would have every datagram after the first silently
  misrouted to the association's already-fixed destination, since
  `handleSocksUDPAssociate`'s inbound loop only checked the datagram's
  *source* against the association's peer, never its *destination* — is
  closed. `serveSOCKSUDPAssociate` now also compares each later datagram's
  decoded destination against the association's negotiated one (learned from
  the first datagram) and drops (does not forward) any mismatch. One
  destination per association is now enforced, not just assumed of a
  well-behaved client — proven by
  `TestHandleSocksUDPAssociateDropsCrossDestinationDatagram`
  (core/udprelay_test.go), which sends a second datagram to a different
  loopback target and confirms it never reaches either the original or the
  new destination.
- Hard invariant (kill-switch): a UDP flow whose tunnel relay can't be
  established is dropped outright — no fallback to a direct dial for a
  destination split-tunnel policy routed through the tunnel, no
  retry-forever loop. Proven in
  `clients/windows/udprelay_test.go`'s `TestHandleGeneralUDPDropsWhenTunnelUnreachable`,
  driven through a real (in-memory, no OS TUN device or admin privilege
  needed) gVisor forwarder via two bridged stacks — not just a unit test of
  the leaf dial function. Building that test caught a real trap worth
  recording: gVisor's own martian-packet filter silently drops a
  loopback-destined packet arriving on a non-loopback-flagged NIC *before* it
  ever reaches the UDP forwarder, which made an earlier version of this test
  pass vacuously (nothing leaked because nothing ran, not because the code is
  correct). Fixed by enabling `ipv4.Options.AllowExternalLoopbackTraffic` on
  the test stacks and by asserting the forwarder callback actually fired as
  a hard precondition of the test — confirmed by deliberately reintroducing a
  direct-dial fallback and observing the test catch it before reverting.
  **Extended (issue #99):** the same invariant is now also proven on the
  core side, which had no test of its own before this — core has no
  TUN/netstack layer to bridge (that's the Windows client's concern; core's
  client-facing boundary is already a plain loopback SOCKS5 server), so
  `TestServeSOCKSUDPAssociateDropsWhenTunnelUnreachable`
  (core/udprelay_test.go) drives `handleSocksUDPAssociate` directly with a
  `Session` whose `OpenStream` always fails — standing in for an unreachable
  exit/transport — guarded by an `OpenStream`-attempted signal channel in
  place of the client-side test's forwarder-invoked one, and confirmed the
  same way: by deliberately reintroducing a direct-dial fallback, observing
  the test catch it, then reverting.
- Nits closed alongside #99: `decodeSOCKSUDPFrame` (both the core and the
  deliberately-duplicated windows copy) now also validates RSV == 0, not
  just FRAG and ATYP; `dialSOCKSUDPAssociate` now refuses to dial a
  non-loopback BND.ADDR in the server's UDP ASSOCIATE reply, since the local
  SOCKS server it talks to only ever binds to loopback by construction.
- Relation to #17 (peer-relay vs. TURN preference): the new relay is layered
  entirely above `Session`/`Transport` — it never chooses or influences which
  transport or path carries the bytes, only what happens once a stream is
  open. #17's future work on path preference and this PR's UDP relay are
  orthogonal by construction.
