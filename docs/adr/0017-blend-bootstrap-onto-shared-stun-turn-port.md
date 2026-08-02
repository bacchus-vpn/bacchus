# 17. Blend cold-start bootstrap onto the shared STUN/TURN port

- Status: accepted
- Date: 2026-07-03

## Context

ADR-0012 decided first contact blends with STUN/WebRTC to our own STUN
server. ADR-0013 implemented the bootstrap wire protocol but, in its point 6,
recorded a known gap versus that goal: the bootstrap listener ran on a
**second, independent UDP socket** (`cmd/coordinator -bootstrap-addr`,
default `:3479`), not literally the same port/process as the real STUN/TURN
server (`cmd/turn`, pion/turn). A censor's DPI keying on port number alone —
not just packet shape — could still separate bootstrap traffic from ordinary
STUN/TURN traffic to the same box. That gap was filed as issue #30 rather
than blocking `old #18`'s acceptance.

## Decision

1. **Socket-level demux, not a pion/turn fork.** A new `core/coldstart.Demux`
   wraps the `net.PacketConn` handed to `turn.NewServer`. It intercepts and
   answers only STUN Binding Requests that carry the bootstrap `USERNAME`
   attribute, reusing the same authenticate-then-maybe-attach-`SNAPSHOT`
   logic `Serve` already used. Every other packet — a bare Binding Request
   (ordinary reflexive-address gathering) or any TURN message (Allocate,
   Refresh, CreatePermission, ChannelBind, Send/ChannelData) — passes
   through to pion/turn completely unmodified. This was chosen over hooking
   pion/turn's internals (forking it, or replacing its STUN/TURN handling
   with a codec built on `core/coldstart`'s parser) because pion/turn
   exposes no hook for a comprehension-optional attribute, and a fork would
   mean carrying an ongoing diff against upstream; the demux needs no
   pion/turn changes at all.
2. **The demux key is presence/absence of `USERNAME` on a Binding Request**,
   nothing deeper. An ordinary STUN reflexive-address query never carries
   one (RFC 5389 Binding requests are unauthenticated), so this can't
   misroute real ICE traffic — and it means ordinary Binding Requests keep
   getting pion/turn's native response (including its `FINGERPRINT`
   attribute) instead of `core/coldstart`'s minimal one, which now only ever
   appears on wire shapes no legitimate STUN client produces.
3. **`cmd/turn` folds into `cmd/coordinator`.** The coordinator already owns
   the registry, the snapshot-signing loop, and the secrets store that
   bootstrap needs; it now also owns the TURN credentials/flags
   (`-turn-public-ip`, `-turn-realm`, `-turn-user`, `-turn-pass`) and binds
   the one shared UDP port (`-turn-addr`, default `:3478`). `cmd/turn` is
   deleted rather than kept as an unused parallel binary: running it
   standalone would conflict with the coordinator on the same port in the
   real single-box deployment (coordinator + STUN/TURN + exit on one VPS).
4. **The wire protocol itself is unchanged** — ADR-0013's framing stands.
   This is a transport/deployment change only.

## Consequences

- Closes the port-based distinguishing signal ADR-0013 flagged: bootstrap
  and ordinary STUN/TURN traffic to the coordinator now share one UDP port
  and one OS process, confirmed by an integration test that drives a real
  TURN allocation, a plain STUN binding, and an authenticated bootstrap
  fetch concurrently against the same merged listener.
- One fewer systemd unit/binary to build, deploy, and keep TURN credentials
  in sync for (`bacchus-turn` retired; see `deploy/`).
- `core/coldstart.Serve` (the standalone read loop used before this change)
  stays exported for contexts that want a bare bootstrap listener without a
  full TURN server alongside it — e.g. a future mesh-walk node (issue #31)
  that only relays snapshots. `Demux` and `Serve` both sit on top of the
  same package-internal request handler, so the authenticated/unauthenticated
  response logic has exactly one implementation either way.
- `core/coldstart`'s Binding Success Response still never carries a
  `FINGERPRINT` attribute, unlike pion/turn's own Binding responses — a
  pre-existing gap (present since #29/ADR-0013) that is more consequential
  now that both response shapes can be observed on the *same* port. Left
  as-is here because ADR-0013 froze the wire format and this decision's
  scope is transport-only; filed as a separate follow-on issue rather than
  folded into this change.
- The coordinator process is now a slightly bigger blast radius: it takes
  signaling, STUN/TURN, and bootstrap down together, where before a
  `cmd/turn` crash only lost STUN/TURN. Acceptable for the current
  single-box deployment; worth revisiting if the topology ever splits
  across boxes.
