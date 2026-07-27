# 16. Protocol version + capability handshake

- Status: accepted
- Date: 2026-07-03

## Context

Every node (client, relay, exit) and the coordinator share one wire protocol
over the coordinator's UDP channel, but they do not all ship in lockstep — a
volunteer relay can lag a release, a client can be mid-update. Without an
explicit check, two peers running different revisions of that protocol just
start exchanging register/list/connect/signaling messages neither necessarily
still agrees on the shape of, and a mismatch surfaces (if at all) as role
logic failing in some unrelated, confusing way deep in a session — "silently
corrupting sessions" (issue #8). An unexpected wire shape from a stale node is
also itself a fingerprint, which matters given the detection arms race
ADR-0015 describes.

ADR-0015 already assumes this mechanism exists ("a node reports its version to
the coordinator at registration, over the version/capability handshake") but
left it unspecified. This record is that specification. Full policy on top of
it — a minimum serving version the coordinator enforces, fencing stale nodes
from matchmaking — is separate follow-on work (issue #36); this is the
negotiation primitive that work will consume.

## Decision

**A versioned "hello" is the first message a node sends the coordinator**,
before register/list/connect (`core/handshake`, a leaf package with no
dependency on the rest of `core` or WebRTC, so the coordinator binary — which
otherwise avoids that dependency weight, same reasoning as `core/coldstart` —
can use it directly):

- **Shape**: `{magic, version, capabilities}`, plain JSON on the existing
  wire envelope (a new `"hello"` message type), not a separate binary
  sub-protocol. Coldstart's STUN-shaped binary framing exists to camouflage
  traffic from censorship middleboxes — a concern this handshake does not
  have, since it runs on the coordinator's already-plaintext-JSON control
  channel, so reusing that channel's own shape is the simpler, consistent
  choice.
- **`magic`** is a fixed string identifying a genuine Bacchus hello, so the
  coordinator can reject unrelated traffic on its port through the same path
  as a real version mismatch.
- **`version`** is a single monotonic integer, `core/handshake.ProtocolVersion`
  — the wire *shape*, not the product release (semver stays ADR-0015's, for
  the separate min-serving-version policy). v1 of this mechanism checks it for
  exact equality: "same-version peers connect" (issue #8's acceptance
  criterion) is a stricter, simpler bar than a min/max range, and a range only
  earns its complexity once something has actually shipped two compatible
  wire versions at once. Nothing here blocks widening this to a range later.
- **`capabilities`** is a set of named flags, defined empty today. The field
  exists so a future optional feature can be negotiated without another
  protocol-breaking version bump; an unrecognized capability is never a
  rejection reason, which is what keeps it forward compatible.

**On a match, the coordinator replies nothing** — register/list/connect
proceed exactly as they did before this existed. **On a mismatch, it replies
`{"type":"reject", "reason": "..."}`** and logs the same reason server-side.
The reason names only protocol/version data (which side is newer) and nothing
about the peer's identity, so it is always safe to log and to echo back
verbatim — satisfying "fail fast with a logged reason (no user-identifying
data)" on both ends at once.

**The coordinator does not gate register/list/connect on having seen a prior
hello.** Hello is sent once, synchronously, right after the node's UDP socket
comes up — not resent on a timer the way registration is. Register already
carries its own periodic-resend liveness mechanism (TTL-backed, because the
registry needs to expire stale entries over time); hello has no such
staleness concept, it is a one-time startup check. Making it a hard
precondition for every later message would need the coordinator to track
per-source handshake state and would race UDP's unordered delivery (the hello
packet is not guaranteed to arrive before a register packet sent moments
later, even from the same node). Keeping it advisory means a lost hello
packet just forgoes this startup's diagnostic — it degrades to exactly
today's pre-#8 behavior for that one instance, never a new failure mode.

Hello itself carries no node id, role, or address — those belong to the
role-specific messages that follow once it succeeds, keeping it genuinely
"before any role logic" rather than a superset of `register`.

## Consequences

- **+** A version mismatch between a node and the coordinator is caught at
  the door, with a clear, actionable, safe-to-log reason, instead of
  surfacing as an unexplained failure inside role logic.
  - **+** The happy path is unchanged: same-version peers see no new
  round trip, no new latency in `Engine.Start`, no new failure mode when a
  hello packet is simply lost.
- **+** `core/handshake` is a small, dependency-free surface issue #36 (min-
  version fencing) can build policy on top of, without that issue needing to
  also design the wire negotiation itself.
- **−** Because the coordinator does not gate on hello, a node that skips it
  entirely (a bug, or a peer that predates this mechanism) is not blocked —
  only diagnosed when it does say hello. Acceptable for v1: closing that gap
  is exactly the kind of enforcement issue #36's minimum-serving-version
  policy is for, not this primitive.
- **−** Strict version equality means any wire-shape change is a hard cutover
  for node<->coordinator traffic, with no overlap window. Revisit if/when a
  rolling, mixed-version fleet deploy becomes a real operational need.
