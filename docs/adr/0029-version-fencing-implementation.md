# 29. Min-version fencing: implementation of the version policy

- Status: accepted
- Date: 2026-07-04

## Context

ADR-0015 decided the version policy — force-updateable, fenceable nodes and
force-major/skip-minor clients — but recorded only the decision, not its shape.
This record is the implementation (issue #36). ADR-0016 built the version/
capability handshake ADR-0015 assumed, but deliberately scoped its `version` to
the *wire shape* (`handshake.ProtocolVersion`, a monotonic int), leaving the
*product release* semver to this work. So the first question here is where the
release version even lives, and the rest follows from the trust model: who is
allowed to decide a node or client is too old, and what happens when they are.

The signed update/release channel that ADR-0015 also calls for — the actual
remote-code-push path — is explicitly **out of scope here** and deferred until a
beta ship is in sight; it is the highest-value attack surface in the system and
earns its own issue and its own reproducible-build discipline. This ADR covers
the *fencing* half only: reporting, gating, and the client cutover.

## Decision

**The product release version is a new leaf package, `core/version`.** It holds
`Version{Major,Minor,Patch}`, `Parse`/`String`/`Compare`, this build's
`Current()` (a `var current = "0.1.0"` string, stamped at link time via
`-ldflags -X`, so a release needs no source edit), and the two policy predicates
`ServingAllowed` (the node fence) and `ClientMustUpdate` (the client cutover).
Like `core/handshake` and `core/coldstart` it depends on nothing else in `core`,
so the coordinator binary imports it for the gate without the transport stack.
It is deliberately distinct from `handshake.ProtocolVersion`: a release ships
many times without the wire shape changing, and a wire-breaking change is exactly
a MAJOR bump — the two evolve on separate axes.

**A node reports its release; the coordinator fences a stale one.** The register
message carries a new `release` field. A coordinator enforcing a minimum serving
version drops a below-floor node from matchmaking: it is not added to the
directory and gets a `reject` naming only version data (safe to log). This is
enforced at the coordinator, not the node, because **a stale or hostile node
cannot be trusted to fence itself** — the coordinator already gates matchmaking,
so it is the natural authority.

**The client checks itself against the network's advertised release.** The
coordinator stamps its own `release` on every client reply (`exits`, `session`).
The client compares via `ClientMustUpdate`: a MAJOR gap is a hard stop
(`ListExits`/`Connect` refuse with an actionable "update required" error), a
MINOR/PATCH gap is tolerated (skip-minor — a one-time "update available" note,
then it keeps working). This half is **client-side**, because a too-old client
harms only its own user, not network integrity — the opposite trust direction
from the node fence. It is also a belt to the wire-shape handshake: a MAJOR bump
implies a `ProtocolVersion` bump the handshake would also reject, but the
client-side check turns that into a clear message instead of a confusing failure.

**The grace window X is the operator-controlled floor; expiry is soft-drain.**
Rather than bake a per-release timer into the coordinator, the grace window is
operational: during window X the operator leaves `-min-serving-version` at the
old floor (old and new nodes both serve); once X elapses, the operator raises it
and the stragglers are fenced. Expiry is **soft-drain, for free**: fencing
touches only register/matchmaking, so a fenced node gets no *new* sessions while
any already-established session finishes on its own — matchmaking and live
sessions are decoupled, so no teardown and no timer are needed.

**The fence is opt-in and fails open.** The default floor is `0.0.0`, which
fences nobody — including nodes from before the `release` field existed. Turning
the fence on is the operator setting a real floor. This mirrors the admission
gate (ADR-0023): an unconfigured coordinator serves everyone, so the feature is
backward compatible and never silently strands a fleet the operator didn't mean
to strand.

## Consequences

- **+** The fleet is patchable on demand: once a countermeasure ships, the
  operator raises the floor and every stale, now-detectable node is fenced
  automatically — the property the arms race demands.
- **+** Enforcement sits where trust dictates: node fencing is coordinator-
  authoritative (untrusted node), the client cutover is client-side (self-harm
  only). Each is testable in isolation.
- **+** Soft-drain falls out of the architecture, so a fenced node degrades
  gracefully instead of dropping live users.
- **+** Backward compatible: existing nodes and an unconfigured coordinator keep
  working until an operator opts in.
- **−** A fenced node re-registers every ~10s and is re-rejected each time; the
  client de-dupes the surfaced event by reason, but the coordinator log still
  notes each. Acceptable; a back-off could be added if it becomes noise.
- **−** "Network version" is proxied by the *coordinator's* release. During a
  coordinator-pool rollout, members could briefly advertise different releases;
  a client takes the first it sees. Harmless for the MAJOR cutover (a MAJOR bump
  is fleet-wide), but worth noting if finer policy is ever wanted.
- **−** The signed update channel is still absent, so "force-update" today means
  "fence until the operator/volunteer updates out of band," not an automatic
  push. That remote-code-push path is deferred to beta by design.

Supersedes nothing; implements ADR-0015 and builds on ADR-0016.
