# 15. Version policy and forced updates

Status: Accepted (2026-07-03)

## Context

Bacchus operates in an adversarial, fast-moving environment. Detection is an
arms race: a transport shape (fingerprint, handshake, timing) that passes today
can be signatured and blocked tomorrow, and the censor now retires nodes
case-by-case on protocol signature. When a countermeasure ships, any node still
running the previous release carries the *old, now-detectable* shape — and every
user routed through it inherits that exposure. A stale node is not merely behind;
it is a liability to the people using it.

Two capabilities follow from this:

1. We must be able to push the whole **serving fleet** onto a new release
   quickly, and structurally fence nodes that do not comply — "please update" is
   insufficient for a partly volunteer-run fleet.
2. We need a predictable rule for when a **client** is too old to participate.

## Decision

Versioning is semantic — `MAJOR.MINOR.PATCH`. The first number (MAJOR) denotes a
wire/protocol-breaking change.

- **Nodes (relay/exit, including volunteers) are force-updateable and fenced when
  stale.** A node reports its version to the coordinator at registration (over
  the version/capability handshake). After a release, a node has a grace window
  **X** to update; past X the coordinator stops assigning it work — it is dropped
  from matchmaking. It may keep running, but it serves nothing until it updates.
  The coordinator, which already gates matchmaking, enforces a **minimum serving
  version**.

- **Clients tolerate skipped minors and are forced on majors.** A client may skip
  MINOR/PATCH releases and keep working. A MAJOR bump is a hard cutoff: every
  client must update, and older clients stop working because the wire protocol is
  incompatible.

- **The update/release channel is signed.** A force-update mechanism is a
  remote-code-push path to every node; it is treated as security-critical.
  Releases are signed and verified before they are applied, with reproducible
  builds preferred. This channel is the highest-value attack surface in the
  system and is designed as such from the outset.

## Consequences

- **+** The fleet can be patched on demand: a new anti-detection countermeasure
  actually reaches everyone quickly, which is the property the arms race demands.
- **+** Fingerprint-burned, stale nodes are fenced automatically, protecting the
  users who would otherwise be routed through them.
- **+** Client compatibility is predictable: skip minors freely, majors force an
  update.
- **−** The coordinator becomes a policy-enforcement point (it must know the
  current minimum serving version) — a central lever in an otherwise
  decentralized design. Mitigated because it already gates matchmaking; rendezvous
  and coordinator resilience are tracked separately.
- **−** The signed update channel is now the highest-value target we own:
  compromise means a fleet-wide code push. It requires signing, disciplined key
  management, and ideally reproducible builds before the mechanism ships.
- **−** The grace window **X** and expiry behavior (soft-drain in-flight sessions
  versus hard cut) are tunable and must be chosen with both operator experience
  and security in mind.

Implementation is tracked as a separate milestone item; this record captures the
decision, not its schedule.
