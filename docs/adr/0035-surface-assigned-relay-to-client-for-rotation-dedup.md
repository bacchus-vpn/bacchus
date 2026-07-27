# 35. Surface the assigned relay to the client for rotation dedupe

- Status: accepted
- Date: 2026-07-10

## Context

The coordinator pool (ADR-0020) has the client rotate across members on **any**
connect failure: a poisoned or unlucky coordinator can hand back a dead or hostile
relay, and rotating to the next member is how the client escapes it. That rotation
is deliberately blunt — it cannot tell *which* relay it just failed on, because the
coordinator tells only the relay its identity. On a `connect{mode:"relay"}` the
matchmaker sends the assigned relay an `assign{exitAddr}` (ADR-0033) but sends the
client only `session{sid}`; the relay's identity never reaches the client.

So when two pool members happen to assign the **same** bad relay, the client dials
it twice — once per member — because it has no way to see they are the same relay.
It is bounded (by the pool size) and not a correctness bug, but it wastes a full
relay-dial timeout per redundant member and weakens the poison-resistance story:
the whole point of rotating is to *escape* a bad assignment, and re-dialing the
identical one does not.

The client already learns the relay's ICE candidates during signaling, so it can
already fingerprint a relay by address. What it lacks is a **stable handle** it can
compare across members without dialing. Issue #56 asks for exactly that handle,
and no more — deliberately out of #6/ADR-0020's scope, which left the coordinator
binary unchanged.

## Decision

Carry the assigned peer relay's identity to the client as a **stable, opaque tag**
on the `session` reply, and have the client skip a pool member that re-offers a tag
it already failed on this `Connect`.

- **Opaque tag, not an address (`cmd/coordinator`).** A new `relayTag` field on the
  `session` reply carries `relayTag(r.id)` — a domain-separated SHA-256 of the
  relay's node id, truncated to 8 bytes. It is set **only** on the peer-relay path;
  direct and TURN-fallback replies carry none (there is no distinct relay to
  dedupe). Two properties make it work:
  - *Stable across coordinators.* The id is the relay's own identity, registered
    identically with every pool member (one `register` broadcast to all,
    `core/engine.go` `registerLoop`), so two members that assign the same relay
    produce the same tag — which is what lets the client recognise "the same relay
    again."
  - *Reveals nothing new.* It is a hash of the id, not the routable address, so it
    discloses nothing the client could not already infer from the relay's ICE
    candidates (ADR-0009's blind-relay model), and it decouples the wire tag from
    the internal id format.

- **Per-pass skip-set (`core/client.go`).** One `establish` pass owns a
  `relayDedup` — a set of relay tags whose transport dial failed this pass.
  `attemptWith` records a tag on dial failure and skips (without re-dialing) a later
  member that offers a tag already in the set, returning `transportFailed` so
  rotation continues. The set is scoped to the pass on purpose: a fresh reconnect
  starts clean, because a relay that is bad now may have recovered by the next
  attempt. The pool path (ADR-0028) passes `nil` — it has its own cross-transport
  failover and does not use this — and every `relayDedup` method is nil-safe.

- **Additive and optional (no capability bump).** `relayTag` is an optional field.
  A client predating #56 ignores it; a coordinator predating #56 sends none, so the
  client's skip-set stays empty and it behaves exactly as before (fail-open, no
  worse than today). Because the field never becomes *required* — a missing tag
  simply disables the optimisation for that pairing — it does **not** bump the
  ADR-0016 capability/version handshake. The handshake would only need to move if a
  peer had to *reject* an old counterpart for lacking the field, which nothing here
  does.

## Consequences

- A bad relay assigned by two different coordinators now costs **one** failed dial,
  not two: the client escapes it on the first failure and skips its twin. Poison
  resistance is strictly improved, and no worse in any case (a missing/empty tag
  falls back to today's behaviour).
- **Traced through the coordinator's prune/reselect lifecycle (the #105 lens).**
  Skipping a member's assignment abandons the session that member just minted. For a
  peer-relay session that entry has `relayID != ""`, which ADR-0033's #105
  correction **exempts** from `sessionTTL` pruning — so it lingers until
  `reselectDeadRelays` reaps it when the assigned relay goes stale. This is **not a
  new orphan class**: it is byte-for-byte the same entry a *dial-and-fail* would
  have left (the client abandons the pairing either way), and it is the very
  residual ADR-0033 already documents ("any client that re-established onto a fresh
  session while the old relay stayed up … orphaning the old entry … bounded by relay
  lifetime"). The dedupe only removes the wasted *dial*, not any coordinator state
  that was not already there — indeed the `sendN`-triple every relay connect already
  mints two abandoned sessions per attempt, of the same class. So #56 adds no new
  reaping obligation.
- **Privacy is unchanged.** The tag is opaque and address-free; a relay cannot be
  located or singled out from it beyond what its ICE candidates already expose.
- **Backward compatible both directions** (old client + new coordinator, new client
  + old coordinator), by construction of the optional field.
- Accepted limits / named follow-ups:
  - **Per-pass, not cross-Connect, memory.** The skip-set is forgotten between
    reconnects by design (recovery), so a relay that is durably dead is re-tried
    once per reconnect pass rather than banned outright. A longer-lived health memory
    (like the coordinator-link `unhealthy` cooldown) is a possible future refinement,
    not needed for the "escape a poisoned member" goal #56 scopes.
  - **Tag is per relay incarnation.** A relay that restarts under a new id produces a
    new tag — correct, since it is a different incarnation — but a relay that keeps
    its id across a restart keeps its tag, which is also correct (same identity). The
    coordinator's own liveness (ADR-0033 #105) handles a same-id restart under a new
    address independently.
  - **Load-aware relay selection is still a follow-up** (ADR-0033): this changes only
    what the client *learns*, not how the coordinator *picks*.
  - **Tested with fakes.** The coordinator side (tag present on peer-relay, absent on
    direct/TURN-fallback, stable and collision-distinct) is proven by driving
    `handle()` with fake UDP peers; the client skip — and its non-vacuous companion,
    that two *distinct* relays are both dialed — by driving the real
    `establish`/`connectVia`/`attemptWith` ladder over a fake transport that counts
    dials. As in ADR-0033 the `-race` detector is unavailable locally (needs cgo);
    the skip-set is per-pass stack state with no new cross-goroutine sharing.
