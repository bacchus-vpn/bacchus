# 38. Configurable multi-hop relay chaining (client-assembled onion)

- Status: accepted (design spike — issue #76; implementation follows in child issues)
- Date: 2026-07-11

## Context

The relay tier is single-hop (ADR-0033): when a client cannot reach its exit
directly, the coordinator picks one relay, tells it the exit's address
(`assign{ExitAddr}`), and the relay blind-splices ciphertext (`core/forwarder.go`
`relayPipe`). That one relay sees **both** endpoints at the Bacchus layer — the
client's source address (it is the transport peer) and the exit's address (the
coordinator named it) — though never the content or internet destination, which live
inside the client↔exit Noise_NK channel (ADR-0009).

Issue #76 asks for a **configurable number of relay hops** so a user can route the
relayed data plane through a chain `R₁ → … → Rₙ` where no single relay sees both the
client and the exit, while keeping the client↔exit end-to-end guarantees (#60/#69)
exactly as they are — and with a default that is byte-for-byte today's single hop, so
the feature is a strict superset with zero regression when unset.

The full design is [`docs/design/relay-chaining.md`](../design/relay-chaining.md);
this record captures the decisions and their justification against the standing
threat model (a possibly-hostile coordinator, ADR-0020/#60; untrusted relays).

## Decision

Adopt **client-assembled, onion-layered relay chains**, engaged only at hop count
`≥ 2`, built from primitives already in the tree.

1. **The construction is nested Noise_NK — no new protocol.** A chain is the existing
   client↔exit handshake (`core/e2e.go`) run once per hop. The client telescopes
   layers (Tor-style): Noise_NK to `R₁` carrying the encrypted address of `R₂`, then
   through it Noise_NK to `R₂` carrying `R₃`, … then to the exit carrying the real
   destination. Each relay is the exit's existing `exitTerminate` behaviour pointed at
   the next Bacchus node: Noise_NK responder with its own key, read the encrypted
   next-hop address, dial, splice raw. `core/e2e.go`'s `noiseConn` already re-delimits
   frames over an opaque byte stream, so `noiseConn`s stack directly.

2. **The client assembles the chain; the coordinator never picks the path
   (defends the hostile coordinator).** The client selects all hops and the exit from
   the coordinator-**signed**, pool-cross-checkable directory
   (`core/coldstart.Snapshot`) and names each hop's successor only *inside* the onion.
   The coordinator keeps its two existing, already-untrusted jobs: serve the signed
   directory (tamper-evident) and broker the **first hop only** (client↔R₁ rendezvous,
   which it already sees in single-hop mode). It learns nothing of `R₂…Rₙ` or the exit.
   A coordinator therefore cannot force a colluding/deanonymizing path (it does not
   choose the hops), cannot MITM a hop (each is Noise_NK-authenticated to a directory
   key it does not hold), and cannot MITM the exit (admission-verified E2E, below).
   Coordinator-assembly is rejected: a hostile coordinator would pick an all-colluding
   chain every connect and the client could not tell.

3. **End-to-end exit admission survives the chain by construction.** The innermost
   layer is the unchanged `clientHandshake`/`exitHandshake`; the exit presents its
   `AdmissionCred` in msg2 and the client's `verifyExit` predicate (#60/#69) aborts
   before sending the target if it is unauthorized. Every relay only splices
   ciphertext, so this exchange is bit-identical whether it crossed 0, 1, or n hops —
   the same transparency argument ADR-0033 proved for one hop, extended to any depth.
   Additionally each *relay* hop is authenticated by the client to its directory key
   (stronger than the single-hop blind splice); per-hop relay-role admission
   credentials are an optional follow-up.

4. **Hop count is one knob, default 1 == today (strict superset).** `Config.RelayHops`
   / `-relay-hops` (and the ADR-0036 "route through N nodes" GUI control), default `1`,
   hard-capped at `RelayHopsMax` (proposed 4). At `1` the onion path is **not engaged**
   — the coordinator's existing `pickRelay` + `relayPipe` blind splice runs unchanged,
   so an unset knob is exactly the shipped behaviour. The onion is strictly the `n ≥ 2`
   opt-in. (n=1 stays on the old path deliberately: a 1-hop onion buys no anonymity —
   one relay sees both endpoints regardless — while adding a handshake, so it is not
   worth diverging from the proven path.)

5. **Composition.** The chain lives inside the ADR-0028 selection ladder's `ModeRelay`
   tier (tier order unchanged; depth is engine config, not a per-`Candidate` field) and
   is a strict generalization of ADR-0033's peer relay. It is orthogonal to the
   underlay: the **first** hop rides the ladder's chosen reality/webrtc transport with
   coordinator rendezvous and TURN as its ICE fallback (ADR-0033), while hops
   `R₁→…→exit` are outbound TCP dials to node ingresses. Intermediate hops must be
   publicly reachable (Tor-like); NAT'd residential nodes serve as the first hop
   (hole-punched) or the exit, not as middle hops — hole-punched middle hops would
   re-leak the path to a coordinator and are deferred.

6. **Bounds.** Chain length is capped (`RelayHopsMax`) and client-clamped (a
   coordinator cannot inject hops it never sees). Forwarding is 1:1 with no
   amplification vector; the cost is `n×` volunteer bandwidth per unit of user traffic,
   borne by the mesh, which is why depth is opt-in. Relays forward **only to a known
   Bacchus node** from their cached signed directory (preserving the relay/exit safety
   line — a relay never becomes an open internet proxy) and rate-limit per previous hop
   and in aggregate. Sybil correlation (controlling first + last hop) is bounded by
   AS/operator/vouch-subtree-diverse hop selection and the §5.4 vouch/tenure ladder.

## Consequences

- A user can opt into a relayed path where no single relay links them to their exit,
  reusing the Noise_NK handshake, the transparent splice, the signed directory, and the
  reselect/failover machinery already in the tree — the design is a composition of
  shipped primitives, not a new stack. Default-1 means existing users are unaffected.
- #60/#69 exit-admission verification is unaffected at any depth — proven by
  construction (onion layers sit outside the E2E channel) and to be pinned by an
  n-hop analogue of `TestPeerRelaySplicePreservesE2E`.
- **Honest limits.** No defence against a global passive traffic-correlation adversary
  (the standing limit of low-latency onion routing — Tor shares it). The first hop
  still sees the client's address; the coordinator still sees client↔R₁ — both
  unchanged from single-hop. At the default depth a single relay still sees both
  endpoints; that is today's behaviour, opted out of only at `n ≥ 2`.
- **Dependency.** Client-side hop selection needs each relay's forwarding ingress
  address + operator tag in the signed snapshot — the courier-address advertisement
  ADR-0037 deferred. **This directory seam is now implemented (issue #124 — see the
  Amendment below);** the client-side selection/dialing that consumes it (§2/§4) stays
  deferred, so until those land, intermediate hops are directory-/operator-anchored.
- **A feasibility probe ships with this spike** ([`cmd/relaychain-probe`](../../cmd/relaychain-probe/README.md)):
  a dependency-free, in-process demonstrator that telescopes real `flynn/noise` layers
  and asserts the peel property (each relay learns only its neighbours; the innermost
  target + admission credential survive; a substituted hop key fails its handshake). It
  imports no `core/` package and wires nothing into production.
- **Deferred to child issues** (enumerated in the design doc §9): relay onion-forward
  handler + ingress; client telescoping dialer; directory ingress/AS metadata (gates
  selection); AS-diverse hop selection; the hop-count knob + GUI; chain liveness +
  rebuild; relay-side DoS controls; optional per-hop relay admission creds; and the
  deferred NAT-traversed middle hop. This PR is **Part of #76** and does not close it.

## Amendment (issue #124, 2026-07-11): relay ingress + operator advertised; AS-tag advisory-only

The directory seam §6 and the Dependency consequence named — "each relay's forwarding
ingress address + operator tag in the signed snapshot" — is now implemented on the
production/directory side. This is the **ungated foundation** of the epic (§9 item 3):
§1 (relay onion-forward handler) and §2/§4 (client selection + telescoping dial) build on
it; it wires none of them.

**What landed.** `core/coldstart.Entry` gains two additive, `omitempty` fields, both
inside the ed25519-signed snapshot body, and the coordinator populates them in
`buildSnapshot`:

- `Ingress` — the TCP address a client's onion layer dials to use the node as an
  intermediate hop, distinct from `Addr` (a relay's coordinator-observed UDP *signaling*
  address, a NAT-punched hole, not a forward-dial target). The coordinator composes it as
  the **observed source IP** of the relay's register joined to the relay's **self-reported
  listener port**. Only the port is a node self-report; the host is never the node's to
  assert, so a relay cannot advertise an ingress in an AS it does not occupy. A relay that
  reports no port advertises no ingress and is, by `Entry.RelayEligible`, simply not a hop.
- `Operator` — the coordinator-known operator / vouch-subtree tag for operator-diversity
  hop selection (§6). It is **coordinator-side truth** (loaded from the operator's
  `-operators` assignment file), never a node self-report — a node cannot be trusted to
  state its own operator, or a Sybil would fabricate diversity. Empty when unassigned
  (fail-open, like admission #42): hops are then merely unlabeled.

Signing covers both fields end-to-end (a tampered ingress or operator tag fails snapshot
verification), the addition is backward-compatible both ways (a pre-#124 snapshot verifies
under the new parser and vice-versa — no version bump), and a mesh-walk courier (#31)
forwards the fields verbatim without being able to strip or forge them.

**No AS field is carried — the honest limit on §6/§7 anti-Sybil.** The spike's §6
listed "AS/operator/vouch-subtree-diverse hop selection." Of these, **AS is deliberately
NOT put in the signed directory at all.** A self-reported — or even coordinator-asserted —
AS number cannot be trusted for network diversity: a hostile coordinator or Sybil operator
would fabricate AS diversity in a signed tag, and the client cannot verify it. Such a field
would have **no trustworthy consumer**, because real AS-diversity is enforced in §4 by
deriving each hop's AS from its **observed IP** against an independent public routing table,
client-side, never from this snapshot. If any AS hint is ever carried here for coordinator
bookkeeping, it must be documented — in code and here — as **advisory only, never a client
diversity input.** The operator/vouch tag *is* legitimately signed (operator identity is
not IP-derivable), but it too is an advisory anti-Sybil signal anchored in coordinator
bookkeeping; the load-bearing network-diversity anchor for §4 is the IP-derived AS, not any
tag in this directory.

**Still deferred (unchanged):** the relay onion-forward handler + ingress listener (§1);
client hop selection, diversity, and the telescoping dialer (§2/§4); everything else in the
§9 list. This change stays inside `core/coldstart` + `cmd/coordinator`; it is **Part of #76**
and does not close it.

## Relationship

Extends ADR-0033 (single hop is n=1) and ADR-0028 (the `ModeRelay` tier); preserves
ADR-0009 and ADR-0026/#69 through the chain; selects from ADR-0037's signed snapshot;
reuses ADR-0030/#96/#105 for failover.
