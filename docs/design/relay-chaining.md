# Multi-hop relay chaining — design

- Status: **implemented and shipped** for the client and relay halves (issue #142).
  Issue #76 remains the open epic; §9 marks what landed and what is still deferred.
- Date: 2026-07-11 (implementation notes 2026-07-25; rebuilt on the ADR-0042 wire
  2026-07-27)
- Implementation record: the [ADR-0038 amendments](../adr/0038-configurable-multi-hop-relay-chaining.md),
  which are authoritative where they differ from this document. Two of this
  document's original assumptions are **superseded**:
  - §4.1 assumed the coordinator-assigned relay `R₁` peels the outermost layer. It
    cannot: Noise_NK needs the responder's key up front, and the client is never told
    which relay it was assigned (#56/ADR-0035). The client names its own first
    PEELING hop; the assigned relay blind-splices to it unchanged.
  - The client named that hop in `connect{exitId}` until ADR-0042 removed the
    client's ability to name an exit at all. It now names it in `connect{firstHop}`,
    the field [ADR-0042 §9](../adr/0042-country-only-exit-assignment.md) reserved,
    and resolves its own terminating exit from the signed snapshot. See §0.2.
- Track: transport coverage / resilience (extends M2)
- Companion decision record: [ADR-0038](../adr/0038-configurable-multi-hop-relay-chaining.md)
- Builds on: [ADR-0033](../adr/0033-prefer-peer-relays-over-turn-for-the-data-plane.md)
  (single-hop peer relay), [ADR-0028](../adr/0028-transport-pool-and-per-user-failover.md)
  (selection ladder, the relay tier), [ADR-0009](../adr/0009-end-to-end-encryption-client-to-exit.md)
  (client↔exit Noise_NK), [ADR-0026](../adr/0026-end-to-end-exit-admission-verification.md)
  (E2E exit-admission verification), [ADR-0037](../adr/0037-mesh-walk-recovery-via-signed-peer-exchange.md)
  (signed directory snapshot the client selects from),
  [ADR-0042](../adr/0042-country-only-exit-assignment.md) (the connect wire this is
  built on).

---

## 0. Orientation — read this first

This section is the whole feature in one page. §§1–11 are the reasoning behind it.

### 0.1 What problem it solves, and what it does not

Today's relayed path has **one** relay in it. That relay is your transport peer, so
it sees your address; the coordinator told it your exit's address, so it sees that
too. It cannot read your traffic or learn your destination — those are inside the
client↔exit Noise channel — but it knows **who is talking to whom**.

Relay chaining routes that path through several nodes so that no single one of them
holds both ends. It buys you exactly one property:

> **Unlinkability of client↔exit from any single participating node.**

It does **not** hide you from an adversary who can watch every link at once and
correlate timing and volume. No low-latency system does; Tor has the same limit. And
it does not hide your address from the first node in the path — something always
sees that. See §7 for the full honest list, and §0.5 for what is enforced by code
versus what is currently only intended.

### 0.2 How a chain is built, end to end

Depth `n` counts every node between you and your exit. One of them is the
coordinator's blind-splicing relay; the other `n-1` are hops you chose and can peel
a layer at.

```
client ──► R₁ ──► H₁ ──► … ──► Hₙ₋₁ ──► exit ──► the internet
           ▲       ▲                       ▲
   coordinator   you chose these        you chose this
    chose this   from the signed        from the signed
                 directory              directory
```

1. **You resolve your own exit.** `chooseChainExit` picks one at random from the
   exit-role entries of the signed directory that are in the country you asked for.
   Random, not "best": a deterministic rule would give every client the same answer
   for a given country, which is a fingerprint and a load magnet.
2. **You pick the hops.** `selectHops` shuffles the directory with `crypto/rand`,
   takes a head that the coordinator can pair you with, then fills the rest,
   preferring operator-distinct nodes. Your exit is excluded — a chain that doubles
   back through its own exit hides nothing.
3. **You ask the coordinator for the head, and only the head.**
   `connect{firstHop: H₁, mode: "relay"}` — no country, no exit. It pairs you with
   `H₁` through a peer relay `R₁` and mints a session recording **no** terminating
   exit, because it does not know one.
4. **You check what came back.** The reply must be a genuine peer relay (a TURN
   fallback fails the attempt), and `R₁` must not be one of your own hops
   (`verifyChainDisjoint`). Either failure fails the path — it never downgrades.
5. **You telescope the onion.** `dialChain` runs Noise_NK against `H₁` over the
   transport, tells it only `hop:<H₂'s address>`, then runs Noise_NK against `H₂`
   *through that tunnel*, and so on. The last layer is the ordinary
   `clientHandshake` to your exit, carrying the real destination and verifying the
   exit's admission credential (#60/#69) exactly as an unchained connection does.

Each hop decrypts precisely one layer, learns one address — its successor — and
splices the rest onward as bytes it cannot read.

### 0.3 Why the onion starts at a hop you named

Noise_NK authenticates the responder by a static key the initiator supplies **before
the handshake**. So you can only peel at a node whose X25519 key you already hold.

You do not hold `R₁`'s. The coordinator names it to you only as `wire.RelayTag`, a
non-routable digest (#56, ADR-0035) — deliberately, so that a rotating client cannot
be handed a map of the relay fleet. `R₁` therefore **cannot** be a peeling hop, and
the onion has to begin one node further in, at a node you selected yourself.

That is why `firstHop` exists on the wire at all. It is the minimum the coordinator
needs to wire you to a node of your choosing, and it is deliberately the *only* node
of the path it learns.

### 0.4 How the directory is obtained and trusted

Every node id in this design **is** an X25519 public key (ADR-0009/#12), so "trusting
the directory" means exactly "trusting the mapping from ids to addresses".

- It is a `coldstart.Snapshot`, **signed** by the coordinator's snapshot-signing key,
  distributed by `cmd/coldstart-bootstrap -cache` and by mesh-walk couriers (ADR-0037).
- The client verifies the signature against `-mesh-pubkey` and **rejects an expired
  one** — unlike the mesh-walk proof-of-prior-contact, which is legitimately stale. A
  hop directory names nodes that are supposed to answer a dial right now.
- A tampered directory cannot forge a hop: it could name a wrong *address* for a
  real id, but the node at that address will not hold the key, and the layer's
  handshake fails. It could substitute both id and address, which is why the
  signature matters.
- It is loaded **once, at construction**. See the rough edge in §10.

### 0.5 What is enforced, and what is not

The distinction matters more here than in most features, because a user acts on
these properties. "Enforced" means code fails the path when it is violated.

| Property | Status |
|---|---|
| Each hop learns only its two neighbours | **Enforced** by the construction — Noise_NK layers, one peel per hop |
| The client↔exit admission check (#60/#69) survives the chain | **Enforced** — the innermost layer is the unmodified handshake, bound to the exit key from the plan |
| A substituted hop cannot complete its layer | **Enforced** — `PeerStatic` is the directory-published id |
| The coordinator is never told the terminating exit | **Enforced** — it is on no wire, in any mode; the direct tier is disabled while chaining |
| Failure never silently shortens the chain | **Enforced** — every failure fails the path; a depth above the cap is refused at construction |
| A relay is never an open proxy | **Enforced** — forwards only to an address in the signed directory, and never to itself |
| `R₁` is not also one of the chain's hops | **Enforced against an HONEST coordinator only** — see §7 |
| Two hops are not run by the same operator | **NOT enforced today** at depth 2 (one peeling hop, nothing to differ from), and **inert on any deployment without a curated operators file** — see §6 |
| Two hops are not in the same AS | **NOT enforced today** — no implementation; §9 item 4 |
| An intermediate hop is rate-limited | **NOT enforced today** — traffic is metered but uncapped; §9 item 7 |
| A hop presents a relay-role admission credential | **NOT enforced today** — the wire seam exists, the client passes `nil`; §9 item 8 |

### 0.6 Where the code is

| Concern | File |
|---|---|
| Directory loading, hop + exit selection, the onion dial, the relay peel | `core/relaychain.go` |
| Where a chained request differs on the wire | `core/client.go` — `connectReq`, `attemptWith` |
| Honouring `firstHop` | `cmd/coordinator/assign.go` — `resolveFirstHop`; `cmd/coordinator/main.go` — the `connect` handler |
| The acceptance test, through the real `New()` | `core/relaychain_acceptance_test.go` |
| The coordinator's half | `cmd/coordinator/firsthop_test.go` |
| A dependency-free demonstration of the crypto alone | [`cmd/relaychain-probe`](../../cmd/relaychain-probe/README.md) |

---

## 1. Problem statement

Today the relay tier is **single hop**. When a client cannot hole-punch a direct
path to its exit, the coordinator picks one relay node, hands it the exit's TCP
ingress address (`assign{ExitAddr}`), and the relay blind-splices ciphertext
between the client and the exit (`core/forwarder.go` `relayPipe`; ADR-0033). One
relay carries the whole relayed data plane, and — because the coordinator told it
the exit and it sees the client as its transport peer — **that one relay sees both
endpoints of the connection** (the client's source address and the exit's address).
It cannot see *content* or the internet *destination* (those live inside the
client↔exit Noise_NK channel, ADR-0009), but it can see *who is talking to whom* at
the Bacchus layer.

For most users on most days that is an acceptable trade: the relay is a blind
ciphertext forwarder, and the exit — not the relay — is the party the client
authenticates and admission-verifies end to end (#60/#69). But a user who needs
their **client↔exit relationship** unlinkable from any single relay (a
higher-assurance posture, matching the "stable tier" in the cold-start trust model,
[rendezvous-cold-start.md §5.1](rendezvous-cold-start.md)) has no way to ask for it.

**Issue #76** adds a **configurable number of relay hops**: route the relayed data
plane through a *chain* of relays `R₁ → R₂ → … → Rₙ` so that no single relay sees
both the client and the exit, while keeping the client↔exit end-to-end guarantees
exactly as they are today. The number of hops is a knob whose **default is 1**, i.e.
today's single-hop relay — so the feature is a strict, safe superset of current
behaviour with zero regression when unset.

This is the relay-tier depth referred to as "node count" in the client UI work
(#75/ADR-0036) and the transport pool (ADR-0028): the selection ladder already has a
"route through nodes" tier; #76 makes that tier *n* nodes deep instead of one.

---

## 2. Threat model

The system's standing adversaries (from [threat-model.md](threat-model.md) and
[rendezvous-cold-start.md §2](rendezvous-cold-start.md)) that this design must answer:

| # | Adversary | What multi-hop must guarantee |
|---|---|---|
| T1 | **Hostile / compromised coordinator** (ADR-0020 §5.6: the apex, assumed possibly-hostile since #60) | It cannot force a chain that deanonymizes or MITMs the user (requirement (a)). |
| T2 | **Hostile single relay** (any one hop is untrusted) | No single relay learns *both* the client and the exit/destination; it cannot read or forge content (requirement (b)). |
| T3 | **Colluding relays** (a Sybil running several hops) | Bounded: correlation requires controlling the *first and last* hop of the chain; hop selection makes that expensive (§6). |
| T4 | **Amplification / resource abuse** (a client or censor abusing the relay tier) | Bounded chain length, 1:1 (non-amplifying) forwarding, and relay-side rate limits (§6). |

**What onion chaining defends, precisely.** For a chain of `n ≥ 2` relays, **and
provided the coordinator's assigned relay `R₁` is not also one of the peeling hops**
(a proviso that is enforced against an honest coordinator and not against a hostile
one — §7):

- The **first** relay `R₁` sees the client's transport source address and the address
  of `R₂` — never the exit or the destination.
- The **last** relay `Rₙ` sees `Rₙ₋₁` and the exit's ingress address — never the client.
- Any **middle** relay `Rᵢ` sees only `Rᵢ₋₁` and `Rᵢ₊₁` — neither endpoint.
- The **exit** sees `Rₙ` and the destination and the client's admission demand — never
  the client's address (already true for single-hop relay mode today).
- **No hop, and not the coordinator, can read or alter the content** — every hop
  forwards ciphertext, and the innermost client↔exit Noise_NK channel terminates only
  at the exit (§4.3).

**What it does *not* defend against (stated honestly, §7).** A **global passive
adversary** who can observe traffic at every link and correlate timing and volume can
still link a low-latency chain end to end — this is the well-known limit of
low-latency onion routing (Tor shares it), not a solvable property for an
interactive VPN. Multi-hop raises the bar against *individual* malicious relays and a
hostile coordinator; it does not claim traffic-analysis resistance against an
omniscient observer.

---

## 3. Design principles

1. **Reuse the handshake, don't invent a protocol.** A chain is the existing
   Noise_NK client↔exit handshake (`core/e2e.go`) run once per hop. Each relay hop is
   the existing "read an encrypted target, dial it, splice ciphertext" behaviour
   (`exitTerminate`) pointed at the next Bacchus node instead of the internet. New
   crypto is a risk; nesting a reviewed primitive is not.
2. **The client assembles the chain; the coordinator never picks the path.** Path
   choice is client-side policy selecting from the coordinator-**signed**,
   pool-cross-checkable directory — the same trust posture that already moved *exit*
   authorization to the client end-to-end (ADR-0026). A hostile coordinator that
   picked your hops could pick all-colluding ones; denying it that choice is the core
   of requirement (a).
3. **Default 1 = today.** Hop count 1 is byte-for-byte the shipped single-hop path
   (ADR-0033) — the onion mechanism engages only at `n ≥ 2`. The feature is a strict
   superset; an unset knob changes nothing (requirement (c)).
4. **A relay is never an exit.** An intermediate relay forwards only to *another
   Bacchus node*, never to an arbitrary internet destination — preserving the
   mandatory relay/exit safety line (rendezvous-cold-start §5.3: a relay forwards
   ciphertext and never egresses under the user's IP). Only the exit egresses.
5. **Every hop is authenticated by a key the client chose.** Each hop runs Noise_NK
   with `PeerStatic` = that node's directory-published X25519 id (a node id *is* its
   public key, #12/#60). A coordinator cannot substitute a hop it controls without
   holding that hop's private key.
6. **Onion cost is paid in volunteer bandwidth, opt-in.** `n` hops cost `n×` relay
   bandwidth per unit of user traffic; that cost falls on the volunteer mesh, so the
   depth is a user-chosen anonymity/throughput trade, defaulted to the cheapest (1).

---

## 4. Architecture

### 4.1 The core construction — nested Noise_NK (onion) layers

A chain is `n` **nested** Noise_NK tunnels. From the inside out:

```
innermost   client ⇄ exit     Noise_NK, target = real destination, exit presents admission cred (#60/#69)
   layer n  client ⇄ Rₙ       Noise_NK, target = exit ingress addr
     …
   layer 1  client ⇄ R₁       Noise_NK, target = R₂ ingress addr
  transport client → R₁       reality / webrtc underlay + coordinator rendezvous (the one censored hop)
```

The insight that makes this cheap: `core/e2e.go`'s `noiseConn` is already documented
to work "whether raw is message-oriented (a WebRTC data channel) or a byte stream
(the relay's TCP hop, which flattens message boundaries)" — it re-delimits frames
from an opaque byte stream. So a `noiseConn` can run **over another `noiseConn`**: the
client stacks them.

**Client side — telescoping build (Tor-style circuit construction).** The client
holds a `raw` transport session to `R₁` (§4.6). It then, per hop:

1. Runs Noise_NK **initiator** over the current innermost stream with the next node's
   directory key, obtaining a `*noiseConn` (this is exactly what `clientHandshake`
   does today).
2. Sends the *encrypted target*: for an intermediate hop the target is the **next
   hop's ingress address**; for the innermost (exit) hop it is the **real
   destination** (or the `probe`/`udp:`/`acct` sentinels, unchanged).
3. Treats that `noiseConn` as the `raw` transport for the *next* handshake.

After `n+1` handshakes (n relays + the exit) the client has an innermost `noiseConn`
that is the *unchanged* client↔exit channel; it writes the real target into it and
carries application bytes over it. Each handshake for `Rᵢ` and its target travels
**inside** the tunnel to `Rᵢ₋₁`, so `Rᵢ₋₁` transports those bytes as opaque
ciphertext and cannot read them.

**Relay side — one peel + splice.** Each relay runs a TCP ingress; on an inbound
connection it behaves like a generalization of `exitTerminate`:

1. Noise_NK **responder** with its own static key (authenticating itself to the
   client by the very key the client selected from the directory).
2. Read the encrypted target = the next hop's ingress address.
3. Dial the next hop, and **splice raw** — `io.Copy` between the decrypted layer and
   the next hop's socket, exactly as `relayPipe` / `exitTerminate` splice today. The
   bytes it decrypts from its layer *are* the next hop's handshake and traffic, which
   it forwards without understanding.

The relay peels exactly one layer and forwards the inner ciphertext. It never sees
more than its two neighbours.

**Exit side — unchanged.** The exit is the innermost responder: it runs
`exitTerminate` verbatim — Noise_NK with its exit key, presents its admission
credential in msg2 (#60), reads the real target, dials the internet, splices. It
cannot tell how many relays the connection crossed, and does not need to.

> The feasibility probe ([`cmd/relaychain-probe`](../../cmd/relaychain-probe/README.md))
> implements exactly this stacking with the real `flynn/noise` handshake and asserts
> the peel property in-process.

### 4.2 Chain assembly — **client-assembled** (requirement (a))

**Decision: the client assembles the chain. The coordinator never chooses the
intermediate hops.**

The client selects `R₁ … Rₙ` and the exit from the coordinator-**signed** directory
snapshot (`core/coldstart.Snapshot`, the same artifact the cold-start bootstrap,
coordinator pool, and mesh-walk courier already distribute and the client already
re-verifies, ADR-0013/0037). Selection is client-side policy (§6, an extension of the
ADR-0028 ladder). The coordinator's role shrinks to the two things it already does
and is already assumed possibly-hostile for:

- **Serve the signed directory.** Tamper-evident: a lying coordinator's snapshot
  diverges from its pool peers' and is detectable by cross-check (rendezvous-cold-start
  §5.6). It cannot forge a relay's identity key.
- **Broker the *first hop only*.** Client↔R₁ rendezvous/NAT-traversal is the existing
  `connect{mode:"relay"}` exchange — the coordinator already sees client↔R₁ in
  single-hop mode, so this leaks nothing new. It learns **nothing** about `R₂…Rₙ` or
  the exit, because those are chosen by the client and named only *inside* the onion.

**Why client-assembled defeats the hostile coordinator (T1):**

1. *It cannot force a colluding path.* The coordinator does not pick `R₂…Rₙ`; the
   client does, and encrypts each hop's next-address to that hop's key. Even a
   coordinator that fills the directory with Sybil relays cannot choose *which* of
   them a given client strings together, and the client's AS/operator-diverse random
   selection (§6) spreads the choice.
2. *It cannot MITM a hop.* Every hop is Noise_NK-authenticated to a directory key the
   client selected; the coordinator holds no hop's private key. A substituted hop
   fails its handshake.
3. *It cannot MITM the exit.* The exit is admission-verified end-to-end (#60/#69)
   *through* the chain (§4.3): a hostile exit id the coordinator names is rejected
   before a byte of traffic is sent, at any chain length.
4. *The client can even split trust across the pool.* It may fetch the directory from
   one coordinator and rendezvous the first hop through another (coordinator pool,
   ADR-0020), so no single coordinator both defines the candidate set and sees `R₁`.

**Rejected alternative — coordinator-assembled.** If the coordinator chose the chain
(the natural extension of today's `pickRelay`), a hostile coordinator would select an
all-colluding chain on *every* connect and deterministically deanonymize the user,
who could not tell a good chain from a bad one. That collapses requirement (a)
entirely. Coordinator-assembly is categorically weaker and is rejected. (It is
tolerable at hop **1** only because a single relay sees both endpoints regardless of
who picked it — there is no path-anonymity property to protect at n=1, which is why
today's `pickRelay` is fine and stays unchanged, §4.4.)

### 4.3 Per-hop crypto and E2E survival (requirement (b))

Two authentication guarantees ride the chain, and **neither depends on the
coordinator being honest**:

**(1) The client↔exit end-to-end channel is byte-identical to today.** The innermost
layer *is* the existing `clientHandshake`/`exitHandshake` Noise_NK exchange
(`core/e2e.go`). The exit presents its `AdmissionCred` in msg2's Noise payload; the
client's `verifyExit` predicate (`core/exit_admission.go`, #60/#69) checks the
signature under the admission root, `subject == hex(exitPub)`, exit role, validity
window, and CRL — and **aborts before the target is sent** if the exit is not
authorized. Because every relay only splices ciphertext, this handshake is
*bit-for-bit the same* whether it crossed 0, 1, or n relays. This is the identical
argument ADR-0033 makes for single-hop (`TestPeerRelaySplicePreservesE2E`), now
extended to arbitrary depth: **onion layering is outside the E2E channel, so #60/#69
survive the chain intact by construction.**

**(2) Each relay hop is authenticated too.** The client runs Noise_NK against each
relay with `PeerStatic` = the relay's directory-published id, so a relay (or a
coordinator substituting one) that does not hold that private key cannot complete the
hop. This is stronger than today's single-hop splice, where the relay is *not*
individually authenticated by the client (it is a blind L4 pipe chosen by the
coordinator) — multi-hop authenticates every hop because the client, not the
coordinator, is stringing them together.

- **Relay admission (optional, v1-deferrable).** The #60 machinery generalizes: an
  intermediate relay MAY present a *relay-role* admission credential in its layer's
  msg2, and the client MAY verify `role == relay` under the same admission root. This
  extends hostile-node rejection from exits to relays. v1 can ship with hop
  authentication by directory key alone (a hop is only usable if the client trusts the
  directory that named its key) and add per-hop admission-cred verification as a
  follow-up (§9). The wire seam (a cred in msg2) already exists.

**Ordering of checks.** Each layer is verified as it is built, outermost first, so a
bad `R₁` fails before the client ever tunnels to `R₂`; the exit's admission check is
last (innermost) and still gates sending the real destination. A failure at any layer
aborts the whole build and the chain is retried with fresh nodes (§5).

### 4.4 The hop-count knob (requirement (c))

A single configuration value — the **number of relay hops**, call it `RelayHops`
(`core/engine.go` `Config.RelayHops`, `-relay-hops` flag, and the "route through N
nodes" GUI control from ADR-0036) — with:

- **Default `1`.** Identical to today: the coordinator's existing `pickRelay` assigns
  one relay via `assign{ExitAddr}` and `relayPipe` blind-splices (ADR-0033). **The
  onion path (§4.1) is not engaged at all.** Zero new code path, zero regression — an
  unset knob is exactly the shipped behaviour. This is the strict-superset guarantee.
- **`n ≥ 2`.** The client builds an n-hop onion (§4.1) inside the `ModeRelay` tier.
- **Hard upper bound `RelayHopsMax`** (`4`; §6). A value above the cap is **refused
  at construction** — the node does not start and says why. It was clamped with a
  logged notice until #142's rework, which is the silent downgrade this design
  otherwise forbids everywhere: an operator who asked for 6 hops and was given 4
  without failing has been handed a weaker path than the one they requested.
- **`0` is not "no relay".** Hop count applies only once the selection ladder has
  reached the relay tier; direct modes are unaffected. `0`/`1` both mean "one relay
  when relaying", preserving the today-semantics; only `≥ 2` opts into chaining.

Why 1 stays on the *old* path rather than a 1-hop onion: a 1-hop onion (client tells
`R₁` the exit address over Noise) would be functionally equivalent to today but would
add a handshake at `R₁` and make `R₁` terminate a Noise layer instead of blind-
splicing — a behaviour change for no anonymity gain (a single relay sees both
endpoints either way). Keeping n=1 on the proven `relayPipe` path is the
zero-regression choice; the onion is strictly the `n ≥ 2` opt-in.

### 4.5 Composition with existing tiers and underlays (requirement (d))

- **#17 peer relay (ADR-0033).** Multi-hop is a **strict generalization** of it:
  hop count 1 *is* ADR-0033, unchanged. `n ≥ 2` chains the same peer-relay concept.
  The transparent-splice invariant ADR-0033 rests on is exactly what lets the layers
  nest.
- **The `ModeRelay` last-resort tier (ADR-0028).** The chain lives **inside**
  `selection.ModeRelay` — the ladder's tier structure (`Ladder()` in
  `core/selection`) does not change: direct-primary → direct-alternate → relay is
  still the order, and relay is still the last resort. What changes is that when the
  connection manager (`core/pool.go`) builds a `ModeRelay` candidate and `RelayHops ≥
  2`, it builds an n-hop chain instead of a single hop. The `Candidate` type keeps
  `{Transport, ExitID, Mode}`; hop count is engine config, not a per-candidate field
  (every relay candidate for a given run uses the same configured depth). Learned-path
  memory (`selection.Store`) remembers "relay worked here" as it does now; it does not
  persist a specific ephemeral chain (§5).
- **reality / TURN underlays.** Orthogonal. The onion layers ride **on top of**
  whatever transport carries the **first** hop: the client↔R₁ leg uses the ladder's
  chosen transport (webrtc or reality, ADR-0024/0028) and the coordinator's
  rendezvous, with TURN as the ICE fallback *for that first hop only* if hole-punch
  fails (ADR-0033). Hops `R₁→R₂→…→exit` are node-to-node over the node TCP ingress
  (the same ingress the exit runs today, `serveExit`). So underlay selection and chain
  depth are independent axes: the underlay defends the one censored hop; the onion
  layers add path-anonymity above it.
- **Mesh-walk / directory (ADR-0037).** The chain is selected from the same signed
  `Snapshot`. Multi-hop needs one thing the snapshot does **not carry yet** — each
  relay's *forwarding ingress address and AS/operator tag* — which is precisely the
  "courier address auto-advertisement" seam ADR-0037 already named as deferred. §9
  files it; until then intermediate hops are operator-configured/directory-anchored.

### 4.6 First-hop rendezvous vs. intermediate dialing (the NAT model)

A residential relay behind NAT cannot accept an inbound TCP connection. The chain
resolves this the way Tor does — **only the client is assumed un-dialable**:

- **First hop (client → R₁): coordinator-brokered, over a disguised underlay.** Uses
  the existing `connect{mode:"relay"}` rendezvous and NAT-traversal (WebRTC/ICE, TURN
  fallback). A NAT'd residential relay is fine as `R₁` because the client reaches it
  via hole-punching, exactly as single-hop relay works today.
- **Intermediate and final hops (Rᵢ → Rᵢ₊₁ → … → exit): a direct outbound TCP dial to
  a reachable ingress.** Each hop dials the next hop's advertised ingress. This needs
  the next hop to be **publicly reachable** (a dialable ingress, like the exit's
  `serveExit` today). So **intermediate hops must be reachable nodes**; NAT'd
  residential nodes can serve as the **first hop** (reached by hole-punch) or the
  **exit** (reached by the last relay's outbound dial to the exit's public ingress),
  but not as a *middle* hop in v1.

  This keeps the coordinator blind to the path (every hop after the first is a plain
  outbound dial the coordinator never sees) at the cost of requiring reachable
  intermediate nodes. Hole-punched relay-to-relay hops (to allow NAT'd middle nodes)
  would reintroduce per-hop coordinator brokering — leaking the path back to the
  coordinator — and are explicitly deferred (§9). The reachable-intermediate
  constraint mirrors Tor's "relays are publicly reachable; clients need not be" and is
  the right v1 line.

---

## 5. Failure and latency model (requirement (e))

**Latency.** Each hop adds one relay's worth of RTT to the path. A direct connection
is `client↔exit`; an n-hop chain is `client→R₁→…→Rₙ→exit→dest`, so end-to-end latency
grows roughly linearly in `n`. Circuit **construction** also costs `n+1` sequential
Noise_NK handshakes (telescoping is inherently sequential — each layer is built
through the previous), so setup latency is `~(n+1)` round-trips along the growing
path. This is the concrete price of the anonymity/throughput trade the knob exposes,
and the reason the default is 1.

**Chain death — reuse the #105/#106 failover machinery, split by who can see the
failure:**

- **First hop `R₁` dies.** `R₁` is the coordinator-brokered relay, so the coordinator
  knows its id and heartbeat and the existing `reselectDeadRelays` sweep (#96/#105)
  already nudges the client to re-establish when it goes stale. The client's own
  transport teardown to `R₁` (auto-reconnect, ADR-0030) is the other trigger. Either
  way the client rebuilds the chain.
- **A downstream hop `R₂…Rₙ` or the exit dies.** The coordinator **cannot** see these
  (it does not know they are in the path — that is the point), so recovery is
  **client-driven**: the innermost client↔exit channel stalls, and the client detects
  it exactly as ADR-0028's "connected ≠ working" defence already does — the sustained-
  flow probe (`probeSentinel`, a ~32 KB echo round-trip over the E2E channel) fails,
  and the pool tears the path down and rebuilds. A dead middle hop is indistinguishable
  from a dead exit to the client (both surface as an E2E stall), which is fine: the
  response to either is the same — rebuild the chain.
- **Rebuild = a fresh chain, not a repair.** Like Tor, a broken circuit is discarded,
  not spliced. The client selects a fresh set of hops (the failed nodes sink in the
  health memory / cooling set, `selection` `Cooling`) and telescopes a new chain. No
  attempt is made to reroute around a single dead middle hop in place (it would require
  re-keying downstream layers and leak which hop died).

**What is persisted.** The `selection.Store` learned-winner memory records that the
*relay tier at depth n* worked for this network+geo, so the client starts there next
time — but it does **not** persist the specific node ids of a chain (they are
ephemeral, may be offline or freshly cooling, and re-pinning them would concentrate
load and metadata). Each connect telescopes a fresh chain from the current directory.

---

## 6. DoS, amplification, and Sybil bounds (requirement (f))

**Bounded chain length.** `RelayHopsMax` (proposed 4) caps depth. The client clamps
its own knob; it cannot be coerced into a longer chain because *it* builds the onion
(a coordinator cannot inject extra hops — it never sees or writes the inner layers).
A cap of 3–4 is well past the point of diminishing anonymity returns for a low-latency
system and keeps the volunteer-bandwidth multiplier small.

**No amplification.** Onion forwarding is **1:1** — every hop reads `x` bytes of
ciphertext and writes `x` bytes onward, with no response inflation. There is no
reflection/amplification vector (unlike DNS/NTP): a relay cannot be turned into an
amplifier because it emits exactly what it receives. The DoS surface is *bandwidth
consumption*, not amplification.

**Who bears the cost.** An n-hop chain consumes `n×` relay bandwidth for `1×` of user
traffic; that cost falls on the **volunteer mesh** (the relays), which is why depth is
an opt-in knob defaulted to the cheapest value. This is the honest framing of the
trade: more hops = more unlinkability = more volunteer bandwidth burned per user.

**Relay-side controls (a relay protects itself):**

- **Forward only to a Bacchus node (principle #4).** An intermediate relay must
  **not** become an open internet proxy. It constrains its dial target to a node it
  can recognize from its cached signed directory (`coldstart.SnapshotCache`, already
  held for the mesh-walk courier role, ADR-0037) — i.e. it forwards to known mesh
  ingresses, not arbitrary `host:port`. This both preserves the relay/exit safety line
  and bounds abuse. (This depends on ingress addresses being *in* the snapshot — the
  ADR-0037 deferred seam, §9.)
- **Rate-limit per previous hop and in aggregate.** A relay caps concurrent forwarded
  circuits and bandwidth per inbound peer and overall, shedding load rather than
  amplifying a flood. Intermediate relays cannot see the client (onion), so limits are
  keyed on the *previous hop* and on totals.
- **Integrity probes (rendezvous-cold-start §5.5).** The planned coordinator canary
  flows that check a relay forwards faithfully apply unchanged to chained relays.

**Sybil surface.** Multi-hop *raises* the incentive to run many relays, because
controlling the **first and last** hop of a chain re-links client↔exit (classic
end-to-end correlation). Defences, all reusing planned/existing machinery:

- **AS/operator-diverse hop selection.** The client must not place two hops of one
  chain in the same AS / operator / vouch-subtree, and should maximize diversity
  across the chain — the same AS-diversity checks §5.5 already calls for against exit
  eclipse. This is the primary anti-correlation control and it lives in client-side
  selection (§9 files it).

  **How far the shipped version actually goes, which is not far.** `selectHops`
  prefers operator-distinct hops and falls back to allowing a repeat rather than
  refusing to connect. Three limits, none of them cosmetic:

  1. It constrains a *pair*, so at depth 2 — one peeling hop — it does nothing at all.
  2. `operators[id]` is `""` for any node the coordinator has no assignment for, and
     two empty tags are never treated as a collision. On a deployment with no curated
     operators file the control is **inert**, not merely weak. That is a deliberate
     choice over the alternative, which is refusing to build chains on an uncurated
     network — but it means "operator diversity is enforced" is false as a general
     statement, and this document said it for two revisions.
  3. It was worse than that until #142's rework: the coordinator stamped the operator
     tag on relay entries only, and a chain head must be exit-role, so the head was
     never labelled and never collided against. Exits now carry the tag.

  The AS half — deriving each hop's AS from its **observed** ip against an independent
  routing table, client-side — is the load-bearing one and is **not implemented**.
  Until it lands, one operator spread across several unlabelled entries is undetected.
- **Vouch + tenure (rendezvous-cold-start §5.4).** Running many *diverse, tenured,
  vouched* relays is exactly what the Sybil-resistant admission ladder makes slow and
  costly; multi-hop leans on it rather than re-inventing it.
- **Random, non-persisted chains (§5).** Fresh random selection per connect denies a
  Sybil a fixed target and spreads observation, the same reasoning that keeps
  `pickRelay` random (ADR-0033).

---

## 7. What this explicitly does NOT provide (honest limits)

- **No defence against a global passive adversary.** Low-latency onion routing cannot
  hide end-to-end timing/volume correlation from an observer who sees every link
  (§2). Multi-hop targets malicious *participants* (relays, coordinator), not
  omniscient *observers*. We do not claim traffic-analysis resistance.
- **First hop still sees the client.** `R₁` always learns the client's transport
  source address (it is the transport peer). Multi-hop hides the *exit* from `R₁`, not
  the client from `R₁`. Hiding the client's address from the first hop is what the
  disguised underlay + the client's own network position do, not what the onion does.
- **Coordinator still sees client↔R₁, and now also client↔H₁.** First-hop rendezvous
  is coordinator-brokered, as today, and a chaining client additionally names its
  chain head in `connect{firstHop}`. So the coordinator learns *two* nodes of the
  path rather than one — the relay it assigned and the head you chose — and never the
  exit or any hop after the head. Naming the head is unavoidable: it is how you are
  wired to it. It is not a tracking handle, because the head is drawn fresh from a
  shuffled candidate set on every connect and is by construction not the node you
  egress from.
- **A hostile coordinator can still collapse the chain, and you cannot detect it.**
  `R₁` is coordinator-chosen and the client never learns its identity. If the
  coordinator assigns an `R₁` that is also one of your peeling hops, that one node
  sees your address (as `R₁`) and its hop's successor — and when the collision is
  with the LAST hop, its successor is your exit. One node, both ends.

  The client closes the *accidental* case: `wire.RelayTag` is a published function
  of a node's id (`relayTagFor`), so the client recomputes it for every hop it
  selected and fails the path on a match. This matters because an honest coordinator
  really can collide — `pickRelay` excludes only the node it paired, never the
  client's later hops, which it cannot see.

  It cannot close the *deliberate* case. A coordinator that wants the collision
  reports a tag that does not match the relay it wired, and no client-side signal
  contradicts it. **Against a coordinator actively colluding with a node in your
  path, this design's unlinkability property does not hold, at any depth.** Closing
  it needs a relay identity the client can verify independently of the coordinator's
  say-so — filed as §9 item 10 / issue #190.
- **n=1 is unchanged, including its exposure.** At the default depth a single relay
  sees both endpoints — that is today's accepted behaviour, not a regression. Users
  who need the stronger property opt into `n ≥ 2`.
- **Chaining disables direct paths.** A direct path has no relay in it to build an
  onion on, so a chaining client is not offered the direct tier at all. This costs
  latency and costs you the tier that works when no relay is free — a real
  availability trade, made deliberately, because the alternative is a client that
  silently connects unchained while believing otherwise.

---

## 8. Feasibility probe

[`cmd/relaychain-probe`](../../cmd/relaychain-probe/README.md) is a throwaway,
dependency-free demonstrator (mirroring `cmd/coldstart-probe`) that answers the one
question the design hinges on before any production wiring exists:

> **Do nested Noise_NK layers peel exactly one-per-hop, so that each relay learns only
> its two neighbours while the innermost client↔exit target and admission credential
> survive the full chain intact?**

It builds a client, `k` relays, and an exit — each with a real X25519 keypair — wires
them with in-memory pipes, telescopes the onion with the real `flynn/noise` handshake
(already a module dependency; no new dep, and using the *actual* primitive is the
honest test), and asserts:

- each relay recovers **only** its next-hop address, never the destination or the
  client;
- the exit recovers the real destination **and** verifies a stand-in admission
  credential — proving #60/#69 rides through the chain;
- flipping one relay's key (a substituted/hostile hop) makes that hop's handshake
  fail, never silently corrupting downstream layers.

It imports no `core/` package and touches no production file, so it is reviewable as
part of the design. It is *not* a network reachability test (that is future work with
real nodes) — it validates the cryptographic construction only.

---

## 9. Deferred → child implementation issues to file

This spike decides the shape; the build is deliberately split into file-disjoint,
independently-reviewable issues (as the cold-start spike split into #29/#30/#31/#32).

**Status after issue #142 (2026-07-25).** Items 1, 2 and 5 **landed**, item 3 landed
earlier with #124/#126, and item 4 landed **only in its operator-tag half**. Items 6,
7, 8 and 9 remain open and are filed as child issues of #76. What #142 shipped:

| § | Item | Status |
|---|------|--------|
| 1 | Relay onion-forward handler + ingress | **Shipped** — the `hop:` branch of `exitTerminate`, `relayForward`, and the `RelayIngress` listener. Forwarding is admitted only to an address in the node's signed directory, and a relay-only node refuses to egress at all. |
| 2 | Client-side chain construction | **Shipped** — `core/relaychain.go`'s `buildChain` + `dialChain`, reached through the single `dialE2E` seam so SOCKS CONNECT, UDP ASSOCIATE, and the pool probe all chain alike. |
| 3 | Directory: relay ingress + operator metadata | **Shipped earlier** (#124/#126, the ADR-0038 #124 amendment). |
| 4 | AS/operator-diverse hop selection | **Barely shipped, and weaker than this document originally claimed.** Operator diversity is applied where a tag exists, but it constrains a *pair* of hops, so it does nothing at depth 2 — the depth most clients will run — and `operators[id]` is empty for every node absent from the coordinator's curated operators file, so on an uncurated deployment it is **inert, not merely weak**. The IP-derived AS diversity the #124 amendment calls the load-bearing anchor is **not implemented**. Stays a child issue. |
| 5 | Hop-count knob + config surface | **Shipped** for core and `cmd/node` (`Config.RelayHops` / `-relay-hops`, default 1, refused above `RelayHopsMax`). The ADR-0036 GUI control is **not** wired and stays a child issue. |
| 6 | Chain liveness + rebuild | **Open.** A dead hop currently surfaces as an end-to-end stall and rebuilds through the existing ADR-0028/ADR-0030 machinery — correct, but not chain-aware. |
| 7 | Relay-side DoS controls for onion forwarding | **Open.** Forwarding is metered per ADR-0040 and a hop refuses to dial itself, but there is no per-previous-hop circuit or bandwidth cap, and nothing bounds a ring of nodes pointed at each other (#174). |
| 8 | Per-hop relay admission-cred verification | **Open.** The wire seam exists (every responder presents its credential in msg2); the client passes `nil` for hop layers today. |
| 9 | NAT-traversed intermediate hops | **Open, and still a non-goal** to revisit only if reachable intermediate capacity proves insufficient. |
| 10 | Coordinator-independent relay identity (#190) | **Open, new.** The client cannot verify which node was assigned as `R₁`, so a hostile coordinator can collapse the chain undetectably (§7). Needs an `R₁` identity the client can check without the coordinator's say-so. |

Two constraints #142 added that this section did not anticipate:

- A chain's **first peeling hop must be a node the coordinator can pair a client
  with** (an exit-registered node), because that is how the client reaches it — by
  naming it in `connect{firstHop}`. Later hops are reached by an outbound dial from
  the hop before them and need no coordinator relationship, so a relay-only node with
  an ingress serves those positions.
- A **forwarding relay needs a persistent identity** (`-exit-key`). Its node id is the
  key clients authenticate it against, published in a directory clients cache, so a
  key regenerated per restart makes the node unreachable as a hop until a fresh
  snapshot propagates. `-exit-key`'s help was scoped to exits, which gave a
  relay-only operator no reason to set it; that combination is now refused at startup.

The original list, unchanged:

1. **Relay onion-forward handler + node ingress** (`core/`). Generalize the exit's
   `exitTerminate` into a relay forwarding handler: Noise_NK responder with the node's
   key, read the encrypted next-hop ingress, dial it, splice inner ciphertext — with
   the **forward-only-to-a-known-Bacchus-node** constraint (principle #4) enforced
   against the cached signed directory. Includes the relay-side TCP ingress that
   accepts onion layers. *Depends on 3 for the directory constraint.*
2. **Client-side chain construction** (`core/onion.go` + `core/pool.go`). A telescoping
   n-hop dialer that stacks `noiseConn`s (§4.1), integrated as the `ModeRelay`
   connection builder when `RelayHops ≥ 2`; reuse the sustained-flow probe to validate
   the assembled chain. Refactor `clientHandshake` into a reusable "NK + send target"
   primitive the layers share.
3. **Directory: relay ingress address + AS/operator metadata in the signed snapshot**
   (`core/coldstart`, `cmd/coordinator`). Implements the ADR-0037-deferred courier-
   address advertisement, extended with the AS/operator tag hop-diversity needs.
   **Gates client-side selection** (2/4).
4. **AS/operator-diverse hop-selection policy** (`core/selection`). Choose `n` diverse
   hops from the directory; never two hops in one AS/operator/vouch-subtree; feed the
   cooling/health memory. The core anti-correlation control (§6).
5. **The hop-count knob + config surface** (`core/engine.go`, `cmd/node`, `clients/`
   Windows GUI per ADR-0036). `Config.RelayHops` / `-relay-hops`, default 1, hard cap
   `RelayHopsMax`; the "route through N nodes" GUI control (#75/#76 "node count").
6. **Chain liveness + rebuild** (`core/`, `cmd/coordinator`). Wire first-hop death to
   the existing `reselectDeadRelays` nudge (#96/#105); client-side E2E-stall detection
   triggers a full chain rebuild with bounded retry (§5).
7. **Relay-side DoS controls for onion forwarding** (`core/`). Per-previous-hop and
   aggregate rate/bandwidth caps; integrate with the §5.5 integrity probes and
   accounting.
8. **Per-hop relay admission-cred verification** (`core/`, extends #60/#69). Optional:
   each relay presents a relay-role admission credential the client verifies, extending
   hostile-node rejection from exits to intermediate relays.
9. **(Deferred, may never be needed) NAT-traversed intermediate hops.** Allow NAT'd
   residential nodes as *middle* hops via per-hop rendezvous — explicitly out of v1
   because it re-leaks the path to a coordinator (§4.6). Filed as a tracked non-goal to
   revisit only if reachable intermediate capacity proves insufficient.

---

## 10. Turning it on, and verifying it end to end

Everything below is **off by default**. A node that sets none of it behaves exactly
as it did before #142.

### 10.1 What the network needs first

A chain has requirements the single-hop path does not, and a client whose network
cannot satisfy them will fail to connect rather than quietly connect unchained. At
depth `n` the signed directory must contain, in addition to the coordinator:

- **At least one exit in the country you ask for** — your terminating exit.
- **At least one OTHER exit-registered node** — the chain head. The head must be a
  node the coordinator can pair a client to, and your terminating exit is excluded,
  so a single-exit network cannot chain at all. This is the requirement most likely
  to bite on a small deployment.
- **`n - 2` more forwarding nodes** for the middle positions, each a relay running
  `-relay-ingress` on a publicly reachable address.
- **At least one relay free to be assigned as `R₁`.** A TURN fallback fails a chained
  attempt by design.

So depth 2 needs two exit-role nodes and a relay; depth 3 adds a forwarding relay.

### 10.2 A client that wants a chained relay path

```
bacchus-node -role client \
  -relay-hops 2 \
  -geo NL \
  -relay-directory /path/to/snapshot.bin \
  -mesh-pubkey <coordinator snapshot-signing key, hex>
```

`-relay-hops` counts the nodes between you and your exit, so `2` means the
coordinator's relay plus one hop you chose. `1` (the default) is today's single
relay. A value above `4` is **refused**, not clamped.

`-geo` is the country you want to **egress** in. It is used differently from an
unchained client's: your own machine filters the directory's exits by it and picks
one, and the country is **not** sent to the coordinator at all, because the
coordinator is not choosing your exit. Leaving it unset asks the coordinator for its
country list and takes the first assignable one, which still works — the list is a
public, aggregate reply — but it is one more question you did not have to ask.

The directory is a coordinator-signed snapshot — the same artifact
`cmd/coldstart-bootstrap -cache` writes — and it must verify against `-mesh-pubkey`
and be unexpired, or the client refuses to start.

Expect it to be **slower and less available**: each hop adds a round-trip to every
packet, setup pays `n+1` sequential handshakes, and the direct tier is not offered
at all while chaining (§7).

### 10.3 A node that wants to carry other people's chains

```
bacchus-node -role relay \
  -relay-ingress :20030 \
  -exit-key <64 hex chars, generated once and kept> \
  -relay-directory /path/to/snapshot.bin \
  -mesh-pubkey <coordinator snapshot-signing key, hex>
```

`-exit-key` is **required** here despite its name, and the node refuses to start
without it. A hop's node id *is* its X25519 public key, and clients authenticate hops
against the id in a directory they cache — so a key regenerated on each restart makes
this node unreachable as a hop until a fresh snapshot propagates. Generate one once
and keep it, exactly as an exit does.

The ingress must be **publicly reachable** — a middle hop is reached by an outbound
TCP dial from the hop before it, not by hole-punching. The node reports the port to
the coordinator, which advertises it joined to the source ip it observes. This costs
your uplink: you carry other users' traffic in both directions, so set
`-max-speed` / `-monthly-quota` (issue #143) if that matters to you.

Three things such a node will **not** do, by construction: it never egresses to the
internet (only a `-role exit` node does), it only ever forwards to addresses named in
the signed directory you gave it, and it will not dial itself — so it cannot be used
as an open proxy or as a one-node amplifier.

### 10.4 Verifying it actually chained

The failure this is worth checking for is not "no connection" — that is loud. It is
"connected, but not the way I asked", which the fail-closed rule is supposed to make
impossible and which you should confirm anyway.

**On the client**, at startup, one line states the depth that took effect:

```
relay chaining: 2 hops on relayed paths — 1 peeling hop(s) chosen per connect
from 5 directory candidates; DIRECT paths are not offered while chaining
```

If that line is absent, you are **not** chaining — check `-relay-hops`. Then connect
and look for `connected via RELAY to exit …`. A chaining client that reports
`connected DIRECT` is a bug, not a fallback; the direct tier is removed from its
ladder.

**On the coordinator**, a chained session logs a deliberately different line from an
unchained one:

```
session <id> PEER-RELAY (chained): client <addr> <-> relay <addr> -> first hop <id>(<cc>);
terminating exit not known to this coordinator
```

That line is the property, observable from the side that would violate it: the
coordinator names the head and states plainly that it does not know the exit. If you
instead see the ordinary `-> exit <id>` form, the connect was not chained.

**End to end**, `core/relaychain_acceptance_test.go` does all of this in-process
against real forwarding nodes and asserts what arrived at the exit; it is the
executable version of this section.

### 10.5 Known rough edges

- **The directory is read once at startup.** A node running longer than its
  snapshot's validity window will refuse forwards to nodes that joined since, and a
  client's hop selection can go stale. Restart to adopt a fresh snapshot; in-place
  refresh is §9 item 6's neighbourhood.
- **A chained client's egress load is invisible to the coordinator's exit ranking**
  (ADR-0042 §9 — the session records no exit id, deliberately, so a hop is not
  charged as a terminator). On a network where most clients chain, exit balancing
  degrades accordingly. That is a known consequence, not a bug.
- **Operator diversity may be doing nothing** on your deployment. See §0.5 and §6.

## 11. Relationship to other work

- **#17 / ADR-0033 (peer relay)** — multi-hop is its strict generalization; n=1 is
  ADR-0033 verbatim.
- **#15 / ADR-0028 (transport pool)** — the chain lives inside the ladder's `ModeRelay`
  tier; depth is the "node count" that pool/UI work referenced.
- **#60 / #69 (E2E exit admission)** — rides through the chain unchanged (§4.3); the
  whole design is arranged so this stays true by construction.
- **#96 / #105 / #106 (relay reselect/failover)** — reused for first-hop death; the
  client's ADR-0028 stall-detection covers downstream death (§5).
- **#18 / ADR-0037 (cold-start + mesh-walk)** — supplies the signed directory the
  client selects the chain from; multi-hop needs the deferred ingress-advertisement
  seam (§9.3).
- **rendezvous-cold-start §5 (trust model)** — the vouch/tenure/AS-diversity machinery
  is the Sybil bound multi-hop leans on (§6); relay/exit safety line (§5.3) is
  principle #4.
