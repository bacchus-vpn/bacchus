# Rendezvous cold-start — design

- Status: **implemented (`old #18`; design spike `old #18a` + bootstrap implementation `old #18b`)**
- Date: 2026-07-02 (design), 2026-07-03 (bootstrap implementation)
- Track: rendezvous (M3)
- Companion decision records: [ADR-0012](../adr/0012-cold-start-rendezvous-without-domain-fronting.md) (design), [ADR-0013](../adr/0013-bootstrap-wire-protocol.md) (wire protocol)
- The concrete per-user-secret + signed-snapshot fetch this design calls for
  is implemented in `core/coldstart`, wired into `cmd/coordinator`, and
  spec'd in [bootstrap-protocol.md](bootstrap-protocol.md) — see that
  document for the byte-level protocol and §7 below for which open questions
  it resolves.

> This is the make-or-break part of the whole system. A perfect, undetectable
> data channel is worthless if a brand-new client in the censored region cannot
> **find a first contact** and **get its keys**. This document is the design for
> that first contact, plus the trust model that keeps the network alive once
> contact is made.

---

## 1. Problem statement

A brand-new client, holding **only what ships in the app**, must bootstrap to:

- **WHERE** — at least one live, in-region-reachable entry point (address / port /
  transport), and
- **SECRETS** — a per-user credential so that a *harvested* endpoint is inert to
  anyone who doesn't hold the secret,

…over a channel the censor also watches **and can participate in** (the censor can
download our app too). The defining tension of the whole field applies:

> **Discoverability ⟂ blockability.** Anything easy for a real user to find is
> easy for the censor to find. The only escape is *asymmetric distribution*: each
> honest user learns a tiny slice; the censor — even wearing many identities —
> cannot learn enough to block it all without paying an unacceptable cost.

### Why this is the boss fight

The single most-proven cold-start mechanism in the circumvention field is a
**domain-fronted broker** (the Snowflake model): the bootstrap request looks like
traffic to a giant CDN, so blocking it means blocking the CDN. **That mechanism is
unavailable to us** — CDN fronting is not viable in our target region (the main
CDN is itself blocked there). So we are in deliberately under-explored territory
and must engineer the asymmetry another way.

---

## 2. Threat model

### The censor's goals against rendezvous

| # | Attack | What it looks like |
|---|---|---|
| A1 | **Insider / enumeration** | Poses as a user (or many), harvests endpoints, blocks them. How VPN IPs and Tor bridges get mass-blocked. |
| A2 | **Block the bootstrap channel** | Block the website / broker / seed distribution point. |
| A3 | **Monitor the bootstrap** | Without blocking it, watch handouts to learn endpoints. |
| A4 | **Sybil / scraping** | Automate thousands of fake identities to drain the address pool fast. |
| A5 | **Distribution attack** | Block the app itself (store removal, installer host). |

### The two axes of blocking (both must be answered)

Blocking in the target region operates on **two independent axes**, and defeating
only one is not enough:

1. **Fingerprint axis** — *does this traffic look like a proxy / a known protocol
   / random noise?* Enforced by deep packet inspection: exact-shape protocol
   signatures (e.g. fixed-length handshakes are ~100% detected), **entropy
   analysis** that flags high-entropy streams matching no known protocol, and
   **active probing** (the middlebox connects to a suspected server and pokes it;
   if it answers like a proxy, it is blocked).
2. **IP-classification axis** — *is the destination a foreign datacenter?*
   Independent of protocol. A cryptographically perfect handshake still dies on a
   flagged datacenter IP. Residential / mobile-carrier IPs are treated as real
   users and are not frozen.

Blocking is **per-IP, detection-driven, and regionally fragmented** (deployed
per-operator; the same endpoint works in some cities and not others). RST
injection — the mechanism that kills TCP sessions to flagged IPs — is **TCP-only**,
so UDP still reaches those IPs.

The endgame tail-risk is **default-deny / SNI-allowlisting** ("white internet"),
already applied regionally during shutdowns: only a small allowlist of
domestically-hosted services works. It is not (yet) permanent or nationwide
because the economic collateral is enormous, but it is the direction of travel.

*(The full mechanism taxonomy and current per-protocol status are tracked in the
team's internal research notes; nothing region-specific or sensitive is repeated
here so this document stays publishable.)*

---

## 3. Design principles

1. **Obfuscation solves the fingerprint axis, never the IP axis.** However good
   our disguise, an enumerated IP is still blockable. So disguise **and** IP
   strategy are separate, mandatory work items.
2. **Make harvested IPs inert, don't try to out-rotate.** We cannot rotate
   datacenter IPs faster than the censor blocks them. Instead, **per-user secrets**
   make a harvested address useless to anyone without the secret — and a residential
   volunteer mesh supplies natural churn for free.
3. **Blend, don't hide.** Looking like *nothing* (random bytes) is now itself a
   signal (entropy analysis). Look like *something structured and permitted* that
   is expensive to ban.
4. **Authenticated first packet.** A prober without the per-user secret must see
   silence or a plausible decoy, never a proxy-shaped response (defeats A3 active
   probing).
5. **UDP-first.** UDP survives the TCP-only RST block and the datacenter freeze.
6. **Coverage, not perfection.** No single endpoint / protocol / IP works for
   everyone. Success = *every user finds ≥1 working path*, via a union of partial
   transports plus client-side failover.

---

## 4. Architecture

Four cooperating layers: **transport disguise**, **seed** (cold bootstrap),
**recovery** (warm re-bootstrap), and **enumeration resistance**.

### 4.1 First-contact transport

**Decision: the first contact looks like — or actually is — a STUN / WebRTC
NAT-traversal exchange to our own STUN server.**

Rationale:

- STUN is the tiny UDP protocol every video/voice call uses. Generic, self-hosted
  WebRTC/STUN **still passes** in the target region: the messenger-call blocks
  there are **app-targeted** (specific apps' endpoint IPs and traffic signatures),
  **not** a ban on WebRTC the protocol — other WebRTC VoIP apps keep working, and
  the blocks are bypassed by any VPN.
- Banning STUN broadly breaks ordinary video calls → high collateral → the
  "expensive to ban" property we want. This is *blend*, not *hide*: we look like
  the generic VoIP that still works, not like a banned app.
- It is UDP (survives the datacenter freeze) and reuses infrastructure we already
  run.

Hard requirements on top:

- **Randomize the DTLS/ICE fingerprint.** A fixed handshake shape is fatal (a
  previous domain-fronted system was fingerprinted and blocked on exactly this).
  We must not match any known-proxy signature *or* any specific messenger's
  signature.
- **Do not rely on QUIC mimicry** as the primary disguise — QUIC/HTTP3 is degraded
  in the target region, so it is a weaker blend than STUN/WebRTC here.
- **Keep a transport pool with per-user failover** for regions where UDP/WebRTC is
  degraded (e.g. obfuscated-WireGuard variants that survive in some operators).
  This is the same partial-transport-union principle as the data plane.

#### 4.1.1 What is built, as of ADR-0059 and ADR-0060 — and what is not

This section stated a requirement for **years** that the code did not meet, and in
a way that was invisible from either side: the DTLS/ICE fingerprint machinery
`core/dtls_fingerprint.go` and `core/ice_fingerprint.go` implement **existed**,
was tested, and was wired to `core/transport_webrtc.go` — the *data-plane*
transport. `Config.DTLSFingerprint` never reached `core/coordpool.go`. Meanwhile
`coordLink.send` was `json.Marshal` then `conn.Write`, so **the first packet a
client ever sent was plaintext JSON over raw UDP** and a DPI box read
`{"type":"connect"` off it. Everything below was downstream of that.

So this table, rather than prose, and it is kept honest as the slices land:

| §4.1 requirement | State |
|---|---|
| First contact is DTLS-shaped rather than cleartext | **Built, both halves** (ADR-0059 `#175` slice 1, ADR-0062 slice 2). The signaling port accepts DTLS alongside raw JSON, and the **client speaks it with no fallback to plaintext** — a censor dropping the handshake and a coordinator predating slice 1 are the same silence, so a fallback would send the cleartext the shape exists to remove at exactly the moment it matters. A coordinator that does not speak it is unreachable to a current client, which is what `-rendezvous-dtls=false` now costs |
| Actually STUN/WebRTC-shaped, not merely DTLS-shaped | **Built, both halves** (ADR-0060 `#202`, ADR-0062 `#175` slice 2). The port answers any well-formed Binding Request with the same two attributes the TURN port on `-turn-addr` already answers with — byte-identical by construction, since two ports on one host answering differently would be a distinguisher in itself — and the client now emits the check before its ClientHello, through the same `core/coldstart` codec for the same reason. `core/ice_fingerprint.go` has its first caller at this hop. The response **decides nothing**: gating on it would be the probe the two open questions below are about |
| Randomize the DTLS/ICE fingerprint | **Not applied at this hop** — slice 3. The profiles exist and `dtls.Config` takes their hooks directly; what is missing is a `dtls.Config` counterpart to `dtlsProfile.apply`, which takes a `*webrtc.SettingEngine` |
| Do not rely on QUIC mimicry | Held — nothing here uses QUIC |
| **A transport pool with per-user failover at this hop** | **Not built.** `#175` stays open for it. The hop still has one protocol, no probe, no race and no per-`NetworkKey()` learning — every one of which the data plane has had since ADR-0028. ADR-0062 makes the last one *smaller* rather than closer: with no fallback there is no per-coordinator shape to remember, so `NetworkKey()` has nothing to store until there is something to race |

Two of `#175`'s design questions are deliberately **still open** and were not
answered to get here, because the shape ruled (S1/S2) adds no probe: what a probe
*is* when there is no end-to-end Noise channel yet, and whether a coordinator-hop
probe leaks a distinguisher of its own.

One correction this work produced, recorded because the wrong version of it is the
intuitive one: **`handshake.ProtocolVersion` is not the compatibility mechanism
for a shape change at this hop and must not be used as one.** `handshake.Check`
rejects a mismatch in *both* directions, so bumping it is a fleet break rather
than a window. The window is a first-bytes demux on the coordinator — see ADR-0059
§4. Its other half, try-then-fall-back on the client, was **withdrawn** before it
was built (ADR-0062): so the window is one-sided, and what it now covers is
*forwarders*, whose links slice 2 deliberately left cleartext, rather than clients.

### 4.2 Seed — the cold bootstrap (a fresh client with nothing)

A layered fallback that degrades gracefully. Each layer is a courier for the same
tiny payload: a **signed, encrypted bundle** of `{ a few entry points, a per-user
secret, an expiry }`. The app ships the public key to *verify* bundles; it does
not necessarily ship the bundles.

1. **Download-time fresh snapshot (fast path).** The distribution site hands the
   user a current bundle at download. Best-effort: the site is itself blockable
   (A2/A5), so this is never the only path. **Nothing shared across all downloads
   may be a long-lived secret** — assume the censor downloads the app and reads
   whatever is baked in.
2. **Signed invite bundle / QR (resilient path).** An existing user generates a
   **signed invite** carrying a **per-recipient secret** and hands it over out of
   band (mainstream messenger, QR in person). To block this the censor must block
   person-to-person messaging entirely. *Preferred over generating a personalized
   installer* (`.exe`/`.apk`): a signed bundle/QR keeps the same per-recipient
   secret without the code-signing burden and the "why did my friend send me an
   executable" malware-fear problem. Installer generation remains a possible
   advanced option, not the default.
3. **First-launch parse-and-refresh.** On first run the client parses whatever it
   was given, probes reachability, and pulls a **fresh signed snapshot** from
   whichever entry point answers, then caches it. From then on the client is
   self-updating (see recovery).

Whatever is baked into a public build is treated as **burnable**: a small rotating
set of entry points we are willing to lose, protected by per-user secrets so the
addresses are inert to the censor even though the app is public.

### 4.3 Recovery — warm re-bootstrap (mesh-walk)

Once a client has *ever* connected it has collected peers. If every coordinator it
knows is unreachable, it asks **any node it knows — even a plain relay — for a
current, signed snapshot** of where the coordinators/entry points are, and walks
the mesh until it finds a live path. This is **signed peer-exchange (PEX)**: every
node ever met becomes a re-entry point.

- **Recovery, not cold-start.** It needs at least one prior contact, so it
  *complements* the seed, it does not replace it.
- **Directory data is coordinator-signed.** A relaying node is a *courier*, not an
  *author* — it cannot forge endpoints (this closes the poisoning vector).
- This is the **coordinator pool (issue #6) generalized**: #6 rotates among a
  configured set of coordinators; mesh-walk lets *any node* hand you a fresh signed
  snapshot. Design them as one mechanism.

> **Implemented** (issue #31, [ADR-0037](../adr/0037-mesh-walk-recovery-via-signed-peer-exchange.md);
> builds on the same `core/coldstart.Snapshot` the cold-start bootstrap and the
> coordinator pool use). How the three bullets above became code:
>
> - **Courier (`core/coldstart`).** A relay/exit caches the last coordinator-signed
>   snapshot verbatim (`SnapshotCache`) and serves those exact bytes (`ServeCourier`);
>   a courier holds no signing key and re-signs nothing. The recovering client
>   re-verifies every reply with the existing `Verify`, so a courier that lies serves
>   a stale-but-genuine snapshot or nothing — never a forged directory. A courier
>   keeps its cache warm by fetching from its coordinator with `Bootstrap` under an
>   operator invite (`bacchus-node -courier-listen -courier-invite`); no new
>   coordinator→node path is needed.
> - **Proof of prior contact = anti-probe.** "Needs at least one prior contact" is
>   enforced *on the wire*: a mesh-walk request carries a `PROOF` attribute — a
>   snapshot the coordinator once signed — and the courier serves the directory only
>   when that proof's signature checks out (expiry ignored, since a recovering
>   client's proof is legitimately stale). A prober with no prior snapshot gets the
>   plain STUN response a public server sends (principle #4). The client, conversely,
>   requires the *reply* to be unexpired — it is about to reconnect through it.
> - **Client walk.** `establish` returns `ErrNoCoordinatorReachable` when every
>   coordinator is silent; `Engine.MeshWalk` then walks known peer couriers for a
>   verified fresh snapshot and the client (`bacchus-node -mesh-peers`) adopts its
>   coordinator entries, re-caches the fresher snapshot as its next proof, and
>   reconnects — walking on if the rediscovered coordinators are down too.
>
> **Deferred (follow-ups, not built here):** a node does not yet advertise its
> courier address through the coordinator's signed directory (that needs the
> node→coordinator register seam), so couriers are operator-configured today; and the
> coordinator-pool *rotation* work (issue #6) will consume these same courier
> snapshots rather than reimplement them. Sybil/trust gating of *which* peers a client
> accepts a snapshot from — beyond signature verification — is the unbuilt vouch
> system (§5.4), out of scope here.

> **Update (2026-07-12) — recovery past the first-connect boundary (issue #115).**
> The initial implementation engaged mesh-walk only at first connect. Losing every
> coordinator *mid-session* — or on the transport-pool path, at any point — still
> failed cold. Three couplings closed that gap:
>
> - **Mid-session, single-transport.** The auto-reconnect loop (ADR-0030) retries a
>   dropped path forever. It now counts consecutive *all-silent* passes and, after a
>   few, walks known peer couriers; if one names a **genuinely different** live
>   coordinator it hands that directory to the supervisor, which rebuilds the engine
>   against it (`Engine.NeedsRecovery`/`RecoveredDirectory`). This never abandons
>   ADR-0030: a walk that finds nothing better, or that only re-lists the same dead
>   coordinators, leaves the loop retrying in place — so a *transient* outage still
>   self-heals without a rebuild, and only a real coordinator move triggers one.
> - **Transport pool.** The pooled connect/failover path (issue #15) never surfaced
>   `ErrNoCoordinatorReachable`, so recovery could not key on it. It now does — the
>   exit-list fetch distinguishes "every coordinator silent" from "answered but no
>   exits" (a pinned exit cannot be paired without a coordinator, so all-silent yields
>   the sentinel rather than a doomed pin) — and the pool's failover loop escalates to
>   the same mesh-walk before giving up.
> - **Courier freshness enforced, not merely cadenced.** A courier refreshes its cache
>   every 30 s, well inside the coordinator's ~5-min snapshot TTL — but only *while its
>   coordinator is reachable*. If that coordinator is down past the TTL the cache ages
>   out, and the courier now **withholds** the expired snapshot (serving the plain STUN
>   answer a prober gets) instead of handing out entries that may be gone. This makes
>   the serve side honor the same `Verify` (signature **and** freshness) the client
>   already applies to the reply — the two ends are now symmetric.
>
> Recovery still **rebuilds the engine** (the coordinator set is fixed at
> construction); mid-session simply routes that rebuild through the supervisor once a
> walk has a concrete better directory, so there is exactly one failover loop and no
> double-connect. See ADR-0037's *Update (2026-07-12)* block.

### 4.4 Enumeration resistance

Enumeration cannot be *prevented* (you can't make an endpoint findable by real
users and unfindable by the censor among them). It can be made **bounded, costly,
and useless**:

- **Per-user secrets (primary).** Knowing an IP is worthless without the user's
  secret; a prober without it sees silence/decoy. This is the highest-leverage
  defense and the reason we don't need to out-rotate IPs.
- **Residential volunteer churn = rotation for free.** A volunteer mesh is a large,
  churning pool of the un-frozen (residential) IP class.
- **Rationed, bucketed handout with honeytokens.** Each identity learns few
  endpoints; different buckets see different subsets; unique canary endpoints per
  bucket reveal *which bucket leaked* when they go dark → quarantine it.

---

## 5. Trust, tiers, and admission

The mechanism that keeps the protected network alive. **One identity system for
everyone** — a person is not "a client" or "a volunteer" but an identity that can
hold roles `{client, relay, exit, coordinator}` and a trust score, matching the
node's existing multi-role design. **Trust gates what roles and what tier you
unlock.**

### 5.1 Client tiers — what the end user experiences

Untrusted does **not** mean locked out: a new user gets working VPN immediately on
the ephemeral tier, and it gets *better* as trust is earned.

| End-user experience | Untrusted (ephemeral tier) | Stable tier |
|---|---|---|
| Speed / bandwidth | Lower — shared burnable endpoints | Higher — reserved, less crowded |
| Reliability / drops | More churn — these get burned by the censor | Steady — protected by per-user secrets |
| On a currently-blocked endpoint? | Higher chance (this is the tier being burned) | Low — protected, not enumerable |
| Exit choice | Limited / no pinning | Full — pin country/city, premium exits |
| Priority under congestion | Best-effort | Prioritized |
| Credential | Ephemeral, rotates | Persistent per-user secret, follows you |

**Why only trusted users get stable:** stable endpoints are protected by per-user
secrets, so they can't be burned *from outside*. The only remaining way to burn one
is *from inside* (a holder reveals its IP). Trust exists solely to make inside
access **slow, costly, and traceable** — which is what keeps the good tier alive.

### 5.2 Entry doors and graduation

Two doors, both starting **untrusted** (marked as "we know nothing about them"):

- **Contribute** — agree to run as **relay** (or, opt-in, **relay + exit**) while
  the VPN is on. Fair exchange: you carry traffic, that earns your access.
- **Pay** — via **privacy-preserving blind tokens** (unlinkable proof that
  *someone* paid, never *who* — vital for user safety, and the reason plain card
  payment is unacceptable). Reuses the separate payment service's machinery.

**Graduation to stable** after enough good behavior, checked on:

- **Real contribution over real time** (Sybils are cheap to *create*, but trust
  costs *duration*).
- **Behaves like a user, not a harvester** (not enumerating the directory /
  grab-and-drop).
- **No burn correlation** — endpoints given to them don't go dark shortly after
  (honeytokens). A user whose endpoints keep getting blocked is **revoked**, not
  graduated.

**Honest limitation:** a determined state actor *can* contribute traffic to grind a
few Sybils into stable. Graduation-by-behavior raises the cost but isn't infinite,
which is why stable is *also* defended by per-user secrets + honeytoken
burn-detection + fast revocation, and why social vouching (below) is the
higher-assurance path.

### 5.3 The Sybil-resistant admission ladder

Stable-and-above access is **not** earned by wasteful proof-of-work (burning CPU
on a meaningless puzzle is pointless and, against a state actor's compute, weak).
It is earned by mechanisms that are **useful**:

- **Proof-of-contribution (bandwidth/relay).** To fake many identities the censor
  must contribute real residential bandwidth for each — expensive, hard at scale,
  and it *grows our network while they try*. Their attack cost is our capacity.
- **Privacy-preserving payment** (blind tokens) — a real cost that also funds the
  mesh, without a deanonymizing paper trail.
- **Social vouching** — the strongest against a *state* adversary, because it does
  not scale even with money or bandwidth (see §5.4).

**Relay/exit safety line (mandatory):** a **relay** only forwards ciphertext and
never egresses under the user's IP — safe to default. An **exit** egresses others'
traffic under its own IP — real legal exposure, so it is **strong opt-in, never
defaulted, and never for at-risk (in-region) users**. In-region contributors are
relay-only; exit duty is for vetted operators in safer geographies.

### 5.4 Social vouching — the graph and its math

Access to stable (and to promotions) can be granted **only** by **social vouch**
or **direct service grant**. The vouch graph is parameterized by:

- **k** = distinct stable vouchers required to admit one new member.
- **v** = vouch budget per member per period.

**Governing formula.** If the stable tier has `N` members all vouching to their
max, new admits per period = `N·v/k`, so the tier grows by a factor of
**`1 + v/k`** per period.

> Key insight: vouching arithmetic **cannot** stop growth — for any positive `v`
> it is exponential. The numbers set the *rate*; **revocability sets the
> ceiling.** The real Sybil brake is: **Sybil trees must grow slower than we
> detect-and-revoke them.**

Growth with **k = 3**:

| v (vouches / member / **year**) | annual growth | doubling time |
|---|---|---|
| 3 | 2× | 12 months |
| **6** | **3×** | **~7.5 months** |
| 9 | 4× | ~6 months |

**Chosen parameters:** `k = 3`, `v = 6` per **year** (annual budget, not monthly —
monthly runs away; even 1/month is 5×/year). Budget **scales with tenure /
reputation** (freshly-graduated members get a small budget, long-proven veterans
get the full amount), concentrating vouch power in the hardest-to-fake accounts.

Three damping levers make a generous `v` safe:

1. **Tenure-to-vouch (≈6 months).** A new member can't vouch immediately. This sets
   a **generation time** on any Sybil tree — the censor advances one layer per
   tenure period regardless of budget.
2. **Accountable vouching + subtree revocation.** Vouching **stakes your own
   standing**. A caught Sybil collapses **the whole subtree it vouched in**, and its
   vouchers take the hit. Caught branches disappear, so the censor runs to stay
   still.
3. **Global admission-rate cap** — an independent circuit breaker on total
   stable-tier growth per period.

### 5.5 Unified rails for volunteers (non-client contributors)

Pure volunteers (run infrastructure, don't browse) ride the **same** credential,
vouch graph, tenure, honeytoken, and subtree-revocation machinery. Only two things
differ:

- **What trust gates** is **role + traffic sensitivity**, not client QoS:

  | Volunteer trust | Role allowed | Carries | Blast radius if hostile |
  |---|---|---|---|
  | Untrusted (new) | **Relay only** (ciphertext, no egress) | Untrusted-tier client traffic | Sees ciphertext + timing only — low |
  | Trusted / tenured | May **exit** (opt-in, safe geo) + serve stable clients; listed in signed snapshots | Stable-tier clients | Higher — which is why it had to earn in |
  | **Highly trusted** | May run a **coordinator** (see §5.6) | Directory / matchmaking authority | Highest — apex trust only |

  Anyone can join as a **burnable relay** with near-zero friction ("frictionless
  ephemeral contribution"); exit duty, serving stable clients, and running a
  coordinator are earned.

- **Detection** swaps endpoint-burn correlation for **active integrity probes** —
  the coordinator sends canary flows and checks the node forwards faithfully / an
  exit doesn't tamper or inject, plus AS/IP-diversity checks so one actor can't
  quietly run a large share of exits (eclipse/Sybil defense). Failure → same
  subtree revocation.
- **Reward** swaps access for **payout/credit** (or altruism); trust also gates
  payout eligibility, which kills Sybil "earning farms" with the same machinery.

### 5.6 The coordinator tier and separation of powers

The apex role. Because a coordinator is the **directory authority + rendezvous
point**, a hostile one is the most damaging node in the system (it can poison
discovery and observe who talks to whom). So **only highly-trusted, long-tenured,
AS-diverse operators are promoted to coordinator**, by service grant or top-tier
vouch.

**Separation of powers:** promoting operators to coordinator decentralizes
*matchmaking and directory service*, but the **root of trust for identities and
revocation stays tighter** (service-held, or a small highly-trusted quorum).
Coordinators matchmake and serve **signed** snapshots; they are not the authority
that issues or revokes identities. A client using the coordinator **pool** can
**cross-check** snapshots from multiple coordinators — a coordinator that lies
diverges from the others and is detectable.

### 5.7 Revocation mechanics (the kill switch)

Required for every identity, client or volunteer.

- **Issued, short-TTL credentials.** Identity is *issued* (not self-asserted) and
  bound to a credential with a short lifetime that must be renewed.
- **Coordinator-mediated refusal.** Every session is brokered, so revocation =
  the coordinator drops the ID's registration and refuses to pair it. Instant,
  and it reuses the choke point we already have.
- **Age-out + subtree collapse.** Stop renewing → the identity ages out even from
  the mesh-walk fallback (its signed records expire). Abuse → revoke the identity
  **and** collapse the vouch subtree beneath it.

### 5.8 Bootstrap → filter flip (launch sequencing)

Turning on trust-filtering is an **ordering**, not a user-count threshold. The trap
in the naive "stay open until N users" plan: the censor quietly grabs many stable
accounts *during* the open window and, once filtering flips on, is already inside as
high-trust **roots** with full vouch power.

Correct sequence:

1. **Private seed (curated).** The first userbase gets stable directly — but keep
   it **invite/community-based, not open-public**. These are the **roots of the
   entire vouch tree**; a censor in the seed is a permanent high-trust root. Vet
   them like co-founders.
2. **Flip filtering ON while still private**, once the vetted core is self-
   sustaining (enough tenured vouchers that no single account is pivotal and the
   graph can hit target growth). This is the "enough people to grow themselves"
   trigger — and it fires **before** going public.
3. **Then open the public front door.** The public now enters **untrusted**, on the
   ephemeral tier, earning stable via vouch/contribution/payment. Stable is never
   handed freely to the open public, so the pre-stocking attack is closed.

Safety nets in every phase: honeytokens watch pre-flip accounts too (early ≠
immune), and the global admission-rate cap stays on as the circuit breaker.

---

## 6. Evaluation & acceptance

**Acceptance criterion (`old #18`):** a documented, tested bootstrap that a cold
client completes from an in-region vantage with **no operator pre-screening step**.

**The one empirical question the spike must answer first:** does a STUN-shaped,
fingerprint-randomized bootstrap packet **reach our coordinator from the in-region
vantage and get a signed snapshot back**, with no pre-screening? Only real packets
from a real in-region vantage can answer it — see the measurement prototype in
[`cmd/coldstart-probe`](../../cmd/coldstart-probe/README.md).

**Rubric for the design as a whole:**

- **Insider blocking rate** — with `M` fake identities over time `T`, what fraction
  of the fleet can the censor block? Target: bounded / sublinear, not 100%.
- **User reachability** under `X`% endpoint loss.
- **Time-to-recover** after a node / bucket / coordinator is blocked.
- **Seed reachability** under distribution-channel pressure (A2/A5).

---

## 7. Open questions (tracked, not yet decided)

1. **Same-country server prioritization** — when a client has 2+ exits in one
   country, rank by health/liveness, measured latency (urltest-style), and load.
   Client-side selection policy; separable from cold-start.
2. **Sybil grinding bound** — exactly how slow/costly graduation must be so a state
   actor can't grind stable Sybils faster than honeytokens catch them.
3. **~~Per-user-secret provisioning crypto~~ — resolved, see
   [bootstrap-protocol.md](bootstrap-protocol.md).** Concretely: an 8-byte
   secret ID (the STUN `USERNAME`) + 32-byte HMAC key, minted by
   `cmd/coldstart-issue`, packed into an unsigned `bacchus1:...` invite string
   that travels out of band. What's still open: how the *very first* invite
   for the private seed phase (§5.8 step 1) reaches its recipients in
   practice (operational, not cryptographic — the crypto itself is done).
4. **Coordinator snapshot cross-checking** — the exact client-side algorithm for
   detecting a divergent (lying) coordinator in the pool.
5. **Whitelist endgame** — if SNI-allowlisting goes permanent/nationwide, the
   Reality-style SNI-borrowing counter and its infrastructure needs.
6. **Installer generation vs. QR** — whether personalized-installer generation is
   ever worth the code-signing/malware-fear cost over signed bundles/QR.

---

## 8. Relationship to other work

- **#6 coordinator pool + rotation** — the narrow case of §4.3 mesh-walk; they
  share the signed-snapshot mechanism, now built as the mesh-walk courier (issue
  #31, ADR-0037). #6's rotation consumes the same `core/coldstart.Snapshot`.
- **#9 threat model** — §2 here is the rendezvous-specific slice of it.
- **#10 pluggable transport interface** — §4.1 STUN/WebRTC disguise and the
  transport pool are transports behind that interface.
- **#12 client↔exit E2E** — per-user secrets (§4.4) and the data path meet here.
- **payment service (separate private repo)** — supplies the blind-token Sybil
  resistance reused in §5.2–§5.3 and the payout accounting in §5.5.
