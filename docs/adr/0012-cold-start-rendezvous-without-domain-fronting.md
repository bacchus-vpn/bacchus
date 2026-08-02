# 12. Cold-start rendezvous without domain fronting

- Status: proposed (design spike, `old #18`)
- Date: 2026-07-02

## Context

A brand-new client in the censored region, holding only what ships in the app, must
reach a *first contact* to obtain entry points and keys, over a channel the censor
watches and can join. The most-proven mechanism for this — a **domain-fronted
broker** (Snowflake) — is unavailable to us because CDN fronting is not viable in
the target region. Blocking there operates on two independent axes (traffic
**fingerprint** and **IP classification**), uses entropy analysis and active
probing, is per-IP and regionally fragmented, and RST-injection is TCP-only. This
is the highest-risk, least-built part of the system.

The full design is in
[docs/design/rendezvous-cold-start.md](../design/rendezvous-cold-start.md); this
record captures the decisions.

## Decision

1. **First contact blends with STUN/WebRTC** to our own STUN server (generic
   self-hosted WebRTC still passes; messenger-call blocks are app-targeted, not a
   WebRTC ban), over **UDP**, with a **randomized DTLS/ICE fingerprint** and a
   transport pool for degraded regions. Not QUIC (degraded in-region). *Blend with
   a permitted structured protocol; do not look like random noise (entropy
   analysis) or a known-proxy signature.*
2. **Authenticated first packet / per-user secrets** everywhere, so harvested IPs
   are inert and active probes without the secret see silence/decoy. We do **not**
   try to out-rotate IPs; we make them inert and lean on residential churn.
3. **Layered seed:** download-time signed snapshot → signed invite bundle/QR with a
   per-recipient secret → first-launch parse-and-refresh. Anything baked into a
   public build is burnable; no shared long-lived secrets in a public build.
4. **Warm recovery via signed peer-exchange (mesh-walk):** any known node (even a
   relay) can hand a client a coordinator-**signed** snapshot; nodes are couriers,
   not authors. This is issue #6's coordinator pool generalized.
5. **One identity system; trust gates role + tier.** Roles
   `{client, relay, exit, coordinator}` on one credential. Client trust buys QoS
   (ephemeral → stable); volunteer trust buys role + traffic sensitivity; the apex
   (**coordinator**) is highly-trusted only.
6. **Sybil resistance is useful, not wasteful:** proof-of-contribution (relay
   bandwidth) + privacy-preserving blind-token payment + **social vouching**. No
   meaningful reliance on raw proof-of-work. Relay is the safe default; **exit is
   opt-in and never for in-region users**.
7. **Vouch graph:** `k = 3` vouchers to admit, budget `v = 6`/member/**year**
   (tenure-scaled). Growth factor `1 + v/k`; the numbers set the rate, and
   **revocability sets the ceiling** — safe because of tenure-to-vouch (~6mo),
   **subtree revocation** of caught trees, and a global admission-rate cap.
8. **Revocation** = issued short-TTL credentials + coordinator-mediated refusal +
   age-out + vouch-subtree collapse.
9. **Separation of powers:** matchmaking/directory decentralizes to coordinators,
   but the identity/revocation root of trust stays tighter (service or small
   highly-trusted quorum); pooled coordinators are cross-checkable.
10. **Launch sequencing:** curated private seed (the vouch-tree roots) → flip
    trust-filtering ON while still private → *then* open the public front door as
    untrusted. The flip is an ordering, not a user count.

## Consequences

- No dependency on domain fronting or any single broker; the rendezvous chokepoint
  becomes a *set* of cross-checkable, signed, rotatable contacts.
- Harvesting the public app yields inert addresses; enumeration is bounded and
  costly, not prevented.
- Clients and volunteers share one trust/credential/vouch/revocation system, which
  also feeds the payment service's payout accounting and Sybil resistance.
- A determined state actor can still grind a bounded number of Sybils into the
  trusted tier; this is accepted and contained by honeytokens + subtree
  revocation + rate caps, not eliminated.
- Several sub-designs remain open (per-user-secret crypto, coordinator
  cross-check algorithm, same-country selection, whitelist-endgame counter) — see
  the design doc's open-questions section.
