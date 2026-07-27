# 11. v1 scope is narrow: one platform pair, RU-reliable, accounting stubbed

- Status: accepted
- Date: 2026-07-02

## Context

Earlier planning (`ROADMAP.md`, `MVP-PLAN.md`) laddered toward a
full-featured Version 1 with multi-platform clients, real crypto payouts,
and a reachability map. The risk-sequenced board review concluded the
riskiest unknowns (safe client, transport coverage, rendezvous cold-start
under real RU censorship) are unproven and gate everything else — building
mobile clients or payout rails before those land would be effort spent on
features that a still-unproven core network can't support.

## Decision

v1 = completing milestones M0–M4 on the board: one platform pair (RU client
+ volunteer node, currently Windows), reliable specifically under Russian
censorship conditions, with accounting **stubbed** as co-signed metering
receipts and no real payout (issue #20). Mobile (gomobile facade), real
crypto payouts/tokens, multi-platform clients (Mac/Android/iOS), and a
reachability map / decentralized rendezvous are explicitly **v2: deferred**
(issue #4 and siblings).

## Consequences

- Effort concentrates on de-risking the network core (safety, transport
  coverage, cold-start) before investing in breadth (platforms) or monetary
  complexity (real payments).
- v2-deferred features are not blocked architecturally — `core/` and the
  gomobile facade (`bind/`, ADR-0005) exist specifically so mobile can follow
  without a rewrite — they're sequenced later, not designed out.
- "v1 done" has a concrete, checkable definition: M0–M4 closed, per
  `docs/design/v1.md`.
