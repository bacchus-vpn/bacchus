# 6. Signaling runs over UDP for rendezvous reachability

- Status: accepted
- Date: 2026-07-02

## Context

In the target environments, flagged datacenter IPs are frequently TCP-blocked while
UDP still passes. The coordinator and STUN/TURN are the rendezvous chokepoint and
must stay reachable.

## Decision

The coordinator uses **UDP** signaling, and STUN/TURN run on the same UDP-reachable
host(s). Reachability is verified per IP before use.

## Consequences

- The rendezvous layer survives on IPs where TCP is blocked but UDP passes.
- Reachability is not guaranteed on every IP; the product answer is many
  coordinators + rotation + client fallback (tracked separately).
