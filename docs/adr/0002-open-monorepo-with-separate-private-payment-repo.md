# 2. Open monorepo, with the payment service in a separate private repo

- Status: accepted
- Date: 2026-07-02

## Context

The clients, node, and coordinator share a large amount of code (the engine) and
change together — especially the wire protocol. The payment/token service must be
proprietary and must never expose secrets.

## Decision

Everything open source lives in one public monorepo (`bacchus`). The payment
service lives in a separate **private** repo (`bacchus-payment`). The boundary is a
**network boundary** — the payment service issues blind tokens over the wire and
shares no code — so there is no cross-repo version pinning.

## Consequences

- Cross-cutting changes (e.g. the protocol) are atomic: one commit spans core +
  node + clients. No inter-repo version drift.
- The private repo is physically separate, so proprietary code cannot leak into the
  public tree.
- A component can still be split into its own repo later (with history) if it earns
  an independent release cadence; the monorepo does not foreclose that.
