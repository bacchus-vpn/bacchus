# 1. Record architecture decisions

- Status: accepted
- Date: 2026-07-02

## Context

We want a durable, reviewable record of significant technical decisions and their
rationale, so contributors — and our future selves — understand why the system is
the way it is.

## Decision

Record architecture decisions as short Markdown ADRs in `docs/adr/`, numbered
sequentially. Each states Status, Context, Decision, and Consequences. Superseded
ADRs are kept and marked, not deleted.

## Consequences

- A lightweight paper trail; a PR that makes a significant decision adds or updates
  an ADR in the same PR (ADR-0007).
- Numbers are immutable once merged.
