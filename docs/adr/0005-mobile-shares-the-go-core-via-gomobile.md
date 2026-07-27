# 5. Mobile clients share the Go core via gomobile

- Status: accepted
- Date: 2026-07-02

## Context

Android and Apple clients need the same protocol/engine as desktop. Reimplementing
a censorship protocol per platform risks divergent bugs — and divergent bugs are
fingerprints an adversary can detect.

## Decision

Keep one engine in `core` (Go). Expose a **gomobile-safe facade** in `bind/` (simple
types only) and bind it to Kotlin/Swift. Desktop imports `core` directly.

## Consequences

- `core` must keep a clean API surface and no package-level mutable state so it
  binds cleanly — this constrains how we build it from day one.
- Mobile UIs are native; only the engine is shared.
