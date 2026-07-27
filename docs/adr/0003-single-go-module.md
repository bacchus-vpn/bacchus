# 3. A single Go module for the monorepo

- Status: accepted
- Date: 2026-07-02

## Context

The monorepo holds several binaries (node, coordinator, turn) and the desktop
client, plus the shared `core` and `bind` libraries. They do not need divergent
dependency trees today.

## Decision

Use a **single Go module** at the repo root. Binaries live under `cmd/`, the client
family under `clients/`, and libraries at `core/` and `bind/`. Platform-specific
code uses build tags.

## Consequences

- Refactoring across `core`/`cmd`/`clients` is trivial; no internal version pins.
- One dependency set for all targets (a Windows-only dependency is listed but only
  linked into Windows builds). Acceptable.
- If a product later needs a conflicting dependency tree, we introduce a second
  module then.
