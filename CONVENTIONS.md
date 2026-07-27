# Conventions

## Language & style

- Go for `core`, `cmd/*`, and the desktop client engine. One implementation of
  the protocol means one place for protocol/security bugs.
- `gofmt` + `goimports`; keep `golangci-lint` clean.
- `core` holds **no package-level mutable state** — a `Node` takes explicit
  config and has an explicit lifecycle, so it embeds (desktop) and binds
  (gomobile) cleanly. Rich types stay in `core`; `bind/` exposes only
  gomobile-safe types (strings, ints, `[]byte`, interfaces).
- Propagate `context.Context`; log via `log/slog`.

## Commits, branches, versioning

- Conventional Commits with a component scope: `feat(core): …`, `fix(node): …`.
- Trunk-based: short-lived branches → reviewed PR → `main`. `main` always builds.
- The repo is versioned with SemVer tags (`v0.x`). The **wire protocol carries
  its own integer version**, negotiated on connect; mismatches are rejected
  cleanly (clients and nodes update at different rates).

## Security & user safety

- **The repo is always publishable:** zero secrets, zero real infrastructure IPs,
  zero credentials — ever, in any commit. Endpoints/credentials load from local
  config / env (gitignored); ship `*.example` templates.
- **Minimal logging is a safety feature.** Never log client IPs, destinations, or
  user↔traffic correlations at the default level. Verbose logging is opt-in and
  must not capture user-identifying data.
- Relays forward only; exits egress. Collect and retain the minimum.

## Documentation

- Docs ship in the **same PR** as the change — "Done" includes docs.
- Architecture decisions are recorded as ADRs in [docs/adr/](docs/adr/).
