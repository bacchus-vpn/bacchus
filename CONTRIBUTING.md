# Contributing

Thanks for helping build Bacchus. The project moves in small, reviewed steps.

## Workflow (every change)

1. **Claim an issue** on the project board (move it Todo → In Progress).
2. **Branch off `main`**: `feat/<service>-<desc>` (or `fix/…`, `docs/…`).
3. **Build and test** — unit + integration; run a smoke test for anything that
   touches the running stack.
4. **Document in the same PR** — docs are part of "Done".
5. **Open a PR** linking the issue (`Closes #N`) and summarize the change.
6. `main` changes **only** through reviewed, merged PRs.

## Conventions

- **Commits:** Conventional Commits with a component scope — `feat(core): …`,
  `fix(node): …`, `docs: …`.
- **Code:** `gofmt` + `goimports`; keep `golangci-lint` clean; no package-level
  mutable state in `core`.
- Full set: [CONVENTIONS.md](CONVENTIONS.md). Architecture decisions:
  [docs/adr/](docs/adr/).

## Parallel work

One branch per task; **own a service, not a file**. Coordinate on the board.

## Security

Never commit secrets or real infrastructure IPs (see `.gitignore` and
[SECURITY.md](SECURITY.md)). Report vulnerabilities privately, not via issues.
