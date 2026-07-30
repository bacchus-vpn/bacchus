# Bacchus

Bacchus is an open, incentivized mesh VPN built to resist nation-state censorship
— deep-packet inspection, protocol fingerprinting, and IP blocking. Any node can
act as **client**, **relay**, and **exit** at once; peers find each other through
a lightweight coordinator and connect directly over WebRTC/ICE (NAT-traversal),
falling back to relays only when a direct path fails.

> **Status: early.** The engine and a working desktop path exist; the network,
> incentives, and multi-platform clients are in progress. Expect breaking changes.

## How it works

```
client ──WebRTC (coordinator + STUN/TURN, NAT-traversal)──► [relay] ──► exit ──► internet
```

- **Coordinator** — UDP signaling / peer directory. Never in the data path.
- **Node** — one binary, many roles (`-role client,relay,exit`). Relays only
  forward; exits egress to the internet.
- **Direct-first** — a client connects straight to an exit when reachable; relays
  are a fallback (and a privacy option).
- **End-to-end encrypted** — traffic is sealed client-to-exit (Noise); a relay
  forwards ciphertext and the next hop only, never the destination or content.
- **Reachability-aware** — the mesh routes around regional blocking.

## Repository layout

| Path | What |
|---|---|
| `core/` | the shared engine (all roles) — embedded by every product |
| `bind/` | gomobile facade (Kotlin/Swift) over `core` |
| `cmd/node/` | the volunteer node binary — a thin flag wrapper over `core` (client/relay/exit) |
| `cmd/coordinator/` | rendezvous / directory + STUN/TURN (pion) + cold-start bootstrap, blended onto one port |
| `clients/windows/` | Windows tray client |
| `deploy/` | systemd units + config templates |
| `docs/` | runbook + architecture decisions (`docs/adr/`) |

The payment/token service is proprietary and lives in a separate private repo; it
talks to the network over the wire and shares no code with this one.

## Build

```sh
# server binaries (Linux)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bacchus-coordinator ./cmd/coordinator
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bacchus-node        ./cmd/node

# Windows client
go build -ldflags "-H=windowsgui" -o bacchus.exe ./clients/windows
```

See [docs/RUNNING.md](docs/RUNNING.md) to run the stack and
[deploy/README.md](deploy/README.md) to deploy the services.

## Contributing & security

> **Issue numbers come from two trackers.** This project moved trackers on 2026-07-28
> and re-filed every open issue, so a `#N` in code comments, docs or ADRs may belong to
> the current tracker or to the retired one, depending on when it was written. A retired
> number below the current high-water mark still autolinks, and points somewhere
> unrelated. The retired tracker is gone — not private — so those numbers resolve
> nowhere; read the surrounding sentence instead. Full explanation, and the convention
> for writing new references, in [docs/adr/README.md](docs/adr/README.md).

- [CONTRIBUTING.md](CONTRIBUTING.md) — workflow, branch/commit conventions.
- [CONVENTIONS.md](CONVENTIONS.md) — code style, versioning, safety rules.
- [SECURITY.md](SECURITY.md) — responsible disclosure. Please do **not** open
  public issues for vulnerabilities.

## License

[AGPL-3.0](LICENSE) — fully open and auditable, with a network-use copyleft
clause: run a modified version as a service, publish your changes. See
[ADR-0019](docs/adr/0019-relicense-to-agpl-3-0.md).
