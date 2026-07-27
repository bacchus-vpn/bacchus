# relaychain-probe — multi-hop relay-chaining feasibility (spike)

A throwaway demonstrator for the multi-hop relay-chaining design spike (issue #76).
It builds a client, `k` relays, and an exit — each with a real X25519 keypair — wires
them with in-memory pipes, and telescopes a **nested Noise_NK onion** using the real
`flynn/noise` handshake (already a module dependency). It then reports what each hop
could see and checks the design's headline property.

It exists to answer the **one cryptographic question** the design hinges on (see
[../../docs/design/relay-chaining.md](../../docs/design/relay-chaining.md) §8) before
any production wiring exists:

> Do nested Noise_NK layers **peel exactly one-per-hop**, so each relay learns only
> its two neighbours while the innermost client↔exit target and admission credential
> survive the whole chain intact?

This is **not** a network reachability test (that needs real nodes and an in-region
vantage — a later step, cf. `cmd/coldstart-probe`). It validates the *construction*
only: that a chain is the existing client↔exit handshake run once per hop, that no
intermediate relay can read the endpoints, and that a substituted hop key fails.

It imports **no `core/` package** and wires nothing into production — the onion codec
in [onion.go](onion.go) is a self-contained port of `core/e2e.go`'s `noiseConn`, kept
local exactly as `cmd/coldstart-probe` hand-rolls its own STUN codec.

## Run

```sh
# Default: 3 relays between client and exit.
go run ./cmd/relaychain-probe

# Any depth from 1 to 8:
go run ./cmd/relaychain-probe -hops 4
```

Exit code `0` = the peel property held, `1` = it did not, `2` = usage error.

At `-hops 1` the single relay sees both endpoints — today's single-hop behaviour
(design §4.4); the "no single relay sees both endpoints" property is the `n ≥ 2`
opt-in, which is what the probe demonstrates at higher depths.

## What a result means

```
what each hop learned (peeling one layer each):
  relay-1  inbound=client   next-hop=relay-2          [blind to: exit, destination, content]
  relay-2  inbound=relay-1  next-hop=relay-3          [blind to: client, exit, destination, content]
  relay-3  inbound=relay-2  next-hop=exit             [blind to: client, destination, content]
  exit     inbound=relay-3  destination=example.com:443  admission-cred=VERIFIED   [blind to: client]
```

- **Each relay's `next-hop` is only its successor**, and its `[blind to: …]` lists the
  endpoints it never learned. The first relay sees the client but not the exit; the
  last relay sees the exit but not the client; a middle relay sees neither — so no
  single relay links the two ends.
- **The exit recovers the real destination and verifies the admission credential**,
  proving the #60/#69 end-to-end check rides through the chain unchanged.

`go test ./cmd/relaychain-probe/` additionally pins the peel property across 1..8
relays and proves a **wrong/substituted hop key fails the handshake** (a hostile
coordinator cannot force a hop it does not hold the key for).

## Next steps beyond the probe

The probe settles the crypto; the build is split into the child issues enumerated in
[docs/design/relay-chaining.md](../../docs/design/relay-chaining.md) §9 (relay
onion-forward handler, client telescoping dialer, directory ingress/AS metadata,
AS-diverse hop selection, the hop-count knob, chain liveness, DoS controls). A real
in-region reachability probe over live nodes is a separate later step.
