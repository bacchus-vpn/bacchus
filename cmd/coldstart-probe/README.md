# coldstart-probe — cold-start reachability measurement (spike)

A throwaway measurement tool for the rendezvous cold-start spike (`old #18`). It
sends STUN Binding Requests to a target UDP endpoint and reports whether a valid,
transaction-matched reply comes back, with the round-trip time and the reflexive
address the server observed.

It exists to answer the **one empirical question** the cold-start design hinges on
(see [../../docs/design/rendezvous-cold-start.md](../../docs/design/rendezvous-cold-start.md) §6):

> Does a **STUN-shaped UDP** bootstrap packet reach a candidate coordinator/STUN
> endpoint **from the in-region vantage** and get a reply, with no operator
> pre-screening?

This is **not** the real bootstrap: it carries no per-user secret and fetches no
directory snapshot. It measures reachability of the *disguise* — the riskiest
unknown — which only real packets from a real in-region vantage can settle.

## Run

```sh
# Default target is a public STUN server, so it works out of the box for a
# local sanity check:
go run ./cmd/coldstart-probe

# Point it at a candidate endpoint from the in-region vantage:
go run ./cmd/coldstart-probe -target HOST:PORT -count 5 -timeout 3s
```

Exit code `0` = reachable (≥1 probe answered), `1` = unreachable from this vantage,
`2` = usage/resolve error.

## What a result means

- **OK with a reflexive address** — the STUN-shaped packet traversed the path and
  the server answered; the disguise survives here.
- **No response** — either the endpoint is down or this vantage/operator drops the
  path. Re-test from another operator; blocking is regionally fragmented, so one
  failure is not a verdict.

## Next steps beyond the probe

Done: the real per-user-secret-authenticated, signed-snapshot bootstrap is
implemented in [`core/coldstart`](../../core/coldstart), wired into
`cmd/coordinator`, and exercised end-to-end by
[`cmd/coldstart-bootstrap`](../coldstart-bootstrap) +
[`cmd/coldstart-issue`](../coldstart-issue) — see
[docs/design/bootstrap-protocol.md](../../docs/design/bootstrap-protocol.md).
This probe remains useful on its own as a lighter-weight reachability-only
check (no credential, no snapshot) when re-testing a candidate endpoint from
a new vantage.
