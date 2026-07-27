# capacity-probe — what an active speed test can and cannot tell you (spike)

A self-contained demonstrator for the node-capacity design spike (issue #144). It
exists to answer, physically, the question the design turns on
([../../docs/design/node-capacity.md](../../docs/design/node-capacity.md) §6.1):

> Can the network learn a node's capacity by **testing** it?

The answer is **no**, and this tool is the demonstration rather than the argument.

Like [`cmd/relaychain-probe`](../relaychain-probe/README.md) and `cmd/coldstart-probe`,
it imports no `core/` package and wires nothing into production.

## The demonstration

```sh
go run ./cmd/capacity-probe -demo
```

Two nodes with **identical pipes**. One is honest. The other is the adversary issue
#144 names — "fast to the tester and throttled to real clients" — implemented in
about fifteen lines (`servingNode.rateFor`), with no cryptography and no timing
analysis. It just checks whether it recognises who is asking.

```
node                       probe measures   real client gets   verdict
----                       --------------   ----------------   -------
honest-node                   67.1 Mbit/s        67.1 Mbit/s   consistent
discriminating-node           67.1 Mbit/s         2.1 Mbit/s   PROBE FOOLED
```

The probe measures both nodes at the same speed. One of them serves real users at
1/32 of it. **The probe cannot tell them apart** — and the gap is not subtle, it is
a factor of thirty-two.

The cheapness of the attack is the finding. A defence that a fifteen-line
`if whitelist[peer]` defeats is not a defence with a tuning problem; it is the wrong
shape.

## Why patching it does not work

The instinct is to hide the tester. It fails on four independent grounds, and each
one alone is fatal — which is why the design abandons the approach rather than
hardening it:

1. **The tester is identifiable.** Rotating prober addresses does not help: an
   admitted client can call `list` and enumerate the network's own nodes, and any
   prober that is *not* a node still has to come from somewhere, in bulk, on a
   schedule.
2. **It measures the wrong path.** Capacity is not a scalar property of a node — it
   is a property of a *path*. Fast to a prober in Frankfurt says nothing about a
   client on a Moscow mobile network, which is the only path anyone cares about.
3. **The traffic shape is self-identifying.** A speed test is a bulk unidirectional
   flood of fixed duration. Real sessions are not. Even from a perfectly anonymous
   source, a flood is recognisable *as a flood*.
4. **It burns the quota #143 exists to protect.** Re-testing is recurring cost on
   both ends, forever. Spending a volunteer's 400 GB cap to prove they have a 400 GB
   cap is self-defeating — and this one sinks the design even against a wholly honest
   fleet.

Stealth is an arms race against an adversary who **owns the endpoint being
measured**, so it is a race that cannot be won. The design's response is to not
enter it: there is **no tester**. A node's rating is what real clients attest it
delivered *to them* — the one thing a node cannot fake by recognising who is asking,
because it does not know which flows are scored (all of them are).

## The honest use

The measurement itself is real and useful when **you run both ends**. An operator
who does not know their own upload speed — which is most residential volunteers —
can find out, and set `cmd/node -max-speed` to a number they did not guess:

```sh
# On a host elsewhere (a VPS, a friend's machine):
go run ./cmd/capacity-probe -serve :9999

# On the node:
go run ./cmd/capacity-probe -probe 203.0.113.10:9999 -duration 10s
```

That number is a fine basis for your **own** declared cap. It is not a capacity
anyone else should believe about you, and the network does not:
`core/capacity.Estimator.Seed` clamps any probe result to a provisional ceiling
rather than trusting it, so a seed can save an honest node a slow ramp but can never
buy a liar a rating (`TestSeedIsClampedToTheCeiling`).

## Flags

| flag | meaning |
|---|---|
| `-demo` | run the honest-vs-discriminating demonstration over loopback and exit |
| `-serve <addr>` | serve side: listen and flood any peer that connects |
| `-probe <addr>` | probe side: measure throughput from a `-serve` peer |
| `-duration` | how long to measure (default 5s) |

## What this is not

Not a benchmark, not a monitoring tool, and not wired into any node. It is a spike
artifact: it exists so that "an active probe cannot be trusted" is a claim you can
**run**, and so the reasoning behind ADR-0040 survives the people who wrote it.
