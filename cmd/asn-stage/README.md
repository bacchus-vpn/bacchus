# asn-stage — the per-release IP→AS table refresh

Turns a published IP→ASN **range** feed into the **disjoint CIDR prefix** table
[`core/asn`](../../core/asn) loads, and writes it where the client build embeds it.

Unlike `cmd/relaychain-probe` and `cmd/capacity-probe`, this is **not** a spike. It
is a production step: ADR-0044 ruled that the table is committed to this repository
and refreshed per release, which makes the transform that produced it something a
reviewer has to be able to re-run and compare. That is why it is a checked-in tool
rather than a script somebody kept locally.

## Refreshing the table

```sh
curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip
go test ./core/asn/ ./core/
```

Then update the retrieval date, hashes and row counts in
[`core/asn/TABLE.md`](../../core/asn/TABLE.md).

| flag | |
|---|---|
| `-in` | upstream feed, `.tsv` or `.tsv.gz` (required) |
| `-out` | output path; empty writes to stdout |
| `-gzip` | gzip the output at best compression |
| `-family` | `both` (default), `v4`, or `v6` |

`-family v4` is ADR-0044 §6's costed fallback if binary size ever becomes pressing:
~2.49 MB instead of ~3.14 MB, at the cost of resolving every IPv6 hop to unknown —
which the unknown-pooling rule handles safely, but which makes the control inert for a
v6-heavy fleet.

## What it does

```
range_start range_end AS_number country_code AS_description     (upstream, 45 MB)
                          ↓
                 prefix<TAB>asn, disjoint, sorted                (staged, 15 MB → 3.14 MB gzip)
```

1. **Drops the country and description columns.** `core/asn` reads neither, and they
   are the bulk of the bytes.
2. **Drops the unrouted (`AS0`) markers**, so unrouted space becomes a **gap**.
   `core/asn` resolves by containment, so an address in a gap matches no prefix and
   returns *unknown* — which is what an unrouted address should return, and what the
   diversity control's unknown-pooling rule assumes. Carrying the markers is not an
   option anyway: `asn.Read` rejects AS0 outright (RFC 7607).
3. **Merges runs that are genuinely adjacent and share an AS**, so the split below has
   fewer, larger ranges to work with.
4. **Splits each range into aligned CIDR blocks** — the minimal set, host bits clear.

### The one rule that matters

**A merge must never cross a gap.** Two same-AS ranges either side of unrouted space
are not one span, and joining them would announce an AS over address space nobody
announces — a hop inheriting a neighbour's AS, which is exactly the failure the
unknown answer exists to prevent.

What enforces that is arithmetic, not bookkeeping: adjacency is tested as
`end + 1 == next.start` on **addresses**. An unrouted span between two ranges occupies
the addresses that would have made them adjacent, so it defeats the merge whether or
not its marker row is still in hand. `TestUnroutedSpaceBecomesAGap` pins this, and
fails if the adjacency term is dropped.

## Reproducibility

The tool is **deterministic**: the same input produces byte-identical output, verified
by `TestRunIsDeterministic`. That is load-bearing rather than tidy — ADR-0044 chose to
commit the table specifically so the build stays reproducible, and a reviewer checking
a published binary against published source has to be able to regenerate the committed
file and compare hashes.

The **fetch is deliberately not this tool's job**. Keeping it a separate documented
step is what leaves the transform hermetic — file in, file out — so it can be re-run
against a feed the reviewer fetched themselves.

## Source and licence

The feed Bacchus ships is iptoasn.com's combined IPv4+IPv6 export under **PDDL v1.0**
— public domain, redistribution permitted, no attribution required — which is what
makes committing the output to an AGPL-3.0 repository possible at all. The tool does
not assert this: it will stage any feed in the same column shape, and the terms of
whatever you point it at are yours to check.

**CAIDA `routeviews-prefix2as` is a different dataset** and is not interchangeable
with this one. ADR-0044 §6 used it for the churn measurement only; it ships under an
Acceptable Use Agreement, which suits measurement and is not assumed to permit
redistribution.
