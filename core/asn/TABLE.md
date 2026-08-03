# `table.tsv.gz` — provenance, licence, and how to refresh it

This directory carries a third-party dataset that ships inside every Bacchus client
binary. This file records where it came from, under what terms, and how to replace
it. ADR-0044 and its two amendments carry the reasoning; this is the operational
record that has to sit beside the bytes.

## Source

| | |
|---|---|
| Dataset | `ip2asn-combined.tsv.gz` — combined IPv4 + IPv6 range→ASN feed |
| Publisher | iptoasn.com |
| URL | `https://iptoasn.com/data/ip2asn-combined.tsv.gz` |
| Licence | **PDDL v1.0** (Open Data Commons Public Domain Dedication and Licence) |
| Retrieved | 2026-07-29 |
| Upstream SHA-256 | `c0cdfbec3431d04ba32c83a0e3a6f25b4698daf870651f52ab7c25027032992f` |
| Staged SHA-256 | `ce0f9a083a0c435a9b4bd3e53703229bb9c749dcf93c72b399ff8a1d9397f949` |

Upstream rebuilds hourly, so the URL is not a stable artifact and the upstream hash
pins **the snapshot this table was built from**, not something re-downloadable. The
staged hash is reproducible: `asn-stage` is deterministic, so the same input through
the same tool yields byte-identical output.

## Why this licence permits committing it

The repository is AGPL-3.0 and redistributes this data inside compiled binaries, so
the source's terms have to allow that. PDDL v1.0 is a public-domain dedication, not a
reciprocal licence. Confirmed against the licence text, not inherited from a summary:

- It grants "a worldwide, royalty-free, non-exclusive, licence to Use the Work",
  where Use covers "doing any act that is restricted by Copyright or Database Rights
  whether in the original medium or any other", including the right to sublicense.
- Recipients "may use this work commercially, use technical protection measures,
  combine this data or database with other databases or data, and share their changes
  and additions or keep them secret."
- Attribution is **not** required: "It is not a requirement that recipients provide
  further users with a copy of this licence or attribute the original creator of the
  data or database as a source."

No attribution obligation, no share-alike, no restriction on redistribution in a
derived or compiled form. The attribution recorded here is therefore a provenance
record we keep because a security-relevant input should say where it came from — not
a licence condition being discharged.

**CAIDA `routeviews-prefix2as` is a different dataset and is NOT the source here.**
ADR-0044 §6 used it for the churn measurement only. It ships under an Acceptable Use
Agreement, which is suitable for measurement and is not assumed suitable for
redistribution. The two must not be conflated.

Contrast `.gitignore`'s GeoLite2 rule: that dataset is deliberately *not* committed
because MaxMind's terms are not ours to redistribute under. This one is committed
because PDDL says it can be. The difference is the licence, not the file size.

## What the staged table is

`prefix<TAB>asn`, one row per line, disjoint prefixes, sorted within each family —
the format `asn.Read` parses and validates. Produced from the upstream ranges by
`cmd/asn-stage`, which drops the country and description columns, drops the unrouted
(`AS0`) markers so unrouted space becomes a **gap** that resolves to *unknown*, merges
genuinely adjacent same-AS runs, and splits what remains into aligned CIDR blocks.

| | |
|---|---|
| Rows | 700,442 (550,049 IPv4 + 150,393 IPv6) |
| Distinct ASNs | 86,612 |
| Uncompressed | 15.48 MB |
| **Committed (gzip)** | **3.14 MB** |
| Parse cost | ~190 ms, ~28 MB heap, once per process, lazily |
| Lookup cost | ~113 ns |

It contains nothing but CIDR/ASN pairs: no comments, no free text, no address of this
project's own infrastructure — the transform discards every column that could carry
one, and the committed file is verified to hold only numeric rows. It is a global
public routing table, which is exactly why it identifies nothing about Bacchus.

## Refreshing it (per release)

```bash
curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip
sha256sum ip2asn-combined.tsv.gz core/asn/table.tsv.gz
go test ./core/asn/ ./core/
```

Then, in the same commit:

1. Set `TableRetrieved` in [`embedded.go`](embedded.go) to today's date. **This is not
   optional bookkeeping** — `TestEmbeddedTableIsFresh` reads it and fails once the
   table is more than 90 days old, so leaving it behind either hides a stale table or
   fails CI on a table that is actually fresh.
2. Update the retrieval date, both hashes and the row counts in the tables above.

**Two bars read that date, not one** (issue #66). The 90 days above is the floor under
*any* build, and it runs in `ci.yml`. A **release** has to clear a tighter one: 30 days,
enforced by the `verify-table` job in `.github/workflows/release.yml`, which the Windows
bundle job `needs:` so a refusal lands before anything is compiled. The reason the two
differ is that 90 days is a budget on how wrong the table may be in the hands of somebody
running it, and against the floor alone all of it can be spent before the artifact ships.
Set `BACCHUS_ASN_RELEASE_TABLE=1` to check the release bar locally:

```bash
BACCHUS_ASN_RELEASE_TABLE=1 go test ./core/asn/
```

The date is a hand-maintained constant rather than something `asn-stage` stamps into
the file, and that is deliberate: a tool that writes "today" into its output produces
different bytes every run, which would destroy the determinism the whole
regenerate-and-compare check rests on.

The fetch is deliberately a separate manual step rather than something the tool does:
that is what keeps `asn-stage` hermetic — file in, file out — so a reviewer can re-run
it against a feed they fetched themselves and compare bytes.

**Cadence is a security parameter.** ADR-0044 §6 measured the mapping drifting ~1.3%
per month, ~3.6% per quarter. A stale table degrades *safely* — toward §3's unknown
handling, which pools rather than counts as diverse, so a stale answer never becomes a
false claim of diversity — but it degrades. Refreshing every release keeps the error
tracking release cadence, which is the whole basis on which ADR-0044 chose embedding
over fetching.
