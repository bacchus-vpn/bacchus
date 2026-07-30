# 44. An independent IP→AS lookup behind one seam, AS-diverse hop selection, and the distribution question left open

- Status: accepted (issue #23); amended twice — see the amendments at the end.
  The seam, the unknown-case rule, the hop-selection ladder and the coordinator's
  use of it were accepted and implemented when this record was written. **How the
  table ships and refreshes was left open**, and was then ruled on: option A,
  embedded in the client build (first amendment). The two questions that ruling
  explicitly left unsettled — the encoding, and the source's licence — are measured
  and closed in the second amendment, which is where the bytes actually reach a
  client (#55). Issue #23 is delivered on both sides as of that amendment.
- Date: 2026-07-29

## Context

Relay chaining (`old #142`, ADR-0038) spreads a chain's hops across operators using the
coordinator-signed `Entry.Operator` tag (`old #124`). ADR-0038's `old #124` amendment already
says that is the advisory half, and that real network diversity is **AS diversity**,
derived client-side from each hop's **observed IP** against an independent routing
table — never from a tag in the snapshot, because neither a node nor a coordinator
can be trusted to assert an AS number. A Sybil operator asked to state its own
diversity would simply fabricate it.

`selectHops` documented that gap in its own comment. So a single operator spread
across several unlabeled directory entries was **not detected**, and a chain could
route two hops through one network — exactly the first-and-last-hop correlation
multi-hop is bought to prevent.

The same missing table blocked something else. `cmd/coordinator`'s `observedAS`
masks an attester's observed IP to a /24 or /48 as a "same-network" proxy, and said
in its own comment that a real ASN lookup is required before the TRUSTED capacity
stream is fed, because the ~4:1 AS bound is denominated in autonomous systems.
ADR-0041 line 173 records the same follow-up. The trusted stream is what B3's serve
floor (#15), B6's share-based backpressure and B2's two-rating design (`old #157`) wait
on. Four things, one missing component.

Before this change the repository contained **no ASN machinery of any kind** (the
`asn1` occurrences are unrelated certificate encoding in vendored crypto).

### What the address in the directory actually is

The AS has to be derived from something a node cannot choose. It is:
`cmd/coordinator`'s `buildSnapshot` advertises a relay's `Ingress` as **the
coordinator's own observed source IP** joined to the relay's self-reported *port*,
so a relay cannot assert the host half and therefore cannot claim to sit in an AS it
does not occupy. `Entry.Addr` is built the same way. That is what makes an
IP-derived AS worth anything, and it is why deriving beats reading: a signed AS tag
is free to fabricate, an address is not, because it has to actually route or the hop
is unreachable.

## Decision

### 1. One seam: `core/asn.Lookup`

```go
type Lookup interface {
    LookupAS(ip netip.Addr) (AS, bool)
}
```

Observed IP in, AS out, plus an explicit unknown as the second return. Both
consumers depend on this and on nothing else — neither knows, or can know, where the
table came from. That is the point: the owner's ruling in §6 changes one
implementation and nothing at either call site.

`*asn.Table` is the file-backed implementation. Every method is nil-safe, and a nil
`*Table` is a meaningful value — a lookup that resolves nothing.

There is **no fetch path in the package, on purpose**: nothing in it can make a
network call. An outbound whois/RDAP/route lookup would tell a third party the IP of
every node a client is about to chain through, which is the one correlation this
subsystem exists to deny.

### 2. The table format is disjoint prefixes, validated at load

One `prefix<TAB>asn` row per line, `#` comments. Prefixes must be **disjoint** and
`Load` rejects a file where they are not.

A BGP table as observed carries more-specifics, which needs longest-prefix matching
— a slower lookup and a more intricate one to audit. Flattening overlaps into
disjoint spans is a mechanical transform that belongs in whatever stages the table,
and it is the form the widely published IP→ASN range datasets already ship in. So
the package takes the flattened form and **verifies** it, rather than carrying a
longest-prefix implementation every reader would have to check. It fails loudly on
an unflattened file instead of resolving by accident of row order.

Text rather than a packed binary, following `core/geoip`'s reasoning: no decoder, the
whole parse auditable in one screen, and a fixture readable by anyone reviewing a
diversity test. §6 records what the compact encodings measure at.

`AS0` is rejected on load (reserved, never announced — RFC 7607), so the zero value
cannot collide with a real answer.

### 3. Unknown means **accept the hop, but count no diversity for it**

This is the decision the card says must not be left silent, and it is two rules:

- **An unresolved hop cannot satisfy a diversity pass.** Only a hop with a resolved,
  unused AS can. So a resolvable candidate is always preferred while one exists.
- **Unresolved hops share ONE bucket**, so two of them collide with each other
  rather than counting as two ASes.

It is still placeable by the relaxed passes, which is what makes this
accept-but-do-not-count rather than reject — and **any chain leaning on one is
reported as degraded**, because "these hops are in different networks" is precisely
the claim that was never established about it.

**Why not "reject the hop".** With no table staged every hop is unknown, so rejection
would mean building no chains at all on any deployment that has not staged one —
which is every deployment today. That is the outcome `selectHops` already refuses for
the operator tag ("refusing to build chains on a network nobody has curated"), and
the reasoning carries over.

**Why not "treated as diverse".** It inverts the control. An attacker would buy a
whole chain's worth of diversity for the cost of using address space the table does
not cover. Pooling costs an honest node in unmapped space the chance to sit beside
another such node; that is the cheaper mistake.

**Why this differs from the operator tag, which DOES treat empty as non-colliding.**
The asymmetry is deliberate. An absent operator tag means the *coordinator* has not
curated a file — an administrative gap that applies to honest and hostile nodes
alike, and one no attacker chooses. An unresolvable address is different in kind:
**the attacker picks the address.**

### 4. The selection ladder degrades the two controls independently

Four passes, the honest lattice of two constraints that can each hold or not:

| pass | AS-distinct | operator-distinct |
|---|---|---|
| 0 | yes | yes |
| 1 | yes | — |
| 2 | — | yes |
| 3 | — | — |

Both middle rungs are load-bearing:

- **Without pass 1**, a directory that can supply AS diversity but not operator
  diversity gives up BOTH — sacrificing the load-bearing control to satisfy the
  advisory one.
- **Without pass 2**, the no-table case is worse than useless. Every hop pools into
  unknown, so no pass demanding AS distinctness can place anything, and the fill
  falls straight through to unconstrained — **silently switching off the operator
  diversity that has run since `old #124`**. Adding a control must not remove one.

The order between them is the ranking #23 states: operator is advisory and is dropped
first, AS is load-bearing and is dropped last.

This follows the shape `selectHops` already had (strict pass, then relaxed, never
refuse) rather than inventing a second one beside it.

### 5. The fallback is named, and the degradation is reported

`selectHops` returns a `hopDiversity` alongside the hops. A degraded chain and a
strong one are otherwise the same value — a `[]relayHop` of the right length — and a
security control that can quietly stop applying while its caller reports success is
not a control. Operator diversity has degraded silently this way since it was
written; #23 does not extend that to the signal it calls load-bearing.

`buildChain` emits it, and the level splits on whether the table was working:

- **`EventError`** when a staged table could not keep two hops apart. That is a real
  weakening on a real deployment and an operator can act on it.
- **`EventInfo`** when nothing resolved at all. Every build ships with no table until
  §6 is settled, so raising that as an error would cry wolf on every connect, for
  every user, about a decision none of them can take.

`observedAS` gets the same treatment on the coordinator side: it resolves through the
seam, and the prefix mask survives as `asFallback` — the **named** fallback for when
the table is unavailable, not the silent default it was. It is still reached on every
local stack, where nodes register from loopback and no AS announces `127.0.0.0/8`;
returning a masked prefix there rather than nothing is deliberate, because an empty AS
makes `handleCapacityReport` drop the sample and the capacity feed would silently stop
on every developer box.

The two key spaces are kept syntactically disjoint — `asn.AS` renders `AS64496`, the
fallback renders a CIDR — because they share one field (`capacity.Sample.AS`) and one
distinct-value count. One real AS spanning several /24s counts as **several** "ASes"
under the mask and as **one** under the table, so the mask makes the ceiling cheaper
to reach than the AS bound intends. Tolerable while only the untrusted stream is fed
(it clamps to the ceiling regardless); precisely what stops being tolerable when the
trusted stream is fed.

### 6. **OPEN — how the table ships and refreshes**

> **Superseded: this was ruled on — option A. See the amendments at the end.** The
> section is kept as written because the measured evidence is what the ruling rests
> on, and a decision is only auditable while the numbers that produced it are still
> readable.
>
> **Two figures below did not survive contact with the shipped form. Do not quote
> them as the cost of this decision.**
>
> - **"~1.4 MB compressed" is not what a client carries. The shipped table is
>   3.14 MB.** The 1.38 MB row is a correct measurement of a *delta-varint binary*
>   encoding of *ranges* — a form this project did not adopt, because it would have
>   put a custom decoder in front of a security-relevant parser. What ships is gzipped
>   **text** holding **disjoint CIDR prefixes**, and *both* differences cost bytes: an
>   arbitrary range is not one prefix, so 494,257 ranges become 700,442 prefixes. The
>   figure below is therefore accurate about a thing that was measured and misleading
>   about the thing that was built. The second amendment §1 has the full table.
> - **"IPv4-only (1.07 MB)" is no longer a live option.** It was offered here as a
>   further reduction "if binary size is pressing". Measured on the shipped form the
>   saving is 0.65 MB — about a fifth — in exchange for resolving *every* IPv6 hop to
>   unknown. That trade was declined; both families ship. See the second amendment §2.

**This is the owner's decision and this record does not make it.** What follows is
measured evidence and a recommendation.

The constraint that rules out the easy answer: **#23 is explicit that hop AS is
derived client-side.** `observedAS` is coordinator-side, and a coordinator is an
operator-run machine that can simply be pointed at a staged file (`-asn-table`, which
this change adds). A client cannot — nobody stages files on a user's laptop. **A
distribution mechanism that only reaches servers does not solve #23 at all.**

Note also that the table must NOT arrive from the coordinator in the signed snapshot.
A table the coordinator also supplied is a tag with extra steps, and #23 exists
because the coordinator is not trusted to assert a hop's AS.

#### Measured: how big the table is

Source: the public BGP-derived combined IPv4+IPv6 range→ASN dataset, 2026-07-29.
"Reduced" = ASN only (org names and country codes dropped, both unused here),
adjacent runs sharing an ASN merged, unrouted gaps kept as explicit markers so a
lookup returns *unknown* rather than inheriting a neighbour's AS.

| form | entries | bytes | gzip |
|---|---|---|---|
| upstream as published | 711,512 | 45.07 MB | 8.87 MB |
| reduced, fixed-width | 632,669 | 6.93 MB | 2.53 MB |
| **reduced, delta-varint** | **632,669** | **4.53 MB** | **1.38 MB** |
| reduced, delta-varint, IPv4 only | 477,329 | 2.13 MB | 1.07 MB |
| reduced, delta-varint, IPv6 only | 155,340 | 2.40 MB | 0.31 MB |

Distinct ASNs: 86,549.

#### Measured: how fast the mapping churns

Source: CAIDA `routeviews-prefix2as` (rv2, IPv4), snapshots at 1 week / 1 month /
3 months / 1 year before 2026-07-27, 60,000 sampled addresses per series.
Metric: P(the AS answer for a routed address differs from today's).

| table age | prefix-weighted | IP-weighted |
|---|---|---|
| 1 week | 0.36% | 0.09% |
| 1 month | **1.30%** | 0.51% |
| 3 months | **3.61%** | 2.12% |
| 1 year | 11.24% | 7.69% |

Prefix-weighted samples one random address inside each announced prefix (closer to
"a random hosting network"); IP-weighted samples uniformly over announced space. The
announced-prefix count is near-flat over the year: 1,043,661 → 1,106,835 (+6%).
Multi-origin and AS-set rows are ~0.4% of the table; the first origin is taken as
canonical.

#### What those two numbers mean

**A client-shippable table is ~1.4 MB compressed, and it drifts ~1.3% per month.** A
year-old table is still ~89% right. Staleness here is *degradation* — a diversity
verdict scored against an out-of-date AS — not breakage.

That reframes the release-channel worry. An embedded table makes the release channel
(#34 `[G7]`) a **quality** dependency, not a **correctness** one: a client that never
updates for a year mis-scores roughly one verdict in nine, and mis-scores toward the
`unknown`/collision handling in §3 rather than toward a false claim of diversity.

#### The options, with what each actually costs

**A. Embedded in the client build, refreshed per release.**
~1.4 MB added to each client binary. No network request, ever — nothing to
fingerprint, nothing to block, nothing that leaks which client is about to build a
chain. Error tracks release cadence: ~1.3% monthly, ~3.6% quarterly. Cost: the
binary grows, and correcting a bad table means shipping a release.

**B. Scheduled fetch.**
Buys back that ~1.3%/month. Costs a predictable, periodic, fingerprintable request
from every client on a censored network — the exact property the transport spends its
entire budget avoiding — and a fetch endpoint is a blocking target and a
de-anonymisation surface. **At this churn rate the trade is bad and the measurement
is what makes that a finding rather than an opinion.**

**C. Signed, policy-delivered.**
Reuses what Wave 7 built: `core/delegation` and `core/policy` already do offline
verify, `seq` rollback defence and grace, so the table would arrive with the same
guarantees as the policy bundle and could be corrected out of band without a release.
The cost is a genuine mismatch of shape: the policy blob is a **small document
fetched often**, and a routing table is a **large artifact that changes slowly**.
Putting 1.4 MB behind a mechanism designed for a few KB means either paying it on
every policy refresh, or building versioning/delta machinery that does not exist
today. It also does not by itself answer *how the bytes reach the client* — policy
reaches clients through coordinators, and §6's opening constraint applies.

**D. Coordinator-supplied in the signed snapshot.** Rejected, not an option: see the
opening of this section.

**E. Embedded baseline + signed out-of-band correction.** A and C composed: ship the
table in the release, allow a signed delta to correct it between releases. Strictly
better coverage, and strictly more machinery — the delta format, its versioning, and
its delivery path all have to be designed and none exists.

#### Recommendation (not a ruling)

**Start with A, and treat C/E as the upgrade once a release channel exists.**

The measurements say the thing a fetch buys is small (~1.3%/month) and the thing it
costs is exactly what this project refuses to spend (a periodic, fingerprintable,
blockable request from every client). Embedding is the only option that adds **zero**
network surface, and at ~1.4 MB it is affordable. Quarterly refreshes keep error near
3.6%, which the §3 unknown-handling degrades safely rather than silently.

Shipping IPv4-only first (1.07 MB) is a reasonable further reduction if binary size
is pressing, at the cost of resolving every IPv6 hop to unknown — which §3 pools
rather than treats as diverse, so it is safe, but it makes the control inert for a
v6-heavy fleet.

**Until this is ruled on, the client ships with no table.** `relayDirectory.as` is
nil, every hop resolves to unknown, the ladder degrades through pass 2 to exactly the
chain it built before this change, and the degradation is reported at `EventInfo`.
The seam is in place and both consumers use it; what is missing is bytes on a client.

## Consequences

- **#23's client-side property is not yet delivered**, and this record does not
  pretend otherwise. The seam, the ladder, the unknown rule and the reporting are
  built and tested; the client has no table until §6 is answered. What *is* delivered
  today is the coordinator side, which can be pointed at a file now.
- **ADR-0041's follow-up is closed on the coordinator side.** `observedAS` resolves a
  real AS when `-asn-table` is staged, which is the prerequisite ADR-0041 line 173
  named for feeding the TRUSTED stream. Feeding it remains `old #157`'s decision; this only
  removes the blocker.
- **A configured-but-unusable table is fatal at startup.** An operator who passed
  `-asn-table` believes AS resolution is running; starting anyway would hand them the
  prefix-mask fallback under its name. No path given is a *choice* and stays silent.
- **Mixed key spaces are visible, not silent.** A window containing both `AS64496`
  and `192.0.2.0/24` means some attesters resolved and some did not; the two forms
  cannot be confused, but a consumer counting distinct values will count them
  separately, and that is the honest reading of what happened.
- **The disjointness requirement pushes work into staging.** Whoever produces a table
  from a BGP feed must flatten more-specifics first. `Load` fails loudly rather than
  resolving by row order, so this cannot pass unnoticed.
- **Fixtures are synthetic and must stay so.** The repo is public. `core/asn/testdata`
  uses documentation address space (RFC 5737, RFC 3849) and documentation ASNs
  (RFC 5398) only. A real routing-table excerpt would carry real allocations into a
  public repository and must not be committed.
- **The diversity rejections are mutation-checked.** Removing the same-AS guard, the
  pooled-unknown bucket, the `!resolved` rule, the operator-only rung, the
  `unresolved` term of `degraded()`, or the report in `buildChain` each makes a
  specific named test fail. A diversity control whose tests have never been seen to
  *reject a chain* is not testing anything.

## Amendment (issue #23) — §6 is ruled: option A, embedded in the client build

§6 set out five options and declined to choose. This is the choice.

### Decision

**A — the IP→AS table is embedded in the client build and refreshed per release.**

B (scheduled fetch) is rejected on §6's own measurement. Fetching buys back roughly
1.3% of accuracy per month and costs a predictable, periodic, fingerprintable request
from every client on a censored network — the exact property the transport spends its
whole budget avoiding, and a blocking target besides. The measurement is what makes
that a finding rather than a preference: had the churn been 15% a month, the trade
would have gone the other way.

C (signed, policy-delivered) and E (embedded baseline plus signed correction) remain
the upgrade path, not the starting point. Both want a delivery channel that does not
exist yet; C additionally has the shape mismatch §6 describes, and neither is worth
building before there is a release channel (#34 `[G7]`) to hang them on.

D stays rejected for the reason §6 gives: a table the coordinator supplied is a tag
with extra steps.

### Sub-decision: the table is committed, not fetched at build time

§6 did not distinguish these, and they are not the same decision. Fetching the table
during the build keeps the repository small, but makes the build **non-reproducible**
and introduces a third-party dependency into it. Reproducibility is load-bearing here:
the signed release channel (#34) and code signing (#38) both rest on a reviewer being
able to establish that a published binary corresponds to published source, and a
censorship-resistance tool whose users cannot check that has given away part of what
it is for.

So the table is committed, and the repository carries the growth. That cost is real
and permanent — every clone pays it forever — and it is accepted deliberately rather
than by omission.

### What this does *not* settle

**The encoding.** §6's headline figure of ~1.4 MB compressed is the delta-varint
binary form, while `core/asn` deliberately reads text, because "it needs no decoder,
the whole parse is auditable in one screen". Embedding the varint form would reverse
that decision and put a custom decoder in front of a security-relevant parser. The
expected resolution is a gzipped **text** table decompressed through the existing
parser — standard-library only, format unchanged, at a size somewhere above §6's
2.53 MB fixed-width figure. That is an expectation, not a measurement, and #55 is to
measure it and come back if the number is unacceptable rather than quietly adopting a
binary format.

**The source and its licence.** §6 measured against a public BGP-derived range→ASN
dataset without naming one, which was adequate for a size estimate and is not adequate
for redistribution. This repository is AGPL-3.0 and would ship the data inside a
binary, so the source's terms must permit that. `iptoasn.com` publishes a combined
IPv4+IPv6 range→ASN feed under PDDL v1.0 — public domain, no attribution required —
and its `range_start range_end AS_number country_code AS_description` columns reduce
to exactly §6's "reduced" form, which makes it the obvious candidate and very likely
what §6 measured. It is to be confirmed at the source, not inherited from this
sentence. CAIDA `routeviews-prefix2as`, used for §6's churn series, ships under an
Acceptable Use Agreement; suitable for measurement, not assumed suitable for
redistribution.

### Consequences

- **#23 stays open and moves back to claimable work.** The ruling removes the blocker;
  it does not deliver the bytes. That is #55.
- **The staging transform becomes a shipped tool, not a local script.** §6 already
  pushed disjointness into staging; committing the output means the transform that
  produced it has to be reviewable and repeatable, because "refreshed per release" is
  a step someone performs repeatedly.
- **Release cadence is now a security parameter.** At ~1.3% drift per month, quarterly
  releases hold the error near 3.6%. Slower releases degrade the control — safely,
  toward §3's unknown handling rather than toward a false claim of diversity, but
  degradation is what it is, and it is now a property of how often Bacchus ships.
- **Fixtures stay synthetic.** Committing the real table is the product; pointing the
  tests at it is not. `core/asn/testdata` keeps using documentation address space, and
  a table this size in the test path would also make failures unreadable.

## Amendment (2026-07-29, issue #55) — the encoding is measured, the source is licensed, and the bytes ship

The first amendment ruled option A and named two things it did **not** settle: the
encoding, and the source's licence. Both are closed here, by measurement and by
reading the licence rather than by inheriting either from a previous sentence. The
client now carries a table.

### 1. The encoding: gzipped text, measured at 3.14 MB

The expectation was "a gzipped **text** table decompressed through the existing
parser — standard-library only, format unchanged, at a size somewhere above §6's
2.53 MB fixed-width figure". That expectation held, and the number is:

| form | entries | bytes | gzip |
|---|---|---|---|
| upstream as published | 711,289 | 45.07 MB | 8.87 MB |
| §6 reduced, fixed-width **ranges** | 632,669 | 6.93 MB | 2.53 MB |
| §6 reduced, delta-varint **ranges** | 632,669 | 4.53 MB | 1.38 MB |
| **staged, disjoint CIDR text — shipped** | **700,442** | **15.48 MB** | **3.14 MB** |
| staged, disjoint CIDR text, IPv4 only | 550,049 | 12.05 MB | 2.49 MB |
| staged, disjoint CIDR text, IPv6 only | 150,393 | 3.43 MB | 0.65 MB |

Measured 2026-07-29 against the same dataset §6 measured: the upstream figures
reproduce §6's row (45.07 MB / 8.87 MB) to the byte, and the entry count differs by
0.03% — the feed rebuilds hourly.

**Why the shipped form is larger than §6's rows, and why that is not a regression.**
The two are not the same object. §6 measured **ranges**; `core/asn` requires
**disjoint CIDR prefixes**, and an arbitrary range is not one prefix — it decomposes
into up to 2·bits aligned blocks. That expansion (494,257 merged ranges → 700,442
prefixes) is the cost of the format §2 chose *for the lookup*, and it was already
paid: §2 pushed flattening into staging precisely so the client would not carry a
longest-prefix implementation. The gzip figure of 3.14 MB is 1.24× §6's fixed-width
range form and 2.28× the delta-varint form.

**The trade, stated plainly.** Adopting delta-varint would save ~1.76 MB per binary
and would put a custom decoder in front of the parser that decides a security
control — reversing this package's stated reason for being text ("it needs no
decoder, the whole parse is auditable in one screen"). The first amendment said to
come back if the number were unacceptable rather than quietly adopt a binary format.
It is not unacceptable: 3.14 MB is affordable in a desktop binary, the only decoder
in the path is `compress/gzip`, and the committed artifact is still readable with
`gunzip -c`. **Text stands.**

Runtime cost, for completeness: ~190 ms and ~28 MB of heap to parse, ~113 ns per
lookup. Parsing is lazy and happens at most once per process (`sync.OnceValues`),
which is load-bearing rather than tidy — the relay directory *reloads* on an interval
(#27), and every reload asks for this table.

### 2. Both address families ship — the IPv4-only reduction is declined

§6 kept a size lever alive: *"Shipping IPv4-only first (1.07 MB) is a reasonable
further reduction if binary size is pressing, at the cost of resolving every IPv6 hop
to unknown."* Measured on the form actually shipped, that trade is worse than it
looked, and it is **declined**.

| | gzip | IPv6 hops resolvable |
|---|---|---|
| **both families — shipped** | **3.14 MB** | yes |
| IPv4 only | 2.49 MB | **no** |

**0.65 MB — about a fifth — to make the control blind on IPv6.** Every IPv6 hop would
resolve to unknown, which §3 pools into a single bucket contributing no diversity. That
is *safe*, in the sense that it never becomes a false claim of diversity, but a control
that cannot see half the address space is not doing the job #23 asked for, and a
v6-heavy directory would degrade straight through to the operator-only rung.

§6 conditioned the reduction on binary size being **pressing**. At 3.14 MB in a desktop
binary it is not, and 0.65 MB does not change that. Both families ship.

`cmd/asn-stage` keeps a `-family` flag, and this does not reopen the option: it is a
measurement and diagnostic capability — it is how the row above was produced, and how a
future re-measurement would be — not a supported shipping configuration.

### 3. The source: iptoasn.com, PDDL v1.0, confirmed at the source

§6 measured "a public BGP-derived range→ASN dataset" without naming one, and the first
amendment named `iptoasn.com` as the obvious candidate **to be confirmed at the
source, not inherited from that sentence**. Confirmed:

- **Dataset:** `ip2asn-combined.tsv.gz`, the combined IPv4+IPv6 range→ASN feed.
  Columns `range_start range_end AS_number country_code AS_description`, which reduce
  to §6's "reduced" form once the last two are dropped — as §6 predicted.
- **Licence: PDDL v1.0**, stated by the publisher and verified against the licence
  text itself. It grants "a worldwide, royalty-free, non-exclusive, licence to Use
  the Work", covering any act restricted by copyright or database rights "whether in
  the original medium or any other", with the right to sublicense; it permits
  commercial use and combination with other databases; and it explicitly does **not**
  require attribution or impose share-alike.
- **Retrieved:** 2026-07-29. Upstream rebuilds hourly, so the recorded hash pins the
  snapshot rather than a re-downloadable artifact.

That is what makes shipping the data inside an AGPL-3.0 binary sound: a public-domain
dedication imposes no condition the redistribution could violate. The provenance
recorded in `core/asn/TABLE.md` is therefore a record we keep because a
security-relevant input should say where it came from — **not** a licence obligation
being discharged.

**CAIDA `routeviews-prefix2as` was not used for the shipped data**, and the two are
kept apart exactly as the first amendment required. It ships under an Acceptable Use
Agreement; §6 used it for the churn series only, which is measurement and not
redistribution. §6's churn numbers are unchanged and are not re-derived here.

The contrast with GeoLite2 is worth stating, because the repository already refuses to
commit a bulk dataset: `.gitignore` excludes MaxMind's database because its terms are
not ours to redistribute under. This table is committed because PDDL says it can be.
**The deciding factor is the licence, not the size.**

### 4. What shipped

- **`cmd/asn-stage`** — the staging transform, as the first amendment required ("the
  transform becomes a shipped tool, not a local script"). Upstream ranges → disjoint
  CIDR prefixes: it drops the unused columns, drops the unrouted `AS0` markers so
  unrouted space becomes a **gap**, merges genuinely adjacent same-AS runs, and splits
  the remainder into aligned blocks. It is **deterministic** — same feed, byte-identical
  output — which is what makes "committed, not fetched at build time" reviewable: a
  reviewer regenerates the file and compares. The fetch is deliberately a separate
  manual step, so the transform itself is hermetic.
- **`core/asn/table.tsv.gz`** — 700,442 rows (550,049 IPv4 + 150,393 IPv6), 86,612
  distinct ASNs, 3.14 MB. Committed. The repository carries the growth, as ruled.
- **`asn.Embedded()`** — `go:embed` of the gzipped text through the existing `Read`.
  No fetch path was added and none can be: the package still cannot make a network
  call, and embedded bytes are in the binary before it starts.
- **The wiring**, at `loadRelayDirectory` where `relayDirectory` is constructed —
  **not** in engine configuration. Embedding is not configuration: there is no path,
  no flag and nothing for an operator to set, so routing it through `Config` would add
  a knob to describe a constant. `core/engine.go` is unchanged by this work.
- **The refresh procedure**, in `docs/RUNNING.md` and `core/asn/TABLE.md`.

### 5. On gaps: the guard is arithmetic, not bookkeeping

§6 required unrouted gaps to stay explicit "so a lookup returns *unknown* rather than
inheriting a neighbour's AS". In a prefix table that requirement is met by **omitting**
the unrouted ranges: `core/asn` resolves by containment, so an address in a gap matches
no prefix and is unknown. Carrying the markers as rows is not available in any case —
`asn.Read` rejects AS0 (RFC 7607), and its error message already says to omit the row.
§6's explicit markers were an artifact of the delta-varint form it was costing, where a
run of contiguous spans needs something to break the run.

What keeps a merge from silently spanning a gap is that adjacency is tested on
**addresses** (`end + 1 == next.start`). An unrouted span between two same-AS ranges
occupies the addresses that would have made them adjacent, so it defeats the merge
whether or not its marker is still in hand. The tool was first written the other way,
threading AS0 rows through the merge as sentinels; the tests pass identically without
them, because the arithmetic was doing the work throughout. The sentinel logic was
removed rather than left in as reassurance.

### 6. What this closes, and what it does not

**Closed.** #23's client-side property is delivered. A client build resolves real hop
addresses to real autonomous systems; `selectHops` refuses a chain placing two hops in
one AS while a diverse alternative exists; and `buildChain`'s "no hop resolved" notice
— which fired on *every* connect for *every* user between #52 and #55, because no
client had a table — no longer fires on a normal client. The seam, the ladder, the
unknown rule and the reporting were built in #52; what was missing was bytes, and the
bytes are here.

**Not closed, and deliberately so:**

- **C and E remain the upgrade path, not superseded.** A signed out-of-band correction
  still wants a delivery channel that does not exist. When #34 lands, correcting a bad
  table without shipping a release becomes worth building.
- **The refresh is manual, but no longer unenforced.** `core/asn.TableRetrieved`
  records when the committed table was downloaded, and `TestEmbeddedTableIsFresh`
  fails once that is more than 90 days old — the same threshold `core/geoip` uses and
  the quarterly cadence §6 costed. The check is a **floor, not a schedule**: it says
  the table has gone stale, it does not refresh anything, and performing the refresh
  remains a documented human step.

  The date is a hand-maintained constant rather than something `asn-stage` stamps into
  the table, because a tool writing "today" into its output would differ on every run
  and destroy the determinism that makes the committed table reviewable at all.

  The check runs in CI rather than at client startup, which is where it diverges from
  `core/geoip`'s otherwise identical warning. GeoIP warns an **operator**, who can go
  and stage a fresher file. Nobody can act on this one at runtime — the table is fixed
  in the binary, and only whoever cuts the next release can change it — so warning a
  user would tell the wrong audience about a problem they have no lever on.

  Wiring the refresh into the release process proper still belongs with #34, and is
  tracked separately rather than assumed.
- **Release cadence remains a security parameter**, on §6's numbers: ~1.3% drift per
  month, ~3.6% per quarter, degrading toward §3's unknown handling rather than toward
  a false claim of diversity.
- **The coordinator's `-asn-table` is untouched.** It is a separate consumer with a
  separate lifecycle — an operator-run machine can be handed a file and refreshed
  without a client release — and #52's design of one seam with two independent
  implementations is what makes that unremarkable.

### 7. Consequences

- **Every clone now carries 3.14 MB of third-party data, permanently.** This was ruled
  in the first amendment and is restated because it is now real rather than prospective.
  Each refresh commits a wholly new binary blob; the repository grows by roughly that
  much per refresh, and git cannot delta gzip usefully.
- **A corrupt embedded table degrades rather than refusing.** `embeddedAS` falls back to
  nil, every hop resolves to unknown, and the ladder produces the pre-#23 chain, reported
  as degraded. Refusing would mean a client that cannot connect at all, which §3 already
  rejected in the other direction. The failure cannot arise at runtime — the bytes are in
  read-only data — so what catches it is `TestEmbeddedTableLoads`, in CI, before a release.
- **"The table ships" and "the table is used" are tested as two claims.** Removing the
  wiring at `loadRelayDirectory` fails two named tests and *nothing else in the suite* —
  #52's diversity tests construct their directory by hand and inject a synthetic lookup,
  which is right for testing the ladder and is exactly why they cannot test the attachment.
- **Fixtures stayed synthetic.** `core/asn/testdata` is unchanged and still documentation
  space only. The real table is exercised by a thin smoke test and by assertions that never
  pin a specific AS to a specific address, so a refresh that renumbers an allocation does
  not fail the suite for being correct.
