# 44. An independent IP→AS lookup behind one seam, AS-diverse hop selection, and the distribution question left open

- Status: accepted (issue #23); amended five times — see the amendments at the end.
  The seam, the unknown-case rule, the hop-selection ladder and the coordinator's
  use of it were accepted and implemented when this record was written. **How the
  table ships and refreshes was left open**, and was then ruled on: option A,
  embedded in the client build (first amendment). The two questions that ruling
  explicitly left unsettled — the encoding, and the source's licence — are measured
  and closed in the second amendment, which is where the bytes actually reach a
  client (#55). Issue #23 is delivered on both sides as of that amendment. The third
  amendment (#61) records that the vetted source covers country as well as AS. The
  fourth (#66) makes "refreshed per release" enforceable now that a release process
  exists, and adds a release-time bar tighter than the 90-day build floor. The fifth
  (#151) closes the residual the fourth named: a release is now cut from `main` or it
  is not cut, so the premise the fourth amendment's scope was chosen on is enforced
  rather than assumed.
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

  > **Update (2026-08-03):** done, in the enforcement half — #34's build half shipped a
  > release workflow, and #66 attached a gate to it. There are now **two** bars on this
  > date rather than the one 90-day threshold described above: the floor, unchanged, and
  > a 30-day bar that a release has to clear. The refresh itself is still a human step.
  > See the fourth amendment below.
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

## Amendment (2026-07-30, issue #61) — the chosen source also covers country, so deriving one stops requiring a MaxMind account

The 2026-07-29 amendment §3 vetted a publisher and a licence in order to ship the AS
table: iptoasn.com, PDDL v1.0, confirmed against the licence text rather than a summary.
That vetting turns out to cover a second dataset. The same publisher issues **IP-to-Country**
files on the same terms, and those are now what a coordinator stages for `core/geoip`.

This is recorded here, rather than only in ADR-0042, because it changes what *this* record
committed to. §3 chose a source for one input; the consequence below is that one publisher
is now a dependency for two independent security-relevant inputs.

### 1. What changed

`core/geoip` gained a loader for `range_start range_end country_code` rows beside its
GeoLite2 CSV loader, and `-geoip` now accepts either format in the directory it is given,
preferring the range files. `docs/RUNNING.md` documents the new staging. Nothing about the
AS table moved.

The reason for the switch is licence, not shape. GeoLite2 needs a free MaxMind account and
a licence key to download, and its terms restrict redistribution. That is survivable while
one operator runs every coordinator — each host fetches its own, nobody redistributes
anything — and becomes an onboarding tax the moment coordinators federate, because a
volunteer operator would need to register with a third party before their coordinator
could derive a country at all. The alternative to deriving it is trusting each node's
self-report, which is what `core/geoip` exists to stop (`old #136`). A licence
prerequisite sitting directly upstream of a security property is worth removing before
anyone depends on it.

### 2. What this does *not* extend

The first amendment's ruling — the table is **committed** and embedded in the client
build — stays confined to the AS table. The country file is fetched per host and stays out
of the repository, and the asymmetry is not an oversight:

- The AS table is a **client** input. A client cannot be handed a file, so embedding is
  the only way it arrives, and §6's churn numbers bound the staleness that buys.
- The country table is a **coordinator** input, on an operator-run machine that can be
  handed a file and refreshed without a release. Committing it would buy nothing and bake
  in data that is wrong within weeks — with no reader able to tell, because a stale
  country table does not fail, it mislabels.

So the licence permits committing either, and only one is committed. The reason is the
consumer, not the terms.

### 3. Consequences

- **A federated coordinator operator needs no third-party account** to derive node
  country honestly. That was the point.
- **One publisher is now a single point of dependency for two security inputs**, AS and
  country. Stated plainly rather than left implicit: if iptoasn.com stops publishing or
  starts publishing badly, both the client's diversity scoring and the coordinator's
  country derivation degrade — each toward its own safe direction (§3's unknown pooling,
  and the node-hint fallback respectively), but both at once and from one cause. The
  mitigation is that both degradations are *reported* rather than silent, and that
  neither dataset is on a fetch path at runtime.
- **GeoLite2 remains loadable**, unchanged and still tested, for a deployment that already
  staged it. Nothing about it stopped working, so nothing was deleted.
- **Shipping the loader does not close the hole; staging the file does.** `-geoip` is
  unset in production, which means every node's country is currently its own self-report
  and a Sybil node can claim any country — and country is the only thing a client selects
  on (ADR-0042). The deployment step is the fix, and it is deliberately named here so that
  a closed issue is not read as a closed gap.

## Amendment (2026-08-03, #66) — "refreshed per release" becomes enforceable: a release-time bar tighter than the build-time floor

The first amendment ruled §6 in favour of option A — embedded in the client build,
**refreshed per release**. The second built the thing that notices when it has not been:
`TableRetrieved` and `TestEmbeddedTableIsFresh`, a 90-day floor. Neither could make "per
release" mean anything on its own, because there was no release process to attach it to,
and both said so.

There is one now. #34's build half shipped as `.github/workflows/release.yml`: a `v*` tag
builds the Windows bundle and drafts a GitHub release. So this amendment is not a change
of mind about anything §6 decided — it is the enforcement §6's ruling has been waiting
for, plus one defect that arrived with the release process and one number that turns out
to have been measuring the wrong end of the table's life.

### 1. The defect the release process arrived with

`release.yml` ran **no tests at all**. `TestEmbeddedTableIsFresh` ran, and still runs, in
`ci.yml`. On a tag push GitHub starts both workflows from the same event and there is no
native way to order them — `needs:` is intra-workflow, and `workflow_run` is a different
tool for a different problem. So the freshness check was a **bystander**: it could go red
beside a bundle that had already been built and a draft release that had already been
created. A check that cannot stop the thing it is checking gates nothing.

On one tag spelling it was worse than a bystander. `release.yml` triggers on `v[0-9]*`
**and** `[0-9]*`; `ci.yml` triggers on `v*`. A tag pushed as `1.0.0` rather than `v1.0.0`
starts `release.yml` and does not start `ci.yml` at all, so on that spelling the
freshness check does not run anywhere — not in parallel, not at all.

This is the same finding the release workflow already records about the version
assertion, arrived at from a different direction, and it has the same fix: a first job
**inside** `release.yml` that the bundle job `needs:`. The shape was already proven in
this repository, in both directions, before this card reused it.

> **Update (2026-08-03):** the tag-spelling half of this section is closed. `ci.yml` now
> triggers on `release.yml`'s own list — `['v[0-9]*', '[0-9]*']` — so a tag pushed as
> `1.0.0` starts the test suite as well as the release, and the two lists are documented
> as having to agree (#156). The ordering point is untouched and is the reason the gate
> stayed inside `release.yml`: CI still runs *beside* a release rather than before it,
> which is #151.

### 2. Two bars on one quantity, and why the release one is tighter

`tableMaxAge` is 90 days and is the floor under *any* build. It is not wrong; it is
measuring the wrong end.

90 days is a budget on how wrong the table may be **in the hands of somebody running
it** — §6's ~3.6%-per-quarter figure is about a client resolving hops, not about a
repository. That budget is spent on both sides of a release: the age of the table when
the artifact is built, plus however long the person who installed it keeps running that
build. Against the floor alone, the whole of it can be spent before the artifact leaves
the building. A release cut on day 89 hands a user a table that is already at the limit
on the day they install it, and every day after that is over budget — with no further
refresh possible until the next release, because the bytes are in the binary.

So the release bar is where that split gets chosen, and it is **30 days**:

- it leaves roughly 60 of the 90 days on the user's side, which is the side §6's
  measurement is about;
- it is the unit §6's own churn table is written in — the one-month row is the 1.30%
  figure the entire cadence argument rests on, so the bar is read off the measurement
  rather than picked for looking careful;
- and it is the coarsest bar that still leaves most of the budget where it belongs.

**The cost of a tighter bar, named rather than waved past.** Every refresh commits a
wholly new ~3.14 MB blob and git cannot delta gzip it (second amendment §7). At 30 days
a hotfix cut within a month of a feature release inherits no refresh at all, which is the
common shape; at a week, every hotfix would drag one in, and the repository would grow by
a table per patch release. 30 days buys the accuracy without buying that.

The floor stays at 90 for the reason `TestEmbeddedTableIsFresh` already gives: it blocks
unrelated work when it fires, and a 30-day floor would fire on every unrelated pull
request one month after a refresh. Two bars, one date, one arithmetic — the release bar
is inert unless `BACCHUS_ASN_RELEASE_TABLE` is set, and exactly one thing sets it.

### 3. What the gate asserts, and what it deliberately does not

It runs `./core/asn/` and stops there. It is **not** a second copy of the test suite.

"It duplicates `ci.yml`" is not the reason, and is not an argument against a release
gate at all — a parallel `ci.yml` gates nothing, which is the whole finding in §1. The
reason to stop at the table is different and specific:

**Every other assertion in this repository is a function of the tree.** `ci.yml`'s run on
the pull request that merged those bytes is durable evidence about them; re-running it at
tag time re-derives the same verdict from the same input.
`TestEmbeddedTableIsFresh` is the only assertion here whose verdict changes with the
**calendar** rather than with the tree — it compares `TableRetrieved` against today, so a
tree that passed it on the day it merged fails it on day 91 with nothing having changed.
What has to be re-asserted at the moment of release is what expires.

And re-asserting the rest has a cost that is easy to miss: `ci.yml`'s `server` job needs
user namespaces, `nftables`, `iproute2` and two sysctls before `cmd/bacchus-netd`'s
real-kernel tests can run at all (ADR-0049). A second copy of that apparatus inside
`release.yml` would rot unnoticed, because release runs are rare — and a **half** copy is
actively worse than none, because those tests would silently SKIP and the job would
report green over the only real-kernel coverage the repo has. That is the same
green-over-nothing shape the gate exists to remove.

Two smaller decisions fall out of the same worry:

- The gate runs the **package**, not `go test -run <name>`. A `-run` filter matching
  nothing exits 0, which is the linker's silent-`-X` failure in a different costume.
- The existence of the assertion is **checked**, not assumed: the job asserts
  `go test -list` names `TestEmbeddedTableIsFresh` before running anything.

And the wiring is asserted from the other side.
`core/asn.TestReleaseWorkflowGatesTheTable` reads `release.yml` and fails if the gate job
is missing, if it stops setting the environment variable, or if `windows-bundle` stops
`needs:`-ing it. It runs in `ci.yml`, on every ordinary pull request — so the workflow
that gates merges is what guards the workflow that gates releases. Mutation-testing it
found a real hole before it shipped: a plain substring search for the environment
variable was satisfied by the comment that explains the environment variable, so deleting
the `env:` entry left the check green.

**One residual, named rather than hidden.** Nothing in `release.yml` checks that the
tagged commit is one `ci.yml` ever saw. A tag on a commit that never went through a pull
request has been tested by nothing at all, which weakens §3's "durable evidence" argument
for everything except the table. That is a property of the release process rather than of
this table, and it is #151 rather than something fixed here.

> **Update (2026-08-04, #151): closed.** `verify-version` now refuses a tag whose commit
> `main` does not contain, so the premise this section's scope was chosen on is enforced
> rather than assumed. The fifth amendment below records the ruling, what it forbids, and
> the one thing ancestry still does not establish.

### 4. Which platform this actually covers

**Covered: Windows.** `release.yml` builds the Windows portable zip and installer, so the
gate covers everyone who installs Bacchus for Windows from a GitHub release. Release
scope for 1.0 is Windows and Linux desktop, so that is one of the two.

**Not covered: Linux.** `deploy/install.sh` builds `clients/fyne` from the checkout it is
run in, at whatever revision that checkout happens to be at, stamps it from `VERSION` and
runs no tests. There is no Linux release artifact, so there is no Linux release to gate.
A Linux user's table age is bounded by the 90-day floor on `main` **plus however stale
their clone is**, and the second term is unbounded — a year-old clone installs a
year-old table and nothing anywhere says so.

Stated plainly because the phrase "refreshed per release" reads as covering both and does
not: **"per release" only bites on the platform that has releases.** Making the source
install assert the floor is one `go test ./core/asn/` before the build, in a file this
change does not own, and it is a different bar — an install is not a release. That
decision, with the reason refusing may be exactly wrong for the user this client is for,
is #149.

> **Update (2026-08-03):** #149 is ruled — **warn, never refuse.** `deploy/install.sh`
> now runs `go test ./core/asn/` against the tree it is about to compile, before the
> build, and a failure is printed rather than fatal.
>
> Refusing was the live alternative and it is the wrong one *for this user*. The person
> this client exists for is on a censored network installing from the clone they managed
> to obtain, and the degradation they would be refused over fails **toward** §3's unknown
> pooling rather than toward a false claim of diversity. A refusal there trades a working
> client for a quality margin, which is the trade backwards. The floor stays the bar CI
> applies to the repository; the install reports it.
>
> The warning's text is part of the decision, not packaging. It names **what** degrades
> (AS-diversity scoring for multi-hop chains, roughly one verdict in nine at a year, per
> §6) and **what to do** (`git pull`), because a warning that names neither is one a user
> learns to skip, and a warning everybody skips is worth exactly as much as no check.
>
> `--binaries DIR` remains genuinely uncoverable: it skips the toolchain, so there is no
> tree to test and no assertion this script can make. It now says so as a note, naming
> the check to run in the checkout the binaries were actually built from, rather than
> leaving that as an unstated gap.
>
> What this does **not** change: the source install is still not a release, the two bars
> stay different by design (§2), and a Linux user's table age is still their clone's age.
> This makes that visible at the one moment they can act on it.

### 5. The scheduled refresh: options priced, not ruled

#66 named a scheduled job that opens a refresh PR as worth considering and explicitly did
not decide it, and #85's closing comment gives the argument for it: a detector that only
fails a build after the fact still depends on somebody remembering, which is exactly the
failure mode the country-database timer removed. The gate above does not change that. It
refuses a stale release; it refreshes nothing.

What the country database never had to answer, and this does: **who holds the repository
write credential.** The country refresh writes a file into `/var/lib` on an operator's own
machine, which needs no credential and no repository. This one produces a *commit*.

**A. Scheduled job opening a PR with a stored repository-write credential** (a PAT or a
GitHub App installation token in a secret). Removes "somebody must remember" outright.
Costs a credential that can write to this repository sitting in CI, reachable by anything
that runs in a workflow. ADR-0052 §6 refuses to let CI hold the *update signing key* on
the ground that a build machine that can sign is a build machine that can push code; a
repository-write token is a weaker form of the same object and the sentence still applies
to it.

**B. The same, using the built-in `GITHUB_TOKEN`** with `contents: write` and
`pull-requests: write`. No stored secret at all — but GitHub does not start workflow runs
for events created by `GITHUB_TOKEN`, so the refresh PR would arrive **with no CI on it**,
including the very freshness test that motivated it. (Documented platform behaviour;
nothing here has observed it.) A pull request nothing checks, whose entire diff is 3 MB of
opaque binary, is a worse artifact than a reminder.

**C. Scheduled job with no repository write at all.** Fetch upstream, run `asn-stage`,
compare against the committed table, and fail loudly when it differs — carrying over
`bacchus-geoip-refresh.sh`'s discipline for the fetch half: stage atomically, fail loudly,
leave the previous file intact on a bad download. No credential, no PR, no branch. It
removes "somebody must remember" — the run is on a timer and its failure is visible — but
not "somebody must act".

**The argument that cuts across all three**, and that this record thinks is the real one:
the table is 3 MB of third-party bytes, and this ADR committed it *specifically so a
reviewer can regenerate it from the same feed and compare byte for byte*. That check needs
a human to perform it. An auto-opened PR whose diff no reviewer can read invites
rubber-stamping precisely the property the determinism was bought to make checkable. It
does not make A wrong, but it raises A's bar: an automated refresh PR is only as good as
the regenerate-and-compare that CI would have to do on it, and B cannot do that at all.

**Recommendation, not a ruling — C**, because it buys most of what A buys at no custody
cost, and because the honest reason to still want A is that C leaves a human in the loop,
which is the thing the timer was supposed to remove. The choice is the owner's; it is a
credential decision, not a CI one. Carried as #150.

### 6. Consequences

- **A release cannot be cut on a stale table** — on Windows, which is where releases are
  cut. The refusal happens before anything is compiled and before any release object
  exists, so recovering from it costs a refresh commit and moving the tag, not deleting a
  draft.
- **A pull request that touches the release path now carries the 30-day bar too.** The
  workflow's `pull_request` trigger is path-filtered to `release.yml` and
  `deploy/windows/**`, so this is rare, and it is deliberate: a change to how releases are
  cut should not be green if a release could not be cut from it. It is also the only way
  the refusal path gets rehearsed before a real tag exists, which is the argument
  `release.yml`'s own header makes about every other release-only path in it.
- **The 90-day floor is unchanged**, and so is everything §6 measured. Nothing here
  revisits embedding, the source, the encoding or the fetch question.
- **`BACCHUS_ASN_RELEASE_TABLE` is a third environment variable of the same family** as
  `BACCHUS_REQUIRE_STAMP` and `BACCHUS_NETD_REQUIRE_NS`. The family is becoming a
  convention: an assertion that is inert by default because it would otherwise block
  unrelated work, made mandatory by the one job that needs it. Worth naming as a pattern
  before a fourth one is invented differently.
- **The gate is enforcement, not schedule.** §5 is undecided (#150), and until it is
  decided the refresh remains a documented human step with two tripwires under it rather
  than a thing that happens.
- **Three cards carry what this amendment names and does not build**: #149 (a Linux
  source install is outside the gate), #150 (the scheduled refresh's credential
  question), #151 (nothing checks a release tag points at a commit CI ever saw).
  #66 closes on the enforcement; none of the three is folded into it.
  > **Update (2026-08-04):** #149 and #151 are both ruled and built — see §4's update
  > and the fifth amendment. #150 is still open and is still a custody decision.

## Amendment (2026-08-04, #151) — a release is cut from `main` or it is not cut

The fourth amendment §3 chose the release gate's scope by argument rather than by
convenience: re-assert what **expires with the calendar**, because every other assertion
in this repository is a function of the tree and `ci.yml`'s run on the pull request that
merged those bytes is durable evidence about them. Then it named the thing that argument
rests on and did not have. Nothing checked that the tagged commit went through a pull
request at all.

That gap is not in the table gate — the table gate is exactly as strong as it was. It is
in the **premise the table gate's scope was chosen on**. A tag pushed onto a branch head,
a local commit, or anything else `main` does not contain built a bundle and drafted a
release from a tree the suite had never seen, with every job in `release.yml` green over
it, and §3's "stop at the table" was a preference rather than a conclusion for as long as
that was possible. So this is the same shape as the fourth amendment itself: not a change
of mind, but the enforcement an earlier argument had been assuming.

### 1. The decision: `main`-only ancestry

**A release is cut from `main` or it is not cut.** `verify-version` gains a second step,
after the tag/`VERSION` comparison, that refuses unless `git merge-base --is-ancestor`
places the tagged commit in `origin/main`'s history. It is a gate in the sense this
workflow already means by that word: `windows-bundle` `needs:` the job, so a refusal lands
before anything is compiled and before any release object exists — not even a draft.

Two steps rather than four more lines in one, because the failures are unrelated: a tag
naming the wrong number and a tag on the wrong commit are different mistakes made by
different people, and a run should say which in the step name before anyone opens a log.

**The alternative was asserting a green `ci.yml` run for the SHA** through the check-suites
API. It is the more permissive rule — it admits a hotfix cut from a branch, which is an
ordinary thing to want — and it is the more intricate one: an API call, a token, a policy
for a run still in progress, and a decision about which conclusions count. That intricacy
would sit in the one workflow in this repository whose publish half cannot be exercised
before it matters, which is the argument `release.yml`'s own header makes about everything
else in it. Ancestry needs one git command and no credential.

**What this forbids, stated rather than discovered.** A hotfix cut from a branch cannot be
released. If that is ever wanted it is a deliberate change to this policy and to the step
that enforces it — the check-suites route above, already priced — and not a flag reached
for at the moment somebody needs one. A hotfix that goes through `main` is unaffected,
which is every release this project has cut.

### 2. The fetch depth is part of the decision, not an implementation detail

`actions/checkout` defaults to depth 1, and on a tag push at that depth it fetches the
tagged commit and no branches at all. The ancestry question cannot be answered from that
clone, and **the way it fails to be answered is the trap**, because git does not say it
cannot tell:

| clone | what `git merge-base --is-ancestor <tagged> origin/main` does |
|---|---|
| no `origin/main` (checkout's default on a tag push) | `fatal: Not a valid object name origin/main`, exit **128** |
| `origin/main` fetched shallow, tagged commit deeper than the graft | exit **1** — a clean *"not an ancestor"* about a commit that is one |
| complete | exit 0, the true answer |

Measured on this repository, 2026-08-04: a clone shallow at depth 20 with the tagged
commit 55 back on `main` returns exit 1, with no error and no warning. The release is
refused, the log says the tag is off `main`, and it is not. That is worse than the hole
being closed, because it is a check that is confidently wrong — and it is precisely what
#151's own four-line sketch (`git fetch --depth=... origin main`) would have produced.

So `fetch-depth: 0`, and the clone is **checked rather than assumed**:
`git rev-parse --is-shallow-repository` and the presence of `refs/remotes/origin/main` are
both asserted first, each with a message naming `fetch-depth: 0` as the fix. This is the
rule the same job already applies to a missing `VERSION` file — a gate that opens, or
refuses for the wrong reason, when its input disappears is not a gate.

**The cost was measured rather than feared**, because the second amendment §7 says this
repository carries ~3.14 MB of committed table per refresh and git cannot delta a gzip, so
"full history" sounds expensive here. It is not: a fresh clone is **5.9 MB packed at full
depth against 5.4 MB at depth 1** — about half a megabyte over 65 commits, since the table
blob is in the depth-1 clone too. One ubuntu job, on a rare event.

The refusal is also **rehearsed on every run, including the dry ones**: a commit is never
an ancestor of its own parent and its parent always is one, so one pair of real commits
tests both directions of the answer before the release-only assertion is reached. That is
the same device as the version rule's self-test in `windows-bundle` and the same reason —
a release-only path whose first execution is a real release is what this file exists to
avoid. It does **not** subsume the depth guard, and is not written as though it does: the
depth-20 clone above passes both self-test lines and still answers the real question wrong.

### 3. What ancestry establishes, and the one thing it does not

The property wanted is *"`ci.yml` ran on this tree"*. What is asserted is *"`main` contains
this commit"*. They coincide because `ci.yml` triggers on `pull_request` **and** on
`push: branches: [main]`, so a commit that arrives on `main` — through a merge, or pushed
straight at it — starts a full run at the pushed tip.

**Where they come apart, named rather than hidden.** `ci.yml`'s push run is on the tip of a
push, not on every commit in it. A push of several commits directly to `main` gives the
interior ones no run of their own, and this gate would admit a tag on one. That requires a
direct multi-commit push to `main`, and nothing on the platform prevents it: checked
2026-08-04, `main` carries **no branch protection and no rulesets**, so "changes only
through reviewed, merged pull requests" is workflow discipline rather than something the
forge enforces. Ancestry is therefore a very good proxy and not the thing itself, and the
remaining sliver closes with branch protection rather than with more shell in this
workflow. It has **no card yet**, and this paragraph is not a substitute for one — which
is the fourth amendment's own lesson, since a residual it named and carried is what this
amendment exists to close.

**Scope is unchanged from the fourth amendment §4.** `release.yml` builds Windows, so this
covers the platform that has releases. A Linux source install through `deploy/install.sh`
is not a release, has no tag and no ancestry to check; #149 already rules what that path
does instead, and it warns rather than refuses.

### 4. Consequences

- **A release cannot be cut from a tree nothing tested.** The fourth amendment §3's
  "durable evidence" argument now rests on an enforced fact rather than a convention, which
  is what makes stopping at the table a conclusion instead of a preference.
- **The refusal names the policy, not just the assertion.** The failure text says why a
  release from off `main` is refused — that nothing re-runs the suite at release time, so a
  commit `main` does not contain has no run to inherit evidence from — because the person
  who hits this in a year needs the reason and not the rule.
- **`fetch-depth: 0` is now load-bearing on one job**, and removing it fails loudly and
  names itself rather than degrading. That is deliberate: of the two ways to break this
  check, the depth is the one that defends itself, and deleting the step outright is the
  one that would be silent.
- **Deleting the step outright is still silent**, and unlike the table gate there is no
  assertion from the other side yet. The fourth amendment §3 built
  `core/asn.TestReleaseWorkflowGatesTheTable` for exactly that reason — the workflow that
  gates merges guarding the workflow that gates releases — and the same treatment belongs
  on this step. Named here so it is not mistaken for having been done.
- **A pre-release tag is still unreachable**, unchanged. `verify-version`'s first step
  compares against a bare `VERSION`, so `v1.0.0-rc1` cannot pass it and never reaches this
  step. Nothing here revisits that.
