# 42. Country-only exit assignment, with a coordinator-derived country and country-granularity backpressure

- Status: accepted (issues #136, #146, #147); amended 2026-07-28 (issues #1, #2, #3 — see the amendment at the end); §8 updated 2026-08-03 (issue #113 — see the dated blockquote there)
- Date: 2026-07-25

## Context

Three problems in the same vertical, which is why they are one record.

**1. A node's country was its own claim.** It came from a hand-typed `-country` flag
(`COUNTRY=` in the unit file), stored verbatim, and advertised to clients. That is a
node self-report, and this project's standing rule is the opposite: an **observed**
address is trusted, a **claimed** one is not — the rule `coldstart.Entry.Ingress`
follows for a relay's forwarding address (#124, ADR-0038 §9-4) and `observedAS` follows
for a capacity attester's network (#158, ADR-0041). Country had escaped it. It also
failed the mundane way: a typo'd or forgotten tag silently corrupted the client's `-geo`
filter, which is how an exit was lost during multi-exit bring-up on 2026-07-12.

**2. The client picked an exact exit.** `connect{exitId}` meant the client chose the
node. That defeats balancing (the coordinator cannot move load it does not place) and it
is a small, stable **tracking handle**: "this user always asks for exit 7" is a
correlator that need not exist. The §5.1 release-plan perk "a stable user may pin an
exit" made the handle a *reward*.

**3. There was no backpressure.** A country whose every exit was spent answered a
connect with a bare error, indistinguishable from any other failure, so a client could
not tell "try a different country" from "that didn't work".

The capacity signal these need already exists and is merged: ADR-0040's declared limits
and ADR-0041's `RatingStore` / `capacity.Usable`. Issue #146 lists `Depends: B3 (#145)`,
the **serve floor** — but #145 is deferred behind #161, and waiting on it was
unnecessary: within-country ranking runs on the existing `Usable`/load view, and #145's
`serveFloor` composes as one more filter, still pinned at zero. That was confirmed
before this work started.

## Decision

### 1. Country is derived from the observed source address, never from the node

`core/geoip` resolves an IP to an ISO-3166-1 alpha-2 code from a **locally staged**
database. The coordinator derives each node's country from the source address it
observed the register arrive from (`deriveCountry`), for **exits and relays alike**, and
advertises the derived tag in the signed directory. `-country` drops to a **fallback
hint**, consulted only when the observed address resolves to nothing.

Local, never a lookup service — for two reasons, either of which is sufficient. An
outbound geo query would tell a third party the IP of every node in the network, which
is the single thing this design spends the most effort not leaking. And it would add a
dependency on reaching a foreign endpoint from inside a censored network, which is the
failure mode the whole architecture routes around. There is no fetch path in the
package: nothing in it can make a network call.

Node-side auto-detection was rejected for the reason #136 states: a node querying its
own public IP still produces a *self-report*, so the trust gap is unchanged and the leak
is added.

**Precedence is not configurable.** An observed resolution always beats the claim. The
claim is consulted only on an unresolved address — an unallocated range, or the loopback
every node registers from in a local stack, which is why the fallback exists at all.
`-geoip-required` removes the fallback entirely for a hardened deployment: no node
self-report can reach a client's country choice under any circumstance, at the cost of
making an unresolvable node unassignable.

Both paths pass through `geoip.Canonical`, so a tag that is not exactly two ASCII
letters becomes **unknown** rather than a string no filter will ever match. That is what
makes the typo class impossible instead of merely unlikely, and it incidentally settles
a standing asymmetry: `core/selection.filterGeo` compares case-**insensitively** while
the learned-path store keys case-**sensitively**, and if every tag the coordinator emits
is canonical upper-case the two agree by construction.

A heartbeat re-derives, because it refreshes the observed address. With one asymmetry: a
previously **observed** tag is never recycled as a hint, or a node moving to an
unresolvable address would keep the country it used to resolve to — laundering a stale
observation into a standing claim. A previously **hinted** tag is still exactly what the
node said, so it survives.

#### Why the CSV, and why the database is not committed

The input is MaxMind's **GeoLite2 Country CSV** — `Blocks-IPv4/IPv6.csv` joined against
`Locations-en.csv` — not the `.mmdb` binary. The CSV needs no third-party decoder, so
`core/geoip` is stdlib-only and the entire parse is auditable in one screen; a binary
decoder would be another dependency inside the path that decides which country a user is
sent to. And the CSV is the upstream artifact as published, so provenance is direct with
no conversion step to trust. The cost is that the table is held in memory (order 500k
prefixes) rather than mmap'd, which for a load-once coordinator is the right trade.

The files are **not committed** — a licensed third-party dataset, and bulk data besides.
`.gitignore` excludes them and `docs/RUNNING.md` documents fetching and staging, the same
pattern `clients/fyne/README.md` uses for `wintun.dll` (#165).

Columns are addressed **by header name**. MaxMind has reordered columns before, and a
positional parser would keep loading and silently read the wrong field as the country —
precisely the invisible corruption this issue exists to remove. A **stale** database is
reported (`DB.Stale`, 90 days) but never refused: stale geodata mislabels countries
without failing anywhere, so it must be said out loud, and taking a coordinator down
over data hygiene would be worse than the warning. A **configured-but-unloadable**
database, by contrast, is fatal: an operator who asked for derived countries must not
silently get self-reported ones.

### 2. The user picks a country; the coordinator picks the exit

`list` now returns a per-country map — `{country, exits, available, busy}` — and
`connect{country}` returns a session naming the chosen exit. **No client can ask for an
exit**: not as a tier perk (the §5.1 pin perk is superseded; stable's benefit becomes
priority and better exits *within* a country) and not as a debug affordance.
`connect{exitId}` is gone from the wire, not deprecated.

That removes pinning as an **entitlement**. It does not, on its own, remove it as an
**outcome** — see the retransmission residual at the end of this section, and §9's
`firstHop` residual, which together are the honest boundary of what §2 delivers.

`connect{firstHop}` (#142, ADR-0038) later added the one field a client may use to
name a node. It is accepted **only on a relay-mode connect** and refused otherwise
(`hop-needs-relay-mode`), because outside relay mode there is no onion and the node
named would be the node the client egresses from — this section's removal, undone
through §9's field. That guard is not a claim that naming is now harmless: see §9.

The reply must carry the chosen exit's id, and this is not informational: an exit's id
**is** its Noise static public key (ADR-0009), so a client cannot bring up the
end-to-end channel without knowing which exit it got. This is also why the coordinator
cannot silently substitute an exit for a client that named one — the reason a
compatibility shim was not an option even in principle.

`ExcludeSessions` carries **sessions this coordinator minted for this client** whose
exits it just failed against, so a retry is not handed the same broken exit — the
ADR-0035 relay-dedupe idea applied to exits now that the client no longer names one.

The first version of this carried **exit ids**, and that was wrong in a way worth
recording. "It can only say what you do not want" is true and irrelevant: a client that
excludes every exit but one has named the one it wants, deterministically, and exact
exit pinning is reconstructed out of its own removal. Exit ids are discoverable for the
asking, because every session reply necessarily carries one. Verified against the first
implementation: with three exits in a country and two excluded, the third was returned
on 200 of 200 picks.

Naming sessions instead closes the **assertion**. To exclude an exit you must first have
been *assigned* that exit, and assignment is the randomized tier pick you are trying to
steer; the complement can no longer be declared, only walked one assignment at a time.
Exclusion is therefore non-amplifying *relative to the cost of an assignment* — not, as
the first draft of this section claimed, relative to the cost of a reconnect. Those are
not the same number, and the residual below is why. Two guards sit on top:

- **Session binding.** A session is honoured only if it was minted for the requesting
  source address, so one client cannot name another's session to discover or steer
  around an exit it was never given.
- **A survivor floor.** The exclusion is honoured only while at least two assignable
  exits remain. Below that it is dropped **whole** and selection runs over the full
  candidate set, so the most a client can ever do is narrow the field to a set it still
  cannot choose within.

Three alternatives were considered and rejected as insufficient on their own, all of
which bound the attack without closing it: capping the list length (with `C` exits and a
cap of `k`, a target is still reached with probability `1/(C-k)`), making exclusion soft
(the target still wins whenever it is within an octave), and refusing when exclusion
would leave exactly one candidate (excluding all but *two* still halves the search, and
repeats). A length cap is kept, but as a **resource** bound on map construction per
datagram — not as the security property.

Dropping a rejected exclusion **silently**, rather than refusing the connect, is
deliberate. A refusal would tell the client its exclusion had crossed the threshold,
which is a one-bit oracle on how many assignable exits the country holds; repeated, it
counts them. An ordinary assignment reveals nothing a plain connect would not.

The aggregate is **strictly less** than clients used to get. The old reply enumerated
every exit id — a network map, and the raw material for a pin. Counts are neither.

**Residual: one connect was several assignments, not one — closed by the amendment
below (#1).** `sendN` sends each connect three times against UDP loss, and `connectVia`
does that once per mode, so a single `Connect()` can put six datagrams on the wire. The
handler processed each independently and minted a session per copy, every one through a
fresh randomized `chooseExit`. Measured with three exits in one country: **one
`Connect()` minted six sessions across three distinct exits.** A client that reads all
six replies and drives whichever names its target pinned in one round trip, with no
exclusion at all — with three exits, roughly nine times in ten.

The retransmission is not new and is not this ADR's doing. What is new is that it
*means* something: before §2 every copy named the same client-chosen exit, so the
redundancy was invisible. Country-only assignment turns each retransmit into an
independent draw.

Two consequences followed:

- Exclusion was cheaper to weaponise than the paragraph above implies, because one
  reconnect was up to six assignments. In a small country a single connect collected
  most of the complement.
- §3's load term was inflatable by a **client**, not just unforgeable by a node: five of
  six sessions were never used yet were counted for `sessionTTL`, so a client could push
  a competitor exit out of the tier at one datagram per increment, and — once `minShare`
  is non-zero — busy out a country.

Both close the same way, and the amendment at the end of this record does it: a
per-connect idempotency key, so duplicate copies of one connect return the same session
and the same exit.

So the property §2 establishes is: **a client cannot present a stable, declared exit
preference, and the coordinator cannot honour one.** With the retransmission residual
closed, an outcome reached by minting and abandoning sessions costs one full request per
draw — and every one of those requests is observed by the coordinator, which is the
sense in which it is louder than the mechanism it replaced. What remains is §9's
`firstHop` residual, which is a different door and is stated there.

### 3. Ranking is a coarse tier with a random pick inside it, not a sort

ADR-0033's `pickRelay` forbids a deterministic best-node pick, at length: a node that
could make itself the perpetual choice would collect every client's source address and
timing, and every coordinator in the pool would keep handing back the same node, so a
client failing over between pool members would keep landing on it. ADR-0040 draws the
same conclusion for declared limits — they compose as a **filter, never a sort**. #146
asks for a ranked pick, so the two have to be reconciled rather than one of them ignored.

The reconciliation: rank on **projected share** — the bandwidth one more session could
expect, `usable / (sessions + 1)` — then keep every candidate **within a factor of two
of the roomiest** (`capacity.OctaveFloor`) and pick among them via the same randomized
map iteration `pickRelay` already relies on. "At random" is the intent rather than a
uniformity claim: the winner is the first tier member in Go's map order, so per-key
probability is proportional to the preceding run of non-matching slots. It is
unexploitable (the hash seed is per-process) and it is exactly `pickRelay`'s existing
mechanism, but it is not a uniform draw and should not be described as one. Three
properties:

- A node must be about **twice** as roomy as the field to be preferred at all, so
  shaving a number buys nothing. The band is measured **from the best candidate**, not
  from fixed power-of-two buckets — an absolute bucketing puts a boundary in the number
  line that a node can sit just beneath and cross for a marginal gain. (This was found
  by a test: 1.0 and 1.9 Mbit straddle 2²⁰ and landed in different absolute buckets,
  falsifying the "within a factor of two" claim the first version of this made.)
- Ranking on projected share is **self-correcting** in a way freshest-first never was:
  every session assigned to the roomiest exit lowers that exit's own share, so the
  choice moves along by itself instead of piling onto one winner.
- An **unrated** node's capacity contribution is clamped to the same `Ceiling` the
  untrusted estimator clamps to. Without that, `RatingStore.Usable` falls back to the
  *declared* cap for an unrated node, and a node claiming 10 Gbit would outrank an
  honestly measured neighbour — paying for a claim in assignments, the exact trade #157
  refused. Clamped, **forging buys what silence buys**.

Two consequences worth stating plainly. Because every rating is ceiling-clamped while
the trusted stream is unfed (ADR-0041), candidates **tie on capacity today**, and the
only term that could discriminate is the **session count** — which this coordinator
observed itself and no node can assert. And `capacity.ProjectedShare` reports "no
information" (uncapped and unrated) as a **flag, not a number**, because both natural
encodings are wrong: `0` would rank an uncapped node last, and a maximum sentinel would
let an unrated node outrank every measured one forever.

**Ranking is therefore near-uniform in practice today, and that has to be said plainly
rather than implied away.** The `sessions` map is a *signaling rendezvous cache*, not a
tunnel registry. Only `offer`/`answer`/`candidate` refresh a session's `lastSeen`, and
pion stops emitting ICE candidates seconds after setup, so a perfectly healthy tunnel
goes quiet within seconds and its entry ages out after `sessionTTL` (2 minutes). In
steady state most exits read zero, tie at `Ceiling/(0+1)`, and the tier pick degenerates
to an arbitrary choice among all of them. The "self-correcting" property above holds for
about two minutes per session and then unwinds. When `minShare` is eventually raised,
`capacity.Full` will be equally blind.

That is survivable, because an arbitrary pick among equals is a *safe* default and the
one ADR-0033 argues for anyway — but only if the blindness is **uniform**. It was not.
`prune` deliberately exempts peer-relay sessions (their liveness is their relay's;
reselectDeadRelays is their sole reaper, issue #96/#105), so counting the raw map gave
an exit serving relayed traffic a permanent load figure while its direct-serving
neighbour read zero — systematically deprioritising exactly the exits carrying relayed
traffic. `exitSessions` now applies **one recency window to every disposition**, so both
decay identically. `TestRankingDecaysUniformlyAcrossDispositions` pins both halves.

No honest liveness signal is available to fix this properly, and the alternatives are
worse than the gap. The data plane deliberately does not touch the coordinator
(ADR-0009/0033), so it cannot observe a live tunnel. A node's own session count would be
a signal, and it is precisely the number a node profits from **understating** — the same
shape as a self-reported capacity, refused for the same reason (ADR-0040). A client
session heartbeat would work, and it would hand a coordinator this project assumes to be
untrusted (ADR-0020, #60) a per-client session-duration signal in exchange for load
balancing that nothing currently needs. The gap is recorded here and left open rather
than closed with a number that would be wrong.

Load is counted from the `sessions` map, not kept as a counter on the registry entry.
The register handler replaces a node's entry wholesale every ~10 s, so a count stored
there would silently reset on every heartbeat with nothing failing visibly — the
identical trap ADR-0041 §5 hit with ratings.

### 4. Backpressure is at country granularity, and it is named

When nothing in a country is assignable, `connect` is refused with
`reason:"country-busy"` and the country named, so the client can say
"<country> is busy — try another" (#147). An unknown or malformed country is a distinct
`reason:"no-such-country"`.

Naming the reason reverses the pre-#146 reticence, which deliberately answered every
failure identically so a prober could not tell "no such exit" from "out of quota". That
argument does not carry here: both facts are already in the country map the same
credentialed client just fetched, so naming them reveals nothing new — and #147
specifically requires the client be able to tell the two apart, because they call for
different behaviour.

A busy country **stays in the list**, marked `busy`, where the pre-#146 code dropped a
withheld exit entirely. A country that vanishes cannot be labelled busy: the user would
watch it disappear instead of being told to try another.

`available` is computed by the **same** predicate assignment uses (`exitAssignable`), so
the aggregate can never promise what `connect` would refuse.

### 5. What is live today, and what ships off

`exitAssignable` withholds an exit for four reasons. Two are **live**: a spent declared
monthly quota (#143), and no derivable country (§1 — such an exit is registered,
healthy, and unreachable, so the register handler logs a warning). Two ship **off**:

- `serveFloor` (#145) stays at zero, unchanged by this work.
- **`minShare`, this record's own gate, ships at zero.** A share floor above zero,
  applied to ratings that are all ceiling-clamped, would cap a rated exit at a couple of
  dozen sessions when it can carry orders of magnitude more — stranding users to protect
  a number that is not yet real. It is #145's trap reached from the other direction, and
  it lifts on the same condition: a fed trusted stream.

So #147 is **not** inert: its quota-exhaustion trigger works today. What is off is only
the share-based trigger.

The opt-out that survives is **narrower than it first reads**, and an earlier draft of
this record stated it far too broadly. `capacity.Full` never catches a node that
declared nothing **and has been measured at nothing** — the standing opt-in promise
declared limits make everywhere else (#143). It stops exactly there.
`RatingStore.Usable(0, measured)` returns `measured`: a declared zero means *uncapped*,
and that does not survive a measurement. So an exit that declared nothing but has
received **any** capacity report is rated, carries a finite usable rate, and **is**
subject to the floor — which under ADR-0041's "measurement IS serving" is the entire
serving fleet. Raising `minShare` therefore *would* reach today's fleet; the claim that
it "could not strand it even by accident" was false, and is withdrawn. Only the
never-measured, never-declaring node is out of reach.

`capacity.Full` takes `Unmetered(declared, rated)` rather than inferring the exemption
from the rate. The obvious shorthand — `usable == 0` — is right until a caller passes a
transformed rate, and `RankShare` clamps an unrated node to the *ceiling*, which is
non-zero: a gate keyed on the rate would silently invert for exactly the nodes the
promise protects. Neither a declaration nor a rating flag can be altered by a clamp on
the way in.

### 6. Per-country ping ships as an unfed seam

`countryInfo.PingMs` exists and is **always 0**, `omitempty`, so it is not even on the
wire. This is deliberate, and it is the same shape ADR-0041 used for its trusted stream.

The only honest source of a client-to-country latency is the **clients**, and their
reporting path is outside this lane. Deriving it from this coordinator's own RTT to each
exit was considered and rejected: it measures coordinator-to-exit latency, which is not
the quantity the user is choosing on, and a plausible-looking wrong number is worse than
a blank. The field ships so the shape is settled and a client can render it the moment
it is fed.

Note for whoever feeds it: the privacy objection to client-reported RTT does not hold.
The coordinator already observes every client's source address directly — that is how
`observedAS` works — so an aggregate per-country ping built from client reports gives it
nothing it cannot already see. What the *published* aggregate costs is genuinely nothing,
as #146 says.

### 7. Where the loader stops, and what the operator log has to carry

`readBlocks` skips any row it cannot use — the other family's rows, and rows MaxMind
attributes to no country — and `Load` errors only when **both** families end up empty.
That combination let a mismatched or partly-corrupt CSV load "successfully" while every
node in the missing ranges quietly fell back to its own self-reported hint: the exact
outcome deriving country from an observed address exists to prevent, reached without a
single error.

Two things narrow it, deliberately split by who knows what:

- **In the loader**, a *ratio*: a blocks file more than half of whose data rows are
  unusable is refused, because that means the blocks and locations files are not from
  the same release. A ratio rather than a row count so it means the same thing for a
  four-row fixture as for a four-hundred-thousand-row release, with no threshold to keep
  in step with MaxMind's publication sizes. The skipped count is exposed (`DB.Skipped`)
  rather than discarded.
- **In the coordinator**, an absolute floor. Only this binary knows it was pointed at a
  GeoLite2 Country release, so only it can say a thousand prefixes is implausible; the
  package is a CSV loader that must stay usable with small fixtures. Startup logs the
  loaded and skipped counts and refuses to run below the floor.

Neither catches a file truncated at a line boundary to, say, 60% of its rows: it has
hundreds of thousands of valid prefixes, skips nothing, and is indistinguishable from a
smaller publication. Catching that needs a checksum against MaxMind's published digest,
which belongs to the staging pipeline rather than the loader. Recorded, not closed.

### 8. Country is derived from signaling; the data plane is bound to it only partly

`deriveCountry` resolves the source of the **register datagram** — the signaling
address. An exit also advertises a data-plane endpoint of its own (`-advertise`), and
the first version of this compared nothing. An operator running an exit in country Y and
forwarding only its coordinator signaling through a cheap host in country X (socat,
DNAT, a tunnelled control channel) got `country=X` derived and advertised to clients
while traffic egressed in Y. `-geoip-required` did not help: the address resolved fine,
just to the wrong machine. For a product whose entire user-facing choice is
jurisdiction, that is the misrouting the feature exists to prevent.

The two are now compared. When the advertised host is an IP equal to the observed
source, signaling and data plane are the same machine as far as this coordinator can
tell and the tag is `observed`. When they disagree — or when the advertisement is a
**name**, which is not checkable without a DNS lookup this coordinator will not perform
on its packet handler for a string the node chose — the tag is recorded as
`observed-signaling-only`, logged loudly, and under `-geoip-required` the exit is given
**no country at all**, which makes it invisible to country-scoped assignment.

**There was one exception, and it was the default — closed by the amendment below (#2).**
An exit that advertises *nothing* had made no claim to contradict, so the comparison
passed vacuously and the tag stayed `observed`. `-advertise` is empty by default and a
direct-mode exit never needs it — relays dial an advertised address, ICE does not. So the
split-endpoint operator described above defeated the check by omitting a flag they had no
reason to set, and did so under `-geoip-required`. Of the two ways to close it — treating
an empty advertisement as unverifiable when that flag is set, or requiring `-advertise`
for the exit role — the amendment takes the first, and says why.

Until that landed the flag's promise was narrower than "no self-report reaches a client's
country choice". It was that no **contradicted** self-report did — worth having, since it
made the split endpoint a configuration an operator had to deliberately avoid rather than
one they got for free, but not the guarantee the name suggests.

**The residual, stated rather than papered over.** The advertised address is still a
claim; it is now a claim that must agree with an observation, not an unconstrained one.
The coordinator never sees the egress: in direct mode the data path is decided by ICE
candidates the exit puts in its own SDP, and nothing in the protocol reports where a
packet finally left from. An operator who places their whole apparatus behind one
address can still egress elsewhere. Country is a strong signal about where a node sits.
It is not a proof about where its traffic leaves, and `deploy/README.md` says so in the
same words.

> **Update (2026-08-03):** the country the node claims is no longer thrown away, and an
> admin can correct the one this coordinator derives (issue #113, owner ruling B).
>
> §8 above resolves a country and returns it. It also computes a *second* answer on the
> way and discards it — `deriveCountry` had the node's own `-country` tag canonicalized
> in hand at the moment it returned the observed one — so from the instant a node
> registered, nothing anywhere could tell there had ever been two. Staging the country
> database on a real fleet for the first time is what made that visible: restarting with
> a database flipped **two exits out of three**, same nodes, same addresses, same
> registrations. The operator knew where those machines were, because they rented them.
>
> **Both claims are now carried, and they answer different questions.** The derived
> country answers *"what will every destination site conclude about a user egressing
> here"*, which is a property of the ADDRESS. The declared one answers *"which building
> does the traffic physically leave from"*, which is a property of the MACHINE and which
> only its operator knows. `coldstart.Entry.DeclaredCountry` carries the second beside
> the first, `omitempty`, in the pattern `Ingress` and `Operator` already use — so a
> pre-change snapshot is byte-identical on the wire and `SnapshotVersion` does not move.
> Nothing in this repository selects, filters, groups or displays on it, and nothing
> should: a user who picks DE picks it to **be treated as** German by every site, and an
> address that resolves US is treated as US regardless of which building it sits in.
>
> It is carried under `-geoip-required` too, where it is precisely *not* the country.
> That flag's promise is that no node self-report reaches a client's country CHOICE, and
> a labelled claim that is never `Country` is not that choice — such an entry ships with
> `Country` empty and the declaration beside it, which is the honest shape of "the node
> says DE and this coordinator will not confirm it". It is also **not elided when it
> agrees**: collapsing *made no claim* into *made a claim that checks out* is the exact
> bug the #2 amendment below closed for the advertised endpoint, and this field has the
> same shape.
>
> **The disagreement is the ORDINARY case, and `CountryContradicted` must never learn
> it.** That predicate is fail-closed — `core/relaychain` refuses a contradicted entry as
> a terminating exit — and what it names is the coordinator's own *two observations*
> disagreeing, both checkable. A node's declaration disagreeing with an observation is a
> different animal: a large cloud provider's block is commonly registered to that
> provider's home country whatever datacentre an instance runs in, so an instance in one
> country resolving to another is normal rather than anomalous. Feeding it into the
> fail-closed test would refuse most of a cloud fleet and stop a client chaining at all
> against a coordinator behaving exactly as it always has — the same failure this record
> already rejects for `hint`, one step further out. `Entry.DeclaredCountryDiffers()`
> observes the difference and deliberately refuses nothing.
>
> **An admin can correct the derivation: `-country-overrides`.** A `{"nodeID":"CC"}` JSON
> file in `-operators`' shape — coordinator-side truth, explicitly not a node self-report
> — carrying its own provenance, `admin-override`, distinct from `observed` and `hint`
> because an admin correction is neither: calling it observed would claim a resolution
> that did not happen, and calling it a hint would credit the node with a statement it
> never made. It replaces the derived country everywhere the derived country is used: the
> country aggregate, assignment, and the signed directory.
>
> **It wins, including under `-geoip-required`.** That flag's promise is about NODE
> self-reports, and an operator assertion is not one — it has the same standing
> `operators` has. This is written into the flag's own text as well as here, because a
> guarantee that narrows one quiet exception at a time ends up guaranteeing nothing, and
> that already happened to this flag once (#2 below).
>
> **It is a correction to the DERIVED value, never a promotion of the DECLARED one.**
> Legitimate: *"your GeoIP table is wrong — this address really does present as DE"*, an
> assertion about the ADDRESS that an admin can check against what real sites conclude
> and this coordinator cannot. Illegitimate: *"the machine is physically in DE even
> though its address resolves US"* — that is the declared value, and promoting it
> delivers exactly the misrouting this section exists to prevent, arriving from the
> operator's side instead of the node's. Both are the same two letters at the moment of
> editing, so the distinction is enforced by being **legible where the admin meets it**:
> the flag text and the file's documented format, not only here.
>
> **What it costs, stated rather than papered over.** An override is terminal: the
> derivation runs to completion and is then replaced wholesale, so for an exit the
> signaling-vs-advertised-endpoint comparison is not re-run against the correction and
> cannot demote it back to `observed-signaling-only`. Overriding a split-endpoint exit
> therefore switches off the one label a chaining client fails closed on. An override
> that *could* be demoted would not be an override, so the cost is paid and made visible
> instead: the derivation is applied last precisely so the coordinator still knows what
> it would have concluded, and it logs a WARNING naming the verdict a correction
> displaced.
>
> **Hot-reloaded, which is against the nearest precedent and deliberately so.**
> `-operators` is read once at startup, and that is right for what it holds: an
> ownership assignment changes on a planned event around which a restart is nothing.
> Ruling B has an admin edit this file **when prompted** — the coordinator surfaces a
> country it could not agree on and somebody answers — so a correction behind a restart
> is a correction that gets deferred, batched and eventually not made. The two revocation
> files are the precedent for the other choice and the closer analogy besides: like a
> revocation, this is an admin saying part of what the network currently believes is
> wrong, and the interval between believing it and stopping is the whole point. A country
> is re-derived on every heartbeat already, so an edit lands within about one reload plus
> one heartbeat with no restart and no touch to the node. The risk hot reload adds — a
> bad write changing what is published with nobody at a terminal — is bounded two ways: a
> file with any unusable row is refused WHOLE (partial application produces a correction
> that looks applied and is not, which is the failure #113 was found through), and a
> refused reload keeps the corrections already in force. Note also that unlike a trust
> anchor, a wrong value here cannot widen who may join the network; it can only mislabel
> where a node is, which is visible, one edit from reversible, and already the thing the
> admin was asked about.
>
> **The prompting is designed here and built elsewhere (#148).** This coordinator has no
> admin surface at all — `net/http` appears once in `cmd/coordinator`, as a *client*
> fetching the policy bundle — and giving it one would mean an authenticated
> administrative listener on the binary whose attack surface this design keeps smallest,
> to solve a presentation problem. The admin console is `bacchus-payment#20` `[F1]` and
> is unbuilt. So the correcting half is local and per-coordinator today, and the open
> question is how a central correction would reach a pool: it can ride the **signed
> policy bundle** (ADR-0043), which every coordinator already fetches and verifies
> against an offline root, or a **sibling signed document** on the same path. The bundle
> carries floors, fences and reserves — network-wide numbers a coordinator cannot author
> — where a per-node country map is *identity-scoped* data of a different kind: putting
> it in the bundle grows every coordinator's policy fetch with the fleet's node count and
> puts a country correction behind whatever ceremony a policy revision needs, while a
> sibling document is a second delegation and a second fetch path to get right. Named,
> not decided — it needs the owner.
>
> **What this does not settle**, and must not be settled by accident: which value is the
> DEFAULT for selection (ruling B keeps it the derived one for 1.0), what a client shows
> (nothing new — the picker is per-country while the disagreement is per-exit, so there
> is no "the declared country" of a country to display), and whether the declared value
> needs any corroboration at all. It is still a bare assertion; carrying it beside a
> derived value that contradicts it is honest, presenting it as equally verified would
> not be.

### 9. What this leaves for client-assembled relay chaining (#142, ADR-0038)

Chaining needs a client to name a **first peeling hop** distinct from the terminating
exit. Landing it later must not require a second incompatible change to this wire, so
three commitments are made here rather than discovered then.

**`country` always names the terminating exit's country.** Never an intermediate hop's.
A `firstHop` field added later changes what the coordinator *pairs* the client to; it
must not change what `country` *means*, or the user's chosen jurisdiction would silently
describe a node whose location is irrelevant to where they egress.

**A session's `exitID` records the terminating exit and only that.** The naive shape —
storing the first hop there because it is the node the coordinator wired — would attribute
chained load to the wrong node, and the session count is the only term in §3's ranking
that could discriminate at all. When the coordinator does not know the terminating exit
(which in chained mode is the *point*), `exitID` stays **empty** and the session is
invisible to exit ranking rather than charged to a hop. `exitSessions` already skips
empty ids, so the shape is enforced today; the `relayID` slot already exists for "who
carries this session", separate from "who terminates it", and chaining reuses it.

**Exit discovery for a chaining client is the signed snapshot, not a coordinator reply.**
This is the question removing the per-exit list actually raises: `buildChain` needs a
concrete exit id to encrypt its innermost layer to, and there is no longer a live reply
carrying one. The answer is `core/coldstart`'s snapshot, which already carries exits with
their countries and is **signed** — strictly better than the list it replaces, and the
same artifact ADR-0038's hop selection already reads. #146 removes the *unsigned live
enumeration*; it does not remove the directory. `core/` does not read exits out of the
snapshot today, and wiring that is chaining's work, not this record's.

Signed is strictly better than unsigned, and it is not the same thing as *verified*: the
signature proves the coordinator said the country, not how it arrived at one. That
distinction is the subject of the #3 amendment below, and it became load-bearing the
moment chaining shipped and this paragraph's "not today" became today.

**And the tension worth naming, because it looks like a contradiction and is not.** A
chaining client *does* choose its own terminating exit, which is exactly the pinning
this record removed. The two coexist because the property being protected is not "no
client may know which exit it uses" — a client always knows, it holds the exit's static
key. It is that **a client must not be able to present a stable exit preference to the
coordinator**, which is a tracking handle for an untrusted coordinator (ADR-0020) and a
defeat of load balancing. In chained mode the coordinator learns the first hop and never
the exit, so there is no handle to present. The two features trade the same piece of
information in opposite directions, and both are coherent for the same reason.

**What that argument assumes, and what is actually enforced.** It assumes the client
is chaining. The coordinator cannot check that, and the reason it cannot is the
feature itself: the terminating exit lives inside an onion layer it must not be able
to read. So the argument above holds for an honest client and states a *convention*,
not a guarantee.

What is enforced is narrower, and it is the whole of the guard: `firstHop` is honoured
**only on a relay-mode connect**, and any other mode — `direct`, or unset — is refused
with `hop-needs-relay-mode` before anything is paired
(`TestConnectFirstHopIsRefusedOutsideRelayMode`). That closes the case where the wire
itself asks to be paired directly with a named node, which is pinning with no cover
story and the only form of it this record can detect.

What remains open, stated rather than argued away: a client may ask for relay mode,
name the node it wants, and simply terminate there instead of peeling. The coordinator
sees a well-formed chained connect and pairs it. Such a client has reconstructed a
stable exit preference and presented it — so for that client, and only that client,
§2's property does not hold. Two consequences follow and neither is theoretical:
load balancing can be gamed by a client willing to do this, and the tracking handle
§2 calls out exists again, though now only for a client that chose to create it.

This was a decision, not an oversight. Closing it properly means the coordinator
assembling the chain rather than the client naming its head — which hands path
selection to the single party multi-hop exists to defend against, and would let a
coordinator answer with three nodes it runs and watch the whole route. Trading a
bounded load-balancing and self-inflicted-fingerprint problem for that was judged the
worse deal. Revisit it if per-hop admission credentials (#175) ever make a hop's role
checkable, since a head that must prove it is serving as a relay is a different
question from one that merely says so.

## Consequences

**Good.**

- Country joins Ingress and Operator as coordinator-established fact **when the
  coordinator is run with `-geoip`**. It is bounded, and §8 states exactly how far it
  goes: with the flag unset — the default — country is still entirely the node's own
  claim, and even at the strictest setting what is verified is where a node *signals
  from*, not where its traffic *leaves from*.
- The pinning tracking handle is deleted rather than restricted, and the coordinator can
  balance load it now actually places.
- Relay country stops being silently discarded — relays registered a `-country` that had
  nowhere to live — and is now derived and carried in the signed directory, which
  ADR-0038's hop selection can use.
- A full country is *sayable*. "NL is busy, try another" replaces "your connection
  failed".
- Ranking discriminates on the one input no node can forge (observed session count), and
  the capacity term is clamped so it stays that way until a trusted rating exists.
- `minShare` and `serveFloor` are both real machinery pinned by tests in **both**
  directions — inert as shipped, and provably effective when raised.

**Bad / open — stated plainly.**

- **This breaks the wire, and `core/` moves with it.** `connect{exitId}` and the `exits`
  list reply are gone; a client sends `connect{country}` and reads the chosen exit off
  the session reply. The owner's call (2026-07-25) is that there is no installed base
  before v1, so a shim would be pure cost.

  The first attempt shipped the coordinator half alone, and that is worth recording as
  the mistake it was: `core/` still sent `{"type":"list"}`, required a reply typed
  `exits`, routed neither `countries` nor anything unrecognized, and never set a country
  on a connect — so no client in the repo could connect, and the full suite stayed green
  because **every test on both sides answered a hand-rolled fake still speaking the old
  protocol**. A fake on both ends of a protocol tests the fakes. Both halves land
  together here, and `cmd/coordinator/protocol_integration_test.go` now puts the real
  handler and the real client on opposite ends of a real socket so a protocol change
  cannot pass on fakes again.

  Client surfaces are converted only as far as the removed API forced: `cmd/node -list`
  prints countries, the Windows tray picker selects a country, and the Fyne controller's
  list-and-pick-the-first-exit engine is gone. The *pickers* — a proper country UI with
  busy states and ping (#150 and its Windows equivalent) — remain the client lane's work.
  `core.Config.ExitID` survives as an accepted-and-ignored field so those clients keep
  compiling, and `New` emits a loud error event when a client sets it: a pin that is
  silently dropped leaves a user believing their traffic leaves through one specific
  node while the coordinator is choosing. It should be deleted with the settings control
  that writes it.
- **The capacity half of the ranking is inert today.** Every rating is ceiling-clamped
  while the trusted stream is unfed, so only load discriminates. This is ADR-0041's
  latency showing through, not a defect here, and it resolves when that seam is fed.
- **An unrated node's declared cap still sets its `Full` threshold**, even though it is
  clamped for *ranking*. A node could declare a small cap to be considered full early
  and shed load. It only ever reduces what that node is given — the same "binds downward,
  therefore trusted" argument `wire.SpeedCap` already rests on — so it buys an operator
  nothing but less work. Worth revisiting only if a node is ever *paid* per session.
- **GeoIP is a third-party judgement about where an address is.** It is wrong sometimes,
  and when it is wrong a node is mislabelled or unassignable, with the operator's
  `-country` no longer able to correct it (that is the point). The staleness warning and
  the provenance documentation are the mitigations; a per-node coordinator-side override
  is deliberately **not** offered, since it would reintroduce a hand-typed tag by the
  back door.
- **No IPv6 country table is required.** `LoadDir` tolerates a missing IPv6 blocks file,
  so a v4-only staging silently leaves every IPv6-registering node unresolved and
  falling back to its hint. Deliberate — a v4-only staging is a legitimate deployment —
  but it is a way to get self-reported countries while believing they are derived, so
  the startup log states the loaded prefix counts per family.
- **Exclusion is bounded but not free.** Naming sessions rather than exit ids means a
  client must be *assigned* an exit before it can exclude it (§2), so the complement can
  only be walked at the same cost as ordinary reconnection, and a survivor floor stops
  it narrowing the field to one. What remains is that a determined client holding `k`
  live sessions raises its odds of landing on a chosen exit from `1/C` to `1/(C-k)`, and
  in a country with few exits that is not a small factor. It is a *bias*, not a pin, and
  closing the last of it would mean refusing exclusion altogether — which costs every
  honest client its retry.
- **Exit ranking is near-uniform today** (§3). The load term measures signaling
  liveness, not tunnels, so it decays within `sessionTTL` of a connect and most exits
  read zero. It is now uniformly blind rather than biased against relay-serving exits,
  which is the part that was actually harmful; a real liveness signal needs either a
  node self-report (wrong shape) or a client session heartbeat (a linkability cost),
  and neither is worth paying for load balancing nothing yet needs.
- **Country describes where a node signals from, not where its traffic leaves** (§8).
  The advertised data-plane endpoint must now agree with the observed signaling source,
  and `-geoip-required` refuses a split — and, since the #2 amendment, refuses an exit
  that advertises no endpoint at all rather than treating silence as agreement. The
  coordinator still never observes the egress itself, so this bounds a claim rather than
  proving a fact.
- **The loader cannot detect a cleanly-truncated database** (§7). A ratio check and a
  coordinator-side floor catch mismatch and gross truncation; a file cut at a line
  boundary needs a staging-pipeline checksum.
- **Ping is unfed** (§6), so the country list is a capacity map but not yet a latency
  map.

## Relationship to other work

- **ADR-0033** (`pickRelay`) supplies the anti-determinism argument §3 reconciles with;
  the relay pick itself is unchanged, and remains a filter plus a random choice.
- **ADR-0035** supplies the retry-dedupe pattern `ExcludeSessions` mirrors for exits.
- **ADR-0038 §9-4** (#124) supplies the observed-IP-derived-metadata principle §1
  applies to country, and gains a relay `Country` in the signed directory.
- **ADR-0040 / ADR-0041** supply the capacity signal, the `Ceiling` clamp §3 reuses, and
  the "ship the gate off, pin it in both directions" pattern §5 follows.
- **ADR-0009** is why the chosen exit's id must come back on the reply (§2).
- **#145** (serve floor) and **#10** (credential tier) remain the two inputs #146 named
  that this record does not supply: the floor stays at zero, and client-tier ranking is
  unstubbed — country, headroom and (later) ping are the shippable core, as #146 allows.
- **ADR-0025**'s `-geo` client filter is no longer a filter over a client-fetched exit
  list — it *is* the connect's country, and the only thing a connect names.
- **ADR-0028** (transport pool): the ladder's per-exit dimension becomes per-country,
  since a candidate must name something a client can ask for. The exit arrives with the
  session and is swapped into the end-to-end key alongside it on every failover.
- **ADR-0030 / ADR-0037**: `readLoop` now logs any reply it cannot route. A well-formed
  message matching no case was indistinguishable from silence, and silence is the
  mesh-walk trigger — the failure mode was a client walking the mesh against a perfectly
  healthy coordinator.
- **#142 / ADR-0038** (relay chaining): §9 records the three wire commitments that let
  it land as a pure addition.

## Amendment (issues #1, #2, #3, 2026-07-28): the three residuals this record left open are closed

This record shipped with three named gaps: §2's retransmission residual, §8's empty
advertisement, and the provenance §8 computed but did not carry past the coordinator.
Each was stated rather than papered over, which is why they were findable; each is closed
here. **No new ADR number is minted — these change what this record's own sections
claim, and a reader who does not reach the follow-up must not be left with the old
promise.**

### 1. `connect{nonce}` — one request is one assignment (#1)

**This is a wire change.** A connect now carries a client-minted per-connect idempotency
key, and a connect without one is **refused** (`reason:"connect-needs-nonce"`).

The coordinator remembers the answer it minted against `(observed source address,
nonce)` and replays exactly those bytes — both the assign to the paired node and the
session reply to the client — for every later copy of that request. One request, one
`chooseExit`, one exit.

*Why refused rather than optional.* An idempotency key a client may omit is not a guard,
it is an opt-in: the client that wants several independent draws is precisely the one
that would leave the field off, so an additive version would bind only the honest. This
wire was already broken once by §2 on the owner's "no installed base before v1" call, and
both halves land together here as they did there.

*Why the source address is in the key.* The same reason it is in §2's session binding.
Keyed on the nonce alone, a client that observed or guessed another's key would be handed
that client's session — learning which exit it was given, and able to steer its own
retries around it. Several clients behind one NAT share an address but not a port, so the
full `UDPAddr` is what separates them.

*What is deliberately NOT collapsed.* The key is per pairing **request**, not per
`Connect()`. `connectVia` walks the mode ladder, and a direct pairing and a relayed one
are not interchangeable answers to one question — a client that fell back to relay
because direct failed genuinely asked twice. So one `Connect()` can still produce two
assignments, and that is a decision rather than a leftover: what is collapsed is
retransmission, which was never a decision. The measurement in §2 goes from six
assignments to one per request.

*Replaying the node's assign too.* The datagram that went missing may have been either
one. Replaying both makes a retransmit recover the whole pairing, which is strictly
better than the behaviour it replaces: there, a lost assign was "recovered" by minting a
second session against a possibly different exit, leaving the client and the node it had
been paired with holding different session ids.

*The peer-relay half.* §3 records that `prune` exempts peer-relay sessions, because their
liveness is their relay's (#96/#105). That exemption covered sessions that were never
brought up at all, so a client harvesting assignments through `mode:"relay"` accumulated
entries no reaper would ever touch — the exits they name stayed nameable in
`ExcludeSessions` indefinitely, where a direct-mode client's aged out in `sessionTTL`.
The coordinator can tell the two apart honestly: every transport drives its handshake
through it (`core.Signaler`), so a session that has never relayed a single frame was
paired and abandoned. Those are now reaped on the ordinary idle bound; a session that was
brought up keeps the exemption in full.

*What this does not close.* §9's `firstHop` residual is untouched — a client that asks
for relay mode, names a node and terminates there has still reconstructed a stable exit
preference, and no coordinator can see it. And §3's load term still counts sessions
minted rather than tunnels served, so a client willing to spend one full request per
increment can still inflate it. The price moved from one datagram to one request; the
mechanism did not disappear.

### 2. Under `-geoip-required`, an empty advertisement is unverifiable, not agreed (#2)

§8's exception was the default configuration. `-advertise` is empty out of the box and a
direct-mode exit never needs it, so the split-endpoint operator §8 describes defeated the
check by **omitting a flag they had no reason to set**: run the exit in RU, forward only
the UDP signaling through a cheap host abroad, and be tagged with the foreign country,
`source=observed`, no warning logged, fully assignable — under the flag whose entire
promise is that no node self-report reaches a client's country choice.

Under `-geoip-required` an exit that advertises no data-plane endpoint now gets **no
country**. The distinction that makes this coherent is between a claim that is
*contradicted* and an observation that cannot be *corroborated*: the flag's promise is
about what this coordinator can establish, and with one address and nothing to check it
against it has established where the exit signals from and nothing about where its
traffic leaves.

Of the two options the issue named, this is the first. Requiring `-advertise` for the
exit role was rejected because it would refuse an ordinary working direct-mode exit at
register for omitting a flag it does not need, in deployments that never asked for the
guarantee. **Without the flag, an empty advertisement still keeps its observed tag** —
unchanged from today. The flag is what buys the property, and it now buys the whole of
it.

The structural half matters as much as the rule. The predicate this replaces answered a
yes/no question — "does the advertisement agree?" — and had to say something about an
exit that made no claim; it said yes. Collapsing *made no claim* into *made a claim that
checks out* is what let the check be bypassed by omission, so the code now carries three
states (`endpointAgrees` / `endpointDisagrees` / `endpointAbsent`) and every caller has
to decide what an absent claim means to it. The provenance is recorded separately too
(`unverifiable-no-endpoint` vs `observed-signaling-only` vs unresolved), because all
three leave an exit with no country and an operator reading the log has three different
faults with three different fixes — and a message saying "your address did not resolve"
is actively wrong for an exit whose address resolved perfectly.

### 3. The signed snapshot carries country provenance, and a chaining client acts on it (#3)

§8 computed `countrySplit`, logged it loudly, and then discarded it at the snapshot
boundary. `coldstart.Entry` had no provenance field, so a split-endpoint exit shipped in
the **signed** directory as `{Country:"NL", Addr:"<RU address>"}` — byte-identical in
shape to a verified entry. So did an exit whose country is nothing but its own
`-country` flag, which is every node in a deployment with no database staged.

That mattered more by the time it was fixed than when it was raised, exactly as §9
predicted without meaning to: chaining has now shipped, and `chooseChainExit` picks the
terminating exit — the jurisdiction the whole feature exists to choose — out of this
artifact, with no live reply to check it against. The signature proves the coordinator
said the country. It says nothing about which of the three it is.

`Entry.CountrySource` now carries it, for relays as well as exits (a relay's address and
ingress agree by construction, but its *country* still falls back to its own hint), and
`core` fails closed on it.

**Where the client's line is drawn, and why it is not "verified".** It refuses a
**contradicted** country — one the coordinator itself observed to disagree with where the
node says it serves traffic from — and nothing else. Refusing everything *unverified*
would refuse every hinted tag, which is the whole fleet wherever no geo database is
staged, so a client would simply stop being able to chain against a coordinator behaving
exactly as it always has. An empty provenance (a coordinator predating the field) is not
contradicted either: that is the status quo, not a discovered disagreement. This is the
same distinction §8's own promise rests on — no *contradicted* self-report — applied
client-side.

The refusal is scoped to the **terminating** exit. A contradicted country says something
about where a node egresses, which matters only for the node that terminates the path; a
peeling hop egresses nothing, and hop diversity is operator- and AS-based (ADR-0038 §4).
Such a node stays in the hop pool and stays a mesh-walk courier.

**And the decision the field does not answer: a split-endpoint exit stays in the
snapshot.** Withholding it was considered and is worse. This snapshot is not only a
jurisdiction menu — it is also ADR-0037's mesh-walk courier list, and dropping a
reachable peer over a property of its *country* withdraws recovery capacity at exactly
the moment recovery is what the client needs, to fix a problem that has nothing to do
with reaching it. It would also put the directory out of step with `connect`, which
without `-geoip-required` still assigns that exit (§8): §4 forbids the aggregate
promising what `connect` would refuse, and the mirror of that is a directory hiding what
`connect` would hand out. So it ships, labelled, and the consumer decides. Under
`-geoip-required` the question does not arise — such an exit has no country at all and
ships as the country-less exit it is.

### On the tests, because all three of these were invisible

Every failure closed here is silent in production. Six sessions per connect is a
perfectly working connection; an exit tagged with the wrong country connects and carries
traffic; a chaining client that picks a contradicted exit egresses somewhere the user did
not choose and is told nothing. None of them fails, so none of them could be found by a
test that only checks that things work.

Two fixture gaps in particular were load-bearing and are worth recording, because they
are the same shape as the "a fake on both ends of a protocol tests the fakes" lesson this
record already carries. `registerExitFrom` always set `Addr` from the source and
`registerSplitExit` always set a different one, so **the default configuration — no
`-advertise`, the one an operator actually runs and the one #2 needs — was the case no
fixture could produce.** And the #96/#105 peer-relay fixtures paired a session without
ever driving the setup handshake they describe as having happened, which is what made
"minted and abandoned" indistinguishable from "up and quiet"; they now signal, and the
abandoned case is a deliberate separate fixture.

Every test added here was mutation-checked: the fix reverted, the test watched to fail,
the fix restored.
