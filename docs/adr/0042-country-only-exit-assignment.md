# 42. Country-only exit assignment, with a coordinator-derived country and country-granularity backpressure

- Status: accepted (issues #136, #146, #147)
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
pattern `clients/windows/README.md` uses for `wintun.dll` (#165).

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
**outcome** — see the retransmission residual at the end of this section, which is the
honest boundary of what §2 delivers.

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

**Residual: one connect is several assignments, not one.** `sendN` sends each connect
three times against UDP loss, and `connectVia` does that once per mode, so a single
`Connect()` can put six datagrams on the wire. The handler processes each independently
and mints a session per copy, every one through a fresh randomized `chooseExit`.
Measured with three exits in one country: **one `Connect()` minted six sessions across
three distinct exits.** A client that reads all six replies and drives whichever names
its target pins in one round trip, with no exclusion at all — with three exits, roughly
nine times in ten.

The retransmission is not new and is not this ADR's doing. What is new is that it
*means* something: before §2 every copy named the same client-chosen exit, so the
redundancy was invisible. Country-only assignment turns each retransmit into an
independent draw.

Two consequences follow, and neither is closed here:

- Exclusion is cheaper to weaponise than the paragraph above implies, because one
  reconnect is up to six assignments. In a small country a single connect collects most
  of the complement.
- §3's load term is inflatable by a **client**, not just unforgeable by a node: five of
  six sessions are never used yet are counted for `sessionTTL`, so a client can push a
  competitor exit out of the tier at one datagram per increment, and — once `minShare`
  is non-zero — busy out a country.

Both close the same way: a per-connect idempotency key, so duplicate copies of one
connect return the same session and the same exit. Tracked as a follow-up rather than
fixed here, because it is a wire change and this ADR is already one.

So the property §2 actually establishes, and the one the rest of this document rests
on, is narrower than the first draft claimed: **a client cannot present a stable,
declared exit preference, and the coordinator cannot honour one.** An outcome reached by
minting and abandoning sessions remains available — and is louder than the mechanism it
replaced, because the coordinator observes it happening.

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

**With one exception, and it is the default.** An exit that advertises *nothing* has made
no claim to contradict, so the comparison passes vacuously and the tag stays `observed`.
`-advertise` is empty by default and a direct-mode exit never needs it — relays dial an
advertised address, ICE does not. So the split-endpoint operator described above defeats
the check by omitting a flag they had no reason to set, and does so under
`-geoip-required`. Closing it means either treating an empty advertisement as
unverifiable when that flag is set, or requiring `-advertise` for the exit role; tracked
as a follow-up.

Until then the flag's promise is narrower than "no self-report reaches a client's
country choice". It is that no **contradicted** self-report does — which is worth having,
since it makes the split endpoint a configuration an operator must now deliberately
avoid rather than one they get for free, but it is not the guarantee the name suggests.

**The residual, stated rather than papered over.** The advertised address is still a
claim; it is now a claim that must agree with an observation, not an unconstrained one.
The coordinator never sees the egress: in direct mode the data path is decided by ICE
candidates the exit puts in its own SDP, and nothing in the protocol reports where a
packet finally left from. An operator who places their whole apparatus behind one
address can still egress elsewhere. Country is a strong signal about where a node sits.
It is not a proof about where its traffic leaves, and `deploy/README.md` says so in the
same words.

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

**And the tension worth naming, because it looks like a contradiction and is not.** A
chaining client *does* choose its own terminating exit, which is exactly the pinning
this record removed. The two coexist because the property being protected is not "no
client may know which exit it uses" — a client always knows, it holds the exit's static
key. It is that **a client must not be able to present a stable exit preference to the
coordinator**, which is a tracking handle for an untrusted coordinator (ADR-0020) and a
defeat of load balancing. In chained mode the coordinator learns the first hop and never
the exit, so there is no handle to present. The two features trade the same piece of
information in opposite directions, and both are coherent for the same reason.

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
  and `-geoip-required` refuses a split, but the coordinator never observes the egress
  itself.
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
