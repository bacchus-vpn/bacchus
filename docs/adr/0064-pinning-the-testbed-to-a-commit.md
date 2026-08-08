# 64. Merging stops meaning running: the deployment is pinned to a commit, and the pin is established by probing a capability

- Status: accepted
- Date: 2026-08-08
- Tracking: issue #205
- Builds on: issue #114 (the silent-skew failure this makes preventable rather
  than only diagnosable), ADR-0063 / issue #182 (the `build=` field this reads),
  ADR-0060 / issue #202 and ADR-0059 / issue #175 (the capability being probed),
  issue #128 (the release stamp), ADR-0042 / issue #85
  (`deploy/bacchus-geoip-refresh.sh`, whose staging discipline this copies)
- Implementation: `deploy/bacchus-pin.sh` (new), `deploy/bacchus-fleet-check.sh`
  (new), `deploy/testbed.env.example` (new), `cmd/coordinator-probe` (new),
  `deploy/pin_test.go` (new), `docs/RUNNING.md` ("Pinning the whole deployment to
  a commit"), `deploy/README.md` ("Update a binary")

## Context

A wave merges to `main` and **nothing deploys**. There is no step anywhere in
this project's workflow that puts `main` on a box, so between deploys the
deployment falls one wave further behind per wave, and every instruction that
says "run it on the testbed" runs against whatever was last copied there by
hand.

On 2026-08-07 the live coordinator was found running a commit from 2026-08-05 —
six merges and two whole waves behind `main`, missing four merged changes.
Nobody had noticed and nothing anywhere said so.

**The reason nobody noticed is the important half.** Its startup line read
`coordinator release 0.1.0 (revision a868e6e3c447)`, and after the redeploy it
read `coordinator release 0.1.0 (revision abe9880ebf17)`. `release=0.1.0` is
true in both. Only the revision separates a two-wave-stale coordinator from a
current one, and the obvious check — grep the log, confirm the releases match —
returns a clean answer either way. A check that cannot fail is not a check.

This is issue #114's failure mode arriving a second time. The first time it cost
an afternoon: three exits three weeks stale registered, heartbeated, were
assigned work, and silently dropped every session, invisible in all three logs.
#114's post-mortem landed on the right discipline — *rebuild and redeploy the
whole deployment from one commit, together* — and left it as a sentence in a
Gotchas list, which is not a thing anyone can run.

Two constraints shape everything below. **The nodes could not be checked at all
until two commits ago**: a node's revision was on no wire, so a coordinator on
`main` logged `release=0.1.0` for a node of any age, and pinning the nodes meant
reaching each box by hand — which is the work the startup line exists to save.
That was issue #182, and ADR-0063 landed it. And **whoever writes this cannot
run it**: the boxes are the owner's, so the deliverable is tooling somebody else
executes on hardware the author cannot see. Anything that works only because it
could be tried is not done.

## Decisions

### 1. One script takes coordinator and nodes to one commit, from one build

`deploy/bacchus-pin.sh` builds both server binaries once, from one checkout,
stamped from `VERSION`; stages them onto every box; installs and restarts them;
and then checks the result. Per-box improvisation is what #114 was about, so the
unit of work is the fleet.

It reads its host list from `deploy/testbed.env`, which is gitignored (`*.env`,
with `!*.env.example` re-including the committed template). This repository is
public and a deploy procedure is the artifact most likely to carry a real
address into it, so the arrangement is structural rather than careful: there is
no field in any tracked file for an address to go in.

### 2. Nodes restart first, the coordinator LAST — and this is a correctness property

`build=` rides the `registered:` log line, and `cmd/coordinator`'s `"register"`
handler prints that line **only for a node it does not already hold** in its
registry. A node restarts in about a second and its registry entry survives 35s
(`ttl`), so a rolling redeploy can replace every binary in the fleet **without
printing `registered` once**. A check that simply grepped the journal afterwards
would then read values from before the deploy and report them with total
confidence — issue #205's own failure mode, one level up.

Restarting the coordinator last empties its registry, so every node re-registers
as new within one 10s register interval and prints a line naming the binary it is
running right now. `noteRelease`'s own doc had already stated the mechanism
("a staged rollout swaps every binary in the fleet without that line firing
once"); this record turns that observation into the deploy order.

`deploy/bacchus-fleet-check.sh` enforces the same window from the reading end: it
ignores everything before the **last** `coordinator release` startup line in its
input, and refuses a window containing no startup line rather than reporting on
whatever it happens to hold.

### 3. The check probes a capability; it never reads a version string

`cmd/coordinator-probe` sends one bare 20-byte STUN Binding Request to the
coordinator's **signaling** port. A build carrying #175 slice 1 and #202 answers
it in place (`answerSTUN` → `coldstart.BindingResponse`); an older one has no such
branch, hands the datagram to `json.Unmarshal`, fails, and drops it. The reply is
40 bytes over IPv4 — header, XOR-MAPPED-ADDRESS, FINGERPRINT, and nothing else —
and all of it is checked, including the FINGERPRINT CRC and the transaction id,
because *answered* and *answered the way this coordinator answers* are different
claims.

The instrument was confirmed on real hardware in both directions before this
record, including against a coordinator started `-rendezvous-dtls=false` as a
negative control.

### 4. The green result is falsifiable, because a Binding Request alone is not evidence

This is the decision that took the most care, and the one a reader is most likely
to think is over-engineering.

The coordinator's own STUN/TURN service on `-turn-addr` answers a Binding Request
with **byte-identical** bytes, on **every build this project has ever shipped**.
That is deliberate: ADR-0060 exports one codec precisely so two ports on one host
do not answer the same question differently, because the difference would be a
distinguisher. The consequence for a check built on that answer is that pointing
the probe one port sideways returns a pass against a coordinator of any age, and
**no shape check can tell the two apart** — sameness is the feature.

So the probe first establishes that it is talking to a Bacchus signaling port at
all, with a question only that port answers and which *every* build answers: a
`hello` whose protocol version cannot match, drawing a `reject` (issue #8,
`core/handshake`). The control is deliberately **older than the capability**, so
it separates "stale build" from "wrong address" instead of moving with the thing
being measured.

Four outcomes, four exit codes, because they are four different instructions:
control-and-capability (0, current); control-only (1, stale — or current and
started `-rendezvous-dtls=false`, which per that flag's own help text removes the
coordinator from the fleet just as thoroughly); capability-only (**4, not a
pass** — a TURN port or an unrelated STUN server); neither (3, which says nothing
about the build at all). `-control=false` exists and its verdict says the port is
unconfirmed in both directions, because a probe that could print a plain pass
without the control would put the false green back.

Rejected: comparing the reply's shape to distinguish the two ports (identical by
construction, see above); comparing releases (the failure this record exists to
end); and reading the deployed revision off a wire (there is none, and inventing
one from a self-report re-introduces the field that is being distrusted).

### 5. The verifier does not share code with the thing it verifies

`cmd/coordinator-probe` hand-rolls its STUN codec beside `core/coldstart`'s
rather than importing it. A verifier built from the encoder it verifies cancels
its own bugs out: a malformed response would be accepted by a parser making the
same mistake, and the probe would report success on bytes no real STUN client
accepts. `cmd/coldstart-probe` hand-rolls one for the same reason.

The tests close the loop from the other side rather than leaving the two halves
unrelated: the independent parser is run against the **production** encoder for
both address families, and each stand-in coordinator in `probe_test.go` answers
with `coldstart.BindingResponse` and `handshake.Check` — so what is asserted is
the probe, not a second copy of the coordinator.

### 6. Staging is two passes: a failed transfer leaves the fleet entirely on its previous build

`deploy/bacchus-geoip-refresh.sh`'s discipline, applied to binaries. Pass one
copies every binary to every box under a temporary name **beside its
destination** and digests it there; nothing running is touched. Pass two stops
the unit, renames the checked file over the live one, and starts it again.

Three properties follow, and each is a real failure this repository has reasons
to care about. The rename is within one directory, so it is atomic and no box can
run a partially written binary — staging through `/tmp` would make the final step
a copy, which is exactly the window this avoids (the geoip script's own argument,
restated for a different payload). A transfer that dies replaces nothing
**anywhere**, so the fleet is entirely on the old commit, which is a state that
works; half-updated is the state #114 was opened about. And the digest is
verified **on the box** before anything is replaced, so a truncated transfer is
refused rather than started.

### 7. Unit files are never copied, and no flag makes it possible

The coordinator's live unit carries hand-added flags that are not in
`deploy/bacchus-coordinator.service`. Re-copying that file silently reverts a
working configuration, and the deployment then behaves differently for reasons no
diff shows. Units are installed once — by hand or by `deploy/install.sh` — and
edited in place; an update is binaries only.

The corollary is that the file in this repository is **not evidence** about the
running service, so the script prints the unit's effective `ExecStart` and
`WorkingDirectory` after a deploy. It also warns on one live mis-set: the unit has
`WorkingDirectory=` empty, which for a system service means `/`, so a relative
default such as `secrets/device-revocations.json` resolves to
`/secrets/device-revocations.json` — which does not exist. That does not fail:
**a missing revocation file means nothing is revoked**, quietly, which is the
worst way for a security control to be off.

### 8. A build that cannot be identified is refused before it leaves the building

Three refusals, all of which produce a deployment that looks healthy if allowed
through:

- **A `git worktree` checkout.** The Go toolchain records VCS data only from a
  checkout with a real `.git` **directory**. A worktree records none, every node
  then reports `build=unknown`, and the fleet check has nothing to compare — the
  pin would be lost at its last step. This is the refusal anyone working on a
  branch in this project hits first, so it names the cause.
- **A dirty tree**, which stamps `-dirty` and is not at any named commit.
- **A release stamp that did not land**, which has two spellings and needs two
  different checks. A plain `go build` records no `-ldflags` at all and reports
  release `0.0.0` (#128) — visible in `go version -m`, and checked there, per
  binary. But **`-X` naming a symbol that does not resolve is silently ignored by
  the linker**: the flag is recorded in the binary's metadata exactly as it would
  be for a correct build, the build succeeds, and the binary still reports
  `0.0.0`. No reading of the built artifact's metadata can see that, because what
  the metadata reports is the flag rather than its effect.

  The mechanism for the second is **already in this repository and is not
  reinvented here**: `core/version.TestStampMatchesTheVersionFile` links the real
  symbol into a test binary and reads the value back out, with
  `BACCHUS_REQUIRE_STAMP` turning its skip-when-absent into a failure, and
  `ci.yml`'s "the release stamp reaches the binary" job runs it on every push. The
  pin script runs it again, against the checkout it is about to ship, **before**
  building anything. CI establishes that the symbol path resolved at the last
  *push*; a deploy needs to know it resolves in the tree being deployed — the same
  distinction that makes the post-deploy checks worth running at all.

  (An earlier draft of this record used a linker detail instead: a landed `-X`
  emits a `…core/version.current.str` symbol beside the variable and an ignored
  one does not, which building `cmd/coordinator` unstamped, stamped, and stamped
  at `version.Current` confirms. It works, and it is strictly worse — it depends
  on undocumented linker output where the repository already had a direct
  read-back. Recorded because the observation is true and someone will otherwise
  rediscover it.)

### 9. Everything is tested against a simulated fleet, because none of it can be rehearsed

Whoever wrote this cannot reach the boxes, so no part of the procedure will be
exercised on hardware before an operator runs it against a live fleet. The
properties that make it worth having are exactly the ones a careful reading
cannot confirm.

`deploy/pin_test.go` therefore simulates the fleet rather than mocking it,
following `deploy/asn_drift_check_test.go`'s precedent in a stronger form:
`ssh` and `scp` are replaced by scripts that rewrite the remote path into a
per-host directory and then **really run** the command, so `sha256sum`, `mv` and
`rm` execute against real files; only `systemctl` and `go` are stubs, and both
log what they were asked. Asserted: the coordinator restarts last, a failed
transfer leaves every box on its previous binary with no unit stopped and no
debris left behind, a corrupted transfer is caught before anything is replaced,
each of the three build refusals fires with its own sentence, and no `.service`
file is ever copied. A standing test also fails the build if any of these
artifacts grows a hostname or an IPv4 literal outside the documentation ranges.

What is deliberately **not** asserted: that any of it works against real `ssh`,
real `systemd` or a real coordinator. That is the owner's run, filed as a
`needs-owner-test` card.

## Consequences

- **The pin becomes a precondition** for every card that needs the boxes, rather
  than a first step to improvise. A result from an unpinned box is not evidence
  about the code.
- **A node's build is readable without touching the node**, for the first time —
  but only through a coordinator restart. The ordering is now load-bearing, and
  anyone who reverses it gets a confident answer about the previous deploy.
- **`build=unknown` is a failure, not a warning.** That makes development builds
  undeployable by this path, which is the intent: a fleet whose revision cannot
  be established is the state this record exists to end.
- **The probe's control depends on the coordinator still accepting cleartext
  JSON on its signaling port.** ADR-0062 removed the client's cleartext path;
  the coordinator's remains, and the demux in `servePackets` is what keeps this
  working. If that is ever retired, the control goes silent against a healthy
  coordinator and every verdict becomes UNREACHABLE. The probe reports its two
  observations independently so the state is legible rather than merely wrong,
  and this is the sentence to search for when it happens.
- **The `.str` check is a linker detail and may move.** It fails closed — a
  toolchain change would refuse a correct build rather than pass a broken one,
  which is the right direction — and the refusal names what it looked for.
- **Nothing here has been run against real hardware.** The whole procedure is a
  `needs-owner-test` blocker, and no work should build on the assumption that the
  boxes are pinned until that run happens.

## Amendment (2026-08-08): what the first real run found (#224, #226, #217)

- Implementation: `deploy/bacchus-fleet-check.sh`, `deploy/bacchus-pin.sh`,
  `cmd/coordinator/paths.go` (new), `cmd/coordinator/hello.go` (new),
  `cmd/coordinator/main.go` (the flag declarations and the `hello` case),
  `deploy/pin_test.go`, `cmd/coordinator/paths_test.go` and
  `cmd/coordinator/hello_test.go` (new)

The procedure above was run against the live fleet for the first time on
2026-08-08, at `7fbca67`, and the run itself worked: everything was staged before
anything was stopped, the nodes restarted first and the coordinator last, and the
probe's control fired so the capability result was not a false pass.

Three things it established that no reading had. Two are corrections to decisions
recorded above; the third is a property those decisions turn out to depend on,
which was not written down anywhere.

### A. The fleet check counted roles, so an absent box read as a pinned fleet (#224)

`bacchus-fleet-check.sh` keyed each registration on **`role id`** and incremented
its node count once per unseen key. A box serving two roles therefore counted as
**two nodes**, and a box that never registered counted as none — and its only
cardinality floor was `nodes == 0`. The run printed `3 node(s) registered` and
`the fleet is pinned` from three rows carrying **two** distinct ids, with one of
three boxes dead.

It now counts **ids**, prints one row per box naming every role that box took, and
takes `--expect N`: `bacchus-pin.sh` passes the size of the `NODE_TARGETS` it had
already sourced. Every per-node check §2 relied on — `build=unknown`, `-dirty`,
revision mismatch — was sound; the gap was only presence.

**Absence is not drift, and they now exit differently.** A box on the wrong binary
is #114 and a reason to distrust every result from the fleet (exit 1). A box that
did not register in this window may simply be off, and the check runs about 20
seconds after the coordinator restarts (exit 4, extending that code from its
`nodes == 0` case to the general one). Both are printed when both hold, and drift
takes the exit code.

Three limits, stated because a checker that overstates what it knows is the
failure this record exists to end:

- **A missing box cannot be NAMED.** The journal names node ids — for an exit, its
  X25519 public key — and the host list names ssh targets. Nothing maps one to the
  other, and building the map would need a roll call this check exists to avoid
  making. The report is therefore a count.
- **`--expect` takes a count and refuses a host list**, and this script prints no
  hostname at all. That is deliberate and worth keeping: its output is the half of
  a pin run that is safe to paste into a public issue, while `bacchus-pin.sh`'s
  own output names every ssh target on every line.
- **More ids than expected is not a failure.** A volunteer client serves as a relay
  or an exit (ADR-0053) and registers exactly like a deployed node without being in
  anyone's host list. So `--expect` is a **floor, not a roll call**: a volunteer
  present while a deployed box is absent can hold the count up. That is the
  strongest statement a journal supports.

### B. The relative-path warning read the one surface the failure never touches (#226)

§7 records that the script warns when `WorkingDirectory=` is unset **and**
`ExecStart` names a relative path. The reasoning was right and the condition was
backwards: **a flag left at its default never appears in `ExecStart` at all**, so
the warning stayed silent precisely when the operator had not thought about the
path and fired only when they had. On the live unit every path written into
`ExecStart` is absolute, the warning correctly said nothing, and nine
relative-default flags were resolving under `/` — including both revocation lists,
where a missing file does not fail, it means **nothing is revoked**, and
`-country-overrides`, whose corrections then cannot take effect.

Two changes. An empty `WorkingDirectory=` is now the **whole** condition. And the
coordinator states its own **resolved** paths at startup — each flag, what it
resolves to, whether it is there, and what its absence MEANS, which is the
difference between a state file written on first use and a revocation list that is
off. That report lands in the journal this procedure already reads, and it answers
for somebody reading the journal without the pin, which is what makes it the more
useful half.

Rejected, and it was the option the card priced third: enumerating the flag table
in the shell script. It would be a copy of `cmd/coordinator`'s flags living a
repository away from them and it would rot. In Go the list **is** the flags — every
path flag is declared through `pathFlag`, and a test parses `main.go` and fails on
any `flag.String` whose default looks like a relative path.

### C. The `hello` reject is load-bearing, and bounding its LOG is not bounding the REPLY (#217)

§4 chose a deliberately-mismatched `hello` as the negative control because it is
older than the capability being probed. What that decision did not say is that it
makes the coordinator's **reply** a piece of deployment verification infrastructure:
gate it, rate-limit it, or restrict it to admitted peers, and the probe returns
`control ABSENT, capability ok` — exit 4, which this record defines as explicitly
**not a pass** — so every pin from then on fails its own verification against a
perfectly healthy coordinator.

That mattered immediately, because the same handler was writing one log line per
unauthenticated datagram, naming a source that may be spoofed, which is a real
defect (#217) and the shape of fix that suggests itself is to stop answering. The
LOG is now bounded to one line per minute with a count of what it stood for; the
REPLY is unchanged, and `cmd/coordinator`'s
`TestCoordinatorProbePassesAgainstThisBuild` builds the shipped probe and runs it
against the production packet loop so the dependency is asserted rather than
assumed.

The reflection cost of keeping it, measured on that path: 16 bytes in draws 59
back — 3.7x of payload, and 87 bytes against 44 **on the wire**, 1.98x, once the
IPv4+UDP headers both sides pay for are counted. `answerSTUN` on the same port is
1.42x on that basis, so the reject is the more amplifying of the two, and both sit
far below the 50x-500x ADR-0060 priced. A test pins the figure so a longer reason
string cannot raise it unnoticed.

### D. A node that did not come back is restarted once — a containment, not a fix

Now that a missing node is detectable, the pin restarts the node units **once** and
re-reads the journal. The cause is one this procedure creates: §2's coordinator-last
ordering brings every node up against the outgoing coordinator and then removes it a
second later, and a node in that state never rebuilds the link (#225 — 100 minutes
observed, recovered by `systemctl restart` in under a second).

The ordering does **not** change: `build=` rides the `registered:` line, which fires
only for a node the coordinator does not already hold, so coordinator-last is what
makes the reading fresh at all. The restart is only for exit 4 — drift is never
restarted away, because the box is on the wrong binary afterwards too and the restart
destroys the evidence. It restarts **every** node unit, since which one is missing
cannot be known here; that is cheap exactly here and nowhere else, because this
script restarted all of them about twenty seconds earlier. `--no-restart-absent`
keeps the stranded process for whoever is diagnosing #225, and the whole containment
retires when a client recovers on its own.

## Amendment (2026-08-09): the fleet describes itself (#232, #234)

- Implementation: `deploy/bacchus-node-id.sh` (new), `deploy/bacchus-unit-check.sh`
  (new), `deploy/bacchus-pin.sh`, `deploy/bacchus-fleet-check.sh` (`--ids-to`),
  `deploy/pin_test.go`, `deploy/node_startup_line_test.go` (new),
  `docs/RUNNING.md` ("Pinning the whole deployment to a commit")

Two limits amendment A recorded as limits of a journal turn out to be limits of
*one* journal. Both are removed by reading a second one, and neither needed a
line of Go.

### E. A box that did not register is NAMED, and the log line that pairs it already shipped (#232)

Amendment A stated: *"A missing box cannot be NAMED. The journal names node ids
… and the host list names ssh targets. Nothing maps one to the other."* The
second sentence is true and the first no longer follows. **`#232` was filed on a
premise that is wrong**, and finding that out is most of this section.

`#232` reads that *"`cmd/node` logs nothing at startup that names the id —
`core/engine.go`'s `ID()` is never printed — so a box cannot be asked what it
registers as, even over ssh."* `ID()` is indeed never called. The id is not. Every
node has been stating it at every start since long before this record:
`core.Engine.Start` emits

```
exit <id> (<country>) advertising <host:port> + direct WebRTC
relay <id> online
```

through `e.emit`, and `e.emit` falls back to `log.Println` whenever
`Config.OnEvent` is nil. `clients/fyne` sets `OnEvent`; **`cmd/node` does not**.
So on a node box those go to stderr and systemd files them in the journal. Two
readers looked at `ID()`, and the value travels by a different route.

The consequence is that the pairing cost nothing but a reader and a map — no
change to `cmd/node`, no change to `core`, and no new wire field. Which was
fortunate: `core/engine.go` was frozen for the wave that closed this.

**`deploy/bacchus-node-id.sh` is the reader.** It takes a node's own journal on
stdin and prints one line, the id. Three decisions inside it:

- **The two shapes are matched WHOLE**, including the trailing `+ direct WebRTC`
  and `online`. A loose `exit <hex>` also matches `core/pool.go`'s *"exit … did
  not carry traffic"*, which names an exit this box was **assigned** — somebody
  else's id, appearing after startup on any volunteer box, which runs a client
  and an exit at once. That would not fail to answer; it would answer with a
  stranger's identity, and the roll call would then report a healthy box as
  absent.
- **The last match wins.** One process has one id, but a window can hold more
  than one start.
- **It prints no hostname**, exactly as `bacchus-fleet-check.sh` prints none. It
  reads text on stdin and never learns where the text came from.

**The map lives in `bacchus-pin.sh`**, and that is the decision `#232` asked to
be settled rather than assumed. Naming a box means naming a host. The fleet
check's one distinguishing property is that its output is the half of a pin run
that is safe to paste into a public issue, and the pin's output already names ssh
targets on every line — so the check keeps answering in ids and gains
`--ids-to FILE`, a side channel that writes the ids it counted and changes
nothing about what is printed. A node id is public (it is in the signed directory
and every client holds it), so writing one costs nothing; a hostname is what
would cost.

**The second limit goes with the first, and it is the one that hides a dead
box.** Amendment A: *"a volunteer present while a deployed box is absent can hold
the count up. That is the strongest statement a journal supports."* True of a
count; a roll call compares identities, so a registration belonging to no
deployed box cannot stand in for one that is missing. `--expect` stays, because
it is what answers when a box's own id could not be read and it is what an
operator running the check by hand gets. The pin now has both, and says which one
is speaking.

Two things this had to get right that a reading would not have caught:

- **The map is rebuilt after the containment restart, not carried across it.** A
  relay without `-relay-ingress` takes a fresh random id at every start
  (`randID`); an exit's id is its X25519 public key and does not move; the map
  cannot tell which kind it is holding. Reusing it would report a box that came
  back perfectly as absent, on every run that restarted anything.
- **A box whose id cannot be read falls back to the count and says so.** A roll
  call that quietly drops a box it could not ask reports a complete fleet from an
  incomplete question.

**The startup line is now load-bearing**, which is the cost of not adding one.
It is a contract between Go and shell, the pair ADR-0069 §4 names as the one that
drifts silently, so `deploy/node_startup_line_test.go` never hand-writes it:
it builds `cmd/node`, runs it, and feeds the bytes the real binary produced
through the real script — the same discipline `deploy/update_rollback_test.go`
uses for the update marker. Reword those lines and that test goes red, naming the
pin as what depends on them.

### F. The units are compared, and still never copied (#234)

§7 says unit files are never copied and no flag makes it possible. That stays,
and every word of the reason stays. What §7 did not say is that nothing
**compared** them either, so a directive a template *gained* and a live unit
lacks was invisible — in both directions.

`#222` is the instance. It added `OnFailure=bacchus-update-rollback@%n.service`
to `deploy/bacchus-exit.service` and `deploy/bacchus-coordinator.service`;
merging it put it on no box; and every pin run afterwards reported a pinned
fleet, correctly, because the binaries were pinned. ADR-0069's own consequences
list says so in as many words. That is `#205`'s finding in a different place: the
repository holds a mechanism the fleet does not have, and nothing reports the
difference.

`deploy/bacchus-unit-check.sh` compares `systemctl cat` against the shipped
template and reports three things: **missing** (shipped here, absent there — the
finding), **only on the box** (the hand-added flags the no-copy rule exists to
protect), and **same directive, different value** (`ExecStart=` essentially
always, which is the no-copy rule being right rather than a fault).

- **Directives, not text.** `systemctl cat` prints a `# /path` provenance header
  and any drop-ins, the templates carry long comment blocks, and `\`
  continuations split one directive across lines. A textual diff of those two is
  pages of noise, and noise is how a report stops being read. Comments, blank
  lines, ordering and continuations are normalised away; a repeated key
  accumulates rather than overwriting.
- **It reports; it does not fail the run.** Same call as §7's
  `WorkingDirectory=` warning, for the same reason: units are configuration this
  procedure deliberately does not manage, the binaries genuinely are pinned, and
  a check that failed every pin until somebody hand-edited three units would be
  switched off — or answered by adding the copy flag that must not exist. It is
  loud, it prints the exact commands, and it prints them on every run until the
  box carries the line.
- **A unit with no shipped template is stated, not skipped.** `bacchus-relay` is
  that case today: this repository ships no `deploy/bacchus-relay.service`.

`#234`'s owner action — installing the handler and adding the line on each live
box — is unchanged and is still an owner action. What changes is that from now on
the pin says which boxes are still waiting for it.
