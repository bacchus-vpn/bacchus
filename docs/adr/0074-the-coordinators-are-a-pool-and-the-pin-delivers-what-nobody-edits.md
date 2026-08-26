# 74. The coordinators are a pool everywhere, and the pin delivers the files nobody edits

- Status: accepted
- Date: 2026-08-26
- Tracking: issues #250, #234
- Builds on: ADR-0064 (the pin, and §7's no-copy rule, which this does not weaken),
  ADR-0069 / issue #222 (the rollback this finally delivers), ADR-0020 (the
  coordinator pool and client rotation, whose premise had never been on hardware),
  ADR-0072 / issue #249 (the gate check, now run per member), issue #225 (the
  window every restart opens), issue #60 (why the second coordinator cannot be
  an exit)
- Implementation: `deploy/bacchus-pin.sh`, `deploy/bacchus-fleet-check.sh`
  (`--label`), `deploy/bacchus-gate-check.sh` (`--label`),
  `deploy/bacchus-unit-check.sh` (its instructions), `deploy/testbed.env.example`,
  `deploy/pin_test.go`, `deploy/gate_check_test.go`, `docs/RUNNING.md`,
  `deploy/README.md`

## Context

Two findings, one file. Both live in `deploy/bacchus-pin.sh`, which is why they
are one record.

**The testbed runs one coordinator, so everything that only exists across a pool
is untested on real hardware.** Not untested in the sense of "we have not got
round to it" — untested in the sense that no test could be written. `#212` step 5
asks for `-rendezvous-dtls=false` on **one pool member of two** and for clients to
rotate to the other; there is no other. Client rotation itself, ADR-0020's whole
premise, has never met a real network path. And `-policy-root-pubkey`'s
justification is, in its own words, that *"coordinators are a pool with client
rotation, so one failing closed sheds to its peers"* — with one member there is
nothing to shed to, so the argument that makes a fail-closed gate acceptable has
never been tested where it matters.

The protocol was ready and the tooling was not. A node's `-coordinators` is
already a list and `registerLoop` already broadcasts to every member on every
tick — its own comment states why, which is that **there is no
coordinator-to-coordinator replication**, so registering with all of them is the
mechanism rather than belt-and-braces. Nothing in `core` needed to change.
`bacchus-pin.sh` treated the coordinator as singular in about ten places,
`bacchus-fleet-check.sh` read one journal, and `cmd/coordinator-probe` was pointed
at one address.

**And `#222`'s supervisor-side rollback is inert on every deployed box.** It
shipped `deploy/bacchus-update-rollback.sh`, `bacchus-update-rollback@.service`
and an `OnFailure=` line on both server units. Merging it put none of that on a
machine, because the pin delivers binaries only. That is `#205`'s finding in a
different place: the repository holds a mechanism the fleet does not have.

Half of that was already answered. ADR-0064 amendment F added
`deploy/bacchus-unit-check.sh`, so a directive a template gained and a live unit
lacks is now **reported** on every pin run. What no part of this repository does
is **deliver** anything, and a report that repeats an owner action on every run
until somebody performs it by hand is a mechanism that reaches a box only as fast
as somebody's attention.

## Decisions

### 1. §7 refuses to overwrite CONFIGURATION. It was written over a file extension, and the extension is not the property

This is the record's centre and the question the lane was set.

ADR-0064 §7 says unit files are never copied and no flag makes it possible,
because *"the coordinator's live unit carries hand-added flags that are not in
`deploy/bacchus-coordinator.service`. Re-copying that file silently reverts a
working configuration, and the deployment then behaves differently for reasons no
diff shows."*

Every word of that reason is correct and it stays. But read it again for what it
is about: **a unit that holds the operator's own configuration.** The rule was
stated over `.service` files, and the reason ranges over something narrower.
`#234`'s payload is three things, they fall on different sides of that line, and
separating them dissolves most of the conflict:

- **`bacchus-update-rollback.sh` → `/usr/local/lib/bacchus/bacchus-update-rollback`
  is not a unit at all.** It is an executable artifact of this repository, exactly
  like `bacchus-node` and `bacchus-coordinator`, and §7 has never had anything to
  say about it. It ships by the path that already existed. That is the largest
  single piece of `#234` and it needed no new rule, only somebody noticing that the
  no-copy rule had been read as covering it.
- **`bacchus-update-rollback@.service` → `/etc/systemd/system/` is a unit, and it
  carries none of anybody's configuration.** No `EnvironmentFile=`. No `[Install]`
  section — it is pulled in by `OnFailure=` and by nothing else, and enabling it
  would run a rollback at boot, which is the one moment nothing has failed yet. One
  `ExecStart=`, a fixed path, with `%i` supplying the only variable in the file and
  systemd supplying `%i` from the failing unit's name. There is nothing in it for a
  copy to revert.
- **The `OnFailure=bacchus-update-rollback@%n.service` line on the live
  `bacchus-exit` and `bacchus-coordinator` units stays an owner action, and will
  never be anything else.** Those units are exactly what §7 is about. The unit
  comparison already reports the gap on every run and prints the line; what changes
  is that the line is now the **whole** job on a box, because the two files it
  depends on arrive on their own.

So §7 is not weakened. The one thing §7 protects — a unit carrying the operator's
configuration — is still never written, and no flag makes it possible. What
changes is that two files carrying none of it stop being covered by an accident
of spelling.

**The property is enforced structurally, not remembered.**
`deploy/pin_test.go`'s `TestTheDeliveredArtifactsCarryNoOperatorConfiguration`
reads the shipped unit and fails the build if it grows an `EnvironmentFile=`, an
`[Install]`, a `WantedBy=`, or an `ExecStart` that is anything but that fixed path
plus `%i`. An edit that made the file configurable turns CI red and names this
record, rather than quietly widening what a deploy script may write to a box.

**And the list of what may be delivered lives in `bacchus-pin.sh`, not in
`testbed.env`.** That is a decision rather than an omission: an operator who could
add an entry could add `bacchus-coordinator.service`, and the whole of §7 is that
nobody may. What is deliverable is settled **in review, per file, in this
repository** — never per run, per fleet.

### 2. Nothing is overwritten that this repository did not write, and that is checkable rather than assumed

§1 argues these two files contain nothing to revert. §2 stops the argument being
load-bearing.

Before replacing either file the pin digests the copy on the box and asks whether
that digest is **any version of that file in this repository's history** —
`git log` over the path, `git show` at each commit, digest each. Three outcomes:

- **Absent** — deliver it. Nothing to revert.
- **A digest this repository has shipped** (this commit's, or an older one) —
  deliver it. Somebody's install placed it and nobody has touched it since.
- **Anything else** — **refuse**, name the box and the path, print the one
  `install -D` command that settles it, and leave the file exactly where it is.

The obvious cheaper rule — replace only what is byte-identical to what this commit
ships — is the one that fails, and it fails in the direction that matters: it
works once and then refuses every box the moment the template changes, which is
`#234` again one commit later. Asking the **history** is what makes the rule
survive its own second use.

It fails closed on its own edges. A shallow clone, or a file whose past was
rewritten, yields a short list; the live copy matches nothing in it; the delivery
is refused and named rather than made.

Rejected, and each of these was a real candidate:

- **Copy, keeping a backup.** A backup is not revert-prevention. The deployment
  behaves differently from the moment of the copy and the operator finds out
  later, which is §7's failure with a consolation prize attached.
- **An opt-in flag — `--copy-units`, or an allow-list in `testbed.env`.** §7 says
  in as many words that no flag makes it possible, and this would be exactly that
  flag. It also puts the decision at the wrong end: at run time, per fleet, by
  whoever is deploying, instead of at review time, per file, by whoever is reading
  the diff. An opt-in an operator sets once and forgets is a blanket copy with
  extra steps.
- **Merging the missing directives into the live unit** — the most tempting,
  because it delivers `#222`'s `OnFailure=` line directly. Refused: a merge
  **writes the operator's file**, so the failure §7 names — a live configuration
  changing for reasons no diff shows — comes back with the extra property that the
  result is a file neither the repository nor the operator authored. And a merge
  cannot be reviewed in advance, because what it produces depends on what is on the
  box.
- **A drop-in under `/etc/systemd/system/bacchus-exit.service.d/`.** This one loses
  narrowly and deserves the space. It would deliver `OnFailure=` without touching
  the operator's file at all, and `systemctl cat` renders drop-ins, so the existing
  unit comparison would see it. Two things sink it. It becomes a **second delivery
  path for arbitrary directives** — once a deploy script may write into that
  directory, the deployment's configuration has two authors again and the
  diff-invisible change returns through a new door; a drop-in wins on `OnFailure=`
  and loses on everything that would follow it. And `OnFailure=` is a **list**
  directive: a drop-in can add to it, but removing what a drop-in added means
  assigning the key empty, which resets the whole list including anything the
  operator put there (`bacchus-unit-check.sh` already records this class of
  behaviour, which is why it reads a reset as two values rather than as a reset).
  A delivery mechanism that cannot be undone without stepping on the operator's
  intent is not the mechanism to introduce here.
- **A sidecar file on the box recording what was delivered.** It answers the same
  question as §2 and costs state on every machine that this tooling would then have
  to keep correct — including on boxes installed before it existed. The history is
  already in the checkout the pin is deploying from, and it needs no maintenance.

### 3. The pool is a list everywhere, and every check runs ONCE PER MEMBER

`COORDINATOR_TARGETS` is a list of `TARGET=UNIT` entries spelled exactly like
`NODE_TARGETS`, and `COORDINATOR_SIGNALING` is a list of addresses in the same
order. Per member: the journal read, the fleet check, the gate check, the unit
comparison, the effective-`ExecStart` report and the capability probe.

**The counts must agree**, and a mismatch is refused before anything is built. A
member with no signaling address is a member nothing probes — and it would be
reported at the volume of a member that passed, which is `#248`'s finding arriving
in the one check that establishes a coordinator is serving this commit at all.

The **singular `COORDINATOR_TARGET` / `COORDINATOR_UNIT` pair still works** and is
read as a pool of one. `deploy/testbed.env` is gitignored, so every copy of it in
existence is in somebody's own checkout and a rename would land as a broken deploy
rather than as a rename. Setting **both** spellings is refused rather than
resolved: a run that guessed which one meant the fleet would be guessing about the
thing it exists to pin.

### 4. An asymmetric registration is a finding of its own, and no count can hold it

There is no replication between members. A node registered with one member and
missing from another is therefore a **stable state**, not a delay that resolves:
the member that never saw it will not assign it work, and a client that rotates
there sees a smaller fleet than the one that is running.

It is also invisible to every count in the run, because **each member's own total
can be perfectly ordinary**. Two members, two nodes, one node missing from the
second: member one reports 2 of 2 and member two reports 1 of 2 — and if a
volunteer happens to be registered with member two, even that reads as 2 of 2
(amendment A's floor, and `#232`'s reason for a roll call). So the roll call now
compares each box's stated id against **every member's window separately** and
sorts what it finds into three: seen by all, seen by none (the absence `#232`
added), and seen by some — which is named, per box, with the member ordinals that
missed it.

A member whose window could not be read is **left out of the comparison** rather
than counted as a member that saw nothing. Otherwise one failed `ssh` would report
every box as absent from that member and restart the whole fleet because a journal
could not be fetched. Not-asked and asked-and-empty are different facts; this is
`#248`'s rule one file over.

**The containment restart fires on an asymmetry too**, and that is not generosity.
A node holds one link per member and `#225` kills a **link**, not a node — so
losing one of two links is exactly what `#225` looks like from here, and the
remedy is the same restart. Drift still suppresses it: a box on the wrong binary is
on the wrong binary afterwards too, and restarting destroys the evidence.

### 5. A gate is only as on as the WEAKEST member

Every credential gate fails open when unset (ADR-0072), a client rotates freely,
and nothing replicates. So a member started without `-device-root-pubkey` is not a
partial deployment of the device gate — **it is a way around it**. `COORDINATOR_GATES`
is therefore required of **every** member, and a pin that finds one member short
fails the run and says which.

This is the sharpest edge the pool adds, and it points the other way from the
reason a pool is wanted. A pool exists so that one member failing closed sheds to
its peers; the same rotation means one member failing **open** is a hole with a
peer's name on it.

### 6. `--label` keeps the pasteable half pasteable

`bacchus-fleet-check.sh` and `bacchus-gate-check.sh` print no hostname, which is
what makes their output the half of a pin run that is safe to paste into a public
issue — while `bacchus-pin.sh`'s own output names ssh targets on every line. A
pool produces one report per member, and two unlabelled reports cannot be told
apart, which is how the per-member reading turns back into one undifferentiated
answer.

Both scripts take `--label`, and the pin passes an **ordinal** — `1`, `2`, … in
`COORDINATOR_TARGETS` order — and prints the pairing itself, on the output that
already names hosts. A label containing `.`, `@`, `:`, `/` or a space is refused,
because free text is where a hostname gets in. That is a **floor and not a wall**:
a bare unqualified name would still fit through. It is there so that reaching for
the host takes a deliberate act rather than being the obvious thing to type.

An empty label leaves every line byte-identical to what a single-coordinator
deployment printed before, which is what keeps an already-pasted report readable.

### 7. The restart order does not change, and the `#225` window widens with the pool

Every node first, then every member — the ordering ADR-0064 §2 made a correctness
property, unchanged, because `build=` rides the `registered:` line and that line
fires only for a node the coordinator does not already hold.

The consequence is worth stating rather than discovering: **each member added to
the pool is one more link stranded per deploy.** A node comes up against every
member, then each member is restarted under it in turn, and a node never rebuilds
a link whose coordinator went away. With one coordinator the containment restart
fired often; with a pool it fires essentially every run. Sequential restarts widen
`#225`'s window rather than closing it, and no reordering fixes that — restarting
members first would make the whole reading stale, which is the failure the ordering
exists to prevent. The containment covers it, and the containment retires when
`#225` does.

### 8. What this record deliberately does NOT decide

The second coordinator's own configuration — its bootstrap key material, whether
the two members share a policy root, what `-coordinators` each node is given — is
a deployment question for whoever stands it up, and `#250` says so itself. This is
the tooling that makes a two-member fleet deployable and checkable at all.

**And the box does not exist.** Nothing here has been run against a second
coordinator, because there is not one to run it against; the fake fleet in
`deploy/pin_test.go` grows a second member and every property above is asserted
there, which is ADR-0064 §9's position unchanged and honestly restated. Renting the
box is an owner action and is filed as one, with the role change `#250` requires:
the natural candidate already carries a node and **must drop from `exit,relay` to
relay-only at the same time**, because one host running a coordinator and an exit
is `#60` — the correlation the rest of the design spends its budget denying — and
adding a coordinator to a box that keeps its exit role creates a second instance of
that defect rather than a test fixture.

## Consequences

- **`#212` becomes runnable once a box exists.** Step 5's fixture — one member on
  `-rendezvous-dtls=false`, clients rotating to the other — is now deployable, and
  the per-member probe reports it as a per-member verdict rather than as one fleet
  answer. Six cards sit behind `#212`'s freeze and this is what unblocks the path
  to them.
- **`#222`'s rollback reaches a box for the first time**, and the owner action that
  remains is one line per live server unit, added by hand, which the pin prints on
  every run until it is there.
- **A deploy script may now write to `/etc/systemd/system`**, which it could not
  before. The blast radius is bounded by a fixed list in the script, a structural
  test on the property that makes that list defensible, and a refusal to overwrite
  any content this repository cannot recognise. If a future change wants to widen
  the list, the argument it has to make is §1's, per file, in a diff.
- **The pin's output grows with the pool**, one block per member. That is the
  intended shape: a single summary is what would hide an asymmetry.
- **A gate declared in `COORDINATOR_GATES` now has to be on everywhere**, so
  standing up a second coordinator without the gate flags turns a previously green
  pin red. That is correct and it is the point, and it will be somebody's surprise
  the first time.
- **`bacchus-fleet-check.sh` and `bacchus-gate-check.sh` still print no hostname**,
  and `--label` is the one place that property could be given away. The character
  refusal is a floor; if a real hostname ever appears in a pasted report, this is
  the sentence to search for.
- **Nothing here has been run against real hardware.** The whole procedure remains
  a `needs-owner-test` blocker, and no work should assume a two-member fleet exists
  until the box is rented and the pin has run against it.
