# 69. The demotion watchdog reaches outside the process: a release is on probation for exactly one start, and a rename it cannot perform is performed by the supervisor

- Status: accepted
- Date: 2026-08-08

## Context

ADR-0065 §6 shipped three answers to three release failures and named a fourth
case as a known gap with an owner rather than as something handled:

> **It applies and the process cannot start at all** … **Nothing in the process
> can catch this, because the process never starts.** … a supervisor-side check
> is what would automate it. That belongs in `deploy/`, which this lane does not
> own.

`#222` is that card. This record closes it, and in getting there it corrects the
mechanism ADR-0065 §6 describes — because the in-process half, as built, does not
do what that section says it does, and a supervisor-side check built on top of it
would have inherited the same defect.

**Why the correction comes first.** The supervisor-side rollback has to decide
which failures are its business. The only evidence available to it is the
confirmation marker beside the binary: nothing that never started can leave any
other trace. So the marker's meaning IS the interface between the two mechanisms,
and it was not carrying the distinction either of them needs.

## The correction to ADR-0065 §6: a marker's presence is not a demotion signal

§6 says: *"a start that reaches a working state clears it; a start that FINDS one
renames the previous binary back and exits so the supervisor re-execs it."* The
code on `main` implements that sentence literally, and the sentence is wrong,
because of where an apply runs.

**An apply runs in the OLD binary.** `core/update.Apply` renames the current
binary aside and renames the staged file into place; the running process keeps the
inode it was started from and carries on unharmed — that is §5's whole point about
never writing to the running path. So the applied release does not execute until
the next restart, and its own first start is a start that FINDS a marker.

Two consequences, both provable from `main` and neither theoretical:

- **Every release that works is demoted on the restart that hands over to it.**
  The node applies 0.2.0, is restarted, `checkStartupDemotion` finds the marker,
  renames 0.1.0 back and exits 3, the supervisor re-execs 0.1.0, and six hours
  later the node applies 0.2.0 again. A fleet on this loop never moves off the
  release it is on, and every box reports the apply as a success each time.
- **In the one window where an update does stick, it sticks unprotected.**
  `cmd/node` confirms once, a minute after ITS OWN start (`confirmProbation`). If
  the apply happened inside that minute, the applying process clears the marker
  belonging to a release that has not run yet — so the release survives the
  handover, and the demotion machinery that was supposed to be watching it has
  already been spent.

The failures are opposite, which is why neither shows up as a simple "rollback is
too eager" or "rollback never fires". `core/update`'s own test suite passed
throughout: it called `CheckStartup` once after an `Apply` and asserted a
demotion, which conflates "the first start" with "the start after the first".

### The marker becomes a probation with two states

`Marker` gains `started`. `CheckStartup` has four outcomes rather than three:

| on disk | meaning | action |
| --- | --- | --- |
| no marker | ordinary start | nothing |
| marker, no `.prev` | the apply crashed before publishing | clear the marker |
| marker, `started=false` | the applied release has never run | **claim it and run** |
| marker, `started=true` | the previous start of this release never confirmed | demote, exit |

`Confirm` correspondingly clears only a marker that has started. A process is
entitled to confirm what its own start proved and nothing else; the applying
process's probation timer, firing against a release that has not started, now
correctly leaves the marker alone.

The cost of the extra state is one restart cycle — under `RestartSec=2`, two
seconds — before a crash-looping release is demoted. The cost of not having it is
that the release channel cannot deliver a release.

## Decision

### 1. The supervisor-side half is `OnFailure=`, not `ExecStartPre=`

`#222` weighed both and called neither obviously right. It is `OnFailure=`, on two
grounds.

**`ExecStartPre=` would have to re-implement the probation, in shell, and would
race the thing it duplicates.** It runs before the binary on every start,
including the handover start, where the marker is present and unclaimed and the
correct action is to do nothing and let the new binary run. To distinguish that
from a real "will not start" it would need the same two-state logic the process
already has — a second implementation of one protocol, in a second language, where
disagreement between them is a rollback of a healthy release or a machine left on
a binary that cannot execute.

**`OnFailure=` runs only when something has failed.** The happy path forks no
extra process, and the handler is invoked at a moment when the marker's state is
already decisive: unclaimed *and* the unit is failing means no process of this
release ever reached `main`.

### 2. The gate is the marker's `started` field, and it is what makes the two mechanisms unable to fight

`#222` requires the supervisor-side check to be idempotent and to not fight the
in-process one. Both fall out of the gate rather than being arranged:

- `started=true` — a process reached `main`. A crash loop puts it through
  `CheckStartup` again and the demotion happens there. The script exits without
  touching anything.
- `started=false` — no process of this release has ever run. Nothing in-process
  will ever act on it, because nothing in-process is running. The script acts.

Neither mechanism can encounter the other's state mid-flight, because the state is
only ever advanced by the process actually starting. And the script's first act on
its own case is to remove the marker, so a second run finds nothing to do: running
it twice is a no-op rather than a swap back.

The consequence for testing is that the "do not fight" property is measurable
rather than argued. `deploy/update_rollback_test.go` sets up the in-process case
for real — it calls `update.Apply` and then `update.CheckStartup` — runs the
script beside it, and asserts on bytes that the target is unchanged, the marker is
still there, and the unit was not restarted; then that the in-process demotion
still happens afterwards.

Both cases were also exercised end to end against a live systemd manager, with the
shipped script and a unit carrying this `OnFailure=`, using `update.Apply` to
publish the release. A release whose loader does not exist was rolled back about
two seconds after the restart that handed over to it, with the unit running the
restored binary — and `systemctl restart` had returned 0 and reported
`active/running` for it first, which is §3's second fact happening rather than
being described. A release that reached `main` and then died produced, in order:
the script declining the case, the in-process demotion on the next start, the
supervisor re-execing the previous binary, and a final firing of the script that
found no marker and did nothing.

### 3. Two systemd facts, measured rather than assumed

**`OnFailure=` fires on EVERY failed start, not once when the start limit is
hit.** Measured on systemd 259 with a unit configured `Restart=always`,
`RestartSec=1`, `StartLimitBurst=3` whose `ExecStart` did not exist: the handler
ran four times, and the journal logs `Triggering OnFailure= dependencies.` after
each failure, including the ones followed by an auto-restart.

This matters twice. It is why idempotence is load-bearing rather than good
manners — the script runs repeatedly and concurrently with systemd's own restart
timer. And it is why **nothing here changes the restart policy of a production
unit**: the design does not depend on reaching the start limit, so
`StartLimitIntervalSec=`/`StartLimitBurst=` are left exactly as they were on
`bacchus-exit.service` and `bacchus-coordinator.service`. On an older systemd that
fires only at the limit, the same gate produces the same result about ten seconds
later; retuning a live unit's restart behaviour to speed that up would be a change
with a far wider blast radius than the feature.

**`systemctl start` returns success the instant the process forks.** With
`Type=simple` the unit is `active/running` before the exec has failed — observed
directly in the same measurement, on a unit whose binary did not exist. So "did it
start?" is not a question anything outside the process can ask, and this record
does not build a check that pretends otherwise. What CAN be established from
outside is *"a release was applied and no process of it has ever run"*, which is a
fact on disk.

### 4. The binary to restore is read out of the failing unit

`OnFailure=bacchus-update-rollback@%n.service` passes the failing unit's name, and
the handler reads the path from `systemctl show -p ExecStart --value`. One
template covers every unit, and the path is not written down a second time where
it could go stale against the unit that actually runs it — the same reason
`deploy/bacchus-pin.sh` prints a live `ExecStart` instead of trusting a template.

The handler is a shell script, not a Go binary, and deliberately so: `#222`'s own
constraint is that the checker "must not be the binary being updated", and the
smallest thing that satisfies it on a machine already in trouble is one that
depends on nothing but `sh`, `sed`, `grep` and `mv`. It reads the marker with
`grep` rather than a JSON parser for the same reason. That leaves one contract
encoded twice — `encoding/json` on the writing side, a pattern on the reading
side — which is exactly the pair that drifts silently, so the tests never
hand-write a marker: every fixture is produced by calling the real `update.Apply`.

### 5. It is wired to both units that carry `Restart=always`, including the one with no updater

`bacchus-coordinator.service` gets the same `OnFailure=`, even though
`cmd/coordinator` does not call `CheckStartup` at all today — only `cmd/node`
does. With no updater there is no marker, so on that box the handler fires and
does nothing, which costs one forked shell per coordinator failure. The reason to
wire it now is that the coordinator IS a release role in the manifest
(`core/update.RoleCoordinator`, and `release.yml` emits its artifact row), so the
day it gains an updater the case with no in-process remedy is already covered
rather than newly missing. **Giving the coordinator an in-process
`CheckStartup` is a separate change to `cmd/coordinator`, and it is not made
here.**

## Alternatives rejected

- **`ExecStartPre=`.** §1. It duplicates the probation protocol in a second
  language and runs on the happy path.
- **Waiting for the start limit and demoting once.** `#222`'s own framing, and it
  is what the measurement above ruled out as a *requirement*: the handler is
  invoked long before the limit, so a design that only becomes correct at the
  limit would have been wrong for the first several invocations.
- **Tightening `StartLimitIntervalSec=`/`StartLimitBurst=` on the server units.**
  Not needed, and it would change how those units behave for the hundred failures
  that have nothing to do with an update — a node that crashes every thirty
  seconds currently restarts forever, and a narrower limit would make it give up.
- **A small Go helper instead of a shell script.** It would be a fourth binary to
  build, stamp, ship and update, in order to run four filesystem operations at the
  moment the machine is least able to run anything.
- **A health check the supervisor can ask.** Refused for ADR-0052 §7's standing
  reason and this record's §3: "started" is not observable from outside, and
  "serving" is `#114` and is not observable at all yet.
- **Making the marker's presence alone the signal, and having the script look at
  the unit's exit status instead.** `203/EXEC` is one way a binary fails to run
  and not the only one — a missing loader exits 127, a corrupt ELF may exit
  differently on different kernels — so an allowlist of statuses would silently
  miss cases. The marker answers the question directly.
- **Re-downloading rather than renaming.** The previous binary is already beside
  the target (ADR-0065 §5), so recovery is one `rename(2)` and needs no network on
  a machine whose whole problem is that it is not running.

## Consequences

- **+** The release channel's happy path works. A release that is applied and
  works now survives the restart that hands over to it, which it did not before,
  and no release can be delivered to a fleet until that is true.
- **+** The last of ADR-0052 §7's three failures gains an automatic remedy, and
  the remaining uncovered case is the one nobody can observe (`#114`).
- **+** The two mechanisms are gated on disjoint states, so adding the second one
  cannot break the first — asserted by running both against one real apply.
- **+** No new process on any happy path, no change to any unit's restart
  behaviour, and no new dependency: `sh`, `sed`, `grep`, `mv`, `systemctl`.
- **−** A crash-looping release now takes one extra restart cycle to be demoted
  (about two seconds) because its first start is a trial.
- **−** A unit that fails for an unrelated reason **while an applied release has
  not yet been handed over** is rolled back. The window is between an apply and
  the next start, the trigger has to be a genuine unit failure, and the outcome is
  that the box stays on the release it was already running — which is the working
  state and the same outcome as the update never having arrived. Priced and
  accepted rather than narrowed with an exit-status allowlist that would miss real
  cases.
- **−** The marker's on-disk shape is now a contract between Go and shell. Held by
  tests on both sides that share one fixture generator, and it is one field.
- **−** `bacchus-coordinator.service` names a handler that can do nothing for it
  until `cmd/coordinator` calls `CheckStartup`.

## What this record does not decide

- **A health signal for "applied, started, and cannot serve"** — `#114`, declined
  again for ADR-0052 §7's reason.
- **Whether `cmd/coordinator` should self-update**, and the `CheckStartup` call
  that would go with it.
- **The client's half.** `clients/fyne` has no `CheckStartup` call and no
  supervisor; ADR-0065 §5 applies a release at the next launch, and what a Windows
  or desktop equivalent of this rollback looks like is a separate question.
- **Anything about when a release is signed.** ADR-0065 §8 still stands: none of
  this can fire until the `update` delegation is minted.
