# 66. One atomic file writer, and the line where durability stops

- Status: accepted
- Date: 2026-08-08
- Tracking: issue #188 (and the residual its comment carries from #189)
- Builds on: ADR-0043 (the policy state file and its rollback floor), issue #168
  (the revocation list's atomic write), issue #178 (the secrets file's), issue
  #189 (the ed25519 seed writers' `O_EXCL` and flush), ADR-0051 (the
  `/etc/resolv.conf` capture)
- Implementation: `core/atomicfile` (new — `Write`, `WriteDurable`, `SyncDir`);
  `core/policy/cache.go` (`writeAtomic`, `Store`, `StoreFloor`);
  `core/admission/verify.go` (`SaveFile`; `writeStagedList` deleted);
  `core/coldstart/atomic.go` (`writeFileAtomic`; `writeStaged` deleted);
  `core/devicestore/store.go` (`save`); `core/capacity/quota.go`
  (`checkpoint`); `core/selection/store.go` (`save`);
  `cmd/bacchus-netd/dns.go` (`replaceFile`)

## Context

Issue #188 counted seven hand-rolled copies of one shape — stage a complete
file beside the target, rename it over — and asked whether one helper should
replace them. It also recorded that three of the seven were not merely
duplicated but **wrong**: `core/devicestore`, `core/capacity` and
`core/selection` staged to a FIXED name (`path + ".tmp"`) and renamed WITHOUT
flushing.

**The count was seven when the card was filed and is nine at the commit this
record lands on, and both new copies arrived after it was written.** The card
was filed on 2026-08-06 at 00:51. `clients/fyne/internal/appstate/config.go`
gained a full copy thirteen hours later in #200, and `core/revocation/cache.go`
two days after that in #210, byte-for-byte identical to `core/policy`'s and
saying so in its own comment. `clients/fyne`'s cites this card by number and
declines to consolidate for the reason it gives — the other packages are in
flight — which is exactly right per copy and is how the count got to nine.
`core/revocation`'s does not mention it at all, which is the same problem
arriving without even a note attached.

Two of the copies also carry a hand-maintained list of the OTHER writers in
their doc comments, and **both lists are already wrong**: `core/coldstart`'s
omits `core/revocation` and `clients/fyne`, `core/admission`'s omits those two
and `core/coldstart`. The duplication has therefore already produced stale
documentation about itself, which is the maintenance surface the card's "for"
argument predicted, observed rather than forecast.

That is what decides the question. Two copies are a judgement call; nine copies
growing at one per wave, three of them defective and two of them describing the
set incorrectly, is a shape that does not stay correct.

## Decisions

### 1. One writer, `core/atomicfile`, and the copies adopt it

`core/atomicfile` holds the shape once:

- stage in the target's OWN directory (`os.Rename` is atomic only within one
  filesystem; across one it degrades to copy-then-delete);
- under a UNIQUE name from `os.CreateTemp`, dotted and suffixed `.tmp` so debris
  from a killed writer sorts beside its target, is hidden from a plain `ls`, and
  can never be mistaken for the file itself;
- write, set the mode, flush, close, rename;
- remove the staged file on every path that does not rename it away.

Seven of the nine call sites adopt it in this record. The other two do not, for
ownership reasons rather than technical ones — see §7.

### 2. What it deliberately does NOT absorb, which is how #178's objection is answered

Issue #178 declined to build this helper, and #188 restated why: the modes
differ, the `MkdirAll` behaviour differs, each caller wraps errors with its own
package prefix, and *"a helper carrying all of that as parameters is close to
`os.WriteFile` with extra steps."*

That objection is correct about a helper that absorbs all three differences, and
it is answered by not building that helper:

- **Parent directories are not absorbed.** Three callers create them and three
  deliberately do not, and the three that do disagree about the mode (0700,
  0700, 0755). Each keeps its own `os.MkdirAll` line, where the mode is visible
  at the site that chose it. `clients/fyne`'s `SaveConfig` had already arrived
  at exactly this arrangement independently.
- **Error prefixes are not absorbed.** Every error names the operation and the
  path; callers wrap with `%w` and their own package prefix, as they already do.
- **The mode is a parameter** — see §3.

What is left is one function whose signature IS `os.WriteFile`'s. That is the
point rather than an embarrassment: "close to `os.WriteFile` with extra steps"
describes the intended relationship exactly, because the extra steps are the
entire content, and a caller who reaches for the stdlib function by reflex
should find the substitution costs nothing to make.

### 3. The mode is a parameter, and `core/capacity` keeps 0644

The strongest argument against consolidating was that a helper flattening the
modes either loosens a secret or breaks a reader. Five of the seven converted
writers install 0600, because they hold credentials, state that gates admission,
or a rollback floor. Two do not, and neither is an oversight:

- `core/capacity`'s quota checkpoint installs **0644**. `quotaState`'s own doc
  says an operator debugging "why is my node not serving" must be able to `cat`
  it, and its contents are a byte count and a date.
- `cmd/bacchus-netd`'s `replaceFile` takes the mode from ITS caller — 0644 when
  it points `/etc/resolv.conf` at the tunnel, and the mode it recorded from the
  original file when it puts that back. A writer that could only install one
  mode could not restore a file it did not write.

So the mode is a parameter, not a property of the writer, and
`TestCheckpointStaysOperatorReadable` pins 0644 specifically so that a later
tidy-up cannot quietly narrow the odd one out to match the five.

### 4. The mode is applied AFTER the bytes, and the odd writer out was the correct one

The copies disagreed about one ordering. The three full copies chmod before
writing; `cmd/bacchus-netd`'s `replaceFile` chmods after. Issue #188 lists that
as a fourth variant, and the natural reading — that the late chmod leaves the
file readable-by-default while it is written — **is backwards**:

- `os.CreateTemp` creates its file 0600 whatever the umask, so before any chmod
  the staged file is owner-only.
- `replaceFile`'s mode is **0644**, because `/etc/resolv.conf` must be
  world-readable. Applying that mode BEFORE the write is what would let every
  local user read a half-written resolv.conf.
- The writers that chmod first are safe only because 0600 is not wider than what
  `os.CreateTemp` already gave them — a property of their mode, not of their
  ordering, and one the next caller has no reason to preserve.

Applying the mode after the bytes is correct for a widening mode and for a
narrowing one, so `core/atomicfile` does that for everyone, and the six moved to
match the one. It is applied before the flush so the mode change is flushed with
the data rather than left as a metadata update racing the rename.

### 5. The durability boundary is per WRITE, not per file

A file's own `Sync` makes the BYTES durable. It does not commit the DIRECTORY
ENTRY, so on most filesystems a power loss immediately after the rename can come
back holding the previous file. None of the nine copies fsynced the directory,
and two of them said so in as many words: *"every atomic writer in this
repository stops at the same line"*. Issue #188's comment asks for that boundary
to be decided once, here, rather than seven times.

It is decided, and it is not one line for the whole repository. The
discriminator is not how important the file is — it is **whether anything will
write the same state again**:

> Take the directory fsync when the write records something that will not be
> re-emitted. Skip it when a later ordinary write re-establishes the same state.

For a replacing writer, a lost rename restores a complete OLDER file. Where a
loop re-writes that state on a timer, the loss costs one generation and repairs
itself unprompted; paying an fsync on every write to protect a self-healing
failure is not a trade worth making, and on the hardware `core/capacity` targets
it is a metered stall on the forwarding path. Where nothing re-writes it, the
loss is silent, permanent, and happens after a tool has told an operator the
action succeeded.

Applied:

| Writer | Directory fsync | Why |
| --- | --- | --- |
| `core/admission` revocation list | **yes** | Operator decisions, one at a time. Nothing rewrites it until the next revocation; a lost rename un-revokes a credential silently and forever. |
| `core/coldstart` secrets ledger | **yes** | Read-modify-write of unreconstructable secrets whose other half has already gone out of band to a person. |
| `core/coldstart` client cache | **yes** | The marginal one, taken on `SaveCache`'s own argument: the fallback from an unusable cache is a network fetch that, for these users, may be exactly what is unreachable. |
| `core/policy` state file | **only when the floor RISES** | `cmd/coordinator` re-records the same floor every `policyRefresh` (10s), and those repair themselves. A raise is not re-emitted: lose it and an attacker who controls the fetch gets a genuine, signed, unexpired older generation back. Rare writes pay; repeated ones do not. |
| `core/capacity` checkpoint | no | Re-written every `granularity()` bytes or 30s, on the data path, on SD-card hardware. A lost rename costs less than the crash loss the design already accepts. |
| `core/devicestore`, `core/selection` | no | Re-written on the next renewal or the next success; losing one costs a renewal or a round of discovery. |
| `cmd/bacchus-netd` resolv.conf | no | Held for the length of a session and restored on release; the previous generation is the state the machine was already in. |

`core/policy`'s split is what makes the rule worth stating as "per write": the
same file, the same function, and the answer differs by what the write means.

### 6. The create case is different, and keeps its own card

Issue #188's comment carries a residual from #189: the three ed25519 seed
writers (`cmd/coordinator`, `cmd/admission-issue`, `core/devicestore`'s
`LoadOrGenerateKey`) got `O_EXCL` and a flush, and the flush has the same gap.
Their polarity is worse than a replacing writer's — losing a rename restores a
complete older file, but losing a first-run CREATE leaves **no file at all**,
and all three then regenerate silently on the next start, having already
distributed the public half.

By §5's rule they are on the durable side: a first-run generation is the
definition of a write nothing re-emits. They cannot use `Write` — `O_EXCL` on
the real path is precisely what stops two processes both believing they
generated the key, and a stage-and-rename cannot express that — so
`core/atomicfile.SyncDir` is exported for them. Converting them is issue #215,
because all three live outside the files this record's change owns.

### 7. What is not converted here

- `core/revocation/cache.go` — the ninth copy, and the analogue of
  `core/policy`'s `MinAsOf` floor; §5's policy row applies to it unchanged.
- `clients/fyne/internal/appstate/config.go` — a full copy, correct, whose doc
  now contains one sentence this record falsifies (*"which is where every atomic
  writer in this repository stops"*). By §5's rule that writer keeps `Write`:
  the config is re-written by the next save, and the previous one is a
  configuration the user was already running.
- `core/update`'s downloaded-artifact writer, being written in the same wave.

All three are call-site changes of a few lines each, and all three are outside
this lane's file ownership. Issue #215 carries them, together with §6's three
create-case writers, rather than being reached for mid-wave.

## Consequences

**The two defects are closed, and demonstrated rather than argued.** Restoring
the fixed staged name under the new tests produces exactly the failure #188
describes: a reader observing 6,494 bytes that no writer wrote in
`core/atomicfile`'s own stress test, 992 bytes of unparseable JSON in the
selection cache, 99 in the quota checkpoint — plus renames failing outright,
because one saver's cleanup removes the other's staged file. Restoring the early
chmod produces ~1,000 observations of a world-readable incomplete resolv.conf in
a single run.

**Two test fixtures depended on the defect.** `core/capacity`'s
checkpoint-failure test squatted `path + ".tmp"` to break the write, which only
worked because the staged name was predictable. It now squats the parent
directory after the read instead — an ordering that keeps both halves
platform-independent, which the fixture's own comment records as having been got
wrong once before in the other direction.

**A stall moves onto `core/capacity`'s lock.** `checkpoint` runs under `q.mu`,
which the metered reader takes twice per `Read`, so a checkpoint now holds it
for the length of an `fsync` rather than a `write(2)`. It is bounded by the
checkpoint cadence, never by the read rate. Dropping the lock around the write
instead would let two checkpoints land out of order and install an older total
over a newer one, which is the one failure that counter must not have.

**An observation left deliberately unacted on.** `cmd/coordinator` calls
`policy.Cache.Store` on every successful refresh, which rewrites an identical
file every ten seconds. Skipping a write whose bytes have not changed would
remove ~8,600 file replacements a day; it is a change to when the coordinator
writes rather than to how, so it belongs to whoever owns that loop.

**Nine copies became one plus two, and the accounting is now in one place.**
Anything that changes about this shape — the ordering, the cleanup, the
durability rule — changes in `core/atomicfile` and its ADR, instead of in
however many doc comments happen to describe it correctly that week.
