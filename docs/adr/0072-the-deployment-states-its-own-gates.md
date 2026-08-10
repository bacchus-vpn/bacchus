# 72. Every credential gate fails open, so the deployment states which ones it enforces and a check reads the answer back

- Status: accepted
- Date: 2026-08-09
- Tracking: issues #249, #247, #248
- Builds on: ADR-0064 / issue #205 (the pin, whose §7 no-copy rule shapes every
  mechanism here), ADR-0045 / issue #50 and ADR-0047 / issue #64 (the gates
  themselves and why they fail the direction they do), issue #226 (the `paths:`
  block this reads), issue #224 (absence reported apart from drift, the pattern
  #248 asks for a second time), ADR-0061 / issue #193 (`-account-service`)
- Implementation: `deploy/bacchus-gate-check.sh` (new),
  `deploy/coordinator-gates.env.example` (new), `deploy/bacchus-coordinator.service`
  (`WorkingDirectory=`, the gates `EnvironmentFile=`, `$BACCHUS_COORDINATOR_GATES`),
  `deploy/bacchus-pin.sh`, `deploy/testbed.env.example` (`COORDINATOR_GATES`,
  `UNIT_TEMPLATES`), `deploy/install.sh`, `deploy/gate_check_test.go` (new),
  `deploy/pin_test.go`, `deploy/install-test.sh`, `deploy/README.md`,
  `docs/RUNNING.md`

## Context

The live coordinator runs with **every credential gate off**. It carries the
bootstrap pair, the policy set and `-geoip`, and none of `-admission-pubkey`,
`-admission-authority`, `-device-root-pubkey`, `-account-service`,
`-revocations-root-pubkey` or either `-*-revocations-source` (#249, established
from the effective `ExecStart` the first real pin run printed).

Every one of those flags fails **open** when unset. That is deliberate and each
has its reasons — ADR-0045 §2 is the sharpest, and the direction is a decision
this record does not revisit. The consequence is what this record is about: an
unconfigured deployment is **indistinguishable from a working one**. The fleet
check passes, the unit comparison passes, the capability probe passes, and
nothing is refused anywhere because nothing was asked to refuse.

The cost is not that the gates are off on a testbed with no users. It is that
three owner tests are written as though they were on, and each would return a
**false pass**:

- **#167** — enrollment → gate → connect → renew. With the device gate disabled,
  a connect that succeeds proves the client reached an exit.
- **#173** — a revoked serial refusing a real client. With no revocation input
  the list is empty (#247), so a refusal cannot happen and a non-refusal means
  nothing.
- **#209** — a client following a moved account service. Nothing is published,
  so there is nothing to follow.

A test that cannot fail is worse than an unrun one, because it closes a card.

Two findings arrived beside it, and they are the same shape one level down.
**#247**: the unit has `WorkingDirectory=` empty, which for a system service is
`/`, so nine relative-default flags resolve under the root directory — and *a
missing revocation file is not an error, it means nothing is revoked*.
**#248**: `bacchus-pin.sh` skipped a box whose unit name this repository ships no
template for, and reported the skip at the volume of a pass; on the first real
run, the box it could not compare was the only box that misbehaved.

All three were found by hand, during work on something else. That is the
property this record is trying to change.

## Decisions

### 1. The gates are a configuration `deploy/` ships, not a flag set rediscovered from `-h`

`deploy/coordinator-gates.env.example` documents the whole set in three
cumulative steps — admission and the two revocation lists (stageable today), the
device gate and the account-service address (blocked on `bacchus-payment#82`),
and signed revocation bundles (blocked on `bacchus-payment#79`) — with each
step's preconditions and each blocked step's blocker named in the file.

**The alternative was prose**: a paragraph in `docs/RUNNING.md` saying which
flags to add, which is what existed and is what #249 describes as "a set of flags
rediscovered from `-h` each time". It lost on three counts, in increasing order
of how much they matter.

It gives the operator no artifact — a coordinator is configured by editing a live
unit under `ADR-0064 §7`, and the thing being edited should exist somewhere
before it exists on one box. It gives `bacchus-unit-check.sh` nothing to compare
against, which is the gap #249 itself points at. And decisively: **a paragraph
cannot be run.** `deploy/gate_check_test.go` builds `cmd/coordinator`, fills the
example's placeholders with generated key material, runs the binary with each
shipped recipe, and reads the resulting journal back through
`bacchus-gate-check.sh`. A renamed flag, a re-scoped one, or a default that
changed direction turns that test red. The same claim in prose rots silently, and
this repository has the specific evidence: ADR-0064's amendment B rejected
enumerating the flag table *in a shell script* for exactly this reason, and
solved it by making the list *be* the flags. This is the same move for a
different consumer.

What the file deliberately does **not** carry is `-policy-root-pubkey` and its
two companions. Signed policy is the one control here that fails **closed**, and
folding it in would mean a mistyped gate line stops the coordinator assigning
work. It stays in `ExecStart`, where it already is.

### 2. One word-split `$VAR`, and that is forced rather than chosen

The unit gains two directives:

```
EnvironmentFile=-/etc/bacchus/coordinator-gates.env
ExecStart=… $BACCHUS_COORDINATOR_GATES
```

`$VAR`, **not** `${VAR}`. systemd splits an unquoted `$VAR` at whitespace into
*zero or more* arguments and expands `${VAR}` into *exactly one*, always. That is
the whole mechanism and it is not a stylistic preference:

- **Unset or empty gives zero arguments.** A box with no gates file, or with the
  file this ships (an empty value), runs exactly as it does today. Gates-off
  stays the default and stays silent, which is what makes the directive safe to
  add to a live unit before anybody has decided what to put in it. The leading
  `-` on `EnvironmentFile=` does the same for a box that has no file at all, so
  the two edits can be made in either order.
- **`${VAR}`, or one `${VAR}` per flag, cannot express "off".** An empty
  `${ADMISSION_PUBKEY}` still produces an argument, and `-admission-authority ""`
  is a fatal parse error rather than a disabled gate. The existing
  `${ADVERTISE}`/`${TURN_PASS}` idiom works precisely because those are always
  set.
- **One token means the next gate flag is never a unit edit.** `bacchus-pin.sh`
  refuses to copy a `.service` file over one carrying hand-added flags (ADR-0064
  §7) *because* those accumulate there, so the unit is the worst place to keep
  configuration that changes. After one hand edit per box, the gates move to a
  file, and the unit stops being where policy lives.

There is no variable expansion inside a systemd env file, so each recipe in the
example is one literal, complete line rather than fragments composed by a later
one. That is why the steps are cumulative and verbose: it is the only shape the
parser supports.

The one honest cost: the `ExecStart` token itself still has to be added by hand,
per box, and the unit comparison cannot flag its absence, because `ExecStart`
essentially always differs and that difference is the no-copy rule being right.
What catches a box that got the `EnvironmentFile=` line and not the token is
decision 3, which reads behaviour rather than text — and that is the better
place for it to be caught anyway.

### 3. The check reads what the coordinator CONCLUDED, never what its flags say

`deploy/bacchus-gate-check.sh` takes the coordinator's journal on stdin and
reports one row per gate: admission, device entitlement, the two revocation
lists, signed revocations, signed policy, and the account-service publication.

A flag in `ExecStart` says what an operator asked for; the journal says what the
binary made of it — after parsing the key, after resolving the path, after
finding out whether the file is there. Those differ exactly where it matters. A
revocation flag pointing at a path that does not exist is present in `ExecStart`
and enforces nothing. A signed-revocations root whose namespace gate is off is
configured, started, and inert, and the binary says so in as many words. This is
ADR-0064 §3's choice — probe a capability, never read a version string — applied
to configuration, and it is free here because issue #226 already made the
coordinator state all of it at startup.

**`--require` is what turns a report into a verdict.** The pin passes
`COORDINATOR_GATES` from `testbed.env`, so the deployment declares which gates it
enforces and a pin that finds one off **fails**. Declared-or-nothing is
deliberate and it is the same judgement ADR-0064 §F made about the unit
comparison: a check that failed every pin until the gates were configured would
be switched off long before they were. A check that reports until an operator
says otherwise, and then holds them to it, survives.

The window rule is `bacchus-fleet-check.sh`'s, unchanged: everything before the
last `coordinator release` line describes a coordinator that is not running, and
a window with no startup line is refused rather than read as a pass. And like
that script and unlike `bacchus-pin.sh`, it **prints no hostname** — including
not echoing the device gate's audience, which is this coordinator's own dialable
identity and the one host-shaped value in the lines it reads.

**One gate cannot be read this way and is reported as UNKNOWN, not assumed.**
`-account-service` is the only configured thing `cmd/coordinator` announces
nothing about at startup (#260, filed). Declaring it exits **4** — could not be
read — rather than 0. An unreadable gate is not a gate that is on; that is
#248's finding, and it applies to this check first of all.

### 4. `WorkingDirectory=/etc/bacchus`, and every gate path absolute anyway

Both halves, because they fail differently. The unit gains
`WorkingDirectory=/etc/bacchus`, which is where every other file this coordinator
is handed already lives and which `install.sh` creates mode 0700 — so a flag
nobody thought about resolves under a directory that exists instead of under `/`.
And every path in the shipped gates configuration is absolute, because a gate
that depends on the working directory being right is a gate that will be wrong on
the next box.

`WorkingDirectory=` is a **directive**, which is the point of shipping it:
`bacchus-unit-check.sh` reports it as MISSING from every live unit, at full
volume, on every pin run until somebody adds it by hand. That is the same
mechanism ADR-0064 §F built for `OnFailure=`, used for the condition #247 found.

Stated because it is the way this bites: **adding `WorkingDirectory=` to a live
unit moves every relative path currently in effect.** On the live coordinator
every path written into `ExecStart` is absolute and the relative defaults resolve
to files that do not exist, so nothing moves that anybody is using — but the
`paths:` block is the thing to read before and after, not this sentence.

Not decided here, and deliberately left to a card of its own: whether
`cmd/coordinator` should stop defaulting these paths relatively and refuse loudly
instead, which #247 correctly calls the durable answer and #170 already settled
for `-device-cred-dir`. That is a fail-open→fail-loud change to every deployment
and it is not something to make while editing a unit file; `cmd/coordinator` was
also frozen for the wave this landed in (owner test #212).

### 5. No `bacchus-node.service` is invented; the host list says which template a box's unit is

#248 asks whether a node template should ship. It should not. The role a node
runs is a flag (`-role exit`, `-role exit,relay`, relay-only), so a box whose unit
is called `bacchus-node` or `bacchus-relay` is running what
`deploy/bacchus-exit.service` already describes under another name — and the
card's own instinct, that this may be a naming fix rather than a repository
change, is right. Shipping a second near-identical template would make the
divergence permanent and give a future third name nothing.

`UNIT_TEMPLATES="bacchus-relay=bacchus-exit.service"` in `testbed.env` says it
instead, beside the host list that already names those units. The pairing lives
in the operator's own configuration for the same reason the roll call's does
(ADR-0064 §E): it is knowledge about one deployment, not about this repository.

**And a box that could not be compared is counted.** `bacchus-pin.sh` now prints
`units: N of M compared clean, X with a gap, Y NOT COMPARED` and warns separately
on `Y > 0`. Absence and drift were separated for the fleet check in #224 and this
is the same separation one file over — a check that silently covers two of three
boxes reports on a fleet it did not look at.

### 6. The 2026-08-05 staged material is adopted in one part and rejected in the rest

`#251` found PKI hand-staged on a node box on 2026-08-05, beside a
`bacchus-coordinator.service.bak-2026-08-05` on the coordinator: an
`admission.key`, an operator CA and its two issued certificates, and a
self-signed account-service TLS pair. It reads as the same job this record
finishes, abandoned halfway. The brief was to adopt or reject it rather than mint
a second set beside it.

- **`admission.key` is adopted** as the testbed's operator admission authority.
  It is exactly the shape step 1 needs, it is a raw seed with no expiry, and
  minting a second would leave two keys with one lifecycle between them, which is
  the whole complaint of #251 and #227. **It must be moved off the exit box**: an
  admission signing key on the machine that sees plaintext egress is #60's
  co-location objection applied to a signing key. Adopting it is not endorsing
  where it sits.
- **The operator CA, its certificates and the account-service TLS pair are
  rejected for this purpose.** No flag in this repository consumes any of them;
  they belong to `bacchus-payment`'s operator surface (ADR-0012, ADR-0015) and to
  `bacchus-payment#82`. Nothing here adopts them and nothing here should be read
  as recording them — #251 remains the card that decides their fate.
- **Nothing new is minted.** The device-credential root and the revocations root
  are the account service's and the ceremony's respectively; there is no key to
  adopt because neither exists yet, and inventing a local one would produce a
  gate with no issuer, which refuses every client.

All of this is provisional by the owner's standing ruling: no key is touched
before 1.0 and every ceremony is redone before release. What is being decided
here is which key the testbed uses this month, not what ships.

## Consequences

- **The gate posture is on every pin run's output**, whether or not anyone asked.
  A finding of this class is now reported rather than discovered while doing
  something else, which is the only property that generalises past these three
  cards.
- **#167, #173 and #209 stay blocked, visibly.** The check makes their
  precondition legible instead of leaving each of them to discover it. #173's is
  reachable now (admission on, both revocation files created, revoke by serial);
  #167's and #209's are not, because both need an account service that does not
  exist yet.
- **A deployment that declares a gate and stops enforcing it fails its next
  pin.** That is a new way for a pin to fail and it is meant to be: the failure
  it replaces is a card closed on evidence that does not exist.
- **The `ExecStart` token is a one-time hand edit per box that nothing checks
  for.** A box that received `EnvironmentFile=` and not the token is caught by
  decision 3 rather than by the unit comparison, which is the right place but a
  slower one — the gate reads OFF, and the operator has to know that means the
  token.
- **`account-service` is a permanently UNKNOWN row until #260 lands.** The report
  is complete in every other column, and this one says why rather than being
  quietly absent.
- **Nothing here has been run against real hardware.** The recipes are exercised
  against the real binary and the checks against a simulated fleet; that the flags
  work through *systemd's* env-file parser and word splitting on a live box is a
  `needs-owner-test` blocker (#261), and no card that needs the gates should
  assume they are on until it passes.
