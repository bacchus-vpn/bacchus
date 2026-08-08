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
