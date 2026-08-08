# 71. A node enrolls in one shot, and the claim code is never a value on a command line

- Status: accepted (issue #170)
- Date: 2026-08-09

## Context

ADR-0056 gave `clients/fyne` a real enrollment and renewal path and closed with
a bullet naming what it had not done: *"`cmd/node` still cannot enroll or renew.
A node-role client presents what is in its `-device-cred-dir` and lets it
expire."*

That flag's own help text told the operator the same thing in the other
direction — the credential "is not obtained here (enrollment is account-service
work, tracked separately)". The sentence was true of `cmd/node` and false of the
project the moment `clients/fyne` grew the path, and the two binaries have
disagreed since about how a device gets a credential.

This record decides the shape for `cmd/node`, and it exists mostly for §1: the
answer is not "add the flag", the reason is not obvious, and a future reader
should not have to re-derive it.

**This is not urgent, and the card says so itself.** 1.0 ships the desktop
client, and a node operator can provision a credential out of band. It matters
the moment a node needs an entitlement that expires — and that day is decided by
somebody turning a coordinator's `-device-root-pubkey` on, not by this record.
The scope below is deliberately the smallest thing that makes a node able to get
a credential and keep one.

## Decision

### 1. A one-shot `-enroll` mode. The claim code is never a flag value

ADR-0056 §3 refused a `-claim-code` flag, and issue #170 restates the reason as:
*a flag is re-supplied on every restart, so the second start presents a spent
code and gets `claim_rejected`.*

**That sentence is true of `cmd/node` and it is not true for the reason it
gives**, and the correction is worth making because it changes which failure the
design has to defend against.

A second start presents a spent code only if the device does not remember that
it enrolled. `accountclient.Enroll` asks `DeviceEnrollment.Enrolled()` before it
spends anything, so a node with a persistent `-device-cred-dir` would short-
circuit on every start after the first and never reach the wire. What makes the
failure real here is that **`cmd/node`'s `-device-cred-dir` defaults to empty**,
and empty is `core/devicestore`'s documented in-memory mode: a fresh device
identity every start, persisted nowhere. Under that default the first start
spends the claim code to bind a key the process takes with it when it exits, and
every start afterwards presents a spent code — exactly the described symptom,
produced by the *default* rather than by the flag. `clients/fyne` cannot reach it
because its `deviceCredDir` defaults to a per-user directory (ADR-0056 §5).

So the flag's real costs are two, and both survive the correction:

- **A single-use bearer secret ends up at rest in three places nobody chose** —
  a systemd unit, a shell history, and `/proc/<pid>/cmdline`, which is
  world-readable. `clients/fyne` can hold one in a config file only because a
  config file can be *rewritten*, and it erases the code the instant enrollment
  succeeds. A command line cannot erase itself.
- **The ephemeral-identity trap above**, which destroys the code rather than
  merely exposing it, and which no amount of care on the flag fixes.

**The decision: `-enroll` is a one-shot mode that runs the exchange and exits.**
The service that runs afterwards is given no claim code under any flag name, so
there is nothing for a restart to re-present. That is a stronger property than
erase-on-success, which depends on a write succeeding *after* the irreversible
step already has.

A **flag** one-shot rather than a subcommand, argued rather than assumed:
`-list` is this binary's existing precedent for "do one thing and quit", and
`cmd/node` parses with the `flag` package and no `os.Args[1]` dispatch.
Introducing dispatch would change how every existing invocation parses in order
to gain nothing `-enroll` does not already have.

`-enroll` runs **before every other startup check** — before the volunteer
validation, before the update machinery, before any coordinator is contacted. A
node being provisioned needs no exit key, no advertise address and no reachable
coordinator, and a typo in an unrelated flag should not stand between an
operator and a credential.

### 2. The claim code is read from stdin, or from a file that is unlinked

`-claim-code-file` names the source. `-` is stdin and is the default.

**Stdin is the default because a code piped in never reaches a disk at all.**
There is nothing to erase, and therefore no erasure that can fail. A file exists
anyway, because an unattended provisioning flow often finds dropping a file
easier than feeding a pipe; it is read, and **unlinked once the code has bought a
credential**.

Three details are decisions rather than implementation:

- **Unlink, not overwrite.** Rewriting the bytes in place is not an erase on a
  journaling or copy-on-write filesystem, and doing it anyway would buy a feeling
  rather than a property. The honest statement is that the path is removed, and
  that the shape which genuinely never writes the secret down is stdin.
- **A refused code is left in place**, matching ADR-0056 §3: `claim_rejected` is
  the answer to a typo as much as to a spent code, and an operator who mistyped
  needs to see and correct what they typed rather than face a missing file.
- **An empty file, or an empty stdin, is an error** rather than a fallback to
  §5's collect path. The operator named a source; a source that turned out to
  hold nothing is a mistake to report, not a different intention to infer.

A failed unlink is the one outcome that leaves a spent bearer secret readable on
a server, so it is logged at `WARNING` naming the path, rather than being
swallowed as tidy-up.

### 3. Why the alternatives lost

**A file the DAEMON consumes and unlinks** is the closest rival — issue #170
names it — and it fails on the same seam it was invented to fix. The unlink is a
second operation *after* the one that cannot be repeated, and its failure (a
read-only filesystem, a directory the service cannot write, a crash between the
two) leaves a spent code for the next start to present: the precise outcome
ADR-0056 refused, reached through a different door. It also puts a network call
to the account service on the startup path of a process whose job is to forward
packets, and it forces the daemon to decide what a claim-code file *means* beside
a device that is already enrolled — the code may be for an entirely different
device, so neither deleting it nor keeping it is right.

**An environment variable** (`BACCHUS_CLAIM_CODE`) is better than a flag —
`/proc/<pid>/environ` is not world-readable — and it is still a value re-supplied
on every start, living in a unit file the operator has to remember to go back and
edit. It solves the exposure that `/proc/<pid>/cmdline` causes and none of the
lifecycle problem.

**A separate provisioning binary** was refused on ADR-0056 §1's ground, applied
one level down: the release channel signs and distributes *a* node binary
(ADR-0065), so a second artifact is a second thing to build, sign, ship and keep
in step, in exchange for a mode flag.

**Provisioning and running are different lifecycles.** The decision is to keep
them in different invocations of one binary.

### 4. An account service with no `-device-cred-dir` is a startup refusal

This is the sharpest edge in the change and it is specific to this binary.

`-device-cred-dir` defaults to empty, and §1 explains what empty is. Enrolling
into it spends a single-use claim code on an identity that ceases to exist when
the process does — **unrecoverably**, because the account service erases a spent
claim hash rather than flagging it, so nothing is left for a second attempt to
match. Renewing against it is merely inert, which is worse in a different way: it
looks configured.

So both entry points refuse it, by name and with the reason, and the refusal
happens **before anything reaches the network**. `-enroll` refuses; a start that
names an account service refuses. A start that names no account service is
untouched, which is every node running today.

A second, smaller refusal in the same place: **`-claim-code-file` on a start that
is not `-enroll` is fatal.** That flag is read by the one-shot and by nothing
else, so a unit file carrying it describes an enrollment that will never happen —
the operator would provision a code, watch the node start cleanly, and find out at
the first gate-enabled connect. A silently inert flag is this whole record's
subject matter one level up.

### 5. `-enroll` with no claim code collects, and spends nothing

`-claim-code-file=` (empty) runs `POST /v1/credential` with the device key alone.

It is here because of a real asymmetry in `core/devicestore`, decided by
ADR-0046 §4: the **key** hard-fails on a present-but-unreadable file, while the
**credential** soft-fails to empty. So a node can lose its credential and keep
the identity the account service resolves it by — after which it has no claim
code left to spend, the engine's renewal loop deliberately does not treat an
empty store as a reason to enroll, and there is no way back. `Collect` is the way
back, it spends nothing, and it is safe to repeat.

It is a one-shot rather than something the daemon does on every start with an
empty store, and the reason is a cost the automatic version would pay silently:
`bad_assertion` — the answer for a device that was never enrolled — counts toward
a per-device-key cooldown on the service. A crash-looping node would spend that
cooldown on a question whose answer it already had. An operator running the
one-shot spends one attempt, deliberately.

### 6. Renewal ships with enrollment, through the same `core/accountclient`

ADR-0046 §6's amendment ruled it in advance: *"whatever ships enrollment should
ship renewal with it: one change, one protocol, one place a user configures
it."* It held for `clients/fyne` and it holds here. The one place is
`-account-service`; the protocol is the same three verbs; and a node that could
enroll and not renew would go dark at its credential's expiry having done
everything asked of it.

`core/accountclient` is used **unchanged**. This is a second embedder, not a
second implementation, and nothing about wiring it here needed a change to the
package the desktop client depends on. `Config.DeviceRenew` is filled with
`Client.Renew` exactly as ADR-0056 §2 describes, so the direction of the
dependency is unchanged: `core/accountclient` imports `core`, `core` imports
nothing of it, and this change adds no `core` import in either direction.

One note on the check that argument is usually written with. ADR-0056 §2 says
`go list -deps ./core` "names no HTTP client". **It does — and it did when that
was written.** `core` imports `refraction-networking/utls` directly, which reaches
`net/http` through `andybalholm/brotli`, so `net/http` has been in `core`'s
transitive graph since the fingerprint work landed and nothing about the account
client put it there. The property the ruling protects is real and unaffected — no
package `core` imports dials the account service — but the absolute form of the
check does not measure it. The form that does is the one ADR-0056's own `#166`
update reached for: the output is **unchanged** by the change under review. That
is the form used here; the stale phrasing in the two earlier records is `#239`.

**Configuration is four flags**, mirroring `clients/fyne`'s config keys one for
one: `-account-service` (a comma-separated list of *locations* of one service,
per bacchus#192 — one audience and one pinned CA across all of them, which is
what stops a second address becoming a second authority),
`-account-service-audience`, `-account-service-ca`, `-device-label`. Every
refusal `accountclient.New` makes is fatal at startup, because each is a value
that cannot be defaulted: an empty audience binds assertions to nothing, and an
absent CA falls back to the public root pool, which authenticates the decoy.

`-device-label` defaults to the word `node` and is **never derived from the
machine**. ADR-0056 §5 made that call for a desktop, where a hostname is a
username; a server's hostname is no better, being routinely the provider's, the
datacenter's, or the operator's own name. It travels to the account service in
the clear and is stored there durably.

### 7. A failed renewal escalates on the clock, in the only surface a daemon has

ADR-0046's fourth pre-registered question — *what a failed renewal looks like to
a user rather than to a log line* — has a different answer here, because for a
daemon **the log is the surface**. The question does not go away, though. It is
skipped when renewal failure is treated as an error, because at the moment it
happens it is not one: the node keeps connecting on the credential it holds and
everything works, right up until that credential expires and a gate-enabled
coordinator starts refusing every connect for a reason nobody can connect back to
an outage they never saw.

So the wrapper reports the **remaining life of the credential being replaced**,
and escalates on the clock rather than on what went wrong — what went wrong is
mostly not actionable and how much time is left always is:

| remaining life | what the operator reads |
| --- | --- |
| more than 3h | renewal failed and will be retried; this node keeps connecting on what it holds, valid until … |
| 3h or less | `WARNING`: renewal is failing and the credential expires in about … , after which a gate-enabled coordinator refuses it |
| none, or unreadable | it has EXPIRED and is being refused now / there is no telling how long it lasts |

The 3h threshold is far larger than `core`'s own 6h renewal margin, for
ADR-0056 §6's reason: the margin is when a node *starts* trying, so a node that
cannot reach the service has roughly six hours of ten-minute retries before it
goes dark, and a warning that arrived at the last of them would land inside the
window where nobody can act on it. Half the slack is the line.

Two refusals ignore the clock and say so at once, because no amount of waiting
fixes them: a lapsed subscription and a revoked device.

### 8. What a node does not get, named rather than left to be discovered

- **A node does not learn a moved account-service address from the signed
  directory.** `clients/fyne` does (bacchus#193), and the resolution that does it
  — `EffectiveAccountServiceURLs` — lives in `clients/fyne/internal/appstate`,
  which Go's `internal` rule makes unreachable from `cmd/`. A node's list is
  configuration and only configuration. That matters more than it sounds: the
  account service runs on anonymously rented infrastructure and its address *will*
  change, and a device that cannot reach it has the renewal margin, not the
  credential lifetime, before it stops connecting. Configuring several addresses
  is the mitigation available today; hoisting the resolution somewhere both
  clients can reach it is a separate change.
- **A pure forwarder is unaffected, and says so.** The engine starts its renewal
  loop for the client role alone, because a device credential is presented at
  connect and a forwarder never connects. An account service configured on an
  exit-only node is therefore inert, and that combination logs a warning rather
  than pretending to work.
- **Nothing here mints a node-role admission credential.** ADR-0056 §7's closing
  note applies unchanged: what the account service mints carries the **client**
  role, so a node volunteering as an exit or relay still needs its operator-minted
  `-admission-cred`. This change moves the device credential and touches nothing
  about admission.
- **`-enroll` and a running node share one directory with no lock.** Both write
  the credential through `atomicfile`, so neither can produce a torn file, but a
  renewal landing at the same instant as a collect leaves whichever wrote last —
  and both are valid credentials for the same key, so the cost is a wasted
  exchange rather than a broken node. The documented order is to enroll before
  starting the service.

## Testing

`cmd/node/enroll_test.go` runs a fake account service over real TLS with a
certificate of its own, answering the three verbs and **counting requests by
path**, because almost every claim in this record is a claim about how many times
`/v1/enroll` was sent.

The load-bearing test is
`TestEnrollSpendsTheClaimCodeExactlyOnceAcrossRestarts`, which is §1 written
down: it enrolls, re-runs the identical one-shot, then starts the node's
account-service wiring twice, against a service that behaves as the real one does
and answers `claim_rejected` to any second presentation. `/v1/enroll` must have
been sent exactly once across all four.
`TestEnrollIsIdempotentForADeviceThatAlreadyHoldsOne` covers the case that
actually destroys value — a re-run with a *fresh, live* code, which is what a
provisioning script does when the first run's output was lost — and proves the
second code is neither spent nor deleted.

The rest follow the decisions above: the claim-code file does not exist after the
code has bought a credential and does exist after a refusal; stdin is read and
trimmed and the value on the wire is the one supplied; an empty source is an
error; an empty `-device-cred-dir` is refused **without a single request reaching
the service**; a broken account-service configuration is refused by name; a
`-claim-code-file` on a running start is refused pointing at `-enroll`; and there
is no `-claim-code` flag at all — checked by registering the flags on a throwaway
`FlagSet` and looking, which is the structural half of §1.

Renewal is driven through the seam's real signature, with the fixture's premise
asserted rather than assumed: the test credential is checked to be inside `core`'s
own 6h margin before it is used, so the test cannot quietly stop exercising
anything if the two drift apart. It also asserts all three values survive the
round trip — a seam that dropped the admission credential would refresh the
entitlement and let network membership lapse, which is ADR-0056 §7's finding and
the reason the seam has the shape it has.

## Consequences

- **Issue #170 closes.** `cmd/node` can enroll and can renew, and its
  `-device-cred-dir` help text no longer contradicts the rest of the project.
- **ADR-0056's Consequences bullet is discharged.** "`cmd/node` still cannot
  enroll or renew" describes the state before this change.
- **`Config.DeviceRenew` has a second embedder**, which is the first evidence
  that the seam ADR-0046 kept is fillable by something other than the client it
  was first filled for. It needed no change to `core/accountclient` to serve one.
- **A node with no account service configured behaves exactly as before.** The
  flags are empty by default, `Config.DeviceRenew` stays nil, and renewal is off.
- **Two new startup refusals exist**, and both are for configurations that would
  otherwise have failed silently and much later: an account service with no
  `-device-cred-dir`, and a `-claim-code-file` on a start that will not read it.
- **The claim code's exposure is now a property of how it is supplied**, not of
  the design: piped in, it never touches a disk; in a file, it is removed once
  spent. It is no longer in a process listing under any invocation.
