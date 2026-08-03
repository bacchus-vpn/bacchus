# 52. The signed release channel: a content-addressed manifest under the root's `update` delegation, announced on messages that already flow

- Status: accepted
- Date: 2026-08-02

## Context

ADR-0015 decided the version policy and, in the same breath, decided that the
channel enforcing it must be signed: *"it requires signing, disciplined key
management, and ideally reproducible builds **before the mechanism ships**."*
ADR-0029 built one half — the `release` wire field at registration,
`-min-serving-version`, and the force-major client cutover — and said so
explicitly, deferring the delivery half until "a beta ship is in sight."

Beta is now in sight, and the two halves are backwards for a fleet rollout. The
fence works: a node running a burned release is dropped from matchmaking and
capacity evaporates. Nothing delivers the build that would bring it back. **A
fence without a channel is a kill switch, not a repair tool** — it can subtract
a stale node from the network and cannot make it un-stale. The fencing has
already needed a patch of its own (the pooled path swallowed `ListExits`'s
update-required error and bypassed the force-major cutover), which is precisely
the class of fix a deployed fleet cannot receive today.

The pre-1.0 plan puts the client on a large number of real devices on the premise
that whatever the fleet finds can be pushed as a fix. That premise is currently
false. This record makes it true.

## What already ships, and what the work actually is

Four findings reshaped the scope before any of it was designed. Three of them
shrink the work; one of them corrects a premise the card was built on.

**1. The `update` delegation is already built, on both sides.**
`core/delegation` declares `RoleUpdate Role = "update"` with the doc comment
*"delegates 'may sign forced-update manifests', verified offline by a client"*,
and `VerifyDelegationCert` matches the role **exactly** against the role its
caller asks for — the property that makes a policy cert cryptographically useless
as an update cert. The offline root's ceremony tool signs all three leaf
delegations (`issuer` / `policy` / `update`) today. So §1 of this work is not
"design a delegation": the object, its domain-separation tag, its validity
window, its revocation hook and its exact-role check exist, ship, and are tested
adversarially. What is missing is the object *beneath* the delegation — the
manifest the update key signs. That is genuinely new; the chain above it is not.

**2. The announcement channel is already on the wire, in both directions.**
`Release` is a field on the shared wire struct (`core/engine.go:881`). A node
stamps it on every register; the coordinator stamps its own on every `countries`
and `session` reply (`cmd/coordinator/main.go:764`, `:979`, `:1016`, `:1045`);
and `Engine.observeNetworkVersion` already runs on each client reply that carries
one. **Learning that a newer release exists therefore costs no new traffic
whatsoever** — it is a field on a message the peer was already going to send.
This is what makes the anti-fingerprinting constraint tractable rather than a
tension to be split.

**3. The card's claim about `deploy/install.sh` is not in the tree, and the
underlying mechanism is different from the way it was described.** The brief
states the installer "already works around [the running-executable problem] with
`install → .new` then `mv`." It does not. `install_file`
(`deploy/install.sh:261`) is a bare `install -D -m "$mode" "$src" "$dest"`, and
it is the function every binary goes through — `bacchus-fyne`, `bacchus-netd`,
`bacchus-coordinator`, `bacchus-node`. The temp-file-plus-`mv` at `:331`–`:346`
is the **env file**, and the one at `:519`–`:532` is the **`.desktop` file**.
Neither is a binary and neither is about a running process.

Measured on this workspace (a running Go binary, coreutils 0.8.0):

| operation over a running executable | result |
|---|---|
| `cp new old` | fails — `Text file busy` (`ETXTBSY`) |
| `install -m0755 new old` | **succeeds** — destination inode changes (73197 → 73198) |
| `mv new.staged old` (`rename(2)`) | succeeds |

So the installer survives an upgrade-over-a-running-binary by an accident of
which primitive `install(1)` uses — it unlinks the destination and creates a new
file rather than writing in place — not by a designed workaround. That is fine
for an installer run by an operator who can look at the output. It is not the
shape to copy for an unattended self-update, because **unlink-then-create is not
atomic**: there is a window in which the path does not exist, and a crash inside
it leaves a node with no binary at all. `rename(2)` has no such window.

**4. The prior art that does exist is `core/policy`, not `deploy`.**
`Cache.writeAtomic` (`core/policy/cache.go:183`) is the exact sequence this needs:
create a temp file in the **same directory** as the target, `chmod` it, write,
`Sync`, close, `os.Rename`. It was written for a JSON cache; it is the correct
shape for a binary and is what §3 below adopts.

## The measurement: reproducibility

ADR-0015 prefers reproducible builds. Whether that preference is affordable is a
measurement, not an opinion, so it was measured (Go 1.26.4, `linux/amd64`):

- **`cmd/coordinator`, built twice with `-trimpath` and `CGO_ENABLED=0` from two
  different source directories, is byte-identical** — same SHA-256, once from the
  worktree and once from a copy of the tree at an unrelated path.
- **Without `-trimpath` the same two builds differ**, and the absolute source path
  appears in the binary 839 times. `-trimpath` is exactly the flag that closes
  this, and CI does not currently pass it: `.github/workflows/ci.yml:28` is a
  plain `go build ./cmd/...`.
- **`cmd/node` (20.9 MB), `cmd/coordinator` (13.3 MB) and `cmd/bacchus-netd`
  (5.5 MB) all build with `CGO_ENABLED=0`.**
- **`clients/fyne` does not.** With cgo off the build fails in
  `github.com/go-gl/gl` — "build constraints exclude all Go files" — because the
  GUI is OpenGL through cgo. ADR-0039 recorded this as a build prerequisite, and
  CI's Windows job asserts `CGO_ENABLED=1` on purpose, throwing if it is not.

That split is not incidental: **the binaries that are reproducible are exactly the
binaries whose compromise ADR-0015 calls fleet-wide.** §5 decides on that basis.

## Decision

### 1. A signed manifest, under the `update` delegation that already exists

A release is described by one signed object, `bacchus/update-manifest/v1`. Its tag
is registered in `core/delegation`'s tag registry rather than beside its own
schema — that package's own stated rule, and the reason its file is the one place
the whole set of domain-separation tags can be audited together.

The signed body carries a format version (checked exactly, never as a minimum), a
release semver, an issue time and expiry, a monotonic `seq`, and a list of
artifacts. Each artifact names an OS, an architecture, a role, a size and a
SHA-256. Verification is four tiers, each fully checked before the next is used:

1. the **root public key**, compiled into the binary;
2. the **delegation cert**, verified against the root with `RoleUpdate` matched
   exactly, its window checked, its serial checked against revocation;
3. the **manifest signature**, by the key that cert delegates to;
4. the **artifact hash**, over the complete downloaded bytes.

**The manifest names hashes and never locations.** A URL inside a signed manifest
would make the fetch path part of the trust object, and would hand whoever serves
that path a lever over a fleet that had cryptographically committed to asking it.
A hash is a name any source can satisfy and none can own. This is the single
decision the rest of §2 falls out of.

**Rotation.** The delegation window is the root's medium-lived bound; re-minting
is a signing ceremony, and it is deliberately the only thing that needs one.
Revoking a compromised update key reuses the `revoked func(serial string) bool`
hook `VerifyDelegationCert` already takes — the same shape `core/admission.CRL`
uses to carry revocation to a client over a network it does not trust.

**What the private half means for this repository.** The signer lives outside this
repository and cannot be imported here; `core/delegation`'s own doc comment says
so, and its test explains why signing a delegation "is the root holder's operation
and never this repository's: a public coordinator that could mint delegations
would defeat the entire arrangement." That is the property, not a limitation. Its
one real cost is testing: this side can verify and can never mint, so a bug that
makes both implementations agree on the wrong thing has no local witness. The
answer is the one already in use for the credential chain — **frozen conformance
vectors, run through the other side's verifier** — and the update manifest earns
its own set on the same terms.

### 2. Delivery: announce on what already flows, fetch content-addressed from anywhere

**Announcement is free and already shipped.** A client learns a release exists
from the `release` field on the `countries`/`session` reply it was already
receiving. A node learns from the reply to a register it was already sending
every ten seconds. Nothing new goes on the wire for discovery.

**The manifest is requested on the existing connection, and only on a change.**
When the announced release differs from `version.Current()`, the peer asks for the
manifest over the connection it already has. This is **edge-triggered, not
periodic**. A client that is current never asks. There is no interval to measure,
because there is no interval.

**The bytes are content-addressed, so the source is untrusted by construction.**
The default source is the peer the client is already talking to — ADR-0037's
courier, generalized from a signed snapshot to a release artifact. That record's
formulation is exactly right here: *"dispense, never author."* A node caches the
artifact bytes it last verified and serves them to a peer; it re-signs nothing and
needs no key; a hostile courier can serve stale-but-genuine bytes or nothing, and
never a forgery.

Because the manifest commits to a hash rather than a location, **every other
source is equally acceptable and needs no new trust**: a mirror, a static host,
GitHub Releases, the Telegram bot `docs/distribution.md` §4 recommends, or a USB
stick carried across a room. This is what finally makes that document's §5.4 —
*"no unverified auto-update from an untrusted source"* — satisfiable without ever
naming a trusted source. There is no trusted source. There is a trusted signature.

**Why this is not a fingerprintable fetch.** The constraint on the card is real and
narrow: `clients/fyne` performs **no periodic network activity of its own** — the
only fixed ticker in the engine is `registerLoop`'s, which is the forwarder path
(`core/engine.go:1835`), and the client's traffic is otherwise user-driven. A
recurring update poll would therefore be new, distinctive, well-timed behaviour on
a device whose whole design budget goes into not having any (ADR-0018, ADR-0022,
ADR-0032). Three properties remove it:

- **no period** — the request is triggered by a version change, and a version
  change is a fleet-wide event rather than a per-client one, so it is not a
  per-client tell either;
- **no new endpoint** — the manifest rides the coordinator connection that already
  exists, already blended onto the shared STUN/TURN port (ADR-0017);
- **no new flow** — the artifact bytes ride the data plane the client already has
  up, inside the session, indistinguishable from the traffic the session exists
  to carry.

What is observable to a censor is that a session moved some bytes, which is what
a session does.

**Why this does not require trusting the coordinator with code.** Carrying is not
authorizing. This is not a new argument in this codebase; it is the argument
`core/admission.CRL` already makes about itself. That bundle, in its own words,
*"travels to the client over the network, possibly via the same hostile
coordinator … already assumes may lie, so … it is signed by the admission root
and verified against the anchor the client already holds, trustworthy independent
of whatever relayed it"* — the hostile-coordinator assumption being ADR-0026's.
The update manifest is the same object class against a different anchor.

A lying coordinator can therefore **withhold** an update, or announce a release
that does not exist. It cannot substitute one. Withholding is a
denial-of-service against patching — real, and bounded by two things that already
exist: the coordinator pool and mesh-walk mean a client is not dependent on one
coordinator's honesty (ADR-0020, ADR-0037), and content-addressing means the
announcement is the only thing a coordinator holds, while the bytes are available
from anything that has them. Announcing a phantom release costs a wasted manifest
request and nothing else, because a manifest that does not verify is not a
release.

**The node side is the same mechanism with different sources.** A node's peers are
its coordinators and other nodes, and its fetch is not covert in the way a
client's must be — a node is infrastructure whose conversation with a coordinator
is already its normal traffic. The manifest, the verification and the apply path
are identical; only the source list differs.

### 3. Verify before apply, and the apply is a rename

One sequence, on node and client alike:

1. Download to a **staging file in the same directory as the target**. Same
   directory, not merely the same filesystem, so the final `rename(2)` cannot
   cross a mount boundary — this is the one real constraint the design adds, and
   it is the same one `core/policy.Cache.writeAtomic` lives with.
2. Hash the **complete** staged file and compare it to the manifest. Never
   stream-verify, and never verify incrementally into the live path: a hash that
   is checked as bytes arrive has already let unverified bytes exist somewhere
   they could be executed.
3. `chmod` the staged file, `Sync` it, close it.
4. Move the current binary aside under a known name (kept, not deleted — §7).
5. `os.Rename` the staged file onto the target path.

**Nothing works around `ETXTBSY`, because nothing ever writes to the running
path.** `rename(2)` replaces a directory entry; the running process keeps the
inode it was started from and keeps running unharmed until it exits. The
measurement in the preamble is what rules out the alternatives: `cp` cannot do
this at all, and `install(1)` can only do it by unlinking first, which is the
non-atomic window.

**A failed verification deletes the staging file and touches nothing else.** The
running binary is not moved, the target path is not unlinked, and no partially
written file is ever reachable by the name the supervisor executes — at any point,
including a crash mid-download, because the only operation that publishes
anything is the final rename of a fully verified file. The refusal is logged
naming version data only, per ADR-0029's rule that a version reject names nothing
account-scoped and is therefore safe to log.

### 4. Restart: the node has a supervisor, the client does not

**Node and coordinator.** Both units carry `Restart=always` with `RestartSec=2`
(`deploy/bacchus-exit.service`, `deploy/bacchus-coordinator.service`). After a
successful rename the process exits cleanly and systemd re-execs the new binary at
the same path two seconds later. There is no self-exec, no double-fork, and no new
privilege: writing to `/usr/local/bin` is already something the unit's `User=root`
can do, so the update path adds no capability the node did not have.

`bacchus-netd` is deliberately **not** `Restart=always` — it is socket-activated
and the unit says so at `deploy/bacchus-netd.service:61`. Its replacement
therefore takes effect on the next socket activation rather than on exit, which
is the correct behaviour for it and needs no special case.

**Client.** `clients/fyne` has no supervisor at all. A desktop application that
silently re-execs itself while a tunnel is up is worse than one that asks, so the
client **stages and verifies unattended and applies at a boundary the user is
already at** — the next start, or on explicit consent while disconnected. The
force case does not need a new prompt: a MAJOR gap already hard-stops
`ListExits`/`Connect` with an actionable "update required" (ADR-0029), so the user
is in front of the application by construction at exactly the moment it matters.

**Never restart mid-session with the kill-switch armed.** ADR-0014's default-block
firewall and ADR-0049's helper lifetime mean a client process that dies while
holding the lockdown leaves a machine that cannot reach the network — the correct
behaviour on a crash, and an unacceptable one to *cause* on purpose. Applying only
at a disconnected boundary avoids the question rather than managing it.

### 5. Reproducible builds: yes for the fleet binaries, a recorded no for the GUI

Per the measurement above:

- **`cmd/node`, `cmd/coordinator` and `cmd/bacchus-netd` ship reproducible.** The
  release build is `-trimpath` with `CGO_ENABLED=0` and a **pinned Go toolchain
  version**, since the toolchain is an input to the output and an unpinned one
  makes the property untestable. `-ldflags -X …core/version.current=` is already
  how the release number is stamped (`core/version/version.go:28`) and is
  deterministic, so it costs nothing here.
- **`clients/fyne` ships not reproducible**, and this record says so plainly rather
  than deferring it. Reproducing it means pinning an entire C toolchain and sysroot
  per target — for Windows, a specific mingw-w64 — which is a different and much
  larger project than pinning a Go version, and one whose failure mode is a
  reproducibility claim that quietly stops holding. It ships with a published hash
  and this channel's signature instead.

**The cost, stated without softening:** an independent rebuilder can verify a node
or coordinator release end-to-end and **cannot** verify the GUI client. The
asymmetry is defensible on exactly one ground, which is the ground ADR-0015 itself
argues from: the catastrophe it names is a *fleet-wide* code push, the fleet is
the nodes, and the node binaries are the pure-Go ones. It is not defensible as
"the client matters less" — the client is the piece that runs on the user's
machine — and it should be revisited when the toolchain pin is cheaper, not
treated as settled forever.

ADR-0044 already paid for part of this in advance: it committed the IP→AS table
rather than fetching it at build time *specifically so the build stays reproducible
for #34/#38*. That decision is what makes the pure-Go half actually reproducible
rather than nominally so, and it is worth naming because it is the kind of
investment that looks like overcaution until the record that depends on it arrives.

### 6. Custody: the root is settled, the update signer is the decision, and the anchor is a one-way door

**The root is not decided here.** `[A1]` settled it: an offline root, generated and
used only in a ceremony, its private half split K-of-N so no single holder can
sign, signing nothing but leaf delegations. No key material from it appears in this
repository, in any fixture, in any example, or in any transcript — the ceremony
tool's own standing rule, and one this record does not relax.

**What #34 adds is an update signing key, and it is not the root.** Its entire
purpose is to be the thing that *can* be revoked and re-minted without a ceremony,
which is what makes the ceremony's rarity affordable. The shape decided here:

- It signs **manifests only**, offline, in the same posture as the policy signer.
- It never sits on a coordinator, never on a build machine, and **CI never holds
  it.** A build machine that can sign is a build machine that can push code to
  every node — which is precisely the compromise ADR-0015 calls the
  highest-value attack surface in the system. Signing is therefore a separate,
  deliberate act performed on artifacts CI produced, not a step inside the
  pipeline that produced them.
- Compromise is survivable without a new client: revoke the serial, mint a new
  delegation, and the fleet's existing verifiers reject the old key. This is the
  whole return on the two-tier structure and the reason the update key must never
  be conflated with the root.

**#38 pulls the other way on automation, and the two are reconciled by which key.**
That issue asks that signing "be part of the release pipeline, not a manual step
someone remembers." That is right for the OS certificates and wrong for this one,
because the blast radii are not comparable: a compromised Authenticode certificate
costs a security interstitial and a revocation; a compromised update key costs the
fleet. So the OS signing credentials may live in a signing service, and the update
key may not.

**The compiled-in anchor is a one-way door, and that is a gate before the build
half.** A client verifies against a root public key baked into its binary.
Replacing that root requires shipping a new binary, and shipping a new binary
requires the channel that root authorizes — so the anchor burned into the first
shipped client **cannot be revised by the mechanism this record describes.**
Which root goes in is consequently an owner decision that must be made *before*
the first binary carrying an anchor is published, not discovered afterwards. This
record states the gate; it does not make the call, and the call is not an
engineering one.

> **Update (2026-08-02):** both gates in this section are now ruled — see the
> amendment at the end of this record (#34). The anchor is **the existing root**
> from bacchus-payment#43, decided and irreversible. The update-key custody call is
> made but **provisional**, and its commitment point is the minting of the `update`
> delegation rather than the shipping of a release. One sentence above is also
> corrected there: replacing the anchor requires the channel that root authorizes
> only for the **automatic** channel, so root loss or rotation costs a manual
> reinstall by every user rather than a permanently unreachable fleet, and the
> decision was made against that number.

### 7. Rollback and failure behaviour

Three distinct failures, and they do not share an answer.

**Verification fails.** The staging file is deleted, the running binary is
untouched, and the refusal is logged naming version data only. There is no retry
storm: the next announcement is the next attempt, and announcements arrive on
traffic that was happening anyway.

**The update applies and the new binary will not start.** Under `Restart=always`
this is a crash loop, which is the worst of the three because at a glance it is
indistinguishable from a healthy restart. The previous binary is therefore kept
alongside (§3 step 4), and **the new binary must prove itself**: a start that
reaches a serving state writes a confirmation marker, and a start that finds an
*unconfirmed* marker left by a previous boot renames the previous binary back and
exits. The second failure demotes instead of looping. This is a watchdog built
from a rename and a file, not a second supervisor — deliberately, because a
supervisor that supervises the supervisor is the kind of component that fails in
its own novel way at the worst time.

**The update applies, the process starts, and it cannot serve.** This is what the
card asks about, and the marker does not catch it, because the process is up. It
is #114's failure exactly: a node on a diverged build registers cleanly,
heartbeats, is assigned work, and silently drops every session while all three
logs report health. **This record does not invent a health signal for it**, and
saying so is the honest answer rather than a gap: automatic rollback on "cannot
serve" is not implementable until "cannot serve" is observable, and making it
observable is #114's problem, not this one's. What #34 owes is not to make it
worse — and it does not, because a bad release is already *containable* with the
machinery ADR-0029 shipped: the operator raises `-min-serving-version` past it and
the fence drains those nodes with live sessions left alone. That is the fence used
as designed, in the one direction it genuinely works.

**Rollback is bounded, and the escape from a bad release is forwards.** A peer
refuses a manifest whose `seq` is below the highest it has verified, and persists
that floor, mirroring `core/policy`'s persisted sequence floor and for the same
reason: a floor held only in memory is reset by anyone who can cause a restart.
An attacker who can serve bytes therefore cannot walk the fleet back onto a burned
release that was once legitimately signed. The operator's remedy for a bad release
is a **new, higher** release — never a replay of an old one — and the demotion in
the paragraph above is a local last resort on one machine, not a fleet operation.

### 8. #38 is a different key, and its deferral is narrower than it looks

The split is not subtle and is worth restating: **#34 is our signature verified by
our own client**, so the fleet only applies releases we authored; **#38 is Apple's
and Microsoft's trust roots verified by the operating system**, so the binary is
permitted to run at all. Different keys, different verifiers, different failure
modes, and neither substitutes for the other. #38's own Linux row says the Linux
half *is* this problem and should reuse this solution rather than duplicate it —
there is no OS trust root to satisfy on Linux, so for the 1.0 scope of Windows
plus Linux desktop, Linux is fully answered by this record.

**Where they genuinely interact:** a signed update that installs a binary the OS
then refuses to run is not a working update path. For Windows, the concrete
interaction is narrower than that sentence suggests. SmartScreen's "Windows
protected your PC" interstitial — whose default action is *Don't run* — is
triggered by Mark-of-the-Web, and MotW is an alternate data stream applied **by
the application that downloaded the file**. A binary staged by an
already-running client and published by `rename(2)` is not marked. So #38's
deferral costs the **first install** an interstitial, which is `#18`'s and
`docs/distribution.md`'s problem, and does **not** block the update path described
here. *(This is the mechanism as documented; it is a claim to confirm on real
Windows during the build half, not one to assume in code.)*

Two things survive the deferral and belong on the record now:

- **Once #38 lands, the artifacts this channel ships must be the signed ones.**
  An update that replaces a signed binary with an unsigned one is a downgrade in
  OS trust, and a channel that could do so silently would be a way to strip
  Authenticode from an installed product.
- **The ordering #38 asks to be settled once rather than twice is settled here:
  sign for the OS first, hash and sign the manifest second.** The manifest
  describes what lands on disk. Hashing before Authenticode signing would make
  every OS-signed release fail its own hash check, which is the kind of ordering
  bug that is obvious in a sentence and invisible in a pipeline.

macOS is outside the 1.0 scope, so Gatekeeper's harder rule — an un-notarized app
is refused outright rather than warned about — does not gate this work. It returns
with ADR-0050, and the ordering above is what it will need.

## Corrections to the card

- **`deploy/install.sh` does not do `install → .new` then `mv`, and no binary in
  the tree is installed that way.** `install_file` is a bare `install -D -m`. The
  temp-plus-`mv` pattern the brief points at is the env file and the `.desktop`
  file. The mechanism is also different from the description: `install(1)` does
  not work around `ETXTBSY`, it avoids it by unlinking the destination — which is
  a non-atomic window this design must not inherit. §3 uses `rename(2)` and
  `core/policy.Cache.writeAtomic` instead.
- **The delegation is not a design question.** `core/delegation.RoleUpdate`, the
  exact-role check, the window, the revocation hook and the root's ability to
  mint an `update` cert all ship today. The new object is the manifest beneath
  them, which narrows §1 of the card considerably.
- **Discovery does not need designing either.** `release` is already stamped in
  both directions and already observed on every client reply, so "how a node and
  a client learn a release exists" is answered by code on `main`.
- **"Reproducible builds — or a recorded decision to ship without them" is a false
  binary.** Measured, it is neither: the fleet binaries are reproducible today
  with one flag, and the GUI cannot be without a C-toolchain pin. §5 records both
  halves rather than choosing one answer for a question that has two.

## Consequences

- **+** The premise the pre-1.0 fleet rollout rests on becomes true: a fix found
  by real devices can reach them.
- **+** The fence stops being a one-way instrument. `-min-serving-version` becomes
  a staging control rather than a kill switch, because the nodes it fences now
  have a path back.
- **+** No new periodic network behaviour on any client, which is the property
  ADR-0018/0022/0032 spend their budget on and the one an update poll would have
  quietly spent.
- **+** The coordinator gains no authority over code. It can withhold, which it
  could already do for the directory, and it cannot substitute.
- **+** Content-addressing makes `docs/distribution.md`'s whole channel union —
  mirrors, Telegram, sideloading — usable for updates without extending trust to
  any of them.
- **+** A compromised update key is recoverable without a new client, because the
  two-tier chain is what the delegation exists for.
- **−** A new signed object class, with a new tag, new frozen vectors and a
  cross-repo conformance obligation this repository cannot discharge alone.
- **−** The GUI client is not reproducible, and an independent rebuilder can
  verify less of the product than of the fleet.
- **−** The update signing key is a new high-value secret with a new custody
  procedure, and the procedure's value is entirely in it being followed.
- **−** "Applied and cannot serve" has no automatic remedy, and the containment
  for it is manual (raise the floor) and depends on someone noticing.
- **−** The compiled-in root anchor becomes irrevocable at first ship. That is
  inherent to compiling in an anchor, not a flaw in this design, but it converts
  an owner decision into a deadline.
- **−** Peer couriering puts release bytes on nodes' disks and through their
  links. Bounded — the bytes are public, signed and identical for everyone, so
  serving them reveals nothing about who asked — but it is bandwidth a volunteer
  did not explicitly sign up for and should be capped.

## Scope: what this record does not decide

- **The minimum-serving-version floor.** That is `[A2]`'s signed policy blob, and
  ADR-0043 already gives its `min_serving_version` precedence over the flag in one
  place. This record delivers the binary; that one sets the floor.
- **Initial installation** (`#18`, shipped) and first-run acquisition
  (`docs/distribution.md`).
- **Which root public key is compiled into the first shipped client.** §6 states
  that the choice is a gate before the build half and that it is not reversible
  afterwards. The choice itself is the owner's.

  > **Update (2026-08-02):** made — the existing root from bacchus-payment#43. See
  > the amendment below.
- **The grace window X**, which ADR-0029 deliberately made operational rather than
  a timer, and which nothing here changes.
- **A health signal for "started but cannot serve"** — #114.
- **The IP→AS table's per-release refresh** (`#66`), which hangs off this channel
  existing and is not built by it.
- **Any Go.** This is the design half of #34; the issue stays open for its build.

## Amendment (2026-08-02, #34) — §6's two gates are ruled: the existing root, and a provisional custody call

§6 named two things it deliberately did not decide — which root public key is
compiled into the first shipped client, and how the update signing key is actually
kept — and said the calls were the owner's. Both were made on 2026-08-02. One is a
one-way door and has been walked through; the other is explicitly provisional, and
is written down here so that it is not lost in conversation.

### Gate 1 — the anchor is the EXISTING root. Decided, and irreversible.

**The client anchors to the root generated in bacchus-payment#43**: a 2026-07-29
genesis with real randomness, a 2-of-3 Shamir split, shares in three physical
locations, one holder. It is the same root the production coordinator already runs
against. **One trust root for policy, admission and updates**, rather than a second
root minted for releases.

The cost is accepted knowingly rather than absorbed quietly: **the root's custody
posture is now permanent.** 2-of-3 with a single holder is what every shipped
client will trust for as long as those clients exist. If this project later gains
people and wants a different threshold or a different holder set, that is not a
change this mechanism can deliver — a different root is a different anchor, and a
different anchor is a different binary.

### The correction to §6's own phrasing, because it changes the size of that cost

§6 says that replacing the anchor *"requires shipping a new binary, and shipping a
new binary requires the channel that root authorizes."* **That is true of the
automatic channel only.** A fresh binary can always be distributed the way the
first one was: a download, an installer, the channel union in
`docs/distribution.md`. Nothing about a compiled-in anchor stops a person from
acquiring a new build through the same route that put the first one on their
machine.

So the real cost of root loss or rotation is **"every user reinstalls by hand"**,
not "the fleet is permanently unreachable". For a population behind a censorship
wall that is expensive — it means running acquisition again, for everyone, at
once, through channels that are hostile by design and were never sized for a
simultaneous re-onboarding of the whole user base. It is not fatal. **The decision
above was made against that number**, not against the larger one §6's sentence
implies, and a gate is not meaningfully ruled unless the cost it is weighed
against is the right one.

The Consequences bullet reading *"the compiled-in root anchor becomes irrevocable
at first ship"* stands, read precisely: irrevocable **through this channel**. It
was never a claim that the software becomes unreplaceable.

### Gate 2 — update-key custody. Ruled, and explicitly PROVISIONAL.

Three decisions, all inside the shape §6 already fixed — manifests only, offline,
never on a coordinator, never on a build machine, never in CI:

- **A single key, not split.** The root is 2-of-3 because losing it is severe;
  losing the update key means minting a new delegation, which is annoying rather
  than severe. That asymmetry is the entire return on the two-tier design, and
  spending it on a threshold scheme would be spending it for nothing. A split that
  must be reconstructed for every release is also a split that gets routed around,
  and a procedure people route around is worse than a simpler one they follow.
- **Its own offline medium, separate from the root shares.** The root shares' security
  property is that they are geographically separated and *rarely handled*. Keeping
  a frequently-used update key beside them means touching root-share media on every
  release, which erodes exactly the property that separation exists to create. Two
  media, two handling frequencies, two blast radii.
- **A five-step release procedure**, written down before it is needed rather than
  improvised under pressure:
  1. CI produces the artifacts. It signs nothing and holds nothing.
  2. The pure-Go fleet binaries are **independently rebuilt** and confirmed
     byte-identical to CI's, per §5's measurement (`-trimpath`, `CGO_ENABLED=0`, a
     pinned toolchain). The GUI cannot be, which §5 records rather than defers, so
     its hash is taken from a single designated build.
  3. The manifest is authored **offline**: hashes, version, sequence number. No
     URLs — §1's "names hashes and never locations" is the decision the rest falls
     out of.
  4. It is signed on the air-gapped machine under the `update` delegation.
  5. The signed manifest is published, and the coordinator announces the release.

  The key never touches a network-connected machine, and **signing is never
  triggered by CI**: it is a deliberate act performed on artifacts CI produced,
  which is the distinction §6 draws and the reason a build machine that can sign
  is the highest-value target in the system.

**This is provisional. The owner asked to be re-asked before it is committed to**,
and it is editable until then. It is a placeholder that has been seen and accepted
as one, not a settled answer.

**The commitment point is when the `update` delegation is MINTED, not when a
release ships, and those are different dates.** The delegation binds one specific
public key. Changing the key after the delegation exists means revoking a serial
and minting a new delegation — affordable by design, and the whole point of the
two-tier structure, but it is **a second air-gapped ceremony rather than an edit**.
Everything else about the shape — which medium, where it lives, who performs the
signing, the five steps — stays editable indefinitely, before and after release.

So the ordering that keeps the question free is: **re-ask the owner, then run the
ceremony that mints the `update` delegation, then let the build half produce its
first signed release.** Minting before re-asking breaks nothing; it converts an
edit into a ceremony. Nothing in the code depends on which way the question goes,
so there is no reason to pay that.

### A prerequisite with lead time that nothing is currently holding

**bacchus-payment#43 records minting a `policy`-role delegation, and no record of
an `update`-role one is visible from here.** The ceremony tool signs all three leaf
roles and `core/delegation` has declared `RoleUpdate` for some time — but the
mechanism existing is not the same as the cert existing.

**Stated as what it is: this is unverifiable from this repository.** The
authoritative record of what the root has signed is owner-side notes, not the
tracker, so the honest form of the claim is *no record visible from here*, not
*it was never minted*. If an `update` delegation exists and was simply not written
down publicly, saying so closes this paragraph and nothing follows from it.

If it does not exist, then **#34's build half needs a second signing ceremony
before it can produce a single signed release**: two shares reconstructed, an
`update`-role delegation cert minted, and that cert independently verified against
the root before any use. That is owner-side, air-gapped, has real lead time, and
**is blocked by no code** — nothing in the build half can substitute for it and
nothing in the build half has to wait to start. It should therefore be scheduled
in parallel with the build rather than discovered at the end of it.

### What this amendment does not change

- **The build half.** #34 stays open; this record is still the design half only.
- **Any key material**, which appears nowhere in this repository, in any fixture or
  in any transcript, and does not start appearing now.
- **§5's reproducibility split, §7's failure behaviour, or anything about the
  manifest**, none of which either gate touched.
