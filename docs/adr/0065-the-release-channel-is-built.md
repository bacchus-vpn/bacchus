# 65. The release channel is built: the transport is a seam, the client fetches inside its own tunnel, and the apply is a rename

- Status: accepted
- Date: 2026-08-08

## Context

ADR-0052 designed the signed release channel and said so in its own closing
line: *"Any Go. This is the design half of #34; the issue stays open for its
build."* This is the build half. Everything ADR-0052 decided stands; this record
extends it, corrects two claims in it that the code does not support, and rules
the one question the design left implementable in more than one way.

The card's own sentence for why it blocks 1.0: **a fence without a channel is a
kill switch, not a repair tool.** ADR-0029 shipped the fence — the `release` wire
field, `-min-serving-version`, the force-major client cutover — and nothing
delivered the build that would bring a fenced node back.

The owner ruled on 2026-08-08 that this lands as **one unit, sign through apply**,
rather than shipping the verifier and leaving the delivery path for later. The
ground was that the fence-without-a-channel state costs more than the open fetch
question does.

## What ADR-0052 already settled, and is not re-argued here

- **The anchor is the existing bacchus-payment#43 root.** Decided, irreversible,
  and not this record's to revisit.
- **The manifest names hashes and never locations.** Everything below falls out of
  it.
- **Update-key custody**: a single key, its own offline medium, never on a
  coordinator, never on a build machine, never in CI. Provisional, and its
  commitment point is the minting of the `update` delegation.
- **Reproducibility splits**: the pure-Go fleet binaries are reproducible, the GUI
  is not, and that is a recorded no rather than a deferral.
- **Failure behaviour**: verification failure deletes the staging file, an applied
  release that will not start is demoted by a marker, and "applied, started, and
  cannot serve" has no automatic remedy because #114 has not made it observable.

## Two corrections to ADR-0052, because they change what could be built

**1. A node does not learn a release from the reply to its register, because there
is no reply.** ADR-0052 §2 states that a node "learns from the reply to a register
it was already sending every ten seconds", and that is what made the node's
announcement free. On `main` it is not so: the coordinator's `register` handler
answers only on a REJECT — a fenced node, a failed admission, a coordinator with
no enforceable policy — and the success path sends nothing at all. `Release` is
stamped on the CLIENT replies (`countries`, `session`, `error`, `challenge`), and
`Engine.observeNetworkVersion` runs only for an engine that has a client role.

A pure forwarder therefore has no announcement to be edge-triggered by — and a
pure forwarder is precisely the node this channel exists to repair, because a
fenced one is by construction the one running the burned release. §3 below is what
that correction decides.

**2. `cmd/bacchus-netd` carries no release stamp, and the linker does not say so.**
`go list -deps ./cmd/bacchus-netd` does not contain `core/version`, so
`-ldflags -X …core/version.current=` names a symbol that binary has no reference
to, and the flag is **ignored silently, with a zero exit** — the same class of
failure ci.yml's release-stamp job already exists to catch for the others. It
changes nothing about whether netd can be UPDATED (it can; it is a socket-activated
unit and its replacement takes effect on the next activation), but a release build
that asserted a stamp for it would refuse every release, and one that asserted none
would be blind. §7 makes the assertion derive from the dependency rather than from
a list.

## The question this record exists to answer

The card says delivery *"must not become a fingerprintable network fetch"* and
*"must not require the coordinator to be trusted with code"*. ADR-0052 §2 answered
the first with three properties — no period, no new endpoint, no new flow — and
the second with *"carrying is not authorizing"*. Both hold. What §2 did not settle
is **which concrete transport carries the manifest and the bytes**, and its own
sketch (the manifest requested "over the connection it already has", artifacts
couriered by a peer generalizing ADR-0037) is not buildable today: `#212` blocks
all rendezvous work, which fences `core/client.go`, `core/coordpool.go`,
`core/rendezvous/` and the `challenge`/`connect` handlers — every file that leg
would live in.

That block is what forced the question to be asked properly rather than answered
by whichever file was easiest to edit. The answer below is not a workaround for it.

## Decision

### 1. The transport is a SEAM, not a decision — `core/update.Source`

A `Source` has two methods: fetch the manifest bundle, open an artifact by its
digest. Two implementations ship — a local directory and an https base URL — and
**nothing in the package prefers one**.

This is the direct consequence of ADR-0052 §1. A manifest that names hashes and
never locations makes the fetch path not part of the trust object; making it an
interface is the same statement in code. The alternative — a fetch written into
the updater — would have made whichever source shipped first into the trusted one
by accident, which is exactly what content addressing exists to prevent.

The layout is a convention and not a contract: `<root>/manifest.json` and
`<root>/blobs/<sha256 hex>`. A mirror holding several releases needs no
per-release directory, and a blob two releases share is stored once. Every URL in
this repository is a placeholder or a configured value; no host is named anywhere.

### 2. The manifest is fetched from the same untrusted source as the bytes, NOT over the coordinator connection

ADR-0052 §2 put the manifest request on the existing coordinator connection. This
record moves it to the source, for two reasons, and the second is the durable one.

- **`#212` fences that path this wave.** True, and on its own only a reason to
  wait.
- **A self-authenticating manifest needs no privileged carrier at all.** The
  bundle is root → delegation → signature; verifying it uses nothing but the
  anchor the binary already carries. Putting it on the control connection would
  make the coordinator the REQUIRED carrier for patching — which is precisely the
  residual ADR-0052 §2 names about its own design, that a lying coordinator can
  **withhold**. Fetching it from the same untrusted place as the bytes leaves the
  coordinator holding nothing but the announcement.

So the split is: **the coordinator announces, and carries nothing.** The
announcement is free and already shipped (a `release` field on a reply the peer
was already receiving; `core.Engine.NetworkRelease` is added only so an embedder
can read it as a version rather than out of a formatted event line). The bytes and
the manifest both come from somewhere untrusted.

This survives the card's sentence with room to spare. A coordinator that lies can
announce a release that does not exist, costing a wasted manifest fetch, or
withhold one that does, which it could already do for the directory. It cannot
substitute a release, and unlike in ADR-0052 §2's shape it cannot even withhold
the manifest, because it never had it.

### 3. The node polls; the client is edge-triggered and never polls

**A node checks its configured source on an interval** (default six hours). Two
grounds, and both are needed:

- ADR-0052 §2 already rules that a node's fetch "is not covert in the way a
  client's must be": a node is infrastructure, it registers every ten seconds, it
  is listed in a signed directory clients dial, and its address is public by
  construction. The anti-fingerprinting constraint on this card is a CLIENT
  constraint.
- Per the correction above, **nothing tells a forwarder**. An interval needs no
  other lane's file, and it is independently better in the case that matters: a
  node that every coordinator has fenced, or that can reach none of them, can
  still learn a release exists and fix itself. A node whose repair path runs
  through the party that fenced it is a repair path that fails exactly when it is
  needed.

**A client never polls.** Its trigger is the release string the coordinator
already stamps, read out of memory. The watcher's ticker touches two in-process
values and reaches the network only when the announcement CHANGED, is newer than
this build, and the gate in §4 is open. There is no interval to measure because
there is no interval.

### 4. The client fetches ONLY through its own tunnel

The gate is "a tunnel is up", checked before a byte moves. A refusal is not a
fetch that fails; it is no fetch — and the announcement is deliberately not
recorded as seen, so the first check after the tunnel comes up reconsiders it.

The mechanism this rests on is `clients/internal/enforcement`: the full-device
tunnel excludes a FIXED set of control-plane addresses from the split-default
route (the coordinator pool, STUN/TURN, and per-dial reality underlay addresses)
and nothing else. A fetch to any other destination therefore egresses at the
exit — bytes in a session, indistinguishable from the browsing the session exists
to carry. The same fetch made while disconnected would be a distinctive,
well-timed request from the client's own address, on the censor's side of the
tunnel. **That is the fingerprintable fetch the card forbids, and refusing to make
it is one `if`.**

This is what makes the answer to the fetch question stronger than "we used TLS".
`#175`'s record is what happens when a client network behaviour is designed
without asking what it looks like on the wire; the answer here is that on the
client's own link there is nothing new to look at.

**The one case this leaves, stated rather than hidden.** A client that is
force-majored (ADR-0029 hard-stops `ListExits`/`Connect` on a MAJOR gap) cannot
bring a tunnel up, so it cannot fetch under this rule. It is not a deadlock,
because the acquisition path that put the client on the machine is still there
(`docs/distribution.md`) and ADR-0052's own amendment prices exactly this: root
loss costs "every user reinstalls by hand", and a major cutover costs no more. An
out-of-tunnel fetch on explicit user action would close it and is deliberately NOT
built here: it is a network behaviour, and this record will not add one on the
strength of a case that is already covered by a route that exists.

### 5. Apply is verify-first, whole-file, and published by one rename

The sequence, on node and client alike, and every step is ADR-0052 §3's:

1. download to a staging file **in the same directory as the target**, named by
   the artifact's digest;
2. **re-read that file and hash it complete** — not the stream as it arrives, and
   never incrementally into the live path;
3. `chmod`, `Sync`, close;
4. write the confirmation marker;
5. rename the current binary aside to `<target>.prev`, kept;
6. one `rename(2)` publishes the staged file.

**Nothing works around `ETXTBSY` because nothing ever writes to the running
path.** The running process keeps the inode it was started from. The same order is
also the only order that can work on Windows, for an unrelated reason: a running
`.exe` may be renamed but may not be replaced or deleted, so moving it aside first
is not an optimisation there.

Hashing the file rather than the stream is worth its second pass over 20 MB:
hashing the stream proves the bytes were right on the way past and proves nothing
about the bytes on the disk.

**A refusal at any tier leaves the target untouched, and that is structural rather
than careful.** The only operation in the package that touches the target is the
apply, and it runs last. The test suite asserts it **on bytes** — the target still
holds exactly the running binary, and no staging file is left in its directory —
for a corrupted artifact, a truncated one, an oversized one, an unsigned manifest,
one signed by the wrong key, one delegated by an untrusted root, and a staging
file tampered with after it was verified. One test holds an open descriptor across
an apply and asserts it still reads the OLD bytes, which is the same claim measured
instead of described.

### 6. Rollback: a marker, a kept binary, and a floor that persists

Three failures, three answers, and they are ADR-0052 §7's.

**The release does not verify.** Staging file deleted, running binary untouched,
refusal logged naming version data only. No retry storm: the next announcement is
the next attempt.

**It applies and the new binary starts but never works.** The apply wrote a
marker; a start that reaches a working state clears it; a start that FINDS one
renames the previous binary back and exits so the supervisor re-execs it. For a
node, "reaches a working state" is operationalised as **still running a minute
later**, which is what a crash loop under `RestartSec=2` cannot produce. It is not
a claim that the node can serve.

**It applies and the process cannot start at all** — a corrupt file that verified
because it was signed corrupt, a wrong architecture, a missing loader. **Nothing
in the process can catch this, because the process never starts.** The previous
binary is kept beside the target so recovery is one rename, and a supervisor-side
check is what would automate it. That belongs in `deploy/`, which this lane does
not own; the need is stated in the pull request rather than the file being added.

**It applies, starts, and cannot serve.** #114's shape. The marker does not catch
it and this record does not invent a health signal for it either, for ADR-0052
§7's reason: automatic rollback on "cannot serve" is not implementable until
"cannot serve" is observable. The containment is the fence used as designed —
raise the floor past the bad release — and the escape is forwards.

**Rollback is bounded by a persisted sequence floor.** A manifest below the highest
seq ever accepted is refused, and the floor is on disk, mirroring `core/policy`'s
and for the same reason: a floor held only in memory is reset by anyone who can
cause a restart. The floor ratchets on any manifest that VERIFIES, including one
that carries no artifact for this build — a release this peer cannot use still
establishes that the generation exists.

### 7. Reproducible builds: the claim becomes something CI refuses to ship without

ADR-0052 §5 measured reproducibility and decided it; nothing enforced it. The
release workflow now builds each fleet binary **twice, from two different source
paths**, and refuses the release if any pair differs.

Building twice rather than trusting the flags is the point. A reproducibility
claim whose only evidence is that `-trimpath` was passed stops holding the first
time a dependency embeds a path, a date or a hostname, and nothing says so. The
property is that an INDEPENDENT rebuilder can confirm a release; a build that
cannot reproduce itself on one machine will not reproduce on theirs.

`clients/fyne` is absent from that check and present in the artifact rows, exactly
as ADR-0052 §5 records: it needs cgo, reproducing it means pinning a whole
mingw-w64 sysroot, and its hash is taken from one designated build.

**CI produces rows and signs nothing.** `artifacts.json` — os, arch, role, size,
sha256 — is the entire handover to the ceremony, and `cmd/release-sign` consumes
it offline. A test asserts CI holds no key material, looking for the KEY rather
than for the word "sign", because nothing can sign without the private half and a
release note naming the tool is not a risk.

### 8. This stops at the ceremony

No release can be signed until an `update`-role delegation exists, and ADR-0052's
amendment records that no such delegation is visible from this repository. That is
owner-side, air-gapped, and blocked by no code here.

So the anchor is a **slot**: `core/update.rootPubHex`, stamped at link time
exactly as `core/version.current` is, EMPTY in source. A build with no anchor
refuses to apply any release and says so rather than being silently inert.
`AnchorFingerprint` exists so the stamp can be read back out of a built binary,
because a `-X` naming a symbol that does not exist is ignored silently — see the
second correction above, which is that same failure happening for real.

`cmd/release-sign keygen` produces the update key and prints the public half the
ceremony delegates to; `sign` refuses a delegation that is not live for the update
role against the named root, or that delegates to a different key than the one
signing. Both are mistakes that would otherwise produce a perfectly formed release
that the entire fleet refuses, discovered after the ceremony and by the fleet.

## Alternatives rejected

- **A URL inside the signed manifest.** ADR-0052 §1, settled: it would make the
  fetch path part of the trust object and hand whoever serves it a lever over a
  fleet that had cryptographically committed to asking.
- **The manifest over the coordinator connection** (ADR-0052 §2's own leg).
  Rejected on the merits in §2 above, not only because `#212` fences it: it makes
  the coordinator a required participant in patching, and a self-authenticating
  object does not need one.
- **A periodic poll from the client.** The fingerprint. This is the whole reason
  the announcement rides traffic that was happening anyway.
- **An automatic out-of-tunnel fetch from the client.** Same reason, and it would
  have been the easy way to close §4's force-major case. It is closed by an
  acquisition route that already exists instead.
- **Cleartext http to a remote source.** Integrity does not need TLS here — the
  bytes are signed and content-addressed — but a cleartext GET names the exact
  release being fetched to anyone on the path. Refused in code; loopback is
  exempt, decided from the parsed host rather than a prefix of the string.
- **A version in the fetch's User-Agent.** It would hand whoever runs a mirror a
  fleet inventory, on every check, by the mechanism whose purpose is to fix nodes
  that are behind. The constant carries no version.
- **Peer couriering** (ADR-0037 generalized, ADR-0052 §2's default source).
  Deferred, not rejected: it needs a new wire message on files `#212` fences, and
  the `Source` seam is exactly where it lands. Nothing about it changes anything
  above.
- **Signing in CI.** ADR-0052 §6, and now guarded by a test.
- **Re-exec on the client after an apply.** The release takes effect at the next
  launch instead. One extra launch in the worst case, against a class of bug — a
  GUI restarting itself while a kill-switch may be armed — this project does not
  need to own.

## Consequences

- **+** The premise the pre-1.0 fleet rollout rests on becomes true: a fix found by
  real devices can reach them, and a fenced node has a path back.
- **+** The coordinator gains no authority over code, and less involvement than
  ADR-0052 §2's shape gave it: it announces, and carries nothing.
- **+** No new periodic behaviour on any client, and no new observable surface on a
  client's own link at all.
- **+** Reproducibility stops being a claim and becomes a gate a release cannot get
  past.
- **+** The rename-only apply means no state exists in which the executed path
  holds unverified or partial bytes — asserted on bytes, including through an open
  descriptor across the apply.
- **−** A node polls, which is a periodic fetch that did not exist before. Bounded:
  it is a node, its address is already public, the interval is configurable and the
  request is a few hundred bytes when nothing has changed.
- **−** A force-majored client cannot use the automatic path, and reinstalls by
  hand.
- **−** "Applied and cannot serve" still has no automatic remedy, and "cannot start
  at all" has none IN THIS PROCESS — the demotion needs a supervisor-side check
  that lives in `deploy/`.
- **−** The Windows client's artifact row is taken from a staged path owned by
  `deploy/windows/build-bundle.ps1`. A coupling, read rather than recomputed, and
  it fails loudly with a sentence naming itself.
- **−** Nothing here can be live until the `update` delegation is minted, which is
  an air-gapped ceremony with real lead time.

## What this record does not decide

- **The minimum-serving-version floor** — `[A2]`'s signed policy blob.
- **Initial installation** (`#18`, `#144`) and first-run acquisition.
- **`#176`'s transport-version fence**, whose own note says declining to match
  becomes a flag flip once `#34` lands. The flip is a separate card.
- **A health signal for "started but cannot serve"** — `#114`.
- **Which root public key is stamped into the first shipped binary.** ADR-0052 §6
  ruled it (the existing root) and this record only provides the slot.
- **The update key's custody**, which ADR-0052's amendment holds provisional until
  the owner is re-asked, before the delegation is minted.
