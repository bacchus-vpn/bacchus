# 67. A client that survives its coordinator: a link that stops carrying is rebuilt, on a fresh socket, and says so

- Status: accepted
- Date: 2026-08-08
- Tracking: issue #225
- Builds on: ADR-0062 / issue #175 (the shaped rendezvous hop this condition lives
  inside), ADR-0059 (the association's two ends), ADR-0057 / issue #183 and issue #5
  (the two earlier local faults that were reported as an unreachable network, whose
  argument this reuses verbatim), ADR-0030 / issue #2 (retry-forever, which is what
  made "never" survivable enough to go unnoticed), ADR-0037 / issue #31 (mesh-walk,
  the recovery that exists for this silence and cannot help it), ADR-0064 / issue #205
  (the deploy ordering that guarantees this state on every run), ADR-0053 (one link,
  both roles)
- Implementation: `core/coordpool.go` (`coordLink.relink`, `heardN`, `transport`,
  `holdsAssociation`, `noteLinkStale`), `core/client.go`
  (`Engine.relinkIfStale`, `ErrCoordinatorLinkStale`, the silent branches of
  `establish` and `ListCountries`, `reconnect`'s streak), `core/rendezvous_client.go`
  (two corrected comments), `core/link_recovery_test.go` (new)

## Context

**A client whose coordinator restarts underneath it never reconnects.** Not slowly —
never, until a person restarts the process, and nothing tells them to.

Measured on the testbed, 2026-08-08, on `7fbca67`: a volunteer node emitted **112
consecutive** `reconnect attempt N failed (core: no coordinator reachable)` over
**100 minutes**, consuming **1.6 seconds of CPU in 1h39m** — idle, not spinning, not
backing off into a wall, waiting on a link it never rebuilt. Throughout that window,
from the *same box*, with the *same deployed binary* and the *same release stamp*,
against the *same running coordinator*: a plain `-role client` connected in under a
second, `-role client -volunteer-relay` connected in under a second, and a plain
`systemctl restart` of the failing service itself registered exit and relay and
connected in under a second. The coordinator logged **nothing at all** from that
source for the whole hundred minutes, then logged its registration one second after
the restart.

So it was not the vantage, not the flags, not the release stamp, not the shaped
rendezvous hop, and not the coordinator. Only the already-running link.

### Why the link cannot notice

Since ADR-0062 a client's coordinator link is a DTLS association on a connected UDP
socket. When the coordinator process restarts, its association table is empty. Its mux
will not create an association for a record that is not a handshake — deliberately, so
a spoofed source cannot mint one without the cookie exchange — so every record the
running client sends is dropped on arrival. On the client's side there is **no error
of any kind**: a UDP send into a dead association is a local success, forever. The
send succeeds, the reply never comes, and the member reads as blocked.

`shapedLink` already had one mechanism for exactly this — `rendezvousAssocIdle`,
which retires an association after three minutes so the next send handshakes afresh.
It could not fire, and the reason is the finding. The clock it reads, `lastUsed`, is
stamped by every **send**, and by `establish` itself before it hands the association
back. It therefore retires an association nobody is talking through, and only that. On
the box in question a reconnect every ~53 seconds and a volunteer's register every 10
seconds kept the three-minute threshold permanently out of reach: **the harder the
client tried to recover, the further away recovery moved.**

### Why nothing else caught it either

- **Rotation could not.** The pool had one member. Even with several, each member's
  link wedges independently and rotation only reorders them; a second coordinator
  would have masked this incident, not fixed the defect.
- **Mesh-walk could not**, and this is structural rather than a configuration
  accident. `-mesh-peers` is opt-in and no testbed node sets it, so recovery was never
  armed — but had it been, `tryMeshRecovery` refuses a directory naming the
  coordinators already configured (`sameCoordSet`), and the coordinator's address
  never changed. Mesh-walk rediscovers coordinator **addresses**. The address was
  never in doubt.
- **No test could.** Nothing in this repository had ever taken a coordinator away
  from a live client. Every fixture either starts a coordinator and leaves it up, or
  drops both ends at once.

### Why the message is part of the bug

`coordpool.go`'s own comment on `refusedForSize` calls `no coordinator reachable`
*"the sentence a user on a censored network will believe and report"*, and was written
to stop a local fault wearing it. This is a local fault wearing it, from a third
cause, printed 112 times. A user must be able to tell *the link I held is gone* from
*nothing is reachable*: the second is a reason to change networks and the first is
not.

### Why this is not only a client outage

A volunteer's serve-side registration rides its **client** link — one process, one
coordinator connection, and the client role is what shapes it (a link cannot be half
shaped). So the same moment stripped the box of its exit and its relay, and the
coordinator did not notice anything: it simply never heard from it again. Capacity
left the pool silently, with nothing logged anywhere.

And the deploy pin guarantees the condition on **every** run. ADR-0064 restarts the
coordinator last, deliberately, to empty the registry; the side effect is that every
node is brought up against the outgoing coordinator and then has it removed a second
later.

## Decisions

### 1. Recovery is driven by evidence a leg already has, not by a clock

A link is rebuilt when **both** of these hold at the end of a connect pass:

- the link **held** a completed association when the pass began, and
- the pass heard **nothing at all** back through it.

Neither alone is enough, and the reasons are different.

*Held* says there was something to go stale. A link with no association is not holding
anything; its silence belongs to the member, the recovery is rotation, and rebuilding
the socket would answer a reachability problem with a local one. This is also what
keeps the mechanism out of a role it was not designed for: a pure forwarder's link is
cleartext and holds no association at all.

*Heard nothing* says the association is not carrying. The counter is deliberately
indiscriminate — a countries reply, a refusal, a stray assign, even a message this
build cannot route all count. The question is not "did this member cooperate" but "is
this link still a link", and for that any byte off the far end is proof and none is
absence.

The alternative — re-point `rendezvousAssocIdle` at a *last heard* clock — was
considered and rejected. Hearing nothing is the **normal** state of a healthy link:
the coordinator answers `list`, `connect` and `challenge`, and answers neither `hello`
nor `register`. A volunteer that is merely registering hears nothing from a
coordinator that is perfectly well, so a silence-driven clock would churn every
healthy forwarder's association forever.

### 2. A rebuild is a fresh SOCKET, not a fresh association

This is the load-bearing decision and it was settled by measurement, not preference.

A re-handshake on the same 5-tuple is **swallowed** whenever the far end still holds
the old association: a coordinator's mux finds the source in its table before it looks
at the record type, so the `ClientHello` is delivered into the very conversation it is
trying to replace. Worse, every datagram from that source refreshes the entry's idle
clock, so a client retrying in place holds its own wedge open indefinitely — it would
have converted this bug into a second, self-inflicted one.

Measured against the same stand-in coordinator: recovering in place drew **nothing in
ten seconds and twenty-three attempts**; a fresh socket connected on the **first**.

A new source port is not a new condition for a coordinator. Its `register` and
`heartbeat` handlers both re-learn a node's observed address on every message, for the
case they name themselves — *"a node whose address changes under it, a NAT rebinding,
a new uplink"* — so a rebuilt link presents as something that already happens and a
forwarder's registry entry follows it within one heartbeat (ten seconds). That window
is the only cost: a session assigned to a node inside it is pushed to the port the
node has just left. It is the cost a NAT rebinding already carries.

The old socket is **closed** as part of the rebuild, and that is mandatory rather than
tidy. A shaped transport's `Close` does not touch the socket — `coordLink` owns it —
so its reader goroutine stays parked on it, and a rebuilt link sharing a socket with
the reader of the link it replaced has two goroutines stealing each other's datagrams.
Measured while building this: a rebuild that kept the socket lost roughly every other
reply and recovered nothing, which reads exactly like the wedge it was meant to clear.

### 3. This is not a wire change, and the ruling that forbade one is not strained

Nothing about any message changes: not a field, not a type, not a value, not the order
of the connectivity check and the handshake. What changes is which socket the same
bytes leave from — which is precisely what the `systemctl restart` that recovered this
on hardware already did, once, for the whole process. This change does it per link,
without the process.

### 4. The bound, stated in passes rather than seconds

**One failed connect pass plus the next.** The wedge is diagnosed at the end of the
pass that found it, the link is rebuilt there, and the following pass runs on a fresh
association.

With the shipped ladder that is at most a 12-second direct leg plus an 18-second relay
leg, plus one backoff step capped at 15 seconds, plus a 3-second handshake — **under
50 seconds worst case**, and around 13 in the common shape where the direct leg is the
one that times out. The bound is expressed in passes because the seconds are the
ladder's, not this mechanism's, and will move when the ladder does.

**Attempts are unbounded**, unchanged: `reconnectMaxAttempts` stays 0 and ADR-0030's
retry-forever is untouched. A link that wedges again is rebuilt again, once per pass.

### 5. The user is told which thing broke

`ErrCoordinatorLinkStale` joins `ErrCoordinatorUnroutable` (issue #5) and
`ErrRequestTooLarge` (issue #183) as a **local** fact that would otherwise reach a
waiting leg as nothing-happened and be reported as an unreachable network. Three
instances of one shape now, which is enough to call it the shape.

It is returned only when **every** silent member was silent behind a link this client
held — a pass in which one member wedged and another was genuinely unreachable is
still the second thing.

It deliberately does **not** wrap `ErrNoCoordinatorReachable`, for that sentinel's own
stated reason: it triggers mesh-walk, mesh-walk rediscovers addresses, and this
address was never in doubt.

The event says so in words, at the point of rebuild: that this is a local fault, that
it is *not* the network and *not* a blocked coordinator, that its ordinary cause is a
coordinator restarting underneath a running client, and that a coordinator which is
genuinely unreachable will say so on the next attempt.

### 6. Mesh-walk keeps its trigger

A stale-link pass **neither counts toward nor resets** the consecutive-silence streak
that fires mesh-walk. It is not evidence that rendezvous is down (a courier would name
the same coordinator, and `sameCoordSet` would refuse the rebuild), and it is not
evidence that rendezvous is up — so zeroing a streak a genuine outage had built would
let a wedging link postpone the recovery of a client whose coordinators really had
moved.

The classification is self-limiting, which is what makes that safe. A link can only be
called stale if it **held** a completed association, so a coordinator that is genuinely
gone produces the verdict at most once: the rebuild's handshake finds nobody, the link
holds nothing, and every pass after that is ordinary silence again.

### 7. One member versus several

Unchanged, because the mechanism is per link. Each member's link is judged on its own
evidence and rebuilt on its own socket; rotation and the 30-second health cooldown
continue to order them. A stale member is still marked unhealthy — it is unusable
through the link this client has until the rebuilt one has been tried, and health
memory only reorders the next rotation. What the two kinds of silence must not share
is the **error**, because that is what decides whether the log implicates the network.

With a pool of one — every deployment today — rebuilding is the *only* recovery there
is, which is why "rotate to another member" was never going to be the answer.

## Consequences

- A coordinator restart costs its attached clients one failed pass instead of the rest
  of the process's life, and costs a volunteer's exit and relay the same, with no user
  action and nothing to notice.
- A rebuild that was not needed costs one DTLS handshake and a changed source port.
  The asymmetry is deliberate: a false positive costs a handshake, a false negative
  costs what was measured. A coordinator that is up, still holds this client's
  association, and merely drops its replies will therefore have its link rebuilt —
  and, because the rebuild moves the socket, will be reached anyway.
- `deploy/bacchus-pin.sh`'s restart-coordinator-last ordering (ADR-0064) no longer
  strands the fleet it has just deployed. Whether that ordering should change is a
  separate question this record does not settle; it is simply no longer load-bearing
  for availability.
- One shared assumption is now written down twice rather than once: the two corrected
  comments in `core/rendezvous_client.go` said an association that died is retried on
  the next send, which is true only of one that failed a **write**.

## Residual

**A link that carries only registers still has no liveness signal, and cannot be given
one from this side.** The recovery above is driven by a client leg, so it covers a
volunteer that is attempting to connect — which is the measured incident, and the
state a volunteer is in whenever it is not in a session. It does not cover a volunteer
sitting in a **healthy session** when its coordinator restarts: its client half has
nothing to ask, its registers go out every ten seconds into nothing, and a coordinator
answers a register only to reject it. The registrations come back when that session
eventually drops and the client half attempts again — bounded by the session's
lifetime, which can be hours, rather than permanent.

Closing it needs one of two things, and neither belongs to this change: an
acknowledged register or a heartbeat reply (a coordinator-side change, and a wire
change, which issue #212's freeze forbids), or new periodic client-initiated traffic
(a new externally visible behaviour for a censorship-resistant client, which is not a
decision to make in passing). Filed as a follow-up rather than guessed at here.

**A same-5-tuple re-handshake remains unreachable while the far end holds an
association.** This change routes around that rather than fixing it, and the
underlying interaction — ADR-0062's residual — is unchanged. It is now much less
likely to be hit, because the one path that used to re-handshake in place no longer
does.

**Loopback proves the mechanism, not the deployment.** Every test here runs on
loopback, and ADR-0057's lesson about loopback's 65536-byte MTU applies to its other
properties too: no NAT, no path, no censor. What these tests can show is that the
client detects the condition and comes back through it; that a rebuilt link's new
source port survives a real NAT in front of a real coordinator is the testbed's to
confirm, and the natural time to confirm it is the next deploy — which produces this
exact condition by construction.
