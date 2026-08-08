# 61. The desktop client learns that addresses move

- Status: accepted (issues #193, #201; closes #174)
- Date: 2026-08-07
- Builds on: ADR-0016 in `bacchus-payment` (the account service's address will change),
  ADR-0037 (mesh-walk recovery via signed peer exchange), ADR-0039 (the Fyne client),
  ADR-0056 (the client enrolls)

> Per-repo numbering: `bacchus-payment`'s ADR-0016 is unrelated to anything this
> repository numbers the same.

## Context

### Every address this client dials was a constant

`clients/fyne` held its coordinator pool, its STUN and TURN endpoints and its account
service address as static strings in one JSON file, and had **no mechanism of any kind
for learning that any of them had changed**. Not a fallback that was rarely exercised —
no mechanism.

That is affordable right up until an address moves. Two of them are known to:

- **The account service.** It runs on anonymously rented infrastructure and its address
  *will* change (ADR-0016, from the owner on 2026-08-05). Because a device renews as soon
  as it enters its renewal margin, no device with a reachable service is ever sitting
  inside that margin — so a service unreachable at *T* takes the first devices offline at
  *T* + ~6 h and the last at *T* + 48 h. `DefaultCredentialTTL` 48 h,
  `defaultDeviceRenewMargin` 6 h, `NeedsRenewal` at `exp − margin`: **a device renews
  every 42 h and the outage budget is the 6 h of margin, not the 42.**
- **A coordinator.** Worse, and it is the half `#174` did not ask about: a moved
  coordinator takes the client offline *immediately* rather than in six hours.

### The mechanism was built, verified, and adopted by nobody under `clients/`

`core/coldstart` has carried all of it since `#18`: a coordinator signs a `Snapshot` of
entry points with a validity window, `Verify` splits signature from freshness,
`AddrsForRole` answers with a **list**, and the type's own doc records that a snapshot
*"carries no secret"*. `cmd/node` uses it. Nothing under `clients/` imported the package
or set `MeshPeers`, `MeshProof` or `MeshPubKey`.

### The finding that changed the card's scope

`#193` asked the client to *adopt* the signed directory. **The client had no way to
obtain one.** `coldstart.Bootstrap` needs a per-user invite secret; `FetchSnapshot` needs
a prior snapshot as proof of contact; `clients/fyne` had no field for either.
`DecodeInvite`'s only callers were `cmd/coldstart-bootstrap` and `cmd/node/courier.go`.
Adopting a directory that never arrives would have closed the card having changed
nothing.

## Decisions

### 1. The desktop client consumes a `bacchus1:` invite

Owner ruling A1, 2026-08-07. Everything server-side already exists:
`cmd/coldstart-issue` mints invites, `coldstart.DecodeInvite` parses them, the
coordinator serves the fetch on `-turn-addr` through `coldstart.Demux`, and the invite
carries the bootstrap address, the secret id, the secret and the snapshot-signing public
key.

So `Config` gains one optional key, `invite`. With one, the client fetches, verifies and
caches the directory; without one it is exactly the client it was, which is what every
install in the field is running.

The alternative considered and declined (option A3) was a new signaling verb carrying the
directory on an existing datagram. The snapshot is 674 B for the live fleet and 1369 B at
eight nodes, against ADR-0057's 1232-byte budget — **it would work on the testbed and
break silently as the fleet grew**, which is precisely the class of defect this project
keeps finding.

### 2. The price, stated: a new install needs TWO out-of-band strings, not one

An invite is **per-recipient and never ships inside an installer or a config template.**

`coldstart.LoadMemStore`'s own doc records that a coordinator's bootstrap secrets file
has no vouch or trust system under it — *"every entry here is trusted equally."* A secret
embedded in a downloadable artifact is therefore a secret the censor holds, and holding
it is enough to fetch the directory of every entry point in the network.

So the accepted cost is that provisioning a device now takes an invite **alongside** the
claim code. The shipped template carries `"invite": ""`, which is a slot rather than a
credential, and `TestTheTemplateShipsNoInvite` fails the build if that ever stops being
true.

### 3. The coordinator gap closes in the same change, not a follow-up card

`#193`'s own "done when" asks for it and ADR-0016 decision 4 says why. One mechanism
answers both roles: the client reads `AddrsForRole("coordinator")` out of the same
verified snapshot it reads the account service from, and the result is what
`core.Config.Coordinators` **and** `enforcement.Policy.Coordinators` are built from.

Both, not one. The kill-switch allows the coordinator addresses through the lockdown, so
a policy built from the config while the engine dials the directory's addresses would
block the one socket the session depends on — the tunnel would come up and the client
would be unable to reach the coordinator that arranged it.

### 4. The account service's list REPLACES; the coordinator list is LED

ADR-0016 decision 4 says *"the directory's list wins; the configured list is the seed."*
Applied literally to both roles that is wrong for one of them, and the reason is a
property of the producer rather than a hedge.

`cmd/coordinator`'s `buildSnapshot` puts exactly **one** coordinator entry in a snapshot —
its own advertised address — because a coordinator has nothing to say about its peers.
There is no peer-coordinator flag and no gossip. So a directory that replaced
`Config.Coordinators` would narrow an operator's three-coordinator pool down to whichever
one happened to sign the snapshot the client fetched: **redundancy deleted by a
client-side change nobody asked for.** What the directory contributes for that role is
therefore *precedence* — its address is dialled first, the configured ones stay behind
it, and `core/coordpool.go`'s healthy-first ranking with a cooldown costs a dead address
a single attempt.

The account service has no such limit. One repeatable coordinator flag states the whole
list, so what arrives is a complete answer and replacing is right — and necessary,
because the configured address is precisely the one that goes stale, and merging would
leave every client permanently re-trying the address the operator moved away from.

Two consequences of that asymmetry:

- **The `-account-service` flag is repeatable.** A single-address flag would have deleted
  the planned-move redundancy `#192` had just shipped, from every client that adopted the
  directory. The flag exists to generalise that redundancy, not to take it away.
- **A directory naming no account service falls back to the configured list.** That is
  what makes this shippable to a fleet whose coordinators have not been given the flag
  yet, and it is the difference between an upgrade and an outage.

### 5. An entry is a LOCATION and never a trust root

The `"account"` entry carries an address and nothing else. The audience every assertion is
bound to and the CA the service's TLS identity is pinned against stay in the client's own
configuration, arriving out of band, and `accountclient.New` validates both **once for the
whole list** — which is exactly what makes a second address a second place rather than a
second authority (ADR-0016 decision 3).

So a coordinator that named a service it controls would be pointing the client at
something that still has to present the identity the client already pins. The gate on
using the directory's addresses at all remains `Config.AccountServiceConfigured()`: a
deployment that names no account service is complete, and a directory naming one this
client was never configured for could not be used anyway.

Publishing the address adds no sensitivity to the artifact — a snapshot carries no
secret, and this address is already in every client's config file. What the directory
adds is the ability to **change** it. An operator who would rather not publish it leaves
the flag unset.

### 6. An expired snapshot is not adopted, and the fallback is the seed rather than nothing

Acquisition answers from the freshest thing it has — a snapshot held in memory, then the
on-disk cache, then the network — and **every tier is signature-checked against the key
inside the current invite, and every tier must be unexpired.**

Checking the in-memory tier against the current invite is not belt-and-braces. An
operator handing a user a replacement invite is the one gesture that changes which
coordinator this client believes, and without the check the snapshot fetched under the
old one would go on answering for the rest of its validity window.

The "wrong-coordinator snapshot" case needs no separate machinery for the same reason: a
snapshot signed by a key this client does not hold is exactly a snapshot that does not
verify. That covers the cache an operator's *previous* invite left sitting at the path
this build reads.

Refusing an expired snapshot costs something real and it is worth naming: the
coordinator's `snapshotTTL` is **five minutes**, so the cache serves a rapid reconnect
and almost never the next day's launch. The whole value of the artifact is that it says
where things are *now*, and a client that adopted a stale one would point itself away
from the seed it was installed with on the strength of a document that has expired.

Everything that can go wrong except a malformed invite therefore produces "no directory"
rather than an error: no cache, a corrupt cache, an unreachable coordinator, a bad
signature. All of them are **logged**, because a client that silently stopped following
the directory is indistinguishable from one that never had an invite.

A malformed invite is the exception and is refused at connect, named. Ignoring it would
leave the user in the worst state available: a client that looks configured to follow a
moved address, silently does not, and gives no sign until the day an address moves.

### 7. Versioned transport names compare on the base name (`#201`)

Inert on the current tree and live the moment any transport version is bumped, so it
lands before the first bump rather than after.

`SanitizePoolOrder` matched `allowedPoolTransports` by exact string, so `reality/2`
matched nothing and was dropped with no message and no log line. The visible outcome was
not a short ladder: a fleet mid-rollout configures `["reality/2", "webrtc/2"]`, **every**
member was dropped, and `core` reads an empty `TransportPool` as *the pool is off*
(`Engine.poolOn`) — so bumping a transport version silently turned a failover ladder into
a single-transport dial, on the client whose entire reason for a pool is that no single
transport works for everyone. `LadderDisplayOrder` compounded it by then appending the
bare name as a phantom second row, and `settings.go`'s `poolCheck` unticked itself over
the wreckage and wrote the result back to disk.

Membership is now decided on the **base** name and the dedupe stays keyed on the **full**
one, which is the point of the version being in the pool's key at all: two versions of one
transport are two distinct members, deliberately, so a bump invalidates the learned winner
instead of re-trying a route validated against the old shape.

A **malformed** version (`reality/two`) is carried through rather than filtered. `core`
refuses it at construction, named, from the field that caused it — deleting it here would
replace that named refusal with the exact silent drop this decision exists to close.

`allowedPoolTransports` and `knownPoolTransports` stay **two** identical slices. They
answer different questions ("may this client enable it" / "does the ladder list it") and
the case that separates them is a transport displayable before it is provably
tunnel-safe. Merging saves one line and deletes the seam that difference lives in.

## Consequences

- **A client that connects at any point after a move learns the new address.** That is
  the shape ADR-0016 asked for, and it is per-device rather than fleet-wide: nobody has
  to be told, nothing has to be re-downloaded, and no config file is edited.
- **A session that outlives a move keeps the list it started with.** Acquisition happens
  at connect (and at a country refresh), not on a timer inside a live session, so a
  client connected across the move renews against the old addresses until it reconnects.
  ADR-0016's own framing is *"a client that connects at any point after the move"*, so
  this is the scope rather than a gap — but it is the honest limit of what shipped, and a
  desktop client can stay connected for longer than the 42-hour renewal period.
- **A client with an invite pays one bounded UDP round trip per snapshot lifetime**, at
  the front of a connect, before the coordinator is dialled. Five seconds at worst on a
  network where the bootstrap port is blocked and signaling is not; nothing at all on the
  repeat path, and nothing ever for a client with no invite.
- **The directory does not yet feed mesh-walk recovery, and that is deliberate.** A walk
  asks a peer running a courier listener on a separate `-courier-listen` address, which
  the snapshot does not carry — so the relay and exit entries of a snapshot are not, in
  this deployment, addresses a walk could ask. The signed bytes are cached anyway,
  because they are the proof of prior contact such a walk has to present, which makes it
  a later wiring job rather than a later protocol job.
- **The directory does not yet feed `relayDirectoryPath` either.** A chained connect still
  reads a hand-staged file; the cached snapshot is the same artifact and could serve, and
  is not wired here.
- **`invite` has no Settings widget**, the same interim `claimCode` is in under ADR-0056
  §3 and for the same reason: this file is the client's existing operator-facing seam, and
  the dialog is the shape.
- **Nothing here has met a moved address on real hardware.** The tests move the account
  service between two live loopback endpoints and prove which one the renewal reached;
  what is untested is a real coordinator's `-turn-addr` blend, a real firewall between the
  client and the bootstrap port, and the kill-switch allowing a directory-supplied
  coordinator through a real lockdown. Filed as a `needs-owner-test` blocker on `#194`.
