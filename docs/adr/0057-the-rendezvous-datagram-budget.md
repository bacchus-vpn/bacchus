# 57. The rendezvous datagram fits a 1280-byte path, and a request that is not sent is not a silent coordinator

- Status: accepted (issues #183, #184)
- Date: 2026-08-06

## Context

Both defects recorded here were found by running the software on real hardware,
and neither is visible to any test this repository had. They share a file set,
they were found in the same testbed session, and each is a client broken in a way
it cannot report.

### #183 — a connect that does not fit the path

A logging UDP proxy between `cmd/node -role client` and a real gated coordinator
measured a `connect` of **1453 bytes**, which needs a 1481-byte IP datagram. That
fits standard Ethernet (1500) and PPPoE (1492). It does not fit:

- **1280** — Tailscale's default tunnel MTU, the path this was found on.
- **1280** — the IPv6 minimum link MTU (RFC 8200 §5), which is guaranteed
  deliverable everywhere by definition and is therefore what any path that has
  fallen back reaches.
- **1420** — WireGuard's common MTU.
- **~1400** — carrier and mobile paths that clamp.

The kernel refuses such a datagram with `EMSGSIZE` — the same error `ping -M do`
prints as "Message too long". `coordLink.send` discarded it:

```go
_, _ = l.conn.Write(b)
```

So the client waited out `awaitSession`, concluded the member was silent, and
returned `core: no coordinator reachable` — which is returned only when every
member was silent, and which is the **mesh-walk trigger** (#31). The failure
therefore presented as *rendezvous is blocked*, the exact diagnosis a user on a
censored network will believe and report, for a packet that never left the host.
A `-list` of 438 bytes succeeded from the same client seconds earlier, so the
loss looked selective — indistinguishable from a soft block. The coordinator
logged nothing at all, because `admitDevice` was never reached.

The cost is concentrated on exactly the wrong users. A censorship-resistant VPN
that cannot run inside another tunnel, or over a link at the IPv6 floor, has lost
the people most likely to be behind one. It is also a live instance of #137
(coexistence with another VPN), arriving before that card was worked.

**What made it 1453.** `connect` carries, in one JSON datagram, the admission
credential, the device credential, the issuer cert, the connect assertion and the
challenge echo. #166 added no field: `Cred: e.admissionCred()` was already there,
but for a client enrolled through the account service it had always been *empty*
— no `Config.AdmissionCred`, no fallback. #166 added the device-store fallback,
which is correct and is what that issue was for. The side effect is +423 bytes on
`connect` **and** +423 on `challenge`, because the credential was already on both.

**Why no test saw it.** Loopback's MTU is 65536. Unit tests, both PR CI runs and
the wave's combination build carried the 1453-byte datagram without complaint and
stayed green — and still would.

### #184 — a renewal that never runs

`deviceRenewLoop` created a `time.NewTicker(deviceRenewCheckInterval)` — ten
minutes — and its `select` had no default and no check before the loop, so its
first action was at T+10min. `clients/fyne` builds an engine **only at connect
time**, and `Controller.connectAsync` calls `eng.Stop()` when `Connect` returns an
error, which a refused connect does in about thirty seconds.

So renewal only ever happened while a connect had **succeeded**. Once the
credential expired the gate refused the connect, and the one mechanism that could
have fixed it was destroyed before it acted. The trigger is not an edge case: it
is not connecting for `DefaultCredentialTTL`, which is 48 hours. A weekend
reaches it.

The device is recoverable throughout, which is what makes it worse. Renewal is
keyed on the enrolled device **key**, not on holding a live credential — the
`/v1/credential` request carries only `device_pub`, `challenge` and `sig`, and the
stored credential is never sent. The account service would have re-issued on
request the whole time. Recovery in practice meant an operator minting a fresh
claim code for a paid, unexpired account.

## Decision

### 1. Rendezvous datagrams are sized to a 1280-byte path, not a 1500-byte one

`safePathMTU = 1280` and `maxRendezvousPayload = 1280 - 40 - 8 = 1232` bytes, the
UDP payload that fits that MTU under an IPv6 header. IPv4 leaves more room (1252),
so the IPv6 arithmetic covers both — which is the point, because a client does not
choose which one its path is.

1500 is a bet on the path. 1280 is the floor the path is allowed to have, from two
independent directions that give the same number: the IPv6 minimum, and the
default MTU of the tunnel this client is most likely to be running inside.

The budget explicitly does **not** account for IPv6 extension headers or for an
outer encapsulation the client cannot see. No constant can; §3 is what covers the
rest.

### 2. The admission credential rides `challenge`, and `connect` carries it only when no challenge was answered

The credential was on the wire **twice per connect attempt** — once on
`challenge` (where it gets the request past the coordinator's client-admission
gate, which guards that message like every other client message) and once on
`connect`. Dropping the second copy is what puts the datagram under the budget.

**This is a conditional move, not a removal**, and "we took it off connect" is the
wrong summary. The coordinator still needs *a* credential whenever admission is
enabled, so three paths still put it on `connect`:

1. **No challenge was sent.** `presentDeviceCredential` returns `ok=false` and
   sends nothing when there is no device store or nothing held. The coordinator
   has no state for this source at all.
2. **A challenge was sent and answered with an empty challenge.** Either the
   device-credential gate is disabled, or the coordinator's challenge store is at
   capacity; `cmd/coordinator` deliberately reports both the same way and stores
   nothing in either.
3. **A challenge was sent and no reply arrived.** The coordinator may hold state
   and this client cannot tell. The credential rides the connect, which is free of
   consequence where it does.

**The condition is a challenge ANSWERED, not a challenge sent.** That distinction
is load-bearing rather than pedantic. `presentDeviceCredential` sends a challenge
whenever this device holds a credential — it cannot see the coordinator's gate —
so a client that reasoned "I sent a challenge, therefore I need not send the
credential" would have **every connect refused** on any deployment running
admission (#42) with the device-credential gate (#50) switched off. That is an
ordinary configuration, not an edge case, and the failure would be total rather
than degraded.

### 3. The coordinator stashes the credential beside the nonce, and stashes only what it verified

`challengeStore` already keys per UDP source with a TTL, a cap and a sweep loop,
so the per-source state a link needs already exists and is already bounded. The
`challenge` handler stores the credential it just verified; the `connect` handler
reads it when the connect carries none.

Two properties keep this from widening anything:

- **Nothing unverified is stored.** The stash is gated on `admissionVerifier`
  being non-nil, not on the field being non-empty. With no authority anchored,
  `admit()` admits everyone and the field is an unverified, unbounded,
  attacker-chosen string arriving on a spoofable UDP source — so nothing is kept,
  and nothing needs to be, because the connect that follows is admitted on the
  same absent gate.
- **A stash can only exist while the device gate is on.**
  `issueDeviceChallenge` returns before touching the store when the gate is
  disabled, so any connect that reads from the stash must also pass `admitDevice`,
  which requires an assertion signed over the nonce this coordinator issued to
  this source. A blind spoofer cannot see the reply, cannot produce the assertion,
  and therefore cannot spend a stashed credential.

The raw string is kept rather than the decoded credential, so the connect re-runs
the full verification — including the revocation check — against the clock at
connect time. A credential revoked inside the challenge's two-minute TTL is still
refused.

**Accepted cost:** an entry grows from a 32-byte nonce to that plus a few hundred
bytes of credential, so `maxPendingChallenges` now bounds roughly 30 MB rather
than roughly 7. Filling it with non-empty entries requires a valid client
admission credential, because the `challenge` handler is admission-gated. A
spoofing attacker with no credential can still fill the store — that was always
true of a UDP-source-keyed map — but every entry they create holds an empty
string.

### 4. A write error is a diagnosis, and EMSGSIZE is a complete one

`coordLink.send` checks the write. Every failure is logged once per message type
per member, naming the size. `EMSGSIZE` additionally gets its own sentence naming
the datagram's size, the IP datagram it needs, the 1280-byte floor and the fact
that this is a local path limit rather than a blocked coordinator — because the
diagnosis a user reaches unaided is the wrong one, and a message that merely omits
it leaves them to supply it themselves.

The client legs distinguish it in **control flow** too, not only in the log. A new
`requestTooLarge` outcome and an `ErrRequestTooLarge` sentinel keep the condition
out of `ErrNoCoordinatorReachable`, so a datagram that never left the host does not
trigger mesh-walk recovery against a healthy pool. The member is deliberately
**not** marked unhealthy: it did nothing, every other member is behind the same
local path, and demoting them one by one only makes the pool's health picture
describe this client's MTU.

**Only EMSGSIZE changes what the client concludes**, and that restraint is the
substantive part of this decision. A connected UDP socket reports a dead peer's
ICMP port-unreachable as `ECONNREFUSED` **on the next write** — so a genuinely
unreachable coordinator fails the write as well. Counting every write error
reclassifies the one condition `ErrNoCoordinatorReachable` exists to name, and the
existing suite caught it doing so. Every other write failure is logged and still
reads as silence, exactly as before.

`EMSGSIZE` is matched by two errnos. On Unix the socket layer returns
`syscall.EMSGSIZE`. On Windows it returns `WSAEMSGSIZE` (10040), and
`syscall.EMSGSIZE` on that platform is one of the "invented values to support what
package os expects" — a number no socket ever produces. The public `syscall`
package does not export `WSAEMSGSIZE`, so the number is written out. Matching only
the named constant would have left this fix **silently inert on Windows**, which
is half of what 1.0 ships to.

### 5. A datagram over the budget is reported even on a path that carries it

`send` compares the marshalled length against `maxRendezvousPayload` and warns
once per message type, whether or not the write succeeded.

This is the half that needs no small path. #183 shipped because loopback carries
1453 bytes happily; this check costs one comparison, needs no network, and would
have said so on a developer's own machine the day the datagram grew. A test can
be forgotten to be written; this cannot be forgotten to be run.

### 6. `deviceRenewLoop` works first, then waits

The loop is `for { work; select { <-stop: return; <-tick } }` — `registerLoop`'s
shape, four lines away in the same package, which sends its first register the
instant it is entered. `deviceRenewLoop` had the same shape with the opposite
behaviour and nothing in its comments argued for the difference.

`maybeRenewDeviceCred` is unchanged. The margin still decides whether anything
happens, and its early return for a device with **nothing enrolled** stays exactly
as it is: an entry check must not become an enrollment attempt, because a claim
code is spent exactly once and the second spend does not fail safely (ADR-0046).
What changed is only *when* the first check happens.

This also makes a refused connect productive: the client tries to renew, succeeds,
and the next connect is admitted — self-healing, with no operator involved.

### 7. The renewal call is cancelled by engine shutdown

The entry check is what makes this necessary. The first call now happens
immediately, so a `Stop` shortly after `Start` can land on an in-flight renewal,
and `Config.DeviceRenew` is an embedder's transport this package does not get to
assume returns promptly. Without cancellation an unreachable account service would
hold `Stop`'s `wg.Wait` for the full `deviceRenewCallTimeout` of 30 seconds —
turning a fix for a client that tears its engine down quickly into a client that
cannot tear it down at all.

## Consequences

**The measured result.** The largest `connect` this client can assemble — a
chained relay request with an excluded session, a full device-credential chain and
a production-sized admission credential in play — is **1097 bytes against a
1232-byte budget, 135 bytes of headroom**. The same datagram with the second copy
of the credential restored is 1443 bytes, 211 over. Production credentials run
slightly larger than the test fixture (the testbed's chain measured ~34 bytes
heavier), so the real headroom is closer to 100 bytes.

**That headroom is thin and should be treated as spent.** Two more fields the size
of the ones already there would exhaust it. The next lever, if one is needed, is
the **issuer cert**: it is 362 bytes, it is identical for every device from one
issuer, and it is re-sent on every connect. Moving it to the challenge is the same
move made twice. #175 argues the coordinator hop needs a transport ladder anyway,
and #183 agrees with it from the other direction; that stays #175's card and this
record does not pre-empt it.

> **The lever was pulled, 2026-08-07 — #206, ADR-0062.** It became a precondition
> rather than an option: ADR-0059 measured DTLS records at 37 bytes against the 135
> above, leaving ~64 of real headroom, and nothing could spend that before the cert
> moved. It measured **378 bytes on the wire** (the 362 plus its JSON key and
> punctuation), taking the largest connect from **1097 to 719** and the headroom from
> 135 to **476 under the 1195-byte shaped budget**. Unlike §2's move it is
> unconditional: the connect never carries the cert again, because it only ever went
> out on a connect whose challenge had already been answered. `minConnectHeadroom`
> now pins a floor of 400, which is the check this record's own test did not have —
> asserting against `maxRendezvousPayload` catches the moment the datagram stops
> fitting and not a byte sooner.

> **Every cert number above is a fixture number, and it was an unstable one — #233,
> 2026-08-09.** The 362 is this repository's own test chain minted from a bare
> `time.Now()` on a workstation whose clock had nine significant nanosecond digits and
> a `+02:00` zone. `time.Time` marshals as RFC3339Nano, which trims trailing zeros, so
> identical code on a UTC runner with a coarser clock minted the same cert anywhere
> from **322 to 349 bytes** — and the test asserting a floor of 362 duly failed at 360
> on CI having passed 240 times locally. The fixture clock is normalized to a whole
> UTC second now, which makes the envelope a constant 322 bytes (338 on a connect,
> once its JSON key is counted) and lets that test assert exactly instead of as a
> floor. The largest connect the suite measures moves 719 → **679** for the same
> reason: the fixture chain got 40 bytes smaller, not the wire. A real issuer cert is
> *larger* than any of these — the account service stamps a `note` and does not
> truncate its clock, and this repository's own frozen chain is 382 bytes — so the 378
> and the 476 understate what the move bought rather than overstating it, which is the
> safe direction for a budget.

> **§4's `EMSGSIZE` diagnosis survives the shaped hop, measured rather than assumed
> (ADR-0062 §6).** The datagram the kernel refuses is now a DTLS record, and the
> refusal has to travel back out through pion for this client to classify it; it
> does, errno intact. A size refusal deliberately does not retire the association —
> `EMSGSIZE` is a fact about this host's path, and retiring one over it would turn a
> local path limit into a member lost for minutes.

**What is now pinned.** A test asserts the connect's size against
`maxRendezvousPayload` on bytes actually written to a socket, and a second asserts
that restoring the second credential copy exceeds it — so the fix cannot be undone
silently and the *reason* it fits cannot rot into coincidence.

**Compatibility.** A client that sends the credential only on `challenge` is
refused by a coordinator that predates this change, because that coordinator reads
no stash and `admit` sees an empty field. The two halves ship together in one
change, and the pairing is client-and-coordinator rather than client-and-client, so
a mixed fleet means a mixed *coordinator* fleet. That is the same deployment
constraint #114 records for stale node binaries and is not made worse here; a
client rotates to another pool member, and this repository has no coordinator it
does not also deploy.

**What is not addressed.** The oversize warning fires on a datagram the current
path happened to carry, which on Ethernet is a warning about a future user rather
than the present one. That is deliberate — it is the only check that runs where
nobody is affected yet — but it means the message has to explain itself, and it
does.

## References

- Issues #183, #184; #166 (the device-store fallback whose side effect this is),
  #31 (mesh-walk, the trigger being protected), #137 (coexistence), #175
  (transport ladder), #114 (mixed-fleet version skew)
- ADR-0045 (connect-time device-credential verification), ADR-0046 (the renewal
  seam and the not-enrolled early return), ADR-0020 (the coordinator pool)
- RFC 8200 §5 (the IPv6 minimum link MTU)
