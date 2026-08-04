# 46. The client answers the connect-time device-credential gate; storage and renewal are a seam, not an account-service client

- Status: accepted (issue #53)
- Date: 2026-07-29

## Context

ADR-0045 landed the coordinator's half of the account service's two-tier
entitlement chain: `-device-root-pubkey` turns on a connect-time gate that
verifies `credential || issuer_cert || assertion` offline against an anchored
root. Its own Consequences section named the gap explicitly: *"a client must be
taught the exchange... that work is not in this change."* Until it was, the gate
was enforcement machinery with nothing able to answer it — the same half-shipped
shape ADR-0043 named for signed policy before #39 closed it.

This record is that other half: `core/client.go`'s connect path presenting a
chain, `core/devicestore` holding what it presents, and a decision about how far
"and keep it renewed" reaches inside this repository before it stops being this
repository's problem.

## Decision

### 1. One chokepoint, one exchange, matching the coordinator's contract exactly

`core/client.go`'s `attemptWith` is where every client path — single-transport
and the pool (issue #15) alike — builds the `connect` message, so
`presentDeviceCredential` (`core/devicecred_connect.go`) hooks in there and
nowhere else: `{"type":"challenge"}` (carrying the admission credential, gated
identically to `list`/`connect`), sign the returned nonce with
`devicecred.SignAssertion(deviceKey, devicecred.PurposeConnect, audience,
challenge)`, splice `challenge`/`deviceCred`/`issuerCert`/`deviceAssert` onto the
connect that was already being built. `core/devicecred` is imported, never
modified — its own doc asks that nobody hold a second implementation of the
framing it owns, and `SignAssertion` already produces the exact bytes a
coordinator's `VerifyAssertion` checks.

`audience` is `coordLink.raw` — "as configured, e.g. `1.2.3.4:8080`" — never
anything a coordinator's own reply says about itself. Bacchus runs a pool
(ADR-0020); an audience taken from the coordinator would let a hostile member
announce an honest one's identity, relay the challenge, and spend this device's
entitlement itself. `TestPresentDeviceCredential_AudienceBindsToDialledAddress`
proves both directions: the real `devicecred.Verifier` admits under the dialled
address and refuses under any other.

A client with nothing to present — no stored credential — sends none of the four
fields, `omitempty`'d away, byte-identical to a connect predating #50.

### 2. The challenge request is sent once, not via `sendN` — this is the opposite of the connect it precedes

`core`'s `sendN` puts three copies of every connect on the wire against UDP loss,
and issue #53's brief says plainly not to work around that — send the same
challenge and assertion across all three, never fetch a fresh one per copy. This
repository's implementation does exactly that. But the brief is silent on the
*request* for the challenge itself, and copying `sendN`'s pattern there is a live
correctness bug, not a stylistic choice:

`cmd/coordinator/devicecred.go`'s `challengeStore.issue` **replaces** whatever
challenge a source already holds on every call — "a client that asks twice is
retrying." A connect's three `sendN` copies are safe to retransmit because the
coordinator collapses them onto one request by the connect nonce (issue #1).
There is no equivalent collapse for `"challenge"`: three requests mint three
different nonces and reply with three different values, and only the *last*
processed is still live server-side by the time this client tried to act on
whichever reply it received first. Sending it three times does not add
redundancy — it races against itself, and the race is won by the coordinator's
processing order, not this client's.

So `presentDeviceCredential` sends the challenge request with a single `l.send`,
matching the framing that already governs the credential proper: fetched fresh
per `attemptWith` call, never cached, never reused across a retry or a rotation
(`TestPresentDeviceCredential_FreshChallengePerCall`,
`TestPresentDeviceCredential_FreshChallengePerCoordinatorOnRotation`). Loss of
that one datagram is not specially handled — it degrades exactly like an
unenforced gate (§3) and the caller's ordinary rotation takes over.

### 3. No usable challenge degrades to a plain connect; it never aborts the attempt

`issueDeviceChallenge` answers both "the gate is off" and "the store is at
capacity" with an empty `Challenge` — deliberately indistinguishable, per its own
doc. This client does not try to tell them apart either: a timeout, an empty
reply, or a decode failure all collapse to the same `ok=false`, and the caller
proceeds with a connect that simply omits the four fields.

That is the correct default rather than a shortcut. If the gate is genuinely off,
the plain connect is exactly right. If it is genuinely on and this device merely
failed to obtain a challenge, the coordinator refuses the connect with a legible
reason (`admitDevice`'s `reject`) through machinery that already exists —
`pairRefused`, surfaced by `refusalText`. Retrying inside `presentDeviceCredential`
itself would duplicate the mode-ladder/pool retry logic `attemptWith`'s callers
already own.

### 4. Storage draws a hard line between identity and entitlement

`core/devicestore` is two things with two different failure postures, not one:

- **The keypair** (`LoadOrGenerateKey`) is generated once and is a hard
  construction error if the file is present but unreadable — mirroring
  `cmd/coordinator`'s `loadOrGenerateBootstrapKey`. Silently minting a
  replacement key on a corrupt file would silently strand whatever credential
  this device already holds, since `DevicePub` is what a credential binds
  (the account service's own `account-model.md` §5, §6 — device count is an
  install cap spent at enrollment; that document is in `bacchus-payment` and
  is not public). That harm is invisible until the next connect fails for a reason
  nobody can see from here, so it is refused at startup instead.
- **The credential + issuer cert** (`Store`) soft-fails to empty on anything
  short of a clean read, mirroring `core/selection`'s cache. Losing this loses a
  renewable, hours-long entitlement, not an identity — "a damaged cache must
  never stop a client connecting" applies exactly as it does to path selection.

Both persist as the opaque envelope strings devicecred already knows how to
encode and decode — never re-marshaled from parsed fields, for the same reason
devicecred's own doc gives a *verifier*: a re-encode risks disagreeing with the
signer over bytes it was never supposed to have an opinion on. This package
never verifies anything, but it is the one place a client's own credential
exists between being received and being presented, so it inherits the
discipline anyway.

### 5. Reading a credential's own claimed expiry is not a verification, and is documented as exactly that

Renewal needs to know when its stored credential expires. `core/devicecred`
exposes no way to read that without a root public key to verify against — by
design, "untrusted bytes never reach the decoder." A device does not need to
verify its own credential's signature to know when to *try renewing it*: that is
a liveness question, not a trust one, and the coordinator is the only party that
ever admits or refuses on this chain's contents, always via a signature-checked
`Verify`.

`devicestore.Expiry` therefore decodes the envelope (devicecred's own exported,
signature-blind `DecodeDeviceCredential`) and reads `exp` out of the body without
checking the trailing signature at all, into a local type that is deliberately
not `devicecred.DeviceCredential` — so a caller reaching for the real type is not
one field access away from treating this read as trustworthy. `Expiry`'s doc
says outright what it is for and is not. Getting it wrong costs a slightly early
or slightly late renewal attempt; it can never affect an admission decision,
because it never makes one.

### 6. Renewal is a signing primitive plus a seam, not a built-in HTTP client

Renewal needs a live network round trip to *some* account-service endpoint. No
such endpoint has a specified request shape anywhere — not in this repository,
not in `bacchus-payment`'s design docs, which sketch the message conceptually
(`{ device_pubkey, sign_device(nonce) }`, its `account-model.md` §5) but define no
path, method, or wire encoding, and that service currently has no HTTP surface
at all (`grep -r net/http` there returns nothing).

Committing an HTTP client in this public, AGPL repository to an endpoint the
private service does not yet own would bind a contract backwards — the account
service should define its own API; this client should conform to it, not
originate it by guesswork. So `Config.DeviceRenew` is a seam
(`func(ctx, DeviceRenewRequest) (cred, issuerCert string, err error)`), matching
this codebase's existing shape for exactly this situation (`OnUnderlayDial`,
`OnEvent`): nil is renewal off, and the client runs unrenewed on whatever
`core/devicestore` already holds until it expires — issue #53's own words, "a
client that does not renew simply stops connecting once the gate is on," which
is a legible, already-handled refusal (§3), not a crash.

What *is* fully implemented, because it is pure cryptography this repository
already owns the framing for: `devicecred_connect.go`'s `purposeRenew` constant —
the literal string `bacchus/assert-renew/v1`, stated here rather than cited,
because the table it comes from lives in the account service's own repository
and a public reader following the citation would find nothing — and a `Sign` closure
handed to the seam instead of the raw private key, scoped to exactly that
purpose. `core/devicecred` deliberately declares only `PurposeConnect` — "a
coordinator has no business holding a verifier for" the others — but `Purpose` is
just a string type, so using this tag needs no change to that package. Keeping
the actual `ed25519.Sign` call inside this repository, rather than trusting a
caller-supplied closure to always remember the right purpose, is the same
argument the purpose tag itself exists for: a key that signs in several contexts
is only safe if nothing outside the intended context can produce its output. A
background loop (`deviceRenewLoop`, mirroring `reloadCRLLoop`'s ticker shape)
checks `devicestore.NeedsRenewal` against a configurable margin (default 6h,
comfortably inside the 24-72h lifetime `bacchus-payment`'s `account-model.md`
§5 describes) and calls
the seam when due.

> **Update (2026-08-04):** the reason above is spent. The seam stays, for
> different reasons (#159).
>
> **What changed.** The account service now specifies *and serves* a renewal
> endpoint — `POST /v1/credential`, in `bacchus-payment`'s
> `docs/design/account-service-transport.md` §3. The two paragraphs above turn on
> "no such endpoint has a specified request shape anywhere" and "that service
> currently has no HTTP surface at all". Both sentences were true when this record
> was accepted and neither is true now. They stand as the record of what was
> decided in July; **they are no longer a reason for anything**, and nothing
> should cite them. What follows replaces them.
>
> That matters because the old reason was a *dependency*, and a decision resting
> on a dependency is not a decision — it expires the moment the dependency
> arrives. This one has, so the question was re-asked on its merits, and the
> merits are these.
>
> **Ruling: `Config.DeviceRenew` remains a seam.** Three reasons, each true on
> this date, none of them a restatement of the one above.
>
> 1. **Renewal is the second half of a flow whose first half is still not here.**
>    `maybeRenewDeviceCred` returns before it ever reaches the seam when the store
>    is empty, and nothing in this repository ever fills it. Enrollment is
>    out-of-band by §7 below, by this record's own Consequences, and by
>    `cmd/node`'s `-device-cred-dir` flag text, which says so to the operator's
>    face; `clients/fyne` — the client 1.0 actually ships — does not set
>    `Config.DeviceCredDir` at all, so it holds no credential to renew under any
>    configuration. A built-in renewal client would give a device the ability to
>    re-up a credential it has no ability to obtain. That is not the seam filled,
>    it is the seam moved onto the harder half, where the claim code, the sibling
>    approval and the six-digit code live. Whatever ships enrollment should ship
>    renewal with it: one change, one protocol, one place a user configures it.
> 2. **A specified endpoint is not a specified exchange.** The primitive this
>    repository owns is challenge-bound — `DeviceRenewRequest.Sign(audience,
>    challenge)` — so a built-in client must commit to where that challenge comes
>    from and what audience string binds it. Knowing that a path exists supplies
>    neither, and inferring them is the same backwards contract the paragraphs
>    above refused.
>    That objection was never really about the endpoint being unspecified; it was
>    about which repository gets to originate a contract, and it reads identically
>    against a specified endpoint.
> 3. **Nothing in this repository dials the account service.** At `b30ce54` the
>    whole tree holds exactly one `net/http` import — `cmd/coordinator/policy.go`,
>    fetching a signed policy from an operator-configured URL. The device-credential
>    machinery is offline verification end to end, stated as a designed property in
>    more than one package doc (`core/devicecred`'s: it "never depends on, and never
>    leaks to, the closed account service"; `verify.go`'s: "It never contacts the
>    account service — that is the whole point"). A renewal client would be the
>    first outbound call from this AGPL tree to the closed service. The property
>    those docs describe belongs to the coordinator rather than to a client, so
>    this is the weakest of the three on its own — but it is what makes the AGPL
>    argument concrete: an operator running Bacchus without an account service
>    should not have to configure their way out of a component the client assumes.
>
> **The cost, stated rather than argued away.** A seam every deployment must fill
> is a seam every deployment can get wrong, and this one is currently filled by
> nobody, so the honest description of renewal today is *not shipped* rather than
> *pluggable*. That is acceptable only because the gate is off by default
> (`-device-root-pubkey` unset) and no shipped client holds a credential in the
> first place — the moment either changes, this ruling is due for re-reading, and
> the trigger is written down below rather than left to be noticed.
>
> **What would reopen this.** Not another endpoint. The seam should be re-asked
> the day this repository grows an enrollment path, because on that day reason 1
> is gone, reason 2 has to be answered anyway to enroll at all, and reason 3 is
> paid once instead of twice. That change reaches into a private repository's wire
> format and wants a card and a wave of its own; it would have to cover how a user
> supplies a claim code and where it is entered (`cmd/node` flag, `clients/fyne`
> UI, or both), which verbs beyond `POST /v1/credential` a client speaks and how it
> obtains the challenge and audience each is bound to, where the service's base URL
> is configured and what a deployment that runs no account service configures
> instead, what a failed renewal looks like to a user rather than to a log line,
> and whether the seam survives underneath as the escape hatch a downstream
> deployment substitutes its own issuer into.

> **Update (2026-08-04, later the same day): the trigger fired. The seam
> survives.** See **ADR-0056** (#163), which is the enrollment path landing here
> and answers all five of the questions listed above.
>
> All three of the reasons above were re-read against a repository that now
> enrolls, and two of the three are spent:
>
> 1. **Gone.** `core/accountclient` obtains a first credential by claim code, so
>    renewal is no longer the second half of a flow whose first half is missing.
>    Enrollment and renewal shipped together, in one change, as this paragraph
>    asked.
> 2. **Answered rather than spent.** The challenge comes from `POST /v1/challenge`
>    and the audience is pinned client-side out of band, never read from a
>    response. That had to be settled to enroll at all, and settling it did not
>    make a built-in renewal client correct — it made one *possible*, which is a
>    different thing.
> 3. **Paid, once, deliberately, and in a package `core` does not import.** This
>    repository now dials the account service. `go list -deps ./core` still names
>    no HTTP client, and that is the property the ruling protects: an operator
>    running Bacchus with no account service imports nothing and configures
>    nothing.
>
> What keeps the seam is therefore no longer any of the three. It is that the
> alternative — renewal built into `core` — would put the closed service's wire
> format inside the package every embedder must import, and would make an
> operator with no account service configure their way out of a component they
> never wanted. ADR-0056 §2 states that in full and prices what it costs.
>
> **What this record's §7 said about `clients/fyne` is also now false**, and the
> falseness is the point: that client sets `Config.DeviceCredDir` and fills
> `Config.DeviceRenew`, so the 1.0 desktop client holds a device credential and
> keeps it fresh. The seam has been filled by an embedder for the first time.

### 7. Config surface: `-device-cred-dir` is proposed, not applied, in this change

Issue #53 asks for "how an operator/user supplies the initial credential,
alongside `-admission-cred`" — `cmd/node`'s flags. This lane's file ownership is
`core/client.go`, `core/coordpool.go`, `core/engine.go`, the new storage package,
and this ADR; `cmd/node` is outside it, and Wave 9's boundary rule is to stop and
propose rather than edit across it unilaterally. `Config.DeviceCredDir` (§4) is
therefore live and fully wired inside `core`, but nothing in this repository's
`main` yet sets it from a flag — a one-line gap, proposed alongside this PR for
the owner to place.

Enrollment itself — obtaining the *first* credential for a `DeviceCredDir` to
hold — is out of this change by the issue's own dependency note: account-service
work, tracked separately, this card built and tested against locally minted
chains instead (`core/devicecred_connect_test.go`'s `mintTestChain`, the pattern
`cmd/coordinator/devicecred_test.go` already established on the verifying side).

> **Update (2026-08-04):** the proposal was taken — `cmd/node` carries
> `-device-cred-dir` today, and its flag text repeats that enrollment happens
> elsewhere. Enrollment itself is still out of this repository, which is the first
> of the three reasons §6's update gives for keeping the seam. `clients/fyne` sets
> no `Config.DeviceCredDir` at all, so the 1.0 desktop client persists no device
> credential under any configuration; that is a gap in the client rather than in
> this record, and it is named here because §6's update leans on it.

## Consequences

- **Issue #53 closes.** The gate ADR-0045 built now has a client able to answer
  it: `-device-root-pubkey` plus a client holding a provisioned credential is a
  complete, working path, proven against the real `devicecred.Verifier`.
- **The gate remains switchable, not yet switched on for real users.** Nothing
  in this repository enrolls a device — that dependency is unchanged from what
  issue #53 named, and turning the coordinator's gate on ahead of a real
  issuance/enrollment path would refuse every connect from every client, since
  none would hold a credential yet.
- **A corrupt device-key file is now a hard startup failure for the client
  role**, matching the bootstrap key's existing posture, not a new one this
  change invents.
- **Renewal is real but untested against a real account service**, because
  none is reachable to test against. `DeviceRenew`'s contract is proven with a
  fake seam; the day `bacchus-payment` ships an HTTP surface, wiring it is an
  embedder's `Config.DeviceRenew` closure, not a change to this package.

  > **Update (2026-08-04):** that day has arrived and the bullet's conclusion
  > survives it. `bacchus-payment` serves `POST /v1/credential`, so "none is
  > reachable to test against" describes July rather than today — but wiring one
  > is still an embedder's closure and not a change to this package, and that is
  > now a ruling on the merits rather than a consequence of a missing dependency.
  > See §6's update for the three reasons that replace the one this record gave
  > (#159). Nothing in this repository has been tested against the real endpoint;
  > whatever fills the seam is what will be.
  >
  > **Update (2026-08-04, later the same day):** it has been. `core/accountclient`
  > fills the seam, and it has been run against the real `bacchus-payment`
  > handlers — enrollment, renewal and both refusals — with the exchange frozen
  > into `core/accountclient/testdata/wire_vectors.json` so this repository can
  > keep testing against those bytes without reaching the private one. ADR-0056
  > §5. The last sentence of this bullet is discharged.
- **`cmd/node` needs one new flag.** Tracked here rather than silently left
  undiscoverable; see §7.

## Testing

`core/devicecred_connect_test.go`'s `mintTestChain` mints a throwaway
root/issuer/device chain using only `devicecred`'s exported types, tag
constants, and envelope encoders — reproducing the `tag || 0x00 || body` framing
`core/delegation` documents rather than importing anything unexported. Chosen
over reusing `core/devicecred/testdata/vectors.json` directly so these tests mint
fresh at whatever clock they run on, rather than pinning every assertion to that
fixture's fixed `now`.

A purpose-built fake coordinator (`fakeDeviceCoordinator`) answers `"challenge"`
per test-configured behavior and records every `"connect"` it receives; it never
verifies anything itself. Verification happens in the test, against the real
`devicecred.NewVerifier`/`Verify` — the same calls `cmd/coordinator/devicecred.go`
makes — so a pass means the real coordinator's gate would have admitted the same
bytes, not merely that they decode.

Each sharp edge issue #53 named has a test built to fail if that edge is lost:
same challenge and assertion across `sendN`'s three connect copies
(`TestAttemptWith_ConnectCarriesSameChallengeAcrossRetransmissions`); a fresh
challenge per call and per coordinator, never cached across either a retry or a
rotation (`TestPresentDeviceCredential_FreshChallengePerCall`,
`...FreshChallengePerCoordinatorOnRotation`); the audience binds to the dialled
address and *only* that address (`...AudienceBindsToDialledAddress`); a silent or
empty challenge reply degrades to a plain connect rather than blocking one
(`...NoChallengeReplyDegradesGracefully`, `...EmptyChallengeDegradesGracefully`).
`TestDeviceCredWireContract` pins the four new `wire` fields against a
hand-written encoding of `cmd/coordinator`'s own struct, the same shape
`TestCountryReplyWireContract` already uses for `wireCountry` — the two `wire`
types remain deliberately separate, non-importing definitions, so nothing else
catches a drift between them.
