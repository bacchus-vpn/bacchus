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
  (account-model.md §5, §6 — device count is an install cap spent at
  enrollment). That harm is invisible until the next connect fails for a reason
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
(`{ device_pubkey, sign_device(nonce) }`, account-model.md §5) but define no
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
already owns the framing for: `devicecred_connect.go`'s `purposeRenew` constant
(`bacchus/assert-renew/v1`, `credential-wire.md` §4's table) and a `Sign` closure
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
comfortably inside the 24-72h lifetime account-model.md §5 describes) and calls
the seam when due.

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
