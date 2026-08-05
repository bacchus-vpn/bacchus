# 56. The client enrolls against the account service for real, and `Config.DeviceRenew` survives as the seam it fills

- Status: accepted (issue #163)
- Date: 2026-08-04

## Context

Bacchus can mint a device credential, persist it, renew it, revoke it, and
verify it offline at connect time. Every one of those halves is built, tested
and merged. **Not one of them had ever been exercised against the other.**

The account service is tested against its own fixtures. The coordinator's gate
is tested against `mintTestChain`, a chain the test mints itself. `clients/fyne`
— the client 1.0 actually ships — set `Config.DeviceCredDir` nowhere, so it held
no device credential under any configuration and presented nothing to a gate
whether that gate was on or off. `Config.DeviceRenew` had never been filled by
anything. Both halves being inert is self-consistent, which is exactly why
nothing had ever failed.

That mattered because of what was queued behind it. Three v1 epics — the
multi-crypto gateway, the captive free tier, and onboarding/activate/buy — are
all unstarted and all assume this spine works, with the largest of them sized L.
Building a buy flow on an enrollment path nobody has run once is how a wave's
work gets spent discovering that the audience string was wrong.

This record is that proof, and the decisions it forced.

ADR-0046 §6's 2026-08-04 amendment wrote the trigger down in advance: *"the seam
should be re-asked the day this repository grows an enrollment path."* It also
listed, in advance, the five things the reopening change would have to cover.
This is that change, and §3–§7 below answer those five in order.

## Decision

### 1. The client speaks `POST /v1/enroll` for real; it is not a development tool

The alternative was a small `cmd/` helper that does the exchange and writes a
credential into a `DeviceCredDir`, leaving `clients/fyne` only to read one.

It was rejected because it proves strictly less than the thing in doubt. The
service and the gate would both get exercised; the *client's ability to reach the
service* would not — and that is the half all three queued epics are built on.
It would also have to exist forever or be thrown away, and neither is attractive:
a provisioning tool that ships is a second enrollment implementation, and one
that does not ship is a test harness wearing a `cmd/` directory.

There is no third option where a credential is copied into place out of band.
ADR-0012 decision 2 dropped `POST /v1/admin/account/enroll` — the one operator
verb that minted a credential directly — so that mutual TLS would be
proportionate to the operator surface. That was right and is not revisited here.
Its consequence is that the only remaining path onto a device is a *client* verb
requiring a claim code, a challenge, and a `bacchus/assert-enroll/v1` signature
by the device's own key.

### 2. `Config.DeviceRenew` survives as a seam, and `core` gains no dependency on what fills it

ADR-0046 kept the seam on three reasons. Enrollment landing here spends two of
them (see that record's amendment). The seam survives anyway, on a reason that
was previously implicit:

> **The dependency runs one way — from the enrollment client to `core`, never
> back — and that direction is what the AGPL escape hatch is made of.**

`core/accountclient` imports `core`. `core` imports nothing of it, and
`go list -deps ./core` says so. Concretely, that buys three things a built-in
client would spend:

- An operator running Bacchus with **no account service** imports no HTTP
  client, configures nothing, and is not degraded. The device-credential gate is
  off unless a coordinator turns it on; a network with no entitlement authority
  is a supported shape, not a broken one.
- A downstream AGPL deployment substituting **its own issuer** replaces one
  `Config` value. Under a built-in client it would fork `core`.
- `core/devicecred`'s package doc — that it "never depends on, and never leaks
  to, the closed account service" — stays true, and `core`'s own import graph
  keeps it true rather than a comment asserting it.

**What this costs, stated rather than argued away.** A seam every deployment must
fill is a seam every deployment can get wrong, and there is now exactly one
embedder filling it correctly. `cmd/node` does not (see §3), so a node-role
client holding a credential still cannot renew it. That is a real gap and it is
named here rather than left to be discovered.

> **Update (2026-08-05, `#166`):** the seam's SHAPE changed and the ruling did
> not. `Config.DeviceRenew` now returns a `devicestore.Credential` rather than two
> strings (§7). `core` still imports nothing that dials an account service, and
> `go list -deps ./core` is byte-identical to what it was before that change —
> which is the check this section's argument actually rests on, so it is the check
> that was run.

### 3. Where the claim code is entered — ADR-0046's first question

**`clients/fyne`'s config file, as a one-shot field, plus a `Controller` method
for the dialog that has not been built.** Not `cmd/node`, and not both.

`Config.ClaimCode` is redeemed at the next connect and **erased from the file the
moment enrollment succeeds**. The erasure is not tidiness: a claim code is a
bearer secret spent exactly once, and the account service *erases* a spent claim
hash rather than flagging it — so a client that kept one on disk would hold the
only remaining record that the code ever existed. A code that is **refused** is
left in place, because a user who mistyped needs to see and correct what they
typed rather than face an empty field.

`Controller.Enroll(ctx, claim, label)` is the same code path with the value
passed in, and it is what a claim-code dialog calls. The dialog is not built
here: `clients/fyne`'s Fyne-touching files are outside this lane's ownership, and
the split ADR-0039 draws between testable model and untestable view is exactly
why the method is here and the widget is not. The config field is the interim;
the dialog is the shape.

**`cmd/node` deliberately gets nothing.** It carries `-device-cred-dir` already
and can present a credential someone else put there — that path is exercised in
this change's testbed run. What it does not get is a `-claim-code` flag, for two
reasons: `cmd/node` is outside this lane's file ownership, and a flag is a poor
home for a single-use bearer secret that would then sit in a shell history, a
systemd unit, or a process listing. If it is wanted, an environment variable or a
consumed file is the shape, and it is a separate decision.

### 4. Which verbs, and where the challenge and audience come from — the second question

Three verbs, and only three: `POST /v1/challenge`, `POST /v1/enroll`,
`POST /v1/credential`. `GET /v1/issuer-cert` has no caller because both issuing
verbs return the issuer cert alongside the credential — deliberately, so a client
is never forced into a second call that could persist a fresh credential against
a stale cert. The sibling verbs, `/v1/recover` and `/v1/device/revoke` are absent
because this repository implements none of those flows, and a verb with no caller
is a verb whose first caller inherits an untested implementation.

**The challenge comes from the service, per exchange, and is never cached.**
**The audience is pinned client-side and never read from a response.** The
service's transport specification forbids putting it in a response at all, and
this client would have nowhere to read it from if it were there: a caller that
learned the audience from the same reply it is about to sign against would let
the responder choose the binding, which is the assertion-harvesting failure the
audience field exists to prevent.

Two further pins follow from the same argument and are enforced at construction
rather than documented:

- **`ServerCAFile` is required and the public root pool is never consulted.** The
  service sits behind a camouflaged front under a name chosen to be
  unremarkable, so a publicly-trusted certificate for that name authenticates the
  decoy. An empty pin would fail invisibly — everything works, against whoever is
  in the middle.
- **`http://` is refused.** The assertions authenticate this client *to* the
  service and cover no response byte, so without TLS everything valuable travels
  back unprotected and an attacker who suppressed a valid enrollment would simply
  complete it and keep the credential.

#### 4.1 `/v1/enroll` is sent exactly once, on every path, and this is the sharpest edge here

The claim code and the challenge are both single-use, and a claim code spent by a
request whose response was lost is **gone**: a retry answers `claim_rejected` and
cannot recover the credential. For a paying customer that is their access
destroyed by a helpful-looking retry loop.

So `Enroll` retries nothing about that verb — not on a timeout, not on a reset,
and **not on `unknown_challenge`**. The last one is worth saying out loud because
it is the case where a retry would in fact be safe today: the service consumes
the challenge *before* it resolves the claim code, so a challenge miss provably
costs the holder nothing. That ordering is a property of the current
implementation and **not a promise in the transport specification**, and the
failure mode if it ever changed is precisely the one this paragraph exists to
prevent. Depending on it would buy one saved round trip on a rare path and stake
a customer's access on a guarantee nobody wrote down. *(A proposal to state it
normatively is in this change's pull request; it is not this repository's
document to edit.)*

When the outcome is genuinely unknown, recovery is a **different call**:
`POST /v1/credential` with the device key still held. If it answers, the
enrollment had succeeded. `already_enrolled` takes the same path for the same
reason.

`claim_rejected` deliberately does **not**. It is the answer to a typo as much as
to a spent code, and a failed recovery attempt returns `bad_assertion`, which
counts toward a per-device-key cooldown on the service. Probing after each typo
would let a user lock their own device key out for the length of that cooldown
while hunting for the code they mistyped — turning a fixable mistake into a wait.

### 5. Where the base URL lives, and what a deployment with no account service configures — the third question

Five optional fields in `clients/fyne`'s existing JSON config:
`accountServiceUrl`, `accountServiceAudience`, `accountServiceCa`,
`deviceCredDir`, `claimCode` (plus `deviceLabel`). **A deployment with no account
service leaves them empty and configures nothing else.** That is the same posture
`admissionPubKey` already has, and it is checked by a test rather than asserted.

Three notes on the individual values:

- The URL is **operator-supplied, never discovered**. The service is reached
  through the onboarding endpoint's payment-only proxy or from inside a paid
  tunnel; reaching it directly over the open internet is, by the deployment
  model, not a path. This change runs on a testbed where direct is fine, and it
  does not *design* as though direct were the answer — nothing here probes,
  falls back to a well-known address, or treats a reachable public endpoint as
  normal.
- `deviceCredDir` **defaults to a per-user directory** rather than to empty.
  Empty is `core`'s documented in-memory mode: a fresh device identity every
  launch, which would mean an enrollment spent on a device that no longer
  exists. It defaults per-user rather than exe-adjacent for issue #118's reason,
  which bites harder here — a device key written next to a binary in a system
  directory fails on permissions, and `core`'s documented response to an
  unwritable key path is a hard construction error at connect.
- `deviceLabel` is **never derived from the machine**. A hostname is a username
  on most desktops and a real name on many, and this is the one field in the
  system a user might put a name in. The default is a word.

**A broken account-service configuration stops the connect and names itself.**
Every refusal `accountclient.New` makes is a value that cannot be defaulted, so a
typo has to be loud rather than leaving the user silently unenrolled — or, worse,
enrolled against whoever answered.

**An unreachable account service does not.** A coordinator's device gate is off
unless an operator turned it on, so making this service's reachability a
precondition for connecting would put the one service the deployment model allows
to be blockable onto the critical path of connecting. A coded refusal *about the
claim code* abandons the connect; a failure to reach the service does not.

### 6. A failed renewal is a user-visible state, not a log line — the fourth question

ADR-0046 named this as the one most likely to be skipped and the only one a user
ever sees. It is skipped when renewal failure is treated as an error, because at
the moment it happens **it is not one**: the device keeps connecting on the
credential it already holds and everything works. It becomes a failure hours
later, all at once, when that credential expires and a gate-enabled coordinator
starts refusing every connect for a reason the user cannot connect back to a
service outage they never saw.

So `Controller.CredentialState()` is **state, not an event**: enrolled, the
credential's own claimed expiry, whether renewal is currently failing, and
whether the user needs to act. It survives a disconnect deliberately — a
credential that could not be renewed is still un-renewed after the user presses
the button, and a warning that vanished exactly when they had time to act on it
would be worse than none.

The sentence escalates on **the clock**, not on what went wrong, because what
went wrong is mostly not actionable and how much time is left always is:

| remaining life | what the user is told |
| --- | --- |
| more than ~3h | Bacchus could not refresh this device's access and will keep trying; the connection is unaffected for now |
| ~3h or less | *your subscription needs attention* — and how long is left, coarsely |
| none, or unreadable | connecting will be refused / cannot tell how long the current access lasts |

The escalation threshold is much larger than `core`'s own renewal margin on
purpose. That margin is when a client *starts* trying; at the service's defaults
a credential lives 48 hours and renewal begins 6 hours out, so a device that
cannot reach the service has roughly six hours of retries before it goes dark.
Waiting until the last of those would put the warning inside the window where the
user can no longer do anything useful with it — reach a support channel, move to
a network that is not being interfered with, pay an invoice. Half the slack is
the line.

Two refusals ignore the clock and say so immediately, because no amount of
waiting fixes them: an expired subscription and a revoked device.

The wiring is a wrapper around the account client's own renewal rather than a
match on `core`'s log text. `clients/fyne` owns the closure it hands to
`Config.DeviceRenew`, so it sees the outcome directly; recognising a message
prefix would work today and would be one reword away from silently reverting a
user-facing warning to nothing.

### 7. The admission credential has nowhere to go, and that is a real gap

**This is the finding the end-to-end run existed to produce.**

The account service mints an admission credential **beside** every device
credential, in one call, over the **same window** — both expire on the same
instant. Both issuing verbs return all three values in one response.

`core.Config.DeviceRenew` returns **two** strings, and neither of them is that
one. `core/devicestore.Store.Put(cred, issuerCert)` stores two. `Config.AdmissionCred`
is read once at construction and never again. So a renewal through the seam
refreshes the entitlement and lets network membership lapse — silently, on the
same instant it would have expired anyway, with the device credential looking
perfectly healthy and a coordinator that enforces admission being entirely right
to refuse.

Nothing had ever noticed because nothing had ever held both at once.

**What this change does about it, inside its own boundary:**

- `core/accountclient` persists the admission credential in a file of its own,
  beside the device key and credential in the same `DeviceCredDir`.
- `clients/fyne` reads it at **every connect** and sets `Config.AdmissionCred`.
- `Client.RenewInto(dir)` — the closure `clients/fyne` actually wires — refreshes
  that file on every successful renewal, so the value the *next* connect reads is
  current.

**The residual, which this change does not fix:** a single engine that stays up
past a credential lifetime keeps presenting the admission credential it was
constructed with. Reconnecting picks up the fresh one; not reconnecting does not.

**What the proper fix is, and why it is not here.** Widening the seam to return
the admission credential, and `devicestore` to store it, changes signatures
`core` owns beyond "as far as the enroll purpose and the sign closure require" —
this lane's stated boundary. It is written up as a proposal in this change's pull
request rather than made unilaterally.

A smaller note in the same area, recorded so it is not mistaken for an
oversight: the credential the account service mints carries the **client** role
only, so a volunteering desktop client presenting it on an *exit* or *relay*
registration would be refused by an admission-enforcing coordinator. That is not
a regression — such a client presented nothing at all before this change, and
nothing is refused too — but it means the volunteer path still needs an
operator-minted node credential, which no `clients/fyne` field can supply today.

> **Update (2026-08-05): the proposal was taken, and the gap is closed
> (`#166`).** Everything above stands as the record of what was found and what
> was deliberately left; what follows replaces the mitigation, not the finding.
>
> **The seam and the store now carry what one response carries.**
> `Config.DeviceRenew` returns a `devicestore.Credential` — device credential,
> issuer cert, admission credential — instead of two strings, and
> `devicestore.Store.Put` takes the same value. The three go in through one
> write, which is not tidiness: it is the same argument §3.3.1 of the transport
> specification makes for returning the credential and the issuer cert together,
> applied to the third value it was already returning. A caller forced into
> separate writes can persist a fresh credential against a stale companion, and
> here the companion is what keeps the device on the network at all.
>
> **A struct rather than a third return value**, argued rather than assumed. Two
> positional strings became three, and three is where a signature stops being
> readable at the call site — but the deciding reason is the next one: a struct
> field is additive and a positional return is not. This seam has now been
> widened once, by a value the account service was already minting and this
> repository had simply never had anywhere to put; the honest expectation is that
> it happens again, and the shape should make the next one a field rather than
> another change to every filler's signature. The cost is that an embedder
> implementing the seam imports `core/devicestore`, which it was already reading
> through `core` to know what to renew from.
>
> **`Config.AdmissionCred` becomes a fallback rather than the only source.** The
> engine reads its effective admission credential per send (`admissionCred`,
> `core/devicecred_connect.go`): the configured value when there is one,
> otherwise whatever the device store holds. `registerLoop` stamps it on each
> register exactly as it already stamps the quota bit, for the same reason — a
> value baked into a template built at `Start` goes stale silently. A configured
> value always wins, so no existing deployment changes behaviour: `cmd/node`'s
> `-admission-cred` still decides, and a node with neither presents none.
>
> **`clients/fyne` stops compensating.** It no longer reads the admission
> credential off disk on every connect, no longer sets `Config.AdmissionCred`,
> and wires `Client.Renew` rather than `Client.RenewInto(dir)` — which is deleted
> along with the separate `admission.cred` file, because the reason both existed
> was that the seam could not carry the value. That was the point of fixing it
> rather than mitigating it again: the mitigation lived in the embedder, so every
> other embedder had the defect.
>
> **The residual named above is gone.** A single engine that stays up past a
> credential lifetime now presents the admission credential it holds *now*, on
> every register, list, connect, challenge and exit handshake.
>
> **One upgrade path exists and is deliberately narrow.** A device enrolled
> between `#163` and this change keeps its admission credential in the separate
> file, and reading only the JSON record would leave it presenting none until its
> next renewal — reproducing the exact lapse this change removes, on the machines
> most likely to be running `#167`. `devicestore.Open` therefore adopts such a
> file once, and the next `Put` folds it into the record. No release ever shipped
> the separate file, so this can be deleted when no such directory remains.
>
> **The role note above is unchanged and still true.** The credential the account
> service mints carries the client role only; a volunteering client presenting it
> on an exit or relay registration is still refused by an admission-enforcing
> coordinator, and the volunteer path still needs an operator-minted node
> credential. What changed is only *which* copy of that credential is presented,
> not what it authorises.

### 8. The package lives at `core/accountclient`

The candidates were `core/accountclient` and `clients/internal/accountclient`.

`clients/internal/` is refused on a checkable ground rather than an aesthetic
one: Go's `internal` rule would make the package importable only from within
`clients/`, so `cmd/node` and the mobile facade could never reach it. §3 above
leaves a `cmd/node` entry point explicitly open, and a location that makes the
open question unimplementable without a move is the wrong location.

`core/accountclient` is not in tension with `core/devicecred`'s "never contacts
the account service" doc, because that doc is about `core/devicecred` — which
still contacts nothing, imports nothing, and verifies offline. The claim that had
to be protected is `core`'s own import graph, and §2 protects it by construction.

## Testing

Three layers, and the middle one is the reason to trust the other two.

**Unit, against a fake service over real TLS.** Every refusal `New` makes; the
enrollment assertion checked under the *real* `devicecred.VerifyAssertion` with
the pinned audience, and refused under any other; `/v1/enroll` sent exactly once
across five distinct failure shapes including a hijacked connection; recovery
from an unread response; no probe after `claim_rejected`; a bare 404 read as
interference rather than as an old deployment; an unrecognized code treated as
transient so that adding one cannot strand a deployed client; the pin proven to
be doing work by pointing a client at a *different* server with a valid
certificate of its own.

**Cross-repo conformance, against the real handlers.** Everything above is a
conversation this package has with itself, which is exactly the shape Wave 21
found surviving `gofmt`, `vet`, `build`, `test`, `-race` and an octopus
combination build one repository over. So a throwaway module with `replace`
directives imports **both** repositories and runs this client against
`bacchus-payment`'s real `transport.NewClient` handlers and real
`account.Service`. Neither repository gains a dependency; what crosses the
boundary is bytes. That harness proves, in one process:

- enrollment with a real claim code minted by the real service;
- the resulting chain admitted by **the coordinator's own** `devicecred.Verifier`
  under the published development root;
- the admission credential admitted by **the coordinator's own**
  `admission.Verifier`, carrying the purchased plan;
- renewal through `core.Config.DeviceRenew`'s exact signature;
- a re-spent claim code refused with `claim_rejected`;
- an unenrolled device refused with `bad_assertion` rather than a distinct
  "unknown device".

Its output is frozen into `core/accountclient/testdata/wire_vectors.json` and
replayed by tests **in this repository**, in both directions: the real responses
must parse, and this client's request field sets must still be the ones the real
service accepted. Renaming `device_pub` would pass every self-authored test in
the package and fail there. The one field shaped like a live bearer secret is
redacted before freezing, and a test fails if it ever is not.

**End to end, on a running stack.** A real account service, a real coordinator
with its device gate enabled and an audience configured, a real exit, and the
real `clients/fyne` binary. The transcript is in this change's pull request. It
establishes that a client which had never held a credential enrolls and connects,
that a client with none is refused by the same coordinator, that traffic really
flows, that the credential survives a restart, and that renewal against the live
service produces a new serial and a refreshed admission credential.

## Consequences

- **Issue #163 closes**, and the three epics behind it are no longer built on an
  assumption. The spine has been run.
- **`clients/fyne` makes the first outbound call from this AGPL tree to the
  closed account service.** ADR-0046 §6 reason 3 is spent, deliberately, once.
  `core` itself still dials nothing.
- **The gate is now answerable by the shipping client**, so turning
  `-device-root-pubkey` on stops being a change that refuses every user. Whether
  to turn it on is an operator decision this record does not make.
- **`Config.DeviceRenew` is filled by an embedder for the first time**, which is
  what ADR-0046 predicted would happen and had never happened.
- **The admission credential's missing return path is now a known gap with a
  written proposal** rather than a latent failure nobody had met (§7).
  **Closed 2026-08-05 by `#166`** — the seam and the store carry all three, and
  `clients/fyne`'s mitigation is gone. See §7's update.
- **`cmd/node` still cannot enroll or renew.** A node-role client presents what
  is in its `-device-cred-dir` and lets it expire. Named rather than implied.
- **The claim code lives in a config file until a dialog exists.** It is erased
  on use; it is still a bearer secret at rest on the way in, on the same footing
  as the TURN password and the exit identity key that file already holds.
