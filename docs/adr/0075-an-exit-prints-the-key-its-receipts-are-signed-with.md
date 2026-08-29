# 75. An exit prints the key its receipts are signed with, and it is base64

- Status: accepted
- Date: 2026-08-29
- Tracking: issue #271
- Builds on: ADR-0021 / issue #20 (the co-signed receipt, whose identity gap this
  is the other half of), ADR-0071 §1 (a one-shot flag rather than a subcommand,
  and why), issue #240 / ADR-0069 (why the placement in `main` is structural),
  issue #103 (why an exit's node id IS its X25519 public key)
- Implementation: `core.ExitAcctIdentity` (`core/accounting.go`),
  `cmd/node -print-acct-pubkey` (`cmd/node/acctkey.go`, `cmd/node/main.go`)

## Context

`accounting.AcctKeyFromSeed` derives an exit's Ed25519 accounting-signing key
from `sha256("bacchus-accounting-v1:" || x25519Priv)` — a domain-separated hash
of the node's **private** scalar. The public half never leaves the process. It
is not in the coordinator snapshot, not in the admission credential, not in any
log line, and not computable from anything published, because the input is the
private scalar rather than the published one.

It rides inside every receipt as `ExitAcctPub`, and that is the problem rather
than the answer. `Receipt.canonical()` covers `(sessionID, seq, intervalSec,
bytes, exitID)` and **no public key**, so `Receipt.Verify()` checks both
signatures against the two keys the receipt carries *for itself*. Anyone can
generate two keypairs, write any exit id and any byte count, and produce a
receipt that verifies. This was measured rather than reasoned about: a receipt
claiming 4096 PiB under an attacker-chosen exit id passes `Verify()` returning
nil, and that receipt is frozen as a vector on the paying side.

The TOFU in ADR-0021 is sound where it was written — the exit learns the client's
key over a connection Noise_NK already authenticated — and it does not travel.
Anything off-box that pays per node therefore needs an out-of-band binding of
node id to accounting public key, checked *before* the signatures are. That
binding is an operator roster, and it shipped on the paying side one wave ago.

**It could not be filled in for a single real node, because nothing printed the
key.** Today it can be read out of a running process or not at all. This record
is the affordance that unblocks it, and nothing more: *who* is allowed onto a
roster stays an operator judgement, and no part of it is decided here.

## Decisions

### 1. An out-of-band printed value, not a wire field

The obvious alternative is to put the accounting key in the coordinator snapshot,
or in the admission credential, so that it arrives with everything else that
identifies a node. That is a real improvement for a *different* consumer — a
client could then bind the key it is about to co-sign against, rather than
accepting whatever the exit presents — and it is not this.

It is refused here for two reasons and only the second is durable. The first is
scope: the snapshot and the credential are both wire formats behind an owner test
that has not run, and a change to either is a change every coordinator, client
and node has to agree about at once. The second is that **it would not discharge
the requirement even if it shipped**. A roster exists because the payer trusts an
operator's assertion, not a coordinator's; a key that arrives over the same
channel as the claim it is meant to authenticate is not an independent binding,
whatever else it improves. Publishing the key would let a client check its
counterparty; it would not let a payer decide whom to pay.

So the wire is untouched, and the snapshot question is a separate card rather
than a deferred part of this one.

### 2. What is printed, exactly

`bacchus-node -print-acct-pubkey -exit-key <64 hex>` writes three lines to stdout
and exits zero. Below is the real output for the all-`11` key the tests in `core`
already use as a fixture — an illustration of the shape, not any node's values:

```
id: 7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13
acct_pub: iqKTaDMxZ1gFEt+L/GYQjZt76OuimkimAT4K0mTz4bA=
acct_pub_hex: 8aa29368333167580512df8bfc66108d9b7be8eba29a48a6013e0ad264f3e1b0
```

**This section is the contract.** A consumer building payouts on top of a roster
needs the format, not the implementation, so it is stated here rather than left
to be read out of the code:

- **`id`** — 64 lowercase hex characters, the node's X25519 static public key.
  This is byte-for-byte what a receipt's `ExitID` carries. See §3.
- **`acct_pub`** — the 32-byte Ed25519 accounting public key in **standard
  base64, with padding**, which is the encoding `encoding/json` gives an
  `ed25519.PublicKey` (a `[]byte`) on both sides of the seam. It is named for the
  roster field it belongs in so that transcription is mechanical.
- **`acct_pub_hex`** — the same 32 bytes in lowercase hex. Printed because every
  other key this project prints or accepts is hex (`-mesh-pubkey`,
  `-admission-pubkey`, `cmd/coordinator -print-bootstrap-pubkey`), so a key
  shown only in base64 would read as a mistake, and because hex is what a person
  compares by eye.

Three `field: value` lines and nothing else — no banner, no prose, no trailing
advice. stdout is what an operator copies out of and what a script reads; the
explanation lives in the flag's own `-h` text and in this record.

**The encoding is the part worth being loud about.** Issue #271 proposed printing
`hex(...)` alone, and a roster's `acct_pub` field is base64. The failure is not
silent — 64 hex characters are all inside the base64 alphabet, so the string
decodes rather than erroring, to **48 bytes**, and a roster refuses it on length —
but it is an hour of somebody's evening spent on a value that looks right. Naming
the base64 form after the field, and the hex form after what it is, is the whole
of the fix.

### 3. The identity is the node id, and it is not the one the operator chose

The roster keys on a node id, and `Receipt.ExitID` is a bare string, so what a
real exit puts there had to be established from the call sites rather than
assumed from the field name.

`handleAcctStream` passes `e.cfg.ID` to `accounting.ExitPropose`. `core.New` sets
`cfg.ID = hex(exitKey.Public)` for the exit role and **overrides any configured
`ID`** — an exit's node id must *be* its X25519 public key or no client can run
Noise_NK against it (issue #103). Since accounting only ever derives a signing key
for the exit role, and that role always takes this branch, a receipt's `ExitID` is
always the hex public key. `-id` is inert for an exit and always was.

That matters because of how the roster fails. An id that does not match what
arrives is not an error anybody sees: receipts are refused one at a time into a
rejection tally so that one bad line in a journal does not abandon ten thousand
good ones, and the node simply **earns zero**. An operator who has `-id
exit-alpha` in a unit file and reads it back as this machine's identity gets a
roster row that matches nothing, forever, silently. So the one-shot prints the
derived id and there is no flag that makes it print anything else, and the
zero — not merely the mismatch — is asserted in a test.

### 4. A one-shot flag, and structurally above the demotion watchdog

A flag rather than a subcommand, for ADR-0071 §1's reason unchanged: `-list`,
`-enroll` and `-version` are this binary's existing "do one thing and quit", and
adding `os.Args[1]` dispatch would change how every existing invocation parses to
gain nothing.

It returns **above** `checkStartupDemotion`, beside `-version`, rather than being
added to the `oneShot` predicate below it. This is the fourth one-shot, and the
predicate is exactly the hand-maintained list issue #240 said somebody would
eventually forget; a one-shot that returns before the watchdog runs cannot inherit
the bug rather than being excused from it. `cmd/node/oneshot_probation_test.go`
discovers one-shots from the binary's own `-h` output and holds every one of them
to the same assertion, so the flag is covered by the property whichever way it is
exempted — and its `knownOneShots` floor now names four.

It needs nothing else from the process. No coordinator, no engine, no bound port,
no writable directory, not even the resolved role set: an exit's node id is its
public key however the role was arrived at, so `-volunteer-exit` and `-role exit`
produce the same answer and neither has to be supplied.

### 5. An absent `-exit-key` is refused, not generated

`core.exitStaticKey` mints a fresh keypair when handed an empty string. That is
correct where it lives — a throwaway lab exit whose regenerated identity fails a
client's admission check immediately, in front of the person who caused it — and
it is the worst possible behaviour here.

A one-shot that fell through to it would print a perfectly well-formed id and key
belonging to an identity the process discards on return, indistinguishable from a
usable pair. The operator pastes it into a roster, every receipt that arrives
verifies, and the node earns nothing. So both `core.ExitAcctIdentity` and the flag
refuse an empty key, with a message that says why rather than what: *a node with
none generates a fresh one every start, so there is no stable id or key to
publish.* The refusal writes nothing to stdout.

The check is in both places deliberately. `core` cannot name a flag — it is
reached from `clients/fyne`, where there is none — and an operator who typed a
flag and is told a Go struct field is unset has not been helped.

### 6. Derived, not read off a constructed engine

`ExitAcctIdentity` recomputes what `New` computes rather than building an `Engine`
and reading `acctKey` and `cfg.ID` off it, because an `Engine` needs an advertise
address, a coordinator and a writable `AcctDir` before it exists.

A re-derivation is exactly the kind of thing that keeps answering confidently
after the original moves, so the repetition is pinned rather than trusted:
`core/accounting_identity_test.go` builds a real exit engine, runs the real
sentinel round trip through it, and compares the receipt that comes out — its
`ExitID` against the printed id, its `ExitAcctPub` against the printed key, and
the exit's signature **re-verified against the printed key** rather than against
the one the receipt carries for itself. That last check is the one that matters,
because `Verify()` passes for a receipt nobody in this fleet minted; substituting
the pinned key and asking again is what turns "internally consistent" into
"signed by the key that box prints", which is the only question a roster asks. A
control with one flipped byte proves the check is not vacuous.

## Consequences

- **The roster can be filled in.** One command per node, run on the box, output
  transcribed into two fields. The paying side's reconciler stops being unusable
  for want of a value.
- **The affordance is out of band and stays that way.** Nothing about this makes
  the key available to a client, a coordinator, or anyone the operator did not
  hand it to. Whether the snapshot should carry it — which would let a client bind
  the key it is about to co-sign against — is a separate card, and a wire change.
- **Two encodings of one key are printed.** This is a deliberate cost: it is one
  more thing to get wrong, and the alternative was one form that is wrong in half
  the places it gets pasted. The field names carry the distinction.
- **The output shape is now a contract with another repository.** Payout work is
  being built on the roster this unblocks; §2 is what it may rely on. A change to
  those three lines is a change to that contract, not a formatting preference.
- **Nothing here helps a node that has no persistent exit key.** That node has no
  stable accounting identity to publish, and the correct answer is a refusal
  rather than a value. An operator who wanted one has to give the node a key
  first, which is what `-exit-key` has always been for.
- **Receipts still only exist for direct-mode sessions on a node with `-acct-dir`
  set** (ADR-0021's stated limit, unchanged). A roster row for a node that is not
  metering anything is a correctly-formed row that never matches a receipt,
  because there are none. The flag's help says so; nothing enforces it, since the
  one-shot deliberately does not read the serving configuration.
- **Not done, and named:** `docs/design/accounting-stub.md`'s *Identity* and
  *Configuration* sections still describe the accounting key as something that
  only ever exists inside the process, which was true when they were written and
  is no longer. They should gain a sentence pointing at this flag and this record;
  that edit is a follow-up rather than part of this change.
