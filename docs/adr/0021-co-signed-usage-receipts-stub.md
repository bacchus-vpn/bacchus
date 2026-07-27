# 21. Co-signed usage receipts (metering stub, no payout)

- Status: accepted
- Date: 2026-07-03

## Context

v1 ships accounting as a stub, not a feature (`docs/design/v1.md`: "payments
are a stub in v1... enough to prove the accounting hook works, no payout
logic"). Before any real payout/token design is worth doing, the riskiest
open question is narrower: can a node and a client agree on how much service
was delivered without either one being able to unilaterally invent the
number? Issue #20 (milestone M4) scopes exactly that, and nothing past it —
no payouts, no crypto wallets, no blind tokens, no commission.

## Decision

A client and the exit it is connected to each sign a claim of "N bytes over
interval T"; a `Receipt` is only valid once both signatures verify over the
same claim, so neither side can produce one alone. The exit proposes (it
already independently counts bytes on every stream it terminates); the client
either cosigns or rejects, based on comparing the claim to its own count
(`accounting.Reconcile` — exact match for this stub, see
[accounting-stub.md](../design/accounting-stub.md) for the tolerance-window
trade-off deferred here). Receipts persist as an append-only JSONL file per
role (no database yet, per this workspace's current stack).

The exchange reuses the existing Noise_NK preamble in `core/e2e.go` verbatim:
the client opens one more stream per interval and sends a reserved
`.invalid` sentinel target instead of a real `host:port`; the exit recognizes
it and hands the authenticated channel to the accounting exchange instead of
dialing TCP. This needed no changes to the E2E handshake or its wire format.

Scope is **direct-mode sessions only**. In relay mode the exit receives a
relay-forwarded connection as a bare spliced TCP stream with no session id
attached — there is nothing to attribute counted bytes to. Closing that gap
means putting a correlation id on the relay↔exit wire, which is real
follow-up work, not something this stub's blast radius should include (see
design doc).

Key material: the exit derives a stable Ed25519 accounting-signing key from
its existing X25519 node identity (domain-separated hash, not the raw key
reused — mixing DH and signature use of one keypair is a known footgun). A
client generates a fresh Ed25519 keypair per session; it has no persistent
accounting identity, matching Noise_NK's anonymity property (ADR-0009).

## Consequences

- Satisfies #20's acceptance test directly: after a session, a co-signed
  receipt exists that neither side could have produced alone, and a tampered
  byte count fails verification (`core/accounting`'s test suite exercises
  both).
- Relay-mode sessions run with accounting silently off, not degraded —
  tracked as a named follow-up rather than a silent gap.
- This is best-effort proof, not trustless accounting: a volunteer exit
  colluding with a fake client can still inflate a receipt both are willing
  to sign. Real anti-fraud (staking/slashing, collusion resistance) is v2,
  same as payouts.
- `Reconcile`'s exact-match policy will sometimes skip a legitimate interval's
  receipt on ordinary timing skew between two independently-ticking
  processes. Acceptable for a stub (the next interval gets another chance);
  picking a tolerance needs real mismatch-rate data this stub is what
  produces.
- `Config.AcctDir` gates the entire feature (empty = off, the default) —
  every caller and test that predates this field sees no behavior change.

> **Update (2026-07-22, issue #158): one client-asserted bit added to `Receipt`.**
> The capacity feed (ADR-0041) reuses this receipt as its throughput sample — `Bytes/
> IntervalSec` is a co-signed throughput — but needs one datum the byte count cannot
> carry and the exit cannot verify: *was the client demand-saturated this interval*
> (design §5.3). So `Receipt` gains a `Saturated bool` (`omitempty`), and it is
> deliberately **NOT co-signed**: it is absent from `canonical()`, so both existing
> signatures are unchanged and every receipt predating #158 is byte-for-byte identical
> on disk and on the wire. The exit cannot attest "I wanted more", so folding the bit
> into the co-signature would be meaningless.
>
> Instead the bit is bound to the co-signing **client** by a *separate* signature —
> `SignReport`/`VerifyReport`, over the receipt claim plus the bit, under a domain tag —
> which the capacity-report carries to the coordinator. This is what stops a node that
> holds the finished receipt (it has `ClientAcctPub` and `ClientSig`, but not the
> client's private key) from forging a report or flipping the bit to inflate its own
> rating. The bit remains unilateral and unverifiable in the sense that a *defaming
> client* can assert it while idle — that is the accepted weakness in design §8.2, and
> it only ever lowers a rating.
