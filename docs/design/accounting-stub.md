# Co-signed usage receipts (metering stub)

Status: implemented (issue #20, ADR-0021). Lives in
[`core/accounting`](../../core/accounting) (protocol/crypto) and
[`core/accounting.go`](../../core/accounting.go) (engine wiring).

## Problem

Before any real payout design is worth doing, v1 needs to know whether
"accounting" is buildable at all: can a client and an exit agree on how much
service was delivered without either one being able to unilaterally invent
the number. This is a stub on purpose — payouts, wallets, tokens, and real
anti-fraud (staking/slashing, collusion resistance) are v2. The only property
this needs to prove is: a receipt should not be producible by one side alone,
and it should not survive tampering.

## Approach

**Co-signing, not a ledger.** The exit signs a claim ("N bytes over interval
T"); the client either cosigns the exact same claim or rejects it. A
`Receipt` verifies only if both signatures check out (`Receipt.Verify`), so
holding a valid receipt is itself proof of the other party's cooperation.

**Reusing the existing E2E preamble instead of a new wire protocol.** The
client's SOCKS-tunnelled streams already run `clientHandshake`/`exitHandshake`
(Noise_NK, `core/e2e.go`) and send a `host:port` target as the first encrypted
message; the exit dials that target and splices. The accounting exchange
reuses this verbatim: the client periodically opens one more stream and sends
`acctSentinel` — a reserved `.invalid` (RFC 2606) target that can never be a
real destination — instead of a real target. `exitTerminate` (in
`forwarder.go`) checks for the sentinel *after* the handshake completes and
branches to `handleAcctStream` instead of dialing TCP. `core/e2e.go` itself
needed no changes: same handshake, same framing, one more recognized value for
an already-existing string.

**Why the exit proposes, not the client.** The exit can never dial the
client — no listener, often behind NAT, the same reason relay mode exists at
all (a relay splices because the exit can't reach the client directly
either). Every accounting round trip is therefore client-initiated, exactly
like every proxied stream is. Within that round trip, the exit sends its
claim first because it is the metered/paid party with the incentive to
request confirmation, and because it already holds an independent count to
propose (see below) — the client only needs to check a number it received,
not invent one to send first.

**Byte counting.** Both sides wrap the `io.Copy` calls that already move
proxied traffic (`client.go`'s `handleSocks`, `forwarder.go`'s
`exitTerminate`) with `accounting.Counter.CountReads`, an atomic-counter
wrapper that is a no-op when accounting is disabled (nil `*Counter`, checked
once per call site, not per byte). `Counter.Delta()` partitions the running
total into non-overlapping intervals as each side reports.

**Direct-mode only — a real, stated limitation, not an oversight.** In relay
mode, `relayPipe` splices the client-facing stream to a plain TCP dial at the
exit's advertised address (`serveExit`'s listener); the exit accepts that
connection with no coordinator session id attached at all — relaying carries
bytes, not metadata about which session they belong to. Threading a
correlation id onto that wire is a real protocol change (it would touch
every relayed connection, not just accounting ones), which is out of
proportion for a stub. `handlerFor` only threads a non-empty `sid` through
the direct-mode path; `exitTerminate` and `handleAcctStream` both treat an
empty `sid` as "nothing to attribute this to" and skip accounting rather than
guessing. Concretely: **relay-mode sessions run today exactly as before this
issue, with accounting simply off.**

**Identity.** The exit's accounting-signing key is Ed25519, derived from its
existing X25519 Noise identity seed via a domain-separated hash
(`accounting.AcctKeyFromSeed`) — stable across restarts like the node id
itself, but cryptographically independent of the X25519 key. Reusing one
keypair for both Diffie-Hellman and signing is a well-known cross-protocol
footgun; deriving two independent keys from one seed avoids it for the cost
of one `sha256.Sum256` call. The client's accounting key is a fresh
`ed25519.GenerateKey` per session — no persistent identity, matching
Noise_NK's anonymity property (ADR-0009): nothing links a client's receipts
across separate sessions.

Neither accounting pubkey is folded into what gets signed (`canonical`
excludes them). Each side signs only what it can itself attest to — session
id, interval sequence, byte count, exit id — which sidesteps an ordering
problem: the exit has to sign its claim before it has ever seen the client's
pubkey (the client doesn't reveal one until after it has checked the claim),
so requiring the exit to also sign the client's pubkey would be impossible at
the point it signs.

**Reconciliation policy (`accounting.Reconcile`).** The client's anti-fraud
check is exact match between its own count and the exit's claim. This is
deliberately the simplest, most conservative starting point:

- Client and exit count the same wire bytes on the same stream, so the honest
  case agrees.
- A mismatch skips that interval's receipt rather than silently smoothing it
  over with a tolerance window — best-effort (the next interval gets another
  chance), and it keeps real-world mismatch rates visible in the logs before
  anyone picks a tolerance number.
- The natural next refinement, once mismatch-rate data exists: an asymmetric
  rule (reject only if the exit's claim exceeds what the client itself saw —
  an exit *under*-claiming only shortchanges its own future payout, not a
  fraud vector against the client), or a small tolerance window for benign
  timing skew between two independently-ticking processes. Picking either
  needs data this stub is what produces, not a guess made before it ships.

**Persistence.** An append-only JSONL file per role (`receipts-exit.jsonl`,
`receipts-client.jsonl` under `Config.AcctDir`), flushed on every append. No
database: the current stack is Go binaries + systemd (see the workspace
guide), and a receipt history is exactly the kind of small, append-only
record a flat file suits until that changes.

## Configuration

`Config.AcctDir` (`-acct-dir`) gates the entire feature: empty disables it
completely (no counters, no extra streams, no files — every caller/test that
predates this field is unaffected). `Config.AcctIntervalSec` (`-acct-interval`,
default 60) sets the reporting cadence while enabled.

## Testing

`core/accounting`'s tests cover the protocol/crypto in isolation over
`net.Pipe`, mirroring `core/e2e_test.go`'s style: a matching round trip,
a mismatched round trip (both sides end up with nothing), a tampered receipt
failing `Verify`, and a receipt with only one valid signature failing
`Verify` — the two acceptance-criteria checks from issue #20 stated directly
as tests. `core/accounting_test.go` proves the engine wiring: the sentinel is
recognized and produces a persisted, verifying receipt in direct mode; an
empty-`sid` (relay-forwarded) connection produces no receipt; and the full
client-side periodic loop — ticker, `OpenStream`, handshake, cosign, persist —
runs correctly against a fake exit built from the existing `loopbackTransport`
test harness (`transport_test.go`), with no real WebRTC or coordinator
needed, consistent with how the rest of `core` is tested.

## Follow-ups (not this issue)

- Relay-mode accounting: needs a correlation id on the relay↔exit wire.
- A tuned `Reconcile` policy once real mismatch-rate data exists.
- Sampling/audit tooling over the persisted receipt stores (the issue's
  "cross-check hook" — the mismatch path already logs both counts; nothing
  reads that data yet beyond the log).
- Everything in ADR-0021's Consequences that is explicitly v2: payouts,
  wallets, tokens, commission, collusion-resistant anti-fraud.
