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

The exit's public half can be read off a box with `bacchus-node
-print-acct-pubkey` (ADR-0075); it is **not** derivable from anything
published, because the seed is the X25519 *private* scalar. That flag is the
only route to it, and an operator roster pinning node id to accounting key is
what the printed value is for — a receipt verifies against the keys it carries
for itself, so nothing else binds one to a node.

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

## What a receipt discloses, and why the client's key is fresh every session

A receipt is not a private record. The exit journals its copy, and that journal
is what reaches the account service's host at payout — so every field on a
`Receipt` is disclosed to the one party the account model works hardest to keep
from assembling a per-user profile. The payout model on that side states the
consequence as "receipts carry no user identity", and the public privacy
statement leans on it.

That claim is true, and it is true for exactly one reason: **`ClientAcctPub` is
generated fresh for every session.** It is not an absence — a receipt *does*
carry an `ed25519` public key belonging to the client, right next to
`SessionID`, `Bytes` and `ExitID`. The claim survives on the key's lifetime
instead.

The generation site is `Engine.startAccounting` (`core/accounting.go`), which
calls `ed25519.GenerateKey(rand.Reader)` and passes the result to
`runClientAccounting` as an argument. The key reaches no `Engine` field, is not
written to any file, and is unreachable once that goroutine returns.
`Engine.connectVia` calls `startAccounting` once per established
direct-disposition path, so one session gets one key and the next gets another —
including across a reconnect, which mints a new one rather than resuming.

Read the caller, not the comment: `runClientAccounting` takes the key as a
*parameter*, so its own doc line about freshness is a statement about a value it
was handed and cannot vouch for. This section, `Receipt`'s doc comment and
`core/accounting_client_key_test.go` all point at `startAccounting` for that
reason.

**What would break if it were stable.** Every journal on the account-service
host would hold a persistent per-client identifier beside a session id and a
byte count. Nobody would have filed those as user records, and they would be
one join away from a complete history of when a user connected and how much
they moved — the profile `account-model.md` §2 exists to prevent, assembled out
of files nobody thought of as records.

**Two consequences worth stating.** The coordinator puts
`hex(Receipt.ClientAcctPub)` into a capacity sample as `Attester`
(`cmd/coordinator/capacity_feed.go`), to cap how much one attester can move a
node's rating. That is harmless for privacy *because* the key is per-session —
and it also means the attester cap is per-session rather than per-client, so the
real Sybil cost there is the AS bound beside it, not this field.

The exit's key is the mirror image and stable on purpose: an exit is the metered
party a receipt must be attributable to across sessions (`AcctKeyFromSeed`,
ADR-0075). The two keys are asymmetric because the two parties are.

This settles claim 2 of `bacchus-vpn/bacchus-payment#98`.

## Configuration

`Config.AcctDir` (`-acct-dir`) gates the entire feature: empty disables it
completely (no counters, no extra streams, no files — every caller/test that
predates this field is unaffected). `Config.AcctIntervalSec` (`-acct-interval`,
default 60) sets the reporting cadence while enabled.

`-print-acct-pubkey` (with `-exit-key`) is a one-shot rather than a setting: it
prints `id`, `acct_pub` and `acct_pub_hex` and exits, touching no directory and
starting nothing. It is independent of `-acct-dir`, since the key exists
whether or not this node is recording anything.

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

The per-session key property above is pinned separately, because a doc line
near a seam is not evidence of the seam's semantics.
`core/accounting_client_key_test.go` runs **two** real accounting round trips
over two sessions on one client engine and compares the key on the receipts
that come out — so it measures the observable property rather than the
variable, and a `startAccounting` that cached its keypair for a plausible
reason would still satisfy every doc comment in the package and fail there. It
also checks the accounting key is never the *device* key (stable by design, and
the most likely shape of the mistake), and enumerates `Engine`'s `ed25519`
private-key fields so a new place for a client identity to live is reported
rather than acquired. `core/accounting/receipt_surface_test.go` pins the field
list the whole argument is made about: a field added to `Receipt` later would
otherwise be covered by no test and by no sentence anywhere, and would simply
start appearing in journals.

## Follow-ups (not this issue)

- Relay-mode accounting: needs a correlation id on the relay↔exit wire.
- A tuned `Reconcile` policy once real mismatch-rate data exists.
- Sampling/audit tooling over the persisted receipt stores (the issue's
  "cross-check hook" — the mismatch path already logs both counts; nothing
  reads that data yet beyond the log).
- Everything in ADR-0021's Consequences that is explicitly v2: payouts,
  wallets, tokens, commission, collusion-resistant anti-fraud.
