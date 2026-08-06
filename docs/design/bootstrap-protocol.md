# Cold-start bootstrap — wire protocol

- Status: **implemented (`old #18`, `core/coldstart`; port-blended by issue #30;
  FINGERPRINT shape parity by issue #46)**
- Date: 2026-07-03
- Companion decision records: [ADR-0013](../adr/0013-bootstrap-wire-protocol.md)
  (wire protocol), [ADR-0017](../adr/0017-blend-bootstrap-onto-shared-stun-turn-port.md)
  (shared-port transport)
- Parent design: [rendezvous-cold-start.md](rendezvous-cold-start.md) — this
  document is the concrete answer to that document's open question #3
  ("per-user-secret provisioning crypto").

This is the byte-level spec for the first-contact exchange: a client, holding
only a per-user secret and the coordinator's public key, fetches a signed
directory snapshot over a single STUN-shaped UDP round trip.

## 1. Framing

The request and response reuse RFC 5389 STUN message framing exactly (20-byte
header: type, length, magic cookie `0x2112A442`, 96-bit transaction ID;
TLV attributes padded to 4 bytes) — **not** RFC 5389 in full. There is no
SASLprep, no long-term credential negotiation, no error responses, and no
interop goal with third-party STUN clients: we control both ends, and the
only requirement is that the packets are byte-shape-indistinguishable from a
real ICE connectivity check to a censor doing protocol-shape analysis (design
doc §2, fingerprint axis).

## 2. Request — Binding Request (`0x0001`)

An **unauthenticated** request (plain reachability check, what
`cmd/coldstart-probe` sends) carries only `FINGERPRINT`.

An **authenticated** bootstrap request additionally carries, in this order:

| Attribute | Type | Value |
|---|---|---|
| `USERNAME` | `0x0006` | the per-user secret ID, hex, 16 ASCII chars (`SecretIDLen` = 8 bytes) |
| `MESSAGE-INTEGRITY` | `0x0008` | `HMAC-SHA1(secret, message-up-to-here)`, 20 bytes, RFC 5389 §15.4 layout (length field temporarily covers up through this attribute) |
| `FINGERPRINT` | `0x8028` | `CRC32(message-up-to-here) XOR 0x5354554e`, RFC 5389 §15.5 |

`secret` is never sent — only the HMAC computed with it, exactly as a real
ICE short-term-credential check would authenticate a connectivity check with
`ice-ufrag`/`ice-pwd`. We reuse the attribute *positions and types*, not RFC
5389's SASLprep credential derivation (§10.4) — our key is the raw per-user
secret bytes.

## 3. Response — Binding Success Response (`0x0101`)

Always, regardless of whether the request authenticated:

| Attribute | Type | Value |
|---|---|---|
| `XOR-MAPPED-ADDRESS` | `0x0020` | the request's observed source address, RFC 5389 §15.2 |

**Only if `MESSAGE-INTEGRITY` validated against a known secret**, additionally:

| Attribute | Type | Value |
|---|---|---|
| `SNAPSHOT` | `0xC001` (comprehension-optional, vendor) | the signed snapshot bytes, §4 below |

Always last, after either of the above:

| Attribute | Type | Value |
|---|---|---|
| `FINGERPRINT` | `0x8028` | `CRC32(message-up-to-here) XOR 0x5354554e`, RFC 5389 §15.5 |

This is the core defense (design doc principle #4, "authenticated first
packet"): the response to a bad or missing credential is **byte-for-byte**
what a plain public STUN server sends. A prober without the secret — even an
active one that connects and pokes — cannot distinguish "wrong secret" from
"right secret, nothing to say" from "this isn't a bootstrap endpoint at all."
Only a party that already holds a valid secret ever observes the `SNAPSHOT`
attribute on the wire (see [`core/coldstart/wire_test.go`](../../core/coldstart/wire_test.go)'s
`TestUnauthenticatedAndAuthenticatedResponsesAreShapeIdentical`, which asserts
this at the byte level). `FINGERPRINT` is unconditional — present whether or
not `SNAPSHOT` is — so it carries no signal of its own; it exists purely so
this response is shape-identical to pion/turn's own Binding Success response,
which always carries one too (issue #46, see
[`TestBuildResponseMatchesPionTurnShape`](../../core/coldstart/wire_test.go)).

This is a single-round-trip design (not two packets): simpler to implement
and test, and the indistinguishability property only needs to hold for an
observer who lacks the secret — an adversary who already holds a valid
secret already knows they're talking to Bacchus (design doc's threat model
does not claim protection against a global passive adversary who has
captured other users' authenticated exchanges; that is explicitly out of
scope, see design doc principle #3).

## 4. Snapshot format and signing

```go
type Snapshot struct {
    Version   int
    IssuedAt  time.Time
    ExpiresAt time.Time
    Entries   []Entry // {Role, ID, Country, Addr}
}
```

Wire form: canonical `encoding/json` of `Snapshot`, with a 64-byte Ed25519
signature appended (`ed25519.SignatureSize` is fixed, so no length prefix is
needed — the last 64 bytes are always the signature). The client verifies
against the coordinator's public key (baked into the client's config/invite,
never fetched over the same channel it's meant to authenticate) and checks
`ExpiresAt`. `cmd/coordinator` re-signs the current registry every 10s
(`snapshotRefresh`) with a 5-minute validity window (`snapshotTTL`), so a
cached snapshot goes stale fast enough that recovery (design doc §4.3,
mesh-walk) has to actually happen rather than living forever on cached data.
A mesh-walk courier honors that same window on the serve side (issue #115): it
withholds a cached snapshot once it has passed `ExpiresAt` and answers as a plain
STUN endpoint, so its 30s refresh guarantees freshness only while its coordinator is
reachable — past the TTL it serves nothing rather than entries that may be gone.

## 5. Per-user secret and invite encoding

`SecretID` (8 random bytes, hex-encoded as the wire `USERNAME`) and `Secret`
(32 random bytes, the HMAC key) are minted by `cmd/coldstart-issue` and
handed to the coordinator's secrets store (a flat `{secretID: hex(secret)}`
JSON file, hot-reloaded every 30s — see `core/coldstart/server.go`). There is
no vouch/trust system wired to this store yet (every entry is trusted
equally); that is tracked as follow-on work, see §6.

**The risk in that file is on the write side, not the read side** (issue #178).
A coordinator that reads an unparseable secrets file keeps the empty store
`startTurnAndBootstrap` seeded, so nobody can bootstrap — fail-closed, noisy,
and repaired by the next tick. But `cmd/coldstart-issue` is read-modify-write
over the whole store: load, add one, write all of it back. A run that dies
mid-write therefore does not lose an update, it loses *every secret ever
issued*. Each of those is a random value living in exactly two places — this
file and a `bacchus1:` invite already handed to a person — so losing the
server's copy does not invalidate the invites in any orderly way. It makes each
one unauthenticatable, with no record of what was issued and no way to tell a
holder from an attacker. In the private-seed phase
(`rendezvous-cold-start.md` §5.8) that is the entire user base.

Two rules follow, both enforced in code rather than by care:

- `MemStore.SaveFile` **installs** the file rather than rewriting it. A complete
  copy is staged under `.<name>.tmp*` in the target's own directory, flushed, and
  renamed over the target, so the path never holds a partial file and a killed
  writer leaves the previous one intact. Same shape and same reasoning as the
  revocation file's write (`node-admission.md` §Revocation, issue #168), with the
  polarity reversed: there an unreadable file means *nothing is revoked*, here it
  means *nobody may bootstrap*.
- `cmd/coldstart-issue` holds a `<path>.lock` for the duration of one
  read-modify-write. Atomicity is a promise to a *reader*; it says nothing about
  two issuers racing, where each writes a perfectly well-formed file and the
  second lands without the first's entry. That failure leaves no torn file to
  notice, so it is prevented rather than detected.

An **invite** packs everything a fresh client needs — coordinator address,
secret ID, secret, coordinator public key — into one copy-pasteable /
QR-able string: `bacchus1:` + unpadded base64url of
`[version:1][secretID:8][secret:32][pubkey:32][coordinator addr:remaining]`.
It is not itself signed: a per-recipient secret is only useful once it
authenticates a fetch against a coordinator that already knows it, so a
censor harvesting invite text gains nothing to forge — the invite's
integrity comes from the out-of-band channel it travels over (design doc
§4.2.2), not from a signature on the invite itself.

## 6. What this does not cover (tracked separately)

- ~~Wiring the bootstrap listener onto the same port/process as the real
  STUN/TURN server~~ — **resolved by issue #30 / ADR-0017.** `cmd/coordinator`
  now binds one UDP port (default `:3478`) shared by both: a socket-level
  demux (`core/coldstart.Demux`) answers bootstrap-shaped Binding Requests
  (ones carrying the `USERNAME` attribute) directly, and passes every other
  packet — ordinary Binding Requests, and all TURN message types — through
  to `pion/turn` unmodified. `cmd/turn` no longer exists as a separate
  binary. ~~One remaining shape gap from this merge: `core/coldstart`'s
  Binding Success Response never carried a `FINGERPRINT` attribute, unlike
  pion/turn's own, despite both now being observable on the same port~~ —
  **closed by issue #46:** the response now always ends with `FINGERPRINT`
  too, see §3 above.
- **Mesh-walk recovery** (design doc §4.3): any known node handing a
  coordinator-signed snapshot onward. This implementation only covers
  cold-start from a coordinator directly; mesh-walk extends issue #6
  (coordinator pool) and is filed separately.
- **QR code generation / personalized installers** for invite distribution —
  `cmd/coldstart-issue` prints a string; turning that into a scannable QR
  image is a small, separable UI task.
- **Trust/vouch gating of who can call `cmd/coldstart-issue`** — v1 treats
  every operator-issued secret as equally trusted, matching the design
  doc's "curated private seed" launch phase (§5.8); the full vouch graph
  (§5.4) is unbuilt.
