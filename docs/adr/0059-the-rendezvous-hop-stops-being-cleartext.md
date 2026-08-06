# 59. The rendezvous hop stops being cleartext, and a transport identity carries a version

- Status: accepted (issues #175 slice 1, #176, #189)
- Date: 2026-08-06

## Context

### The finding, which was on no card

`#175` said the coordinator hop has *"no transport pool, probe, or protocol
choice."* True, and understated. `core/coordpool.go`'s `coordLink.send` is:

```go
b, _ := json.Marshal(m)
...
if _, err := l.conn.Write(b); err != nil {
```

and `cmd/coordinator` read it with `net.ListenUDP` / `ReadFromUDP` /
`json.Unmarshal`. **The first packet a Bacchus client ever sent was plaintext JSON
over raw UDP.** A DPI box saw the literal bytes `{"type":"connect"` in a UDP
payload to one port. `dialPool` uses `net.DialUDP` and there was no second path.

Everything the transport ladder protects is *downstream* of that. A censor does
not need to defeat REALITY or WebRTC camouflage: one signature on the rendezvous
datagram drops every client before the protected ladder ever runs. The exit path,
by contrast, has raced candidates, sustained-flow validation past the
destination-freeze threshold, and a per-`NetworkKey()` learned winner.

### The camouflage existed and was wired to the wrong hop

`core/dtls_fingerprint.go` and `core/ice_fingerprint.go` ship Chrome/Firefox DTLS
profiles and browser-shaped ICE credentials. Their **only** caller is
`core/transport_webrtc.go`, the *data-plane* transport. `Config.DTLSFingerprint`
never reached `core/coordpool.go`.

`docs/design/rendezvous-cold-start.md` §4.1 names *"Randomize the DTLS/ICE
fingerprint"* a hard requirement **for this hop**, requires *"a transport pool
with per-user failover … the same partial-transport-union principle as the data
plane"*, and calls the hop **"the boss fight"**. None of that was at this hop.

### What this record is a slice of

Decision A was first ruled "camouflage only" on a cost estimate that turned out
to be wrong in the expensive direction — there was no DTLS at this hop to point
the profiles at, and making one meant making the coordinator a DTLS server. It
was re-ruled **A2-c: the hop goes genuinely DTLS/WebRTC-shaped**, over three
slices:

| Slice | What |
|---|---|
| **1 — this record** | The shape, the budget, and the **coordinator half**: accept the new shape alongside raw JSON on one port |
| 2 | The **client half** speaks the new shape; raw JSON becomes the fallback |
| 3 | Raw JSON deprecated behind the window; the fingerprint profiles apply per `Config.DTLSFingerprint` |

The coordinator half is first because it is backward-compatible and deployable on
its own. The client half is not.

## Decision

### 1. The shape is DTLS on the signaling port, and the destination is WebRTC-shaped

**Ruled S2, built as S1 first.**

The three options as first framed — DTLS-over-UDP, a WebRTC data channel, or
STUN-shaped — are off by one, and the correction changes the answer. On the wire,
**STUN and DTLS are not alternatives; they are the two halves of one WebRTC
flow.** A real endpoint runs ICE connectivity checks on a 5-tuple and *then* DTLS
on that same 5-tuple. A DTLS ClientHello arriving from nowhere is *DTLS-shaped*,
not *WebRTC-shaped*, and a classifier reads the difference for free.
`core/ice_fingerprint.go` has no job at this hop without the STUN half.

So the destination is both:

- **S1 — DTLS on the signaling port, demultiplexed from raw JSON.** Built here.
- **S2 — a fixed STUN connectivity-check prefix on the same 5-tuple.** Filed as
  `#202`, deliberately not built here. See §7.

### 2. A WebRTC data channel is rejected, and the reason is circularity

Recorded so nobody re-proposes it. **A data channel is established by exchanging
SDP offer/answer and ICE candidates over a signaling channel — and the signaling
channel to the coordinator is the thing being secured.** `core/transport_webrtc.go`
gets its signaling from a `Signaler`, whose frames route through the coordinator.
Using a data channel to reach the coordinator needs a channel to the coordinator.

Breaking the circle means a bespoke offer-in-the-first-datagram, no-trickle design
that is no longer "a WebRTC data channel" — plus an SCTP stack on a binary whose
whole read path is one `ReadFromUDP` loop, plus roughly 28 more bytes of framing
(SCTP common header plus DATA chunk header; arithmetic, not measured) on a budget
that §3 shows has ~64 bytes left. It buys nothing over S2, which reaches the same
observable shape without any of it.

### 3. The budget — 37 bytes, 1195 left, and **~64 of real headroom**

`ADR-0057` fixed the largest `connect` this client can assemble at **1097 bytes
against a 1232-byte budget** (`safePathMTU` 1280 − 40 − 8), and said in terms that
the 135 bytes of headroom *"is thin and should be treated as spent."* DTLS records
are not free. Measured, not derived — a real pion/dtls handshake between two
endpoints configured exactly as `core/dtls_fingerprint.go` configures them (its
`negotiableSuites`, its `browserCurves`, and `rewriteClientHello` /
`rewriteServerHello` driven through `dtls.Config`'s `ClientHelloMessageHook` and
`ServerHelloMessageHook`), counting bytes at the socket:

| Suite | Record overhead | Max app payload in 1232 | Headroom over 1097 |
|---|---|---|---|
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` — **what negotiates** | **37 B** | **1195 B** | **98 B** |
| `..._AES_256_GCM_SHA384` | 37 B | 1195 B | 98 B |
| `..._CHACHA20_POLY1305_SHA256` | 29 B | 1203 B | 106 B |
| `..._AES_256_CBC_SHA` — worst in `negotiableSuites` | 52 B | 1180 B | 83 B |

37 bytes is a 13-byte DTLS 1.2 record header plus an 8-byte explicit GCM nonce
plus a 16-byte tag. The fingerprint profile makes no difference to it — Chrome,
Firefox and no-profile all measured 37 — because the profiles reshape the
*ClientHello*, not the record layer.

**The budget closes.** ADR-0057's 135 bytes becomes **98**, or **83** if the suite
set ever changes such that CBC is selected. ADR-0057 also records that production
credentials measured ~34 bytes heavier than the test fixture, so the number to
plan against is:

> **~64 bytes of real headroom, ~49 in the worst suite.**

**Nothing may spend it before slice 2 moves the issuer cert.** ADR-0057 already
named the next lever: the issuer cert is **362 bytes**, it is identical for every
device from one issuer, and it is re-sent on every connect. Moving it to
`challenge` is the same move ADR-0057 §2 made for the admission credential, made
twice — and it is now **slice 2's precondition, not its follow-up.**

That move is also *safer* inside a DTLS association than it is today, and for a
reason worth stating: ADR-0057 §3 stashes the credential in `challengeStore`,
**keyed per UDP source**, and its own text has to argue at length about what a
blind spoofer can and cannot do with a spoofable key. Inside an association the
key is a completed handshake. The argument gets shorter and the property gets
stronger.

Slice 1 does not bind the budget — it is coordinator-only, and the coordinator
sends replies, not connects. The number is recorded here so slice 2 starts from
it rather than rediscovering it, which is `#183`'s whole lesson: loopback's MTU is
65536 and no test in this tree can see a datagram that is too big.

**What it costs in time, also measured:** three client flights and three server
flights, so **2 RTT before the first `connect` byte can leave**, against 0 today.
The largest handshake datagram is 547 bytes (the server's
ServerHello/Certificate/ServerKeyExchange/Done flight), comfortably inside the
budget. DTLS 1.3 would help and is not available: pion's own `version.go` says it
*"is a work in progress and is currently being implemented"*, and `conn.go` forces
1.2 unconditionally. `dtls.Config.SessionStore` exists, so a returning client can
resume at 1 RTT; that is slice 2's lever and is not taken here.

### 4. The compatibility window is a demux, not a version — and `ProtocolVersion` is not touched

**This corrects the brief this work was given.** It held that the wire's
`Version int` made a compat window *"expressible rather than inventable."* It does
not. `core/handshake.Check` rejects a mismatch in **both** directions —
*"peer protocol version %d is older … peer must update"* and
*"…is newer … this side must update"* — so bumping `handshake.ProtocolVersion` is
a hard fleet break, which is the opposite of a window. The field the repository
actually built for additive change is `Hello.Capabilities`, which `Check` ignores
by design so *"a future feature can be negotiated without another
protocol-breaking version bump."*

Neither is needed, because the two shapes are **self-identifying**:

- **Server side — a first-bytes demux.** A DTLS record begins with a one-byte
  ContentType (20 change_cipher_spec, 21 alert, 22 handshake, 23
  application_data, 25 connection_id) and a two-byte version that for DTLS is
  `0xfeff` or `0xfefd`. A JSON value begins with `{`, `[`, `"`, a digit, `-`, `t`,
  `f`, `n`, or ASCII whitespace. **Those sets are disjoint on the first byte
  alone**; `looksLikeDTLS` checks the version too, which turns "unlikely to
  misclassify" into "cannot".
- **Client side (slice 2) — try DTLS, fall back, remember.** A client attempts
  DTLS and falls back to raw JSON when the handshake does not complete, per
  coordinator. That is the per-user failover ladder §4.1 asks for at this hop,
  arriving as the compatibility mechanism.

So **`handshake.ProtocolVersion` stays at 1 and is not part of this change.** It
is written down because it is the obvious thing to reach for and it is the wrong
thing to reach for.

The **polarity** of the classifier is load-bearing and is the reason it errs the
way it does: anything not conclusively DTLS goes down the JSON path exactly as
before. A false "this is DTLS" breaks every deployed client; a false "this is
JSON" costs one failed `json.Unmarshal` and a dropped datagram, which is what that
loop already did with malformed input.

### 5. `handle()` does not change, and that is most of the cost that was feared

Every piece of per-source state in `cmd/coordinator` — `challengeStore`, the
connect-nonce dedupe, session routing — keys on the UDP source address, and a DTLS
association preserves it: the datagrams still arrive from the same host and port.
So the DTLS layer wraps the read path and the reply path and nothing else.

The reply side is one branch in `send()`, the single function every handler
already replies through: a peer with an established association gets the reply
inside it, and every other peer — which is every client on the current build —
gets the cleartext datagram it always got. No handler learned that a peer might be
on the other shape.

`cmd/coordinator` **already links `pion/dtls`** — 21 packages, pulled in by
`pion/turn/v4` for the STUN/TURN server — so speaking DTLS adds no dependency to
the binary. `go list -deps` is the check, not inspection of the import block.

### 6. What the certificate is for, and what it is not

The coordinator presents a self-signed ECDSA certificate generated fresh at
startup. **It authenticates nothing**, and that is not a shortcut: the desktop
client holds no coordinator public key at all — `MeshPubKey`, `MeshPeers` and
`MeshProof` appear nowhere under `clients/`, and `-print-bootstrap-pubkey`'s own
help says that key is provisioned to `bacchus-node -mesh-pubkey` and to couriers.
A client "verifying" this certificate would be verifying it against nothing.

It exists to make the handshake look like the WebRTC handshake it is imitating.
The authentication that matters at this hop is unchanged and is inside: the
admission credential (ADR-0023/0047) and the device-credential chain
(ADR-0045/0046). What DTLS adds here is **confidentiality against a passive
observer and integrity against an off-path injector**, not authentication of the
coordinator.

What it costs is a fingerprint: a long-lived coordinator presents one stable
certificate. That is acceptable **here and nowhere else**, because the thing it
identifies — this coordinator — is the address the client already dialled to reach
it. Rotating it belongs with the fingerprint profiles in slice 3.

Per-coordinator keys carried in the signed directory would let a client verify
properly. That is `#193`'s mechanism and it is deferred to Wave 26; this record
does not pre-empt it.

### 7. The association table is bounded, and only a handshake mints one

A UDP source address is **spoofable**, so a per-source table keyed on it is
fillable by an attacker who never completes anything — the property
`maxPendingChallenges` exists for one layer up, and the same answer is taken here:
a cap (`maxDTLSAssocs`, 4096), an idle expiry, a handshake timeout, and a sweep
loop, with the at-capacity refusal latched so it costs one log line rather than
one per spoofed datagram.

Two properties keep it a bounded nuisance:

- **Only a handshake record (type 22) from an unknown source creates state.** A
  stray application-data or alert record is consumed and dropped. Otherwise an
  attacker could mint associations without ever starting a handshake, skipping the
  one exchange that makes a spoofed source cheap to refuse.
- **DTLS's own cookie exchange is that exchange.** Measured: the server answers a
  128–157 byte ClientHello with a **48-byte** HelloVerifyRequest and builds no
  cryptographic state until the cookie comes back. A spoofed source never returns
  it and holds its slot only until the handshake timeout.

That cookie exchange also makes this hop's **amplification profile better, not
worse.** Today an unvalidated source can draw a full `list` reply; under DTLS the
pre-validation exchange is 48 bytes against a ≥128-byte request, a ratio below 1.

### 8. S2 — why the STUN prefix is filed rather than built here

Ruled S2, and the mechanical cost is small: a third case in a demux that already
exists, against a signature stronger than the DTLS one (STUN's two high bits are
zero and the magic cookie `0x2112A442` sits at bytes 4..8), with `pion/stun/v3`
already a direct dependency. It is filed as **`#202`** anyway, for two reasons.

**The coordinator half alone is all cost and no benefit.** Nothing emits a STUN
prefix until slice 2 does, so shipping the responder now adds an unauthenticated
reply path to every deployed coordinator that no client exercises for a wave.

**And it carries an undecided security question.** `MESSAGE-INTEGRITY` is keyed on
the peer's ICE `pwd`, which real ICE exchanges in SDP — and this hop has no such
channel, which is the same finding that killed option A2-a. So the coordinator
cannot verify it, and the fork is: answer any Binding Request and become a plain
STUN responder (best *blend*, but a ~2.2x reflection vector on a spoofable source);
answer only requests padded to at least the response size and stay silent
otherwise (no amplification, and design principle 4's own words — *"a prober …
must see silence or a plausible decoy"* — but then principle 3's *"looking like
nothing is now itself a signal"* cuts the other way); or key the `pwd` on
`AdmissionPubKey`, which is fleet-wide and therefore held by anyone with a client
binary. **None of those is obviously right, and the choice determines what the
product's most exposed port answers to a stranger.** `#202` carries it.

### 9. `#176` — a transport identity carries a version, and nothing is fenced on it

Ruled **B3**, recorded here because it is the same axis one layer down.

Transports are patched constantly — a camouflage protocol that is never adjusted
is one that gets fingerprinted — and a transport was identified by a bare name, so
a patched `reality` and an unpatched `reality` agreed that they agreed. That is
`#114` (*a node on a stale binary registers, heartbeats and is assigned work while
silently dropping every session*) one layer further down, with **less** protection
than the node level had: there is no `-min-serving-transport-version`, and on the
coordinator hop there is no probe to fall through to.

What ships: a configured name may carry a version (`reality/2`); a bare name means
version 1 rather than "unversioned", so every pre-`#176` configuration names
exactly what it always named; `transportVersions` records what this build
implements; a version this build does not implement is **built and tried** with
one event naming both numbers. The single refusal is a *malformed* version —
reading `reality/two` as version 1 would hand an operator who typed a version the
transport they were trying to move off, under the name of the one they asked for.

**Nothing is fenced**, and `#34`'s own words are why: *"a fence without a channel
is a kill switch, not a repair tool."* The signed release channel is unstarted, so
a peer left on the wrong transport version has no path to the build that would
bring it back. B1 becomes a flag flip once `#34` lands.

The number is not inert while unenforced. `Engine.transports` and
`selection.Candidate.Transport` are both the configured string, so a bump is a
different learned-winner bucket — a route validated against the old protocol shape
is not tried first next time.

### 10. `#189` — the three seed writers create exclusively and flush

`core/devicestore.LoadOrGenerateKey`, `cmd/admission-issue`'s
`loadOrGenerateAdmissionKey` and `cmd/coordinator`'s `loadOrGenerateBootstrapKey`
each read a path and, on `ErrNotExist`, generated a keypair and persisted the seed
with `os.WriteFile`. Read-then-write is a TOCTOU, and `O_CREATE` without `O_EXCL`
lets the loser of the race overwrite the winner with **no error at all** — reaching
the silent-regeneration outcome `LoadOrGenerateKey`'s own doc forbids, through a
door that comment does not look at. `os.WriteFile` also does not `Sync`, and all
three keys have their public half leave the machine within moments of generation.

All three now `os.OpenFile(path, O_WRONLY|O_CREATE|O_EXCL, 0o600)`, write, `Sync`,
`Close`, and **`EEXIST` refuses and names the path** rather than re-reading,
because the key the caller holds in memory is not the key on disk.

Deliberately **not** made atomic. There is no read-modify-write here, the write is
only reached when the file does not exist, and a partial write is left where it
lies — the malformed-key branch refuses it loudly on the next read, where removing
it would present the next run with a missing file and mint a fresh key silently.

`O_EXCL` closes a hole the card did not name: **`os.WriteFile` follows a symlink**
at the key path, so a dangling symlink in an operator-managed `secrets/` directory
placed the seed wherever the link pointed. `O_EXCL` refuses a symlink outright.

## Consequences

**What is now true.** One coordinator socket serves both shapes. A client on the
current build is served byte-for-byte as before — demonstrated by running the real
`core` client, unmodified, against a DTLS-enabled coordinator — and a client
speaking DTLS gets its reply inside the association. A test asserts that no
datagram of a DTLS exchange contains the literal strings `{"type"`, `reject`,
`bacchus` or `magic`, which is the signature this record exists to remove.

**What is deployable now.** This half, alone, ahead of any client. It refuses
nothing.

**What is not closed.** `#175` is not closed by this record — it is slice 1 of
three, and the hop still has **no transport pool, no probe and no race**. Its two
remaining design questions are untouched and stay open against it: what a probe is
with no end-to-end Noise channel, and whether a coordinator-hop probe leaks a
distinguisher. A2-c adds no probe, so neither had to be answered to get here, and
neither is answered.

**A behavioural side effect, named because it is one.** Making the read loop
testable turned it into `servePackets`, which now returns when the socket is
closed instead of `continue`-ing forever. Before this, a closed signaling socket
left the coordinator busy-spinning at full CPU while unable to receive; it now
exits loudly. Nothing in the process closes that socket, so the path is
unreachable in production either way.

**What slice 2 inherits, and must not get wrong.** `dialPool` builds its links
with `net.DialUDP`, and a **connected** `*net.UDPConn` fails every `WriteTo` with
*"use of WriteTo with pre-connected connection"* — verified — while `dtls.Client`
requires a `net.PacketConn`. The fix is a shim whose `WriteTo` calls `Write`, and
**not** unconnecting the socket: ADR-0057 §4 depends on a connected socket
surfacing a dead peer's ICMP port-unreachable as `ECONNREFUSED` on the next write,
which is the one signal separating an unreachable coordinator from a silent one. A
handshake and a round trip were confirmed to complete through such a shim.

**What slice 3 inherits.** The fingerprint profiles apply without being forked.
`dtls.Config` carries `ClientHelloMessageHook` and `ServerHelloMessageHook`
directly, not only `webrtc.SettingEngine` — the measurements in §3 drove
`core/dtls_fingerprint.go`'s own `rewriteClientHello` through them. What is
missing is a `dtls.Config` counterpart to `dtlsProfile.apply`, which takes a
`*webrtc.SettingEngine` today. That is one function, and slice 1 deliberately did
not write it.

**Accepted costs.** 2 RTT before a client's first `connect` (slice 2's problem,
mitigable with session resumption). A bounded table of per-source associations,
with a flag — `-rendezvous-dtls=false` — to shed it. A stable per-process
certificate that is a per-coordinator fingerprint, on an address that already
identifies the coordinator.

## References

- Issues #175 (slice 1 of three; not closed), #176, #189, #202 (S2), #201
  (`SanitizePoolOrder`), #188 (the directory-fsync boundary), #193
  (per-coordinator keys), #34 (the release channel `#176`'s fence waits on), #114
  (version skew that reports nothing), #183 (the datagram that never left the host)
- ADR-0057 (the datagram budget this spends 37 bytes of), ADR-0020 (the
  coordinator pool), ADR-0016 (`handshake.ProtocolVersion`, deliberately not
  touched), ADR-0018 (the DTLS fingerprint profiles), ADR-0023/0047 (admission),
  ADR-0045/0046 (the device-credential chain), ADR-0015/0029 (`Release`, the other
  version axis), ADR-0028 (the data plane's ladder this hop still lacks)
- `docs/design/rendezvous-cold-start.md` §4.1 (the bar), §3 (the principles §8
  weighs against each other)
- RFC 6347 §4.1 (the DTLS record layer), RFC 6347 §4.2.1 (the cookie exchange),
  RFC 8259 §2 (what a JSON value may begin with)
