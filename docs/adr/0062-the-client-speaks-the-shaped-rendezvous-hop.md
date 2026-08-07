# 62. The client speaks the shaped rendezvous hop, and there is no way back to cleartext

- Status: accepted (issues #175 slice 2, #206)
- Date: 2026-08-07

## Context

ADR-0059 made the coordinator's signaling port serve DTLS alongside raw JSON, and
ADR-0060 made it answer the STUN connectivity check that precedes DTLS in a real
WebRTC flow. Both halves were deployable alone precisely because **nothing emitted
either shape**. `coordLink.send` marshalled a wire struct and wrote it, so the first
packet a Bacchus client ever sent was still plaintext JSON over raw UDP, and a DPI
box still read the literal bytes `{"type":"connect"` off a UDP payload to one port.

This record is the half that closes it, plus the byte budget that had to be
recovered first.

### This is the highest-risk change in the wave, and no test here can settle it

It alters **the first packet every client sends** and removes the path it used to
fall back to. Loopback's MTU is 65536 and a loopback socket is not a censored
network, so nothing in this repository can show that the shape helps, or that a real
path carries it. `#183` is the standing precedent: a 1453-byte datagram passed every
test in this tree and failed on a real home link.

What the tests here *can* settle is what leaves the socket, byte for byte, and they
are built to settle exactly that and to claim nothing further. The rest is a testbed
run, filed as a `needs-owner-test` blocker.

## Decision

### 1. `#206` — the issuer cert rides the `challenge`, and the connect never carries it

ADR-0057 named this lever and ADR-0059 made pulling it a **precondition** rather than
a follow-up: the shaped hop spends 37 bytes per message on a DTLS record against
~64 bytes of measured headroom.

The issuer cert is **362 bytes**, it is identical for every device from one issuer,
and it was re-sent on every connect. The client now puts it on the `challenge`; the
coordinator holds it beside the nonce it just issued and reads it back when the
connect that answers that nonce arrives.

**Unconditional, unlike ADR-0057 §2's move, and the asymmetry is the point.** The
admission credential has to ride a connect whenever no challenge was *answered*,
because the coordinator may hold no state for that source and admission would refuse
it. The issuer cert has no such case: it only ever went out on a connect that
`presentDeviceCredential` had already succeeded for, so a connect with no answered
challenge never carried one to begin with. A connect that carries its own still wins
outright, which is what keeps a client predating this working against a current
coordinator.

**The stash is gated on the anchored ROOT, not on admission — a correction to the
card.** `#206` asks for the cert to be kept "only what it verified, and only under
the same condition the existing stash uses". The first half holds and the second does
not. `stashCred`'s condition is `admissionVerifier != nil`, because admission is what
verified the credential it keeps. Applied literally to the issuer cert, a deployment
running the device-credential gate (`#50`) with admission (`#42`) switched off — an
ordinary configuration — would issue a nonce, receive a connect the client had
therefore stripped the cert from, hold nothing, and **refuse every connect**. That is
the shape of the correction ADR-0057 §2 had to make to its own ruling: total rather
than degraded, and invisible until a real deployment meets it.

The right authority is the one that can speak for the artifact. An issuer cert is
signed by the offline root, which a coordinator running this gate holds by
definition, and it is verifiable **standalone** — unlike an admission credential,
whose bearer is checked one layer up, or a device credential, which means nothing
without the assertion binding it to a nonce. So the cert is verified on arrival and
only a live one the root signed is kept, which is *stronger* than the credential
stash rather than a relaxation of it. The raw envelope is kept rather than the parsed
cert, for ADR-0057 §3's reason: the connect re-runs the whole descent against the
clock and the revocation list **at connect time**, so a cert revoked inside the
challenge's two-minute TTL is still refused.

A size bound (`maxStashedIssuerCert`, 1024) sits behind that gate. The artifact's
size is fixed by its contents at 362 bytes, and the bound is what keeps a malformed
value cheap in the window between arriving and being refused, on a map keyed by a
spoofable UDP source.

**Measured, on bytes written to a socket:**

| | Largest `connect` | Headroom |
|---|---|---|
| Before `#206` | 1097 B | 135 B of 1232 |
| After `#206` | **719 B** | 513 B of 1232 |
| After `#206`, inside a DTLS record | 719 B payload, 756 B on the wire | **476 B of 1195** |

The cert costs **378 bytes** on the wire (362 plus its JSON key and punctuation), and
restoring both fields that have left reproduces ADR-0057's 1443-byte datagram exactly.

`minConnectHeadroom` (400) pins what is left. ADR-0057's test caught the moment the
datagram stopped fitting and not a byte sooner, so a field spending 130 of the 135
bytes then available would have shipped green; this fails while there is still room to
argue about.

### 2. There is no fallback to cleartext — ruling B3

ADR-0059 §4 planned *"try DTLS, fall back, remember"* as the compatibility mechanism.
**It is withdrawn.**

A censor dropping the handshake and a coordinator predating slice 1 are
indistinguishable to that rule — both produce silence — so the fallback reads as
*"when the disguise is blocked, send the cleartext the disguise existed to remove"*,
which hands a censor the plaintext for the price of dropping two datagrams. With
`#34` absent there is no update channel, so whatever ships in the 1.0 client is
permanent.

**The client speaks the shaped hop at this hop or it does not reach the coordinator.**

Three consequences, all taken:

- **The per-network memory is out of scope, and this is a change from ADR-0059.**
  With no fallback there is no per-coordinator shape to remember, so
  `selection.NetworkKey()` has nothing to store yet. It belongs with the
  probe-and-race work that keeps `#175` open; building it now would be a cache with
  one possible value.
- **`-rendezvous-dtls` is no longer a free valve.** It was written as a way to shed
  the per-source association table under a spoofed-source flood. Under B3 it stops
  clients reaching that coordinator *at all*: they rotate to another pool member on
  the existing 30-second cooldown and this coordinator's share goes to its peers. The
  flag's help text says so, because an operator reaching for it under attack will not
  read an ADR first.
- **The removal is asserted, not merely done.**
  `TestNoCleartextRendezvousCanLeaveTheClient` runs a real `attemptWith` through a
  logging UDP proxy and fails if any datagram the client emitted contains `{"type"`,
  `connect`, `challenge`, `bacchus` or `nonce`. A fallback is easy to reintroduce as a
  kindness and impossible to withdraw afterwards.

### 3. The shape is a connectivity check and then a handshake, on one 5-tuple

One ICE Binding Request, then DTLS on the same 5-tuple. Both halves are needed: a
ClientHello arriving from nowhere is *DTLS-shaped*, not *WebRTC-shaped*, and no other
traffic on the internet begins a DTLS association without a preceding check.
`core/ice_fingerprint.go` — which draws browser-shaped ufrag/pwd precisely because
pion's own are a distinguisher — acquires its first caller at this hop here, which is
what ADR-0060 said slice 2 would do.

The check is built by `coldstart.BindingRequest`, the same codec the coordinator
answers with and the same one this client already emits at the bootstrap listener.
That is ADR-0060's argument from the other end: two differently-shaped Binding
Requests leaving one client would be a distinguisher created while removing one.
It carries USERNAME, MESSAGE-INTEGRITY and FINGERPRINT, because a bare 20-byte
Binding Request is not what an ICE agent sends. The integrity attribute is keyed on a
freshly drawn local `pwd` and **nothing verifies it** — ADR-0060 already ruled that a
verifiable key is impossible at this hop and that calling a fleet-wide one
authentication would be a false claim. It is camouflage and is documented as
camouflage everywhere it appears.

**The response decides nothing.** The handshake proceeds on a response, on a 400ms
timeout, and against a coordinator that answers checks with silence, identically.
Making it a precondition would turn the check into a reachability probe — which is
`#175`'s open question, not this slice's to answer, and would give the client a new
externally visible behaviour to be fingerprinted by. What the wait buys is **order**:
check, response, ClientHello, which is the sequence a real endpoint produces.

One check, not a retransmission ladder. A lost check costs this association its shape
and nothing else.

### 4. A connected socket, a shim, and one reader

`dialPool` builds its links with `net.DialUDP`, and a **connected** `*net.UDPConn`
fails every `WriteTo` while `dtls.Client` requires a `net.PacketConn`. The fix is the
shim ADR-0059 specified — `WriteTo` ignores the address and calls `Write` — and
**not** unconnecting the socket, because ADR-0057 §4 reads a dead peer's ICMP
port-unreachable as `ECONNREFUSED` on the next write, and that is the one signal
separating an unreachable coordinator from a silent one.

The socket now carries three things: DTLS records, the Binding Response to our own
check, and in principle a cleartext reply from something that is not a slice-1
coordinator. So exactly one goroutine reads it and routes by shape — the
coordinator's mux inverted. Two readers would steal each other's datagrams, and a
DTLS layer reading the socket directly would consume the Binding Response and error
on it.

The **polarity** of that classifier is inverted from the coordinator's, deliberately.
There, anything not conclusively DTLS falls through to the JSON path, because a false
"this is DTLS" would break every deployed client. Here, anything not conclusively
DTLS is *not* handed to the DTLS layer, because there is no JSON path left to fall
through to. `LooksLikeDTLS` is shared with the client half through `core/rendezvous`;
`cmd/coordinator` keeps its own copy because that binary deliberately does not link
`core`, and `TestTheTwoDTLSClassifiersAgree` pins the two over a corpus rather than
trusting that they were written the same way.

### 5. The handshake is lazy, and that preserves a property nobody had written down

`dialPool`'s own doc promises that dialling every pool member up front reveals
nothing to a censor, because only an actual send does and the client controls those
through rotation. A handshake at dial time would have quietly cost that: a client
would hand over its entire fallback set at startup. So an association is minted by the
**first send** to a member, which is exactly the rotation the client already controls,
and `TestDiallingThePoolStillPutsNothingOnTheWire` is what keeps it true.

Three timing decisions come out of that, and each is set against something rather than
chosen:

- **`rendezvousHandshakeTimeout` (3s)** is the arithmetic on the path this product is
  for: a 400ms RTT gives 400ms for the check and 800ms for the handshake, leaving room
  for one retransmitted flight. It is well under the budgets it spends (`listTimeout`
  8s, `directTimeout` 12s).
- **`rendezvousHandshakeBackoff` (2s)** stops one leg paying that timeout several
  times over — `ListCountries` greets a member and then sends three copies of its
  request, and each send would otherwise start its own doomed handshake. It is
  deliberately *not* aligned with the pool's 30-second health cooldown, because
  `rankCoordinators` still tries a cooling member when every member is cooling ("a
  slow retry beats a client that refuses to connect at all") and a link that refused
  to retry would make that promise false.
- **`rendezvousAssocIdle` (3min)** is set by the *coordinator's* clock, and it is
  longer than the far end's window rather than shorter, which is the opposite of what
  an idle timeout usually wants. See §7.

**A failed handshake stops the leg rather than being waited out.** A member this
client cannot handshake with *is* unreachable, so the conclusion is unchanged —
rotation, the health memo, and `ErrNoCoordinatorReachable` (and therefore mesh-walk)
all still apply. What changes is only *when* the leg gives up: waiting a deadline for
a reply to a datagram that was never sent buys nothing, and with no cleartext fallback
that is a whole leg's budget spent on a member already known to be unusable. This is
deliberately **not** `#183`'s `requestTooLarge` shape, which says something about this
host and nothing about the member.

### 6. `EMSGSIZE` survives the shaped hop, and does not cost the association

`#183`'s diagnosis had to be re-established rather than assumed, because the datagram
the kernel now refuses is a DTLS record and the refusal has to travel back out through
pion. **Measured: it does.** The errno arrives intact and `isMessageTooLong`
recognises it, so a client on a 1280-byte path still gets the complete diagnosis
rather than "no coordinator reachable".

A size refusal explicitly does **not** retire the association. `EMSGSIZE` says
something about this host's path and nothing about the peer, and retiring one over it
would turn a local path limit into a member lost for minutes (see §7). Every other
write failure with no live association is reported as the handshake; every write
failure *with* one is reported as an ordinary send failure, so "this member never
answered the handshake" is never said about a member that did.

Reproducing a size refusal in a test is now a narrow window and that narrowness is
`#183`'s own lesson restated: loopback has no small path, so the only reachable
`EMSGSIZE` is above the UDP maximum, and on the shaped hop that maximum applies to the
record. The payload has to exceed 65507 − 37 and still fit a 16-bit record length. The
test computes its padding from a measured base so a new wire field cannot silently
walk the target out of the band.

### 7. A re-handshake on the same 5-tuple is swallowed, and the idle timeout is set by that

**Found while building this, on no card.** A coordinator's mux keys its association
table on the UDP source address and looks the source up *before* it looks at the
record type, so a fresh ClientHello from a 5-tuple it still holds an association for
is delivered **into** the association it is trying to replace. The handshake then
never completes.

The coordinator sweeps an idle association after 2 minutes on a 30-second ticker, so
it may hold one for up to 2m30s. Two consequences:

- **`rendezvousAssocIdle` is 3 minutes**, longer than that window. A client that
  connected and then sat idle — which is the ordinary case, since a rendezvous is a
  burst and then silence for as long as the session lasts — replaces its association
  on the next send rather than reusing one the far end has forgotten.
- **Without it the link wedges silently.** The client's next datagram would be a
  record from a source the coordinator no longer knows, which it drops; nothing on the
  client side errors, so the send succeeds, the reply never comes, and the member
  reads as blocked forever. There is no error anywhere to notice this by, which is
  why it is a timeout and not a retry.

A client whose own association dies while the coordinator's lives still rotates away
rather than recovering in place. That residual is accepted here: the common cause is a
coordinator restart, after which the far end holds nothing and the re-handshake
succeeds immediately.

### 8. Slice 2 is the CLIENT half — a pure forwarder's links stay cleartext

A relay or exit's `register` wire is a different case from a censored user's first
packet: it is operator-run infrastructure, and shaping both in one wave would double
the blast radius of a change no test in this repository can prove correct. An engine
holding **both** roles (ADR-0053's serve-while-routed) is shaped, because a link
cannot be half of each and the client role is the one with the threat; its register
then travels inside the association, which the coordinator handles without a branch
because `handle()` never learned which shape a peer arrived in.

This is a residual, not a conclusion. It is filed.

### 9. The peer half is factored, because "bind a socket and speak JSON" no longer works

A client with no cleartext fallback cannot talk to a socket that answers JSON, so
every stand-in for a coordinator in the tree stopped standing in for one — in `core`,
in `clients/fyne`, and in `clients/internal/enforcement`. `core/rendezvous.Peer`
terminates the shape so those adopt it by changing which object they read and write
rather than growing their own DTLS server.

It is deliberately **not** `cmd/coordinator`'s mux, which carries what a public port
needs and this does not: a bounded association table with an idle sweep, a latched
at-capacity refusal, the STUN posture ADR-0060 ruled, and the raw-JSON compatibility
path. Having two is a real cost and it is paid down by the test that matters:
`cmd/coordinator/protocol_integration_test.go` now runs the **production** read loop —
`servePackets` with the real mux — against the **real** `core` client. That file exists
because a fake on both sides of a protocol tests the fakes, and before this change it
ran a hand-rolled cleartext loop that no current client could reach, which is that
same failure arriving on the file that exists to prevent it.

Folding the mux onto `core/rendezvous.Peer` is filed rather than done here: it would
put both halves of the hop in one change with no independent evidence for either.

## Consequences

**What is now true.** A client emits an ICE connectivity check and then DTLS, and
nothing it sends at this hop is readable. Its largest `connect` is 719 bytes inside a
1195-byte shaped budget, 756 bytes on the wire against a 1232-byte path. A real
`core` client completes a country list and a pairing against the real coordinator's
production read path, over the shape, on a real socket.

**What is not true, and cannot be shown here.** That the shape survives a censor,
that it survives a real path, or that a real coordinator on real hardware completes it
— which is the same gap `#183` fell through. Filed as a `needs-owner-test` blocker on
all further rendezvous work, with `#205` (the testbed is not pinned to `main`) as its
own precondition.

**What is deliberately not here.** Slice 3: the fingerprint profiles per
`Config.DTLSFingerprint`, which need a `dtls.Config` counterpart to
`dtlsProfile.apply`. What this slice takes from `core/dtls_fingerprint.go` is the
substance underneath the profiles — `negotiableSuites` and `browserCurves`, the
configuration ADR-0059 §3 measured 37 bytes against — and not the ClientHello rewrite.
`#175` stays open for that, for the probe, the race and the per-network memory, and
for its two design questions: what a probe is with no end-to-end Noise channel, and
whether a coordinator-hop probe is itself a distinguisher. **Neither is answered here,
including in passing.**

**Accepted costs.** 2 RTT plus the check's wait before a client's first `connect`
byte; `dtls.Config.SessionStore` exists and resumption is not taken. 37 bytes per
message. A per-process client certificate is not presented at all
(`ClientAuth: NoClientCert`), and the coordinator's is not verified —
`InsecureSkipVerify` is on, because the desktop client holds no coordinator key and
"verifying" would be verifying against nothing (ADR-0059 §6, `#193`).

**A version-skew hole this makes concrete.** A client on a build that predates this
change reaches nothing; a client on a build ahead of the fleet reaches nothing either.
Neither reports anything a user or an operator can act on, and `#182` does not cover
it — that card's wire is a *node's* register. Filed as its own card.

## References

- Issues #175 (slice 2 of three; not closed), #206 (closed by this), #183 (the
  datagram that never left the host), #202, #34 (the release channel B3's permanence
  turns on), #193 (per-coordinator keys), #205 (the testbed is not pinned to `main`),
  #114/#182 (version skew that reports nothing)
- ADR-0059 (slice 1 — the shape, the budget, the coordinator half; §4's fallback is
  withdrawn here), ADR-0060 (the STUN posture and the shared codec), ADR-0057 (the
  datagram budget and the lever this pulls), ADR-0045/0046 (the device-credential
  chain), ADR-0023/0047 (admission), ADR-0020 (the coordinator pool and its cooldown),
  ADR-0018 (the fingerprint profiles slice 3 applies), ADR-0053 (serving while routed,
  which is why a shaped link can carry a register)
- `docs/design/rendezvous-cold-start.md` §4.1 (the bar this hop is held to)
- RFC 6347 §4.1 (the DTLS record layer), RFC 5389 §6 (the STUN header), RFC 8445
  §7.2.5 (ICE connectivity checks), RFC 7983 (demultiplexing STUN from DTLS on one
  5-tuple)
