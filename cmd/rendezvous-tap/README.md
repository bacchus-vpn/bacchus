# rendezvous-tap — what actually goes on the rendezvous hop

A logging UDP proxy. Put it between a client and a coordinator, run the client
through it, and it reports every datagram that crossed: how big it was, what
shape it was, and whether the four things `#212` step 2 asks about held.

It exists because that card names *"a logging UDP proxy between client and
coordinator, which is the instrument `#183` was found with"* and no such tool was
in this repository — the instrument that found the defect was never committed.
Five of that card's six steps report that the connect **worked**; this is the one
that reports what the bytes **were**.

`#183` is why the difference matters. A 1453-byte `connect` passed every test in
this tree — both PR CI runs and a combination build — and failed on a real home
link. Loopback's MTU is 65536, so nothing in a test can see a datagram too big
for a path it does not have.

## Run

```sh
# On the client box. -upstream is where the client would otherwise have pointed.
go run ./cmd/rendezvous-tap -listen 127.0.0.1:18080 -upstream <coordinator-host>:8080

# Then point the client at the tap instead of at the coordinator.
go run ./cmd/node -role client -coordinators 127.0.0.1:18080 -geo NL
```

Ctrl-C the tap when the client is done and read the report.

| flag | |
|---|---|
| `-listen` | where the client connects. Port `0` picks one and the tap prints it. |
| `-upstream` | the coordinator's **signaling** host:port (required). |
| `-budget` | bytes per datagram, default `1232` (ADR-0057). Lower it to measure against a tighter path. |
| `-quiet` | only the report, no line per datagram. |
| `-bytes N` | print `N` leading bytes of each datagram in hex. Default `0` — see *What it does not keep*. |

Exit `0` if every assertion held, `1` if one did not or the tap itself faulted,
`2` usage, `3` could not listen or resolve.

## What it reports

```
127.0.0.1:43152 -> #1     20 B  STUN: Binding Request
127.0.0.1:43152 <- #1     40 B  STUN: Binding Success Response
127.0.0.1:43152 -> #2    756 B  DTLS: handshake record (DTLS 1.2)
127.0.0.1:43152 <- #2    313 B  DTLS: handshake record (DTLS 1.2)

MEASURED, on 127.0.0.1:18080
  client to coordinator:   3 datagrams, 1189 bytes, largest 756 B
      sizes: 20 756 413
  coordinator to client:   3 datagrams, 666 bytes, largest 313 B
      sizes: 40 313 313
  largest datagram either way: 756 B payload — a 804-byte IPv6 datagram, 784-byte IPv4,
      against the 1280-byte path floor the 1232-byte budget is derived from (ADR-0057)

ASSERTIONS (#212 step 2)
  [held        ] 127.0.0.1:43152: the first datagram out is a STUN Binding Request
      20 B, STUN: Binding Request
  [held        ] 127.0.0.1:43152: the second datagram out leads with 0x16, a DTLS handshake record
      756 B, leading byte 0x16, DTLS: handshake record (DTLS 1.2)
  [held        ] no datagram carries {"type"
      0 of 6 datagrams carry it
  [held        ] no datagram exceeds the 1232-byte budget
      0 over; largest out 756 B (476 B spare), largest in 313 B (919 B spare)
```

**Sizes, not verdicts.** Every measurement is printed whether or not anything
failed, and each assertion carries the number that settles it. The largest
datagram a client could build measured 756 bytes in a test; **that figure is not a
threshold anywhere in this tool**, and the thing to check against is the budget.
A tool quietly comparing against last time's number would call a 470-byte
regression a pass.

The two ordering assertions are **per flow** — per client source address — because
they are about the first two datagrams *a* client sends. A client that restarts
appears as a second flow with its own pair.

## It is a passive observer

Bytes out equal bytes in, in both directions. Nothing is rewritten, reordered,
dropped or delayed. A tap that alters the flight it measures gives a confident
wrong answer, and this one's answers are sizes — exactly the kind that can be
wrong without looking wrong. Four things enforce it:

- the datagram is **forwarded before it is looked at**, so no classification or
  logging sits in the path;
- **one goroutine per direction per flow**, so the tap cannot be what reordered a
  handshake flight;
- the read buffer is **larger than any UDP payload can be**, because a short one
  makes the kernel discard the tail of an oversized datagram with no error at all
  — which here would silently repair the one defect the budget exists to catch;
- **nothing is expired**: the flow table has no idle sweep, because closing a
  socket under a late reply is a drop.

`TestTheTapChangesNothing` is what holds that to account, over a corpus that
includes an empty datagram, one at the budget, one over it, and `#183`'s 1453
bytes to the byte. `TestTheTapPreservesOrderUnderABurst` covers the ordering.

## What it does not keep

Datagrams on this hop carry admission credentials, device credentials and issuer
certs. Each one is classified as it is forwarded and then dropped: what the tap
holds is a size and a sentence, never the bytes. `-bytes` is the opt-in for a run
that needs a hex prefix, and it defaults to off.

It also cannot read the handshake, and that is the point — once the hop is shaped
the payload is opaque to anything on the path. What it sees is what a censor's
classifier sees: shape, size and order.

## Why it shares no code with what it measures

`classify.go` reads STUN and DTLS from the RFCs rather than importing
`core/coldstart` or `core/rendezvous`, for the reason `cmd/coordinator-probe`
hand-rolls its own STUN codec: an instrument built out of the thing it measures
agrees with that thing's bugs and reports a clean wire. The loop is closed from
the other side instead — `classify_test.go` runs this reader against the real
`coldstart.BindingRequest` a client emits, the real `BindingResponse` a
coordinator sends, and `rendezvous.LooksLikeDTLS` over a corpus. Those imports are
**test-only**; the binary links neither package.

## What it is not

Not a MITM, not a stand-in coordinator (`core/rendezvous.Peer` is that), and not
a substitute for running the client direct as well. The coordinator sees the
**tap's** address rather than the client's, because a UDP proxy is what this is:
its association table and the `XOR-MAPPED-ADDRESS` in its Binding Success
Response will name the tap. The client discards that attribute
(`coldstart.LooksLikeBindingSuccess` does not read it), which is what makes the
substitution invisible to the flight.

One tap forwards to one upstream. `#212` step 5 needs a pool of two members —
run one tap per member and point the client at both.
