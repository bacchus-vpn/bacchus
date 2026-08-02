# 53. Serving while routed: a source address the served sockets bind, and a uid-scoped rule that routes it past the tunnel

- Status: accepted
- Date: 2026-08-02

## Context

`appstate.ErrVolunteerWhileRouted` refuses both volunteer opt-ins wherever this
client has an `enforcement.Enforcer`. The reasoning is sound and is not what
this record revisits: a served role's forwarding is caught by the client's own
default route, so other people's traffic egresses at the **upstream** exit's
address while the exit checkbox says "under YOUR own IP and jurisdiction", and
an advertised exit is unreachable anyway because the reply to an inbound dial
follows the default route into the TUN.

What changed is who that refusal covers. #59 gave Windows an Enforcer and #37
gave Linux one, so #109 records the result: **the GUI volunteer toggles became
reachable on no platform that ships**, available only on macOS, which has no
client at all. #12 was ruled a before-1.0 commitment on 2026-07-29 — "it should
be in the UI straight away" — so #109 lists three options and the owner ruled
option 2: teach enforcement to carve the served roles' egress out of the tunnel
it installs.

The bar #109 sets is traffic-level, not state-level: served traffic observed
leaving the physical interface under this machine's own address, while the
user's own traffic is still in the tunnel and the kill-switch is still armed.
Getting this wrong makes the disclosure false, which is worse than the feature
being unavailable.

## The measurement that decides the mechanism

The obvious mechanism is a firewall mark: `SO_MARK` on the served sockets, a fib
rule matching that mark, and an nftables allowance for it. It is what the card's
own framing assumes, and it is **not available to this client**.

`SO_MARK` requires `CAP_NET_ADMIN`, or `CAP_NET_RAW` since Linux 5.17. The
engine that opens the served sockets runs in-process inside the Fyne GUI
(ADR-0039), which is an ordinary desktop process holding no capabilities at all.
Measured directly — `setsockopt(SOL_SOCKET, SO_MARK)` from an unprivileged
process with `CapEff: 0000000000000000` on 7.0.0-28-generic — the call returns
`EPERM`. `SO_BINDTODEVICE` succeeded on the same kernel, but it is the same
shape of answer as the one below with a worse property (it names an interface
rather than an address), so it does not rescue the mark design.

Two ways to keep the mark were considered and both fail on the same fact.

- **The client passes each socket's descriptor inward and the helper marks it.**
  This works mechanically — the protocol already passes descriptors, outward,
  for the TUN — but it puts a helper round trip on *every exit dial*, serialized
  behind the one connection that `splittunnel.go`'s DNS interception also waits
  on. An exit handles many connections a second. That is disqualifying on its
  own, before the question of a root process calling `setsockopt` on
  client-supplied descriptors.
- **The helper creates marked sockets and passes them outward**, which would
  keep the fd-passing in the direction ADR-0049 §5 already blessed. Same round
  trip per dial, same disqualification.

It is also worth being explicit that neither would have bought any *trust* that
the design below lacks. The client is the only party that knows which of its
sockets are serving; whichever mechanism is used, it is the client asserting it.

So the classifier has to be something an unprivileged process can set on its own
socket. Binding a local address is exactly that.

## Decision

### 1. `core` binds the served sockets to this machine's own address

`core.Config.ServedSource` is a function returning the local IP a served role's
own sockets bind. `Engine.dialServed` and `dialServedUDP` (`core/servedsocket.go`)
replace the four bare `net.Dial*` calls that carry somebody else's traffic: the
exit's TCP egress, the exit's UDP egress, a relay's dial to its assigned exit,
and a relay's onion forward to the next hop. Unset — every `cmd/node`, and
`clients/fyne` on a platform with no Enforcer — reproduces the previous
behaviour exactly.

A function rather than a value, because of when it is needed: `clients/fyne`
builds `core.Config` and connects the engine **before** it starts enforcement,
so at construction time there is no tunnel and no address. It is asked per
served socket instead, and re-asked rather than cached, so a session that ended
stops handing out an address whose carve-out went with it.

**The exit's listener is deliberately not bound.** It stays on the wildcard
address. An inbound connection arrives *on* this machine's address, so the
accepted socket already has it as its local address and the reply carries it as
the source — the same thing binding would produce, without narrowing which
address an operator can be reached at.

This is not per-app classification and does not reopen ADR-0025's scope cut. A
process choosing the source address of its own sockets is a different thing from
a system classifying somebody else's. Nor could destination-based split
tunnelling do this job: served traffic and the user's own traffic go to the same
destinations and are indistinguishable by address. The socket is what tells them
apart.

### 2. `bacchus-netd` routes that source past the tunnel, one priority ahead of it

A fib rule at `servedRulePriority` = `rulePriority - 1`, selecting on
`FRA_SRC`/32 and `FRA_UID_RANGE`, with `FRA_TABLE` = `RT_TABLE_MAIN`. A lookup
that matches consults `main`, finds the physical default route, and never
reaches the split-default one priority later. A lookup that does not match falls
through to the tunnel's table exactly as before.

Ahead of the tunnel's rule rather than behind it, because behind is inert: our
table answers every destination via the split-default, so a rule after it is
never consulted.

Binding the source is **not sufficient on its own** and the rule is what makes
it work. Measured: with the split-default installed and no rule, a socket bound
to the physical address still resolves `dev tun0`. That is asserted as a
negative control rather than left as a claim.

### 3. Nothing crosses the boundary inward

`VerbAllowServedEgress` and `VerbRevokeServedEgress` carry **no fields beyond
the token**, keeping ADR-0049 §2's inward vocabulary closed — which is worth
stating, because every obvious encoding of a carve-out would have widened it: a
firewall mark, a routing-table id, a source address, a uid, a port range. None
of them has to cross. The helper read the default route, so it knows the
address; `SO_PEERCRED` told it the uid; the table id and the rule priority are
its own compile-time constants.

What the client needs back — the address to bind — travels **outward**, in
`Reply.ServedSource`, on the same footing §2 already gives `Gateway`. A helper
that says yes without naming an address is a protocol violation the client
refuses, because a client that accepted a blank one would bind nothing and serve
through the tunnel under a disclosure saying otherwise.

The protocol version goes 1 → 2. ADR-0049 compares it for equality precisely so
a skew is a refusal rather than a degradation, and this is the case that rule
was written for: at version 1 a new client would Open successfully and discover
only at the carve-out verb that this helper cannot do it — after `core.Config`
was built with a serving role in it.

### 4. The kill-switch allowance is a SOURCE allowance, and that is the real cost

Every other rule in the lockdown says "this specific destination may be
reached". This one says "traffic this machine sent as itself may leave", which
for an exit is necessarily the whole internet — an exit that could only reach an
allowlist would not be an exit.

It is a plain nftables set (`serve4`) holding one address, matched at offset 12
of the IPv4 header, created inside the same transaction as the drop policy so
there is never an instant where the machine is serving and its own lockdown is
dropping what it serves. A carve-out requested *after* arming is refused rather
than reordered, because the set does not exist on a lockdown armed without one.

**What this costs, stated plainly.** The carve-out is keyed on a source address
and a uid, not on a socket. So it reaches:

- every socket `core` binds to that address — the intent;
- every *other* socket the volunteering user's processes bind to that address —
  not the intent, and not preventable here;
- every reply from a socket that address was dialled *at*, which is what makes
  an advertised exit reachable and also means other local services the user runs
  become reachable and answer outside the tunnel.

It does **not** reach other users on the machine (the uid selector, measured:
another uid binding the same address resolves into the tunnel), and it does not
reach an ordinary unbound socket, which is the volunteer's own browser and
everything else they run.

The socket-scoped alternative that would close the residue is the firewall mark,
and §"The measurement" is why it is not available. This is therefore a real
widening of ADR-0039 parity item 2 while a user is volunteering, not a
theoretical one, and it is opt-in behind two checkboxes that are off by default
and a disclosure that a user has to read.

### 5. The carve-out and the lockdown make opposite crash choices, deliberately

ADR-0049 §8 holds the lockdown when a client dies, because holding it fails
closed. The carve-out is **dropped** in the same moment, because holding *it*
would not: the process that was serving is dead, so nothing needs the allowance,
and an allowance nobody is using is a hole in a lockdown that is otherwise being
kept on purpose.

Both are the same rule — keep what fails closed, drop what fails open — applied
to state that fails in opposite directions. It is also the rule ADR-0051 §4
already applies to DNS. Teardown follows it on the clean path too: `tunnel.Close`
revokes before lifting the lockdown, so "the carve-out never outlives the
lockdown it was an exception to" is one sentence covering both paths rather than
two orders to reason about.

### 6. Windows is scoped out, and the reason is the routing half

The socket half transfers unchanged — binding a local address needs no privilege
on Windows either. The routing half does not exist. Windows selects a route by
longest match on the **destination** and then by metric; its route table has no
source selector, and there is no policy-rule layer to add one to. So a Windows
socket bound to the physical adapter's address still meets the `0.0.0.0/1` and
`128.0.0.0/1` routes on the tunnel adapter and still goes into the tunnel.
Binding the source there changes which address the packet claims, not which
adapter it leaves by — the worst available outcome, because it looks like it
worked.

`IP_UNICAST_IF` is the lever that would work, needs no privilege, and is a real
route to a Windows implementation. It is not taken here for two reasons. It is a
differently-shaped hook in `core` — an interface index, not a local address — so
it is not a matter of passing the same value to a different call. And #109's bar
is traffic-level: the Windows CI job builds and smoke-runs this client, which is
more than was true earlier, but it cannot arm a kill-switch, create a TUN or
route a packet, so nothing available here could establish the claim. #88 is the
precedent for what a Windows enforcement claim costs: a hardware run.

So `Enforcer.ServesWhileRouted()` is `true` on Linux and `false` on Windows,
`ErrVolunteerWhileRouted` stays in force there, and `winOS.allowServedEgress`
returns an error rather than an empty string and a nil error — which is the one
genuinely dangerous answer.

## Consequences

- **The refusal is keyed on capability, not on platform.** `PlanVolunteer` and
  the settings window both ask `Controller.VolunteeringRefused()`, which is
  `enf != nil && !enf.ServesWhileRouted()`. `false` is what a new platform gets,
  so a platform that has not built the carve-out keeps refusing by default.
- **A Linux volunteer's stored opt-ins survive a save again.** #101's
  `ClearVolunteeringIfRouted` follows the same gate, so it no longer wipes them
  on a build that can serve.
- **A helper and a client that disagree refuse the session at Open.** Existing
  Linux deployments must upgrade both binaries together; the version-mismatch
  message already says so.
- **`Policy.ServeEgress` must be honored or fail the call.** It is the first
  field in that struct that *widens* what the machine may do, so the existing
  "fail rather than silently ignore" rule carries more than usual: ignoring
  `KillSwitch` leaves a user less protected than they asked, while ignoring this
  one leaves other people's traffic egressing under a false disclosure.
- **An exit on a routed machine cannot serve IPv6 destinations.** The carve-out
  is IPv4, and enforcement disables physical IPv6 for the tunnel's lifetime
  (parity item 6) so there is no IPv6 egress to serve with anyway. `dialServed`
  fails such a dial rather than retrying unbound — an unbound retry would put
  that one connection back in the tunnel, silently, which is the failure this
  record exists to prevent.
- **The relay role's inbound path is not addressed here.** A GUI relay is
  reached over WebRTC, whose sockets are opened inside pion and have no
  socket-creation site in this repo. `ForceRelay` pins those to the configured
  TURN server, which `Policy` already excludes from the tunnel, so the inbound
  leg is expected to work — but that expectation is not measured by anything in
  this change, and it is named rather than implied.

## How this is tested, and what the tests cannot prove

`cmd/bacchus-netd/servedegress_linux_test.go` runs in a user + network
namespace and asserts on **packets**, because state-level assertions would pass
against a carve-out the kernel then declines to apply. The rig is a veth pair —
an `AF_PACKET` socket on the far end is the wire — plus a real TUN device held
open and read, so "left the physical interface" and "went into the tunnel" are
both observed rather than inferred.

Covered: a served socket's packet seen on the wire with this machine's own
source while the kill-switch is armed; the same packet absent from the tunnel;
an ordinary unbound socket's packet present in the tunnel and absent from the
wire; the same source-bound packet staying in the tunnel with no rule installed
(the negative control that makes the rest mean anything); an injected inbound
SYN answered on the wire by a wildcard listener; revocation putting the traffic
back; and the uid scoping, via the kernel's own route resolution for a uid the
test cannot run as.

Every substantive assertion was mutation-checked by breaking the thing it covers
and confirming it went red — including one that did **not**, and was fixed: the
`core` bind assertion originally used `127.0.0.1` as both source and
destination, where a `dialServed` that ignored its source entirely produced an
identical local address and the test passed against a no-op.

What this does not prove is the same limit #59 and #107 were honest about. A
namespace is a synthetic network. A real desktop has NetworkManager, a physical
driver, a distribution's own nftables ruleset already loaded, and — the one that
matters most for a volunteer — a public address behind a NAT with a port
somebody has to have forwarded. **No end-to-end run of a real GUI volunteer
serving a real client from a routed Linux desktop has been done.** Passing these
means the mechanism is right on this kernel, not that an exit is reachable from
the internet.

## Scope: what this record does not decide

- The Windows implementation. §6 names the mechanism and the evidence it would
  need; #109 is where that lives.
- macOS. It does not implement `osNet` at all (ADR-0050 §5), and
  `NEPacketTunnelNetworkSettings` answers this question declaratively or not at
  all. `[E9]` is where it is asked.
- Whether a volunteer's advertised address is actually reachable. That is
  `classifyAdvertise`'s warn-and-serve territory and is unchanged: this record
  makes a reachable exit possible, not certain.
- Which address to carve out on a **multi-homed** interface. `physicalSource`
  takes the first routable IPv4 address on the default route's interface, which
  is the kernel's own answer when there is one and a guess when there are
  several. Reading `RTA_PREFSRC` would narrow it. Left as it is because guessing
  wrong produces an exit that does not work rather than one that leaks — the
  served socket binds an address the operator's NAT does not forward — so the
  failure is visible and safe.
- Anything about `cmd/node`, which does not route the device and therefore never
  had this problem.
