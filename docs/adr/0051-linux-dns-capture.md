# 51. Linux DNS capture: reconfigure systemd-resolved, because the leak is link scoping and not routing

- Status: accepted
- Date: 2026-08-02

## Context

`osNet` (`clients/internal/enforcement/osnet.go`) had no DNS method. ADR-0049
recorded that as its one genuine gap — "anyone estimating #37 from the current
interface will under-count it by one method and its three-way distribution
problem" — and deliberately did not close it, because adding a method to shared
portable code means answering it for Windows and macOS at the same time. #104 is
that card.

#104 names three candidate mechanisms and picks none: per-link DNS on the TUN
via systemd-resolved plus a `~.` routing domain; an nftables redirect of
loopback-stub traffic; rewriting `/etc/resolv.conf` as a fallback. It guesses
that "a real deployment probably needs 1 with 3 as a fallback, but that is a
guess and this card exists to replace it with a decision."

**The guess was close and the reasoning underneath it was wrong in a way that
changes the design.** This record starts with the measurement, because every
choice below follows from it.

## The measurement

Both #104 and ADR-0049 assert two outcomes on a systemd-resolved machine — no
working DNS with the kill-switch armed, a plaintext leak with it off — and
neither had been measured. They are correct. The stated *reason* is incomplete,
and the missing half is what rules out two of the three candidates.

Measured on Ubuntu 26.04, systemd 259, driving the real `systemd-resolved`
binary inside a user + network namespace with a physical link, a tunnel link,
and the `0.0.0.0/1` + `128.0.0.0/1` split-default `addSplitDefaultRoute`
installs. Egress was counted with nftables counters on the `output` hook, per
interface — an independent tool, not a re-reading of anything the test wrote.

**1. The stub hop is unroutable, as recorded.** `/etc/resolv.conf` points at
`127.0.0.53`; `ip route get 127.0.0.53` answers `local ... dev lo`. The kernel
consults the `local` table before ours, so no route reaches it. This half was
already correct and is why `rtnetlink.go`'s `rulePriority` comment says a route
cannot fix DNS.

**2. The upstream hop is not a routing problem either, and this is the new
fact.** With the split-default installed, `ip route get 203.0.113.53` answered
`via 198.51.100.2 dev tun0` — the route table says the tunnel. resolved's query
went out the *physical* link anyway: **6 UDP/53 packets on `phys`, 0 on `tun0`**,
with the socket's source address the physical link's. resolved scopes its
upstream socket to the link the server belongs to, and link scoping overrides
the routing table.

Confirmed against the kernel directly, with a probe sending UDP/53 to an address
the split-default covers:

| socket | egress | source |
|---|---|---|
| plain | `tun0` | tunnel's |
| `IP_UNICAST_IF` = phys | `phys` | physical |
| `SO_BINDTODEVICE` = phys | `phys` | physical |

So a link-scoped socket defeats a split-default, and an unscoped one does not.
**Any mechanism that tries to win by installing a better route is answering the
wrong question.**

**3. Candidate 1 alone does not close it.** Giving the TUN link its own DNS
server and a `~.` routing domain, and changing nothing else, still leaked: 6
packets into the tunnel and **2 still out the physical link**. resolved queries
every scope that matches a name, in parallel, and takes the first answer. The
physical link keeps being asked. With the kill-switch armed those 2 are dropped
and DNS still works, so the failure is invisible exactly when the user is
protected — and with the kill-switch off they leave in the clear, which is the
condition #104's exit criteria forbid.

Revoking the physical link's default-route flag as well closed it: **0 packets
out the physical link**, all resolution over the tunnel. Clearing the physical
link's servers outright also closed it, and is worse — it discards a
configuration the machine may need for its own search domains, where demoting
the flag leaves the link usable for the names it is actually authoritative for.
Reverting restored the original behaviour exactly.

**4. Candidate 2 does not work.** An nftables `dnat` on the `output` hook,
rewriting stub-bound DNS into the tunnel, made the packets **disappear**: 0 on
every interface. The stub hop's socket has a loopback source address, and once
the destination is rewritten off-link the packet is a martian and is dropped.
Making it work needs SNAT on loopback traffic as well as DNAT — rewriting both
ends of every local DNS conversation. Applied to resolved's own upstream hop
instead, the redirect only partially landed (4 packets still out the physical
link, 7 into the tunnel), because the socket's forced output interface survives
the DNAT reroute.

## Decision

### 1. Reconfigure systemd-resolved, in two halves, both required

With resolved present, `bacchus-netd` gives the TUN link its own DNS server and
a `~.` routing domain, **and** clears the physical link's default-route flag.
Neither half is sufficient and §"The measurement" is why. Both are per-link
settings resolved already models, applied to links the helper itself created or
read.

With no resolved, `/etc/resolv.conf` is rewritten to point at the tunnel. That
is #104's candidate 3, kept as the fallback it was proposed as. It captures
every glibc lookup on such a machine, and on a machine with no resolved there is
no local daemon in the path for it to miss.

The two are chosen by asking the system bus whether anyone owns
`org.freedesktop.resolve1`, not by probing for a unit file or a socket — both of
which can exist while resolved is not running.

### 2. Nothing crosses the boundary inward

ADR-0049 §2 fixes the inward vocabulary at IP prefixes, an address, an allowlist
and a session token, and warns that a DNS verb is exactly the kind of thing that
would widen it: the obvious encodings carry an interface name, a unit name, or
`/etc/resolv.conf`'s path.

`capture-dns` and `release-dns` carry **no fields at all** beyond the token. The
helper created the TUN, so it knows the interface and the address; it read the
default route, so it knows the physical link; `/etc/resolv.conf` is a compile-time
constant. The address the resolver is pointed at is derived, not supplied — and
it can be, because `tun2socks.go`'s `handleDNSUDP` intercepts UDP/53 to *every*
destination and substitutes the configured upstream, so the address only has to
be one that lands in the TUN. It is host `.53` of the tunnel's own subnet, never
the TUN's own address, which would be in the `local` table and go to loopback.

### 3. D-Bus in a root process, against ADR-0049 §4

§4 says the helper speaks netlink and nftables directly and never shells out,
because "the entire value of the boundary is that no string from the
unprivileged side can become an instruction". Reaching resolved needs D-Bus.
That is a new dependency in a root binary and it needs an argument, not an
exemption.

**The reason for §4 is satisfied.** D-Bus is a typed, structured, binary IPC in
exactly the respect that matters here. The calls carry an interface index the
helper derived and four bytes of IP address; there is no shell, no `PATH`, no
`LD_PRELOAD`, no argv quoting, and no client string reaches a parser. Shelling
out to `resolvectl` would reintroduce every one of those and is refused for the
same reason §4 refuses `ip` and `nft`.

**The alternatives were checked and do not exist.** resolved's varlink surface
(`io.systemd.Resolve`, `io.systemd.Resolve.Monitor`) is query and monitoring
only — there is no configuration interface. There is no state file to write:
the per-link configuration lives in resolved's memory and is set through
`org.freedesktop.resolve1.Manager` or not at all. And it cannot be done from the
unprivileged client instead: the relevant polkit actions
(`set-dns-servers`, `set-domains`, `set-default-route`, `revert`) are
`auth_admin_keep`, so an active local session gets an administrator password
prompt — the precise failure ADR-0049 §7 rejected polkit over, now on the DNS
path rather than the route path.

**The dependency is smaller than it looks.** `github.com/godbus/dbus/v5` was
already in this module's graph, pulled in indirectly; this change promotes it to
direct rather than adding a new supply-chain entry. What is genuinely new is
linking it into the *root* binary, and that is the cost recorded here.

This does contradict one thing already in the tree, and rather than leave them
disagreeing the comment has been corrected: `uidHasActiveSession` justified
reading logind's state file over using D-Bus partly because "a D-Bus client
library is a large dependency ... to add to it for one boolean". That premise no
longer holds once this file links one. The file read stays, for the reason that
does hold — it is on the connection-accept path, where a file read cannot block
on a bus that is starting or wedged.

### 4. Restore is not only `Close`'s job, and DNS is not held on crash

Whatever the capture changed is restored on `Close`, on the client
disconnecting, and on the helper reaping an orphaned session — the same three
paths `recoverKillSwitch` covers.

**The kill-switch and DNS make opposite choices on crash, deliberately.**
ADR-0049 §8 holds the lockdown when the client dies, because holding it fails
closed and parity item 2 asks for a filter that survives a killed process. A
resolver left pointing into a tunnel that nothing is reading does not fail
closed; it fails to a machine that resolves nothing, which is not safer, only
broken. So DNS is restored on every exit path including the crash one, and it is
restored *before* the disconnect path decides what to do about the lockdown. If
the lockdown is held, the restored resolver is blocked by it and nothing leaks;
if it is not, the machine simply works again.

The physical link's prior default-route value is captured before it is cleared
and restored verbatim, never assumed to have been set — the rule ADR-0049 §3.6
already sets for the IPv6 sysctl, for the same reason. `/etc/resolv.conf` is
restored as a symlink to the same target if that is what it was, byte for byte
if it was a regular file, and removed if there was nothing there. Writes go
through a rename so no reader ever sees a half-written file.

### 5. Windows and macOS answer the same method

This is the three-platform obligation the method was split out of #37 for.

- **Windows implements it as a no-op, and the no-op is the answer.** A Windows
  resolver's servers are ordinary routable addresses, so its queries already
  meet the split-default and enter the TUN. There is no stub on loopback and
  nothing to capture. Reconfiguring a resolver that is already pointed somewhere
  the tunnel sees could only make it worse.
- **macOS does not implement `osNet` at all.** ADR-0050 §5 rules macOS to a
  NetworkExtension packet tunnel in a system extension, where the OS owns
  routing and DNS and the client declares intent rather than installing
  primitives. There is no `osnet_darwin.go` and there is not meant to be one, so
  there is nothing to stub. `osnet.go`'s package doc now says that instead of
  naming an invented mechanism, which is bacchus#110.

## What this does not capture

Stated plainly, because a capture mechanism whose limits are vague is one nobody
can rely on. None of these is Linux-specific and none of them is changed by this
record — Windows and macOS have the same two holes:

- **DNS-over-HTTPS and DNS-over-TLS configured inside an application.** A
  browser with its own resolver never emits a UDP/53 query, so neither the
  interceptor nor this mechanism sees it. It still goes through the tunnel as
  ordinary traffic; it simply is not *intercepted*, so it does not feed
  bypass-domain learning and is not redirected to the configured upstream.
- **A process that hardcodes its own DNS server.** Caught by the tunnel's
  routing like any other traffic, not by this.

What it does now capture, which it did not before, is everything reaching the
system resolver — which on a desktop is almost everything — including via
`nss-resolve`, where the query never becomes a packet at all and only
reconfiguring resolved could have reached it. That is also why candidates 2 and
3 could not be the whole answer on a resolved machine.

`splittunnel.go`'s bypass-domain learning works again as a consequence rather
than as a separate fix: it is driven by `observeDNS`, which is fed by the
interceptor, which now sees the queries.

## Consequences

- **`osNet` grows to sixteen methods**, and the two new ones keep the
  error/no-error split the type doc calls load bearing: `captureDNS` returns an
  error and unwinds bring-up, because a failed capture is not a degraded tunnel
  but an unprotected resolver, and reporting Protected over it is ADR-0039
  parity item 7's exact failure. `releaseDNS` is silent like the other teardown
  primitives.
- **DNS capture sits between the netstack and the kill-switch in `tunnel.go`,**
  and both bounds are pinned by tests. After the netstack, or redirected queries
  land in a device nothing is reading. Before the kill-switch, which stays the
  literal last operation of bring-up.
- **`bacchus-netd` now links a D-Bus client.** §3 is the argument; the cost is
  a larger root binary and a larger parse surface reachable from the system bus.
- **A machine whose physical link cannot be demoted still resolves,** and logs a
  warning rather than failing. The tunnel's scope is installed by then, so DNS
  works; what is lost is the guarantee that nothing is *also* asked on the
  physical link, which the kill-switch drops when armed.
- **`DNSCaptureIsComplete()` is now true on Linux**, so `clients/fyne`'s
  settings window stops qualifying its DNS field. That flag existed to keep the
  UI from claiming more than the client enforced; the claim is now true.

## How this is tested, and what the tests cannot prove

The orderings and the failure paths are pinned against `fakeOS` in
`tunnel_test.go`, and each was mutation-checked by breaking the code and
watching the test go red.

The `/etc/resolv.conf` fallback is tested against a real filesystem in a
namespace, asserting the restored file with an independent read rather than
against the encoder that wrote it.

**The systemd-resolved path is not covered by a Go test in CI, and this record
does not pretend otherwise.** It was verified by driving the real resolved
binary in a user + network namespace, as recorded in §"The measurement", but
that harness needs a session bus and a resolved binary that CI does not have
today. A CI step for it is proposed rather than applied, because
`.github/workflows/ci.yml` is outside this change's ownership — the same pattern
ADR-0046 and ADR-0047 use.

And the limit ADR-0049 was honest about applies here unchanged and is sharper
for DNS than for anything else: **a namespace is not a desktop.** The resolver
in the measurement is the real `systemd-resolved`, which is the part that
mattered, but the network around it is synthetic and NetworkManager is not in
it. A desktop where NetworkManager re-asserts per-link DNS mid-session, or a
`resolvectl` run by the user, is not something these tests see. That is hardware
verification, it is not something Go can assert, and it is the same gap #88
holds open for Windows.

## Scope: what this record does not decide

- Whether to intercept DNS-over-TLS or DNS-over-HTTPS at all. That is a
  different mechanism with a different threat model, on every platform.
- `nss-resolve` behaviour on distributions that ship it in `nsswitch.conf`
  (Fedora does; Ubuntu 26.04 does not). The chosen mechanism covers it either
  way, which is why it did not have to be settled — but it is the specific
  reason candidates 2 and 3 could not stand alone.
- IPv6 DNS servers. The tunnel is IPv4-only and IPv6 is disabled on the physical
  adapter for its lifetime (parity item 6), so an IPv6 resolver is not reachable
  while connected. If that changes, this becomes a live question.
- macOS DNS, which ADR-0050 §"DNS" already records as a different problem with a
  different answer.
