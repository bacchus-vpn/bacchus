# 49. The Linux privilege boundary: a root helper behind a peer-credential-gated unix socket, with the TUN fd passed back

- Status: accepted
- Date: 2026-07-31

## Context

#37 `[E10]` brings Linux to the enforcement level Windows reached in #59. Today
`clients/internal/enforcement/enforcement_linux.go` returns a `NotImplementedError`, and
`clients/fyne` on Linux is an honest SOCKS5 listener that routes nothing.

Every item #37 needs — creating a TUN device, flipping the default route, arming a
fail-closed firewall, disabling IPv6 on the physical adapter — requires `CAP_NET_ADMIN`.
Running the whole GUI as root is not acceptable for a client aimed at ordinary users:
Fyne links a GL stack, an X11/Wayland client and a font renderer, and none of that
belongs in a process that can rewrite the route table. The card says to decide the
privilege model first, and it names three candidates: a small privileged helper spoken
to over a socket, file capabilities on a helper binary, or a polkit-mediated action.

**What #37 has to build is much smaller than the card implies, and knowing exactly how
much smaller is what makes the privilege boundary decidable.** ADR-0039's file-by-file
costing found that 1,317 of `clients/windows`' 1,969 enforcement lines were portable;
#59 moved them. A Linux backend implements `osNet` (`osnet.go`) and inherits `tunnel.go`'s
bring-up ordering, `poolroutes.go`'s underlay-exclusion state machine, `splittunnel.go`,
`tun2socks.go`, `addrs.go` and `redact.go` unchanged. So the privilege question is not
"how do we run the client as root" — it is the much narrower "which side of a boundary
do these fourteen `osNet` methods run on, and what does the privileged side accept?"

ADR-0039's parity bar applies to Linux in full: the eight enforcement items, plus items
9–12, the configuration axis added by its 2026-07-30 amendment (#93). Item 7 is this
record's direct subject — *"Elevated execution is real and documented for the platform:
what this client requires ... and what happens when it's missing — silently degrading to
unprotected is the one failure mode this whole bar exists to rule out."* Item 8 is a
traffic-level test, not a state-level one, and it constrains the design below more than
it looks.

## Decision

### 1. A long-lived privileged helper, `bacchus-netd`, spoken to over a unix socket

Linux enforcement is split across a process boundary. `clients/fyne` keeps running as the
desktop user with no capabilities. A separate binary, `bacchus-netd`, runs as root (or
with `CAP_NET_ADMIN` alone, if the packager prefers `AmbientCapabilities` in the unit) and
owns every privileged operation. They speak over a unix socket at
`/run/bacchus/netd.sock`, mode `0660`, group `bacchus`.

The Linux `osNet` implementation is therefore a **client stub**: each method marshals a
typed request, writes it to the socket, and waits for a typed reply. It contains no
netlink code and no privileged syscall. The privileged half lives entirely in
`bacchus-netd`.

### 2. What crosses the boundary

A closed set of typed requests, one per privileged `osNet` method, carrying only:

- IP prefixes (`netip.Prefix`), as strings on the wire, parsed on the privileged side
- an IPv4 address and prefix length, for the TUN interface
- lists of IP addresses, for the kill-switch allowlist
- a session token, issued by the helper at `Open`

That is the whole vocabulary. **No interface name, no interface index, no next hop, no
routing-table id, no command, no rule text, no file path, and no format string ever
crosses inward.** Everything in that list is either derived by the helper itself or
fixed by the helper at compile time.

This is a deliberate narrowing against the interface as written. `addExclusionRoutes`
takes a `gatewayInfo`, and `disablePhysicalIPv6` takes an `ifAlias`, so the portable code
*does* hand those to `osNet` — but on Linux the helper ignores both and uses its own
session state. That is sound rather than a liberty, and the call sites are why: every
`gatewayInfo` in the package originates from `osn.defaultGateway()` and from nowhere else
(`tunnel.go:79`; `poolroutes.go:114` wires `gatewayFn: osn.defaultGateway`, refreshed at
`poolroutes.go:230`). There is no second producer. So a `gatewayInfo` arriving at the
helper is always a value the helper itself produced a moment earlier; treating it as
input rather than as an echo would let a compromised client point exclusion routes at an
attacker-controlled LAN gateway, or disable IPv6 on an interface of its choosing, using
a parameter that carries no information the helper lacks. `gatewayInfo` crosses
**outward** — the portable code genuinely needs it — and never inward as an authority.

### 3. What the privileged side validates

1. **Peer identity**, via `SO_PEERCRED` on the connected socket: the peer's uid must own
   an active local session (logind seat). A uid that merely belongs to the `bacchus`
   group is not enough on a multi-user machine — group membership is a packaging
   decision, session ownership is the question actually being asked.
2. **One session at a time.** `Open` returns a token; every mutating request must carry
   it. A second client gets `EBUSY`, not a second tunnel. The client that armed the
   kill-switch is the only one that can lift it.
3. **Every prefix is parsed, not interpolated.** `netip.ParsePrefix` on the privileged
   side, and the parsed value is what reaches netlink. A string from the client never
   becomes part of a command line or an `nft -f` script, because there is no command line
   and no script — see §4.
4. **Every route the helper installs is attributable and reapable.** Routes go in a
   dedicated table with a dedicated `rt_protocol` id, and the nftables state lives in one
   table the helper owns by name. The helper refuses to delete a route it did not
   install: `removeRoutes` deletes from its own table only. A compromised client cannot
   use it to tear up the host's unrelated routing, or another VPN's.
5. **Interfaces are derived, never named.** The helper reads the default route itself, and
   the only interfaces it will ever touch are the physical one that read returned and the
   TUN device it created in this session.
6. **`enablePhysicalIPv6` restores the prior value**, captured before
   `disablePhysicalIPv6` wrote it — not a hardcoded `0`. A machine that had IPv6 disabled
   before Bacchus ran must not come back with it enabled.
7. **Every request has a deadline.** This is not tidiness. `splittunnel.go`'s `arm()`
   holds `bypassPolicy.mu` for the whole duration of the install callback — the lock that
   `learn()` and `direct()` also take — and its doc comment prices that against
   PowerShell's several-hundred-milliseconds. On Linux the same lock is held across a
   socket round trip. A helper that can block indefinitely stalls every split-tunnel
   decision and every DNS interception behind it. A bounded deadline, and a failed
   request rather than a hung one, is what keeps `old #73`'s fix from becoming a hang.

### 4. netlink, not shelling out

The helper speaks netlink directly — `RTM_*` for routes and addresses, the nftables
netlink subsystem for the firewall — and does not exec `ip`, `nft`, `sysctl` or anything
else.

This follows from §2 and §3 rather than being a separate taste question. The helper is
root. The entire value of the boundary is that no string from the unprivileged side can
become an instruction; shelling out reintroduces exactly that, and adds `PATH`,
`LD_PRELOAD` and argv-quoting to a root process's trust surface. Windows shells out to
PowerShell because `NetTCPIP`/`NetSecurity` are the only API, and `routes_windows.go`
carries the quoting discipline that implies. Linux has a binary, typed, structured
interface to the same kernel state, and using it makes a whole class of injection bug
unrepresentable rather than merely tested-against.

The cost is real and is recorded here: netlink is more code than string-building,
and the nftables expression encoding is genuinely intricate. That is a known cost of the
boundary, not a surprise to discover during #37.

`nftables` over `iptables` is the direction for the firewall half — one atomic
transaction per change, a named-set primitive `refreshKillSwitchAllowIP` needs (§8), and
`iptables` on any current distribution is usually `iptables-nft` wearing a compatibility
shim. **Whether a legacy-`iptables` fallback ships at all is left to #37's build half**;
it is a distribution-support question, not a privilege-boundary question, and this record
does not settle it.

### 5. The TUN file descriptor crosses the boundary, and it is why this is a socket

`tun2socks.go` bridges a `tun.Device` to the gVisor netstack **in the client process**.
The netstack, the SOCKS bridge and `core.Engine` all run as the desktop user. So the
privileged side must create the device and the unprivileged side must read and write it.

The vendored dependency already splits exactly there.
`golang.zx2c4.com/wireguard/tun`'s `CreateTUN` (`tun_linux.go:551`) opens `/dev/net/tun`
and issues `TUNSETIFF` — the only privileged step — then hands the descriptor to
`CreateTUNFromFile` (`tun_linux.go:585`), which does `TUNGETIFF` on the fd it was given,
reads the interface index, and opens a netlink socket to listen for link events. Every
one of those is unprivileged on a descriptor the caller already holds.

So the helper performs `open` + `TUNSETIFF`, passes the fd back over the unix socket via
`SCM_RIGHTS`, and the client calls `CreateTUNFromFile` on it. No new abstraction, no fork
of the dependency, and the privileged surface is two syscalls wide.

This is the argument that decides the socket over the alternatives in §6 and §7: a unix
socket is the only one of the three that can pass a file descriptor at all.

There is an honest alternative worth naming so it is not rediscovered as an oversight: the
helper could create a **persistent** TUN device owned by the user's uid, which the client
could then open itself with no capability and no fd passing. It works. It is rejected
because it leaves a user-openable tunnel device sitting on the machine between sessions,
and it grants that access uid-wide rather than to one authenticated session — trading a
clean, session-scoped fd for a persistent ambient one.

### 6. Rejected: file capabilities on a helper binary

`setcap cap_net_admin+ep /usr/lib/bacchus/bacchus-netd`, exec'd per operation by the GUI,
with argv as the protocol.

It has a real virtue the chosen design gives up — no resident root process — and it is
rejected for three reasons, in ascending order of severity:

- **Packaging fragility.** File capabilities are an extended attribute. They are lost on
  `cp`, absent on filesystems mounted `nosuid`, unavailable on many network and container
  filesystems, and must be re-applied by every package upgrade. A silent loss degrades the
  client to unenforced — which is the precise failure parity item 7 exists to rule out.
- **The grant is ambient, not session-scoped.** A file capability is held by anyone who
  can execute the file. `SO_PEERCRED` gating a socket is a check the privileged side makes
  per connection; file mode on a binary is a check the kernel makes once, against
  execute permission, with no notion of who is logged in.
- **It puts the rollback of a security boundary in the untrusted process.** This is the
  decisive one. Enforcement is a *session*, not a series of independent operations.
  `tunnel.go`'s bring-up registers a reversal for every step as it goes and unwinds them
  LIFO on failure — the property `TestFailedBringUpOrphansNothing` pins. With exec-per-op,
  nothing on the privileged side knows a session exists, so the only thing that remembers
  what must be undone is the GUI. If the GUI dies mid-bring-up, the half-built state has
  no owner. A resident helper watches its own socket: EOF from the client *is* the
  crash signal, and it can unwind or hold fail-closed on purpose.

### 7. Rejected: a polkit-mediated action

polkit is the desktop-native answer and needs no resident root daemon, and it is the
option this record most regrets rejecting. It fails on the reconnect path.

ADR-0030's auto-reconnect and relay failover change routes without user interaction, by
design — that is the entire point of the feature. A polkit action with a real
authentication prompt turns every reconnect, every relay failover and every roam into a
password dialog, some of them while the screen is locked. The available escape is
`allow_active=yes`, which authorizes the action for any active local session with no
prompt — at which point polkit has stopped being a security boundary and is only a
launcher, with none of the per-request validation §3 describes and no place to put it.
Crash recovery makes it worse: parity item 3 requires lifting a stale lockdown *on next
launch*, so a polkit-gated `Recover()` would prompt the user for a password before they
have asked for anything.

polkit does have a fit here, and the chosen design does not foreclose it: a **one-time,
per-machine** authorization — "allow Bacchus to manage networking" — gating whether the
user is added to the `bacchus` group or whether the unit is enabled at all. That is an
install-time decision, which is the shape of question polkit models well. It is a
packaging matter, and this record does not require it.

### 8. Lifetime, fail-closed, and recovery

- The helper is socket-activated and may exit when idle — **but only when nothing is
  armed.** Its kill-switch state is nftables state, which lives in the kernel and survives
  the helper exiting, so an idle exit is safe; an exit that lifted the lockdown on the way
  out would not be.
- **Client disconnect while armed holds the lockdown.** Parity item 2 requires an OS-level
  filter that survives a killed process, and the client dying is exactly that case. The
  helper marks the session orphaned and keeps the filter.
- **`recoverKillSwitch` becomes the helper reaping its own orphan.** On `Open`, the helper
  looks for its own nftables table with no live session behind it and removes it. This is
  parity item 3, and it lands more cleanly here than on Windows: the helper knows whether
  the table is its own, so there is no heuristic about whose lockdown it is. A reboot
  clears the state on its own — nftables is not persistent unless something writes it to
  disk, and the helper never does.
- **`refreshKillSwitchAllowIP` has no fails-closed window on Linux.** ADR-0025's
  Consequences record that `NetSecurity` has no in-place address-list edit, so Windows
  removes and recreates the rule, leaving a brief interval covered only by the default
  Block. nftables named sets take an element addition as an atomic transaction. The Linux
  implementation must therefore **not** reproduce the remove-and-recreate dance: it adds
  an element to a set. Same guarantee, no window. This changes nothing about Windows and
  amends no Windows behaviour; it is a place where the platform is simply better, and
  writing it down now stops the Windows shape being ported as though it were the design.

### 9. What a compromised GUI can and cannot make the helper do

Stated plainly, because a boundary whose limits are vague is a boundary nobody can rely
on. Assume an attacker has full control of the `clients/fyne` process — arbitrary code as
the desktop user, holding an authenticated session token.

**They can** issue every request in the protocol, because that is what the protocol is
for. Concretely, they can:

- install an exclusion route for any prefix, including one broad enough to carry most
  traffic straight out the physical interface — a leak and deanonymisation primitive;
- lift the kill-switch, or decline to arm it;
- disable IPv6 on the physical interface, or re-enable it mid-session;
- add arbitrary addresses to the kill-switch allowlist;
- create a TUN device and hold its descriptor.

**The honest summary is that a compromised GUI can turn the VPN off.** It cannot be
otherwise: the GUI is the component that decides what to protect, so anything able to
speak for it can decide to protect nothing. The helper cannot be more trustworthy than
the process that tells it what the policy is.

**They cannot**, and this is what the boundary actually buys:

- execute code as root. The protocol has no verb that runs anything, and §4 removes the
  usual accidental one — no client string reaches a shell, an exec, or a rule parser.
- read or write files as root, load kernel modules, or change any sysctl outside
  `net.ipv6.conf.<the one physical interface>.disable_ipv6`.
- touch routing state outside the helper's own table and protocol id, so they cannot
  blackhole the host, hijack an unrelated VPN's routes, or install anything that outlives
  a reboot.
- reach another user's session: `SO_PEERCRED` plus the logind-session check is evaluated
  per connection, and an unprivileged process cannot forge the credentials the kernel
  attaches.
- escape the one-session rule to run two conflicting enforcement states at once.

So the security claim is: **compromise of the GUI costs the user their VPN protection,
not their machine.** That is a genuine reduction — GUI-as-root makes those two the same
event — and it is the most that any design in this space can offer.

One corollary deserves recording because it is easy to assume otherwise: **the
kill-switch is not a defence against local malware running as the user.** It is a defence
against the tunnel dying. Anything able to ask the helper to lift it can lift it. That
matches ADR-0014's actual threat model; this record just makes it explicit for a platform
where the lift is one socket write away.

## The `osNet` map for Linux

What a Linux backend must implement, mechanism by mechanism. This is the estimate #37's
build half needs, and it is deliberately not an implementation.

| # | `osNet` method | Linux mechanism | Privileged | Runs on |
|---|---|---|---|---|
| 1 | `defaultGateway` | netlink `RTM_GETROUTE` (v4, lowest metric) + `RTM_GETROUTE` v6 on the same link + `RTM_GETLINK` for the name | **No** | helper, by choice — §2 |
| 2 | `addExclusionRoutes` | netlink `RTM_NEWROUTE`, AF_INET, via the physical next hop | Yes | helper |
| 3 | `addExclusionRoutesV6` | netlink `RTM_NEWROUTE`, AF_INET6; no-op when `nextHopV6` is empty | Yes | helper |
| 4 | `addInclusionRoutes` | netlink `RTM_NEWROUTE` via the TUN device | Yes | helper |
| 5 | `removeRoutes` | netlink `RTM_DELROUTE`, helper's own table only | Yes | helper |
| 6 | `createTUN` | `open("/dev/net/tun")` + `TUNSETIFF`; fd returned via `SCM_RIGHTS`, client wraps with `CreateTUNFromFile` | Yes | **split** — §5 |
| 7 | `configureTunInterface` | netlink `RTM_NEWADDR` + `RTM_NEWLINK` setting `IFF_UP` | Yes | helper |
| 8 | `addSplitDefaultRoute` | netlink `RTM_NEWROUTE` ×2 (`0.0.0.0/1`, `128.0.0.0/1`) via the TUN address | Yes | helper |
| 9 | `disablePhysicalIPv6` | sysctl write `net.ipv6.conf.<if>.disable_ipv6=1`, prior value captured | Yes | helper |
| 10 | `enablePhysicalIPv6` | same path, restoring the captured value | Yes | helper |
| 11 | `enableKillSwitch` | nftables over netlink: one table, an output chain with policy `drop`, allow rules for the TUN device, loopback and DHCP, plus a named set for control/bypass addresses | Yes | helper |
| 12 | `disableKillSwitch` | nftables delete-table, one transaction | Yes | helper |
| 13 | `recoverKillSwitch` | list tables, delete the helper's own if unowned; idempotent | Yes | helper |
| 14 | `refreshKillSwitchAllowIP` | nftables add-element on the named set — atomic, no rule rebuild (§8) | Yes | helper |

Thirteen of fourteen need `CAP_NET_ADMIN`. The exception is `defaultGateway`, which is a
pure read and could have run client-side; §2 explains why it does not.

Two properties of the interface survive the split and constrain the stub. First, the
error/no-error division in `osnet.go` is load bearing — the route mutators are
best-effort and silent, `createTUN`/`configureTunInterface`/`addSplitDefaultRoute`/
`enableKillSwitch` return errors — so a transport failure on a silent method must stay
silent, and a transport failure on a fallible one must surface. A stub that turns every
socket error into a returned error changes the fail-closed posture the bar depends on.
Second, `defaultGateway` is called repeatedly during a session, not once: `poolroutes.go`
refreshes it in the background for roaming (`old #117`, `old #123c`), so the helper must
serve concurrent requests and must let a session's cached gateway be re-derived.

## The card's split-tunnel item is not an open decision

#37 lists the split-tunnel mechanism as needing "a decision, not just an implementation,"
naming routing rules, cgroup v2 classification, or a netns. **That framing is wrong, and
adopting it would send #37 to build something the project has already decided not to
have.**

Bacchus's split tunnelling is destination-based. `splittunnel.go`'s first line says so,
and its only decision function is `direct(ip net.IP) bool` — it takes an address. There is
no process, pid, cgroup or executable path anywhere in the policy, the config surface
(`Bypass []string` / `BypassMode string`), or the matcher. cgroup v2 classification and
network namespaces are mechanisms for answering *"which application produced this
traffic?"* — a question this design never asks.

Per-app split tunnelling is not an open question either. ADR-0025 ruled it out in its
Consequences, on `old #40`'s own scope cut, consistent with ADR-0011's narrow-v1 stance;
`clients/windows/README.md` states the same limitation to users. Nothing in #37 reopens
it, and #37 is not the place it would be reopened.

So what remains on Linux is not a mechanism choice. It is three `osNet` methods —
`addExclusionRoutes`, `addInclusionRoutes`, `removeRoutes` (rows 2, 4 and 5 above) — each
an ordinary route-table entry. The policy half is decided and shipped: exclude/include
mode, the live DNS-learned bypass set, the `old #64` fix that stops include mode
installing a split-default, and the `old #73` lock that makes arming and learning atomic
are all in portable code that Linux inherits without change. ADR-0039's parity item 1
already anticipated this precisely — for split tunnelling, parity is *"wired correctly,"
not "reimplemented correctly."*

**The smaller truth: there is no split-tunnel mechanism decision for #37 to make.** The
card's bullet should be read as already satisfied by `old #64`, and its three candidate
mechanisms belong to a per-app feature that ADR-0025 declined.

## DNS is where `osNet` is genuinely short a primitive

The card flags systemd-resolved as "the one that will bite." It is right, and it is worth
being exact about why, because this is the one place the existing interface does not
stretch to cover Linux.

DNS is handled portably today: `tun2socks.go`'s `handleDNSUDP` intercepts UDP/53 inside
the netstack and resolves over DNS-over-TCP through the tunnel, and there is no DNS method
on `osNet` at all. That works on Windows because a Windows resolver's configured servers
are ordinary routable addresses, so queries leave the adapter, meet the split-default
route, and enter the TUN where the interceptor sees them.

On a systemd-resolved machine — the default on Ubuntu, Fedora and Debian — `/etc/resolv.conf`
points at `127.0.0.53`. That is loopback. **No route can capture it**: the kernel's `local`
table is consulted before `main`, so a `0.0.0.0/1` + `128.0.0.0/1` split-default cannot
override `127.0.0.0/8`. Queries never reach the TUN, and the interceptor never sees them.
The consequences are both bad and neither is a silent success:

- **Kill-switch armed:** resolved's own upstream query egresses the physical interface to
  a plain-DNS server, which the allowlist deliberately does not cover (parity item 2, "no
  plaintext-DNS allowance"). It is dropped. The machine has a tunnel and no working DNS.
- **Kill-switch off:** that query goes out in the clear on the physical interface. A DNS
  leak.

It also silently breaks `splittunnel.go`'s bypass-domain learning, which depends on the
interceptor seeing every query — the mechanism ADR-0025 built for `old #40`.

This is a Linux-specific gap with no Windows counterpart, and it does not fit any of the
fourteen methods above. **`osNet` will need a new primitive for it** — a DNS-capture
method, privileged, helper-side, whose plausible implementations are per-link DNS on the
TUN device via systemd-resolved plus a `~.` routing domain, or an nftables redirect of
loopback-stub traffic, with a `resolv.conf`-rewriting fallback for machines running
neither resolved nor `resolvconf`.

**This record does not choose among those, and does not add the method.** Extending
`osNet` is a change to shared portable code that Windows and macOS also implement, so it
belongs in #37's build half, with `enforcement_darwin.go` considered at the same time.
What is recorded here is that the gap is real, that it is not optional — DNS is in #37's
Exit criteria — and that anyone estimating #37 from the current interface will
under-count it by one method and its three-way distribution problem.

## How #37 gets tested

The orderings are already executable rather than prose, and this changes what #37's
testing has to prove.

`tunnel_test.go` runs `tunnel.go` against a `fakeOS`, and its file doc is explicit that
this is deliberate: *"Two of the three platforms that will implement this interface do not
exist yet, and these are the tests that tell `[E9]` and `[E10]` what 'correct' means."*
Five orderings are pinned there — control-plane exclusion before the route flip, the
kill-switch armed last, a failed bring-up orphaning nothing, include mode never installing
a split-default, and `Close` restoring egress before removing the tunnel.

The precise consequence, which is easy to overstate in either direction:

- **Those five tests do not test a Linux backend.** They run against `fakeOS`. Adding a
  Linux `osNet` does not make them exercise Linux.
- **They do mean #37 cannot get the orderings wrong.** The sequencing lives in `tunnel.go`,
  which Linux inherits rather than reimplements. The orderings are structurally inherited,
  not re-established — which is exactly why the boundary must not smuggle sequencing into
  the helper. **The helper executes primitives; it must not own bring-up order.** A helper
  that "helpfully" armed the kill-switch as part of route installation would move a pinned
  ordering to the one side no existing test covers.

So what #37 must newly test is each `osNet` method against a real kernel, plus the
boundary itself:

1. **The helper against a real kernel, in CI, unprivileged.** A user namespace plus a
   network namespace gives an unprivileged process a real, isolated kernel network stack
   with real netlink and real nftables. The helper can be driven inside one and asserted
   against actual kernel state — routes present in the right table, the nft set holding
   the right elements, the TUN device up. This is a genuine advantage over #59, which had
   no equivalent and said so.
   A network namespace is useless as a *split-tunnel mechanism* here (see above) and
   valuable as a *test harness*; those are unrelated uses of the same kernel feature and
   should not be confused for one another.
2. **The protocol's refusals.** A malformed prefix, an unknown verb, a missing or wrong
   session token, a second concurrent client, a `removeRoutes` naming a route the helper
   did not install, and a peer uid with no active session — each must be refused, and the
   refusal is the assertion.
3. **Parity item 8, on Linux.** A traffic-level test, not a state-level one:
   `traffic_test.go`'s three tests already carry the shape, and the in-memory TUN
   (`memtun_test.go`) is what lets them run unelevated. On Linux they can be run for real
   inside a netns, with the kill-switch armed and the client killed, against a listener
   that records arrivals — closing on Linux the gap ADR-0039's #59 amendment recorded as
   unverified on Windows hardware, and still open there as #88.

What a netns cannot prove is the same class of thing #59 was honest about: that a
*desktop* machine's real systemd-resolved, real NetworkManager and real physical adapter
behave as the namespace's synthetic ones did. That is hardware verification, it is not
something Go can assert, and #37 should say so in the same terms rather than implying
CI coverage it does not have.

## Consequences

- **Linux gains an installation step.** The client stops being "download a binary and run
  it": `bacchus-netd`, a systemd unit, a socket, and a `bacchus` group have to be
  packaged and installed with root. This is the largest cost of this decision and the main
  thing given up against polkit. It also means the AppImage/flatpak-style single-file
  distribution is not achievable for the enforcing client, only for the SOCKS-only mode.
- **A new root attack surface exists**, reachable from an unprivileged local process. §3's
  validation list and §4's no-strings-become-commands rule are what keep it small, and
  they are load bearing rather than defensive style.
- **Two binaries must be version-matched.** A `bacchus-netd` older or newer than the GUI
  must refuse the connection with a clear error, not negotiate down to a subset. A client
  that silently loses the kill-switch because the helper is old is parity item 7's failure
  mode wearing a version skew.
- **Non-systemd distributions need their own packaging.** Socket activation is an
  optimization, not a requirement — the helper is a plain binary listening on a unix
  socket, and any supervisor can start it — but the shipped unit covers systemd only.
- **`clients/fyne` must fail the connect when the helper is unreachable**, exactly as #59
  made it do when Windows enforcement fails, and `Controller.DeviceEnforced` must stay
  false. Falling back to a working SOCKS proxy under a "Protected" banner is the failure
  parity item 7 exists to rule out, and a missing helper is the most likely way to meet it
  on Linux.
- **The Linux `osNet` implementation is small.** It is fourteen marshal-and-send stubs
  with no privileged code. The volume of #37 sits in `bacchus-netd` and in the netlink and
  nftables encoding — which is where ADR-0039's costing put it, and it is one of the two
  652-line files' worth of genuinely new work, not the six-file port the card's Scope
  section describes.
- **`old #64`, `old #73`, `old #109`, `old #117`, `old #123b` and `old #123c` are not
  reopened on Linux.** Every one of those was fixed in code that is now portable and
  shipped, which was the point of #59's re-pointing. The hardening ADR-0039 worried a port
  would reopen is inherited, not re-derived — provided the helper stays a primitive
  executor and does not reimplement any of it.

## Scope: what this record does not decide

- The wire encoding of the protocol, and the exact request set. §2 fixes the vocabulary
  and §3 the validation; the serialization is #37's.
- `nftables` vs a legacy-`iptables` fallback for older distributions (§4).
- The DNS primitive: that `osNet` needs one is recorded above; which one, and how Windows
  and macOS answer the same method, is #37's build half.
- Any change to the `Enforcer`/`Session`/`Policy` seam. Nothing here requires one — this
  record sits entirely below `osNet`, which is the package's internal porting surface and
  not a contract for callers.
- macOS. `[E9]` (#36) faces the same question with different answers — a system extension
  and `pf` rather than a helper and nftables — and gets its own record.
- #37 itself, which stays open. This is its design half; the card's Exit criteria are
  unmet until the enforcement exists.

## Amendment (2026-07-31): what building it corrected (#37's build half)

The design above survived implementation intact — the helper, the socket, the
peer-credential gate, the one-session rule, netlink-not-shelling-out, the fd
handoff and the nftables kill-switch are all as decided. Three things needed
correcting, and all three are mechanism rather than decision, so they are
recorded here rather than in a new record.

**§5's named entry point is wrong, though its argument is right.** The record
says `CreateTUNFromFile` (`tun_linux.go:585`) "does only unprivileged work on a
descriptor it is handed". It does not: its last step is `setMTU`, an
`SIOCSIFMTU` ioctl needing `CAP_NET_ADMIN`, so an unprivileged client handed a
descriptor gets `operation not permitted` and no device. The entry point that is
genuinely unprivileged is **`CreateUnmonitoredTUNFromFD`** — `TUNGETIFF` and
`TUNSETOFFLOAD` on the fd it was given, nothing else. What it gives up is the
netlink link-event listener behind `Device.Events()`, which nothing in this repo
calls. So the helper sets the MTU itself, which it was always better placed to
do. The split is still exactly where §5 says it is, and the dependency is still
not forked.

**The device must not be created with `IFF_VNET_HDR`.** `CreateTUN` sets it, and
with it set wireguard-go's `Write` requires an offset of at least
`virtioNetHdrLen`. `tun2socks.go`'s `pumpOutbound` calls `dev.Write(bufs, 0)` —
correct for wintun, which has no such header — so on a vnet-hdr device every
outbound packet fails with "invalid offset" while every state-level check stays
green. Creating it without the flag makes the Linux device honour offset 0
exactly as the Windows one does, so the portable pump needs no change. The cost
is GSO/GRO batching, which this architecture cannot use anyway: every flow is
terminated in the netstack and re-dialled over SOCKS, so nothing large passes
through end to end.

**§3.1's session check applies to every uid, including root.** An early draft
refused uid 0 outright. That is defensive rather than defensible: a root process
can already replace the helper binary, ptrace the GUI, or make the same netlink
calls itself, so refusing it protects nothing while breaking a root console
login, which is a genuine active session. The rule is the one §3.1 states — does
this uid own an active local session — and nothing else.

Two things the record left open are now answered by the build half, as it said
they would be:

- **The wire encoding** is length-prefixed JSON with hard caps, decoded with
  unknown fields refused; `cmd/bacchus-netd/netdwire` is the whole of it.
- **No legacy-`iptables` fallback ships.** nftables only. Nothing in the
  supported-distribution range needs it, and a second firewall backend is a
  second thing that can be subtly wrong in the mechanism the kill-switch depends
  on. Reopen it against a distribution that actually fails, not in advance.

**DNS is not answered**, deliberately, and is now #104. The record's warning that
"anyone estimating #37 from the current interface will under-count it by one
method and its three-way distribution problem" is why it is a separate card: the
new `osNet` method is a change to shared code Windows and macOS also implement,
which does not belong in the change that wrote a helper, a protocol and a
backend. #37 stays open on it.

One property the record predicted is worth confirming, because it was the
argument for hand-rolling netlink rather than taking two modules: driving the
helper inside a user + network namespace catches encoding errors that a
transaction-level check cannot. It found a required nftables attribute whose
absence the kernel rejects, two `meta` keys that encode to a VALID comparison
against the wrong field — so the rule installs, matches nothing, and every "did
it arm?" check passes — an `rt_protocol` id that collided with `RTPROT_BGP`, and
a buffer-aliasing bug that corrupted any netlink dump spanning more than one
datagram. That is the verification §"How #37 gets tested" promised, and it is
verification bacchus#59 never had.

## Amendment (2026-08-02): §3.1's session check, and DNS (#104, #111)

**DNS is now answered.** The primitive this record identified and deliberately
left open is decided in ADR-0051, which also corrects the reason recorded above.
The `127.0.0.53` analysis is right about the first hop and incomplete about the
second: resolved's own upstream query does not fall into the tunnel behind the
stub either, because that socket is scoped to its link and link scoping
overrides the routing table. Measured. The practical consequence is that this
record's phrasing — "an nftables redirect of loopback-stub traffic" as a
plausible implementation — describes something that does not work; ADR-0051 §"The
measurement" has the numbers. What survives intact is the claim this record
actually staked: that `osNet` was short exactly one method, and that its
three-way distribution across Windows and macOS was the reason not to fold it
into #37.

**§3.1 said less than the code does, and #111 is the correction.**
`uidHasActiveSession` accepts logind's `online` as well as `active`, where §3.1
says only "the peer's uid must own an active local session (logind seat)". The
code is right and this record was wrong; the words are amended rather than the
gate narrowed, and the reason is worth stating because the card's own premise
did not survive checking.

#111 supposed `online` was the state admitting a seatless SSH login. It is not.
For a uid, logind reports `active` when it owns at least one session that is its
seat's foreground session **or has no seat at all** — a session with no seat is
unconditionally active. So a plain SSH login, and a cron job, already arrive as
`active`. Narrowing this gate to `active` would not have excluded a single
remote login. What it would have excluded is the case `online` exists for: a
local user at a seat who has been switched away from, by fast user switching or
a VT switch. Their session stops being their seat's foreground session and the
uid drops to `online` while they remain logged in at the machine. Refusing that
would tear down a live tunnel because somebody else took the console.

Three things follow, and all three are now in the code:

1. **`online` stays, with the reason stated** where previously only the
   exclusions carried one.
2. **The exclusions' stated reason was wrong** and is corrected. `lingering` and
   `closing` were excluded here because "a lingering user has no seat, which is
   the whole point of asking" — but seats are not what separates them.
   `lingering` is a uid that is *not logged in* with user services still
   running; `closing` is one that is *not logged in* with processes winding
   down. Presence is the discriminator, not seats.
3. **§3.1's parenthetical "(logind seat)" is withdrawn.** This gate does not
   assert a seat and cannot: neither state it accepts implies one. The question
   it actually answers is *is this uid logged in on this machine right now, as
   opposed to lingering, closing, or gone*. If a seat is ever genuinely
   required — to exclude remote logins from device-wide enforcement, which is a
   real question this record never asked — the primitive is logind's `SEATS=`
   field, not `STATE=`, and it deserves its own card rather than being smuggled
   in as a tightening of this one.

A locked screen is unaffected either way: logind's state computation does not
consult `LockedHint`, so a locked desktop session stays `active`. Multi-seat is
unaffected too, since each seat has its own foreground session and both uids
read `active`.

One consequence for §4 is recorded in ADR-0051 §3 rather than here: the helper
now links a D-Bus client, so `uidHasActiveSession`'s comment no longer justifies
its file read by the cost of that dependency. The file read stays, for the
reason that survives — it is on the connection-accept path, where a file read
cannot block on a bus that is starting or wedged.
