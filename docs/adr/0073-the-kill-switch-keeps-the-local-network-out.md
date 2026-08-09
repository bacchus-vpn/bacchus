# 73. The kill-switch keeps the local network out, and the client says so

- Status: accepted
- Date: 2026-08-09

## Context

While Bacchus is connected with the kill-switch armed, the machine cannot reach
its own local network. Measured on Windows 11 during the 2026-08-09 hardware
pass, connected, on a real home LAN: the router's own web page and a LAN host's
SSH port were both refused.

That is not a bug in the lockdown's implementation. It is what the lockdown says:

```
Bacchus-Allow-Tunnel  | iface=Bacchus | remote=Any
Bacchus-Allow-Remotes | iface=Any     | remote=127.0.0.0/8, <coordinator>, the resolved bypass hosts
Bacchus-Allow-DHCP    | iface=Any     | UDP 68->67
```

with the machine's outbound default flipped to `Block`. No RFC1918 range appears
anywhere in it, so every LAN destination falls to the default. `Bacchus-Allow-DHCP`
is correctly narrow — UDP 68 to 67 only — so it does not incidentally cover
anything else. The Linux side is the same shape from a different mechanism: an
nftables `output` chain with policy `drop`, accepting the tunnel interface,
loopback, and an allowlist set holding the control plane and the bypass entries
(`cmd/bacchus-netd/nft.go`). Neither platform allows the LAN, and neither was
written to.

**It has always been an emergent property.** No record says the local network is
excluded; it is excluded because nothing put it in. That is what #257 is
actually about: not that a VPN blocks the LAN — several do — but that this one
does it undocumented, unwarned, and invisible, so the only signal a user gets is
that Bacchus says *Protected* and their printer stops answering.

The predictable outcome of that silence is the dangerous part. A user concludes
the VPN broke their network, and the fix available to them is the kill-switch
checkbox — the one setting that must not be turned off for a bad reason.

Two facts frame the decision, and both were established on the way to it:

- **It is the firewall, not the routing.** A directly connected subnet is an
  on-link route with a longer prefix than the split-default's `0.0.0.0/1` +
  `128.0.0.0/1`, so it wins on longest-match and LAN traffic never enters the
  tunnel. With the kill-switch off, the LAN works normally. This is why the
  disclosure below is conditional rather than permanent — a client that warned
  about a block that was not in force would be this project's characteristic
  defect running backwards.
- **There was no manual escape.** #137's documented workaround for coexisting
  with another VPN is to add its range to `bypass`, and #258 measured that a
  prefix in `bypass` did nothing on the machine it was tried on. A ruling that
  says "punch the hole yourself if you want it" is only honest if the hole can
  be punched.

## Decision

### 1. The local network stays outside the lockdown

No RFC1918 allowance is added, on either platform, and there is no
"allow local network" toggle in 1.0.

The reason is what a LAN allowance actually is. It is not a hole for the user's
printer; it is a hole for **every host that can put a packet on that link with a
source in the allowed range**, at a moment when this machine's whole posture is
that nothing but the tunnel leaves. The threat model this product is built for
(`docs/threat-model.md`) includes networks the user does not control — a hotel,
a café, a shared building, a hostile ISP's CPE — and on those the "local
network" is other people. A deanonymising probe from a LAN peer is cheap and
does not need the user to do anything: a link-local HTTP request, an mDNS query
answered, an SMB connection that leaks a machine name.

The commercial-VPN argument for the toggle is real and is not being dismissed:
every one of them ships it because every one of them gets this complaint. It
is refused **for 1.0** on the record, and what makes that refusal survivable is
§3 below — the block is now visible before it surprises anybody, and it has a
manual escape for a user who wants one and can name what they are opening.

### 2. `bypass` is that escape, and it takes prefixes

A user who wants their NAS back adds its range to `bypass` — `192.0.2.0/24`
shaped — and it is carved out of both the routing and the lockdown, exactly as
a bypass host name already was.

This is a scoping decision, not only a mechanism: the hole a user gets is the
one they wrote down. `192.0.2.10/32` for one printer is available to somebody
who wants only that, and is a different exposure from a `/16` covering the whole private range.

Prefixes were in fact already honoured by `newBypassPolicy`; what #258 found is
the shapes around them that were **accepted, stored, shown back in the config
file, and ignored** — an IPv6 prefix, a malformed one, an address one octet
short. Those are now refused out loud (`CheckBypass`, reported at startup and at
every connect). Accept-and-ignore is the one option this record forecloses: a
user who reads their own config file and sees the entry has every reason to
believe the hole is open.

### 3. The client says it, at the moment it becomes true

Three places, in the order a user meets them:

- **The connect UI.** With the kill-switch armed on a routed build, the
  Protected line reads *"All of this device's traffic goes through Bacchus.
  Other devices on your local network — printers, file shares, your router's own
  page — are not reachable while it is."* Shown only when the kill-switch is
  actually armed, per the on-link fact above.
- **The Settings window**, next to the kill-switch checkbox, where the decision
  is made rather than where the consequence lands — including the one-line
  instruction for keeping a single device.
- **`docs/RUNNING.md` and the client README**, for whoever is reading before
  they install rather than after something stopped working.

The UI is listed first deliberately. A property that is only in a document is a
property the person it affects learns about after they have already drawn their
own conclusion.

## Consequences

- A user who wants their LAN must either name the range in `bypass` or turn the
  kill-switch off. The first is now expressible and the second is now an
  informed choice rather than a guess at what broke.
- The disclosure is another sentence on the one screen this project keeps
  deliberately quiet. It is accepted here because the alternative is the user
  discovering the same fact by watching something stop working, and reaching for
  the wrong lever.
- A `bypass` prefix covering the LAN reopens exactly the exposure §1 refuses,
  for exactly that range. That is the intended shape — the user names it — and
  it is not narrowed further by a warning at save time, which would be a
  second-guess of a setting whose whole purpose is to be an override.
- Windows and Linux are held to the same answer. They arrive at it through
  different mechanisms (`New-NetFirewallRule` + `DefaultOutboundAction Block`
  versus an nftables chain with policy `drop`), and the fact that both already
  behaved this way without either being told to is the reason this record
  exists.
- **Not decided here:** whether an "allow local network" toggle ships after 1.0,
  and if so whether it is a fixed RFC1918 set or the interface's own prefix. The
  second is the better shape — it grants what the machine is actually attached
  to rather than a class of address — and it needs a mechanism to read that
  prefix on both platforms, which is work this record does not price.

## How this is tested, and what the tests cannot prove

- `clients/fyne/ui_test.go` asserts the Protected line names the local network
  when the kill-switch is armed and does **not** name it when it is off or when
  the build routes nothing. That is the whole of the fix a Go test can hold.
- `clients/internal/enforcement/splittunnel_test.go` asserts a prefix in
  `bypass` reaches `staticEntries` — which is what `tunnel.go` hands to both
  `addExclusionRoutes` and `enableKillSwitch`, so there is no third path — and
  that every entry shape the classifier refuses is named rather than dropped.
- `killswitch_windows_test.go` asserts the prefix survives into the generated
  `-RemoteAddress` list.

What none of them prove is the measurement this record is built on: that an
armed lockdown really does refuse a LAN destination, and that a `bypass` prefix
really does restore it. Both are OS guarantees on a machine with a real adapter
and a real LAN, the same class ADR-0039 records for the kill-switch itself, and
they need a hardware run (see the `needs-owner-test` card raised with #257).
