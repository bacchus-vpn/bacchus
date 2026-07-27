# Transport pool + per-user failover (issue #15)

The design and rationale live in [ADR-0028](../adr/0028-transport-pool-and-per-user-failover.md).
This note covers the two things an implementer has to decide with care: the
per-network fingerprint and the tuning constants.

## The priority ladder, at a glance

```
0  LEARNED WINNER        this device · this network · this geo   (skip if cooling)
1  primary transport  ×  fastest in-geo exit (by ping)   direct
2  primary transport  ×  remaining in-geo exits (by ping) direct
3  alternate transports × in-geo exits                    direct
4  relay / route through nodes (primary transport)        — last resort

commit only on sustained-flow validation → persist winner → try it first next time
```

`core/selection` is the pure policy (ladder + store); `core/pool.go` drives it
(dial, validate, race, commit, re-race on drop). See ADR-0028 for how each of the
three field traps — "connected ≠ working", "racing is noisy", "learn per network"
— maps to a mechanism.

## `NetworkKey()` — the per-network fingerprint

`core/selection.NetworkKey()` returns the key under which a winning path is
remembered. It must satisfy three constraints at once:

- **Stable per network** — the same operator/network must yield the same key
  across connects, or the learned winner is never reused (defeats the point).
- **Distinct across networks** — a different network must yield a different key,
  or a stale winner from a blocked network gets trusted on a working one.
- **Not user-identifying** — the key is written to disk. Even though the file
  never leaves the device, it must be safe if it leaks: fingerprint the
  *network*, never the person, and **hash** the raw material so no raw MAC / IP /
  SSID is ever stored.

**Implemented: hashed subnet + interface set, plus the gateway MAC where cheap.**
For every up, non-loopback interface, it masks each assigned address to its
*network* (so DHCP changing the host part within a network doesn't move the key),
pairs it with the interface name, and hashes the sorted set. On platforms with a
cheap default-gateway lookup (Windows, `network_windows.go`) it also mixes in the
gateway's MAC, resolved via `SendARP` — the strongest discriminator, since it
identifies the access point, not the user. Everything is hashed into
`hex(sha256("bacchus-netkey\0" ‖ sorted set [‖ "\0gw\0" ‖ gateway MAC]))[:16]`,
so only a digest is stored — no host IP, no raw MAC. Offline (no usable
interface) it returns the `"default"` bucket, which disables per-network
distinction but stays correct.

Candidate raw inputs and where each landed:

| Source | Stability | Distinctness | Portability | Status |
|---|---|---|---|---|
| **Subnet + iface name** | high | medium (two cafés on `192.168.1.0/24` collide) | pure Go (`net.Interfaces`) | **chosen base** — portable, no OS-specific calls; masked + hashed |
| **Default-gateway MAC** | high | high (MAC is per-AP) | platform-specific ARP (`SendARP`) | **mixed in on Windows (#77)** — breaks the subnet collision; `""`/skipped elsewhere |
| Connection-specific DNS suffix | medium | medium | platform-specific | rejected — often empty on consumer nets |
| Wi-Fi SSID | high | medium (SSIDs repeat) | Wi-Fi only, needs OS API | rejected — no signal on wired/tethered |

The subnet+iface base is portable and safe; its one weakness was that two
different networks sharing the same private subnet and adapter collided into one
bucket. **#77** breaks that by mixing in the gateway MAC where a cheap lookup
exists: the two cafés share a subnet but sit behind different access points, so
their gateway MACs — and therefore their keys — differ. It is strictly additive:
where no gateway resolves (other platforms, or a connect with no default gateway)
the gateway segment is omitted and the key is byte-for-byte the pre-#77 digest,
so no already-learned bucket is invalidated and the collision is simply left
unbroken — never a regression. Even unbroken, a mis-keyed winner only fails
sustained-flow validation and the ladder falls through, so this was always a
learning-efficiency issue, never a correctness or leak one.

## Late underlay exclusion — reality on the full-device client (#109)

A full-device tunnel (the Windows client) routes every destination through the
tunnel and, under the kill-switch, blocks everything not on a small allowlist. So
a candidate's own **underlay** connection — the transport's connection to the
exit — must be carved out of that tunnel (a host route via the physical gateway)
and allow-listed, or it loops into the tunnel it is carrying and, once the
kill-switch arms, is Blocked.

WebRTC gets this for free: `ForceRelay` pins every candidate to the one
configured TURN server, whose address is fixed and excluded up front. Reality
can't be pinned — its exit dial address is in the per-session coordinator answer,
known only at `Dial` time — so the pool exposes it late:

```
Config.OnUnderlayDial(addr)   fired by the transport in dialInner,
                              BEFORE it opens the underlay connection to addr
```

The client (`clients/windows/poolroutes.go`) wires this to a `poolExcluder` that
installs the exclusion route and, under the kill-switch, the allowlist entry, and
returns only once `addr` is tunnel-safe. Firing on the **dial path** — not after
the pool commits a winner — is what makes a mid-session failover safe: when
`maintainPath` re-dials a different exit while the split-default route is already
live, that re-dial excludes its own new address as it dials it, so the route flip
never races the real address. Every partial failure fails *closed* (a missing
route loops the dial into the tunnel; a missing allowlist entry lets the
kill-switch Block it) — the path breaks, nothing egresses in the clear. See
ADR-0028's #109 amendment and `docs/design/client-connection-ui.md` for the full
reasoning and the arm/reserve locking (which mirrors the #73 arm/learn fix).

## Tuning constants (all in `core`, easy to change)

| Constant | Default | Meaning |
|---|---|---|
| `poolStagger` | 800 ms | happy-eyeballs delay before starting the next candidate |
| `poolParallel` | 2 | max candidates dialing at once (keeps the wire quiet) |
| `probeBytes` | 32 KB | validation payload; must exceed the ~16 KB freeze threshold |
| `candCooldown` | 30 s | how long a failed candidate sinks within its tier |
| `selection.DefaultTTL` | 14 d | how long a learned winner is trusted before re-racing |
| `reselectBackoff` | 2 s | delay between failover reselection retries |
| `reselectRetries` | 4 | reselection attempts before failover gives up |

`probeBytes` is the one with a real cost (bandwidth per validated candidate on
metered mobile) versus a real benefit (confidence the path clears the freeze).
Tune it down once the RU freeze threshold is re-measured from the field.
