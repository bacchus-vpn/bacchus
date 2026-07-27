# 14. The kill-switch is enforced by an OS firewall default-block, not by routes

- Status: accepted
- Date: 2026-07-03

## Context

ADR-0010 committed the client to a fail-closed kill-switch: if the tunnel
drops, no traffic may egress in the clear. The full-device routing from the
first half of issue #13 steers all default traffic into the wintun adapter,
whose only egress is the userspace netstack, which only forwards via the
SOCKS tunnel. That is already fail-closed *while our process and the adapter
are alive* — a dead data path just makes connections fail.

But the threat model's worst case is precisely the one routing can't cover:
**our own process dying.** When the client process exits (crash, kill,
OOM), the wintun driver auto-removes the adapter, its routes vanish, and the
physical default route resurfaces — leaking the user's real IP at the exact
moment they believe they're protected. Nothing we install *in* our process
can keep blocking after the process is gone.

## Decision

Enforce the kill-switch with an **OS-level firewall filter that outlives our
process**: while connected, flip the Windows Firewall per-profile
`DefaultOutboundAction` to **Block** and install a narrow allowlist (the
tunnel adapter, the control-plane endpoints, the configured split-tunnel
bypass list, loopback, DHCP — notably *no* plaintext DNS, since DNS runs over
TCP through the tunnel). Restore the prior state on clean disconnect.

To survive our own death, the prior firewall state is stashed in a marker
firewall rule's description; on startup the client detects a leftover
lockdown from a crashed session and restores normal networking before doing
anything else.

Rejected alternatives:

- **Route-based blackhole only** — can't survive adapter/route teardown on
  process death, which is the main leak vector.
- **WFP dynamic filters** (`FWPM_SESSION`) — auto-removed when the creating
  process exits, i.e. they *un-block* on crash: the opposite of fail-closed.
  Persistent WFP filters would work but carry the same crash-recovery burden
  as firewall rules with much more P/Invoke surface; not worth it for v1.

## Consequences

- Genuinely fail-closed, including across a hard crash — meets the ADR-0010
  requirement rather than approximating it.
- The correct-but-sharp trade-off: a crash while connected leaves the machine
  **offline until recovered**. This is intended kill-switch behaviour (no
  leak beats convenience), and recovery is automatic on next launch. It is
  called out in the client README, and users can opt out via
  `disableKillSwitch`.
- Flipping the default outbound action is machine-wide while armed; the
  allowlist must be complete or legitimate traffic (including the tunnel's own
  control plane) breaks. The allowlist is derived from the same exclusion set
  the routing layer already computes, keeping the two in sync.
- The bypass allowance is in place before destination-based split tunnelling
  is routed (a later issue), so that feature won't need to revisit the
  kill-switch.
