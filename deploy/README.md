# Deploy — server services under systemd

Runs the server-side services (coordinator, node/exit) as systemd units
so they auto-restart, survive reboot, and log via journald. The coordinator
binary embeds the STUN/TURN server (pion/turn) and the cold-start bootstrap
listener, blended onto one UDP port (issue #30) — there is no separate TURN
service.

Secrets and host-specific values live in **env files** under `/etc/bacchus/`
(gitignored) — the `.service` files reference them via `${VARS}`. Only the
`*.env.example` templates are tracked.

## Install

`install.sh` does everything in this file, in one command, and — the part that
matters more — undoes it:

```bash
sudo sh install.sh node --role coordinator
sudo sh install.sh node --role exit          # generates EXIT_KEY on this box
sudo sh install.sh client --user "$USER"     # the desktop client (issue #37)
sudo sh install.sh uninstall node --purge
```

On a server with binaries cross-built elsewhere, `--binaries DIR` skips the
build and needs no Go toolchain. It refuses rather than guessing on a host it
does not understand, never starts a unit whose env file still holds template
placeholders, and is safe to re-run. Full notes, including why it is not
`curl … | sh` and what changes once releases are signed
(issue #34): [docs/RUNNING.md](../docs/RUNNING.md#installing-on-linux-issue-18).

Everything below is the same work by hand — worth reading either way, since it
is what the script is doing on your behalf, and it is the fallback on a host
with no systemd.

## Install by hand (on the server box)
1. Build the Linux binaries (on the dev machine) and copy them to
   `/usr/local/bin/`: `bacchus-coordinator`, `bacchus-node`. `chmod +x` them.
2. Copy the `.service` files to `/etc/systemd/system/`.
3. Create the env files from the templates and fill in real values:
   ```bash
   mkdir -p /etc/bacchus
   cp deploy/node.env.example /etc/bacchus/node.env
   cp deploy/coordinator.env.example /etc/bacchus/coordinator.env
   # edit both: set PUBLIC_IP / ADVERTISE / COORDINATORS / TURN_PUBLIC_IP / TURN_PASS ...
   chmod 600 /etc/bacchus/*.env
   ```
4. Open the firewall (`3478/udp` now carries STUN/TURN **and** the cold-start
   bootstrap listener, issue #30 — see
   [docs/design/bootstrap-protocol.md](../docs/design/bootstrap-protocol.md)):
   ```bash
   ufw allow 8080/udp; ufw allow 3478/udp; ufw allow 49152:65535/udp; ufw allow 20000/tcp
   ```
5. Enable + start — **the coordinator only.** An exit does not belong on this box; see
   step 7.
   ```bash
   systemctl daemon-reload
   systemctl enable --now bacchus-coordinator
   systemctl status bacchus-coordinator
   ```
6. On a **coordinator** host only, install the country-database refresh script and its
   timer as well (`bacchus-geoip-refresh.{sh,service,timer}`) — see
   [Keeping it fresh](../docs/RUNNING.md#keeping-it-fresh-issue-85). It is a separate
   step because it is what makes each node's country *derived* rather than
   *self-reported*, and until it runs the coordinator has no database to derive from.
7. **Do not run an exit on a coordinator host** (issue #60). One machine running both
   sees the signaling for an assignment *and* the egress traffic for it — both ends of
   the correlation the rest of this design spends its budget denying. Put the exit on a
   different box: [Adding another exit](#adding-another-exit-issue-5) below is the
   procedure. If a coordinator host must contribute capacity anyway, give
   it the **relay** role rather than the exit role — a relay learns neither the
   destination nor the plaintext, so the correlation it can offer is far weaker. Full
   reasoning: [One host does not run both a coordinator and an exit](../docs/RUNNING.md#one-host-does-not-run-both-a-coordinator-and-an-exit-issue-60).

## Manage
```bash
systemctl restart bacchus-coordinator
journalctl -u bacchus-coordinator -f
journalctl -u bacchus-exit -f
```

## Update a binary
```bash
systemctl stop bacchus-exit          # stop before replacing a running binary
cp bacchus-node /usr/local/bin/      # (scp'd from the dev machine)
systemctl start bacchus-exit
```

## Adding another exit (issue #5)
Exit selection is only meaningful with more than one exit. To add one, provision
a box in a **different country** and point it at the **same** coordinator with
the **same** `TURN_PASS`. On the new box:

1. Copy `bacchus-node` to `/usr/local/bin/` and `chmod +x` it.
2. Generate a persistent identity for this exit — once, and keep it:
   ```bash
   openssl rand -hex 32     # -> EXIT_KEY
   ```
3. Create `/etc/bacchus/node.env` from `node.env.example` with this box's
   `ADVERTISE`, the shared `TURN_PASS`, and that `EXIT_KEY`. `COUNTRY` is now only
   a **fallback hint** (see below).
4. Install `bacchus-exit.service`, open the firewall (`20000/tcp` +
   `49152:65535/udp`), and `systemctl enable --now bacchus-exit`.
5. Confirm registration in the coordinator log, which states the country **and
   where it came from**:
   ```
   exit registered: <id> -> <addr> country=NL (observed IP)
   ```
   `(observed IP)` is the healthy case. `(node hint, unresolved IP)` means the
   GeoIP database could not resolve this box's address and the coordinator fell
   back to its `COUNTRY=` claim; `country=unknown` means neither worked, and such
   an exit is registered, healthy, and **unreachable** — a country is the only
   thing a client can ask for.

Each exit needs its **own** persistent `EXIT_KEY`.

Since issue #136 the coordinator **derives** each node's country from the source
address it observes the node register from, using a local GeoIP database
(`-geoip`, see [docs/RUNNING.md](../docs/RUNNING.md#geoip-country-database-issue-136-adr-0042)).
`COUNTRY=` in `node.env` is consulted only when that address resolves to nothing,
and not at all under `-geoip-required`. So a typo there no longer silently
corrupts selection — a malformed tag becomes "unknown" rather than a country no
client will ever match. Staging that database, and keeping it from going stale
afterwards, is `bacchus-geoip-refresh.timer` on the coordinator host (issue #85) —
[Keeping it fresh](../docs/RUNNING.md#keeping-it-fresh-issue-85). Until it has run, the
first row of the table below is the row you are on.

**How far that goes depends on how the coordinator is run**, and it is worth
being precise, because the flag names do not make it obvious:

| coordinator flags | where an exit's country comes from |
|---|---|
| neither (the default) | 100% the node's own `COUNTRY=` claim — nothing is derived |
| `-geoip <dir>` | the observed signaling address, falling back to `COUNTRY=` when it does not resolve |
| `-geoip` + `-geoip-required` | the observed signaling address, **corroborated by the exit's advertised endpoint**, or no country at all |

Even at the strictest setting the guarantee is bounded. What is verified is the
address the coordinator **observed the register arrive from**, checked against the
data-plane endpoint the exit advertises: an exit that forwards only its
coordinator signaling through a host in another country is detected and, under
`-geoip-required`, refused a country entirely (it is then offered to no one).

That check needs something to check, so **under `-geoip-required` an exit must set
`-advertise` to get a country at all** (issue #2). An exit that advertises nothing has
made no claim to contradict, and until #2 that passed the check vacuously — which meant
the split-endpoint setup above was defeated by *omitting* a flag, since `-advertise` is
empty by default and a direct-mode exit does not otherwise need it. Under the flag,
silence is now treated as unverifiable rather than as agreement. Such an exit registers
and runs normally; it simply carries no country, and the coordinator logs which of the
three reasons it was:

```
WARNING: exit <id> has NO country: its address resolved, but it advertises no
data-plane endpoint and -geoip-required is set … Set -advertise to the address it
serves from.
```

**Without `-geoip-required` nothing changes**: an exit with no `-advertise` keeps its
observed country exactly as before. The flag is what buys the guarantee, so it is the
flag that carries the requirement — you do not have to reconfigure a fleet that never
asked for it.

And the coordinator never sees the egress itself, so an operator who places their whole
apparatus behind one address can still egress elsewhere. Country is a
strong signal about where a node sits, not a proof about where its traffic leaves.
See ADR-0042 §8 and its #2 amendment.

### What the signed directory says about a country (issue #3)

Every entry in the signed snapshot now carries a `countrySource` alongside its
`country`, because the signature proves the coordinator *said* the country and says
nothing about how it arrived at one:

| `countrySource` | meaning |
|---|---|
| `observed` | resolved from the address the coordinator observed, and the advertised endpoint agrees |
| `hint` | the observed address resolved to nothing, so this is the node's own `COUNTRY=` claim — the only source in a deployment with no `-geoip` staged |
| `observed-signaling-only` | resolved, but the advertised endpoint is a **different** address: the tag says where the node signals from, not where it egresses |
| `unverifiable-no-endpoint` | resolved, but nothing was advertised to corroborate it under `-geoip-required` (carries no country) |

A client assembling its own relay chain refuses `observed-signaling-only` as a
terminating exit: it chose that country as a jurisdiction, and the coordinator has
published that the tag describes a different machine. `hint` is still accepted — refusing
it would break every deployment running without `-geoip`.

Exits **may** share a country: a client picks a country and the coordinator picks
the exit inside it by headroom (issue #146, ADR-0042), so two exits in the same
place is a load-balancing pool, not an ambiguity. There is no exact-exit pinning.

## Cold-start bootstrap (`old #18`)

> That number is from the **retired** tracker (see the tracker note in the root
> [README](../README.md)). It is written as a code span so it cannot autolink —
> in the current tracker `#18` is the installer at the top of this file, which is
> a different thing entirely. The rest of the repo still carries this reference
> bare in about twenty places; those are tracked separately.

The coordinator generates its snapshot-signing keypair on first run and logs
the public key once:
```bash
journalctl -u bacchus-coordinator | grep 'bootstrap: generated new signing key'
```
Bake that public key into client config, then issue per-user invites from the
dev machine (or the server) with `cmd/coldstart-issue` — it appends to
`/etc/bacchus/bacchus-bootstrap-secrets.json`, which the running coordinator
picks up within 30s with **no restart**:
```bash
go run ./cmd/coldstart-issue \
  -secrets /etc/bacchus/bacchus-bootstrap-secrets.json \
  -coordinator YOUR_VPS_PUBLIC_IP:3478 \
  -pubkey <hex from the log line above>
```
Hand the printed `bacchus1:...` invite string to the new user out of band
(messenger, QR in person — never through a channel the app itself controls).
See [docs/design/bootstrap-protocol.md](../docs/design/bootstrap-protocol.md).

## The one unit that is not a server unit: `bacchus-netd` (issue #37)

`bacchus-netd.service` / `.socket` are the odd pair in this directory. Everything
else here runs on a **server** box; these run on a **desktop**, next to
`clients/fyne`, and they are what make the Linux client route the device instead
of offering a SOCKS port.

The split is [ADR-0049](../docs/adr/0049-linux-privilege-boundary.md): the GUI
keeps running as the desktop user with no capabilities, a small helper holds
`CAP_NET_ADMIN`, and they speak over `/run/bacchus/netd.sock`, mode `0660`,
group `bacchus`. Running the whole GUI as root is not acceptable for a client
aimed at ordinary users — Fyne links a GL stack, an X11/Wayland client and a
font renderer, and none of that belongs in a process that can rewrite the route
table.

`sudo sh install.sh client --user "$USER"` performs all three steps below, plus
the GUI binary, a desktop entry, and a per-user config seeded somewhere the GUI
can actually write it back. The manual sequence:

```bash
# 1. Build and install the helper (it is not in /usr/local/bin: it is a helper
#    the user never runs by hand, not a command).
go build -o bacchus-netd ./cmd/bacchus-netd
sudo install -D -m 0755 bacchus-netd /usr/local/lib/bacchus/bacchus-netd

# 2. Create the group and put yourself in it.
sudo systemd-sysusers deploy/bacchus-netd.sysusers.conf
sudo usermod -aG bacchus "$USER"        # log out and back in for this to apply

# 3. Install and enable the socket. The SOCKET is what gets enabled, not the
#    service — the helper is socket-activated and starts when the client first
#    connects.
sudo cp deploy/bacchus-netd.service deploy/bacchus-netd.socket /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bacchus-netd.socket
```

Check it:
```bash
systemctl status bacchus-netd.socket
journalctl -u bacchus-netd -f
```

Things worth knowing before the first support question:

- **Group membership needs a fresh login.** Supplementary groups are fixed when
  a session starts, so `usermod -aG` does nothing for the shell you typed it in.
- **The client fails the connect if the helper is unreachable**, on purpose. It
  does not fall back to a working SOCKS proxy under a "Protected" banner —
  that failure mode is the one ADR-0039's parity item 7 exists to rule out, and
  a missing helper is the most likely way to meet it on Linux.
- **The helper and the client must be the same version.** They refuse each other
  outright on a protocol mismatch rather than negotiating down to a subset; a
  client that silently lost its kill-switch to a version skew is the same
  failure wearing different clothes. Upgrade both together.
- **An armed kill-switch survives everything except a reboot or the next
  launch.** It is nftables state in the kernel, so it outlives the client being
  killed (which is what a kill-switch is *for*) and the helper exiting when
  idle. The next session lifts a stale one; so does a reboot.
- **Non-systemd hosts** can run the binary under any supervisor — socket
  activation is an optimization, not a requirement. Such a host has no logind to
  answer "does this uid own an active local session", so it needs
  `-allow-without-logind`, which drops the gate to the socket's group
  permission alone. That is a real weakening and it is opt-in for that reason.

## Notes
- These run on the server box(es). A **relay** or **client** node runs the same
  `bacchus-node` binary with a different `-role`, not as these units. The
  exception is `bacchus-netd` above, which is a desktop-side unit.
- The TURN password (`TURN_PASS`) must match across the coordinator and every
  node/client.
