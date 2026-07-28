# Deploy — server services under systemd

Runs the server-side services (coordinator, node/exit) as systemd units
so they auto-restart, survive reboot, and log via journald. The coordinator
binary embeds the STUN/TURN server (pion/turn) and the cold-start bootstrap
listener, blended onto one UDP port (issue #30) — there is no separate TURN
service.

Secrets and host-specific values live in **env files** under `/etc/bacchus/`
(gitignored) — the `.service` files reference them via `${VARS}`. Only the
`*.env.example` templates are tracked.

## Install (on the server box)
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
5. Enable + start:
   ```bash
   systemctl daemon-reload
   systemctl enable --now bacchus-coordinator bacchus-exit
   systemctl status bacchus-coordinator bacchus-exit
   ```

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
client will ever match.

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

## Cold-start bootstrap (issue #18)
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

## Notes
- These run on the server box(es). A **relay** or **client** node runs the same
  `bacchus-node` binary with a different `-role`, not as these units.
- The TURN password (`TURN_PASS`) must match across the coordinator and every
  node/client.
