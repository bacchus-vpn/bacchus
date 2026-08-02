# Running the stack (our own Go stack)

The validated topology: client → our coordinator/hole-punch → (optional) relay →
exit → internet, all on our own Go stack.

## Topology
```
 client ──WebRTC (our coordinator + STUN/TURN)──► [relay (residential)] ──► exit (VPS) ──► internet
```
| Role | Where | Binary / how |
|---|---|---|
| **coordinator** (UDP signaling + STUN/TURN + cold-start bootstrap, one shared port) | VPS, UDP-reachable from the censored region | `bacchus-coordinator -turn-public-ip <IP> -turn-user <user> -turn-pass <TURN_PASS>` (systemd `bacchus-coordinator`) |
| **exit** (egress) | a VPS that does **not** run the coordinator — see below | `bacchus-node -role exit -listen :20000 …` (systemd `bacchus-exit`) |
| **relay** (forward only, never egresses) | residential PC | `bacchus-node -role relay -advertise <EXIT_HOST>:20000 …` |
| **client** | user device | `bacchus-node -role client …` → local SOCKS5 `127.0.0.1:1080` |

A single node can hold several roles at once (e.g. `-role exit,relay`). One combination is
excluded, and it is not a node-role question at all:

### One host does not run both a coordinator and an exit (issue #60)

ADR-0020 treats the coordinator as **untrusted by standing assumption**. That is not
decoration — it is what justifies country-only exit assignment (ADR-0042), the
client-assembled relay chain (ADR-0038), and the deliberate absence of exact-exit pinning.
The whole matchmaking design is built so that a hostile coordinator cannot deanonymize a
user.

Co-locating an exit defeats that locally. For any session assigned to that exit, one
operator-controlled machine observes both halves of the correlation everything else is
arranged to keep apart: who was assigned, and what left the network. **No protocol change
causes this and no protocol control detects it** — it is purely a property of where the
services are installed, which is why it has to be a rule somebody reads rather than a check
something runs.

It is harmless while the operator is also the only user: there is nothing to learn that is
not already in that operator's own logs. It stops being harmless the moment anyone else
uses the network, which is earlier than 1.0 — roughly `[G2]` closed beta.

**If a coordinator host must contribute capacity, give it the relay role, not the exit
role.** A relay forwards other people's traffic blind: it never learns the destination and
never sees plaintext, so what a co-located relay could correlate is far weaker than what a
co-located exit can. `-role relay` on the coordinator box, `-role exit` anywhere else.

Issue #31 is the same assumption broken a different way — a coordinator that assigns a
first hop which is also one of the client's own chain hops, which the client cannot detect.
That one is a tracked non-goal for 1.0 (ADR-0038's #31 amendment). Both reopen at the same
gate, and are reviewed together rather than separately.

## Build (dev machine)
```powershell
# Linux server binaries
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -o bacchus-coordinator ./cmd/coordinator
go build -o bacchus-node        ./cmd/node
$env:GOOS=""; $env:GOARCH=""; $env:CGO_ENABLED=""
# Windows client
go build -ldflags "-H=windowsgui" -o bacchus.exe ./clients/windows
go build -o node.exe ./cmd/node
```

## Deploy the VPS services
See [../deploy/README.md](../deploy/README.md) — copy the binaries to
`/usr/local/bin/`, install the units, create `/etc/bacchus/*.env` from the
templates (real IP + `TURN_PASS`), open the firewall, `systemctl enable --now`.

## Run relay + client
Endpoints/credentials are passed as flags (or, for the Windows client, via
`bacchus.config.json`). Example (placeholders — fill your own):
```
bacchus-node -role relay  -advertise <EXIT_HOST>:20000 -coordinators <COORD_HOST>:8080 -stun stun:<COORD_HOST>:3478 -turn turn:<COORD_HOST>:3478 -turn-user <user> -turn-pass <TURN_PASS>
bacchus-node -role client -geo <CC>                    -coordinators <COORD_HOST>:8080 -stun stun:<COORD_HOST>:3478 -turn turn:<COORD_HOST>:3478 -turn-user <user> -turn-pass <TURN_PASS>
```
`-coordinators` takes a comma-separated **pool** of coordinator endpoints
(issue #6): `-coordinators host1:8080,host2:8080`. A forwarder (exit/relay)
registers with every member; a client tries them in shuffled, health-ranked
order, so one member being blocked doesn't stop it discovering countries or
connecting. Add `-force-relay` to route via TURN (diagnostic / when a direct
hole-punch is unstable).

`-geo` is the **country** you want to egress in, and it is the only thing a
connect names (issue #146, ADR-0042). The coordinator picks which exit inside
that country you get; there is no way to ask for a specific exit. List what is
available with:
```
bacchus-node -role client -list -coordinators <COORD_HOST>:8080
```
which prints one row per country with how many of its exits are assignable right
now, and marks a country **busy** when none are (issue #147). Leaving `-geo`
empty lets the client take the first available country from that list.

## GeoIP country database (issue #136, ADR-0042)
A node's country is **derived by the coordinator** from the source address it
observes the node register from — never from the node's own `-country` flag,
which is only a fallback hint for an address the database cannot resolve. The
lookup is against a **local** file: there is no outbound geo query, which would
both tell a third party the IP of every node in the network and add a dependency
on reaching a foreign endpoint from inside a censored network.

The database is **not in this repo**: it is bulk data that would be wrong within
weeks of any commit. Fetch and stage it out of band, exactly as the Windows
client does with `wintun.dll`.

**Provenance.** iptoasn.com's *IP-to-Country* files, one
`range_start range_end country_code` row per line, under **PDDL v1.0** — public
domain, no account, no licence key. It is the same publisher core/asn's table
comes from (ADR-0044), so one feed covers both datasets.

```
deploy/bacchus-geoip-refresh.sh /var/lib/bacchus/geoip

bacchus-coordinator -geoip /var/lib/bacchus/geoip ...
```
The script fetches both families, decompresses them and stages them under upstream's
own filenames — the loader looks for exactly those, so nothing is renamed. Both are
staged: without the v6 table an IPv6-registering node resolves to nothing and falls
back to its hint, so the fleet would have to be certainly v4-only for that to be
harmless. The same script is the refresh step; see
[Keeping it fresh](#keeping-it-fresh-issue-85) below.

**Confirm it before treating it as staged.** The startup log prints the row count
**per family** and names the format it read — for example, with counts that move with
every upstream release:
```
geoip: loaded 450917 IPv4 + 117150 IPv6 rows from /var/lib/bacchus/geoip [iptoasn ip2country] (139652 unusable rows skipped)
```
Both families non-zero, both in the hundreds of thousands, and `[iptoasn ip2country]`
named is the healthy case. A large
`unusable rows skipped` count is normal here rather than alarming — upstream attributes
a substantial share of both files to no country at all, and a row with no country is
loaded as a gap rather than as an answer.

**Why not MaxMind GeoLite2** (issue #61). It works and still loads — see below —
but downloading it needs a free MaxMind account and licence key, and its terms
restrict redistribution. That is survivable while one operator runs every
coordinator, since each host fetches its own. It becomes an onboarding tax the
moment coordinators federate: every volunteer operator would need their own
MaxMind account before their coordinator could derive a country at all, and the
alternative to deriving it is trusting each node's self-report. A licence
requirement sitting directly upstream of a security property is worth removing
before anyone depends on it.

A **GeoLite2 Country CSV** staging is still loaded, unchanged, for a deployment
that already has one: put `GeoLite2-Country-Blocks-IPv4.csv`,
`-Blocks-IPv6.csv` and `GeoLite2-Country-Locations-en.csv` in the directory
instead. A directory holding **both** formats loads the range files and ignores
the CSVs, so migrating is a fetch, a restart, and a check that the startup log
names `iptoasn ip2country`.

Refresh it on a **timer, not on memory** — see [Keeping it fresh](#keeping-it-fresh-issue-85)
below. Stale geodata does not fail; it silently mislabels a node's country, so
the coordinator warns at startup once the staged files are more than 90 days old.
A database that is configured but unreadable is **fatal**: an operator who asked
for derived countries must not silently get self-reported ones. So is one that
loads fewer than a thousand rows, which is a half-copied directory rather than a
small release.

`-geoip-required` additionally refuses the `-country` fallback, so no node
self-report can reach a client's country choice at all. Do **not** use it in a
local stack: every node there registers from loopback, which no database
resolves, so every node would end up with no country and nothing would be
assignable. Without `-geoip` at all, the coordinator falls back to each node's
`-country` tag for everything — which is how the local stack and any
pre-staging deployment work.

Under `-geoip-required` an **exit must also set `-advertise`** (issue #2). The
coordinator checks the country it derived from the signaling source against the
data-plane endpoint the exit advertises, and an exit that advertises nothing gives it
nothing to check — which used to pass vacuously, so an operator could defeat the check
by leaving out a flag a direct-mode exit does not otherwise need. Such an exit now
carries no country and is offered to no client; the startup warning names that
specifically, rather than reporting an unresolved address. Nothing changes without the
flag: an exit with no `-advertise` keeps its observed country as before.

### Keeping it fresh (issue #85)

The database is deliberately not in the repository, which means **nothing in CI, no
test and no build can see it go stale** — the one staleness signal is a warning the
coordinator prints at startup, on a process that may not restart for months. A refresh
run by hand closes the gap on the day it is run and reopens it silently over the
following ones, so the refresh is a unit rather than a procedure:

| file | what it is |
|---|---|
| `deploy/bacchus-geoip-refresh.sh` | fetch, decompress and stage both families into a directory |
| `deploy/bacchus-geoip-refresh.service` | oneshot that runs the script against `/var/lib/bacchus/geoip` |
| `deploy/bacchus-geoip-refresh.timer` | runs it **weekly**; carries the reasoning for the cadence |

Install it on each coordinator host:
```bash
install -m 755 deploy/bacchus-geoip-refresh.sh /usr/local/bin/
cp deploy/bacchus-geoip-refresh.service deploy/bacchus-geoip-refresh.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bacchus-geoip-refresh.timer
systemctl start bacchus-geoip-refresh.service   # stage it once, now, rather than next Monday
```
The unit's `ExecStart` names `/var/lib/bacchus/geoip`; if the coordinator's `-geoip`
points somewhere else, change both.

**A refresh cannot leave you worse off than not refreshing.** Each family is fetched
and decompressed under a temporary name *inside the destination directory* and renamed
into place, so a coordinator starting mid-refresh never reads a half-written table; and
nothing is renamed until both families have downloaded, decompressed and passed a row
floor, so a bad download replaces nothing and the previous table survives intact. That
ordering is the point: the fallback for a missing country table is each node's own
self-report, so a refresh able to destroy a good table would be worse than none.

**A refresh does not reach a running coordinator.** The database is read once, at
startup. The unit deliberately does not restart the coordinator — turning a weekly data
refresh into a weekly coordinator restart is an availability decision for whoever runs
the host — so apply it when it suits:
```bash
systemctl try-restart bacchus-coordinator
journalctl -u bacchus-coordinator -n 20 | grep geoip   # confirm the new row counts
```

**A failed refresh is visible, but nothing alerts on it.** The unit exits non-zero and
goes to `failed`, which is what to watch:
```bash
systemctl list-timers bacchus-geoip-refresh.timer
systemctl status bacchus-geoip-refresh.service
```
Attach `OnFailure=` to whatever this host already notifies with. If nobody ever looks,
the backstop is the coordinator's own 90-day staleness warning above — which is a
backstop, not a monitor: it only speaks when the coordinator restarts.

## IP→AS table (issue #23, ADR-0044)

A relay chain's hops are spread across **autonomous systems**, because two hops in
one AS are one operator's hops however they are labelled. The AS is **derived by the
client** from each hop's observed address against a local routing table — never read
from a tag in the signed snapshot, because a Sybil operator asked to state its own
diversity would simply fabricate it.

Unlike the GeoIP database above, **this table is in the repo and ships inside the
client binary**: `core/asn/table.tsv.gz`, ~3.14 MB, loaded by `asn.Embedded()`. There
is nothing to stage and no flag to set. ADR-0044's amendments record why embedding
beat fetching — a periodic table fetch would be a predictable, fingerprintable request
from every client on a censored network, and the mapping drifts only ~1.3% a month, so
the accuracy it buys is not worth the surface it costs.

**Why this table is committed when the country database above is not**, now that both
come from the same publisher under the same terms — PDDL v1.0, public domain,
redistribution permitted, no attribution required — so the licence permits committing
either. What differs is what a commit would buy. The AS table is a **client** input, and
a client cannot be handed a file: embedding is the only way it arrives, and its staleness
is bounded by release cadence (below). The country table is a **coordinator** input on an
operator-run machine that *can* be handed a file, so committing it would buy nothing and
bake in data that is wrong within weeks. GeoLite2, the other loadable country format,
could not be committed under any of this reasoning: MaxMind's terms are not ours to
redistribute under. See [`core/asn/TABLE.md`](../core/asn/TABLE.md) for the full
provenance record.

**A coordinator still takes a file.** `-asn-table <path>` points the coordinator at a
staged table for its capacity attestation (`observedAS`, ADR-0041). That is a separate
consumer with a separate lifecycle — a coordinator is an operator-run machine that can
be handed a file, and its table can be refreshed without shipping a client release.
Without the flag it falls back to a masked `/24`-or-`/48` prefix as the diversity key.
A path that is given but unreadable is **fatal at startup**: an operator who passed the
flag believes AS resolution is running.

### Refreshing the table (per client release)

```
curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip
go test ./core/asn/ ./core/
```

Then, in the same commit, set `TableRetrieved` in `core/asn/embedded.go` to today and
update the retrieval date, hashes and row counts in
[`core/asn/TABLE.md`](../core/asn/TABLE.md).

`asn-stage` turns upstream's address **ranges** into the **disjoint CIDR prefixes**
`asn.Load` requires: it drops the unused country and description columns, drops the
unrouted markers so unrouted space becomes a gap that resolves to *unknown* rather
than inheriting a neighbour's AS, merges adjacent same-AS runs, and splits the rest
into aligned blocks. It is deterministic — the same feed produces byte-identical
output — which is what lets a reviewer re-run it and compare against the committed
file. The download is a separate manual step on purpose, so the transform itself
stays hermetic.

**Cadence is a security parameter, and CI enforces a floor under it.** The mapping
drifts ~1.3% per month and ~3.6% per quarter, so a client that has not been rebuilt in
a year mis-scores roughly one AS verdict in nine. It degrades *safely* — a stale
answer falls into the unknown-pooling rule, never into a false claim of diversity —
but it degrades. `TestEmbeddedTableIsFresh` fails once the committed table is more
than **90 days** old, matching both the GeoIP threshold above and the quarterly
cadence ADR-0044 §6 costed.

That check is a floor, not a schedule: it tells you the table has gone stale, it does
not refresh anything. Wiring the refresh into the release process proper belongs with
the signed release channel (#34) and is tracked separately.

## Transport selection
`-transport` picks the session transport (ADR-0008): `webrtc` (default; UDP/DTLS
with NAT traversal) or `reality` (TCP :443 under camouflage TLS, issue #16). The
two fail on different axes — reality covers networks that throttle UDP or
DataChannels. Both ends of a session must run the same transport.
```
bacchus-node -role exit   -transport reality -reality-listen :443 -reality-advertise <EXIT_HOST>:443 -reality-sni www.microsoft.com -coordinators <COORD_HOST>:8080
bacchus-node -role client -transport reality -geo <CC>                                                                             -coordinators <COORD_HOST>:8080
```
`-reality-advertise` is the host:port clients dial (defaults to `-advertise`);
`-reality-sni` is the site the exit impersonates — the server name worn on the
outer TLS. Clients authenticate inside the ClientHello (ADR-0032), so the exit
decides before terminating TLS whether a peer is one of ours: an authenticated
client is handled locally, while anyone else — a prober, a real browser — is
spliced to the impersonated origin and completes its handshake against that
origin, seeing the origin's genuine certificate chain rather than a self-signed
leaf of ours. `-reality-probe-origin` is that origin: where unauthenticated
connections are spliced and where a failed inner handshake is reverse-proxied
(ADR-0027); it defaults to the SNI host on :443 (on by default), and `off`
restores the immediate close. The reality exit needs no STUN/TURN — TCP does not
hole-punch. A client-side pool that races webrtc against reality per user is
issue #15.

## Exit identity & end-to-end encryption
Traffic is encrypted end-to-end from client to exit (Noise_NK); a relay in the
path forwards ciphertext and the next hop only — it never sees the destination or
content (ADR-0009). The exit is authenticated by its **static public key, which
is its node id**, and a malicious relay cannot impersonate the exit without the
matching private key.

The client does not choose that exit and does not need to know its key in
advance. It asks for a country; the coordinator answers with a session **and the
id of the exit it assigned**, and the client keys its end-to-end handshake on
that (issue #146, ADR-0042). So the key still authenticates the exit — a
coordinator that names the wrong one produces a handshake the real exit cannot
complete — but distributing exit ids to users is no longer part of the workflow.

- An exit generates a fresh key at startup and logs its id
  (`exit <64-hex-id> (<country>) advertising …`). Pass `-exit-key <64-hex>` to
  pin a **stable** identity across restarts. This matters for the OPERATOR
  (admission credentials are bound to the node id, and a changing id means
  re-issuing one every boot), not for clients, which never name it.
- `bacchus-node -role client -list` shows countries, not exits. Exit ids are
  deliberately not enumerable: the list was both a network map and the raw
  material for pinning a client to one node.

## Usage receipts (accounting stub)
Off by default. Pass `-acct-dir <path>` on both the exit and the client to turn
on the co-signed metering stub (issue #20, ADR-0021): every `-acct-interval`
seconds (default 60) they exchange and sign a receipt for bytes served, and
each side appends its verified copy to `<path>/receipts-{exit,client}.jsonl`.
No payout, no tokens — this only proves the two sides agree on the count.
**Direct-mode sessions only** — see
[accounting-stub.md](design/accounting-stub.md) for why relay-mode isn't
covered yet.

## Volunteering your connection (issue #12)
A node that uses the network can also donate itself to it. That used to be
reachable only by knowing to write `-role client,relay,exit`, which nobody finds
by accident; there are two flags for it now, and `bacchus-node -h` lists them.

**Relay and exit are two separate choices, and neither turns on the other.** The
two costs are not comparable:

- **`-volunteer-relay`** carries other people's traffic **encrypted and
  blind-forwarded**. A relay never learns the destination and never sees
  plaintext. What it costs you is **bandwidth**.
- **`-volunteer-exit`** egresses other people's traffic to the internet **under
  your own IP and jurisdiction**. Your address is what every site they reach sees
  in its logs, and abuse reports, provider notices, and legal process arrive at
  **you**. What it costs you is **legal exposure**, and no quantity of spare
  bandwidth is a substitute for having decided that on purpose.

Both are off by default. There is deliberately no single `-volunteer` that turns
on both: one switch spanning them means somebody who meant to donate bandwidth
accepts liability they never read about. Relay-only is the option most home
connections can safely take, and it has to be sayable on its own.

The volunteer flags **add** serve roles to whatever `-role` names, so with the
default `-role client` they make a node that uses the network and also donates to
it. Both may be given together.

### Relay only — what most home connections can take
```sh
bacchus-node -volunteer-relay \
  -coordinators <COORD_HOST>:8080 \
  -max-speed 20Mbit -monthly-quota 400GB -quota-cycle-day 17 \
  -quota-state /var/lib/bacchus/quota.json
```
No port forwarding, no stable identity, nothing else to configure. Behind a home
NAT you serve as a client's **first hop**, reached the way the client itself is —
the coordinator uses the address your registration arrives from. Carrying somebody
else's **middle** hop is a different job: it is reached by an inbound dial, so it
needs a publicly reachable `-relay-ingress` (plus `-relay-directory` and a
persistent `-exit-key`, which the node insists on whatever roles it holds). Behind
a home NAT, first hop and exit are realistic; middle hop is not.

### Exit — a separate decision, with a legal cost attached
This is the one where other people's traffic leaves the internet-facing side of
**your** connection, under **your** address, in **your** jurisdiction.
```sh
bacchus-node -volunteer-exit \
  -listen :20000 -advertise <YOUR_PUBLIC_IP>:20000 \
  -exit-key <64-hex> \
  -coordinators <COORD_HOST>:8080 \
  -max-speed 20Mbit -monthly-quota 400GB -quota-cycle-day 17 \
  -quota-state /var/lib/bacchus/quota.json
```
`-volunteer-exit` refuses to start without the two things an exit actually needs,
rather than registering as an exit nothing can reach:

- **`-advertise`** — the `host:port` a relay dials to reach you. It has to be the
  address the internet reaches you at, with that port forwarded to this machine. A
  wildcard, loopback, or link-local address is **refused**: none of them can be
  dialed from another machine, so registering one is a node that serves nobody and
  says nothing about it. A private or carrier-NAT address **warns and carries on**,
  because a LAN, a lab, or a tunnelled uplink advertises one correctly. Behind
  carrier-grade NAT (`100.64.0.0/10`) there is no port for you to forward at all —
  relay-only works there, an exit will not.
- **`-exit-key`** — a persistent X25519 private key. An exit's node id **is** its
  public key, so a key generated afresh at each start is a new identity at each
  start, while the signed directory clients cache still names the old one: the node
  is unreachable until a new directory propagates, after every restart. Generate one
  once and keep it: `openssl rand -hex 32`.

You do **not** state your country. The coordinator derives it from the address your
registration arrives from and, for an exit, cross-checks that against what you
advertise — see
[GeoIP country database](#geoip-country-database-issue-136-adr-0042). `-country` is
only a hint, consulted when the observed address resolves to nothing.

Bound what any of this costs you with the declared limits below. Volunteering
without them warns at startup rather than silently serving uncapped.

### Your client half can fail without taking your donation down
A volunteer node runs two halves that fail for unrelated reasons: the **serve**
side (relay/exit registrations and listeners) and its **own client** connection.
"Every exit in the country I asked for is busy" says nothing about whether this node
can still carry other people's traffic — so on a node that serves, a client-connect
failure is logged and retried against the running engine (15s, doubling to a
10-minute ceiling) while the serve roles keep serving throughout. It no longer ends
the process. A node that only clients still exits on a failed connect, as before.

### The same choice on the desktop client
The desktop client has the same two opt-ins, as two checkboxes in `File → Settings…`,
with the exit's cost printed next to the exit's own checkbox — see
[clients/fyne/README.md](../clients/fyne/README.md#volunteering-your-connection-12).
Relay-only needs nothing beyond ticking it; exiting asks for the address relays dial
and a permanent identity key, which the window can generate.

One difference worth knowing before you plan a deployment: the desktop client
**refuses to serve on a build that routes the whole device** (Windows today), and is
available where it runs proxy-only (Linux, macOS). A relay or exit sharing a process
with a full-device tunnel has its forwarding caught by that tunnel's own default
route, so other people's traffic would egress at *your* upstream exit rather than
under your address, and an advertised exit would be unreachable. To donate from a
Windows machine, run `bacchus-node` with the flags above — it installs no routes and
has no such conflict.

## Declared node limits (running a node from home)
Off by default: a node with no declared limits is uncapped and unmetered, exactly
as before. This exists so a **residential volunteer** can participate without
risking their ISP bill (issue #143, [ADR-0040](adr/0040-node-capacity-declared-limits-and-attested-measurement.md)).

Declare what you are *willing* to serve — this is a limit on what leaves your
connection, not a claim about how fast it is:

```sh
bacchus-node -role exit,relay \
  -max-speed 20Mbit \            # aggregate, across all sessions
  -monthly-quota 400GB \         # of YOUR CAP — see below; carries ~200GB of traffic
  -quota-cycle-day 17 \          # your ISP BILLING day — see below
  -quota-state /var/lib/bacchus/quota.json
```

- **`-monthly-quota` is spent against your cap, not delivered to users.** Traffic
  you forward crosses your line **twice** — once arriving, once leaving — and a
  residential ISP meters both against one number. So the node counts each byte
  twice, because that is what your bill does: `-monthly-quota 400GB` spends 400GB
  of your cap and carries roughly **200GB** of user traffic. Set it to what you can
  afford to *spend*, which is the number on your invoice, not what you want to
  *serve*. (If your provider bills egress only, as most VPSes do, this over-counts
  by 2x — declare double what you mean to give. The asymmetry is deliberate:
  over-counting stops a node early, under-counting sends you an overage bill.)
- **`-quota-cycle-day` is your billing day, not the 1st.** Residential caps reset
  on the day you signed up. Check your last invoice. Getting this wrong is how a
  node sails past your real cap mid-cycle and you get the overage bill.
- **`-quota-state` is strongly recommended.** Without it the counter lives in
  memory and any restart mints a fresh month.
- Units are decimal, as an ISP bills them (`400GB` = 400×10⁹, not 2³⁰).
- Both the exit **and** relay roles are limited — a relay spends your uplink too.

Enforcement is at both ends, and the node's is the one that counts: the
coordinator stops offering an exhausted node (so it reads as "not offered" rather
than "connection failed"), and the node itself paces to `-max-speed` and stops at
the quota — because you, not the coordinator, pay the overage.

**Don't know your upload speed?** Most people don't. Measure it with both ends in
your own hands:

```sh
go run ./cmd/capacity-probe -serve :9999           # on a VPS or a friend's machine
go run ./cmd/capacity-probe -probe <that>:9999     # on your node
```

That number is a fine basis for your own `-max-speed`. It is deliberately **not**
a capacity the network believes about you — run `capacity-probe -demo` to see why
in about ten seconds.

## Node admission (who may join)
Off by default: with no `-admission-pubkey`, the coordinator serves anyone (and
logs a loud warning). To enforce membership (issue #42, ADR-0023), give the
coordinator the admission authority's public key; then every node and client
must present a credential signed by it.
```
# One-time: mint the admission root key and print its public key.
admission-issue -pubkey                                  # key auto-generated on first use

# Coordinator: enforce admission.
bacchus-coordinator -turn-public-ip <IP> -turn-user <u> -turn-pass <p> -admission-pubkey <PUBKEY>

# Issue credentials (exit bound to its node id; client is bearer) and run with them.
admission-issue -subject <exit-64-hex-id> -roles exit -ttl 720h > exit.cred
bacchus-node -role exit -exit-key <hex> -admission-cred exit.cred  …
admission-issue -subject alice -roles client -ttl 2160h > alice.cred   # hand out of band
bacchus-node -role client -geo <CC> -admission-cred alice.cred  …

# Revoke by serial (hot-reloaded, no coordinator restart).
admission-issue -revoke <serial>
```
Node credentials are bound to the node id (a leaked one can't be replayed under
another id); client credentials are bearer, so their safety is the out-of-band
channel they're delivered over. See
[node-admission.md](design/node-admission.md).

### More than one authority (issue #64, ADR-0047)

`-admission-pubkey` anchors **one** authority trusted for **every** role. That is
fine while the operator mints everything by hand, but the account service mints
client credentials automatically — always online, high volume — and under a single
anchor it would have to hold the same private key that admits a host as a relay or
an exit. `-admission-authority` scopes an authority to the roles it may admit:
```
-admission-authority role[,role...]:<hex pubkey>     # repeatable, one per authority
```
The two flags compose, so splitting the account service off is a flag you add:
```bash
# today
bacchus-coordinator … -admission-pubkey <OPERATOR>

# add the account service, scoped to client only — nothing else changes
bacchus-coordinator … -admission-pubkey <OPERATOR> \
                      -admission-authority client:<ACCOUNT>

# then narrow the operator key to the roles it actually mints
bacchus-coordinator … -admission-authority relay,exit:<OPERATOR> \
                      -admission-authority client:<ACCOUNT>
```
Admission is off only when **both** flags are unset. A credential is admitted only
if an authority anchored for the role being taken signed it — so the scoping holds
even against an issuer that writes any roles it likes into what it mints. Roles are
`client`, `relay`, `exit`. A malformed anchor is fatal at startup rather than
skipped, and the startup line prints each authority's roles and a short key prefix,
so a wrong scope is visible in the log. Anchors are read once: changing them needs a
restart, unlike `-admission-revocations`, which is hot-reloaded.

One list covers every authority — serials are unique per credential regardless of
who signed it — so revocation is unchanged by any of this.

> `-admission-pubkey` names a different thing on `bacchus-node`: there it is the
> **client's** anchor for verifying an exit's credential end-to-end (issue #60),
> not a coordinator's authority set. See ADR-0047.

## Device entitlement at connect (issue #50, ADR-0045)

A **second, separate** gate from admission above, and both are checked. Admission
asks "may this party be on the network at all?"; this asks "does this device hold
a live entitlement right now?". They anchor to different keys on purpose — do not
configure one expecting it to cover the other.

Off by default: with no `-device-root-pubkey` the gate is disabled and connects are
gated by admission alone. To enforce it, give the coordinator the **offline root's**
public key (hex) — the account service's root, not the admission authority's:
```
bacchus-coordinator -turn-public-ip <IP> -turn-user <u> -turn-pass <p> \
    -admission-pubkey <ADMISSION_PUBKEY> \
    -device-root-pubkey <ROOT_PUBKEY> \
    -advertise <host:port>

# Revoke a device credential or issuer cert by serial (hot-reloaded, no restart).
# A flat JSON list of serials, same shape as the admission revocation file.
$EDITOR secrets/device-revocations.json
```
The coordinator holds only the root **public** key, verifies the whole chain
offline, and never calls the account service — so this keeps working when that
service is unreachable, and leaks nothing to it when it is not. The cost is
revocation latency, bought back by short credential lifetimes.

Two startup failures are **fatal rather than degraded**, both because they would
otherwise look exactly like success:
- a malformed `-device-root-pubkey` (a coordinator told to enforce entitlement with
  an unusable anchor must not fall through to serving everyone), and
- an enabled gate with no audience: set `-advertise` (or `-device-audience`) to the
  identity clients dial this coordinator by, or a device's assertion would be bound
  to nothing.

The audience must be what a client knows **independently**, because it chose to
dial it. Bacchus runs a pool of coordinators, and an audience a coordinator merely
announced would let a hostile pool member announce someone else's, relay the
challenge, and spend another account's entitlement.

Note the failure direction is the same as `-admission-pubkey` (unset = off) and the
**opposite** of `-policy-root-pubkey`, which stops assigning new work once its
policy goes stale. ADR-0045 §2 records why. Once a root *is* configured there is no
soft mode: a chain that fails verification is refused.

**Clients must be updated first.** The wire fields are additive, so a client
predating #50 connects exactly as it does today — but it does not perform the
challenge exchange, so enabling the gate on a network with such clients refuses
them.

## Routing the whole device on Linux (issue #37, ADR-0049)

Until now the Linux client was an honest SOCKS5 listener on `127.0.0.1:1080`: it
routed nothing, and its settings window said so. It can now route the device —
TUN, split-tunnel, kill-switch — but that needs `CAP_NET_ADMIN`, and running a
GUI as root is not acceptable for a client aimed at ordinary users. Fyne links a
GL stack, an X11/Wayland client and a font renderer, and none of that belongs in
a process that can rewrite the route table.

So enforcement is split across a process boundary
([ADR-0049](adr/0049-linux-privilege-boundary.md)). `bacchus-fyne` keeps running
as you, with no capabilities. A small helper, `bacchus-netd`, holds
`CAP_NET_ADMIN` and owns every privileged operation. They speak over
`/run/bacchus/netd.sock`, mode `0660`, group `bacchus`, and the helper checks
`SO_PEERCRED` on every connection.

**This is an installation step, and it is the main cost of the design.** The
Linux client stops being "download a binary and run it". Install per
[deploy/README.md](../deploy/README.md#the-one-unit-that-is-not-a-server-unit-bacchus-netd-issue-37):

```sh
go build -o bacchus-netd ./cmd/bacchus-netd
sudo install -D -m 0755 bacchus-netd /usr/local/lib/bacchus/bacchus-netd
sudo systemd-sysusers deploy/bacchus-netd.sysusers.conf
sudo usermod -aG bacchus "$USER"          # then log out and back in
sudo cp deploy/bacchus-netd.{service,socket} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bacchus-netd.socket
```

Confirm it: `systemctl status bacchus-netd.socket`, and
`journalctl -u bacchus-netd -f` while you connect.

### What changes once it is installed

The settings window stops saying split-tunnel, kill-switch and DNS are "saved
for later use" and starts saying they take effect on the next connect, because
they do. The state indicator earns the word "Protected" the same way the Windows
client does.

**If the helper is missing or unreachable, the connect fails.** It does not fall
back to a working SOCKS proxy under a "Protected" banner — that failure is the
one ADR-0039's parity bar exists to rule out, and a missing helper is the most
likely way to meet it here. The error names the helper.

**Keep the two binaries in step.** A `bacchus-netd` older or newer than the GUI
refuses the connection outright rather than negotiating down to a subset; a
client that silently lost its kill-switch to a version skew is the same failure
wearing different clothes.

### What happens to DNS

DNS is intercepted inside the tunnel, which is enough on its own for any program
that queries a routable DNS server. It is not enough for `systemd-resolved` —
the default on Ubuntu, Fedora and Debian — and on those machines `bacchus-netd`
does one extra thing while the tunnel is up.

The reason is worth knowing if you are debugging it. resolved's stub listens on
`127.0.0.53`, which is loopback, and the kernel consults the `local` routing
table before anything else, so no route can capture a query aimed at it. Nor
does resolved's own upstream query fall into the tunnel behind it: that socket
is scoped to the link its DNS server belongs to, and link scoping overrides the
routing table outright. Neither hop is reachable by routing, which is why this
takes a mechanism rather than another route.

So while connected, the helper gives the tunnel interface its own DNS server and
a `~.` routing domain, and clears the physical link's default-route flag. You
can see both, and confirm the tunnel is winning:

```bash
resolvectl status                 # the tunnel link should show DNS Domain: ~.
resolvectl status <your-wifi>     # Default Route: no, while connected
```

The physical link keeps its own DNS servers and its own search domains, so a
corporate or LAN-local name that only that link can resolve still resolves.

**It is put back when the tunnel goes down** — on a clean disconnect, and also
if `bacchus-fyne` is killed outright. The helper notices the dropped connection
and restores the resolver itself. This is the one piece of state it does *not*
hold across a crash: the kill-switch is held deliberately, because holding it
fails closed, whereas a resolver still pointed into a dead tunnel just leaves
the machine unable to resolve anything. If you ever find one that was not
restored — the helper was killed with `SIGKILL` at the wrong moment, say —
`resolvectl revert <link>` on each link puts it back, and so does a reboot.

On a machine with no `systemd-resolved`, the helper rewrites `/etc/resolv.conf`
instead and restores it the same way, symlink and all.

ADR-0051 has the measurements this is built on, including why an nftables
redirect and a `resolv.conf` rewrite alone were both ruled out on a resolved
machine.

### If something goes wrong

- **"bacchus-netd is not reachable"** — the socket unit is not enabled, or your
  session predates `usermod -aG bacchus`. Supplementary groups are fixed at
  login: log out and back in.
- **"another Bacchus session already holds device-wide enforcement"** — one
  session at a time, by design. The client that armed the kill-switch is the
  only one that can lift it.
- **No network after a crash** — an armed kill-switch is nftables state in the
  kernel, so it deliberately survives the client being killed. Launching Bacchus
  again lifts it; so does a reboot. To check by hand:
  `sudo nft list table inet bacchus`.
- **Non-systemd hosts** run the same binary under any supervisor, but have no
  logind to answer "does this uid own an active local session". They need
  `-allow-without-logind`, which drops that gate to the socket's group
  permission alone — a real weakening, and opt-in for that reason.

### What is verified, and what is not

The helper is tested against a real kernel: CI drives it inside a user + network
namespace and asserts actual kernel state — routes in the right table, the nft
set holding the right elements, the TUN device up, a packet genuinely delivered
into the tunnel, and traffic blocked with the kill-switch armed. That is
verification the Windows implementation never had.

What a namespace cannot prove is that a **real desktop** behaves as the
synthetic one did: its `systemd-resolved`, its NetworkManager, its physical
adapter and its driver are not there. That is hardware verification, no Go test
can assert it, and it has not been done. The same gap is still open for Windows
as issue #88.

## Verify
On the client device:
```
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me     # -> the exit's IP
```
Expect: client `ICE: connected` → `connected DIRECT` / `connected via RELAY`; the
exit's journal (`journalctl -u bacchus-exit`) shows the forwarded connections.

## Gotchas (learned)
- **Coordinator/STUN/TURN must be on a UDP-reachable-from-the-region IP** (TCP-blocked
  datacenter IPs can still pass UDP — but verify per IP; some are fully blocked).
- Relay needs no inbound/port-forward (dials out + hole-punches).
- TCP-only via SOCKS; point apps at `127.0.0.1:1080` (or set the system proxy).
- Stop a systemd binary before replacing it (`text file busy` otherwise).
