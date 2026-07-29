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
| **exit** (egress) | same/another VPS | `bacchus-node -role exit -listen :20000 …` (systemd `bacchus-exit`) |
| **relay** (forward only, never egresses) | residential PC | `bacchus-node -role relay -advertise <EXIT_HOST>:20000 …` |
| **client** | user device | `bacchus-node -role client …` → local SOCKS5 `127.0.0.1:1080` |

A single node can hold several roles at once (e.g. `-role exit,relay`).

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

The database is **not in this repo** and never will be: it is a licensed MaxMind
dataset under its own terms, and bulk data besides. Fetch and stage it out of
band, exactly as the Windows client does with `wintun.dll`.

**Provenance.** MaxMind *GeoLite2 Country* in the **CSV** distribution (not the
`.mmdb` binary — the CSV needs no third-party decoder, so the whole parse is
stdlib-only and auditable, and it is the upstream artifact as published, with no
conversion step to trust). A free MaxMind account and licence key are required;
MaxMind publishes updates weekly.

```
# Download GeoLite2-Country-CSV (needs your own MaxMind licence key), then:
unzip GeoLite2-Country-CSV_*.zip
mkdir -p /var/lib/bacchus/geoip
cp GeoLite2-Country-CSV_*/GeoLite2-Country-Locations-en.csv \
   GeoLite2-Country-CSV_*/GeoLite2-Country-Blocks-IPv4.csv \
   GeoLite2-Country-CSV_*/GeoLite2-Country-Blocks-IPv6.csv \
   /var/lib/bacchus/geoip/

bacchus-coordinator -geoip /var/lib/bacchus/geoip ...
```
Keep MaxMind's own filenames — the loader looks for exactly those. The IPv6
blocks file is optional; without it, an IPv6-registering node resolves to nothing
and falls back to its hint, so stage it unless you are certain the fleet is v4
only. The startup log prints the prefix count **per family**, which is how you
confirm that.

Refresh it on MaxMind's cadence. Stale geodata does not fail — it silently
mislabels a node's country — so the coordinator warns at startup once the staged
files are more than 90 days old. A database that is configured but unreadable is
**fatal**: an operator who asked for derived countries must not silently get
self-reported ones.

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

The difference from GeoLite2 is **licence, not size**. MaxMind's terms are not ours to
redistribute under, so that database is fetched out of band; this table comes from
iptoasn.com under PDDL v1.0 (public domain, redistribution permitted, no attribution
required), so it can be committed. See
[`core/asn/TABLE.md`](../core/asn/TABLE.md) for the full provenance record.

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

Then update the retrieval date, hashes and row counts in `core/asn/TABLE.md`, and
commit the regenerated table with them.

`asn-stage` turns upstream's address **ranges** into the **disjoint CIDR prefixes**
`asn.Load` requires: it drops the unused country and description columns, drops the
unrouted markers so unrouted space becomes a gap that resolves to *unknown* rather
than inheriting a neighbour's AS, merges adjacent same-AS runs, and splits the rest
into aligned blocks. It is deterministic — the same feed produces byte-identical
output — which is what lets a reviewer re-run it and compare against the committed
file. The download is a separate manual step on purpose, so the transform itself
stays hermetic.

**Cadence is a security parameter, and this step has no automation behind it yet.**
The mapping drifts ~1.3% per month and ~3.6% per quarter, so a client that has not
been rebuilt in a year mis-scores roughly one AS verdict in nine. It degrades
*safely* — a stale answer falls into the unknown-pooling rule, never into a false
claim of diversity — but it degrades. When the signed release channel (#34) lands and
brings a release checklist with it, this belongs in that checklist; until then it
lives here and in `TABLE.md`.

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
