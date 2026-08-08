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
# The release number these binaries will report. It is not optional — see below.
$v = (Get-Content VERSION).Trim()
$stamp = "-X github.com/bacchus-vpn/bacchus/core/version.current=$v"

# Linux server binaries
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -ldflags $stamp -o bacchus-coordinator ./cmd/coordinator
go build -ldflags $stamp -o bacchus-node        ./cmd/node
$env:GOOS=""; $env:GOARCH=""; $env:CGO_ENABLED=""
go build -ldflags $stamp -o node.exe ./cmd/node
```

The same from a POSIX shell:
```sh
stamp="-X github.com/bacchus-vpn/bacchus/core/version.current=$(cat VERSION)"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$stamp" -o bacchus-coordinator ./cmd/coordinator
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$stamp" -o bacchus-node        ./cmd/node
```

### The release version comes from `VERSION` (issue #128)

`VERSION` at the root of the repository is one line holding a bare
`MAJOR.MINOR.PATCH`, and it is the **single source of truth** for the release
every binary reports. Three build paths read it and they all have to agree:
these commands, [`deploy/install.sh`](#installing-on-linux-issue-18) (which
stamps whatever it builds on the box it installs onto), and CI. A fence that
some builds participate in and others do not is worse than one that never fires,
because it fences an arbitrary subset and reports success either way.

A file rather than `git describe --tags`, deliberately: a file still works from
a source tarball with no git history, it is deterministic (ADR-0052 §5 wants the
fleet binaries byte-identical, and adds `-trimpath` with `CGO_ENABLED=0` on top
of this for an actual release build), and it makes a version bump a reviewable
one-line commit — which is what a release should be.

**Bumping it.** Edit `VERSION`, commit it on its own, and tag that commit
`v<VERSION>` — `0.2.0` in the file, `v0.2.0` as the tag. CI asserts on every tag
push that the two match, so they cannot drift.

**There are no release candidates, and this is the one rule to read before
tagging.** `VERSION` and the tag are a bare `MAJOR.MINOR.PATCH` and nothing else:
**`v1.0.0-rc1` is not a tag this project can build**, and neither is
`v1.0.0+build.7`. The reason is not style. `core/version.Version` models three
integers, deliberately (ADR-0015's serving fence and the client's force-major
check both *order* on them, and there is no defined ordering for a suffix), so a
pre-release string is not a version that can be compared — only one that can be
stamped. A binary stamped with one **panics at startup**, on the machine it was
installed on, having built and installed cleanly. Wanting release candidates is a
change to that model and to the two policy predicates that turn on it, not a tag
somebody can push.

Three things refuse one before it can reach a binary, and they are independent on
purpose: `deploy/install.sh` validates `VERSION` and will not build; CI checks the
shape of both `VERSION` and the tag; and `core/version`'s own tests parse the file
on every push. If all three are bypassed — a hand-typed `-ldflags` — the panic
message names the rule and the file.

All of that sits at the front of the pipeline because **nothing downstream would
catch it**. No CI job runs a coordinator or node binary, and the two that launch
the GUI smoke-test it without connecting — the client reads its release on
*connect*, not at startup. A client stamped `1.0.0-rc1` would build, install,
launch, sit there looking healthy, and crash the first time its user pressed
Connect.

**A binary nobody stamped still runs, and says so.** A bare `go build` — no
`-ldflags` — produces a development build, which is correct and supported. It
reports the release `0.0.0` (*no release*, not "zero point zero"), and it prints
one loud line at startup saying it was not stamped. It is not refused: a
development build must work. What it must not do is pass for a release build,
which is what it silently did until #128 — every binary this project had ever
produced reported `0.1.0`, into three mechanisms that do nothing but compare
releases:

| mechanism | where | with everything reporting one number |
|---|---|---|
| `-min-serving-version` node fence | coordinator (ADR-0015) | any floor above it fences the whole fleet, any floor at or below it fences nobody |
| client force-major / skip-minor check | client (ADR-0015) | client and network are always equal, so it never triggers |
| build-skew warning | coordinator (issue #114) | node and coordinator never differ, so it cannot fire |

A `release=0.0.0` on a coordinator's registration line therefore means *that node
was built by something that does not stamp*, and it is worth chasing: it is a
node the fence cannot rank and the skew warning cannot compare.

The **desktop client** is deliberately absent from that list, on either target:
`clients/fyne` links a C toolchain and, per platform, an OpenGL/X11/Wayland or
mingw-w64 stack (ADR-0039), so it is built on the machine it will run on — which
is what `deploy/install.sh` does for you on Linux. `cmd/bacchus-netd` is
Linux-only for the same reason. A Windows build additionally needs `wintun.dll`
placed next to the exe at runtime, and there is no installer that does it
(bacchus#136) — see `clients/fyne/README.md`.

## Deploy the VPS services
`deploy/install.sh node --role coordinator` or `--role exit` does all of this in
one command, including generating the exit's persistent identity on the box —
see [Installing on Linux](#installing-on-linux-issue-18) below.
[../deploy/README.md](../deploy/README.md) is the same work by hand: copy the
binaries to `/usr/local/bin/`, install the units, create `/etc/bacchus/*.env`
from the templates (real IP + `TURN_PASS`), open the firewall,
`systemctl enable --now`.

That is a **first** install. Updating an existing deployment to a new commit is
a different job with different failure modes, and it has its own procedure:
[Pinning the whole deployment to a commit](#pinning-the-whole-deployment-to-a-commit-issue-205-adr-0064).
Do not reinstall to update — it re-copies the unit files, which is the one thing
an update must not do.

## Installing on Linux (issue #18)

`deploy/install.sh` installs either half of the Linux story and, just as
importantly, removes it again.

```bash
# a desktop client: the GUI, the root helper, its unit, its socket, its group
sudo sh deploy/install.sh client --user "$USER"

# a server node: binary, unit, env file, and (for an exit) a persistent identity
sudo sh deploy/install.sh node --role coordinator
sudo sh deploy/install.sh node --role exit

# and back out again
sudo sh deploy/install.sh uninstall client
sudo sh deploy/install.sh uninstall node          # keeps /etc/bacchus
sudo sh deploy/install.sh uninstall node --purge  # destroys it too
sudo sh deploy/install.sh uninstall all           # both installs; still keeps /etc/bacchus
```

Uninstall removes the units, the socket, the group, the binaries, the desktop
entry, `/run/bacchus` and the per-user config. There is one rule about what
survives, and it is whether the state can be regenerated: a client's config can,
so it goes by default; an exit's `EXIT_KEY` is the node id clients pinned and a
coordinator's signing key is what its snapshots are trusted by, so
**`/etc/bacchus` stays until you ask for it with `--purge`**. `all` means both
*installs*, not "and the keys too" — it does not override that rule, because a
wider word does not make irreplaceable state replaceable. Uninstall says out loud
which it did.

Uninstall never reads the repository, so removing this does not require still
having the checkout you installed from.

**The client is the half this matters most for, and it is newer than the card
that asked for an installer.** Before issue #37 the Linux client offered a SOCKS
port and needed nothing installed. It now routes the whole device through
`bacchus-netd`, which means a binary in `/usr/local/lib/bacchus`, a systemd unit
and socket, and a `bacchus` group — all placed with root. Without them the
client does not degrade to a proxy, it **refuses to connect** (ADR-0039 parity
item 7, deliberately). So until this script existed, the platform that shipped
in #37 was reachable only by someone willing to build from source and follow
[deploy/README.md](../deploy/README.md) by hand.

A server that already has cross-built binaries does not need a Go toolchain:
`--binaries DIR` takes the ones you copied over, which is the workflow
[Build (dev machine)](#build-dev-machine) above describes.

### `curl … | sh`, and why we still recommend downloading first

The pipe works. What makes it safe is not a check the script performs but a
property of how it is laid out:

> **Every side effect lives behind the final `case $mode` dispatch, which is the
> last statement in the file.**

Above that line there is nothing but `set -eu`, variable assignments, function
definitions, argument parsing, and read-only resolution of where the unit files
are. `sh` executes a pipe as it arrives, so a download that dies at 60% runs only
what arrived — and what arrived defines functions that nobody calls. **A
truncated fetch installs nothing**, rather than leaving the half-applied install
that is otherwise the real hazard of this shape. It cannot even stop halfway
through a compound command, because a shell will not execute a `case` or a
function body whose end it has not seen.

That is a guarantee about the code's *shape*, so it is pinned by a test rather
than by good intentions: `deploy/install-test.sh` truncates the script at 42 byte
offsets, pipes each fragment into `sh` exactly as `curl` would, and asserts that
not one file was placed and not one unit written. Add a top-level side-effecting
statement above the dispatch and that test goes red — which is the point, because
that is the change that would quietly reintroduce the hazard.

So the one-liner is supported:

```bash
curl -fsSL https://raw.githubusercontent.com/bacchus-vpn/bacchus/main/deploy/install.sh \
  | sudo sh -s client --user "$USER"
```

One caveat that is about plumbing rather than posture, and it applies **today**:
the installer *writes* the `.service` and `.socket` files, it does not generate
them, and a piped script has no directory of its own to find them in. So run the
line above from inside a checkout, or add
`--deploy-dir /path/to/bacchus/deploy`. It says exactly that rather than failing
obscurely. Once #34 ships a release tarball carrying the script and the units
together, the caveat goes away.

**We still recommend downloading it first**, for two reasons that the layout
guarantee does not address:

```bash
curl -fsSLO https://raw.githubusercontent.com/bacchus-vpn/bacchus/main/deploy/install.sh
less install.sh
sudo sh install.sh client --user "$USER"
```

1. **There is nothing to check in a pipe.** This project's users are, by
   construction, the people most likely to be behind an adversary who can
   intercept TLS or serve a substituted response. The pipe asks exactly them to
   run an unexamined artifact as root, with no step in between where a signature
   or a human's eyes could intervene.
2. **It forecloses ever asking a question.** Piping makes the script the shell's
   own standard input, so anything read from the terminal would read the script's
   remaining source. Everything here is driven by flags, which is the right
   design anyway — but it is a constraint the pipe imposes rather than one chosen
   freely.

**Once [#34](https://github.com/bacchus-vpn/bacchus/issues/34) `[G7]` signs
releases, downloading first stops being a recommendation and becomes the only
path**: fetch the release tarball — which carries the script and the unit files
together — verify its signature against a key obtained out of band, then run the
installer from inside it. That is the argument that eventually retires the
one-liner, because a signature check has nowhere to happen inside a pipe.

### What it refuses to do

A half-written unit is worse than no unit: it survives reboots, it looks
installed, and it fails at connect time. So the script refuses, changing
nothing, when it cannot do the job properly — on a host not running systemd
(pointing at the manual steps, since ADR-0049 records that socket activation is
an optimisation and any supervisor can start the helper), when it cannot tell
which user will run the client, when `--role` is missing or unrecognised, and
when a binary it was told to install is not where it was told to look.

There is deliberately **no distribution whitelist**. Nothing here is
Debian-shaped or Fedora-shaped: the script needs systemd, coreutils' `install`,
and `groupadd`/`usermod`. Each is probed and named individually, so a
distribution nobody tested works if it has them, and one that lacks something
gets told *which* thing rather than that it is "unsupported".

A node whose env file still holds template placeholders is installed and
deliberately **left stopped** — a unit started against `YOUR_VPS_PUBLIC_IP`
does not fail once, it crash-loops behind `Restart=always`. Fill the file in and
re-run the same command.

Running the installer twice is safe: it never creates the group twice, never
overwrites an env file or a user config, and — the one that would be expensive —
never re-mints an exit's `EXIT_KEY`, since that key *is* the node id that clients
pin and learned paths point at.

### The exit key never travels

An exit's `EXIT_KEY` is generated on the host, at install time, straight into
`/etc/bacchus/node.env` at mode `0600`. It is not printed, not logged, not passed
as a command-line argument (where `/proc` would expose it to every local user),
and not echoed even under `sh -x` — the generator runs in a subshell with tracing
disabled, and `deploy/install-test.sh` asserts exactly that. Back that file up if
you want the exit to keep its identity across a rebuild; nothing else has a copy.

### Testing it

`deploy/install-test.sh` runs install → verify → uninstall → verify-clean for
every mode, asserting against the filesystem and the recorded system commands
rather than the installer's own output. **CI runs it** — the `deploy` job in
`.github/workflows/ci.yml`, which also runs `shellcheck` over `deploy/*.sh`
(issues #158 and #160). It did not until then, which is how the suite spent
weeks dying two thirds of the way through and reporting the part it reached; it
now pins its own case and assertion counts and fails a run that stops early.

What CI still does not run is the half that needs a booted systemd and root: see
the REAL-SYSTEM CHECKLIST at the end of that file for the things no harness can
assert — that systemd accepts the units, that the socket really comes up
`0660 root:bacchus`, and that the helper is activated by the client's first
connect. Those are still done by hand on a disposable machine.

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

### Correcting a country an admin knows is wrong (issue #113)

A node's country is really **two** claims: where its address resolves, which is what
every site it visits will conclude, and where the machine physically is, which only its
operator knows. They disagree routinely — a large cloud provider's address block is
commonly registered to that provider's home country whatever datacentre an instance runs
in — so the coordinator now carries **both**: the derived country is what clients select
on, and the node's own `-country` tag is kept beside it rather than discarded. The
registration line shows both when they differ:

```
exit registered: <id> -> <host>:20000 country=NL (observed IP; node declares DE) release=0.1.0
```

When the **derived** value is wrong — the database has the address in the wrong country,
and you can check what real sites conclude about it — stage a correction:

```json
{ "<node id>": "DE" }
```

```
bacchus-coordinator -country-overrides /etc/bacchus/country-overrides.json ...
```

It is re-read every 30s, so an edit takes effect on the node's next register or
heartbeat with no restart. A file with any unusable row is refused whole — fatal at
startup, and on a reload the corrections already in effect are kept.

**This corrects the DERIVATION, and is not a way to say where the machine sits.** If the
box is in DE but its address resolves US, the right value is `US`: a user picks DE to be
*treated as* German by every site they visit, and an address that resolves US is treated
as US regardless of which building it is in. Overriding that misroutes exactly the user
who cared enough to choose — the same misrouting `-geoip` exists to prevent, arriving
from your side instead of the node's.

Two consequences to know. An override **wins even under `-geoip-required`**, because
that flag's promise is that no *node* self-report reaches a client's country choice and
an operator assertion is not a node self-report. And an override is **terminal**: for an
exit it also suppresses the signaling-vs-advertised-endpoint check above, and the
contradiction label a chaining client refuses on. The coordinator logs a warning naming
that when it happens.

**What clients are told.** Without `-geoip-required`, the node's declaration travels in
the signed directory beside the derived country, as a labelled claim nothing selects on.
**Under `-geoip-required` it is withheld from the directory entirely** — the coordinator
still derives it, stores it and shows it to you above, but a client sees neither a
country nor a declaration for such a node. That artifact is where a relay-chaining
client picks its terminating jurisdiction, with no live reply to check it against, and
the flag's whole promise is that no node self-report reaches that choice.

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

**Cadence is a security parameter, and CI enforces two bars under it.** The mapping
drifts ~1.3% per month and ~3.6% per quarter, so a client that has not been rebuilt in
a year mis-scores roughly one AS verdict in nine. It degrades *safely* — a stale
answer falls into the unknown-pooling rule, never into a false claim of diversity —
but it degrades.

| bar | age | where it runs | what it stops |
| --- | --- | --- | --- |
| build floor | **90 days** | `TestEmbeddedTableIsFresh` in `ci.yml`, every push and pull request | work continuing on a table nobody has refreshed in a quarter |
| release bar | **30 days** | the `verify-table` job in `.github/workflows/release.yml` | a **release** being cut on a table older than a month |

The two are not second opinions about the same thing. 90 days is a budget on how wrong
the table may be *in the hands of somebody running it*, and that budget is spent on both
sides of a release — the age of the table when the artifact is built, plus however long
the person who installed it keeps running that build. Against the floor alone a release
cut on day 89 hands a user a table already at the limit on the day they install it.
Shipping at most 30 days old leaves roughly 60 days of the budget on the user's side.

`verify-table` is a job the Windows bundle job `needs:`, not a check beside it, and that
is the load-bearing part: a refusal happens **before** anything is compiled and before
any release object exists, not after a draft has been created. Recovering from one means
refreshing the table, committing it, and moving the tag onto that commit — the same
shape as the version gate refusing a tag that disagrees with `VERSION`.

**What the release bar covers, and what it does not.** `release.yml` builds the Windows
artifacts, so the bar covers everyone who installs Bacchus for Windows from a GitHub
release. It does **not** cover a Linux install: [`deploy/install.sh`](../deploy/install.sh)
builds `clients/fyne` from the checkout it is run in, at whatever revision that checkout
happens to be at, and runs no tests. There is no Linux release artifact, so there is no
Linux release to gate. A Linux user's table age is bounded by the 90-day floor on `main`
plus however stale their clone is — and the second term is unbounded. Pull before you
install.

Both bars are floors rather than schedules: they refuse, they do not refresh anything.
Performing the refresh is still the manual step above.

### The scheduled drift check (issue #150)

The two bars above only ever fire once somebody pushes, opens a pull request, or cuts a
release — so a quiet repository can drift past them with nothing noticing. A scheduled
workflow closes that gap the same way [`bacchus-geoip-refresh.timer`](#keeping-it-fresh-issue-85)
closes it for the country database above, but it cannot refresh anything the way that timer
does: ADR-0044's fourth amendment §5 priced a scheduled job that opens a refresh pull
request against the credential it would need, and the owner ruled against holding one in
CI (recorded in the ADR's sixth amendment). What runs instead only **detects**:

| file | what it is |
|---|---|
| `deploy/bacchus-asn-drift-check.sh` | fetch upstream, stage it through `asn-stage`, compare against the committed table |
| `.github/workflows/asn-table-drift.yml` | runs the script weekly, and on demand via `workflow_dispatch` |

```
sh deploy/bacchus-asn-drift-check.sh
```
run from the repository root, is exactly what the workflow runs and the way to rehearse it
by hand against the real feed. It fetches, decompresses, checks a row-count floor, stages
through `asn-stage` and compares — never writing to `core/asn/table.tsv.gz` on any path,
including every failure path. Exit **0** means no drift; exit **1** means the check itself
could not complete (a bad download, a corrupt transfer, a feed too small to be a real
release) and says nothing about whether the table is stale; exit **2** means the staged
table differs from the committed one, and the message names the same three commands as
[above](#refreshing-the-table-per-client-release) for fixing it.

**Expect the workflow to stay red for stretches of ordinary time.** This compares byte for
byte against a feed upstream rebuilds hourly, not against the calendar, so once the
committed table is even a day behind it keeps failing on every scheduled run until somebody
refreshes it — not only once it crosses 90 or 30 days. That is the intended shape of the
signal: a single workflow staying red until acted on, rather than a pile of filed issues
(this project's board treats the claim signal as the column a card sits in, and a bot-filed
issue lands in none of them). No repository write, no stored credential, and no pull
request are opened at any point — see
[ADR-0044](adr/0044-as-lookup-seam-and-as-diverse-hop-selection.md)'s sixth amendment for
the full argument and for why a repository-write credential in CI was refused rather than
merely left unbuilt.

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

### When the coordinator restarts underneath you (issue #225, ADR-0067)
A running client holds a live rendezvous association with its coordinator, and a
coordinator that restarts forgets it. Nothing on the client's side errors when that
happens — a datagram sent into a forgotten association is accepted by the local
network stack and dropped on arrival — so until this was fixed the client sent into
it forever, reported `no coordinator reachable` on every attempt, and only a restart
of the client recovered it. **On a volunteer that took the exit and relay
registrations down with it**, silently, because they ride the same connection: the
coordinator simply stopped hearing from the node and logged nothing at all.

A client now notices within one failed connect attempt and rebuilds the link on a
fresh socket, with no user action; the serve-side registrations come back with it.
The log line to recognise names the fault as a local one:

```
the link this client held to coordinator <addr> has gone stale and is being rebuilt …
This is a LOCAL fault — this client's own link, NOT the network …
```

That sentence is the point of it. `no coordinator reachable` means every coordinator
was silent and is a reason to suspect the network or a block; this one means the
connection this process was holding stopped working and has been replaced. If you see
it once around a coordinator deploy, that is the mechanism working. If you see it on
every attempt for minutes, the coordinator is answering handshakes and nothing else,
which is worth looking at from the coordinator's side.

One case is not covered: a volunteer sitting in a **healthy session** when its
coordinator restarts has nothing to ask it, so it does not find out until that session
ends. Its registrations come back then. A coordinator answers a `register` only to
reject it, so there is no reply for the node to miss.

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

## Telling clients that an address moved (issue #193, ADR-0061)

Every address the desktop client dials — the coordinator pool, and the account
service beside it — used to be a constant in a JSON file on each machine, with no
way to correct it. That matters because the account service runs on anonymously
rented infrastructure and **its address will change**: a device renews as soon as
it enters its 6 h renewal margin, so a service that goes unreachable at *T* takes
the first devices offline at *T* + ~6 h and the rest by *T* + 48 h. A moved
**coordinator** is worse — it takes a client offline immediately.

The coordinator already signs a cold-start directory and already serves it, on the
same UDP port as STUN/TURN (`-turn-addr`). It now carries the account service too,
and the desktop client reads both roles out of it.

**Coordinator side.** One repeatable flag, empty by default:
```
bacchus-coordinator -turn-public-ip <IP> -turn-user <u> -turn-pass <p> \
    -advertise <host:port> \
    -account-service https://<account-host>:8443 \
    -account-service https://<successor-host>:8443
```
List **every** address a client should try, in preference order, including the
successor *before* a planned move — the directory's list REPLACES what a client has
in its own config, so naming one address here narrows a client that was configured
with two. `https` only, scheme and host, no path; anything else is refused at
startup rather than published for every client to choke on. Leave the flag unset
and no such entry is published, which leaves every client on its own configuration.

What travels is a **location, not a trust root**: the client keeps the audience it
binds assertions to and the CA it pins the service's TLS identity against, both out
of band, so an address named here still has to present the identity that client
already pins.

**Client side.** A client needs an invite to fetch the directory at all. Mint one
per recipient, exactly as for `cmd/coldstart-bootstrap`:
```
# on the coordinator VPS, once, to learn the snapshot-signing key
bacchus-coordinator -print-bootstrap-pubkey

# one invite per user; appends the secret to the coordinator's secrets file,
# which is hot-reloaded, so no restart
bacchus-coldstart-issue -coordinator <host>:3478 -pubkey <BOOTSTRAP_PUBKEY>
```
and put the printed `bacchus1:…` string in that user's client config:
```jsonc
{
  "coordinators": ["<host>:8080"],   // still the seed: used until a directory arrives
  "invite": "bacchus1:...",           // per-recipient, never shared
  "accountServiceUrls": ["https://<account-host>:8443"],
  "accountServiceAudience": "...",
  "accountServiceCa": "/path/to/ca.pem"
}
```

> **An invite is per-recipient and must never go into an installer, an image, or a
> config template.** A coordinator's bootstrap secrets file has no vouch system
> under it — every entry in it is trusted equally — so one invite baked into a
> downloadable artifact is a working credential for the whole network, held by
> everyone who downloads it. Provisioning a device takes **two** out-of-band
> strings: an invite and a claim code.

Behaviour worth knowing before you rely on it:

- A client with **no** invite is unchanged and fully supported. It dials what is in
  its config file.
- The directory **leads** for coordinators and **replaces** for the account service.
  A snapshot names only the coordinator that signed it, so replacing that list would
  throw away the rest of your pool; the account service list is stated in full by
  the flag above, so it is a complete answer.
- An **expired**, unsigned or wrong-key snapshot is not adopted, and the client falls
  back to its configured addresses rather than to nothing. The snapshot TTL is five
  minutes, so the client's on-disk cache serves a rapid reconnect, not a next-day
  launch.
- The directory is read at **Connect**. A client already connected across a move
  keeps the addresses it started with until it reconnects.
- Re-issuing an invite takes effect at the next Connect: a cached snapshot signed by
  a key the new invite does not name simply does not verify.

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
go build -ldflags "-X github.com/bacchus-vpn/bacchus/core/version.current=$(cat VERSION)" \
  -o bacchus-netd ./cmd/bacchus-netd
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

## Pinning the whole deployment to a commit (issue #205, ADR-0064)

Merging is not deploying. Nothing in this project's workflow puts `main` on a
box, so between deploys the deployment drifts — one wave per wave, silently —
and every instruction that says "run it on the testbed" then runs against
whatever was last copied there by hand. **A result from a stale box is wrong in
the direction that is hardest to catch: plausible.** It looks like a finding
about the code and it is a finding about the deployment.

```sh
# From a CLONE at the commit you intend to deploy (not a git worktree — see below).
cp deploy/testbed.env.example deploy/testbed.env   # once; it is gitignored
$EDITOR deploy/testbed.env                          # your hosts and units
sh deploy/bacchus-pin.sh --commit "$(git rev-parse HEAD)"
```

That builds both server binaries once, from that one checkout, stamped from
`VERSION`; stages a checked copy onto every box without replacing anything;
then installs and restarts **nodes first and the coordinator last**; then
establishes the result rather than asserting it. `--dry-run` prints every
remote command it would run and touches nothing.

### The five things it will not do, and why each one matters

1. **It never copies a `.service` file.** The coordinator's live unit carries
   hand-added flags that are *not* in `deploy/bacchus-coordinator.service`, so
   re-copying that file silently reverts a working configuration and the
   deployment then behaves differently for reasons no diff shows. Units are
   installed once — by hand or by `deploy/install.sh` — and edited in place.
   This is binaries only, and there is no flag that changes that.
2. **It never checks anything out.** It reads the commit the repository is
   already on and refuses if `--commit` disagrees. A script that moved HEAD for
   you could turn a half-finished rebase into a deployment.
3. **It never touches `/etc/bacchus`.** Keys, env files and revocation lists are
   state, not artifacts.
4. **It refuses a build from a `git worktree`.** The Go toolchain records VCS
   data only from a checkout with a real `.git` **directory**; a worktree records
   none, every node then reports `build=unknown`, and the check below has
   nothing to compare. Clone, check the commit out, build from there.
5. **It refuses a binary whose release stamp did not land.** Two ways that
   happens, and they need two different checks: a plain `go build` records no
   `-ldflags` at all (visible in `go version -m`, checked per binary), while an
   `-X` naming a symbol that does not resolve is **silently ignored** by the
   linker — flag recorded, build successful, binary still reporting `0.0.0`, and
   nothing in the artifact's metadata can tell it from a correct build. For that
   one the script runs `core/version`'s own read-back
   (`TestStampMatchesTheVersionFile` with `BACCHUS_REQUIRE_STAMP`, the same check
   CI runs on every push) against this checkout, before it builds anything.

### The order is part of the check, not a preference

Restart the coordinator **last**. That is not tidiness: it is what makes the
node check readable at all.

`build=` (issue #182) rides the `registered:` line, and that line fires only for
a node the coordinator does not already hold in its registry. A node restarts in
about a second and its entry survives 35s, so **a rolling redeploy can replace
every binary in the fleet without printing `registered` once** — and a journal
read afterwards then answers with values from before the deploy, with total
confidence. Restarting the coordinator empties its registry, so every node
re-registers as new and prints a fresh line naming the binary it is running now.

### Establishing the result

Two checks, asking two different questions. Both run automatically at the end of
`bacchus-pin.sh`; both are also usable on their own, which is what you want when
you are checking a deployment somebody else did.

**Which build is each node running?** — from the coordinator's journal, without
reaching a single node:

```sh
ssh <coordinator-host> "journalctl -u bacchus-coordinator --since -10min --no-pager" |
  sh deploy/bacchus-fleet-check.sh --expect 3 "$(git rev-parse HEAD)"
```

It reports one line per node and exits non-zero on any drift. It ignores
everything before the last `coordinator release` startup line in the input — a
registration made before the coordinator restarted is not evidence about what is
running now, and it looks exactly as convincing — and it refuses a window
containing no startup line rather than reading whatever it happens to hold. A
node reporting `build=unknown` is a **failed** pin, not a pass: a fleet whose
revision cannot be established is the state this exists to end.

`--expect N` is how many node **processes** should appear, and `bacchus-pin.sh`
passes the size of its own `NODE_TARGETS`. Give it by hand too: without it the
only floor is that *something* registered, which is how the first real run
reported `3 node(s) registered` and `the fleet is pinned` with one of three boxes
dead (issue #224). A box serving two roles prints two `registered:` lines
carrying one node id and counts **once**.

| finding | exit | what it means |
|---|---|---|
| every expected node on the pinned commit | 0 | pinned |
| a node on a different build, `-dirty`, or `build=unknown` | 1 | drift — issue #114; distrust every result from these boxes |
| no `coordinator release` line in the window | 3 | the window cannot answer the question; widen it |
| fewer node ids than `--expect` | 4 | a box that should be there did not register in this window |

Three things it will not tell you, each of which is a limit of a journal rather
than of the script. It cannot **name** the missing box: this journal names node
ids and your host list names ssh targets, and nothing maps one to the other.
`--expect` takes a **count and refuses a host list**, because the script prints no
hostname at all — that is what makes its output the half of a pin run you can
paste into an issue, while `bacchus-pin.sh`'s own output names every ssh target
on every line. And **more** ids than expected is not a failure, because a
volunteer client serves and registers without being in anybody's host list — so
`--expect` is a floor, not a roll call, and a volunteer can hold the count up
while a deployed box is absent.

**When a node has not come back**, the pin restarts the node units once and reads
the journal again. That is a containment for issue #225 — a node brought up
against the outgoing coordinator never rebuilds the link, which the
coordinator-last order guarantees on every deploy — and not a fix; it retires when
a client recovers on its own. It never restarts to answer *drift*, which would
destroy the evidence, and `--no-restart-absent` keeps the stranded process for
whoever is diagnosing it.

**Is the coordinator serving what that commit carries?** — by behaviour:

```sh
go run ./cmd/coordinator-probe -addr <coordinator-host>:8080
```

Read [Why the version string is not the check](#why-the-version-string-is-not-the-check)
before trusting a green from it, especially the part about which port.

### Why the version string is not the check

On 2026-08-07 the live coordinator was found running a commit two waves old. Its
startup line read:

```
coordinator release 0.1.0 (revision a868e6e3c447)
```

and a current one read:

```
coordinator release 0.1.0 (revision abe9880ebf17)
```

`release=0.1.0` is true in both. The obvious check — confirm the releases match
— returns a clean answer either way, and a check that cannot fail is not a
check. So `cmd/coordinator-probe` asks the coordinator to *do* something only a
current build can do: one bare 20-byte STUN Binding Request to its **signaling**
port. A build carrying issue #175 slice 1 and issue #202 answers it in place; an
older one hands the datagram to `json.Unmarshal`, fails, and drops it.

**The negative control, without which a green means nothing.** The coordinator's
own STUN/TURN service on `-turn-addr` answers a Binding Request with
byte-identical bytes — deliberately, since two ports on one host answering
differently would be a distinguisher (ADR-0060) — on *every build this project
has ever shipped*. **Point the probe at the TURN port and it goes green against
a coordinator of any age**, and no shape check can tell them apart. So the probe
first establishes the port, with a question only a signaling port answers and
which every build has answered since issue #8: a `hello` whose protocol version
cannot match, which draws a `reject`. Four outcomes, four exit codes:

| control | capability | exit | means |
|---|---|---|---|
| answered | answered | 0 | this is a signaling port and it serves the shaped rendezvous hop |
| answered | silent | 1 | stale build — or current and started `-rendezvous-dtls=false`, which removes it from the fleet just as thoroughly |
| silent | answered | 4 | **not a pass** — this is a TURN port or an unrelated STUN server |
| silent | silent | 3 | wrong address, a firewall, or nothing running. Says nothing about the build |

Both confirmed on real hardware in both directions, including against a
coordinator started `-rendezvous-dtls=false` as the negative control.

**That makes the coordinator's `reject` reply deployment infrastructure**, which
is worth knowing before anyone tries to make it quieter. The handler used to
write one log line per unauthenticated datagram, naming a source that may be
spoofed, and the obvious fix is to stop answering strangers — which turns every
future pin into row three of the table above: `control silent, capability
answered`, exit 4, **not a pass**, against a perfectly healthy coordinator. The
log is bounded instead (one line a minute, carrying a count of what it stood
for); the reply is not, and `cmd/coordinator` has a test that builds the real
probe and runs it against the production packet loop so the dependency cannot be
broken quietly (issue #217).

### Which paths are actually in effect (issue #226)

The coordinator's unit has **`WorkingDirectory=` empty**, which for a system
service means `/`. Every relative path therefore resolves under the root
directory: `secrets/device-revocations.json` becomes
`/secrets/device-revocations.json`, which does not exist. That does not fail —
**a missing revocation file means nothing is revoked**, quietly, which is the
worst way for a security control to be off.

The dangerous half of this is the half that is invisible. `cmd/coordinator` has
**nine** flags whose default is a relative `secrets/…` path, and **a flag left at
its default never appears in `ExecStart` at all** — so a check that reads
`ExecStart` stays silent precisely when the operator never thought about the
path. On the first real pin run every path written into the live `ExecStart` was
absolute, and the flags that were not written there were resolving under `/`.

Two places now answer it:

- **The coordinator says so itself, at startup.** A block of `paths:` lines names
  every file flag, what it **resolves** to, whether it is there, and what its
  absence means — a state file written on first use and a revocation list that is
  off look identical from the path alone. It ends with one `WARNING` when the
  working directory is `/` and anything is still relative. `journalctl -u
  bacchus-coordinator | grep '^.*paths:'` is the whole answer, with or without a
  pin.
- **`bacchus-pin.sh` warns on an empty `WorkingDirectory=`, full stop** — no
  longer only when `ExecStart` also spells out a relative path. It still prints
  the unit's effective `ExecStart` and `WorkingDirectory`, because the file in
  this repository is not evidence about the running service.

The fix on the box is either a `WorkingDirectory=` in the unit or absolute paths
on the flags; the point of the two reports is that you can tell which flags are
affected without guessing.

### Cards that need the boxes

**The pin is a precondition, not a first step to improvise.** Anything that
needs the testbed — the credential chain end to end, the revocation loop, a
rendezvous change — runs `bacchus-pin.sh` first and confirms both checks pass
before its own result means anything.

## What the coordinator says about node builds (issue #114)

A node running a binary built from a different commit than the coordinator
**registers cleanly, heartbeats every 10s, is never pruned, is offered to
clients, is assigned work — and can silently drop every session it is given.**
Registration and heartbeat are stable across builds; session setup is not. That
is the failure that opened #114: three exits on a binary three weeks older than
the coordinator, no session establishing on any path, and every log involved
reporting health. These four lines are what a coordinator now says about it.
None of them refuse anything: refusing on a version difference by default would
turn one silent failure into a fleet-wide outage on any staged rollout, and
`-min-serving-version` (below) already exists for operators who want that.

**1. A node's release, when it registers.**
```
exit registered: n7 -> <EXIT_HOST>:20000 country=NL (observed IP) release=0.4.1
relay registered: n9 (<RELAY_ADDR>) country=DE (node hint, unresolved IP) release=0.4.1
```
Two values are worth reading twice. `release=unknown` is a node old enough to
predate ADR-0015 and send no release at all; `release=0.0.0` is a build nobody
stamped — a bare `go build` — which is a node the fence cannot rank (see
[The release version comes from `VERSION`](#the-release-version-comes-from-version-issue-128)).

**2. A release changing under a running coordinator.**
```
exit n7 changed release: 0.4.0 -> 0.4.1
```
This is the **only** line that shows a rebuild of a live fleet. The `registered`
line above fires only for a node the coordinator does not already have: an
update restarts a node in about a second, its registry entry survives 35s, so a
staged rollout can replace every binary in the fleet without printing
`registered` once.

**3. A node built from a different commit than the coordinator.**
```
WARNING: exit n7 reports release 0.4.0 and this coordinator is 0.4.1 — a node and
a coordinator built from different commits register and heartbeat normally and can
still drop every session between them, because registration is stable across builds
and session setup is not (issue #114). It is NOT refused: -min-serving-version is
the fence for that, and it is unaffected by this line
```
Printed once per node per release — on a node's first register and again
whenever its release changes, not on all 8,640 registers it sends in a day.
**Until #128 this line could not fire at all**, because nothing stamped a
release and every binary reported the same one; it is the same commit that
stamped them which made this sentence stop being true. It still compares
*releases*, so two builds of the same release from different commits do not
trip it — which is why the coordinator's own startup line also prints the VCS
revision the toolchain recorded, and why line 4 exists.

**4. A node that is assigned work and answers none of it.**
```
WARNING: exit n7 was assigned 3 session(s) that a client tried to bring up and has
answered NONE of them (the longest has been waiting 2m14s). It registers and
heartbeats normally, so nothing else here reports it: check it is reachable and
running a build compatible with this coordinator — it reports release 0.4.0, this
coordinator is 0.4.1 (issue #114)
```
This is the one that generalises: it catches *any* cause of "the node never
answered", not just version skew — a firewall, a half-dead process, a node that
lost its egress. A session counts as unanswered when a client signalled it and
nothing came back for 30s; the sweep runs every 10s. It is said once per
episode, and re-arms as soon as that node answers anything, so a node that
fails, recovers and fails again is reported both times. A single unanswered
session is not a fault — a client can always walk away — which is why the line
fires only when a node has answered **none**.

**The fence, for when a warning is not enough.** `-min-serving-version` drops
nodes below a release from matchmaking entirely:
```
bacchus-coordinator -min-serving-version 0.4.0 …
```
It defaults to `0.0.0`, which disables it — every node serves regardless of
version. The intended use is to raise it behind a release once the grace window
has passed, which pulls stragglers up. Two things to know before setting it: a
node exactly at the floor keeps serving (the floor is the oldest *acceptable*
release), and an unstamped node reports `0.0.0`, so any floor above zero fences
every unstamped binary in the fleet. That is the correct posture — a build whose
release cannot be established cannot be shown to meet a floor — but it is worth
knowing before turning the flag on with hand-built binaries in the field.

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
- **Rebuild and redeploy the whole deployment from one commit, together** —
  `deploy/bacchus-pin.sh`, which exists so this stops being advice
  ([the procedure](#pinning-the-whole-deployment-to-a-commit-issue-205-adr-0064)).
  A node on an older build registers, heartbeats and is assigned work exactly as
  a current one does, and then drops every session it is given — the coordinator
  logs a healthy fleet throughout (issue #114). If sessions stop establishing
  after a partial update, that is the first thing to rule out; the four lines
  under [What the coordinator says about node
  builds](#what-the-coordinator-says-about-node-builds-issue-114) are where it
  shows.
- **Merging is not deploying, and the release number will not tell you.** Two
  coordinators two waves apart both report `release 0.1.0`. Pin the boxes and
  run both checks before trusting any result that came off them.
- Binaries built with a bare `go build` report release `0.0.0` and warn at every
  start. That is fine for development and wrong for anything deployed — stamp
  them from `VERSION`, or install with `deploy/install.sh`, which does it for
  you.
