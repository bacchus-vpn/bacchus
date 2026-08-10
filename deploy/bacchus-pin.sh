#!/bin/sh
# Take the whole deployment to ONE named commit, from ONE build (issue #205, ADR-0064).
#
# usage: bacchus-pin.sh [--commit SHA] [--config FILE] [--repo DIR] [--dry-run] [--no-verify]
#
# A wave merges to `main` and nothing deploys. The boxes fall one wave further behind
# per wave, silently, and every card that says "run it on the testbed" then runs against
# whatever was last copied there by hand. A result from a stale box is wrong in the
# direction that is hardest to catch: it looks like a finding about the code and it is a
# finding about the deployment. This script is the step that was missing.
#
# ---------------------------------------------------------------------------
# WHAT IT WILL NOT DO
# ---------------------------------------------------------------------------
# * It never copies a `.service` file, and there is no flag that makes it. The
#   coordinator's real unit carries hand-added flags that are NOT in
#   deploy/bacchus-coordinator.service, so re-copying that file silently reverts a
#   live configuration and the deployment then works differently for reasons no diff
#   shows. Units are installed once, by hand or by deploy/install.sh, and edited in
#   place. This is binaries only.
#
#   It does COMPARE them, which is a different thing and was missing (issue #234): a
#   directive a template gained and a live unit lacks was invisible in both directions,
#   which is how issue #222's OnFailure= rollback shipped to a repository and reached no
#   box while every pin run reported a pinned fleet. See deploy/bacchus-unit-check.sh.
#   The comparison copies nothing and does not fail the run — it reports. A box it could
#   not compare is COUNTED and named as NOT COMPARED, because a skip reported at the
#   volume of a pass is a box with no coverage reading like a box with nothing wrong
#   (issue #248).
# * It never configures a gate. It READS them, from what the coordinator said at
#   startup, and says which are off (deploy/bacchus-gate-check.sh, issue #249). Every
#   credential gate this binary has fails OPEN when unset, so a fleet with all of them
#   off passes every other check here and refuses nothing anywhere — which is what would
#   make issues #167, #173 and #209 each return a false pass. Set COORDINATOR_GATES in
#   testbed.env to the gates this deployment enforces and a pin that finds one off
#   FAILS; leave it empty and the posture is reported and nothing is judged.
# * It never checks anything out. It reads the commit the repository is ALREADY on and
#   refuses if `--commit` disagrees, so moving HEAD stays the operator's deliberate act
#   and a half-finished rebase cannot become a deployment.
# * It never touches /etc/bacchus. Keys, env files and revocation lists are state, not
#   artifacts.
#
# ---------------------------------------------------------------------------
# THE ORDER, WHICH IS PART OF THE CHECK AND NOT A PREFERENCE
# ---------------------------------------------------------------------------
# Nodes restart first and the COORDINATOR RESTARTS LAST. A restarting coordinator
# empties its registry, so every node re-registers as new and prints a `registered:`
# line carrying `build=<revision>` (issue #182) — which is what lets one journal on one
# host establish every node's binary without an ssh per box. Restart the coordinator
# first and no `registered:` line fires at all: a node is back inside its 35s registry
# TTL, the entry is simply refreshed, and the journal keeps answering with values from
# before the deploy. See deploy/bacchus-fleet-check.sh, which enforces the same window.
#
# ---------------------------------------------------------------------------
# STAGING: TWO PASSES, THE SAME DISCIPLINE bacchus-geoip-refresh.sh USES
# ---------------------------------------------------------------------------
# Pass one copies every binary to every box under a temporary name beside its
# destination and checks its digest THERE. Nothing that is running is touched, so a
# transfer that dies — a dropped link, a full disk, a box that is not up — replaces
# nothing anywhere. Pass two stops the unit, renames the checked file over the live one
# (a rename, in the same directory, so it is atomic and never a partially-written
# binary) and starts the unit again. A failure in pass one leaves a fleet that is
# entirely on the old commit, which is a state that works; a fleet half-updated is the
# state issue #114 was opened about.
#
# ---------------------------------------------------------------------------
# CONFIGURATION LIVES OUTSIDE THIS REPOSITORY
# ---------------------------------------------------------------------------
# Hosts are read from deploy/testbed.env, which is gitignored (`*.env`). See
# deploy/testbed.env.example for the shape. No address, hostname or credential belongs
# in this file or anywhere else in this repository.
#
# `ssh`, `scp` and `go` are taken from BACCHUS_SSH / BACCHUS_SCP / BACCHUS_GO when set,
# which is how deploy/pin_test.go exercises every path below against a fake fleet.

set -eu

self="${0##*/}"

usage() {
	cat >&2 <<'USAGE'
usage: bacchus-pin.sh [--commit SHA] [--config FILE] [--repo DIR] [--dry-run]
                      [--no-verify] [--no-restart-absent]

  --commit SHA   refuse unless the repository is already on this commit
  --config FILE  host list (default: deploy/testbed.env beside this script)
  --repo DIR     the checkout to build from (default: this script's repository)
  --dry-run      print every remote command instead of running it, and build nothing
  --no-verify    skip the post-deploy fleet check and capability probe
  --no-restart-absent
                 do not restart the node units when one has not re-registered.
                 The restart is a containment for issue #225 and it destroys the
                 state that diagnoses it, so pass this when the stranded process
                 is what you want to look at

Exit: 0 pinned · 1 deploy failed · 2 usage/configuration · 3 built and deployed, but
      verification did not confirm it
USAGE
}

log() { printf '%s: %s\n' "$self" "$*"; }
fail() {
	printf '%s: ERROR: %s\n' "$self" "$1" >&2
	exit "${2:-1}"
}
fail2() { fail "$1" 2; }

commit=""
config=""
repo=""
dry=0
verify=1
restart_absent=1

while [ "$#" -gt 0 ]; do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	--commit)
		[ "$#" -ge 2 ] || fail2 "--commit needs a value"
		commit="$2"
		shift 2
		;;
	--config)
		[ "$#" -ge 2 ] || fail2 "--config needs a value"
		config="$2"
		shift 2
		;;
	--repo)
		[ "$#" -ge 2 ] || fail2 "--repo needs a value"
		repo="$2"
		shift 2
		;;
	--dry-run)
		dry=1
		shift
		;;
	--no-verify)
		verify=0
		shift
		;;
	--no-restart-absent)
		restart_absent=0
		shift
		;;
	*)
		printf '%s: unknown argument: %s\n' "$self" "$1" >&2
		usage
		exit 2
		;;
	esac
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
: "${repo:=$(dirname -- "$script_dir")}"
: "${config:=$script_dir/testbed.env}"

SSH="${BACCHUS_SSH:-ssh}"
SCP="${BACCHUS_SCP:-scp}"
GO="${BACCHUS_GO:-go}"

# ---------------------------------------------------------------------------
# 1. The checkout
# ---------------------------------------------------------------------------

[ -d "$repo/.git" ] || {
	if [ -e "$repo/.git" ]; then
		fail2 "$repo/.git is a FILE, so this is a git worktree, and the Go toolchain records VCS
       data only from a checkout with a real .git DIRECTORY. Every binary built here would
       report build=unknown, the fleet check would have nothing to compare, and the whole
       point of pinning would be lost at the last step. Build from a clone: git clone the
       repository, check out the commit, and point --repo at it."
	fi
	fail2 "$repo is not a git checkout (no .git)"
}

command -v git >/dev/null 2>&1 || fail2 "git is not installed, and this cannot run without it"

head=$(git -C "$repo" rev-parse HEAD) || fail2 "cannot read HEAD in $repo"
if [ -n "$(git -C "$repo" status --porcelain)" ]; then
	fail2 "$repo has uncommitted changes. A build from a dirty tree is stamped '-dirty' and is
       not at any named commit, so there would be nothing to pin the fleet TO."
fi
if [ -n "$commit" ]; then
	want=$(git -C "$repo" rev-parse "$commit^{commit}" 2>/dev/null) ||
		fail2 "$commit is not a commit in $repo"
	[ "$want" = "$head" ] ||
		fail2 "$repo is on $head, not $want. This script never moves HEAD — check the commit out
       yourself and run it again."
fi
short=$(printf '%.12s' "$head")

# ---------------------------------------------------------------------------
# 2. The host list
# ---------------------------------------------------------------------------

[ -r "$config" ] || fail2 "no host list at $config.
       Copy deploy/testbed.env.example to deploy/testbed.env and fill it in. It is
       gitignored: real addresses never enter this repository."

# shellcheck disable=SC1090
. "$config"

: "${COORDINATOR_UNIT:=bacchus-coordinator}"
: "${BIN_DIR:=/usr/local/bin}"
: "${TARGET_GOOS:=linux}"
: "${TARGET_GOARCH:=amd64}"

[ -n "${COORDINATOR_TARGET:-}" ] || fail2 "$config sets no COORDINATOR_TARGET"
[ -n "${NODE_TARGETS:-}" ] || fail2 "$config sets no NODE_TARGETS"
if [ "$verify" -eq 1 ] && [ -z "${COORDINATOR_SIGNALING:-}" ]; then
	fail2 "$config sets no COORDINATOR_SIGNALING, so the capability probe has nothing to probe.
       Set it (the coordinator's -addr, reachable from here) or pass --no-verify — but read
       what --no-verify costs: without the probe, 'deployed' rests on scp having exited 0."
fi

# ---------------------------------------------------------------------------
# 3. Build, once, from that checkout
# ---------------------------------------------------------------------------

version=$(cat "$repo/VERSION") || fail2 "cannot read $repo/VERSION"
stamp="-X github.com/bacchus-vpn/bacchus/core/version.current=$version"
stage="${TMPDIR:-/tmp}/bacchus-pin.$$"
mkdir -p "$stage" || fail "cannot create $stage"
trap 'rm -rf "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log "repository $repo"
log "commit     $head"
log "release    $version (from VERSION)"
log "target     $TARGET_GOOS/$TARGET_GOARCH"

build_one() {
	_out="$stage/$1"
	_pkg="$2"
	log "building $1"
	if [ "$dry" -eq 1 ]; then
		printf 'DRY-RUN build: GOOS=%s GOARCH=%s CGO_ENABLED=0 %s build -ldflags "%s" -o %s %s\n' \
			"$TARGET_GOOS" "$TARGET_GOARCH" "$GO" "$stamp" "$_out" "$_pkg"
		return 0
	fi
	(cd "$repo" && GOOS="$TARGET_GOOS" GOARCH="$TARGET_GOARCH" CGO_ENABLED=0 \
		"$GO" build -ldflags "$stamp" -o "$_out" "$_pkg") ||
		fail "building $_pkg failed — nothing was deployed"
	verify_stamp "$_out" "$1"
}

# verify_stamp refuses a binary whose release stamp is not recorded, or that is not the
# commit being pinned.
#
# `go version -m` records the -ldflags a build was given, which catches a plain
# `go build` — a binary that reports release 0.0.0 on the box and warns at every start,
# correct for development and wrong for anything deployed. It does NOT catch an -X
# naming a symbol that does not resolve: the linker ignores one silently, so the flag is
# recorded exactly as it would be for a correct build and the binary still reports 0.0.0.
# That half is checked once, before any build, by verify_symbol_path.
verify_stamp() {
	_bin="$1"
	_name="$2"
	_meta=$("$GO" version -m "$_bin" 2>/dev/null) ||
		fail "cannot read build metadata from $_name"

	printf '%s\n' "$_meta" | grep -q -- "-ldflags=.*core/version.current=$version" ||
		fail "$_name was built WITHOUT the release stamp: it would report release 0.0.0 on the box,
       which is a node the version fence cannot rank and the build-skew warning cannot
       compare. Nothing was deployed."

	printf '%s\n' "$_meta" | grep -q "vcs.revision=$head" ||
		fail "$_name does not carry vcs.revision=$head. Without it a node registers as
       build=unknown and the fleet check has nothing to compare. Nothing was deployed."

	printf '%s\n' "$_meta" | grep -q "vcs.modified=false" ||
		fail "$_name was built from a modified tree. Nothing was deployed."

	log "  $_name: release $version, revision $short, stamp recorded"
}

# verify_symbol_path establishes that the -X above names a symbol the linker can
# actually resolve IN THIS CHECKOUT, by linking it into a test binary and reading the
# value back out — not by asserting the flag was passed, which is the assertion that
# cannot see the failure.
#
# This is not a new mechanism: core/version.TestStampMatchesTheVersionFile exists for
# exactly this, ci.yml's "the release stamp reaches the binary" job runs it on every
# push, and BACCHUS_REQUIRE_STAMP is what turns its skip-when-absent into a failure. It
# is run again here because CI proves the symbol path resolved at the last PUSH, while
# what a deploy needs to know is that it resolves in the tree it is about to ship — the
# same distinction that makes the checks after the deploy worth running.
verify_symbol_path() {
	log "confirming the release stamp's symbol path resolves in this checkout"
	[ "$dry" -eq 0 ] || return 0
	(cd "$repo" && BACCHUS_REQUIRE_STAMP=1 "$GO" test -count=1 \
		-ldflags "$stamp" -run TestStampMatchesTheVersionFile ./core/version/ >/dev/null) ||
		fail "the release stamp does not reach core/version.current in this checkout. A -X naming
       a symbol the linker cannot resolve — a renamed variable, a moved package, a typo'd
       module path — is IGNORED SILENTLY: the build would succeed, this script's own
       metadata check would pass, and every binary would report 0.0.0 for the life of the
       deployment. Nothing was built."
}

verify_symbol_path
build_one bacchus-coordinator ./cmd/coordinator
build_one bacchus-node ./cmd/node

# The probe runs from HERE, against the deployment, so it is built for this machine
# rather than the target. It reads no version of its own.
probe="$stage/coordinator-probe"
if [ "$verify" -eq 1 ] && [ "$dry" -eq 0 ]; then
	log "building coordinator-probe (this machine)"
	(cd "$repo" && "$GO" build -o "$probe" ./cmd/coordinator-probe) ||
		fail "building ./cmd/coordinator-probe failed — nothing was deployed"
fi

# ---------------------------------------------------------------------------
# 4. Pass one — stage everywhere, replace nothing
# ---------------------------------------------------------------------------

# Each entry of NODE_TARGETS is TARGET=UNIT. `=` rather than `:` because an ssh target
# can be an IPv6 literal and a scp argument is already host:path.
node_target() { printf '%s' "${1%%=*}"; }
node_unit() {
	case "$1" in
	*=*) printf '%s' "${1#*=}" ;;
	*) printf 'bacchus-exit' ;;
	esac
}

remote() {
	_target="$1"
	shift
	if [ "$dry" -eq 1 ]; then
		printf 'DRY-RUN ssh %s %s\n' "$_target" "$*"
		return 0
	fi
	"$SSH" "$_target" "$*"
}

copy() {
	_src="$1"
	_target="$2"
	_dst="$3"
	if [ "$dry" -eq 1 ]; then
		printf 'DRY-RUN scp %s %s:%s\n' "$_src" "$_target" "$_dst"
		return 0
	fi
	"$SCP" "$_src" "$_target:$_dst"
}

# digest_of prints the sha256 of a local file, using whichever of the two tools this
# machine has. The digest exists so a transfer that arrives truncated is refused BEFORE
# it replaces a working binary rather than after.
digest_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		fail "neither sha256sum nor shasum is installed, and a transfer this script cannot
       verify is one it will not make"
	fi
}

# staged accumulates TARGET=BASENAME for every temporary file that exists on a box, so
# a failure anywhere removes the debris everywhere rather than leaving a half-fleet
# holding an unexplained `.bacchus-pin.new` beside its live binary.
staged=""
# Invoked indirectly, through the EXIT trap below — shellcheck cannot follow a trap
# target to its definition and reports it as unreachable/unused, the same way
# bacchus-asn-drift-check.sh's cleanup is reported.
# shellcheck disable=SC2317,SC2329
cleanup_staged() {
	for _s in $staged; do
		remote "${_s%%=*}" "rm -f $BIN_DIR/${_s#*=}.bacchus-pin.new" >/dev/null 2>&1 || true
	done
	staged=""
}

stage_to() {
	_target="$1"
	_bin="$2"  # local file in $stage
	_name="$3" # destination basename in $BIN_DIR
	_want=""
	[ "$dry" -eq 1 ] || _want=$(digest_of "$stage/$_bin")

	log "staging $_name -> $_target"
	copy "$stage/$_bin" "$_target" "$BIN_DIR/$_name.bacchus-pin.new" ||
		fail "copying $_name to $_target failed. Nothing on any box was replaced; the fleet is
       still entirely on its previous build, which is a state that works."
	staged="$staged $_target=$_name"

	if [ "$dry" -eq 1 ]; then
		printf 'DRY-RUN ssh %s sha256sum %s\n' "$_target" "$BIN_DIR/$_name.bacchus-pin.new"
		return 0
	fi
	_got=$(remote "$_target" "sha256sum $BIN_DIR/$_name.bacchus-pin.new" | cut -d' ' -f1) ||
		fail "cannot digest the staged $_name on $_target"
	[ "$_got" = "$_want" ] ||
		fail "the copy of $_name on $_target digests $_got, not $_want — the transfer is corrupt
       or truncated. Nothing was replaced anywhere."
	remote "$_target" "chmod 0755 $BIN_DIR/$_name.bacchus-pin.new" ||
		fail "cannot make the staged $_name executable on $_target"
}

trap 'cleanup_staged; rm -rf "$stage"' EXIT

for entry in $NODE_TARGETS; do
	stage_to "$(node_target "$entry")" bacchus-node bacchus-node
done
stage_to "$COORDINATOR_TARGET" bacchus-coordinator bacchus-coordinator

log "every box holds a checked copy; nothing has been replaced yet"

# ---------------------------------------------------------------------------
# 5. Pass two — replace and restart, nodes first, coordinator last
# ---------------------------------------------------------------------------

install_on() {
	_target="$1"
	_unit="$2"
	_name="$3"
	log "installing on $_target ($_unit)"
	# One command, so an interrupted connection cannot leave the unit stopped with the
	# old binary in place. The rename is within one directory, so it is atomic; the unit
	# is stopped first because a running text file cannot be written to (though it can be
	# renamed over), and because a service restarting into a half-swapped state is the
	# kind of thing that is only ever debugged once.
	remote "$_target" "systemctl stop $_unit && mv -f $BIN_DIR/$_name.bacchus-pin.new $BIN_DIR/$_name && systemctl start $_unit" ||
		fail "installing on $_target failed. This box may be stopped or on either binary — check
       it by hand (systemctl status $_unit) before re-running."
}

for entry in $NODE_TARGETS; do
	install_on "$(node_target "$entry")" "$(node_unit "$entry")" bacchus-node
done

# Last, deliberately: see "THE ORDER" above.
install_on "$COORDINATOR_TARGET" "$COORDINATOR_UNIT" bacchus-coordinator
staged=""

log "every box is on $short"

if [ "$dry" -eq 1 ]; then
	log "dry run — nothing was built, copied or restarted"
	exit 0
fi

# ---------------------------------------------------------------------------
# 6. Verify — by behaviour, not by having exited 0
# ---------------------------------------------------------------------------

if [ "$verify" -eq 0 ]; then
	log "verification skipped (--no-verify). 'Deployed' currently means 'scp exited 0'."
	log "Run deploy/bacchus-fleet-check.sh and cmd/coordinator-probe before trusting these boxes."
	exit 0
fi

# A node re-registers every 10s (core/engine.go, registerLoop), so this is one interval
# plus the coordinator's own start, doubled for slack. Waiting is not optional: read the
# journal too early and it truthfully reports that no node has registered yet, which
# reads as a fleet that is down. Overridable because a fleet whose nodes are elsewhere
# may need longer, and because deploy/pin_test.go sets it to 0.
settle="${BACCHUS_PIN_SETTLE:-20}"
if [ "$settle" -gt 0 ]; then
	log "waiting ${settle}s for every node to re-register with the restarted coordinator"
	sleep "$settle"
fi

rc=0

# What the unit ACTUALLY runs. Printed rather than assumed, because the coordinator's
# real unit carries hand-added flags that deploy/bacchus-coordinator.service does not,
# so the file in this repository is not evidence of anything about the running service.
#
# The check underneath it is for one live class of mis-set: the unit has
# `WorkingDirectory=` empty, which for a system service means `/`, so a relative default
# like `secrets/device-revocations.json` resolves to `/secrets/…` — a path that does not
# exist. A missing revocation file does not fail; it means NOTHING IS REVOKED, quietly,
# which is the worst way for a security control to be off.
#
# It used to warn only when ExecStart ALSO named a relative path, and that condition is
# exactly backwards (issue #226). A flag left at its default never appears in ExecStart
# at all, so the warning stayed silent precisely when the operator had not thought about
# the path, and fired only when they had. On the first real run of this script every
# path written into the live ExecStart was absolute, the warning correctly stayed quiet,
# and nine relative-default flags — including both revocation lists — were resolving
# under /. So the empty WorkingDirectory is now the whole condition.
#
# The list of flags is deliberately NOT enumerated here. It would be a copy of
# cmd/coordinator's flag table living in a shell script a repository away from it, and
# it would rot. The binary states its own resolved paths at startup instead
# (cmd/coordinator/paths.go), which the journal read below already carries, and which
# also answers for somebody reading the journal without this script.
log "the coordinator's effective unit configuration"
if unit_cfg=$("$SSH" "$COORDINATOR_TARGET" "systemctl show -p ExecStart -p WorkingDirectory $COORDINATOR_UNIT" 2>/dev/null); then
	printf '%s\n' "$unit_cfg" | sed 's/^/    /'
	wd=$(printf '%s\n' "$unit_cfg" | sed -n 's/^WorkingDirectory=//p')
	if [ -z "$wd" ] || [ "$wd" = "/" ]; then
		printf '%s: WARNING: this unit has no WorkingDirectory=, so for a system service it is /.\n' "$self" >&2
		printf '%s: Every relative path this coordinator uses therefore resolves under the root\n' "$self" >&2
		printf '%s: directory, where nothing is staged — and cmd/coordinator has nine flags whose\n' "$self" >&2
		printf '%s: default is a relative secrets/ path, none of which appear in ExecStart at all.\n' "$self" >&2
		printf '%s: A missing revocation file does not fail: it means NOTHING IS REVOKED.\n' "$self" >&2
		rel=$(printf '%s\n' "$unit_cfg" | sed -n 's/^ExecStart=//p' |
			tr ' ' '\n' | grep -E '^[A-Za-z0-9_.-]+/' || true)
		if [ -n "$rel" ]; then
			printf '%s: ExecStart also spells out relative paths, which resolve the same way:\n' "$self" >&2
			printf '%s\n' "$rel" | sed 's/^/      /' >&2
		fi
		printf '%s: Read the "paths:" lines in the journal below for what is actually in effect.\n' "$self" >&2
	fi
else
	log "  could not read it (not fatal) — check it by hand before trusting a result from this box"
fi

# The floor the check could not have on its own: how many node PROCESSES should appear
# (issue #224). One entry of NODE_TARGETS is one bacchus-node, and a box serving two
# roles is still one — it prints two `registered:` lines carrying one node id, which is
# what the check now counts. A count is passed rather than the list itself: the check
# prints no hostname, which is what keeps its output the half of a run that is safe to
# paste into an issue, while everything this script prints names ssh targets.
expected_nodes=0
for entry in $NODE_TARGETS; do
	expected_nodes=$((expected_nodes + 1))
done

# ---------------------------------------------------------------------------
# THE ROLL CALL (issue #232): the two namespaces finally meet, and they meet HERE
# ---------------------------------------------------------------------------
# The coordinator's journal names node IDS; NODE_TARGETS names SSH TARGETS. Until now
# nothing mapped one to the other, so an absent box was reported as a count — `2 of 3
# expected node(s) registered` — and finding out which one cost a `systemctl status` per
# box, the per-box work this script exists to end.
#
# Both halves are now readable. Each box states its own id at startup (core.Engine.Start
# prints `exit <id> (<country>) advertising …` and `relay <id> online`, and cmd/node sets
# no Config.OnEvent so those go through log.Println into the journal) — read with
# deploy/bacchus-node-id.sh. The coordinator's side comes from the fleet check's
# `--ids-to`. Subtracting one from the other names the box.
#
# THE PAIRING LIVES IN THIS SCRIPT, and that is a decision rather than an accident. The
# fleet check prints no hostname, which is what makes its output the half of a run that
# is safe to paste into a public issue; naming a box means naming a host, and this
# script's output already names ssh targets on every line. So the check keeps answering
# in ids, this holds the map, and neither gains the other's property.
#
# It removes the SECOND limit too, and that one is easier to miss: a volunteer client
# serves as a relay or an exit (ADR-0053) and registers exactly like a deployed node
# without being in anybody's host list, so a volunteer present while a deployed box is
# absent holds the COUNT up and the check passes. A roll call compares identities, so a
# registration that belongs to no deployed box cannot stand in for one that is missing.
# `--expect` is still passed: it is what answers when a box's own id could not be read,
# and it is what the check gives an operator running it by hand.
#
# The map is rebuilt after the containment restart below rather than carried across it.
# A relay without -relay-ingress takes a FRESH RANDOM id at every start (core/engine.go,
# randID), so a map read before a restart names an identity that no longer exists and
# would report a box that came back perfectly as absent. An exit's id is its X25519
# public key and does not move; the map cannot tell which kind it is holding.
node_ids="$stage/node-ids"
registered_ids="$stage/registered-ids"
id_unknown=0

read_node_ids() {
	: >"$node_ids"
	id_unknown=0
	for entry in $NODE_TARGETS; do
		_t=$(node_target "$entry")
		_u=$(node_unit "$entry")
		# stderr is dropped because bacchus-node-id.sh explains itself at length and
		# cannot name the box; the one line below does both, once per box.
		_id=$("$SSH" "$_t" "journalctl -u $_u --since '-5 min' --no-pager" 2>/dev/null |
			sh "$script_dir/bacchus-node-id.sh" 2>/dev/null) || _id=""
		if [ -z "$_id" ]; then
			id_unknown=$((id_unknown + 1))
			log "  $_t ($_u): no node id in its journal — this box cannot be named in the roll call"
			continue
		fi
		printf '%s|%s|%s\n' "$_t" "$_u" "$_id" >>"$node_ids"
		log "  $_t ($_u): $_id"
	done
	if [ "$id_unknown" -gt 0 ]; then
		printf '%s: %d box(es) did not state a node id. A node prints one at startup, per serving\n' "$self" "$id_unknown" >&2
		printf '%s: role; a box on a binary older than that, a unit that is down, or a journal window\n' "$self" >&2
		printf '%s: that does not reach the last start all produce this. Those boxes fall back to the\n' "$self" >&2
		printf '%s: count (--expect), which cannot name them and which a volunteer can hold up.\n' "$self" >&2
	fi
}

roll_absent=0
roll_extra=0

# roll_call compares the ids the boxes state with the ids the coordinator saw. It NAMES
# what it finds, which is the whole point, and it is silent when it has nothing to add.
# It takes the fleet check's exit code, because half of "silent" is knowing when the
# other side of the comparison is not evidence.
roll_call() {
	roll_absent=0
	roll_extra=0
	# Only a window the check could READ says anything about who registered. Exit 3
	# is a window with no `coordinator release` line in it and exit 2 is a usage
	# error; both leave an empty ids file, and an ssh that failed would then read as
	# every box being absent — naming all of them and restarting the whole fleet
	# because a journal could not be fetched.
	case "$1" in
	0 | 1 | 4) ;;
	*) return 0 ;;
	esac
	[ -s "$node_ids" ] || return 0
	[ -f "$registered_ids" ] || return 0

	while IFS='|' read -r _t _u _id; do
		[ -n "$_id" ] || continue
		grep -qxF "$_id" "$registered_ids" && continue
		if [ "$roll_absent" -eq 0 ]; then
			printf '%s: ROLL CALL: a box that IS deployed did not register in this window.\n' "$self" >&2
		fi
		roll_absent=$((roll_absent + 1))
		printf '%s:   %s (%s) registers as %s — that id is not in the coordinator journal\n' "$self" "$_t" "$_u" "$_id" >&2
	done <"$node_ids"

	while read -r _rid; do
		[ -n "$_rid" ] || continue
		cut -d'|' -f3 "$node_ids" | grep -qxF "$_rid" && continue
		roll_extra=$((roll_extra + 1))
	done <"$registered_ids"

	if [ "$roll_absent" -gt 0 ]; then
		printf '%s: This is NOT drift: every node that did register is reported above, on the build it\n' "$self" >&2
		printf '%s: is running. It is a box that is not answering — down, unable to reach this\n' "$self" >&2
		printf '%s: coordinator, or the state a deploy guarantees (issue #225: a node brought up against\n' "$self" >&2
		printf '%s: the OUTGOING coordinator never rebuilds the link, because the coordinator restarts\n' "$self" >&2
		printf '%s: last by design). Start with: systemctl status on the box named above.\n' "$self" >&2
	fi
	if [ "$roll_extra" -gt 0 ] && [ "$id_unknown" -eq 0 ]; then
		log "$roll_extra registration(s) belong to no box in NODE_TARGETS — a volunteer serving as a"
		log "  relay or an exit (ADR-0053). Not a failure, and it no longer counts towards the floor:"
		log "  the check above compares numbers, this compares identities."
	fi
}

# The coordinator's journal, read ONCE per check and kept, because two different
# questions are asked of the same window: which build each node registered on
# (bacchus-fleet-check.sh) and which credential gates this coordinator actually came up
# with (bacchus-gate-check.sh, issue #249). Reading it twice would let the two answers
# describe two different windows — and after the containment restart below it is read
# again, so the last read is the one both checks see.
coord_journal="$stage/coord-journal"

fleet_check() {
	"$SSH" "$COORDINATOR_TARGET" "journalctl -u $COORDINATOR_UNIT --since '-5 min' --no-pager" \
		>"$coord_journal" 2>/dev/null || true
	sh "$script_dir/bacchus-fleet-check.sh" --expect "$expected_nodes" --ids-to "$registered_ids" "$head" \
		<"$coord_journal"
}

log "asking every node box what it registers as (issue #232)"
read_node_ids

log "reading the coordinator's journal for every node's build"
fleet_rc=0
fleet_check || fleet_rc=$?
roll_call "$fleet_rc"

# ---------------------------------------------------------------------------
# A node that did not come back is restarted ONCE — a containment, not a fix
# ---------------------------------------------------------------------------
# Exit 4 from the check means a node that should be there did not register in this
# window. The most likely cause is one this script CAUSES: the coordinator restarts
# last, so every node is brought up against the OUTGOING coordinator and then has it
# removed a second later — and a node in that state never rebuilds the link. It sits
# idle, registers with nobody, and is invisible to the coordinator for as long as it is
# left alone (issue #225: 100 minutes observed, recovered by `systemctl restart` in
# under a second).
#
# So this restarts the node units once and reads the journal again. Three things about
# that, in order of how easy they are to get wrong:
#
#   * It is a CONTAINMENT and it goes away when #225 is fixed. A client that recovers on
#     its own needs no help from a deploy script.
#   * It does NOT change the restart order, and must not. `build=` rides the
#     `registered:` line, which fires only for a node the coordinator does not already
#     hold, so coordinator-last is what makes the reading fresh at all.
#   * It restarts EVERY node unit, even now that the roll call can usually NAME the
#     absent one. Restarting only the named box would be wrong whenever the roll call is
#     incomplete — a box whose own id could not be read is exactly a box that may be the
#     one that is down — and this is cheap precisely here and nowhere else, because this
#     script restarted every one of them about twenty seconds ago.
#
# The trigger is either finding: the check's exit 4 (fewer ids than expected) OR the
# roll call naming a deployed box that is missing. They are not the same condition — a
# volunteer holds the COUNT up while the roll call still sees the gap, which is issue
# #232's whole point. Drift (exit 1) is never restarted away either way: a box on the
# wrong binary is still on the wrong binary afterwards, and restarting it would destroy
# the evidence.
absent=0
if [ "$fleet_rc" -eq 4 ] || [ "$roll_absent" -gt 0 ]; then
	absent=1
fi
if [ "$absent" -eq 1 ] && [ "$fleet_rc" -ne 1 ] && [ "$restart_absent" -eq 1 ]; then
	log "a node did not re-register — restarting every node unit ONCE (issue #225 containment, not a fix)"
	for entry in $NODE_TARGETS; do
		_t=$(node_target "$entry")
		_u=$(node_unit "$entry")
		log "restarting $_u on $_t"
		remote "$_t" "systemctl restart $_u" ||
			log "  restart failed on $_t — check it by hand"
	done
	if [ "$settle" -gt 0 ]; then
		log "waiting ${settle}s for the restarted nodes to register"
		sleep "$settle"
	fi
	# The map is rebuilt, not reused: a relay takes a fresh random id at every start,
	# so the ids read before the restart describe processes that no longer exist.
	log "asking every node box what it registers as, again"
	read_node_ids
	log "re-reading the coordinator's journal"
	fleet_rc=0
	fleet_check || fleet_rc=$?
	roll_call "$fleet_rc"
	if [ "$fleet_rc" -eq 0 ] && [ "$roll_absent" -eq 0 ]; then
		printf '%s: NOTE: the fleet is complete only AFTER a node restart this script had to do itself.\n' "$self" >&2
		printf '%s: That is issue #225 — a node whose coordinator went away never rebuilds the link — and\n' "$self" >&2
		printf '%s: every deploy reproduces it, because the coordinator restarts last by design.\n' "$self" >&2
	fi
fi

if [ "$fleet_rc" -ne 0 ] || [ "$roll_absent" -gt 0 ]; then
	rc=3
fi

# ---------------------------------------------------------------------------
# The units — compared, never copied (issue #234)
# ---------------------------------------------------------------------------
# The no-copy rule above is correct and stays. What was missing is that nothing compared
# the two either, so a directive a template GAINED and a live unit lacks was invisible:
# issue #222 added `OnFailure=bacchus-update-rollback@%n.service` to both server units,
# merging it put it on no box, and every pin run afterwards reported a pinned fleet. That
# is issue #205's finding in a different place — the repository holds a mechanism the
# fleet does not have, and nothing reports the difference.
#
# This REPORTS and does not fail the run, for the same reason the WorkingDirectory
# warning above does not: units are configuration this script deliberately does not
# manage, the binaries genuinely are pinned, and a check that failed every pin until
# somebody hand-edited three units would either be switched off or answered by adding
# the copy flag that must not exist. It is loud, it says exactly what to type, and it
# says it on every run until the box carries the line.
#
# A box this could not compare is COUNTED, and counted separately from a box that
# compared clean (issue #248). It used to return quietly, at the same volume as a pass,
# so a box with no coverage at all read like a box with nothing wrong — and on the first
# real run the box the check could not compare was also the only box that misbehaved.
# That is issue #224's finding in a different file: a check that silently covers two of
# three boxes reports a fleet it did not look at.
unit_gap=0
unit_unchecked=0

# unit_template maps a live unit NAME to the template it should be compared against.
# By default that is the file of the same name, which is the right guess and not always
# the right answer: the role a node runs is a flag (-role exit, -role exit,relay,
# relay-only), so a box whose unit is called bacchus-node or bacchus-relay is running
# what deploy/bacchus-exit.service describes under another name. UNIT_TEMPLATES in
# testbed.env says so — `UNIT_TEMPLATES="bacchus-node=bacchus-exit.service"` — which
# keeps the pairing in the operator's own configuration, beside the host list that
# already names those units, rather than inventing a second template here for every name
# a box might use.
unit_template() {
	for _m in ${UNIT_TEMPLATES:-}; do
		case "$_m" in
		"${1%.service}="*)
			printf '%s' "$script_dir/${_m#*=}"
			return 0
			;;
		esac
	done
	printf '%s' "$script_dir/${1%.service}.service"
}

compare_unit() {
	_target="$1"
	_unit="$2"
	_tmpl=$(unit_template "$_unit")
	log "unit $_unit on $_target"
	if [ ! -r "$_tmpl" ]; then
		unit_unchecked=$((unit_unchecked + 1))
		log "  NOT COMPARED: nothing ships as deploy/${_tmpl##*/} — this box has no unit coverage at all"
		log "  Either rename the unit on the box to one this repository ships, or map it in"
		log "  testbed.env: UNIT_TEMPLATES=\"${_unit%.service}=bacchus-exit.service\""
		return 0
	fi
	if ! _live=$("$SSH" "$_target" "systemctl cat $_unit" 2>/dev/null); then
		unit_unchecked=$((unit_unchecked + 1))
		log "  NOT COMPARED: could not read it — compare it by hand before trusting this box"
		return 0
	fi
	# Any non-zero counts, not only the missing-directive 5: an EMPTY answer from
	# `systemctl cat` (3) means the unit does not exist on that box at all, which is
	# the same finding arriving in its strongest form and must not be the quiet case.
	_urc=0
	printf '%s\n' "$_live" | sh "$script_dir/bacchus-unit-check.sh" "$_tmpl" || _urc=$?
	if [ "$_urc" -ne 0 ]; then
		unit_gap=$((unit_gap + 1))
	fi
	return 0
}

log "comparing every live unit with the one this commit ships (copying nothing)"
unit_total=0
for entry in $NODE_TARGETS; do
	unit_total=$((unit_total + 1))
	compare_unit "$(node_target "$entry")" "$(node_unit "$entry")"
done
unit_total=$((unit_total + 1))
compare_unit "$COORDINATOR_TARGET" "$COORDINATOR_UNIT"

log "units: $((unit_total - unit_gap - unit_unchecked)) of $unit_total compared clean, $unit_gap with a gap, $unit_unchecked NOT COMPARED"

if [ "$unit_gap" -gt 0 ]; then
	printf '%s: WARNING: %d live unit(s) do not carry what this commit ships — a missing directive,\n' "$self" "$unit_gap" >&2
	printf '%s: or no such unit on the box at all. The binaries ARE pinned; this is not drift and it\n' "$self" >&2
	printf '%s: does not fail the run. But a mechanism that is present here and absent there is\n' "$self" >&2
	printf '%s: exactly issue #205, and it stays that way until somebody edits those units by hand.\n' "$self" >&2
	printf '%s: Nothing was copied; see the lines above for what to add and where.\n' "$self" >&2
fi
if [ "$unit_unchecked" -gt 0 ]; then
	printf '%s: WARNING: %d box(es) were NOT COMPARED at all (issue #248). That is not a pass and it\n' "$self" "$unit_unchecked" >&2
	printf '%s: is not a small gap: on the first real run of this script the box with no template was\n' "$self" >&2
	printf '%s: also the only box that failed to re-register. A unit nothing compares can be missing\n' "$self" >&2
	printf '%s: every directive this commit ships and read exactly like a healthy one.\n' "$self" >&2
	printf '%s: Fix it in testbed.env (UNIT_TEMPLATES) or by renaming the unit on the box.\n' "$self" >&2
fi

# ---------------------------------------------------------------------------
# The credential gates — read from what the coordinator SAID, not from its flags
# ---------------------------------------------------------------------------
# Every gate fails open when unset, so an unconfigured deployment passes every check
# above and refuses nothing anywhere (issue #249). Three owner tests are written as if
# the gates were on and would each return a false pass against a fleet in that state, so
# this reports the posture on every run — and, when the operator has DECLARED which
# gates this deployment enforces (COORDINATOR_GATES in testbed.env), fails the run when
# one of them is off.
#
# Declared-or-nothing, deliberately. A check that failed every pin until the gates were
# configured would be switched off long before they were, exactly as the unit comparison
# would have been; a check that reports until an operator says otherwise, and then holds
# them to it, survives.
log "reading the coordinator's credential gates from the journal above"
gate_rc=0
if [ -n "${COORDINATOR_GATES:-}" ]; then
	sh "$script_dir/bacchus-gate-check.sh" --require "$COORDINATOR_GATES" "$coord_journal" || gate_rc=$?
else
	sh "$script_dir/bacchus-gate-check.sh" "$coord_journal" || gate_rc=$?
fi
if [ "$gate_rc" -ne 0 ] && [ -n "${COORDINATOR_GATES:-}" ]; then
	printf '%s: ERROR: this deployment declares COORDINATOR_GATES="%s" and is not enforcing all of\n' "$self" "${COORDINATOR_GATES:-}" >&2
	printf '%s: them. Do not run a test that expects a refusal against this fleet: it would pass\n' "$self" >&2
	printf '%s: without refusing anything, which closes a card on evidence that does not exist.\n' "$self" >&2
	rc=3
fi

log "probing the deployed coordinator's capability"
if ! "$probe" -addr "$COORDINATOR_SIGNALING"; then
	rc=3
fi

if [ "$rc" -ne 0 ]; then
	printf '%s: ERROR: the binaries were deployed and the checks above did NOT confirm the result.\n' "$self" >&2
	printf '%s: Do not run anything on these boxes that assumes the pin held.\n' "$self" >&2
	exit "$rc"
fi

log "the deployment is pinned to $head and serving the capability that commit carries"
