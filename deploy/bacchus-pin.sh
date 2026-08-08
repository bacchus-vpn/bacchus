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
usage: bacchus-pin.sh [--commit SHA] [--config FILE] [--repo DIR] [--dry-run] [--no-verify]

  --commit SHA   refuse unless the repository is already on this commit
  --config FILE  host list (default: deploy/testbed.env beside this script)
  --repo DIR     the checkout to build from (default: this script's repository)
  --dry-run      print every remote command instead of running it, and build nothing
  --no-verify    skip the post-deploy fleet check and capability probe

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
log "the coordinator's effective unit configuration"
if unit_cfg=$("$SSH" "$COORDINATOR_TARGET" "systemctl show -p ExecStart -p WorkingDirectory $COORDINATOR_UNIT" 2>/dev/null); then
	printf '%s\n' "$unit_cfg" | sed 's/^/    /'
	wd=$(printf '%s\n' "$unit_cfg" | sed -n 's/^WorkingDirectory=//p')
	if [ -z "$wd" ] || [ "$wd" = "/" ]; then
		rel=$(printf '%s\n' "$unit_cfg" | sed -n 's/^ExecStart=//p' |
			tr ' ' '\n' | grep -E '^[A-Za-z0-9_.-]+/' || true)
		if [ -n "$rel" ]; then
			printf '%s: WARNING: WorkingDirectory is unset (so it is /) and ExecStart names relative paths:\n' "$self" >&2
			printf '%s\n' "$rel" | sed 's/^/      /' >&2
			printf '%s: each of those resolves under / on this box. Confirm they exist there — a missing\n' "$self" >&2
			printf '%s: revocation file in particular does not fail, it means nothing is revoked.\n' "$self" >&2
		fi
	fi
else
	log "  could not read it (not fatal) — check it by hand before trusting a result from this box"
fi

log "reading the coordinator's journal for every node's build"
if ! "$SSH" "$COORDINATOR_TARGET" "journalctl -u $COORDINATOR_UNIT --since '-5 min' --no-pager" |
	sh "$script_dir/bacchus-fleet-check.sh" "$head"; then
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
