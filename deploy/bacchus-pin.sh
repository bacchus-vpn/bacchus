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
# * It never copies a unit that carries somebody's configuration, and there is no flag
#   that makes it. The coordinator's real unit carries hand-added flags that are NOT in
#   deploy/bacchus-coordinator.service, so re-copying that file silently reverts a live
#   configuration and the deployment then works differently for reasons no diff shows.
#   Those units are installed once, by hand or by deploy/install.sh, and edited in place.
#   ADR-0064 §7, unweakened.
#
#   It does COMPARE them, which is a different thing and was missing (issue #234): a
#   directive a template gained and a live unit lacks was invisible in both directions,
#   which is how issue #222's OnFailure= rollback shipped to a repository and reached no
#   box while every pin run reported a pinned fleet. See deploy/bacchus-unit-check.sh.
#   The comparison copies nothing and does not fail the run — it reports. A box it could
#   not compare is COUNTED and named as NOT COMPARED, because a skip reported at the
#   volume of a pass is a box with no coverage reading like a box with nothing wrong
#   (issue #248).
#
#   It DOES deliver the artifacts this repository is the sole author of, which is the
#   other half of issue #234 and is new here (ADR-0074). §7's refusal is about a unit
#   that holds the OPERATOR's configuration; it was stated over a file extension and its
#   reason is a property, and two files fall on the wrong side of that gap:
#   deploy/bacchus-update-rollback.sh and deploy/bacchus-update-rollback@.service. Neither
#   carries one byte of anybody's configuration — no EnvironmentFile=, no [Install], an
#   ExecStart that is a fixed path, and `%i` supplying the only variable in either — so
#   there is nothing in them a copy could revert. deploy/pin_test.go holds them to that.
#
#   Even so, nothing is replaced that this repository did not write. A live copy is
#   overwritten only when its digest matches SOME version of that file in this
#   repository's own history; anything else is refused, named, and left exactly where it
#   is. That is the property §7 actually protects — no configuration is ever reverted
#   silently — restated as something a run can check rather than as a blanket ban.
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
# Nodes restart first and EVERY COORDINATOR RESTARTS LAST. A restarting coordinator
# empties its registry, so every node re-registers as new and prints a `registered:`
# line carrying `build=<revision>` (issue #182) — which is what lets one journal on one
# host establish every node's binary without an ssh per box. Restart the coordinator
# first and no `registered:` line fires at all: a node is back inside its 35s registry
# TTL, the entry is simply refreshed, and the journal keeps answering with values from
# before the deploy. See deploy/bacchus-fleet-check.sh, which enforces the same window.
#
# ---------------------------------------------------------------------------
# THE COORDINATORS ARE A POOL, AND EVERY CHECK BELOW IS PER MEMBER (issue #250)
# ---------------------------------------------------------------------------
# There is NO coordinator-to-coordinator replication — cmd/node's registerLoop
# broadcasts to every pool member on every tick precisely because there is none. So a
# node can be registered with one member and missing from another, and that asymmetry is
# a real finding rather than noise: the member that never saw it will never assign it
# work, and a client that rotates to that member sees a smaller fleet than the one that
# is running. Flattening the members into one count would hide exactly that, so the
# journal read, the fleet check, the gate check, the unit comparison and the capability
# probe all run ONCE PER MEMBER and are reported per member.
#
# Two consequences that are costs of the pool and not of anything here:
#
# * Each additional member WIDENS the issue #225 window rather than closing it. A node
#   holds one link per member, a member restarting under it strands that link, and the
#   restarts are sequential — so after a pool pin a node is typically stranded from all
#   of them. The containment restart below already covers it, and with a pool it fires
#   on essentially every run instead of occasionally.
# * A pool is only as gated as its WEAKEST member. Every credential gate fails open when
#   unset, and a client rotates freely, so one member started without -device-root-pubkey
#   is a way around the gate rather than a partial deployment of it. COORDINATOR_GATES is
#   therefore required of every member, not of the fleet on average.
#
# ---------------------------------------------------------------------------
# STAGING: TWO PASSES, THE SAME DISCIPLINE bacchus-geoip-refresh.sh USES
# ---------------------------------------------------------------------------
# Pass one copies every artifact to every box under a temporary name beside its
# destination and checks its digest THERE. Nothing that is running is touched, so a
# transfer that dies — a dropped link, a full disk, a box that is not up — replaces
# nothing anywhere. Pass two stops the unit, renames the checked file over the live one
# (a rename, in the same directory, so it is atomic and never a partially-written
# binary) and starts the unit again. A failure in pass one leaves a fleet that is
# entirely on the old commit, which is a state that works; a fleet half-updated is the
# state issue #114 was opened about.
#
# The two rollback artifacts go through the same two passes for the same reasons. The
# rename matters there too: the handler is a script systemd EXECUTES, and a copy over a
# running one is the window a rename does not have.
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

: "${BIN_DIR:=/usr/local/bin}"
: "${LIBEXEC_DIR:=/usr/local/lib/bacchus}"
: "${UNIT_DIR:=/etc/systemd/system}"
: "${TARGET_GOOS:=linux}"
: "${TARGET_GOARCH:=amd64}"

# COORDINATOR_TARGETS is a LIST, spelled exactly like NODE_TARGETS (TARGET=UNIT entries,
# `=` rather than `:` because an ssh target can be an IPv6 literal). The singular
# COORDINATOR_TARGET / COORDINATOR_UNIT pair is still accepted, because every existing
# deploy/testbed.env in anybody's checkout is written that way and this file is gitignored
# — a pin that stopped parsing the operator's own host list would land as a broken deploy
# rather than as a rename. Setting both is refused rather than resolved: a run that
# guessed which one meant the fleet would be guessing about the thing it exists to pin.
if [ -n "${COORDINATOR_TARGETS:-}" ] && [ -n "${COORDINATOR_TARGET:-}" ]; then
	fail2 "$config sets BOTH COORDINATOR_TARGETS and COORDINATOR_TARGET. Keep the plural one —
       it is a list of TARGET=UNIT entries and holds the singular case as a list of one —
       and delete COORDINATOR_TARGET and COORDINATOR_UNIT."
fi
if [ -z "${COORDINATOR_TARGETS:-}" ]; then
	[ -n "${COORDINATOR_TARGET:-}" ] || fail2 "$config sets no COORDINATOR_TARGETS"
	COORDINATOR_TARGETS="$COORDINATOR_TARGET=${COORDINATOR_UNIT:-bacchus-coordinator}"
fi
[ -n "${NODE_TARGETS:-}" ] || fail2 "$config sets no NODE_TARGETS"

coord_count=0
for entry in $COORDINATOR_TARGETS; do
	coord_count=$((coord_count + 1))
done

# One signaling address per member, and the counts must AGREE. A pool member with no
# address is a member nothing probes, which is issue #248's finding — an unchecked box
# reported at the volume of a checked one — arriving in the one check that establishes a
# coordinator is serving the commit at all.
sig_count=0
for _s in ${COORDINATOR_SIGNALING:-}; do
	sig_count=$((sig_count + 1))
done
if [ "$verify" -eq 1 ]; then
	[ "$sig_count" -gt 0 ] || fail2 "$config sets no COORDINATOR_SIGNALING, so the capability probe has nothing to probe.
       Set one address per COORDINATOR_TARGETS entry, in the same order (each member's
       -addr, reachable from here), or pass --no-verify — but read what --no-verify costs:
       without the probe, 'deployed' rests on scp having exited 0."
	[ "$sig_count" -eq "$coord_count" ] || fail2 "$config names $coord_count coordinator(s) and $sig_count signaling address(es).
       There is no replication between pool members, so a member nothing probes is a member
       this run cannot say anything about — and it would be reported at the volume of one
       that passed. List one address per member, in the same order as COORDINATOR_TARGETS."
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

# Each entry of NODE_TARGETS and of COORDINATOR_TARGETS is TARGET=UNIT. `=` rather than
# `:` because an ssh target can be an IPv6 literal and a scp argument is already
# host:path. The two lists share the split and differ only in the default unit.
entry_target() { printf '%s' "${1%%=*}"; }
node_unit() {
	case "$1" in
	*=*) printf '%s' "${1#*=}" ;;
	*) printf 'bacchus-exit' ;;
	esac
}
coord_unit() {
	case "$1" in
	*=*) printf '%s' "${1#*=}" ;;
	*) printf 'bacchus-coordinator' ;;
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

# digest_stdin and digest_of print the sha256 of what they are given, using whichever of
# the two tools this machine has. The digest exists so a transfer that arrives truncated
# is refused BEFORE it replaces a working binary rather than after — and, for the
# artifacts below, so that a file this repository did not write is recognised as one.
digest_stdin() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 | cut -d' ' -f1
	else
		fail "neither sha256sum nor shasum is installed, and a transfer this script cannot
       verify is one it will not make"
	fi
}
digest_of() { digest_stdin <"$1"; }

# staged accumulates TARGET=ABSOLUTE_PATH for every temporary file that exists on a box,
# so a failure anywhere removes the debris everywhere rather than leaving a half-fleet
# holding an unexplained `.bacchus-pin.new` beside its live binary.
staged=""
# Invoked indirectly, through the EXIT trap below — shellcheck cannot follow a trap
# target to its definition and reports it as unreachable/unused, the same way
# bacchus-asn-drift-check.sh's cleanup is reported.
# shellcheck disable=SC2317,SC2329
cleanup_staged() {
	for _s in $staged; do
		remote "${_s%%=*}" "rm -f ${_s#*=}.bacchus-pin.new" >/dev/null 2>&1 || true
	done
	staged=""
}

# The locals are `_s`-prefixed because copy() and remote() assign _src/_dst/_target of
# their own and a shell function has no scope: sharing a name with a callee is a variable
# that changes under this one halfway through.
stage_to() {
	_starget="$1"
	_ssrc="$2"  # a local file
	_sdst="$3"  # its absolute destination on the box
	_smode="$4" # the mode the staged copy takes, so the rename lands it correct
	_swant=""
	[ "$dry" -eq 1 ] || _swant=$(digest_of "$_ssrc")

	log "staging ${_sdst##*/} -> $_starget"
	# The destination directory may not exist on a box that never ran deploy/install.sh
	# — /usr/local/lib/bacchus is the case — and scp into a missing directory fails with
	# a message about the file rather than the directory.
	remote "$_starget" "mkdir -p ${_sdst%/*}" >/dev/null ||
		fail "cannot create ${_sdst%/*} on $_starget. Nothing on any box was replaced."
	copy "$_ssrc" "$_starget" "$_sdst.bacchus-pin.new" ||
		fail "copying ${_sdst##*/} to $_starget failed. Nothing on any box was replaced; the fleet
       is still entirely on its previous build, which is a state that works."
	staged="$staged $_starget=$_sdst"

	if [ "$dry" -eq 1 ]; then
		printf 'DRY-RUN ssh %s sha256sum %s\n' "$_starget" "$_sdst.bacchus-pin.new"
		return 0
	fi
	_sgot=$(remote "$_starget" "sha256sum $_sdst.bacchus-pin.new" | cut -d' ' -f1) ||
		fail "cannot digest the staged ${_sdst##*/} on $_starget"
	[ "$_sgot" = "$_swant" ] ||
		fail "the copy of ${_sdst##*/} on $_starget digests $_sgot, not $_swant — the transfer is
       corrupt or truncated. Nothing was replaced anywhere."
	remote "$_starget" "chmod $_smode $_sdst.bacchus-pin.new" ||
		fail "cannot set mode $_smode on the staged ${_sdst##*/} on $_starget"
}

trap 'cleanup_staged; rm -rf "$stage"' EXIT

# ---------------------------------------------------------------------------
# The artifacts this repository is the SOLE AUTHOR of (issue #234, ADR-0074)
# ---------------------------------------------------------------------------
# Issue #222 shipped a supervisor-side rollback for a release that will not start at all,
# and merging it put it on no box: `bacchus-pin.sh` delivered binaries only, so the two
# files the handler needs reached a machine only when somebody did it by hand. ADR-0064
# §7 is why — and §7 is right about what it is about. It refuses to copy a unit that
# carries the operator's own configuration, because the live server units carry
# hand-added flags these templates do not and a copy would revert them silently.
#
# These two carry none. No EnvironmentFile=, no [Install], an ExecStart that is a fixed
# path, and `%i` supplying the only variable in either: there is nothing in them for a
# copy to revert, so §7's reason does not reach them and §7's rule did only because it
# was stated over a file extension. deploy/pin_test.go asserts the property directly, so
# a future edit that gave one of them a configurable surface fails the build rather than
# quietly widening what this script may write.
#
# Three fields, colon separated: the file in deploy/, its absolute destination, its mode.
#
# THE LIST LIVES HERE AND NOT IN testbed.env, and that is the decision rather than an
# omission. An operator who could add an entry could add bacchus-coordinator.service,
# which is precisely what must remain impossible — so what may be delivered is settled in
# review, per file, in this repository, and never per run, per fleet.
managed_artifacts="bacchus-update-rollback.sh:$LIBEXEC_DIR/bacchus-update-rollback:0755
bacchus-update-rollback@.service:$UNIT_DIR/bacchus-update-rollback@.service:0644"

# artifact_known writes every digest this repository has EVER had for deploy/$1, which is
# the only question that separates a copy somebody edited from one placed by an older
# commit — without keeping state on the box, which would be a second thing to get right.
#
# It fails CLOSED: a history that cannot answer (a shallow clone, a file whose past was
# rewritten) yields a short list, the live copy matches nothing in it, and the delivery is
# REFUSED and named rather than made. The refusal prints the one command that fixes it.
artifact_known() {
	_rel="deploy/$1"
	_out="$2"
	: >"$_out"
	git -C "$repo" log --format=%H -- "$_rel" 2>/dev/null | while read -r _c; do
		if git -C "$repo" show "$_c:$_rel" >"$stage/blob" 2>/dev/null; then
			digest_of "$stage/blob" >>"$_out"
		fi
	done
}

artifact_plan="$stage/artifact-plan"
: >"$artifact_plan"
artifact_refused=0
artifact_planned=0

# plan_artifact decides, for one file on one box, whether this run may replace it — and
# refuses rather than guessing. Absent, or a version this repository shipped, may be
# written. Anything else is somebody's edit, or a file from outside this repository, and
# is left exactly where it is.
plan_artifact() {
	_target="$1"
	_src="$2"
	_dst="$3"
	_mode="$4"
	_shipped="$5"
	_knownfile="$6"

	if [ "$dry" -eq 1 ]; then
		printf 'DRY-RUN would compare and deliver %s on %s\n' "$_dst" "$_target"
		printf '%s|%s|%s|%s\n' "$_target" "$_src" "$_dst" "$_mode" >>"$artifact_plan"
		artifact_planned=$((artifact_planned + 1))
		return 0
	fi

	# The remote pipeline ends in `cut`, so it exits 0 whether or not the file is there
	# and a non-zero status means the BOX did not answer. Those are different findings and
	# collapsing them would report an unreachable machine as one with a missing file — and
	# then plan a delivery to it.
	if ! _live=$("$SSH" "$_target" "sha256sum $_dst 2>/dev/null | cut -d' ' -f1" 2>/dev/null); then
		log "  $_target: could not be asked about $_dst — not checked, and nothing planned for it"
		return 0
	fi
	_live=$(printf '%s' "$_live" | tr -d '[:space:]')

	if [ -z "$_live" ]; then
		log "  $_target: $_dst is not on this box — delivering it"
	elif [ "$_live" = "$_shipped" ]; then
		return 0
	elif grep -qxF "$_live" "$_knownfile"; then
		log "  $_target: $_dst is an earlier version of this file — updating it"
	else
		artifact_refused=$((artifact_refused + 1))
		printf '%s: REFUSING to replace %s on %s.\n' "$self" "$_dst" "$_target" >&2
		printf '%s: It digests %s, which is not any version of deploy/%s this\n' "$self" "$_live" "$_src" >&2
		printf '%s: repository has ever held — so it was edited on the box, or it came from\n' "$self" >&2
		printf '%s: somewhere else. Nothing was written. This script replaces only what it can\n' "$self" >&2
		printf '%s: recognise, which is what keeps ADR-0064 §7 true: no configuration is ever\n' "$self" >&2
		printf '%s: reverted silently.\n' "$self" >&2
		printf '%s: Look at it, then either keep it or put this commit'"'"'s copy there by hand:\n' "$self" >&2
		printf '%s:   install -D -m %s deploy/%s %s\n' "$self" "$_mode" "$_src" "$_dst" >&2
		return 0
	fi
	printf '%s|%s|%s|%s\n' "$_target" "$_src" "$_dst" "$_mode" >>"$artifact_plan"
	artifact_planned=$((artifact_planned + 1))
}

all_targets=""
for entry in $NODE_TARGETS; do
	all_targets="$all_targets $(entry_target "$entry")"
done
for entry in $COORDINATOR_TARGETS; do
	all_targets="$all_targets $(entry_target "$entry")"
done

log "checking the rollback artifacts on every box (issue #234)"
for _a in $managed_artifacts; do
	_asrc=$(printf '%s' "$_a" | cut -d: -f1)
	_adst=$(printf '%s' "$_a" | cut -d: -f2)
	_amode=$(printf '%s' "$_a" | cut -d: -f3)
	_aship=""
	if [ "$dry" -eq 0 ]; then
		[ -r "$repo/deploy/$_asrc" ] ||
			fail "managed_artifacts names deploy/$_asrc and this checkout does not have it. Nothing
       was deployed. Either the file moved and the list above did not, or this is not a
       checkout of this repository."
		_aship=$(digest_of "$repo/deploy/$_asrc")
	fi
	_aknown="$stage/known-${_asrc##*/}"
	[ "$dry" -eq 1 ] || artifact_known "$_asrc" "$_aknown"
	for _box in $all_targets; do
		plan_artifact "$_box" "$_asrc" "$_adst" "$_amode" "$_aship" "$_aknown"
	done
done
if [ "$artifact_planned" -eq 0 ] && [ "$artifact_refused" -eq 0 ]; then
	log "  every box already carries both, unmodified"
fi

for entry in $NODE_TARGETS; do
	stage_to "$(entry_target "$entry")" "$stage/bacchus-node" "$BIN_DIR/bacchus-node" 0755
done
for entry in $COORDINATOR_TARGETS; do
	stage_to "$(entry_target "$entry")" "$stage/bacchus-coordinator" "$BIN_DIR/bacchus-coordinator" 0755
done
while IFS='|' read -r _t _src _dst _mode; do
	[ -n "$_t" ] || continue
	stage_to "$_t" "$repo/deploy/$_src" "$_dst" "$_mode"
done <"$artifact_plan"

log "every box holds a checked copy; nothing has been replaced yet"

# ---------------------------------------------------------------------------
# 5. Pass two — replace and restart, nodes first, coordinators last
# ---------------------------------------------------------------------------

install_on() {
	_target="$1"
	_unit="$2"
	_dst="$3"
	log "installing on $_target ($_unit)"
	# One command, so an interrupted connection cannot leave the unit stopped with the
	# old binary in place. The rename is within one directory, so it is atomic; the unit
	# is stopped first because a running text file cannot be written to (though it can be
	# renamed over), and because a service restarting into a half-swapped state is the
	# kind of thing that is only ever debugged once.
	remote "$_target" "systemctl stop $_unit && mv -f $_dst.bacchus-pin.new $_dst && systemctl start $_unit" ||
		fail "installing on $_target failed. This box may be stopped or on either binary — check
       it by hand (systemctl status $_unit) before re-running."
}

# The artifacts land BEFORE the units restart, and that ordering is worth a sentence: the
# handler is what a failing unit's OnFailure= reaches for, so a box that is about to be
# restarted onto a new binary should already have it. The rename is atomic and the handler
# is a script systemd executes, so replacing it under a copy that is running is safe — the
# running one keeps the inode it was started from.
#
# The staged name in /etc/systemd/system is `<unit>.bacchus-pin.new`, and systemd ignores
# it: a file there is a unit only if its extension is one systemd knows (.service,
# .socket, .timer, …), and `.new` is not one. So the staging window adds no half-parsed
# unit, and it closes at the rename either way.
reload_needed=""
while IFS='|' read -r _t _src _dst _mode; do
	[ -n "$_t" ] || continue
	log "delivering deploy/$_src -> $_dst on $_t (mode $_mode)"
	remote "$_t" "mv -f $_dst.bacchus-pin.new $_dst" ||
		fail "delivering $_dst on $_t failed. Check that box by hand before re-running."
	case "$_dst" in
	*.service) case " $reload_needed " in *" $_t "*) ;; *) reload_needed="$reload_needed $_t" ;; esac ;;
	esac
done <"$artifact_plan"

# A unit file that arrived is not a unit systemd knows about until it re-reads them. It is
# never enabled and never started — it is pulled in by OnFailure= and by nothing else, and
# enabling it would run a rollback at boot, which is the one moment nothing has failed yet.
for _t in $reload_needed; do
	log "systemctl daemon-reload on $_t"
	remote "$_t" "systemctl daemon-reload" ||
		log "  daemon-reload failed on $_t — the file is in place; run it by hand"
done

for entry in $NODE_TARGETS; do
	install_on "$(entry_target "$entry")" "$(node_unit "$entry")" "$BIN_DIR/bacchus-node"
done

# Last, deliberately, and every member of the pool after every node: see "THE ORDER".
for entry in $COORDINATOR_TARGETS; do
	install_on "$(entry_target "$entry")" "$(coord_unit "$entry")" "$BIN_DIR/bacchus-coordinator"
done
staged=""

log "every box is on $short"

if [ "$artifact_refused" -gt 0 ]; then
	printf '%s: WARNING: %d rollback artifact(s) were NOT replaced, because this run could not\n' "$self" "$artifact_refused" >&2
	printf '%s: recognise what is on the box. The binaries ARE pinned. Until those are settled the\n' "$self" >&2
	printf '%s: demotion rollback on those boxes is whatever is already there (issue #234).\n' "$self" >&2
fi

if [ "$dry" -eq 1 ]; then
	log "dry run — nothing was built, copied or restarted"
	exit 0
fi

# ---------------------------------------------------------------------------
# 6. Verify — by behaviour, not by having exited 0
# ---------------------------------------------------------------------------

if [ "$verify" -eq 0 ]; then
	log "verification skipped (--no-verify). 'Deployed' currently means 'scp exited 0'."
	log "Run deploy/bacchus-fleet-check.sh and cmd/coordinator-probe against EVERY pool member"
	log "before trusting these boxes."
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
#
# Per member, because there is no replication: a pool member's WorkingDirectory is a
# property of that box and one member resolving its revocation lists under / is a hole
# for every session that member assigns.
show_effective_unit() {
	_target="$1"
	_unit="$2"
	log "the effective unit configuration on $_target ($_unit)"
	if ! unit_cfg=$("$SSH" "$_target" "systemctl show -p ExecStart -p WorkingDirectory $_unit" 2>/dev/null); then
		log "  could not read it (not fatal) — check it by hand before trusting a result from this box"
		return 0
	fi
	printf '%s\n' "$unit_cfg" | sed 's/^/    /'
	wd=$(printf '%s\n' "$unit_cfg" | sed -n 's/^WorkingDirectory=//p')
	if [ -z "$wd" ] || [ "$wd" = "/" ]; then
		printf '%s: WARNING: %s has no WorkingDirectory=, so for a system service it is /.\n' "$self" "$_target" >&2
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
}

for entry in $COORDINATOR_TARGETS; do
	show_effective_unit "$(entry_target "$entry")" "$(coord_unit "$entry")"
done

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
#
# WITH A POOL THERE IS A THIRD ANSWER, AND IT IS THE INTERESTING ONE (issue #250). The
# ids are compared against EVERY member's window separately, because there is no
# coordinator-to-coordinator replication and a node can be registered with one member and
# missing from another. Present everywhere is fine; present nowhere is the absence above;
# present on SOME is an asymmetry — a finding of its own, and one a union or a total would
# erase. It does not resolve on its own either: the member that never saw the node will
# not assign it work, and a client that rotates to that member sees a smaller fleet than
# the one that is actually running.
node_ids="$stage/node-ids"
answered="$stage/answered"
id_unknown=0

read_node_ids() {
	: >"$node_ids"
	id_unknown=0
	for entry in $NODE_TARGETS; do
		_t=$(entry_target "$entry")
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
roll_asym=0

# roll_call compares the ids the boxes state with the ids EACH pool member saw. It NAMES
# what it finds, which is the whole point, and it is silent when it has nothing to add.
#
# `answered` holds the ordinal of every member whose window is evidence about who
# registered — the fleet check exited 0, 1 or 4. Exit 3 is a window with no
# `coordinator release` line in it and exit 2 is a usage error; both leave an empty ids
# file, and an ssh that failed would then read as every box being absent from that member
# — naming all of them and restarting the whole fleet because a journal could not be
# fetched. A member that did not answer is left out of the comparison rather than counted
# as a member that saw nothing, which is the same #248 rule one file over: not asked and
# asked-and-empty are different facts.
roll_call() {
	roll_absent=0
	roll_extra=0
	roll_asym=0
	[ -s "$node_ids" ] || return 0
	[ -s "$answered" ] || return 0
	_members=0
	while read -r _m; do
		[ -n "$_m" ] || continue
		_members=$((_members + 1))
	done <"$answered"

	while IFS='|' read -r _t _u _id; do
		[ -n "$_id" ] || continue
		_seen=0
		_missing=""
		while read -r _m; do
			[ -n "$_m" ] || continue
			if grep -qxF "$_id" "$stage/registered-ids.$_m" 2>/dev/null; then
				_seen=$((_seen + 1))
			else
				_missing="$_missing $_m"
			fi
		done <"$answered"

		if [ "$_seen" -eq "$_members" ]; then
			continue
		fi
		if [ "$_seen" -eq 0 ]; then
			if [ "$roll_absent" -eq 0 ]; then
				printf '%s: ROLL CALL: a box that IS deployed did not register with ANY pool member.\n' "$self" >&2
			fi
			roll_absent=$((roll_absent + 1))
			printf '%s:   %s (%s) registers as %s — that id is in no coordinator journal\n' "$self" "$_t" "$_u" "$_id" >&2
			continue
		fi
		if [ "$roll_asym" -eq 0 ]; then
			printf '%s: ROLL CALL: a box registered with SOME pool members and not others (issue #250).\n' "$self" >&2
		fi
		roll_asym=$((roll_asym + 1))
		printf '%s:   %s (%s) registers as %s — seen by %d of %d member(s), missing from coordinator(s):%s\n' \
			"$self" "$_t" "$_u" "$_id" "$_seen" "$_members" "$_missing" >&2
	done <"$node_ids"

	# Extras are counted over the UNION: a registration belonging to no deployed box is a
	# volunteer whichever member saw it, and counting it once per member would report one
	# volunteer as several.
	sort -u "$stage"/registered-ids.* 2>/dev/null >"$stage/registered-union" || : >"$stage/registered-union"
	while read -r _rid; do
		[ -n "$_rid" ] || continue
		cut -d'|' -f3 "$node_ids" | grep -qxF "$_rid" && continue
		roll_extra=$((roll_extra + 1))
	done <"$stage/registered-union"

	if [ "$roll_absent" -gt 0 ]; then
		printf '%s: This is NOT drift: every node that did register is reported above, on the build it\n' "$self" >&2
		printf '%s: is running. It is a box that is not answering — down, unable to reach any\n' "$self" >&2
		printf '%s: coordinator, or the state a deploy guarantees (issue #225: a node brought up against\n' "$self" >&2
		printf '%s: an OUTGOING coordinator never rebuilds that link, and every member restarts last by\n' "$self" >&2
		printf '%s: design). Start with: systemctl status on the box named above.\n' "$self" >&2
	fi
	if [ "$roll_asym" -gt 0 ]; then
		printf '%s: There is NO coordinator-to-coordinator replication, so this does not settle itself.\n' "$self" >&2
		printf '%s: The member that did not see that box will not assign it work, and a client that\n' "$self" >&2
		printf '%s: rotates to that member sees a smaller fleet than the one that is running. A node\n' "$self" >&2
		printf '%s: registers with every member it was given, so check -coordinators in that box'"'"'s unit\n' "$self" >&2
		printf '%s: first, then whether that member is reachable from it.\n' "$self" >&2
	fi
	if [ "$roll_extra" -gt 0 ] && [ "$id_unknown" -eq 0 ]; then
		log "$roll_extra registration(s) belong to no box in NODE_TARGETS — a volunteer serving as a"
		log "  relay or an exit (ADR-0053). Not a failure, and it no longer counts towards the floor:"
		log "  the check above compares numbers, this compares identities."
	fi
}

# Each member's journal is read ONCE per check and kept, because two different questions
# are asked of the same window: which build each node registered on
# (bacchus-fleet-check.sh) and which credential gates that coordinator actually came up
# with (bacchus-gate-check.sh, issue #249). Reading it twice would let the two answers
# describe two different windows — and after the containment restart below every member is
# read again, so the last read is the one both checks see.
#
# The label the checks are given is an ORDINAL, never the ssh target. Those two scripts
# print no hostname, which is what makes their output the half of a pin run that is safe
# to paste into a public issue; this script's output names ssh targets on every line and
# pairs the ordinals for whoever is running it.
fleet_drift=0
fleet_absent=0
fleet_unread=0

fleet_check_all() {
	fleet_drift=0
	fleet_absent=0
	fleet_unread=0
	: >"$answered"
	_n=0
	for _e in $COORDINATOR_TARGETS; do
		_n=$((_n + 1))
		_t=$(entry_target "$_e")
		_u=$(coord_unit "$_e")
		log "coordinator $_n of $coord_count — $_t ($_u)"
		"$SSH" "$_t" "journalctl -u $_u --since '-5 min' --no-pager" \
			>"$stage/coord-journal.$_n" 2>/dev/null || true
		: >"$stage/registered-ids.$_n"
		_rc=0
		sh "$script_dir/bacchus-fleet-check.sh" --label "$_n" --expect "$expected_nodes" \
			--ids-to "$stage/registered-ids.$_n" "$head" <"$stage/coord-journal.$_n" || _rc=$?
		case "$_rc" in
		0 | 1 | 4) printf '%s\n' "$_n" >>"$answered" ;;
		esac
		case "$_rc" in
		1) fleet_drift=$((fleet_drift + 1)) ;;
		esac
		case "$_rc" in
		4) fleet_absent=$((fleet_absent + 1)) ;;
		esac
		case "$_rc" in
		0 | 1 | 4) ;;
		*) fleet_unread=$((fleet_unread + 1)) ;;
		esac
	done
}

log "asking every node box what it registers as (issue #232)"
read_node_ids

log "reading every coordinator's journal for every node's build"
fleet_check_all
roll_call

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
# The trigger is any of three findings: a member's exit 4 (fewer ids than it expected),
# the roll call naming a deployed box missing from every member, or the roll call naming
# one that is missing from SOME. They are not the same condition — a volunteer holds a
# COUNT up while the roll call still sees the gap (issue #232), and an asymmetry is
# invisible to every count because each member's own total can be right (issue #250).
#
# The asymmetry belongs in this trigger because it is the SAME failure: a node holds one
# link per pool member, and #225 kills a link rather than a node. Losing one of two links
# is what a partial re-registration looks like from here, and the containment is the same
# restart. Drift (exit 1 anywhere) is never restarted away either way: a box on the wrong
# binary is still on the wrong binary afterwards, and restarting it destroys the evidence.
absent=0
if [ "$fleet_absent" -gt 0 ] || [ "$roll_absent" -gt 0 ] || [ "$roll_asym" -gt 0 ]; then
	absent=1
fi
if [ "$absent" -eq 1 ] && [ "$fleet_drift" -eq 0 ] && [ "$restart_absent" -eq 1 ]; then
	log "a node did not re-register with every member — restarting every node unit ONCE (issue #225 containment, not a fix)"
	for entry in $NODE_TARGETS; do
		_t=$(entry_target "$entry")
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
	log "re-reading every coordinator's journal"
	fleet_check_all
	roll_call
	if [ "$fleet_drift" -eq 0 ] && [ "$fleet_absent" -eq 0 ] && [ "$fleet_unread" -eq 0 ] &&
		[ "$roll_absent" -eq 0 ] && [ "$roll_asym" -eq 0 ]; then
		printf '%s: NOTE: the fleet is complete only AFTER a node restart this script had to do itself.\n' "$self" >&2
		printf '%s: That is issue #225 — a node whose coordinator went away never rebuilds that link — and\n' "$self" >&2
		printf '%s: every deploy reproduces it, because every member restarts last by design. Each member\n' "$self" >&2
		printf '%s: added to the pool is one more link in that state, so this gets MORE likely as the pool\n' "$self" >&2
		printf '%s: grows, not less.\n' "$self" >&2
	fi
fi

if [ "$fleet_drift" -gt 0 ] || [ "$fleet_absent" -gt 0 ] || [ "$fleet_unread" -gt 0 ] ||
	[ "$roll_absent" -gt 0 ] || [ "$roll_asym" -gt 0 ]; then
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
	compare_unit "$(entry_target "$entry")" "$(node_unit "$entry")"
done
for entry in $COORDINATOR_TARGETS; do
	unit_total=$((unit_total + 1))
	compare_unit "$(entry_target "$entry")" "$(coord_unit "$entry")"
done

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
#
# EVERY MEMBER IS HELD TO THE WHOLE LIST, and that is the pool's sharpest edge (issue
# #250). Gates fail open, a client rotates freely, and there is no replication — so one
# member started without -device-root-pubkey is not a partial deployment of the gate, it
# is a way around it. "The fleet enforces X" is only true when every member does.
log "reading each coordinator's credential gates from the journal above"
gate_bad=0
_n=0
for entry in $COORDINATOR_TARGETS; do
	_n=$((_n + 1))
	gate_rc=0
	if [ -n "${COORDINATOR_GATES:-}" ]; then
		sh "$script_dir/bacchus-gate-check.sh" --label "$_n" --require "$COORDINATOR_GATES" \
			"$stage/coord-journal.$_n" || gate_rc=$?
	else
		sh "$script_dir/bacchus-gate-check.sh" --label "$_n" "$stage/coord-journal.$_n" || gate_rc=$?
	fi
	if [ "$gate_rc" -ne 0 ] && [ -n "${COORDINATOR_GATES:-}" ]; then
		gate_bad=$((gate_bad + 1))
		printf '%s: coordinator %d (%s) is not enforcing every declared gate.\n' "$self" "$_n" "$(entry_target "$entry")" >&2
	fi
done
if [ "$gate_bad" -gt 0 ]; then
	printf '%s: ERROR: this deployment declares COORDINATOR_GATES="%s" and %d member(s) are not\n' "$self" "${COORDINATOR_GATES:-}" "$gate_bad" >&2
	printf '%s: enforcing all of them. A gate is only as on as the WEAKEST pool member, because a\n' "$self" >&2
	printf '%s: client rotates and there is no replication. Do not run a test that expects a refusal\n' "$self" >&2
	printf '%s: against this fleet: it would pass without refusing anything, which closes a card on\n' "$self" >&2
	printf '%s: evidence that does not exist.\n' "$self" >&2
	rc=3
fi

# One probe per member, and each is its own verdict. A pool where one member answers the
# shaped rendezvous hop and another does not is exactly issue #212 step 5's fixture, and
# it is also what a half-finished deploy looks like — so it is reported per address and
# never summed.
_n=0
for _addr in $COORDINATOR_SIGNALING; do
	_n=$((_n + 1))
	log "probing coordinator $_n of $coord_count for the capability this commit carries"
	if ! "$probe" -addr "$_addr"; then
		printf '%s: coordinator %d (%s) did not confirm it.\n' "$self" "$_n" "$_addr" >&2
		rc=3
	fi
done

if [ "$rc" -ne 0 ]; then
	printf '%s: ERROR: the binaries were deployed and the checks above did NOT confirm the result.\n' "$self" >&2
	printf '%s: Do not run anything on these boxes that assumes the pin held.\n' "$self" >&2
	exit "$rc"
fi

log "the deployment is pinned to $head and every coordinator serves the capability that commit carries"
