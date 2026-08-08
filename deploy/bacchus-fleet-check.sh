#!/bin/sh
# Answer "is every box on the commit I pinned?" from the coordinator's journal alone,
# without reaching a single node (issue #205, ADR-0064).
#
# usage: bacchus-fleet-check.sh REVISION [JOURNAL_FILE]
#        journalctl -u bacchus-coordinator --since -10min | bacchus-fleet-check.sh REVISION
#
# REVISION is the commit the fleet was pinned to — a git sha of at least 7 characters.
# `git rev-parse HEAD` is the safe thing to hand it; see "The abbreviation trap" below.
#
# Why this can work at all: until issue #182 a node's build revision was on no wire, so
# a coordinator logged `release=0.1.0` for a node of any age and pinning the nodes meant
# an ssh per box. Nodes now self-stamp their VCS revision on every register
# (core/engine.go, nodeBuildRevision) and the coordinator prints it as `build=` on both
# role lines, so one journal on one host names every node's binary.
#
# ---------------------------------------------------------------------------
# THE ORDERING THIS DEPENDS ON, WHICH IS NOT OPTIONAL
# ---------------------------------------------------------------------------
# `build=` appears on the `registered:` line, and that line fires ONLY for a node the
# coordinator does not already have in its registry. A node restarts in about a second
# and its registry entry survives 35s (cmd/coordinator's ttl), so a rolling redeploy can
# replace every binary in the fleet without printing `registered` once — and a check that
# simply grepped the journal would then read values from BEFORE the deploy and report
# them with total confidence. That is issue #205's own failure mode, one level up.
#
# What makes the reading fresh is restarting the COORDINATOR LAST. That empties its
# registry, so every node re-registers as new within one 10s register interval and prints
# a `registered:` line carrying the binary it is running right now.
#
# This script enforces the ordering rather than trusting it: it finds the LAST
# `coordinator release` startup line in the input and ignores everything before it. So a
# journal window that happens to include older registrations cannot contribute a stale
# answer, and a window with no coordinator start in it is refused outright instead of
# being read as a pass.
#
# ---------------------------------------------------------------------------
# THE ABBREVIATION TRAP
# ---------------------------------------------------------------------------
# The wire form is the first 12 hex characters of the revision (renderBuildRevision),
# plus `-dirty` when the tree had uncommitted changes at build time. `git rev-parse
# --short HEAD` gives 7 or so, and its length depends on the repository's object count,
# so comparing the two as strings fails on a correct deployment. Both sides are lowered
# and truncated to 12 here, and REVISION may be given at any length from 7 up.
#
# ---------------------------------------------------------------------------
# WHAT `build=unknown` MEANS, AND WHY IT IS A FAILURE HERE
# ---------------------------------------------------------------------------
# The Go toolchain records VCS data only when it builds from a checkout with a real
# `.git` DIRECTORY. A build made in a `git worktree` — how this project's development
# branches are built — records none, and the node then reports `build=unknown`. That is
# the ordinary case for a development build and it is a FAILED PIN here: a fleet whose
# revision cannot be established is exactly the state this check exists to end. Build the
# fleet's binaries from a clone (deploy/bacchus-pin.sh refuses to do otherwise).
#
# Nothing here is host-specific and nothing here is secret: it reads text on stdin.

set -eu

usage() {
	printf 'usage: %s REVISION [JOURNAL_FILE]\n' "${0##*/}" >&2
	printf '       journalctl -u bacchus-coordinator --since -10min | %s REVISION\n' "${0##*/}" >&2
	printf '\nREVISION is the commit the fleet was pinned to (>= 7 hex characters).\n' >&2
	printf 'Exit: 0 pinned · 1 drift · 2 usage · 3 no coordinator start in this window · 4 no node registered since it\n' >&2
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	printf 'bacchus-fleet-check: expected REVISION and at most one file, got %s argument(s)\n' "$#" >&2
	usage
	exit 2
fi

want=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
case "$want" in
*[!0-9a-f]*)
	printf 'bacchus-fleet-check: %s is not a hex revision\n' "$1" >&2
	exit 2
	;;
esac
if [ "${#want}" -lt 7 ]; then
	printf 'bacchus-fleet-check: revision %s is shorter than 7 characters — too short to identify a commit\n' "$1" >&2
	exit 2
fi
# Truncated to the wire's own width. Done here rather than in awk so the comparison is
# one rule in one place, and so a caller passing a full 40-character sha (the safe thing
# to pass) is not quietly compared against 12 characters of it by accident.
want=$(printf '%.12s' "$want")

if [ "$#" -eq 2 ] && [ "$2" != "-" ] && [ ! -r "$2" ]; then
	printf 'bacchus-fleet-check: cannot read %s\n' "$2" >&2
	exit 2
fi

# The whole reading happens in one awk pass. Roles and ids are extracted by pattern
# rather than by field position, because the input is normally journalctl output, whose
# per-line prefix (timestamp, host, unit[pid]:) is not fixed-width and is absent when the
# input is a plain log file.
#
# Note the two renderings of one fact, which is a trap rather than a detail: the
# coordinator writes its OWN dirty flag as `(revision abc, uncommitted changes)`
# (describeBuild), while a node's wire value carries `-dirty` (renderBuildRevision).
# Both are handled, separately, because a pattern written for one silently reports the
# other as clean.
awk -v want="$want" '
	# The comparison is a PREFIX one: `git rev-parse --short` produces 7-ish characters,
	# the wire carries 12, and a full sha is 40, so three correct spellings of one commit
	# would fail an equality test. want is already lowered and capped at 12 by the shell.
	function matches(actual) {
		return substr(tolower(actual), 1, length(want)) == want
	}

	# A coordinator startup line. Everything before it describes a coordinator that is
	# no longer running and nodes whose registrations it no longer holds, so the table
	# is emptied here rather than merged.
	/coordinator release / {
		split("", build)
		split("", order)
		nodes = 0
		started = 1
		coord = "unknown"
		coorddirty = 0
		if (match($0, /\(revision [0-9a-fA-F]+/)) {
			coord = substr($0, RSTART + 10, RLENGTH - 10)
			if ($0 ~ /\(revision [0-9a-fA-F]+, uncommitted changes\)/) coorddirty = 1
		}
		next
	}

	# `<role> registered: <id> ...  build=<rev>` on both role lines.
	started && /(relay|exit) registered: / {
		if (!match($0, /(relay|exit) registered: [^ ]+/)) next
		split(substr($0, RSTART, RLENGTH), p, " ")
		key = p[1] " " p[3]
		b = "unknown"
		if (match($0, /build=[^ ]+/)) b = substr($0, RSTART + 6, RLENGTH - 6)
		if (!(key in build)) { order[nodes++] = key }
		build[key] = b
		next
	}

	END {
		if (!started) {
			fflush()
			print "bacchus-fleet-check: no `coordinator release` startup line in this input." > "/dev/stderr"
			print "  Without one there is no way to tell a registration made AFTER the pin from one made" > "/dev/stderr"
			print "  before it, and the pre-pin values look exactly as convincing. Widen the window" > "/dev/stderr"
			print "  (journalctl --since) so it covers the coordinator restart, and re-read." > "/dev/stderr"
			exit 3
		}

		bad = 0
		if (coord == "unknown") {
			printf "coordinator  build UNRECORDED  — this coordinator was built without VCS data (a worktree, or a\n"
			printf "             source tarball). Its own commit cannot be established from here.\n"
			bad = 1
		} else if (coorddirty) {
			printf "coordinator  %-14s DIRTY — built from a tree with uncommitted changes, so it is not at any\n", coord
			printf "             named commit. Rebuild from a clean checkout.\n"
			bad = 1
		} else if (!matches(coord)) {
			printf "coordinator  %-14s MISMATCH — wanted %s\n", coord, want
			bad = 1
		} else {
			printf "coordinator  %-14s ok\n", coord
		}

		if (nodes == 0) {
			fflush()
			print "" > "/dev/stderr"
			print "bacchus-fleet-check: the coordinator started and NO node has registered since." > "/dev/stderr"
			print "  A live node re-registers every 10s, so after a restart this window should name every" > "/dev/stderr"
			print "  one of them within seconds. Either the nodes are down, or they cannot reach this" > "/dev/stderr"
			print "  coordinator, or this window was captured before they got a chance." > "/dev/stderr"
			exit 4
		}

		for (i = 0; i < nodes; i++) {
			key = order[i]
			b = build[key]
			if (b == "unknown") {
				printf "%-12s build UNRECORDED — this node was built without VCS data (a `git worktree` build\n", key
				printf "             records none). Its commit cannot be established, which is a failed pin.\n"
				bad = 1
			} else if (b ~ /-dirty$/) {
				printf "%-12s %-14s DIRTY — built from a tree with uncommitted changes.\n", key, b
				bad = 1
			} else if (!matches(b)) {
				printf "%-12s %-14s MISMATCH — wanted %s\n", key, b, want
				bad = 1
			} else {
				printf "%-12s %-14s ok\n", key, b
			}
		}

		printf "\n%d node(s) registered since the coordinator started.\n", nodes
		if (bad) {
			fflush()
			print "" > "/dev/stderr"
			print "bacchus-fleet-check: the fleet is NOT on one commit. A node on a different build" > "/dev/stderr"
			print "  registers, heartbeats and is assigned work exactly as a current one does, and then" > "/dev/stderr"
			print "  drops every session it is given, with every log involved reporting health (issue" > "/dev/stderr"
			print "  #114). Re-run deploy/bacchus-pin.sh before trusting any result from these boxes." > "/dev/stderr"
			exit 1
		}
		printf "the fleet is pinned to %s\n", want
		exit 0
	}
' ${2+"$2"}
