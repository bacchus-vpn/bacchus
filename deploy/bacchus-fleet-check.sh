#!/bin/sh
# Answer "is every box on the commit I pinned?" from the coordinator's journal alone,
# without reaching a single node (issue #205, ADR-0064).
#
# usage: bacchus-fleet-check.sh [--expect N] REVISION [JOURNAL_FILE]
#        journalctl -u bacchus-coordinator --since -10min | bacchus-fleet-check.sh REVISION
#
# REVISION is the commit the fleet was pinned to — a git sha of at least 7 characters.
# `git rev-parse HEAD` is the safe thing to hand it; see "The abbreviation trap" below.
#
# ---------------------------------------------------------------------------
# WHAT COUNTS AS A NODE, AND WHY THE FLOOR HAS TO BE GIVEN (issue #224)
# ---------------------------------------------------------------------------
# A box serving two roles prints TWO `registered:` lines carrying ONE node id, and
# `-role exit,relay` and `-volunteer-relay -volunteer-exit` both produce that. This
# counts distinct IDS. Keying on `role id` instead — which this did until #224 — counts
# a dual-role box twice, and the first real run of the pin printed `3 node(s)
# registered` and `the fleet is pinned` from three rows carrying two ids, with one of
# three boxes dead.
#
# Above zero there was no floor at all, because nothing told this script how many boxes
# to expect. `--expect N` is that number: `bacchus-pin.sh` passes the size of its own
# NODE_TARGETS, and by hand it is however many node processes you deploy. Without it the
# only floor is still `nodes == 0`, which is the state this was already good at.
#
# Two things it is honest about rather than quiet about:
#
# * `--expect` takes a COUNT, never a host list, and this script prints no hostname
#   ever. Its output is the pasteable half of a pin run — it goes into issues, and
#   bacchus-pin.sh's does not, because that one names every ssh target on every line.
#   The journal names node ids and a host list names ssh targets; nothing here maps one
#   to the other, so a missing box is reported as a count and not as a name. Naming it
#   would need a roll call this cannot make from a journal.
# * MORE ids than expected is NOT a failure and is only noted. A volunteer client serves
#   as a relay or an exit (ADR-0053) and registers exactly like a deployed node, without
#   being in anybody's host list. The consequence to know: a volunteer present while a
#   deployed box is absent can hold the count up, so `--expect` is a FLOOR and not a roll
#   call, and it is the strongest statement a journal supports.
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
	printf 'usage: %s [--expect N] REVISION [JOURNAL_FILE]\n' "${0##*/}" >&2
	printf '       journalctl -u bacchus-coordinator --since -10min | %s REVISION\n' "${0##*/}" >&2
	printf '\nREVISION is the commit the fleet was pinned to (>= 7 hex characters).\n' >&2
	# %s rather than a literal: a printf format beginning with `-` is undefined in
	# POSIX sh, because printf reads it as an option (shellcheck SC3045).
	printf '%s\n' '--expect N   how many distinct node ids should appear (a dual-role box is ONE).' >&2
	printf '%s\n' '             A count, never a host list: nothing here prints a hostname.' >&2
	printf 'Exit: 0 pinned · 1 drift · 2 usage · 3 no coordinator start in this window\n' >&2
	printf '      4 a node that should be there did not register in this window\n' >&2
}

expect=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	--expect)
		[ "$#" -ge 2 ] || {
			printf 'bacchus-fleet-check: --expect needs a value\n' >&2
			exit 2
		}
		expect="$2"
		shift 2
		;;
	--)
		shift
		break
		;;
	-*)
		printf 'bacchus-fleet-check: unknown option: %s\n' "$1" >&2
		usage
		exit 2
		;;
	*)
		break
		;;
	esac
done

case "$expect" in
'' | *[!0-9]*)
	printf 'bacchus-fleet-check: --expect takes a count of node processes, not %s.\n' "$expect" >&2
	printf '  It is deliberately not a host list: this script prints no hostname, which is what\n' >&2
	printf '  makes its output the half of a pin run that is safe to paste into an issue.\n' >&2
	exit 2
	;;
esac

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	printf 'bacchus-fleet-check: expected REVISION and at most one file, got %s argument(s)\n' "$#" >&2
	usage
	exit 2
fi

want=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
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

# A named file becomes this shell's stdin, so the awk below always reads one place.
if [ "$#" -eq 2 ] && [ "$2" != "-" ]; then
	[ -r "$2" ] || {
		printf 'bacchus-fleet-check: cannot read %s\n' "$2" >&2
		exit 2
	}
	exec <"$2"
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
#
# The program is single quoted so awk's own $0/$1 reach awk rather than being expanded
# by the shell first; want is passed with -v, which is the reason nothing here needs to
# interpolate at all.
# shellcheck disable=SC2016
awk -v want="$want" -v expect="$expect" '
	# The comparison is a PREFIX one: `git rev-parse --short` produces 7-ish characters,
	# the wire carries 12, and a full sha is 40, so three correct spellings of one commit
	# would fail an equality test. want is already lowered and capped at 12 by the shell.
	function matches(actual) {
		return substr(tolower(actual), 1, length(want)) == want
	}

	# pad right-pads to a width computed from the rows themselves. A fixed column
	# was fine while the first field was `exit n7`; an exit node id IS its X25519
	# public key (64 hex characters), so the width has to come from the data.
	# Written out rather than using printf "%-*s", which not every awk accepts.
	function pad(s, w,   out) {
		out = s
		while (length(out) < w) out = out " "
		return out
	}

	# A coordinator startup line. Everything before it describes a coordinator that is
	# no longer running and nodes whose registrations it no longer holds, so the table
	# is emptied here rather than merged.
	/coordinator release / {
		split("", build)
		split("", order)
		split("", roles)
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
	#
	# Keyed on the ID ALONE. One box serving two roles is one node running one
	# binary, and it prints one line per role; keying on `role id` counted it twice
	# and made the only cardinality statement this produces — how many — untrue in
	# the direction that hides a dead box (issue #224). The roles are collected
	# alongside so the row still says what the box is doing.
	started && /(relay|exit) registered: / {
		if (!match($0, /(relay|exit) registered: [^ ]+/)) next
		split(substr($0, RSTART, RLENGTH), p, " ")
		role = p[1]
		id = p[3]
		b = "unknown"
		if (match($0, /build=[^ ]+/)) b = substr($0, RSTART + 6, RLENGTH - 6)
		if (!(id in build)) {
			order[nodes++] = id
			roles[id] = role
		} else if (index("," roles[id] ",", "," role ",") == 0) {
			roles[id] = roles[id] "," role
		}
		# Last value wins. Both role lines of one process carry the same build, so
		# this only differs from the first when a node was replaced mid-window —
		# in which case the later line is the one describing what is running.
		build[id] = b
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

		# One column width for every row, taken from the rows themselves.
		width = 12
		for (i = 0; i < nodes; i++) {
			k = roles[order[i]] " " order[i]
			if (length(k) > width) width = length(k)
		}
		indent = pad("", width + 1)

		bad = 0
		if (coord == "unknown") {
			printf "%s build UNRECORDED  — this coordinator was built without VCS data (a worktree, or a\n", pad("coordinator", width)
			printf "%ssource tarball). Its own commit cannot be established from here.\n", indent
			bad = 1
		} else if (coorddirty) {
			printf "%s %-14s DIRTY — built from a tree with uncommitted changes, so it is not at any\n", pad("coordinator", width), coord
			printf "%snamed commit. Rebuild from a clean checkout.\n", indent
			bad = 1
		} else if (!matches(coord)) {
			printf "%s %-14s MISMATCH — wanted %s\n", pad("coordinator", width), coord, want
			bad = 1
		} else {
			printf "%s %-14s ok\n", pad("coordinator", width), coord
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
			id = order[i]
			b = build[id]
			key = pad(roles[id] " " id, width)
			if (b == "unknown") {
				printf "%s build UNRECORDED — this node was built without VCS data (a `git worktree` build\n", key
				printf "%srecords none). Its commit cannot be established, which is a failed pin.\n", indent
				bad = 1
			} else if (b ~ /-dirty$/) {
				printf "%s %-14s DIRTY — built from a tree with uncommitted changes.\n", key, b
				bad = 1
			} else if (!matches(b)) {
				printf "%s %-14s MISMATCH — wanted %s\n", key, b, want
				bad = 1
			} else {
				printf "%s %-14s ok\n", key, b
			}
		}

		# Absence is a DIFFERENT finding from drift, so it is counted separately and
		# exits differently (issue #224). Drift means a box is serving the wrong
		# binary, which is issue #114 and a reason to distrust every result from the
		# fleet. Absence means a box is not there — possibly for a reason the pin did
		# not cause, since this runs seconds after the coordinator restarts. Both are
		# non-zero; neither is the other.
		missing = 0
		if (expect > 0 && nodes < expect) missing = expect - nodes

		if (expect > 0) {
			printf "\n%d of %d expected node(s) registered since the coordinator started.\n", nodes, expect
			if (nodes > expect) {
				printf "  (More than expected, which is not a failure: a volunteer client serves as a relay\n"
				printf "   or an exit and registers exactly like a deployed node, without being in any host\n"
				printf "   list. It does mean the count is a floor — a volunteer can hold it up while a\n"
				printf "   deployed box is absent.)\n"
			}
		} else {
			printf "\n%d node(s) registered since the coordinator started.\n", nodes
			printf "  No --expect given, so the only floor is that SOMETHING registered: a box that never\n"
			printf "  came back cannot be seen from here. Pass --expect with the number of node processes.\n"
		}

		if (bad) {
			fflush()
			print "" > "/dev/stderr"
			print "bacchus-fleet-check: the fleet is NOT on one commit. A node on a different build" > "/dev/stderr"
			print "  registers, heartbeats and is assigned work exactly as a current one does, and then" > "/dev/stderr"
			print "  drops every session it is given, with every log involved reporting health (issue" > "/dev/stderr"
			print "  #114). Re-run deploy/bacchus-pin.sh before trusting any result from these boxes." > "/dev/stderr"
		}
		if (missing > 0) {
			fflush()
			print "" > "/dev/stderr"
			printf "bacchus-fleet-check: %d of %d expected node(s) did NOT register in this window.\n", missing, expect > "/dev/stderr"
			print "  This is not drift: every node that DID register is accounted for above. It is a box" > "/dev/stderr"
			print "  that is not there — down, unable to reach this coordinator, or still coming up when" > "/dev/stderr"
			print "  the window was captured, which is possible because a pin reads it about 20s after" > "/dev/stderr"
			print "  restarting the coordinator." > "/dev/stderr"
			print "  It can also be a node that came up, registered with the OUTGOING coordinator and never" > "/dev/stderr"
			print "  rebuilt the link when that one went away (issue #225) — the state a deploy guarantees," > "/dev/stderr"
			print "  since the coordinator restarts last. Which box it is cannot be answered from here: this" > "/dev/stderr"
			print "  journal names node ids and your host list names ssh targets. Check each unit." > "/dev/stderr"
		}
		if (bad) exit 1
		if (missing > 0) exit 4

		printf "the fleet is pinned to %s\n", want
		exit 0
	}
'
