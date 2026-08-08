#!/bin/sh
# Answer "what node id does this box register as?" from the node's OWN journal
# (issue #232, ADR-0064).
#
# usage: bacchus-node-id.sh [JOURNAL_FILE]
#        ssh <node-box> "journalctl -u bacchus-exit --since '-5 min' --no-pager" |
#          bacchus-node-id.sh
#
# It prints ONE line — the node id — and nothing else, so a caller can capture it in
# a variable. Everything explanatory goes to stderr.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS: TWO NAMESPACES THAT NEVER MET
# ---------------------------------------------------------------------------
# The coordinator's journal names node IDS. deploy/testbed.env's NODE_TARGETS names
# SSH TARGETS. Nothing mapped one to the other, so deploy/bacchus-fleet-check.sh could
# only ever report a missing box as a COUNT — `2 of 3 expected node(s) registered` —
# and the operator then ran `systemctl status` on every box to find out which one it
# was. That is the per-box work ADR-0064 exists to end, paid once per failed pin.
#
# Worse than the missing name: a volunteer client serves as a relay or an exit
# (ADR-0053) and registers exactly like a deployed node, without being in anybody's
# host list. So the count is a FLOOR and not a roll call — a volunteer present while
# a deployed box is absent holds it up and the check passes. Only a pairing removes
# both limits, and a pairing needs one end of it to come from the box.
#
# ---------------------------------------------------------------------------
# WHAT IT READS, AND WHY IT IS NOT A NEW LOG LINE
# ---------------------------------------------------------------------------
# Issue #232 was filed reading that "cmd/node logs nothing at startup that names the
# id". That is true of core/engine.go's ID() method, which is indeed never called, and
# false of the id itself. core.Engine.Start emits, through e.emit:
#
#     exit <id> (<country>) advertising <host:port> + direct WebRTC
#     relay <id> online
#
# and e.emit falls back to log.Println whenever Config.OnEvent is nil. clients/fyne
# sets OnEvent; cmd/node does not. So on a node box those two lines go to stderr, and
# systemd puts stderr in the journal: every deployed exit and relay has been naming
# its own id at every start all along. Confirmed by running the real binary, and the
# contract is held by TestTheNodeStartupLineCarriesTheIdThisScriptReads, which builds
# cmd/node, runs it, and feeds its actual output through this script.
#
# That is why nothing in cmd/ or core/ changes for this: the line to parse already
# ships. It also means the two shapes above are a CONTRACT between Go and shell, which
# is the pair that drifts silently (ADR-0069 §4 makes the same point about the update
# marker), so they are matched whole — including the trailing `+ direct WebRTC` and
# `online` — rather than by a loose `exit <hex>` pattern that other log lines also
# satisfy. core/pool.go prints `exit <id> in <country> did not carry traffic` about a
# DIFFERENT node's id on a box that is also a client, and a loose pattern would report
# that as this box's identity.
#
# ---------------------------------------------------------------------------
# ONE PROCESS, ONE ID — SO THE LAST MATCH WINS
# ---------------------------------------------------------------------------
# An engine has exactly one id, and a dual-role node prints both lines carrying it. A
# window can still hold more than one id, because it can hold more than one START:
# deploy/bacchus-pin.sh restarts a node that did not re-register (issue #225
# containment) and reads this again afterwards. The id from the PREVIOUS start is not
# wrong, it is stale — and for a relay it is a different value, since a relay without
# -relay-ingress takes a fresh random id at every start (core/engine.go, randID). An
# exit's id is its X25519 public key and does not move.
#
# So the last matching line in the input wins, and the caller is expected to hand this
# a window that covers the start it cares about.
#
# ---------------------------------------------------------------------------
# A NODE ID IS PUBLIC, AND THIS SCRIPT STILL PRINTS NO HOSTNAME
# ---------------------------------------------------------------------------
# The id is in the coordinator-signed directory and every client holds it, so printing
# one discloses nothing. What this deliberately does NOT do is learn where it came
# from: it reads text on stdin, exactly as bacchus-fleet-check.sh does, and the ssh
# target stays with the caller. deploy/bacchus-pin.sh holds the map.

set -eu

self="${0##*/}"

usage() {
	printf 'usage: %s [JOURNAL_FILE]\n' "$self" >&2
	printf '       ssh <node-box> "journalctl -u bacchus-exit --since '\''-5 min'\'' --no-pager" | %s\n' "$self" >&2
	printf '\nPrints the node id this box registers as, from the node'\''s own journal.\n' >&2
	printf 'Exit: 0 found · 2 usage · 4 no node id in this window\n' >&2
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
-?*)
	printf '%s: unknown option: %s\n' "$self" "$1" >&2
	usage
	exit 2
	;;
esac

if [ "$#" -gt 1 ]; then
	printf '%s: expected at most one file, got %s arguments\n' "$self" "$#" >&2
	usage
	exit 2
fi

if [ "$#" -eq 1 ] && [ "$1" != "-" ]; then
	[ -r "$1" ] || {
		printf '%s: cannot read %s\n' "$self" "$1" >&2
		exit 2
	}
	exec <"$1"
fi

# The program is single quoted so awk's own $0 reaches awk rather than the shell.
# shellcheck disable=SC2016
awk '
	# The two lines core.Engine.Start emits, matched whole. The trailing anchor is
	# the point: `exit [0-9a-f]+` on its own also matches core/pool.go reporting on
	# an exit this client was ASSIGNED, which is another node id entirely.
	{
		if (match($0, /exit [0-9a-f]+ \([^)]*\) advertising [^ ]+ \+ direct WebRTC$/) ||
		    match($0, /relay [0-9a-f]+ online$/)) {
			split(substr($0, RSTART, RLENGTH), p, " ")
			id = p[2]
		}
	}

	END {
		if (id == "") {
			print "bacchus-node-id: this journal window names no node id." > "/dev/stderr"
			print "  A node states it at startup, once per role — `exit <id> (<country>) advertising" > "/dev/stderr"
			print "  <host:port> + direct WebRTC` and `relay <id> online`. Nothing here matched either." > "/dev/stderr"
			print "  Either the window does not cover a start (widen journalctl --since), or this unit" > "/dev/stderr"
			print "  runs no serving role, or the unit is not up at all. Note that a CLIENT-only node" > "/dev/stderr"
			print "  prints neither line and registers with nobody, so it is correctly invisible here." > "/dev/stderr"
			exit 4
		}
		print id
	}
'
