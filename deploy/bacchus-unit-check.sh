#!/bin/sh
# Report the difference between a unit file this repository SHIPS and the unit a box
# is actually running — and copy nothing (issue #234, ADR-0064 §7).
#
# usage: bacchus-unit-check.sh TEMPLATE [LIVE_FILE]
#        ssh <box> "systemctl cat bacchus-exit" | bacchus-unit-check.sh deploy/bacchus-exit.service
#
# ---------------------------------------------------------------------------
# WHY A COMPARISON AND NOT A COPY
# ---------------------------------------------------------------------------
# deploy/bacchus-pin.sh never copies a .service file and there is no flag that makes
# it, because the live units carry hand-added flags the templates here do not: copying
# one silently reverts a working configuration and the deployment then behaves
# differently for reasons no diff shows (ADR-0064 §7). That refusal is correct and
# stays.
#
# What was missing is that nothing COMPARED them either, in either direction. Issue
# #222 shipped a supervisor-side rollback wired by `OnFailure=` lines added to
# deploy/bacchus-exit.service and deploy/bacchus-coordinator.service, and merging it
# put it on no box: the mechanism was in the repository, absent from the fleet, and
# every pin run reported a pinned fleet (issue #234). That is issue #205's finding in
# a different place — the repository holds a mechanism the fleet does not have, and
# nothing reports the difference.
#
# So: a directive the template ships and the live unit lacks is the finding. The
# reverse — a directive only the box has — is printed too, because "invisible in both
# directions" was the complaint, but it is expected rather than wrong: it is the
# hand-editing the no-copy rule exists to protect.
#
# ---------------------------------------------------------------------------
# WHAT IT COMPARES, AND WHAT IT DELIBERATELY DOES NOT
# ---------------------------------------------------------------------------
# Directives, as `[Section] Key=Value`, with comments, blank lines, ordering and line
# continuations normalised away. Not a textual diff: `systemctl cat` prints a `#
# /etc/systemd/system/…` provenance header and any drop-ins, the template carries a
# long comment block, and a diff of those two would be noise an operator learns to
# scroll past — which is the same as not having the check.
#
# `ExecStart=` will essentially always differ, and that is the point of the no-copy
# rule rather than a fault. It is reported as a difference and never as missing.
#
# Two limits worth stating rather than discovering:
#
# * A drop-in that RESETS a list directive by assigning it empty (`ExecStart=` on its
#   own, then a new one) is read here as two values for one key, not as a reset. The
#   report then says the directives differ, which is true and is the direction that
#   errs towards telling you something.
# * `systemctl cat` renders the unit files, not the manager's resolved view, so a
#   directive dropped because of a parse error still appears here. `systemctl show`
#   answers that question and cannot answer this one, because it never reports what
#   the unit did NOT say.
#
# ---------------------------------------------------------------------------
# THIS OUTPUT IS NOT THE PASTEABLE HALF
# ---------------------------------------------------------------------------
# A live `ExecStart=` carries the operator's real advertise address. Like
# deploy/bacchus-pin.sh's own output, and unlike deploy/bacchus-fleet-check.sh's, what
# this prints is for the person running it.

set -eu

self="${0##*/}"

usage() {
	printf 'usage: %s TEMPLATE [LIVE_FILE]\n' "$self" >&2
	printf '       ssh <box> "systemctl cat bacchus-exit" | %s deploy/bacchus-exit.service\n' "$self" >&2
	printf '\nCompares the shipped unit against the running one. It copies nothing, ever.\n' >&2
	printf 'Exit: 0 the live unit carries every shipped directive · 2 usage\n' >&2
	printf '      3 the live unit could not be read · 5 the live unit is missing a directive\n' >&2
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	printf '%s: expected TEMPLATE and at most one file, got %s argument(s)\n' "$self" "$#" >&2
	usage
	exit 2
fi

template="$1"
[ -r "$template" ] || {
	printf '%s: cannot read the template %s\n' "$self" "$template" >&2
	exit 2
}
# Non-empty, because the awk below tells the two inputs apart with the NR==FNR idiom
# and an empty first file makes that read the live unit as the template.
[ -s "$template" ] || {
	printf '%s: the template %s is empty, so there is nothing to compare against\n' "$self" "$template" >&2
	exit 2
}

if [ "$#" -eq 2 ] && [ "$2" != "-" ]; then
	[ -r "$2" ] || {
		printf '%s: cannot read %s\n' "$self" "$2" >&2
		exit 2
	}
	exec <"$2"
fi

# The template first, then `-` — the live unit on this shell's stdin. One pass over
# each; the two are told apart inside by NR==FNR.
# shellcheck disable=SC2016
awk '
	# normalise strips a comment or blank line to "" and otherwise trims both ends.
	# systemd comments start with # or ; and `systemctl cat` adds a `# /path` header
	# per file, which is provenance rather than configuration.
	function normalise(s) {
		sub(/^[ \t]+/, "", s)
		sub(/[ \t]+$/, "", s)
		if (s ~ /^[#;]/) return ""
		return s
	}

	# record files one directive under its section, keyed so [Unit] OnFailure= and a
	# hypothetical [Service] OnFailure= cannot collide. A repeated key (After=,
	# Environment=, ExecStartPre=) accumulates rather than overwriting, so a unit that
	# names three of something is not compared as though it named one.
	#
	# Membership is asked of the SEEN arrays throughout, never of the value arrays:
	# referring to arr[k] in awk creates the element, so `arr[k] (k in arr ? …)` is
	# always true on the first write and would silently drop the first value.
	function record(which, section, line,   key, val, eq, k) {
		eq = index(line, "=")
		if (eq == 0) return
		key = substr(line, 1, eq - 1)
		val = substr(line, eq + 1)
		sub(/[ \t]+$/, "", key)
		sub(/^[ \t]+/, "", val)
		k = "[" section "] " key
		if (which == "t") {
			if (k in tseen) { tval[k] = tval[k] "\n" val ; return }
			torder[tn++] = k ; tval[k] = val ; tseen[k] = 1
		} else {
			if (k in lseen) { lval[k] = lval[k] "\n" val ; return }
			lorder[ln++] = k ; lval[k] = val ; lseen[k] = 1
		}
	}

	BEGIN { section = "" ; pending = "" }

	# The file boundary. FILENAME is not portable for a `-` argument, so the two
	# inputs are told apart by NR==FNR — which is why the shell above refuses an empty
	# template. A continuation left open at the end of one file is closed here rather
	# than being joined onto the first line of the next.
	FNR == 1 && NR > 1 {
		if (pending != "") { record("t", section, pending) ; pending = "" }
		section = ""
	}

	{
		which = (NR == FNR) ? "t" : "l"
		line = normalise($0)
		if (pending != "") {
			# A continued line: systemd joins `\` continuations with a space.
			line = pending " " line
			pending = ""
		}
		if (line == "") next
		if (line ~ /\\$/) {
			sub(/[ \t]*\\$/, "", line)
			pending = line
			next
		}
		if (line ~ /^\[.*\]$/) {
			section = substr(line, 2, length(line) - 2)
			next
		}
		record(which, section, line)
	}

	END {
		if (pending != "") record("l", section, pending)

		if (ln == 0) {
			print "bacchus-unit-check: the live unit is empty or unreadable." > "/dev/stderr"
			print "  `systemctl cat <unit>` prints nothing when the unit does not exist on that box," > "/dev/stderr"
			print "  which is itself a finding: the mechanism is in this repository and the machine has" > "/dev/stderr"
			print "  no unit to carry it. Check the unit name against your NODE_TARGETS entry." > "/dev/stderr"
			exit 3
		}

		missing = 0
		for (i = 0; i < tn; i++) {
			k = torder[i]
			if (!(k in lseen)) {
				if (missing == 0)
					print "  MISSING from the live unit — shipped here, absent there:"
				missing++
				n = split(tval[k], vs, "\n")
				for (j = 1; j <= n; j++) printf "    %s=%s\n", k, vs[j]
			}
		}

		extra = 0
		for (i = 0; i < ln; i++) {
			k = lorder[i]
			if (!(k in tseen)) {
				if (extra == 0)
					print "  only on the box — hand-added, and the reason units are never copied:"
				extra++
				n = split(lval[k], vs, "\n")
				for (j = 1; j <= n; j++) printf "    %s=%s\n", k, vs[j]
			}
		}

		differs = 0
		for (i = 0; i < tn; i++) {
			k = torder[i]
			if ((k in lseen) && tval[k] != lval[k]) {
				if (differs == 0)
					print "  same directive, different value — expected for ExecStart, read the rest:"
				differs++
				printf "    %s=\n", k
				n = split(tval[k], vs, "\n")
				for (j = 1; j <= n; j++) printf "      shipped: %s\n", vs[j]
				n = split(lval[k], vs, "\n")
				for (j = 1; j <= n; j++) printf "         live: %s\n", vs[j]
			}
		}

		if (missing == 0 && extra == 0 && differs == 0)
			print "  the live unit and the shipped template carry the same directives"

		if (missing > 0) {
			fflush()
			printf "bacchus-unit-check: the live unit is missing %d directive(s) this commit ships.\n", missing > "/dev/stderr"
			print "  Nothing was copied — that refusal is deliberate and stays (ADR-0064 §7): the live" > "/dev/stderr"
			print "  units carry hand-added flags these templates do not, so copying one would revert a" > "/dev/stderr"
			print "  working configuration silently. Add the missing line(s) BY HAND, keeping everything" > "/dev/stderr"
			print "  the unit already has, then `systemctl daemon-reload`." > "/dev/stderr"
			print "  For OnFailure=bacchus-update-rollback@%n.service the handler also has to be on the" > "/dev/stderr"
			print "  box (issue #234) — deploy/install.sh places it, or by hand from a checkout at the" > "/dev/stderr"
			print "  pinned commit:" > "/dev/stderr"
			print "    install -D -m 0755 deploy/bacchus-update-rollback.sh \\" > "/dev/stderr"
			print "      /usr/local/lib/bacchus/bacchus-update-rollback" > "/dev/stderr"
			print "    install -D -m 0644 deploy/bacchus-update-rollback@.service \\" > "/dev/stderr"
			print "      /etc/systemd/system/bacchus-update-rollback@.service" > "/dev/stderr"
			exit 5
		}
		exit 0
	}
' "$template" -
