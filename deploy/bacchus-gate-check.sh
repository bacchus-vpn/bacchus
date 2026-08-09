#!/bin/sh
# Answer "which of this coordinator's credential gates are actually ON?" from its own
# journal, and fail when a gate the deployment DECLARED is off (issues #249, #247,
# ADR-0072).
#
# usage: bacchus-gate-check.sh [--require GATE[,GATE...]] [JOURNAL_FILE]
#        journalctl -u bacchus-coordinator --since -10min | bacchus-gate-check.sh
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS: EVERY GATE FAILS OPEN, SO A HEALTHY FLEET PROVES NOTHING
# ---------------------------------------------------------------------------
# -admission-pubkey, -admission-authority, -device-root-pubkey,
# -revocations-root-pubkey and both -*-revocations-source all fail OPEN when unset.
# That is deliberate and each has its reasons (ADR-0045 §2 for the sharpest one), and
# it is exactly why an unconfigured deployment is invisible: the fleet check passes,
# the unit comparison passes, the capability probe passes, and nothing is being refused
# anywhere because nothing was asked to refuse.
#
# The cost is not that the gates are off. It is that three owner tests are written as
# if they were on, and each would return a FALSE PASS against a fleet in that state
# (#249): #167's connect proves the client reached an exit rather than that any
# entitlement was checked; #173 cannot see a refusal because an empty revocation list
# refuses nothing; #209 has no published address to follow. A test that cannot fail is
# worse than an unrun one, because it closes a card.
#
# So this reads the posture out loud, and — given `--require` — turns "off" into a
# non-zero exit. The pin passes the list the operator declared in testbed.env
# (COORDINATOR_GATES), which is what makes the deployment describe itself rather than
# be rediscovered.
#
# ---------------------------------------------------------------------------
# IT READS THE JOURNAL, NOT THE FLAGS, AND THAT IS THE POINT
# ---------------------------------------------------------------------------
# A flag in ExecStart says what the operator asked for. The journal says what the
# binary CONCLUDED — after parsing the key, after resolving the path, after finding
# out whether the file is there. Those differ in the direction that matters: a
# revocation flag pointing at a path that does not exist is present in ExecStart and
# enforces nothing (#247), and a gate flag whose namespace is not enabled is started
# and inert (`signed revocations(device): … the device gate is not configured`).
#
# It is the same choice ADR-0064 §3 made for the build: probe a capability, never read
# a version string. Here the "probe" is free, because cmd/coordinator already states
# all of it at startup — the admission and device-gate lines, the signed-revocations
# and policy lines, and the `paths:` block issue #226 added, which names every file
# flag, what it RESOLVES to, whether it is there, and what its absence MEANS.
#
# One gate cannot be read this way and is reported as UNKNOWN rather than assumed:
# -account-service (#209's publication) is the one gate cmd/coordinator says nothing
# about at startup. See "account-service" below. An unreadable gate is never an ok —
# that is #248's finding, and it applies to this script first of all.
#
# ---------------------------------------------------------------------------
# THE WINDOW
# ---------------------------------------------------------------------------
# Everything before the LAST `coordinator release` line is a coordinator that is no
# longer running, and its gate posture is not evidence about the one that is. Same rule
# as deploy/bacchus-fleet-check.sh, and a window with no startup line in it is refused
# (exit 3) rather than read as a pass.
#
# ---------------------------------------------------------------------------
# IT PRINTS NO HOSTNAME
# ---------------------------------------------------------------------------
# Like bacchus-fleet-check.sh and unlike bacchus-pin.sh, the output is the half of a run
# that is safe to paste into a public issue. It reads text on stdin and never learns
# where the text came from — and it deliberately does NOT echo the device gate's
# audience, which is a coordinator's own dialable identity and the one host-shaped value
# in the lines it reads.

set -eu

self="${0##*/}"

usage() {
	printf 'usage: %s [--require GATE[,GATE...]] [JOURNAL_FILE]\n' "$self" >&2
	printf '       journalctl -u bacchus-coordinator --since -10min | %s\n' "$self" >&2
	printf '\n%s\n' 'Gates: admission device revocation-lists signed-revocations policy account-service' >&2
	printf '%s\n' '--require    the gates this deployment declares ON. Anything else is reported only.' >&2
	printf 'Exit: 0 every required gate is on · 1 a required gate is OFF · 2 usage\n' >&2
	printf '      3 no coordinator start in this window · 4 a required gate could not be read\n' >&2
}

require=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	--require)
		[ "$#" -ge 2 ] || {
			printf '%s: --require needs a value\n' "$self" >&2
			exit 2
		}
		require="$2"
		shift 2
		;;
	--)
		shift
		break
		;;
	-*)
		printf '%s: unknown option: %s\n' "$self" "$1" >&2
		usage
		exit 2
		;;
	*)
		break
		;;
	esac
done

if [ "$#" -gt 1 ]; then
	printf '%s: expected at most one journal file, got %s argument(s)\n' "$self" "$#" >&2
	usage
	exit 2
fi

# Commas are the documented separator; spaces are accepted because a shell variable
# holding a list is more often space separated and refusing that would be a papercut
# with no upside.
require=$(printf '%s' "$require" | tr ',' ' ')
for g in $require; do
	case "$g" in
	admission | device | revocation-lists | signed-revocations | policy | account-service) ;;
	*)
		printf '%s: %s is not a gate this reads.\n' "$self" "$g" >&2
		printf '%s\n' '  Known: admission device revocation-lists signed-revocations policy account-service' >&2
		exit 2
		;;
	esac
done

if [ "$#" -eq 1 ] && [ "$1" != "-" ]; then
	[ -r "$1" ] || {
		printf '%s: cannot read %s\n' "$self" "$1" >&2
		exit 2
	}
	exec <"$1"
fi

# One awk pass. Matching is by index() on ASCII substrings of cmd/coordinator's own
# startup lines rather than by regex: several of those lines carry an em dash, and a
# byte-wise substring test cannot be turned into a false negative by a locale.
#
# The Go/shell pair is the one ADR-0069 §4 names as the one that drifts silently, so
# deploy/gate_check_test.go never hand-writes these strings for the on case: it builds
# cmd/coordinator, runs it with the flag set deploy/coordinator-gates.env.example
# ships, and feeds the bytes the real binary produced through this script.
#
# shellcheck disable=SC2016
awk -v require="$require" '
	function set_state(gate, state, note) {
		st[gate] = state
		nt[gate] = note
	}

	function pad(s, w,   out) {
		out = s
		while (length(out) < w) out = out " "
		return out
	}

	BEGIN {
		started = 0
		# Every gate starts UNREAD. Not "off": a journal that never said is a
		# different fact from a coordinator that said DISABLED, and collapsing the
		# two is how an uncompared thing starts reading like a passing one (#248).
		split("admission device revocation-lists signed-revocations policy account-service", order, " ")
		for (i in order) set_state(order[i], "UNREAD", "")
	}

	index($0, "coordinator release ") > 0 {
		started = 1
		for (i in order) set_state(order[i], "UNREAD", "")
		# Every latch below is cleared here too, and that is not tidiness: each one
		# is set by a line and never by its absence, so a `paths:` block or a
		# NOT ENFORCED notice from before the restart would otherwise describe the
		# coordinator that is gone. The gate rows are reset above for the same
		# reason and the same reason bacchus-fleet-check.sh empties its table.
		rev_dev = ""
		rev_adm = ""
		wd = ""
		wd_root = 0
		tier_off = 0
		sigrev_dev = ""
		sigrev_adm = ""
		# -account-service is published into the signed cold-start directory and
		# announced nowhere, so it is UNREAD in every window, on every build. Stated
		# once, here, so the row carries its reason rather than looking like a gap in
		# this window.
		set_state("account-service", "UNKNOWN", "cmd/coordinator states nothing about -account-service at startup, so no journal can answer this (issue #260). Read the effective ExecStart the pin prints.")
		next
	}

	!started { next }

	index($0, "admission DISABLED") > 0 {
		set_state("admission", "OFF", "no credential is required to register or connect — any client or node may join (issue #42)")
		next
	}
	index($0, "admission ENABLED") > 0 {
		anchors = ""
		if ((p = index($0, "anchors: ")) > 0) anchors = substr($0, p + 9)
		set_state("admission", "on", "anchors: " anchors)
		next
	}

	index($0, "device-credential gate DISABLED") > 0 {
		set_state("device", "OFF", "connects are gated by admission alone; no entitlement is checked (issue #50)")
		next
	}
	# The audience is deliberately not carried into the note: it is this coordinator
	# as clients dial it, which is the one host-shaped value in these lines, and this
	# output is meant to be pasteable.
	index($0, "device-credential gate ENABLED") > 0 {
		set_state("device", "on", "every connect must present a credential chaining to the configured offline root")
		next
	}

	index($0, "signed revocations DISABLED") > 0 {
		set_state("signed-revocations", "OFF", "-revocations-root-pubkey unset; the two -*-revocations files are the only source (issue #199)")
		next
	}
	index($0, "signed revocations(device) ENABLED") > 0 { sigrev_dev = "on" ; next }
	index($0, "signed revocations(admission) ENABLED") > 0 { sigrev_adm = "on" ; next }
	# Configured, started for neither namespace, enforcing nothing: the root is set and
	# the namespace gate is not, so no verifier would ever consult the list.
	index($0, "signed revocations(device): -revocations-root-pubkey is set") > 0 { sigrev_dev = "inert" ; next }
	index($0, "signed revocations(admission): -revocations-root-pubkey is set") > 0 { sigrev_adm = "inert" ; next }

	index($0, "signed policy DISABLED") > 0 {
		set_state("policy", "OFF", "this coordinator enforces only its own flags (issue #39)")
		next
	}
	index($0, "signed policy ENABLED") > 0 {
		set_state("policy", "on", "past exp+grace this coordinator STOPS assigning new work — the one gate here that fails CLOSED")
		next
	}

	index($0, "tier limits NOT ENFORCED") > 0 { tier_off = 1 ; next }

	# The paths block (issue #226). Both revocation FILES are read from it, because
	# "the flag is set" and "the list has anything in it" are different claims and the
	# gap between them is the whole of #247: a missing revocation file is not an error,
	# it means nothing is revoked.
	#
	# The trailing space is load-bearing: -device-revocations-state is a different flag
	# and its name continues where this one ends.
	(p = index($0, "paths: -device-revocations ")) > 0 { rev_dev = substr($0, p + 27) ; next }
	(p = index($0, "paths: -admission-revocations ")) > 0 { rev_adm = substr($0, p + 30) ; next }
	(p = index($0, "paths: working directory ")) > 0 { wd = substr($0, p + 25) ; next }
	index($0, "path(s) above are RELATIVE") > 0 { wd_root = 1 ; next }

	# describe_list turns one `paths:` tail into a verdict for a revocation FILE.
	function describe_list(tail,   path) {
		if (tail == "") return ""
		if (index(tail, "(empty") > 0) return "disabled (empty path)"
		path = tail
		sub(/ \[.*$/, "", path)
		sub(/^ +/, "", path)
		if (index(tail, "CANNOT TELL") > 0) return path " — this coordinator cannot tell whether it exists"
		if (index(tail, "ABSENT") > 0) return path " — ABSENT, so NOTHING IS REVOKED in this namespace"
		if (index(tail, "present") > 0) return path " — present"
		return path
	}

	END {
		if (!started) {
			fflush()
			print "bacchus-gate-check: no `coordinator release` startup line in this input." > "/dev/stderr"
			print "  A gate posture read from before the last restart is not evidence about the" > "/dev/stderr"
			print "  coordinator that is running now, and it looks exactly as convincing. Widen the" > "/dev/stderr"
			print "  window (journalctl --since) so it covers the coordinator start, and re-read." > "/dev/stderr"
			exit 3
		}

		# The two namespaces are one row: they share -revocations-root-pubkey and one
		# verifier, and an operator reading a report wants "is the signed path live",
		# not two half-answers. Any namespace inert is reported, because a root that is
		# set and feeding nothing is the configuration that looks done and is not.
		if (st["signed-revocations"] != "OFF") {
			if (sigrev_dev == "on" && sigrev_adm == "on")
				set_state("signed-revocations", "on", "both namespaces fetching and verifying")
			else if (sigrev_dev == "on" || sigrev_adm == "on")
				set_state("signed-revocations", "PARTIAL",
					"device=" (sigrev_dev == "" ? "unread" : sigrev_dev) " admission=" (sigrev_adm == "" ? "unread" : sigrev_adm) \
					" — a namespace whose own gate is off has no verifier that would consult its list")
			else if (sigrev_dev != "" || sigrev_adm != "")
				set_state("signed-revocations", "OFF", "the root is set and NEITHER namespace is fed — nothing verifies anything")
		}

		dev = describe_list(rev_dev)
		adm = describe_list(rev_adm)
		if (dev != "" || adm != "") {
			ok = (index(dev, "ABSENT") == 0 && index(adm, "ABSENT") == 0 && dev != "" && adm != "")
			set_state("revocation-lists", ok ? "on" : "EMPTY", "")
		}

		w = 0
		for (i in order) if (length(order[i]) > w) w = length(order[i])
		print "bacchus-gate-check: what this coordinator said about its own gates at startup"
		for (i = 1; i <= 6; i++) {
			g = order[i]
			line = "  " pad(g, w) "  " pad(st[g], 7)
			if (g == "revocation-lists") {
				sub(/ +$/, "", line)
				print line
				if (dev != "") print "  " pad("", w) "    -device-revocations    " dev
				if (adm != "") print "  " pad("", w) "    -admission-revocations " adm
				if (dev == "" && adm == "") print "  " pad("", w) "    no `paths:` block in this window — this binary predates issue #226"
				continue
			}
			if (nt[g] != "") line = line "  " nt[g]
			sub(/ +$/, "", line)
			print line
		}

		if (wd != "") print "  working directory  " wd
		if (wd_root) {
			print "  WARNING: the working directory is / and relative paths remain, so they resolve"
			print "  under the root directory where nothing is staged (issue #247). Set"
			print "  WorkingDirectory= in the unit, or give every gate flag an absolute path."
		}
		if (tier_off) {
			print "  NOTE: signed policy is on and admission is not, so no connect carries the"
			print "  (trust, plan) pair the policy tiers are indexed by — every session is"
			print "  assigned unshaped (issue #58, ADR-0048)."
		}

		# The verdict. Only what was REQUIRED can fail: a deployment that declares
		# nothing gets a report, which is what makes this safe to run on any box.
		# Flushed first so the findings below land after the table they refer to
		# rather than ahead of it, the way bacchus-fleet-check.sh does.
		fflush()
		n = split(require, want, " ")
		bad = 0
		unread = 0
		for (i = 1; i <= n; i++) {
			g = want[i]
			if (st[g] == "on") continue
			if (st[g] == "UNREAD" || st[g] == "UNKNOWN") {
				unread++
				printf "bacchus-gate-check: %s is DECLARED ON and this journal does not say either way (%s).\n", g, st[g] > "/dev/stderr"
				if (nt[g] != "") printf "  %s\n", nt[g] > "/dev/stderr"
				continue
			}
			bad++
			printf "bacchus-gate-check: %s is DECLARED ON and is %s.\n", g, st[g] > "/dev/stderr"
			if (nt[g] != "") printf "  %s\n", nt[g] > "/dev/stderr"
		}
		if (bad > 0) {
			print "bacchus-gate-check: this deployment declares gates it is not enforcing. Any test" > "/dev/stderr"
			print "  that expects a refusal will PASS without refusing anything (issue #249) — do not" > "/dev/stderr"
			print "  run #167, #173 or #209 against this fleet until the report above is clean." > "/dev/stderr"
			print "  The flags, and what each one needs staged first: deploy/coordinator-gates.env.example." > "/dev/stderr"
			exit 1
		}
		if (unread > 0) {
			print "bacchus-gate-check: a gate that could not be read is NOT a gate that is on." > "/dev/stderr"
			exit 4
		}
		if (n > 0) print "bacchus-gate-check: every declared gate is enforcing"
		exit 0
	}
'
