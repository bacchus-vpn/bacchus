#!/bin/sh
# bacchus-update-rollback — put the previous binary back when an applied release
# will not start at all.
#
# Issue #222. core/update's demotion watchdog covers "applied, started, and never
# worked": the apply writes a confirmation marker beside the target, the release's
# own first start claims it, a start that finds it ALREADY claimed restores the
# previous binary and exits, and a start that reaches a working state clears it.
# All of that runs inside the process.
#
# It cannot cover "applied, and the process will not start at all" — a wrong
# architecture, a missing loader, a file that verified because it was signed
# corrupt. The binary never reaches main, so nothing in-process runs, the marker is
# never claimed, and under Restart=always the unit loops on a binary that cannot
# execute. THE FIX IS NECESSARILY OUTSIDE THE PROCESS, which is this script, wired
# to the unit by OnFailure=.
#
# # The signal, and why the two watchdogs cannot fight
#
# The marker records whether a process of the applied release ever reached
# CheckStartup:
#
#   started=false  no process of this release has run. Either the handover has not
#                  happened yet, or the binary cannot execute. THIS SCRIPT'S CASE.
#   started=true   a process reached main. A crash loop puts it through the
#                  in-process check again, which demotes there. NOT this script's
#                  case, and it exits without touching anything.
#
# So the two mechanisms are gated on states neither leaves behind for the other,
# and both perform the same one rename from the same place. Running this twice is a
# no-op rather than a swap back: the first run removes the marker, and every run
# after that finds nothing to do.
#
# # OnFailure= fires more often than the design needed, which is why the gate is
# # everything
#
# Measured on systemd 259 rather than assumed: with Restart=always, OnFailure=
# fires on EVERY failed start — the journal logs "Triggering OnFailure=
# dependencies" after each one — not once when the start limit is finally hit. Four
# firings for a unit configured to give up after three attempts. So this script is
# invoked repeatedly, concurrently with systemd's own restart timer, and its
# idempotence is load-bearing rather than good manners.
#
# It also means the mechanism does not depend on the start limit at all, and
# nothing here changes the restart policy of a production unit to make it work. On
# an older systemd that fires only at the limit, the same gate produces the same
# result about ten seconds later.
#
# # What this deliberately does not try to be
#
# It is not a health check. `systemctl start` returns success the instant the
# process forks (Type=simple), so "did it start?" is not a question that can be
# asked from outside; what CAN be established from outside is "an update was
# applied and no process of it has ever run", which is a fact on disk and is the
# only thing this acts on.
#
# Usage: bacchus-update-rollback.sh <unit>
set -eu

progname=bacchus-update-rollback

log() { printf '%s: %s\n' "$progname" "$*" >&2; }

fail() {
	log "ERROR: $*"
	exit 1
}

unit=${1:-}
[ -n "$unit" ] || fail "usage: $progname <unit>. It is wired to a unit by OnFailure=bacchus-update-rollback@%n.service, which passes the failing unit's name as %i."

# The binary the unit executes, read out of the unit rather than configured here,
# so one template covers every unit that carries Restart=always and there is no
# second place for a path to go stale. `systemctl show -p ExecStart --value`
# renders "{ path=/usr/local/bin/bacchus-node ; argv[]=... ; ... }".
target=$(systemctl show -p ExecStart --value "$unit" 2>/dev/null |
	sed -n 's/^{[[:space:]]*path=\([^[:space:];]*\).*/\1/p' | head -n 1)
[ -n "$target" ] || fail "cannot read an ExecStart path out of $unit, so there is no binary to roll back. Nothing was changed."

marker="$target.pending"
previous="$target.prev"

if [ ! -f "$marker" ]; then
	# The ordinary case, and the reason this exits 0 rather than complaining: a
	# unit reaches OnFailure= for every kind of failure, and almost none of them
	# are a release that cannot start. Saying so once per firing is the whole
	# report.
	log "$unit failed and $marker does not exist, so no release is on probation for $target. Nothing to roll back — this failure is not an update that will not start."
	exit 0
fi

# grep rather than a JSON parser because there is no JSON parser to depend on in a
# unit that runs when the machine is already in trouble. The field is written by
# core/update.writeMarker with encoding/json's MarshalIndent, and
# core/update.TestTheMarkerRecordsWhetherTheReleaseEverStarted plus
# deploy/update_rollback_test.go pin this reading against markers produced by that
# writer, so the two encodings cannot drift apart unnoticed.
if grep -q '"started"[[:space:]]*:[[:space:]]*true' "$marker"; then
	log "$unit failed, but the release in $marker has already started at least once, so the in-process demotion check owns this case and will restore $previous on its next start. Nothing was changed."
	exit 0
fi

release=$(sed -n 's/.*"release"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$marker" | head -n 1)
[ -n "$release" ] || release='(unnamed)'

if [ ! -f "$previous" ]; then
	# Nothing to go back to. The marker is LEFT: it is the only remaining record
	# that a release was applied and never ran, and the in-process check clears it
	# harmlessly the moment anything starts.
	fail "$unit failed with release $release applied and never started, but there is no previous binary at $previous to restore. The rollback this exists to perform is a rename, and the file it renames is gone. $target has to be replaced by hand."
fi

# Restore first, clear the marker second. A crash between the two leaves a marker
# with no previous binary beside it, which the in-process check clears on the next
# start; the other order would leave a machine with no marker AND no rollback.
mv -f "$previous" "$target" ||
	fail "restoring $previous over $target failed. $target still holds a release ($release) that will not start, and it has to be replaced by hand."
rm -f "$marker"

log "rolled $target back to the previous binary: release $release was applied and no process of it ever started. The node is on its previous release; it did not update, which is the working state."

# reset-failed AND start, because the unit may be in either state by the time this
# runs: systemd's own restart timer is still counting on an early firing, and on a
# late one the unit has given up and nothing else will start it. --no-block because
# a oneshot that waits on a start job of the unit that triggered it is a deadlock
# waiting to be discovered on the one machine that most needs this to work.
systemctl reset-failed "$unit" 2>/dev/null || true
systemctl --no-block start "$unit" ||
	fail "$unit could not be started after the rollback. $target now holds the previous binary, which is the working one, but nothing is running it — start it by hand. This unit is left FAILED so that is visible in the journal rather than only here."
