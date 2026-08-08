#!/bin/sh
# Tests for deploy/install.sh (issue #18).
#
# usage: deploy/install-test.sh
#
# WHAT THIS ASSERTS AGAINST
#
# Every check here reads the filesystem and the recorded system-command calls,
# never the installer's own output. An installer that says "installed" is not
# evidence of anything — the failure mode this is guarding against is precisely
# a script that reports success and leaves the machine in a state where the
# client cannot connect, so a test that trusted the script's narration would be
# checking the wrong artifact. `installed X` never appears in an assertion; the
# mode bits of X do.
#
# HOW IT GETS A SYSTEM TO INSTALL INTO
#
# install.sh takes a --root staging prefix, so every path it writes can be
# redirected into a temporary tree and asserted exactly. That covers file
# placement, modes, templating, idempotence and the whole of uninstall — which
# is most of what there is to get wrong.
#
# What a prefix cannot redirect is the three things that touch system state
# rather than files: systemctl, groupadd/groupdel and usermod. Those are stubbed
# onto PATH by this script and RECORD their arguments, so the tests assert the
# exact sequence of system commands as well as the exact file tree. That is a
# seam, and a seam is a thing that can be wrong — see WHAT THIS DOES NOT COVER.
#
# WHAT THIS DOES NOT COVER, AND WHO HAS TO
#
# Nothing here proves that systemd accepts the units, that the socket comes up
# with mode 0660 root:bacchus, that the helper is activated on first connect, or
# that a real groupadd/usermod behaves as the stubs assume. Those need a booted
# systemd and root, which means a container or a VM. The real-system half is
# still manual: the procedure is at the bottom of this file under REAL-SYSTEM
# CHECKLIST and has to be run by hand on a disposable machine before this is
# called verified. This FILE now runs in CI (the `deploy` job in
# .github/workflows/ci.yml) — it did not until issues #158 and #160.
#
# WHY IT COUNTS ITS OWN CASES
#
# `set -eu` is in force, so any command that fails outside a guard stops this
# script where it stands. Between 451555c and issue #158 that is exactly what
# happened: fixture_repo's `cp` met the new deploy/windows DIRECTORY, exited
# non-zero, and took the release-stamp and pipe-safety sections with it. Every
# case above the failure printed `ok` and nothing said the rest had not run.
#
# So the totals are pinned and checked from an EXIT trap, which is the one place
# that runs even when the bottom of the file is never reached. A run that does
# not reach every case is reported as no result at all, rather than as the pass
# it happens to look like.

set -eu

# What a complete run does. Both are asserted in finish(); a case or an
# assertion added or removed on purpose is a deliberate edit here in the same
# change, which is the difference between a change and a loss.
#
# `checks` is stable across hosts because a case that cannot run on this one
# calls skip(), which counts. The only such case today is the user+mount
# namespace one at the bottom.
expected_cases=29
expected_checks=144

failures=0
checks=0
cases=0
skips=0
current=''
reached_the_end=''

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
installer=$here/install.sh

work=$(mktemp -d)
# Upgraded to finish() as soon as that is defined, a few lines below. This
# first form exists only so the temporary tree is still removed if something
# fails in the setup between here and there.
trap 'rm -rf "$work"' EXIT INT TERM

calls=$work/calls.log
fake_groups=$work/groups
: >"$calls"
: >"$fake_groups"

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

case_start() {
	current=$1
	cases=$((cases + 1))
	printf '\n== %s\n' "$current"
}

ok() {
	checks=$((checks + 1))
	printf '   ok   %s\n' "$1"
}

bad() {
	checks=$((checks + 1))
	failures=$((failures + 1))
	printf '   FAIL %s\n' "$1"
}

# A check this host cannot make. It counts, so the total stays the same
# everywhere and a skip cannot be mistaken for coverage — the tally names it
# separately instead.
skip() {
	checks=$((checks + 1))
	skips=$((skips + 1))
	printf '   SKIP %s\n' "$1"
}

# The end of a run, wherever the run actually ends.
#
# This is the EXIT trap rather than the last few lines of the file, because the
# last few lines of the file are precisely what a run killed by `set -e` never
# reaches — see WHY IT COUNTS ITS OWN CASES at the top.
#
# The verdict is ordered deliberately. `cases` is the truncation signal and
# nothing else perturbs it: case_start runs unconditionally, whatever the
# assertions inside a case do. A short case count therefore means the run
# stopped, and no other reading of the output is worth anything. Only once the
# run is known to be complete do failures, and then a drifted check count, mean
# what they say.
finish() {
	status=$?
	trap - EXIT INT TERM
	set +e
	rm -rf "$work"

	printf '\n%s of %s cases, %s of %s checks, %s failures' \
		"$cases" "$expected_cases" "$checks" "$expected_checks" "$failures"
	[ "$skips" -eq 0 ] || printf ', %s skipped' "$skips"
	printf '\n'

	if [ "$cases" -ne "$expected_cases" ] || [ -z "$reached_the_end" ]; then
		cat <<EOF

THIS RUN IS NOT A RESULT. It stopped in case $cases of $expected_cases
(exit status $status):

  $current

The cases below that one did not run, did not fail, and are covered by
nothing above. The failure itself is printed after that case's '==' heading.

If a case was added or removed on purpose, expected_cases at the top of this
file is part of that change.
EOF
		exit 1
	fi

	[ "$failures" = '0' ] || exit 1

	if [ "$checks" -ne "$expected_checks" ]; then
		cat <<EOF

Every case ran and none failed, but $checks assertions were made where
$expected_checks were expected. A case did less than it is written to do —
a loop that iterated the wrong number of times, or a branch that quietly
asserted nothing. Find it before trusting this run.

If an assertion was added or removed on purpose, expected_checks at the top
of this file is part of that change.
EOF
		exit 1
	fi

	[ "$status" = '0' ] || exit "$status"

	cat <<'EOF'

REAL-SYSTEM CHECKLIST — none of the above ran systemd, and CI runs this file
but not the real-system checks. On a disposable machine with systemd (a VM, or
a container booted with systemd as PID 1), as root:

  sh deploy/install.sh client --user <you>
  systemctl status bacchus-netd.socket           # active (listening)
  stat -c '%a %U:%G' /run/bacchus/netd.sock      # 660 root:bacchus
  systemctl is-enabled bacchus-netd.service      # must NOT be enabled
  # log out, log back in, then:
  id -nG | tr ' ' '\n' | grep -x bacchus         # membership took effect
  bacchus-fyne                                   # connect: helper is reachable
  sh deploy/install.sh uninstall client --user <you>
  systemctl status bacchus-netd.socket           # not found
  getent group bacchus                           # empty
  ls /usr/local/lib/bacchus /run/bacchus         # both gone

  sh deploy/install.sh node --role exit --binaries /path/to/staged
  # edit /etc/bacchus/node.env, then re-run the same command
  systemctl status bacchus-exit                  # active
  sh deploy/install.sh uninstall node --purge
EOF
}
trap finish EXIT INT TERM

assert_file() {
	path=$1
	want_mode=$2
	if [ ! -f "$path" ]; then
		bad "expected file $path"
		return 0
	fi
	got=$(stat -c '%a' "$path")
	if [ "$got" = "$want_mode" ]; then
		ok "$path exists, mode $got"
	else
		bad "$path mode is $got, wanted $want_mode"
	fi
}

assert_dir_mode() {
	if [ ! -d "$1" ]; then
		bad "expected directory $1"
		return 0
	fi
	got=$(stat -c '%a' "$1")
	if [ "$got" = "$2" ]; then
		ok "$1 is a directory, mode $got"
	else
		bad "$1 mode is $got, wanted $2"
	fi
}

assert_absent() {
	if [ -e "$1" ]; then
		bad "$1 should be gone, but it is still there"
	else
		ok "$1 is gone"
	fi
}

assert_present() {
	if [ -e "$1" ]; then
		ok "$1 is still there"
	else
		bad "$1 should still be there, but it is gone"
	fi
}

assert_grep() {
	if grep -qE "$2" "$1" 2>/dev/null; then
		ok "$3"
	else
		bad "$3"
	fi
}

assert_not_grep() {
	if grep -qE "$2" "$1" 2>/dev/null; then
		bad "$3"
	else
		ok "$3"
	fi
}

assert_called() { assert_grep "$calls" "$1" "system command called: $1"; }
assert_not_called() { assert_not_grep "$calls" "$1" "system command NOT called: $1"; }

# ---------------------------------------------------------------------------
# Stubs for the three things a staging root cannot redirect
# ---------------------------------------------------------------------------

stubdir=$work/stubs
mkdir -p "$stubdir"

make_stub() {
	name=$1
	body=$2
	{
		printf '#!/bin/sh\n'
		printf 'printf "%%s %%s\\n" "%s" "$*" >>"%s"\n' "$name" "$calls"
		printf '%s\n' "$body"
	} >"$stubdir/$name"
	chmod +x "$stubdir/$name"
}

# The single-quoted halves below are SOURCE CODE FOR THE GENERATED STUB, not
# strings this shell should expand: $a and $1 are the stub's own loop variable
# and the stub's own argument, and expanding them here would bake in this
# shell's values and produce a stub that records nothing. The parts that DO
# have to be resolved now — the fake_groups path, which the stub cannot know —
# are spliced in by leaving the quotes, which is what the '"…"' seams are.
# Hence the disables rather than a rewrite; SC2016 is describing the intent
# correctly and the intent is right.
make_stub systemctl 'exit 0'
make_stub usermod 'exit 0'
# shellcheck disable=SC2016
make_stub groupadd 'for a; do case $a in -*) ;; *) echo "$a" >>"'"$fake_groups"'";; esac; done; exit 0'
# shellcheck disable=SC2016
make_stub groupdel 'grep -vx "$1" "'"$fake_groups"'" >"'"$fake_groups"'.n" || true; mv "'"$fake_groups"'.n" "'"$fake_groups"'"; exit 0'
make_stub systemd-sysusers 'echo bacchus >>"'"$fake_groups"'"; exit 0'

# getent is only intercepted for `group`; `passwd` falls through to the real one
# so that the desktop user's home directory is resolved the way the installer
# will really resolve it (and then prefixed by --root, which is what keeps this
# test out of the real home directory).
#
# Same reason for the disable as the stubs above: ${1:-}, ${2:-} and "$@" are
# the generated getent's parameters and must reach the file unexpanded. The two
# paths that must NOT are passed as printf arguments and land through %s.
# shellcheck disable=SC2016
{
	printf '#!/bin/sh\n'
	printf 'if [ "${1:-}" = group ]; then\n'
	printf '  printf "%%s %%s\\n" getent "$*" >>"%s"\n' "$calls"
	printf '  if [ -n "${2:-}" ]; then grep -qx "$2" "%s" && { echo "$2:x:9999:"; exit 0; }; exit 2; fi\n' "$fake_groups"
	printf 'fi\n'
	printf 'exec /usr/bin/getent "$@"\n'
} >"$stubdir/getent"
chmod +x "$stubdir/getent"

PATH=$stubdir:$PATH
export PATH

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Stand-in binaries. What is under test is the installer, not the compiler, so
# --binaries keeps a Go toolchain out of the loop entirely — which also means
# these tests run on a box that has never built this project.
bins=$work/bins
mkdir -p "$bins"
for b in bacchus-fyne bacchus-netd bacchus-node bacchus-coordinator; do
	printf '#!/bin/sh\necho stand-in %s\n' "$b" >"$bins/$b"
	chmod +x "$bins/$b"
done

user=$(id -un)
home=$(getent passwd "$user" | cut -d: -f6)

stage=''
new_stage() {
	stage=$work/stage.$1
	mkdir -p "$stage/run/systemd/system"
	: >"$calls"
	: >"$fake_groups"
}

# The staging root is passed through the environment rather than as --root
# because the mode is positional and has to come first; --root itself gets its
# own case further down.
run_installer() {
	out=$work/out.log
	set +e
	BACCHUS_ROOT=$stage sh "$installer" "$@" >"$out" 2>&1
	rc=$?
	set -e
	return $rc
}

expect_ok() {
	if run_installer "$@"; then
		ok "install.sh $* exited 0"
	else
		bad "install.sh $* exited $? — output follows"
		sed 's/^/        | /' "$work/out.log"
	fi
}

expect_refusal() {
	want=$1
	shift
	if run_installer "$@"; then
		bad "install.sh $* should have refused, but exited 0"
		return 0
	fi
	assert_grep "$work/out.log" "$want" "refusal mentions /$want/"
	assert_grep "$work/out.log" 'nothing was installed or changed' 'refusal states nothing changed'
}

# ---------------------------------------------------------------------------
# client
# ---------------------------------------------------------------------------

case_start 'client: a fresh install puts every piece in place'
new_stage client
expect_ok client --user "$user" --binaries "$bins"

assert_file "$stage/usr/local/bin/bacchus-fyne" 755
assert_file "$stage/usr/local/lib/bacchus/bacchus-netd" 755
assert_file "$stage/etc/systemd/system/bacchus-netd.service" 644
assert_file "$stage/etc/systemd/system/bacchus-netd.socket" 644
assert_file "$stage/usr/local/share/applications/bacchus.desktop" 644
assert_file "$stage$home/.config/Bacchus/fyne-client.json" 600
assert_grep "$stage/usr/local/share/applications/bacchus.desktop" \
	'^Exec=/usr/local/bin/bacchus-fyne$' 'desktop entry execs the installed path, not the staging one'

assert_called 'usermod -aG bacchus '"$user"
assert_called 'systemctl daemon-reload'
assert_called 'systemctl enable --now bacchus-netd\.socket'

# The socket is what gets enabled and the service is what does not. Enabling the
# service would hold a root process open from boot instead of activating it on
# the client's first connect, and it is the single easiest way to get a
# socket-activated pair wrong — so it is asserted rather than assumed.
assert_not_grep "$calls" 'enable.*bacchus-netd\.service' 'the SERVICE is not enabled — only the socket'

# The one place in this file where the OUTPUT is the artifact rather than
# narration about one. The last thing a fresh user reads has to send them
# somewhere that can do the job, and this text used to end "…or use the app's
# Settings window" for the five network keys — which that window cannot set, by
# design (they are file-only; clients/fyne/settings.go binds enforcement,
# transport, admission and volunteering, none of these). That is issue #134's
# defect, sitting in the Linux installer the whole time it was believed to be
# Windows-only, and nothing here would have caught it.
assert_grep "$work/out.log" 'BY EDITING THE CONFIG FILE' \
	'the next steps send the user to the config file'
assert_grep "$work/out.log" "$stage$home/\.config/Bacchus/fyne-client\.json" \
	'and name it by the path it was actually seeded at'
assert_grep "$work/out.log" 'cannot' \
	'and say the Settings window cannot set these keys'
assert_not_grep "$work/out.log" 'or use the app.s Settings window' \
	'rather than offering it as the alternative'

case_start 'client: running it twice changes nothing and clobbers no config'
cfg=$stage$home/.config/Bacchus/fyne-client.json
printf '{ "coordinators": ["sentinel.invalid:8080"] }\n' >"$cfg"
: >"$calls"
expect_ok client --user "$user" --binaries "$bins"
assert_grep "$cfg" 'sentinel\.invalid' 'an existing user config survives a second install'
assert_not_called 'groupadd'
assert_not_called 'systemd-sysusers'
assert_grep "$work/out.log" 'group bacchus already exists' 'the group is created once, not twice'

case_start 'client: uninstall reverses all of it'
: >"$calls"
expect_ok uninstall client --user "$user"
assert_absent "$stage/usr/local/bin/bacchus-fyne"
assert_absent "$stage/usr/local/lib/bacchus/bacchus-netd"
assert_absent "$stage/usr/local/lib/bacchus"
assert_absent "$stage/etc/systemd/system/bacchus-netd.service"
assert_absent "$stage/etc/systemd/system/bacchus-netd.socket"
assert_absent "$stage/usr/local/share/applications/bacchus.desktop"
assert_absent "$stage$home/.config/Bacchus"
assert_absent "$stage/run/bacchus"
assert_called 'groupdel bacchus'
assert_called 'systemctl stop bacchus-netd\.socket'
assert_called 'systemctl disable bacchus-netd\.socket'

# The load-bearing claim of the whole uninstall path: after it, the staging tree
# holds nothing named after this project anywhere.
leftovers=$(find "$stage" -iname '*bacchus*' 2>/dev/null | grep -v '^'"$stage"'/run/systemd' || true)
if [ -z "$leftovers" ]; then
	ok 'nothing bacchus-shaped is left anywhere under the staging root'
else
	bad "leftovers after uninstall: $leftovers"
fi

case_start 'client: uninstall --keep-config keeps only the config'
new_stage keepcfg
expect_ok client --user "$user" --binaries "$bins"
expect_ok uninstall client --user "$user" --keep-config
assert_present "$stage$home/.config/Bacchus/fyne-client.json"
assert_absent "$stage/usr/local/bin/bacchus-fyne"

# ---------------------------------------------------------------------------
# node: exit
# ---------------------------------------------------------------------------

case_start 'node/exit: install generates a persistent identity and refuses to start on placeholders'
new_stage exit
expect_ok node --role exit --binaries "$bins"

assert_file "$stage/usr/local/bin/bacchus-node" 755
assert_file "$stage/etc/systemd/system/bacchus-exit.service" 644
# The supervisor-side half of the demotion watchdog (issue #222). bacchus-exit
# names it in OnFailure=, so an install that placed the unit without it would
# leave every failure of that unit pointing at a unit that is not on the box.
assert_file "$stage/usr/local/lib/bacchus/bacchus-update-rollback" 755
assert_file "$stage/etc/systemd/system/bacchus-update-rollback@.service" 644
assert_file "$stage/etc/bacchus/node.env" 600
assert_dir_mode "$stage/etc/bacchus" 700

env_file=$stage/etc/bacchus/node.env
key=$(sed -n 's/^EXIT_KEY=//p' "$env_file")
if printf '%s' "$key" | grep -qE '^[0-9a-f]{64}$'; then
	ok 'EXIT_KEY is 64 hex characters, generated on this host'
else
	bad "EXIT_KEY is not 64 hex characters (got ${#key} chars)"
fi

# The secret must not have travelled anywhere it could be copied out of.
assert_not_grep "$work/out.log" "$key" 'the generated EXIT_KEY is never printed'

# A unit pointed at an un-edited template would crash-loop behind
# Restart=always rather than fail once, so it is installed and left stopped.
assert_not_grep "$calls" 'enable --now bacchus-exit' 'the exit unit is NOT started while the env file still has placeholders'
assert_grep "$work/out.log" 'NOT starting bacchus-exit' 'the refusal to start is stated, with the reason'

case_start 'node/exit: re-running never re-mints the identity'
before=$key
: >"$calls"
expect_ok node --role exit --binaries "$bins"
after=$(sed -n 's/^EXIT_KEY=//p' "$env_file")
if [ "$before" = "$after" ]; then
	ok 'EXIT_KEY is unchanged across a re-install (the node keeps its id)'
else
	bad 'EXIT_KEY was regenerated on re-install — every client pin and learned path for this exit just broke'
fi

case_start 'node/exit: sh -x cannot leak the key into a trace'
new_stage trace
set +e
BACCHUS_ROOT=$stage sh -x "$installer" node --role exit --binaries "$bins" >"$work/trace.log" 2>&1
set -e
tracekey=$(sed -n 's/^EXIT_KEY=//p' "$stage/etc/bacchus/node.env")
if [ -n "$tracekey" ]; then
	assert_not_grep "$work/trace.log" "$tracekey" 'a key generated under sh -x does not appear in the trace'
else
	bad 'no EXIT_KEY was generated under sh -x'
fi

case_start 'node/exit: with the env file filled in, it starts'
new_stage started
expect_ok node --role exit --binaries "$bins"
# RFC 5737 TEST-NET-2 and an obviously-not-a-password string: this file is in a
# public repository, so even a fixture must not look like it came off a real
# deployment.
sed -i 's/YOUR_VPS_PUBLIC_IP/198\.51\.100\.7/; s/YOUR_COORDINATOR_HOST/198\.51\.100\.9/g; s/CHANGE_ME/not-a-real-turn-password/' \
	"$stage/etc/bacchus/node.env"
: >"$calls"
expect_ok node --role exit --binaries "$bins"
assert_called 'systemctl enable --now bacchus-exit'

case_start 'node: uninstall keeps the identity unless asked to purge'
: >"$calls"
expect_ok uninstall node
assert_absent "$stage/usr/local/bin/bacchus-node"
assert_absent "$stage/etc/systemd/system/bacchus-exit.service"
assert_absent "$stage/usr/local/lib/bacchus/bacchus-update-rollback"
assert_absent "$stage/etc/systemd/system/bacchus-update-rollback@.service"
assert_present "$stage/etc/bacchus/node.env"
assert_grep "$work/out.log" 'KEPT' 'uninstall says loudly that it kept the identity'

case_start 'node: --purge destroys it'
: >"$calls"
expect_ok uninstall node --purge
assert_absent "$stage/etc/bacchus"

# ---------------------------------------------------------------------------
# node: coordinator
# ---------------------------------------------------------------------------

case_start 'node/coordinator: unit, env and the country-database timer'
new_stage coord
expect_ok node --role coordinator --binaries "$bins"
assert_file "$stage/usr/local/bin/bacchus-coordinator" 755
assert_file "$stage/etc/systemd/system/bacchus-coordinator.service" 644
assert_file "$stage/etc/bacchus/coordinator.env" 600
assert_file "$stage/usr/local/lib/bacchus/bacchus-update-rollback" 755
assert_file "$stage/etc/systemd/system/bacchus-update-rollback@.service" 644
assert_file "$stage/usr/local/bin/bacchus-geoip-refresh.sh" 755
assert_file "$stage/etc/systemd/system/bacchus-geoip-refresh.service" 644
assert_file "$stage/etc/systemd/system/bacchus-geoip-refresh.timer" 644
assert_not_grep "$calls" 'enable --now bacchus-coordinator' 'the coordinator is not started on placeholders either'

case_start 'node/coordinator: uninstall --purge takes the timer with it'
expect_ok uninstall node --purge
assert_absent "$stage/usr/local/bin/bacchus-geoip-refresh.sh"
assert_absent "$stage/etc/systemd/system/bacchus-geoip-refresh.timer"
assert_absent "$stage/etc/systemd/system/bacchus-geoip-refresh.service"
assert_absent "$stage/etc/bacchus"

# ---------------------------------------------------------------------------
# Refusals. Each one must also leave the tree untouched.
# ---------------------------------------------------------------------------

case_start 'uninstall all removes both installs and still keeps the irreplaceable half'
new_stage all
expect_ok client --user "$user" --binaries "$bins"
expect_ok node --role exit --binaries "$bins"
allkey=$(sed -n 's/^EXIT_KEY=//p' "$stage/etc/bacchus/node.env")
: >"$calls"
expect_ok uninstall all --user "$user"
# Both installs are gone...
assert_absent "$stage/usr/local/bin/bacchus-fyne"
assert_absent "$stage/usr/local/lib/bacchus/bacchus-netd"
assert_absent "$stage/usr/local/bin/bacchus-node"
assert_absent "$stage/etc/systemd/system/bacchus-netd.socket"
assert_absent "$stage/etc/systemd/system/bacchus-exit.service"
# ...the client's replaceable config with them...
assert_absent "$stage$home/.config/Bacchus"
# ...and the exit's identity is NOT destroyed by the wider word.
assert_present "$stage/etc/bacchus/node.env"
still=$(sed -n 's/^EXIT_KEY=//p' "$stage/etc/bacchus/node.env")
if [ "$allkey" = "$still" ]; then
	ok '"all" did not take the exit identity with it — that still needs --purge'
else
	bad '"all" changed or destroyed EXIT_KEY without --purge'
fi
assert_grep "$work/out.log" 'KEPT' '"all" says out loud what it kept'

case_start 'uninstall all --purge takes everything'
: >"$calls"
expect_ok uninstall all --user "$user" --purge
assert_absent "$stage/etc/bacchus"

case_start 'uninstall needs no unit files — the checkout may already be gone'
new_stage nosrc
expect_ok client --user "$user" --binaries "$bins"
set +e
BACCHUS_ROOT=$stage sh "$installer" uninstall client --user "$user" --deploy-dir /nonexistent \
	>"$work/out.log" 2>&1
rc=$?
set -e
if [ "$rc" = '0' ]; then
	ok 'uninstall works with --deploy-dir pointing at nothing'
else
	bad "uninstall demanded the source tree (exit $rc)"
	sed 's/^/        | /' "$work/out.log"
fi
assert_absent "$stage/usr/local/bin/bacchus-fyne"

case_start 'an install with no unit files anywhere refuses and explains'
new_stage nounits
set +e
BACCHUS_ROOT=$stage sh "$installer" client --user "$user" --binaries "$bins" \
	--deploy-dir "$work/emptydir" >"$work/out.log" 2>&1
rc=$?
set -e
mkdir -p "$work/emptydir"
if [ "$rc" -ne 0 ]; then
	ok 'refuses when pointed at a directory with no unit files'
else
	bad 'installed with no unit files available'
fi
assert_absent "$stage/usr/local/bin/bacchus-fyne"

case_start '--root overrides BACCHUS_ROOT rather than the other way round'
new_stage flagroot
other=$work/stage.flagroot.other
mkdir -p "$other/run/systemd/system"
set +e
BACCHUS_ROOT=$stage sh "$installer" node --role coordinator --root "$other" --binaries "$bins" \
	>"$work/out.log" 2>&1
rc=$?
set -e
if [ "$rc" = '0' ]; then
	ok 'install.sh with both --root and BACCHUS_ROOT exited 0'
else
	bad "exited $rc"
	sed 's/^/        | /' "$work/out.log"
fi
assert_present "$other/usr/local/bin/bacchus-coordinator"
assert_absent "$stage/usr/local/bin/bacchus-coordinator"

case_start 'refuses a host that is not running systemd, and points at the manual steps'
new_stage nosystemd
rmdir "$stage/run/systemd/system" "$stage/run/systemd" "$stage/run"
expect_refusal 'not running systemd' client --user "$user" --binaries "$bins"
assert_absent "$stage/usr/local/bin/bacchus-fyne"
assert_grep "$work/out.log" 'ADR-0049' 'the refusal cites the record saying socket activation is optional'
assert_grep "$work/out.log" 'allow-without-logind' 'the refusal names the flag a non-logind host needs'
assert_grep "$work/out.log" 'deploy/README\.md' 'the refusal points at the manual steps'

case_start 'refuses a node with no role rather than picking one'
new_stage norole
expect_refusal 'role coordinator or --role exit' node --binaries "$bins"
assert_absent "$stage/usr/local/bin/bacchus-node"

case_start 'refuses an unknown role'
new_stage badrole
expect_refusal 'unknown role' node --role relay --binaries "$bins"
assert_absent "$stage/etc/bacchus"

case_start 'refuses a client install when it cannot tell which user will run it'
new_stage nouser
set +e
env -u SUDO_USER BACCHUS_ROOT="$stage" sh "$installer" client --binaries "$bins" >"$work/out.log" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
	ok "exits non-zero with no --user and no \$SUDO_USER"
else
	bad 'guessed a user instead of refusing'
fi
assert_grep "$work/out.log" 'cannot tell which user' 'the refusal says what it could not determine'
assert_absent "$stage/usr/local/bin/bacchus-fyne"

case_start 'refuses --binaries pointing at a directory with nothing in it'
new_stage nobins
mkdir -p "$work/emptybins"
expect_refusal 'does not contain bacchus-node' node --role exit --binaries "$work/emptybins"
assert_absent "$stage/usr/local/bin/bacchus-node"

# ---------------------------------------------------------------------------
# The release stamp (issue #128)
# ---------------------------------------------------------------------------
#
# Every case above passes --binaries, which is the whole point of --binaries and
# also means none of them has ever entered the BUILD path. So the code that reads
# VERSION and stamps it into a binary had no coverage here at all.
#
# These three enter it, and still need no Go toolchain: `go` is stubbed like
# systemctl and groupadd, and — because it records its arguments — the assertion
# can be the thing worth asserting. "It exited 0" would pass just as well with
# the -ldflags silently dropped, and a build path that quietly stops stamping is
# exactly the failure #128 was filed about: every binary reporting one release
# into three mechanisms that do nothing but compare releases.
#
# The fixture is a repository root of the test's own making — --deploy-dir points
# at a copy of this directory, so repo_root is its parent — which is what lets a
# case put a deliberately broken VERSION in front of the installer without going
# anywhere near the real one.

# Writes a runnable stand-in at whatever -o names, because the installer goes on
# to install what it just "built".
#
# Single-quoted for the reason the other stubs are: "$@", $a, $prev and $out
# belong to the generated `go`, which has to read the installer's real argument
# list at the time the installer runs it.
# shellcheck disable=SC2016
make_stub go 'out=""; prev=""
for a in "$@"; do
	if [ "$prev" = "-o" ]; then out=$a; fi
	prev=$a
done
if [ -n "$out" ]; then printf "#!/bin/sh\nexit 0\n" >"$out"; chmod +x "$out"; fi
exit 0'

fixture_repo() {
	fixture=$work/fixture.$1
	rm -rf "$fixture"
	mkdir -p "$fixture/deploy"
	# -R because deploy/ has held a SUBDIRECTORY since 451555c (deploy/windows).
	# Without it `cp` refuses the directory and exits non-zero, `set -eu` kills
	# the suite here, and everything below this line silently stops running —
	# which is issue #158 and is why the tally is now asserted rather than
	# printed.
	cp -R "$here"/* "$fixture/deploy/"
	: >"$fixture/go.mod"
}

case_start 'the build path refuses a checkout with no VERSION file'
new_stage noversion
fixture_repo noversion
expect_refusal 'no VERSION file' node --role coordinator --deploy-dir "$fixture/deploy"
assert_absent "$stage/usr/local/bin/bacchus-coordinator"

# The four shapes somebody actually types. 1.0.0-rc1 is the one that matters
# most and the one most likely to be tried: it is an ordinary thing to want to
# call a release, this project has no such version at any layer (core/version
# models three integers and the fence orders on them), and a binary stamped with
# it builds and installs cleanly and then PANICS at startup on the machine it was
# installed on. Refused here, by name, is the whole point.
case_start 'the build path refuses a VERSION it cannot stamp'
for bad_version in v0.2.0 1.0.0-rc1 0.2 1.0.0+build.7; do
	new_stage "badversion.$bad_version"
	fixture_repo badversion
	printf '%s\n' "$bad_version" >"$fixture/VERSION"
	expect_refusal 'bare MAJOR\.MINOR\.PATCH' node --role coordinator --deploy-dir "$fixture/deploy"
	assert_absent "$stage/usr/local/bin/bacchus-coordinator"
	if [ "$bad_version" = '1.0.0-rc1' ]; then
		assert_grep "$work/out.log" 'pre-release' \
			'the refusal names the pre-release rule rather than leaving it to a panic'
	fi
done

case_start 'every built binary is stamped with the release VERSION names'
new_stage stamped
fixture_repo stamped
# Written the way a checkout that ignored .gitattributes would leave it: leading
# and trailing spaces and a CR. All of that has to come off before the value
# reaches the linker, because core/version.Parse rejects " 0.7.3" and
# core/version.Current PANICS on a stamp it cannot parse — so a CR surviving to
# here is not a cosmetic problem, it is every binary from this install dying at
# startup. The assertion below pins the value AND its boundary for that reason.
printf '  0.7.3 \r\n' >"$fixture/VERSION"
expect_ok node --role coordinator --deploy-dir "$fixture/deploy"
assert_grep "$calls" 'go build -ldflags -X github\.com/bacchus-vpn/bacchus/core/version\.current=0\.7\.3( |$)' \
	'the build stamps the normalised release onto the core/version.current symbol'
assert_file "$stage/usr/local/bin/bacchus-coordinator" 755

# The stub is scoped to this section. Nothing below builds, and a `go` on PATH
# that produces a working stand-in without compiling anything must not be able to
# make a later case pass.
rm -f "$stubdir/go"

# ---------------------------------------------------------------------------
# The pipe, and the property that makes it safe
# ---------------------------------------------------------------------------
#
# `curl … | sh` is a supported shape. What makes it safe is not a check the
# script performs but a property of its LAYOUT: every side effect lives behind
# the final `case $mode` dispatch, which is the last statement in the file, so a
# shell fed a truncated download executes only function definitions and argument
# parsing and writes nothing.
#
# That is a guarantee one well-meaning top-level statement above the dispatch
# would silently destroy, and no amount of reading the file proves it stayed
# true. So it is asserted behaviourally: truncate the script across a spread of
# byte offsets, pipe each fragment into `sh` exactly as curl would, and require
# that not one file was placed.

case_start 'the complete script installs when piped into sh (the shape #18 asks for)'
new_stage pipefull
# --deploy-dir because a pipe gives the script no directory of its own: $0 is
# the shell's name, so it cannot find the units beside itself.
set +e
BACCHUS_ROOT=$stage sh -c 'cat "$1" | sh -s client --user "$2" --binaries "$3" --deploy-dir "$4"' \
	_ "$installer" "$user" "$bins" "$here" >"$work/out.log" 2>&1
rc=$?
set -e
if [ "$rc" = '0' ]; then
	ok 'piping the whole script into sh exits 0'
else
	bad "piping the whole script into sh exited $rc"
	sed 's/^/        | /' "$work/out.log"
fi
assert_present "$stage/usr/local/bin/bacchus-fyne"
assert_present "$stage/etc/systemd/system/bacchus-netd.socket"

case_start 'a truncated download installs nothing, at every offset'
total=$(wc -c <"$installer")
truncated_runs=0
dirty=''
# A spread across the whole file, plus the two offsets that matter most: just
# short of the final dispatch, and one byte short of the end.
offsets=''
i=1
while [ "$i" -lt 40 ]; do
	offsets="$offsets $((total * i / 40))"
	i=$((i + 1))
done
# Plus the three boundary offsets, which are the ones with something to say:
#   pre        — everything except the dispatch. Every function defined, none
#                called. This is the case the whole property rests on.
#   pre + 20   — partway into the dispatch's own compound command.
#   total - 5  — the entire file except the closing `esac`, so the `case` is
#                unterminated and the shell cannot run it.
#
# Deliberately NOT total-1: the last byte is the newline after `esac`, so that
# offset is a COMPLETE script and installs correctly. It looked like a
# tempting "almost the whole file" case and it is really a positive control —
# which the piped-full-script case above already covers properly.
# A grep PATTERN, not a string to expand: the \$ matches the literal dollar in
# the installer's own `case $mode in` line. Expanding it here would search for
# whatever this suite happens to have in $mode, which is nothing.
# shellcheck disable=SC2016
dispatch_at=$(grep -n '^case \$mode in' "$installer" | cut -d: -f1)
pre=$(head -n "$((dispatch_at - 1))" "$installer" | wc -c)
offsets="$offsets $pre $((pre + 20)) $((total - 5))"

for off in $offsets; do
	frag_stage=$work/stage.trunc
	rm -rf "$frag_stage"
	mkdir -p "$frag_stage/run/systemd/system"
	set +e
	head -c "$off" "$installer" |
		BACCHUS_ROOT=$frag_stage sh -s client --user "$user" --binaries "$bins" --deploy-dir "$here" \
			>/dev/null 2>&1
	set -e
	truncated_runs=$((truncated_runs + 1))
	# Anything at all outside the /run/systemd/system fixture means the fragment
	# wrote something, which is the failure this case exists to catch.
	placed=$(find "$frag_stage" -mindepth 1 \
		-not -path "$frag_stage/run" \
		-not -path "$frag_stage/run/systemd" \
		-not -path "$frag_stage/run/systemd/system" 2>/dev/null)
	if [ -n "$placed" ]; then
		dirty="$dirty
  at byte $off: $(printf '%s' "$placed" | tr '\n' ' ')"
	fi
done
rm -rf "$work/stage.trunc"

if [ -z "$dirty" ]; then
	ok "$truncated_runs truncated fragments piped into sh, none placed a file or wrote a unit"
else
	bad "truncated fragments wrote something — a top-level side effect has appeared above the final dispatch:$dirty"
fi

case_start 'unknown mode is a usage error, not a refusal'
set +e
sh "$installer" wibble >"$work/out.log" 2>&1
rc=$?
set -e
if [ "$rc" = '2' ]; then
	ok 'an unknown mode exits 2 with usage'
else
	bad "an unknown mode exited $rc, wanted 2"
fi

# ---------------------------------------------------------------------------
# Real absolute paths, in a namespace, where one is available.
# ---------------------------------------------------------------------------
#
# The staging root above proves placement RELATIVE to a prefix. This case
# removes the prefix: it runs the installer with --root '/' against real
# absolute paths, inside a user+mount namespace where /usr/local, /etc and /run
# are tmpfs. That closes the one gap a prefix leaves — a path-joining bug that
# only shows up when the prefix is empty — and it is the same trick
# cmd/bacchus-netd's tests use to get a real kernel without root.
#
# BACCHUS_INSTALL_TEST_REQUIRE_NS turns the skip into a failure, and CI sets it.
# Same shape and same reason as BACCHUS_NETD_REQUIRE_NS and
# BACCHUS_REQUIRE_STAMP in ci.yml: this is the only case that runs at a real
# absolute path, and a runner that quietly lost the capability would report a
# green job over the one thing a staging prefix cannot check. A developer's
# machine without user namespaces still skips, and the tally names the skip.
case_start 'real absolute paths inside a user+mount namespace'
if ! unshare -Urm --propagation private true 2>/dev/null; then
	if [ -n "${BACCHUS_INSTALL_TEST_REQUIRE_NS:-}" ]; then
		bad 'unprivileged user+mount namespaces are unavailable, and BACCHUS_INSTALL_TEST_REQUIRE_NS demands them'
	else
		skip 'unprivileged user+mount namespaces are unavailable on this host'
	fi
else
	nsout=$work/ns.log
	set +e
	# The single-quoted body is the inner shell's script, and $1/$2/$3 are the
	# arguments handed to it after the `_` at the bottom of this command. It
	# must reach that shell unexpanded — this one has no positional parameters
	# to give it.
	# shellcheck disable=SC2016
	unshare -Urm --propagation private sh -c '
		set -eu
		mount -t tmpfs none /usr/local
		mount -t tmpfs none /etc/systemd
		mount -t tmpfs none /run
		mkdir -p /run/systemd/system /etc/systemd/system
		sh "$1" client --user "$2" --binaries "$3" >/dev/null 2>&1
		[ -f /usr/local/bin/bacchus-fyne ] || { echo "MISSING /usr/local/bin/bacchus-fyne"; exit 1; }
		[ -f /usr/local/lib/bacchus/bacchus-netd ] || { echo "MISSING helper"; exit 1; }
		[ -f /etc/systemd/system/bacchus-netd.socket ] || { echo "MISSING socket unit"; exit 1; }
		[ "$(stat -c %a /usr/local/lib/bacchus/bacchus-netd)" = 755 ] || { echo "BAD helper mode"; exit 1; }
		sh "$1" uninstall client --user "$2" --keep-config >/dev/null 2>&1
		[ ! -e /usr/local/bin/bacchus-fyne ] || { echo "LEFTOVER gui"; exit 1; }
		[ ! -e /usr/local/lib/bacchus ] || { echo "LEFTOVER libexec dir"; exit 1; }
		[ ! -e /etc/systemd/system/bacchus-netd.socket ] || { echo "LEFTOVER socket unit"; exit 1; }
		echo NS-OK
	' _ "$installer" "$user" "$bins" >"$nsout" 2>&1
	rc=$?
	set -e
	if [ "$rc" = '0' ] && grep -q NS-OK "$nsout"; then
		ok 'install and uninstall at real absolute paths, verified against the real filesystem'
	else
		bad "namespace run failed (rc=$rc):"
		sed 's/^/        | /' "$nsout"
	fi
fi

# ---------------------------------------------------------------------------

# The last statement in the file, and the only thing that sets this. finish()
# reads it: an unset value means the run stopped somewhere above, whatever the
# counters happen to say.
reached_the_end=yes
