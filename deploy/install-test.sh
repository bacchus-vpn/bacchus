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
# systemd and root, which means a container or a VM. The repo's CI has no
# container runtime step for this, so CI DOES NOT RUN ANY OF IT — not this file
# and not the real-system checks. The manual procedure is at the bottom of this
# file under REAL-SYSTEM CHECKLIST, and it is what has to be run by hand on a
# disposable machine before this is called verified.

set -eu

failures=0
checks=0
current=''

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
installer=$here/install.sh

work=$(mktemp -d)
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

make_stub systemctl 'exit 0'
make_stub usermod 'exit 0'
make_stub groupadd 'for a; do case $a in -*) ;; *) echo "$a" >>"'"$fake_groups"'";; esac; done; exit 0'
make_stub groupdel 'grep -vx "$1" "'"$fake_groups"'" >"'"$fake_groups"'.n" || true; mv "'"$fake_groups"'.n" "'"$fake_groups"'"; exit 0'
make_stub systemd-sysusers 'echo bacchus >>"'"$fake_groups"'"; exit 0'

# getent is only intercepted for `group`; `passwd` falls through to the real one
# so that the desktop user's home directory is resolved the way the installer
# will really resolve it (and then prefixed by --root, which is what keeps this
# test out of the real home directory).
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
	ok 'exits non-zero with no --user and no $SUDO_USER'
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

case_start 'refuses to run from a pipe'
set +e
out=$(cat "$installer" | sh 2>&1)
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
	ok "piping into sh exits non-zero ($rc)"
else
	bad 'piping into sh was accepted'
fi
if printf '%s' "$out" | grep -q 'will not run from a pipe'; then
	ok 'the pipe refusal explains itself'
else
	bad "the pipe refusal did not fire; got: $out"
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
case_start 'real absolute paths inside a user+mount namespace'
if ! unshare -Urm --propagation private true 2>/dev/null; then
	printf '   SKIP unprivileged user+mount namespaces are unavailable on this host\n'
else
	nsout=$work/ns.log
	set +e
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

printf '\n%s checks, %s failures\n' "$checks" "$failures"
[ "$failures" = '0' ] || exit 1

cat <<'EOF'

REAL-SYSTEM CHECKLIST — none of the above ran systemd, and CI does not run any
of this file. On a disposable machine with systemd (a VM, or a container booted
with systemd as PID 1), as root:

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
