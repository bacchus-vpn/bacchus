#!/bin/sh
# Install, or completely remove, a Bacchus Linux client or a Bacchus server node
# (issue #18).
#
# usage:
#   install.sh client   [options]
#   install.sh node --role coordinator|exit [options]
#   install.sh uninstall client|node|all [--purge] [--keep-config]
#   install.sh --help
#
# Two modes, one script. The card that asked for this was written when the Linux
# client routed nothing and "installer" meant a server node; issue #37 changed
# that, and the CLIENT is now the half that cannot work without this file at all.
# It needs a helper binary, a systemd unit, a socket and a group, all placed with
# root, or clients/fyne refuses to connect. The two modes share the distribution
# preflight, the systemd handling, the idempotence rules and — the part that
# actually matters — the uninstaller. Splitting them into two scripts would
# duplicate all of that, and the half that would drift is uninstall: the half
# nobody exercises until they are in a hurry.
#
# ---------------------------------------------------------------------------
# `curl … | sh` WORKS, AND WHY THE RECOMMENDED PATH IS STILL DOWNLOAD-THEN-RUN
# ---------------------------------------------------------------------------
#
# The card names the pipe shape and it is supported. The structural reason it is
# safe here is the one property this file must not lose:
#
#   EVERY SIDE EFFECT IN THIS SCRIPT HAPPENS BEHIND THE FINAL `case $mode`
#   DISPATCH, WHICH IS THE LAST STATEMENT IN THE FILE.
#
# Above that line there is nothing but `set -eu`, variable assignments, function
# definitions, argument parsing, and read-only resolution of where the unit files
# are — all of which can print or exit, and none of which can write. `sh` executes
# a pipe as it arrives, so a download that dies at 60% executes only what arrived —
# and what arrived defines functions nobody calls. A truncated fetch therefore
# installs NOTHING, rather than leaving the half-applied install that would
# otherwise be the real hazard of this shape. It cannot even leave a syntax error
# halfway through a compound command, because a shell will not execute a `case`
# or a function body it has not seen the end of.
#
# That is a guarantee about the code's SHAPE, which means it can be broken later
# by a single well-meaning top-level statement added above the dispatch. So it is
# not left to reasoning: install-test.sh truncates this file at a spread of byte
# offsets, pipes each fragment into `sh`, and asserts that not one file was
# placed and not one unit written. If you add a top-level side effect above the
# dispatch, that test is what will tell you.
#
# The pipe is still not the RECOMMENDED path, for two reasons that survive:
#
#  1. There is nothing to check. Our users are, by construction, the population
#     most likely to be behind an adversary that can intercept TLS or serve a
#     substituted response. The pipe asks exactly those users to execute an
#     unexamined artifact as root, with no step in between where a signature, a
#     checksum or a human's eyes could intervene.
#
#  2. It forecloses ever asking a question. Piping makes this script the shell's
#     own standard input, so anything read from the terminal would read the
#     script's remaining source instead. Everything here is therefore driven by
#     flags, which is the right design anyway — but it is a constraint the pipe
#     imposes rather than one chosen freely, and it is worth knowing that is why.
#
# So the documented recommendation is: download the file, look at it, then run
# it. Three lines instead of one, of which the third is identical either way.
#
# Once issue #34 [G7] signs releases this stops being a recommendation and
# becomes the only path: fetch the tarball, verify its signature against a key
# obtained out of band, THEN run this. That is the argument that eventually
# retires the one-liner, because a signature check has nowhere to happen inside
# a pipe. It is not this change.
#
# ---------------------------------------------------------------------------
# WHAT IT REFUSES, AND WHY IT CHECKS CAPABILITIES RATHER THAN DISTRIBUTIONS
# ---------------------------------------------------------------------------
#
# There is no distribution whitelist here on purpose. A whitelist answers the
# wrong question: nothing this script does is Debian-shaped or Fedora-shaped. It
# needs systemd, coreutils' `install`, and shadow-utils' `groupadd`/`usermod`.
# Every distribution that has those three works, including ones that did not
# exist when this was written; every distribution that lacks one of them fails
# in a way a whitelist would have described as "unsupported" without saying what
# was missing. So each capability is probed and named individually, and a
# missing one is a refusal that says which and what to do instead.
#
# A refusal is always preferred to a guess. A half-written unit on a host this
# script did not understand is worse than no unit at all: it survives reboots,
# it looks installed, and the failure it produces is at connect time.
#
# ---------------------------------------------------------------------------
# SECRETS
# ---------------------------------------------------------------------------
#
# An exit's EXIT_KEY is its permanent identity — its node id IS its X25519
# public key. It is generated HERE, on the host that will use it, at install
# time, and it never travels: not to a build machine, not through a terminal, not
# into a log. It is written directly into /etc/bacchus/node.env (mode 0600) by a
# subshell with tracing disabled, so that even `sh -x install.sh` cannot echo it.
# Nothing in this file prints a key, and re-running the installer never
# regenerates one that already exists.

set -eu

progname='bacchus-install'

# ---------------------------------------------------------------------------
# Paths. Every one of them goes through p(), so that a staging root can be
# prefixed for testing and packaging (see --root below). In a real install root
# is "/" and p() is the identity.
# ---------------------------------------------------------------------------

#
# BACCHUS_ROOT is the environment spelling of --root, for callers that find it
# easier to set than to thread a flag through. It is read here so that an
# explicit --root on the command line still wins over it.
root=${BACCHUS_ROOT:-/}

p() { printf '%s' "${root%/}$1"; }

# The GUI is a command a user runs; the helper deliberately is not (deploy/README
# makes this point) — it is started by systemd when the client connects, and a
# user who runs it by hand has misunderstood something. Hence libexec-style
# placement under /usr/local/lib rather than a second entry in $PATH.
bin_dir='/usr/local/bin'
libexec_dir='/usr/local/lib/bacchus'
unit_dir='/etc/systemd/system'
etc_dir='/etc/bacchus'
runtime_dir='/run/bacchus'
desktop_dir='/usr/local/share/applications'

# ---------------------------------------------------------------------------
# Output. Everything informational goes to stdout, everything diagnostic to
# stderr, and nothing anywhere carries a key.
# ---------------------------------------------------------------------------

log() { printf '%s: %s\n' "$progname" "$*"; }
warn() { printf '%s: WARNING: %s\n' "$progname" "$*" >&2; }

die() {
	printf '%s: ERROR: %s\n' "$progname" "$*" >&2
	exit 1
}

# refuse is die for a host this script has decided not to touch. The distinction
# is worth having in the output: an error means something went wrong partway, a
# refusal means NOTHING was changed and the operator can act on the advice and
# start over.
refuse() {
	printf '%s: REFUSING: %s\n' "$progname" "$1" >&2
	shift
	for line in "$@"; do
		printf '%s:   %s\n' "$progname" "$line" >&2
	done
	printf '%s: nothing was installed or changed.\n' "$progname" >&2
	exit 1
}

usage() {
	cat <<'EOF'
usage:
  install.sh client   [options]              install the Linux desktop client
  install.sh node --role coordinator|exit    install a server node
  install.sh uninstall client|node|all       remove what was installed
  install.sh --help

client options:
  --user NAME        desktop user to add to the bacchus group and seed config
                     for. Defaults to $SUDO_USER. Required if that is unset.
  --binaries DIR     use prebuilt bacchus-fyne / bacchus-netd from DIR instead
                     of building from source.

node options:
  --role coordinator|exit    which node this box is. Required.
  --binaries DIR             use prebuilt binaries from DIR (the usual server
                             case: cross-built on a dev machine and copied over,
                             so the server needs no Go toolchain).

uninstall options:
  --purge            also remove /etc/bacchus. For a node this destroys the
                     exit's persistent identity and the coordinator's signing
                     key, so it is not the default.
  --keep-config      (client) keep the per-user config file.

  "all" means both INSTALLS, not "and the keys too". It removes the client and
  the node, purging the client's config (which is replaceable) and keeping
  /etc/bacchus (which is not) exactly as the two separate commands would. There
  is one rule here and "all" does not override it: irreplaceable state goes only
  when you ask for it with --purge. Uninstall says which it did, either way.

common options:
  --no-start         install and enable units but do not start them.
  --deploy-dir DIR   where the .service/.socket/.env.example files are. Defaults
                     to this script's own directory, then ./deploy, then the
                     working directory. Needed when the script was piped in,
                     since a pipe gives it no directory of its own.
  --root DIR         prefix every path with DIR. For packaging and for this
                     script's own tests; it is NOT a way to install into a
                     chroot you then boot, because the systemd and group work
                     still happens against the running system.
  --help             this text.
EOF
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || refuse "$1 is not installed, and this script needs it." "$2"
}

need_root() {
	# A staging root is a file-placement exercise, not an install, so it does not
	# need privilege. A real install does.
	[ "$root" = '/' ] || return 0
	[ "$(id -u)" = '0' ] || refuse "this must run as root." \
		"It installs binaries into $bin_dir, systemd units into $unit_dir," \
		"and creates a system group. Re-run it with sudo."
}

# systemd_booted mirrors sd_booted(3): the presence of /run/systemd/system is
# the documented test for "this system is running systemd", and it is true only
# when systemd is PID 1 — unlike the mere existence of a systemctl binary, which
# plenty of non-systemd hosts have installed as a dependency of something else.
systemd_booted() { [ -d "$(p /run/systemd/system)" ]; }

require_systemd() {
	systemd_booted && return 0
	refuse "this host is not running systemd, and every unit here is a systemd unit." \
		"Writing them anyway would leave files that look installed and do" \
		"nothing. Bacchus itself does not require systemd — ADR-0049 records" \
		"that socket activation is an optimisation, not a requirement, and" \
		"bacchus-netd is a plain binary listening on a unix socket that any" \
		"supervisor can start. What it needs is: the binary in place, the" \
		"bacchus group created, and something that starts it with CAP_NET_ADMIN" \
		"and hands it a 0660 root:bacchus socket at /run/bacchus/netd.sock." \
		"A host with no systemd-logind also has no way to answer 'does this uid" \
		"own an active local session', so the helper needs" \
		"-allow-without-logind there, which drops the gate to the socket's group" \
		"permission alone. That is a real weakening; it is opt-in for that" \
		"reason." \
		"" \
		"The manual steps are in deploy/README.md."
}

# require_platform checks the things every mode needs, in the order that gives
# the most useful first failure.
require_platform() {
	[ "$(uname -s)" = 'Linux' ] || refuse "this installs systemd units and a Linux TUN helper; this host is $(uname -s)."
	need_root
	require_systemd
	need_cmd install 'It is part of coreutils, which this host appears to be missing.'
	need_cmd systemctl 'systemd is running but systemctl is not on PATH, which should not happen.'
}

# ---------------------------------------------------------------------------
# Idempotent primitives
# ---------------------------------------------------------------------------

# install_file overwrites unconditionally, which is what makes re-running safe:
# there is no "already there" branch to get wrong, and an upgrade is just
# another run.
# file_mode rather than mode: sh has no function scope, so `mode=$3` here
# assigns the SAME variable the final dispatch switches on (`case $mode in`,
# at the bottom of this file). Nothing reads it after the dispatch begins, so
# this was not a live bug — it was one edit away from being one, in a script
# where the wrong branch of that case is an uninstall.
install_file() {
	src=$1
	dest=$(p "$2")
	file_mode=$3
	[ -f "$src" ] || die "missing file to install: $src"
	install -D -m "$file_mode" "$src" "$dest"
	log "installed $dest"
}

# install_group creates the group only if it is absent. groupadd --system is not
# reached twice, so a second run neither fails nor creates a duplicate.
install_group() {
	if getent group bacchus >/dev/null 2>&1; then
		log "group bacchus already exists"
		return 0
	fi
	# Prefer the sysusers file over an open-coded groupadd: it is the declared
	# definition of this group, it lives next to the units, and going through it
	# means a change there is followed here rather than silently diverging.
	if command -v systemd-sysusers >/dev/null 2>&1 && [ -f "$deploy_dir/bacchus-netd.sysusers.conf" ]; then
		systemd-sysusers "$deploy_dir/bacchus-netd.sysusers.conf"
	else
		groupadd --system bacchus
	fi
	log "created system group bacchus"
}

# add_to_group is idempotent in usermod itself: -aG with a group the user is
# already in is a no-op that succeeds.
add_to_group() {
	user=$1
	usermod -aG bacchus "$user"
	if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx bacchus; then
		log "user $user is in group bacchus"
	fi
}

systemd_reload() { systemctl daemon-reload; }

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

# gen_hex32 prints 64 hex characters and is the ONLY place a key is produced.
# The subshell disables tracing first so that running this script under `sh -x`
# — which an operator debugging a failed install is quite likely to do — cannot
# echo a freshly minted exit identity into a terminal or a journal.
gen_hex32() {
	(
		set +x
		if command -v openssl >/dev/null 2>&1; then
			openssl rand -hex 32
		else
			od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
			printf '\n'
		fi
	)
}

# ensure_exit_key fills in an empty EXIT_KEY= line, and leaves a populated one
# strictly alone. That second half is not politeness, it is correctness: the key
# IS the exit's node id, so regenerating it on an upgrade would silently change
# the identity clients pinned and invalidate every learned path pointing at this
# box.
ensure_exit_key() {
	env_file=$1
	if grep -q '^EXIT_KEY=.\{16,\}' "$env_file"; then
		log "EXIT_KEY already set in $env_file — left untouched (it is this exit's permanent identity)"
		return 0
	fi
	tmp="$env_file.tmp.$$"
	old_umask=$(umask)
	umask 077
	: >"$tmp"
	umask "$old_umask"
	# The key is piped straight from gen_hex32 into the file. It is never
	# assigned to a shell variable that something later might print, and never
	# passed as an argument, where it would be visible in /proc/*/cmdline to
	# every local user for as long as the process lives.
	{
		grep -v '^EXIT_KEY=' "$env_file" || true
		printf 'EXIT_KEY='
		gen_hex32
	} >"$tmp"
	chmod 600 "$tmp"
	mv "$tmp" "$env_file"
	log "generated a persistent EXIT_KEY into $env_file (not printed here, and it never leaves this host)"
}

# ---------------------------------------------------------------------------
# Env files
# ---------------------------------------------------------------------------

# install_env_file copies a template into place ONLY if nothing is there. An env
# file is the one thing in this install that holds operator-entered values and a
# secret, so overwriting it on a re-run would be the single most destructive
# thing this script could do.
install_env_file() {
	template=$1
	dest=$(p "$2")
	if [ -f "$dest" ]; then
		log "$dest already exists — left untouched"
		return 0
	fi
	install -D -m 0600 "$template" "$dest"
	log "created $dest from the template (mode 0600)"
}

# has_placeholders reports whether an env file still carries the template's
# fill-me-in markers. A unit started against those does not fail cleanly; it
# crash-loops with a Restart=always in front of it.
has_placeholders() { grep -qE 'CHANGE_ME|YOUR_[A-Z_]+' "$1"; }

# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

# resolve_binary finds each binary either in --binaries DIR or by building it.
#
# --binaries exists because it is the documented server workflow and not a
# convenience: docs/RUNNING.md builds the Linux server binaries on a dev machine
# and copies them across, so requiring a Go toolchain on a VPS in order to
# install a node would be a new demand this card has no business making.
build_dir=''
binaries_dir=''

# release_version is the number every binary built here is stamped with, read
# from the repository's VERSION file — the single source of truth for it
# (issue #128). Empty until read_release_version runs, which prepare_build_dir
# does before the first build and --binaries skips along with the toolchain.
#
# Until #128 nothing stamped anything, so every binary this project had ever
# produced reported the same release into three mechanisms that compare one:
# a coordinator's -min-serving-version fence, the client's force-update check,
# and the coordinator's "this node is on a different build from me" warning.
# This script is one of THREE build paths that had to start agreeing on the
# number — the others are the manual builds in docs/RUNNING.md and CI — and the
# agreement is the whole point. A fence that some builds participate in and
# others do not is worse than one that never fires, because it fences an
# arbitrary subset and reports success either way.
release_version=''

# version_symbol is the linker symbol the number lands on, spelled out in full
# and in exactly one place because of HOW A WRONG ONE FAILS: `-X` naming a
# symbol that does not resolve is ignored by the linker, silently, with no
# warning and a zero exit. A typo here builds clean, installs clean, starts
# clean, and reports 0.0.0 for the life of the deployment. CI links this same
# string and reads the value back out of the linked binary
# (core/version.TestStampMatchesTheVersionFile), which is what keeps a rename on
# the Go side from quietly disabling this one.
version_symbol='github.com/bacchus-vpn/bacchus/core/version.current'

# version_valid accepts exactly what core/version.Parse accepts: three
# non-negative decimal components and nothing else. Deliberately not lenient.
# core/version.Current PANICS on a malformed stamp, so a "v0.2.0", a trailing
# "-rc1" or an editor's stray second line waved through here is not a build
# error to be fixed later — it is every binary from this install dying at
# startup on the machine it was installed on.
#
# The pre-release case is the one to expect, because it is the one somebody will
# reasonably try: "1.0.0-rc1" is an ordinary thing to want to call a release, and
# this project has no such version at any layer. core/version.Version is three
# integers and the fence/force policy (ADR-0015) orders on them, so a suffix is
# not a version that compares — only one that crashes. This refuses it here, by
# name, rather than letting it become a panic on a machine three weeks later.
version_valid() {
	case $1 in
	*[!0-9.]* | .* | *. | *..* | *.*.*.*) return 1 ;;
	*.*.*) return 0 ;;
	*) return 1 ;;
	esac
}

read_release_version() {
	version_file="$repo_root/VERSION"
	[ -f "$version_file" ] || refuse "no VERSION file at $version_file." \
		"One line at the root of the repository, holding the release number every" \
		"build is stamped with. This script will not build binaries that cannot say" \
		"which release they are, because a coordinator's version fence and its" \
		"build-skew warning both believe what a node reports." \
		"" \
		"Run from a complete checkout, or pass --binaries DIR with binaries built" \
		"elsewhere."
	# tr rather than `read`: a lone CR from a checkout that ignored .gitattributes
	# would otherwise ride into the -ldflags, and a stamp that core/version.Parse
	# rejects is a panic at startup rather than a failure here.
	release_version=$(tr -d ' \t\r\n' <"$version_file")
	version_valid "$release_version" || refuse "VERSION does not hold a release number." \
		"$version_file contains: $release_version" \
		"" \
		"It must be a bare MAJOR.MINOR.PATCH — 0.2.0. Not v0.2.0 (the TAG carries the" \
		"v, the file does not), not 0.2, and NOT a pre-release or build-metadata" \
		"suffix: 1.0.0-rc1 and 1.0.0+build.7 are not releases this project has. The" \
		"version model is three integers and the serving fence orders on them," \
		"so a suffix cannot be compared — only stamped, and then panicked on at" \
		"startup by every binary carrying it. This refuses it here instead."
}

# check_asn_table warns about the one thing in this checkout whose correctness
# expires on the CALENDAR rather than on the code: the IP→AS table behind
# AS-diverse hop selection (ADR-0044). It is embedded in the binary at build
# time, so a client built from an old clone carries an old table, and nothing at
# runtime can tell it so. `release.yml` puts a hard bar on that for the Windows
# artifacts; a Linux source install has no release to gate, which left the whole
# platform uncovered (issue #149).
#
# IT WARNS AND DOES NOT REFUSE, and that is the ruling rather than an oversight.
# The user this project exists for is on a censored network installing from the
# clone they managed to obtain. Refusing them a working client over a degradation
# that fails TOWARD ADR-0044 §3's unknown pooling — never toward a false claim of
# diversity — gets the trade backwards. An install is not a release.
#
# It runs the PACKAGE rather than `go test -run TestEmbeddedTableIsFresh`,
# because a -run filter matching nothing exits 0: a renamed test would silently
# turn this into a check that always passes, which is the linker's ignored-`-X`
# failure in a different costume.
check_asn_table() {
	log 'checking the age of the IP→AS table this build will embed'
	if ( cd "$repo_root" && go test ./core/asn/ >/dev/null 2>&1 ); then
		return 0
	fi
	warn 'the IP→AS table in this checkout did not pass its freshness check.'
	cat >&2 <<EOF
$progname:   go test ./core/asn/ failed on the tree about to be compiled, and an
$progname:   out-of-date table is what that test is there to catch. Run it by
$progname:   hand for the exact age; the table is embedded in the binary, so its
$progname:   age is this clone's age and no update after the build can fix it.
$progname:
$progname:   WHAT IS DEGRADED: AS-diversity scoring for multi-hop chains, and
$progname:   nothing else. A year-old table mis-scores roughly one verdict in
$progname:   nine (ADR-0044 §6) — toward counting a hop's network as unknown,
$progname:   never toward claiming diversity that is not there.
$progname:
$progname:   WHAT TO DO: update the clone and run this again.
$progname:
$progname:     git pull
$progname:
$progname:   Continuing anyway. This is a quality degradation and not a broken
$progname:   client, and a client you cannot install is worse than a stale table.
EOF
}

# prepare_build_dir makes the scratch directory in the CALLING shell, which is
# not a stylistic preference: resolve_binary is used as `x=$(resolve_binary …)`,
# and a variable assigned inside a command substitution is assigned in a
# subshell and lost. Creating it there would leak one temporary directory per
# binary and leave the EXIT trap with nothing to clean up.
prepare_build_dir() {
	if [ -n "$binaries_dir" ] || [ -n "$build_dir" ]; then
		return 0
	fi
	[ -f "$repo_root/go.mod" ] || refuse "no prebuilt binaries and no source tree." \
		"This script builds from the checkout it lives in, but $repo_root does" \
		"not look like one (no go.mod). Either run it from a clone, or pass" \
		"--binaries DIR pointing at binaries you built elsewhere."
	need_cmd go 'Install Go, or build elsewhere and pass --binaries DIR.'
	read_release_version
	check_asn_table
	build_dir=$(mktemp -d)
}

resolve_binary() {
	name=$1
	pkg=$2
	if [ -n "$binaries_dir" ]; then
		if [ ! -f "$binaries_dir/$name" ]; then
			refuse "--binaries $binaries_dir does not contain $name." \
				"Expected: $binaries_dir/$name"
		fi
		printf '%s' "$binaries_dir/$name"
		return 0
	fi
	if [ ! -f "$build_dir/$name" ]; then
		log "building $name $release_version from source (this can take a minute)" >&2
		( cd "$repo_root" && go build -ldflags "-X $version_symbol=$release_version" -o "$build_dir/$name" "$pkg" ) || build_failed "$name"
	fi
	printf '%s' "$build_dir/$name"
}

# build_failed turns the least helpful failure this script can produce into the
# most helpful one. clients/fyne is the first package in the repo needing a C
# toolchain (Fyne's desktop driver is cgo), so "build failed" on a fresh desktop
# is almost always a missing system library rather than anything about Go.
build_failed() {
	printf '%s: ERROR: building %s failed.\n' "$progname" "$1" >&2
	if [ "$1" = 'bacchus-fyne' ]; then
		cat >&2 <<'EOF'
bacchus-install:   The GUI links a C toolchain, an OpenGL stack and X11/Wayland
bacchus-install:   headers. A build that fails on a fresh desktop is almost
bacchus-install:   always one of those missing rather than a Go problem. The
bacchus-install:   package set this project builds against is:
bacchus-install:
bacchus-install:     Debian/Ubuntu: gcc libgl1-mesa-dev xorg-dev libwayland-dev \
bacchus-install:                    libxkbcommon-dev wayland-protocols
bacchus-install:     Fedora:        gcc mesa-libGL-devel libX11-devel libXcursor-devel \
bacchus-install:                    libXrandr-devel libXinerama-devel libXi-devel \
bacchus-install:                    libXxf86vm-devel wayland-devel libxkbcommon-devel
bacchus-install:
bacchus-install:   Those two are HINTS for the two distributions this project has
bacchus-install:   built on, not a supported-platform list. On anything else,
bacchus-install:   install your distribution's equivalents; the build error above
bacchus-install:   names the specific header or library it wanted.
EOF
	fi
	exit 1
}

# ---------------------------------------------------------------------------
# client
# ---------------------------------------------------------------------------

desktop_user=''
no_start=0

# resolve_desktop_user refuses rather than guessing. Installing the client
# involves two things done ON BEHALF OF a specific human — group membership and
# a config file in their home directory — and picking the wrong one produces an
# install that looks complete and cannot connect, because the user running the
# GUI is not the user in the group.
resolve_desktop_user() {
	[ -n "$desktop_user" ] || desktop_user=${SUDO_USER:-}
	[ -n "$desktop_user" ] || refuse "cannot tell which user will run the client." \
		"This adds a user to the bacchus group and seeds their config, so it" \
		"needs to know who. It normally reads \$SUDO_USER, which is empty here" \
		"— you are probably in a root shell rather than using sudo. Pass it:" \
		"" \
		"  install.sh client --user alice"
	id "$desktop_user" >/dev/null 2>&1 || refuse "no such user: $desktop_user"
	[ "$(id -u "$desktop_user")" != '0' ] || refuse "--user must be the desktop user, not root." \
		"The whole point of ADR-0049's split is that the GUI does NOT run as" \
		"root: it links a GL stack, a display client and a font renderer, none" \
		"of which belong in a process that can rewrite the route table."
}

install_client() {
	require_platform
	resolve_desktop_user
	prepare_build_dir

	fyne_bin=$(resolve_binary bacchus-fyne ./clients/fyne)
	netd_bin=$(resolve_binary bacchus-netd ./cmd/bacchus-netd)

	install_file "$fyne_bin" "$bin_dir/bacchus-fyne" 0755
	install_file "$netd_bin" "$libexec_dir/bacchus-netd" 0755

	install_group
	add_to_group "$desktop_user"

	install_file "$deploy_dir/bacchus-netd.service" "$unit_dir/bacchus-netd.service" 0644
	install_file "$deploy_dir/bacchus-netd.socket" "$unit_dir/bacchus-netd.socket" 0644

	install_desktop_entry
	seed_client_config

	systemd_reload
	# The SOCKET is enabled, not the service. The helper is socket-activated and
	# starts when the client first connects; enabling the service instead would
	# hold a root process open from boot for nothing, and is the single most
	# common way to get this pair wrong.
	if [ "$no_start" = '1' ]; then
		systemctl enable bacchus-netd.socket
		log "enabled bacchus-netd.socket (not started, --no-start)"
	else
		systemctl enable --now bacchus-netd.socket
		log "enabled and started bacchus-netd.socket"
	fi

	client_next_steps
}

# install_desktop_entry gives the GUI a launcher. Icon= names a freedesktop
# icon-naming-spec name rather than a file we ship, because this repo has no
# icon asset; a theme without it falls back to a generic launcher icon, which is
# a better outcome than a broken absolute path.
install_desktop_entry() {
	dest=$(p "$desktop_dir/bacchus.desktop")
	tmp="${TMPDIR:-/tmp}/bacchus.desktop.$$"
	cat >"$tmp" <<EOF
[Desktop Entry]
Type=Application
Name=Bacchus
GenericName=VPN
Comment=Route this device through the Bacchus network
Exec=$bin_dir/bacchus-fyne
Icon=network-vpn
Terminal=false
Categories=Network;Security;
StartupNotify=true
EOF
	install -D -m 0644 "$tmp" "$dest"
	rm -f "$tmp"
	log "installed $dest"
}

# seed_client_config writes the per-user config.
#
# This used to be load-bearing. clients/fyne saved a first config next to the
# executable, so with the GUI in /usr/local/bin a fresh install's first Save
# targeted a root-owned directory and failed on permissions; seeding the
# per-user copy here meant LoadConfig found a file, reported that path, and
# Settings saved back to it. That was a workaround for a client bug, and it
# masked the bug for installer users while leaving it live for anyone running a
# downloaded binary. Issue #118 fixed it where it belonged: a first Save now
# goes to the per-user directory whatever the binary's directory is, and
# SaveConfig creates that directory itself.
#
# So this is kept for what is left once the bug is gone: a first-run
# convenience. A new user gets the example template, with the keys they need to
# fill in already present and commented on by client_next_steps, instead of an
# app with no config file to edit. Removing it would break nothing and help
# nobody.
seed_client_config() {
	user_home=$(getent passwd "$desktop_user" | cut -d: -f6)
	[ -n "$user_home" ] || refuse "cannot resolve a home directory for $desktop_user"
	cfg_dir=$(p "$user_home/.config/Bacchus")
	cfg=$cfg_dir/fyne-client.json
	if [ -f "$cfg" ]; then
		log "$cfg already exists — left untouched"
		return 0
	fi
	install -d -m 0700 "$cfg_dir"

	example=$repo_root/clients/fyne/bacchus-fyne.config.example.json
	if [ -f "$example" ]; then
		install -m 0600 "$example" "$cfg"
		log "seeded $cfg from the example template"
	else
		# The script can be copied out of the repo and run on its own, in which
		# case the example is not beside it. A minimal file is still better than
		# none, because its ABSENCE is what sends Settings to an unwritable path;
		# the keys it needs to carry are the ones with no useful zero value.
		cat >"$cfg" <<'EOF'
{
  "coordinators": [],
  "stun": "",
  "turn": "",
  "turnUser": "bacchus",
  "turnPass": ""
}
EOF
		chmod 600 "$cfg"
		log "seeded a minimal $cfg (the example template was not beside this script)"
	fi

	# Both the directory and the file must end up owned by the desktop user: this
	# ran as root, so everything it just created is root's, and a config the user
	# cannot write is the exact problem this function exists to avoid. Tolerated
	# if it fails only because a staging root has no such user to chown to.
	chown -R "$desktop_user" "$cfg_dir" 2>/dev/null ||
		warn "could not chown $cfg_dir to $desktop_user — check it by hand"
}

# client_next_steps is the last thing a fresh user reads, so step 2 has to send
# them somewhere that can actually do the job.
#
# It used to end "…or use the app's Settings window", and the Settings window
# CANNOT set any of the five network keys: coordinators, stun, turn, turnUser and
# turnPass are file-only by design (clients/fyne/settings.go binds enforcement,
# transport, admission and volunteering — not these). So the one instruction a
# user cannot skip pointed at a dialog with no field for it. That is issue #134's
# defect, which everyone believed was Windows-only; it has been in this script the
# whole time. A Linux user installed the documented way does not hit #134's
# refusal — seed_client_config gives them a file — they hit its placeholder
# COORDINATOR_HOST instead and go looking in Settings for somewhere to change it.
#
# The path is printed resolved rather than as \$HOME, because it is the file they
# have to open and this script is the one process that knows whose home it is in.
client_next_steps() {
	cat <<EOF

$progname: the client is installed. Two things left, and the first one bites
$progname: everybody:

$progname:   1. LOG OUT AND BACK IN. A session's supplementary groups are fixed
$progname:      at login, so $desktop_user is not yet effectively in the bacchus
$progname:      group in any shell or desktop session that is already running.
$progname:      Until then the client will report the helper as unreachable.

$progname:   2. Fill in a coordinator, BY EDITING THE CONFIG FILE:
$progname:        $cfg
$progname:      It is the example template, so it points at a placeholder host
$progname:      (COORDINATOR_HOST) that resolves nowhere — connecting before you
$progname:      change it fails to dial. Set "coordinators", "stun", "turn" and
$progname:      "turnPass" to your network's ("turnUser" already has the usual
$progname:      value). Editing it needs no root: the file is yours.
$progname:
$progname:      These five keys are NOT in the app's Settings window and cannot
$progname:      be set from it — Settings covers the kill switch, split tunnel,
$progname:      DNS, transports, admission and volunteering. Do not go looking
$progname:      there for a coordinator field; there is not one (issue #134).

$progname: Then launch Bacchus from your application menu, or run
$progname: $bin_dir/bacchus-fyne.

$progname: To remove everything this just did:  sudo sh install.sh uninstall client
EOF
}

# ---------------------------------------------------------------------------
# node
# ---------------------------------------------------------------------------

node_role=''

install_node() {
	case $node_role in
	coordinator | exit) ;;
	'') refuse "node mode needs --role coordinator or --role exit." "  install.sh node --role exit" ;;
	*) refuse "unknown role: $node_role" "Valid roles are 'coordinator' and 'exit'." ;;
	esac

	require_platform
	install -d -m 0700 "$(p "$etc_dir")"

	if [ "$node_role" = 'coordinator' ]; then
		install_coordinator
	else
		install_exit
	fi
}

install_coordinator() {
	prepare_build_dir
	bin=$(resolve_binary bacchus-coordinator ./cmd/coordinator)
	install_file "$bin" "$bin_dir/bacchus-coordinator" 0755
	install_file "$deploy_dir/bacchus-coordinator.service" "$unit_dir/bacchus-coordinator.service" 0644
	install_env_file "$deploy_dir/coordinator.env.example" "$etc_dir/coordinator.env"

	# The country-database refresh belongs to the coordinator host and nowhere
	# else (deploy/README step 6): it is what makes each node's country DERIVED
	# rather than self-reported. Installing the timer here rather than leaving it
	# as a follow-up step is the difference between a coordinator that derives
	# countries and one that believes whatever a node claims.
	install_file "$deploy_dir/bacchus-geoip-refresh.sh" "$bin_dir/bacchus-geoip-refresh.sh" 0755
	install_file "$deploy_dir/bacchus-geoip-refresh.service" "$unit_dir/bacchus-geoip-refresh.service" 0644
	install_file "$deploy_dir/bacchus-geoip-refresh.timer" "$unit_dir/bacchus-geoip-refresh.timer" 0644

	systemd_reload
	start_or_explain bacchus-coordinator "$(p "$etc_dir/coordinator.env")"

	cat <<EOF

$progname: A coordinator also needs the country database staged before it can
$progname: derive any node's country. Enable the refresh timer and run it once:

$progname:   systemctl enable --now bacchus-geoip-refresh.timer
$progname:   systemctl start bacchus-geoip-refresh.service

$progname: Firewall: 8080/udp (signaling), 3478/udp (STUN/TURN + cold-start
$progname: bootstrap, issue #30), 49152:65535/udp (TURN relays).

$progname: Do NOT also run an exit on this box (issue #60) — one machine seeing
$progname: both the assignment and the egress defeats the separation the rest of
$progname: the design pays for. Give it --role relay capacity instead if it must
$progname: contribute. See docs/RUNNING.md.
EOF
}

install_exit() {
	prepare_build_dir
	bin=$(resolve_binary bacchus-node ./cmd/node)
	install_file "$bin" "$bin_dir/bacchus-node" 0755
	install_file "$deploy_dir/bacchus-exit.service" "$unit_dir/bacchus-exit.service" 0644
	install_env_file "$deploy_dir/node.env.example" "$etc_dir/node.env"
	ensure_exit_key "$(p "$etc_dir/node.env")"

	systemd_reload
	start_or_explain bacchus-exit "$(p "$etc_dir/node.env")"

	cat <<EOF

$progname: Firewall: 20000/tcp and 49152:65535/udp.

$progname: This exit's EXIT_KEY is its permanent identity and is stored only in
$progname: $(p "$etc_dir/node.env"). Back that file up if you want this exit to keep
$progname: the same id across a rebuild. It was never printed and never left
$progname: this host.
EOF
}

# start_or_explain is the "refuse rather than guess" rule applied to runtime.
# Starting a unit whose env file still says YOUR_VPS_PUBLIC_IP does not fail
# usefully — Restart=always turns it into a crash loop that fills the journal
# and looks like a bug in the binary. So an un-edited env file means the unit is
# installed and left stopped, with the exact remaining commands printed. A second
# run, after editing, starts it. That is also what makes this idempotent in the
# way that matters: the same command moves the box forward from either state.
start_or_explain() {
	unit=$1
	env_file=$2
	if has_placeholders "$env_file"; then
		log "$env_file still contains template placeholders — NOT starting $unit"
		cat <<EOF

$progname: $unit is installed but deliberately not started: $env_file
$progname: still has fill-me-in values in it. A unit started against those would
$progname: crash-loop behind Restart=always rather than fail once.

$progname:   1. edit $env_file
$progname:   2. re-run this installer, or: systemctl enable --now $unit
EOF
		return 0
	fi
	if [ "$no_start" = '1' ]; then
		systemctl enable "$unit"
		log "enabled $unit (not started, --no-start)"
		return 0
	fi
	systemctl enable --now "$unit"
	log "enabled and started $unit"
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------

purge=0
keep_config=0

# remove_unit stops, disables and deletes a unit, in that order, tolerating each
# step being unnecessary. `systemctl disable` on a unit file that is already gone
# cannot clean up its symlinks, so the order matters and is not just tidiness.
remove_unit() {
	unit=$1
	f=$(p "$unit_dir/$unit")
	if systemd_booted; then
		systemctl stop "$unit" 2>/dev/null || true
		systemctl disable "$unit" 2>/dev/null || true
	fi
	if [ -f "$f" ]; then
		rm -f "$f"
		log "removed $f"
	fi
}

remove_path() {
	f=$(p "$1")
	if [ -e "$f" ]; then
		rm -rf "$f"
		log "removed $f"
	fi
}

uninstall_client() {
	remove_unit bacchus-netd.socket
	remove_unit bacchus-netd.service
	remove_path "$libexec_dir/bacchus-netd"
	remove_path "$bin_dir/bacchus-fyne"
	remove_path "$desktop_dir/bacchus.desktop"
	# /run/bacchus is created by systemd as the parent of the socket's
	# ListenStream path, so it is ours to take away.
	remove_path "$runtime_dir"
	rmdir "$(p "$libexec_dir")" 2>/dev/null || true

	# The client config goes by default, and that IS the considered choice. A
	# client config holds no identity worth preserving, and a user of a
	# circumvention tool who uninstalls it usually means the residue to be gone
	# too — a leftover file naming the coordinators they used is exactly the
	# thing they were removing.
	if [ "$keep_config" = '1' ]; then
		log "keeping per-user client config (--keep-config)"
	else
		remove_client_configs
	fi

	remove_group
	if systemd_booted; then systemd_reload; fi
	log "client removed."
}

# remove_client_configs clears the config for whichever users have one. It looks
# at --user/$SUDO_USER first and otherwise sweeps home directories, because by
# uninstall time nobody remembers which account was used and leaving one behind
# silently is the failure this whole section exists to prevent.
remove_client_configs() {
	u=${desktop_user:-${SUDO_USER:-}}
	if [ -n "$u" ] && h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6) && [ -n "$h" ]; then
		remove_path "$h/.config/Bacchus"
		return 0
	fi
	getent passwd 2>/dev/null | cut -d: -f6 | sort -u | while read -r h; do
		[ -n "$h" ] || continue
		[ -d "$(p "$h/.config/Bacchus")" ] || continue
		remove_path "$h/.config/Bacchus"
	done
}

# remove_group deletes the group only when nothing still needs it. groupdel
# fails if it is some user's PRIMARY group, which is not a state this installer
# creates but is one an operator could have made by hand; the failure is
# reported rather than swallowed, because a leftover group is exactly the kind
# of residue "it reverses itself" is a claim about.
remove_group() {
	getent group bacchus >/dev/null 2>&1 || return 0
	if groupdel bacchus 2>/dev/null; then
		log "removed system group bacchus"
	else
		warn "could not remove the bacchus group — it is probably some user's primary group. Remove it by hand: groupdel bacchus"
	fi
}

uninstall_node() {
	remove_unit bacchus-exit.service
	remove_unit bacchus-coordinator.service
	remove_unit bacchus-geoip-refresh.timer
	remove_unit bacchus-geoip-refresh.service
	remove_path "$bin_dir/bacchus-node"
	remove_path "$bin_dir/bacchus-coordinator"
	remove_path "$bin_dir/bacchus-geoip-refresh.sh"

	# /etc/bacchus is NOT removed by default, and the asymmetry with the client
	# above is deliberate rather than an oversight. It holds an exit's EXIT_KEY —
	# a permanent identity clients may have pinned — the coordinator's
	# snapshot-signing key, and its issued bootstrap secrets. Destroying those
	# silently to be tidy would make a reinstall a different network rather than
	# the same one, so it takes an explicit --purge. The client has no such
	# state, which is why its config goes by default.
	if [ "$purge" = '1' ]; then
		remove_path "$etc_dir"
		remove_path '/var/lib/bacchus'
		log "purged node configuration and state"
	else
		if [ -d "$(p "$etc_dir")" ]; then
			cat <<EOF

$progname: KEPT $(p "$etc_dir") — it holds this box's persistent identity
$progname: (an exit's EXIT_KEY, or a coordinator's signing key and bootstrap
$progname: secrets). A reinstall will pick them up and the node keeps its id.
$progname: To destroy them as well:
$progname:   sudo sh install.sh uninstall node --purge
EOF
		fi
	fi

	if systemd_booted; then systemd_reload; fi
	log "node removed."
}

do_uninstall() {
	[ "$(uname -s)" = 'Linux' ] || die "not a Linux host"
	need_root
	case $uninstall_what in
	client) uninstall_client ;;
	node) uninstall_node ;;
	all)
		# "all" scopes WHICH INSTALLS are removed. It deliberately does not
		# change what --purge is for. A user typing "all" plainly means "get
		# everything off this box", and the temptation is to let the word carry
		# the keys with it — but the rule that decides this is whether the state
		# can be regenerated, and that does not become true because a wider word
		# was typed. An exit's EXIT_KEY is still the node id clients pinned; it
		# is still gone for good; and there is still no way to get it back after
		# a mistyped removal. So "all" is exactly `uninstall client` followed by
		# `uninstall node`, which means the client's replaceable config goes and
		# /etc/bacchus stays until --purge asks for it. The kept-state notice
		# prints here too, so nobody has to infer any of this.
		uninstall_client
		uninstall_node
		;;
	*) refuse "uninstall needs one of: client, node, all" ;;
	esac
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

mode=''
uninstall_what=''
deploy_dir=''
repo_root=''

[ "$#" -gt 0 ] || {
	usage >&2
	exit 2
}

case $1 in
-h | --help | help)
	usage
	exit 0
	;;
client | node)
	mode=$1
	shift
	;;
uninstall)
	mode=uninstall
	shift
	uninstall_what=${1:-}
	[ -n "$uninstall_what" ] || refuse "uninstall needs one of: client, node, all"
	case $uninstall_what in
	client | node | all) shift ;;
	*) refuse "uninstall needs one of: client, node, all" "Got: $uninstall_what" ;;
	esac
	;;
*)
	printf '%s: unknown mode: %s\n' "$progname" "$1" >&2
	usage >&2
	exit 2
	;;
esac

while [ "$#" -gt 0 ]; do
	case $1 in
	--role)
		node_role=${2:-}
		[ -n "$node_role" ] || die "--role needs a value"
		shift 2
		;;
	--role=*)
		node_role=${1#--role=}
		shift
		;;
	--user)
		desktop_user=${2:-}
		[ -n "$desktop_user" ] || die "--user needs a value"
		shift 2
		;;
	--user=*)
		desktop_user=${1#--user=}
		shift
		;;
	--binaries)
		binaries_dir=${2:-}
		[ -n "$binaries_dir" ] || die "--binaries needs a value"
		shift 2
		;;
	--binaries=*)
		binaries_dir=${1#--binaries=}
		shift
		;;
	--deploy-dir)
		deploy_dir=${2:-}
		[ -n "$deploy_dir" ] || die "--deploy-dir needs a value"
		shift 2
		;;
	--deploy-dir=*)
		deploy_dir=${1#--deploy-dir=}
		shift
		;;
	--root)
		root=${2:-}
		[ -n "$root" ] || die "--root needs a value"
		shift 2
		;;
	--root=*)
		root=${1#--root=}
		shift
		;;
	--purge)
		purge=1
		shift
		;;
	--keep-config)
		keep_config=1
		shift
		;;
	--no-start)
		no_start=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		printf '%s: unknown option: %s\n' "$progname" "$1" >&2
		usage >&2
		exit 2
		;;
	esac
done

# deploy_dir is where the unit files live. Normally that is this script's own
# directory, since the units ship beside it — but $0 is the shell's own name
# when the script is piped in, and `dirname sh` is not a useful answer. So the
# location is resolved from candidates and confirmed by a marker rather than
# assumed, and a run that cannot find them says so instead of failing later with
# "missing file to install: ./bacchus-netd.socket".
#
# repo_root is only consulted when something has to be BUILT, which --binaries
# skips entirely.
is_deploy_dir() {
	[ -f "$1/bacchus-netd.socket" ] && [ -f "$1/bacchus-coordinator.service" ]
}

resolve_deploy_dir() {
	if [ -n "$deploy_dir" ]; then
		is_deploy_dir "$deploy_dir" ||
			refuse "--deploy-dir $deploy_dir does not hold this project's unit files."
		return 0
	fi
	# $0's directory first (the ordinary case), then a checkout the caller is
	# standing in, which is what makes `curl … | sh` work from inside a clone.
	if [ -f "$0" ] && d=$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) && is_deploy_dir "$d"; then
		deploy_dir=$d
		return 0
	fi
	for d in "$PWD/deploy" "$PWD"; do
		if is_deploy_dir "$d"; then
			deploy_dir=$d
			return 0
		fi
	done
	refuse "cannot find this project's unit files (bacchus-netd.socket and friends)." \
		"They ship in the repository's deploy/ directory, beside this script, and" \
		"the installer needs them — it writes them, it does not generate them." \
		"" \
		"If you piped this script in, the shell gave it no directory of its own," \
		"so run it from a checkout instead, or point it at one:" \
		"" \
		"  git clone https://github.com/bacchus-vpn/bacchus" \
		"  sudo sh bacchus/deploy/install.sh client --user \"\$USER\"" \
		"" \
		"or:  sudo sh install.sh client --deploy-dir /path/to/bacchus/deploy" \
		"" \
		"Once releases are signed (issue #34) a release tarball will carry both" \
		"this script and the units together."
}

# Only an INSTALL needs the unit files. Uninstall removes things by path and
# reads nothing from the repository, which matters: somebody removing this in a
# hurry may well have deleted the checkout first, and "you cannot uninstall
# because you no longer have the source" would be an absurd thing to say to
# them.
if [ "$mode" != 'uninstall' ]; then
	resolve_deploy_dir
	repo_root=$(CDPATH='' cd -- "$deploy_dir/.." && pwd)
fi

if [ -n "$binaries_dir" ]; then
	if [ ! -d "$binaries_dir" ]; then
		refuse "--binaries $binaries_dir is not a directory"
	fi
	# Prebuilt binaries carry whatever release they were stamped with when they
	# were linked. This script never links them, so it can neither stamp them nor
	# read what they say — say so once rather than let the difference surface
	# three weeks later as a version fence with nothing to compare (issue #128).
	log "using prebuilt binaries from $binaries_dir: their release is whatever stamped them."
	log "  Cross-build them the way docs/RUNNING.md documents; a bare \`go build\` leaves"
	log "  a binary that reports 0.0.0 and warns at every start."
	# The same gap, for the other thing this script cannot see: check_asn_table
	# asserts something about a TREE, and on this path there is no tree. Named
	# rather than left silent, because a gap nobody states is one nobody closes
	# (issue #149).
	log "  Nor is the embedded IP→AS table checked here: these binaries carry whatever"
	log "  table their own checkout had. Check it there, before building:"
	log "    go test ./core/asn/          (ADR-0044)"
fi

cleanup() { [ -z "$build_dir" ] || rm -rf "$build_dir"; }
trap cleanup EXIT INT TERM

case $mode in
client) install_client ;;
node) install_node ;;
uninstall) do_uninstall ;;
esac
