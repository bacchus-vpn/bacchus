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
# WHY THIS IS NOT `curl … | sh`
# ---------------------------------------------------------------------------
#
# The card names that shape. This script deliberately refuses it, for three
# reasons, of which only the first is a matter of taste:
#
#  1. It does not work. Piping into `sh` makes the script itself the shell's
#     standard input, so a script that ever needs to read from the terminal
#     reads its own source instead. Every confirmation an installer for a
#     security tool ought to be able to ask becomes structurally impossible. The
#     usual workaround — never prompt — is the wrong direction for a program
#     that installs a root-privileged helper.
#
#  2. `sh` executes the pipe as it arrives. A connection that dies at 60% does
#     not produce a failed install; it produces a PARTIAL one, with no error and
#     no record of where it stopped. For an installer whose job includes
#     arranging a fail-closed kill-switch, half-applied is the worst outcome
#     available.
#
#  3. There is nothing to check. Our users are, by construction, the population
#     most likely to be behind an adversary that can intercept TLS or serve a
#     substituted response. `curl | sh` asks exactly those users to execute an
#     unexamined artifact as root, with no step in between where a signature, a
#     checksum or a human's eyes could intervene.
#
# So: download the file, look at it or verify it, then run it. That is three
# lines instead of one, and the third line is identical either way. To keep the
# distinction from being merely advisory, the script exits if it cannot find its
# own source on disk — see require_own_source below.
#
# Once issue #34 [G7] signs releases, the recommended flow gains the step that
# makes it worth the extra lines: fetch the tarball, verify its signature
# against a key obtained out of band, THEN run this. That is a story `curl | sh`
# can never tell, because the verification has nowhere to happen.
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

# bacchus_install_marker — require_own_source greps for this exact string to
# confirm that the file $0 names really is this script. Do not remove it.

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

common options:
  --no-start         install and enable units but do not start them.
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

# require_own_source is the `curl | sh` refusal described in the header. When a
# script is piped into a shell, $0 is the shell's own name and there is no file
# behind it; when it is run normally, $0 names a readable file containing this
# script's marker. The marker check rather than a bare -f test is deliberate:
# $0 is "sh" under a pipe, and a directory that happened to contain a file
# called "sh" would otherwise satisfy -f.
require_own_source() {
	if [ ! -f "$0" ] || [ ! -r "$0" ] || ! grep -q 'bacchus_install_marker' "$0" 2>/dev/null; then
		refuse "this installer will not run from a pipe." \
			"It looks like it was invoked as 'curl ... | sh', which cannot be done" \
			"safely: the shell executes the script as it arrives, so a connection" \
			"that drops leaves a PARTIAL install with no error, and there is no" \
			"point at which you could have checked what you were about to run as" \
			"root. Download it, look at it, then run it:" \
			"" \
			"  curl -fsSLO https://raw.githubusercontent.com/bacchus-vpn/bacchus/main/deploy/install.sh" \
			"  less install.sh" \
			"  sudo sh install.sh client" \
			"" \
			"Once releases are signed (issue #34) the middle step becomes a" \
			"signature check against a key you obtained out of band."
	fi
}

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
install_file() {
	src=$1
	dest=$(p "$2")
	mode=$3
	[ -f "$src" ] || die "missing file to install: $src"
	install -D -m "$mode" "$src" "$dest"
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
		log "building $name from source (this can take a minute)" >&2
		( cd "$repo_root" && go build -o "$build_dir/$name" "$pkg" ) || build_failed "$name"
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

# seed_client_config writes the per-user config, and WHERE it writes is the
# point.
#
# clients/fyne looks for its config next to the executable first and in the
# user's config directory second, and DefaultConfigPath — where Settings saves
# when it loaded nothing — is the FIRST of those. With the GUI in
# /usr/local/bin, a fresh install with no config would therefore try to save to
# /usr/local/bin/bacchus-fyne.config.json, which the desktop user cannot write.
# Seeding the per-user copy here means LoadConfig finds a file, reports that
# path, and Settings saves back to the same writable place. This is worked
# around here rather than fixed there because clients/ is not this change's to
# touch; it is filed as a follow-up.
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

client_next_steps() {
	cat <<EOF

$progname: the client is installed. Two things left, and the first one bites
$progname: everybody:

$progname:   1. LOG OUT AND BACK IN. A session's supplementary groups are fixed
$progname:      at login, so $desktop_user is not yet effectively in the bacchus
$progname:      group in any shell or desktop session that is already running.
$progname:      Until then the client will report the helper as unreachable.

$progname:   2. Fill in a coordinator. The seeded config is the example
$progname:      template and points at placeholder hosts:
$progname:        \$HOME/.config/Bacchus/fyne-client.json
$progname:      Set "coordinators", "stun", "turn" and "turnPass" to your
$progname:      network's, or use the app's Settings window.

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

require_own_source

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

# deploy_dir is where the unit files live: this script's own directory, always,
# because the units ship beside it. repo_root is only consulted when something
# has to be BUILT, which --binaries skips entirely.
deploy_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$deploy_dir/.." && pwd)

if [ -n "$binaries_dir" ] && [ ! -d "$binaries_dir" ]; then
	refuse "--binaries $binaries_dir is not a directory"
fi

cleanup() { [ -z "$build_dir" ] || rm -rf "$build_dir"; }
trap cleanup EXIT INT TERM

case $mode in
client) install_client ;;
node) install_node ;;
uninstall) do_uninstall ;;
esac
