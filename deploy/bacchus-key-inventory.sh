#!/bin/sh
# Answer "what key material does this box hold, and can this deployment account for all
# of it?" — without ever emitting any of it (issues #251, #227).
#
# usage: bacchus-key-inventory.sh --role exit|coordinator[,...] [--dir DIR]
#                                 [--expect NAME[,NAME...]] [--label L]
#        ssh <box> "sudo sh -s -- --role exit" < deploy/bacchus-key-inventory.sh
#
# It runs ON the box, because the questions are about files: it lists a directory, it
# stats what it finds, and it hashes secrets it never prints. Everything explanatory
# goes to stderr; the table goes to stdout.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS: BOTH FINDINGS WERE DISCOVERIES, NOT REPORTS
# ---------------------------------------------------------------------------
# Issue #227 found a second copy of an exit's EXIT_KEY in a stale `node.env.save`
# beside the live env file, while investigating something else. Issue #251 then found
# an operator CA private key, an admission authority key and an account-service TLS
# identity on a node box "by listing the directory for an unrelated reason, which is
# the whole problem". Nothing on any box uses that material and no inventory names it.
#
# Both are the same shape one level apart: KEY MATERIAL WITH NO LIFECYCLE. It is not
# rotated when the live key is, not removed when the box is decommissioned, not in any
# record, and — this is what makes it a defect rather than untidiness — the only way it
# has ever been found is somebody looking at something else.
#
# `bacchus-payment#23`, the adversarial security and privacy audit, is a v1 card. An
# audit that discovers a second copy of a private key by reading files by hand is an
# audit spending its budget on something a script should have found first. This is that
# script.
#
# ---------------------------------------------------------------------------
# THE RULE IT CHECKS: A BOX HOLDS WHAT ITS ROLE NAMES, AND ONE COPY OF EACH
# ---------------------------------------------------------------------------
# Two halves, and they are the two cards:
#
#   * ONE COPY PER NODE (#227). A node's key is both a secret and an identity — its
#     node id IS its X25519 public key — so a second copy is a second private key with
#     none of the attention the live one gets, and a name like `.save` is one restore
#     away from reinstating an identity the signed directory does not name. The rule
#     is stated in deploy/node.env.example, printed by deploy/install.sh after it
#     provisions an exit, and written up in deploy/README.md. Until this script,
#     nothing could FIND a copy.
#
#   * A BOX HOLDS WHAT ITS ROLE NAMES (#251). Anything else is reported UNACCOUNTED —
#     not condemned. An operator who deliberately keeps something says so with
#     --expect, which is the same shape as COORDINATOR_GATES in deploy/testbed.env:
#     the deployment describes itself, and what it does not describe is visible rather
#     than discovered. #251's step 3 asks for exactly that recording.
#
# The manifest below is what each role's own units, templates and flag defaults name.
# It is not a list somebody typed once: deploy/key_inventory_test.go reads the paths
# out of deploy/bacchus-coordinator.service, deploy/bacchus-exit.service,
# deploy/coordinator-gates.env.example and cmd/coordinator's `secrets/…` flag defaults
# and fails if any of them is missing from here. A file the deployment learns to write
# and this script does not know about would otherwise be reported as a finding on every
# box, forever, which is how a check gets switched off.
#
# ---------------------------------------------------------------------------
# NOTHING IT CAN PRINT IS A SECRET, AN ADDRESS OR A HOSTNAME
# ---------------------------------------------------------------------------
# This is the property the whole file is arranged around, because the natural
# debugging instinct — echo what you found — is the one thing that must not happen in
# a tool that reads private keys, and because this repository is PUBLIC and its output
# ends up pasted into issues.
#
#   * It prints PATHS and never CONTENT. No file is ever cat'd, no line is ever
#     echoed, no value ever becomes an argument to anything.
#   * "Are these the same key?" is answered WITHOUT printing either key — and without
#     printing either digest. Issue #227's own recipe hashes both files and has a
#     person compare the two digests by eye; this compares them in process and prints
#     the verdict, which is strictly less to leak. A digest of a 32-byte random key is
#     not brute-forceable, and it is still a value derived from a secret, and there is
#     nothing an operator can do with one that the verdict does not already tell them.
#   * Every value is read from a file straight into a hash on a pipe, inside a subshell
#     with tracing turned OFF, so that `sh -x bacchus-key-inventory.sh` cannot echo a
#     key either. deploy/install.sh takes the same precaution where it generates one.
#   * Which is why cross-box comparison is deliberately NOT offered here. "Do two boxes
#     hold the same exit key?" is already answerable from public data: an exit's node
#     id is its public key, it is in the signed directory, and two boxes sharing a key
#     register as one id — which deploy/bacchus-fleet-check.sh and
#     deploy/bacchus-node-id.sh already show you. It needs no digest to travel.
#
# --label is an ordinal and never a host, the same rule and the same refusal as
# deploy/bacchus-gate-check.sh, because free text is where a hostname gets in.
#
# ---------------------------------------------------------------------------
# WHAT IT COULD NOT READ IS NOT WHAT IT FOUND CLEAN
# ---------------------------------------------------------------------------
# Run without the privileges to read a file, this says so and exits 4 rather than
# reporting a directory it could only half look at. That is issue #248's rule — a skip
# printed at the volume of a pass is how a check silently covers two boxes of three —
# and it applies to this script first of all, since /etc/bacchus is mode 0700 and an
# unprivileged run can see the NAMES of everything and the contents of none of it.
#
# ---------------------------------------------------------------------------
# WHAT IT DOES NOT DO
# ---------------------------------------------------------------------------
# It never deletes, moves, chmods or writes anything. Remediation is the operator's:
# whether the second copy is the same key or a previous identity changes what should
# happen to it, and #227 is explicit that a differing copy is worth knowing about
# before it is destroyed. This tool's whole job is to put that decision in front of
# somebody.

set -eu

self="${0##*/}"

usage() {
	printf 'usage: %s --role exit|coordinator[,...] [--dir DIR] [--expect NAME[,NAME...]] [--label L]\n' "$self" >&2
	printf '       ssh <box> "sudo sh -s -- --role exit" < deploy/bacchus-key-inventory.sh\n' >&2
	printf '\nLists what a box holds under /etc/bacchus and flags what the deployment cannot\n' >&2
	printf 'account for. It prints paths, never contents: no key, no address, no hostname.\n' >&2
	printf '\n--role    which node this box is. Repeatable, or comma separated.\n' >&2
	printf '--dir     the directory to inventory. Default /etc/bacchus.\n' >&2
	printf '--expect  paths this box is SUPPOSED to hold, spelled as the report names them,\n' >&2
	printf '          so they stop being findings. Record them somewhere too — #251.\n' >&2
	printf '--label   which box this report came from. An ordinal, never a host.\n' >&2
	printf '\nExit: 0 everything is accounted for · 1 a finding · 2 usage\n' >&2
	printf '      3 the directory could not be listed · 4 something could not be read\n' >&2
}

dir='/etc/bacchus'
roles=''
expect=''
label=''

while [ "$#" -gt 0 ]; do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	--role)
		[ "$#" -ge 2 ] || {
			printf '%s: --role needs a value\n' "$self" >&2
			exit 2
		}
		roles="$roles $(printf '%s' "$2" | tr ',' ' ')"
		shift 2
		;;
	--dir)
		[ "$#" -ge 2 ] || {
			printf '%s: --dir needs a value\n' "$self" >&2
			exit 2
		}
		dir="$2"
		shift 2
		;;
	--expect)
		[ "$#" -ge 2 ] || {
			printf '%s: --expect needs a value\n' "$self" >&2
			exit 2
		}
		expect="$expect $(printf '%s' "$2" | tr ',' ' ')"
		shift 2
		;;
	--label)
		[ "$#" -ge 2 ] || {
			printf '%s: --label needs a value\n' "$self" >&2
			exit 2
		}
		label="$2"
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

if [ "$#" -gt 0 ]; then
	printf '%s: this script takes no positional arguments, got: %s\n' "$self" "$1" >&2
	usage
	exit 2
fi

# A role is required rather than guessed. Guessing it from which unit files happen to
# be installed would make the answer depend on a box's leftovers, which is the class of
# thing being looked for.
if [ -z "$(printf '%s' "$roles" | tr -d ' ')" ]; then
	printf '%s: --role is required.\n' "$self" >&2
	printf '  What a box is SUPPOSED to hold is a function of what it runs, and a role\n' >&2
	printf '  inferred from what is on disk would be inferred from the leftovers this\n' >&2
	printf '  script exists to find. Say `--role exit` or `--role coordinator`.\n' >&2
	exit 2
fi

for r in $roles; do
	case "$r" in
	exit | coordinator) ;;
	*)
		printf '%s: %s is not a role this knows.\n' "$self" "$r" >&2
		printf '%s\n' '  Known: exit coordinator. A relay box runs the same binary and the same' >&2
		printf '%s\n' '  node.env as an exit — `--role exit` is its inventory too.' >&2
		exit 2
		;;
	esac
done

# The label may not be a host, for the reason in the header: this output is meant to be
# pasteable, and free text is where a hostname gets in. Same characters and same refusal
# as deploy/bacchus-gate-check.sh and deploy/bacchus-fleet-check.sh.
case "$label" in
*[./@:]* | *' '*)
	printf '%s: --label %s looks like a host, and this script prints none.\n' "$self" "$label" >&2
	printf '  Use an ordinal. The pairing between an ordinal and a box belongs with the\n' >&2
	printf '  caller, which is where the host list already lives (issue #232).\n' >&2
	exit 2
	;;
esac

# An --expect value is a path RELATIVE to the inventoried directory — exactly as the
# report prints it, so `secrets/whatever.key` is what you declare for a file one level
# down. An absolute one, or one that climbs out with `..`, matches nothing this walk can
# produce and is a mistake worth naming rather than a row that silently never clears.
# `@` and `:` are refused for the reason --label is: whatever is passed here is echoed
# back, and this output has one job.
for e in $expect; do
	case "$e" in
	/* | ../* | */../* | */.. | *@* | *:*)
		printf '%s: --expect %s is not a path this report can produce.\n' "$self" "$e" >&2
		printf '  Declare it exactly as the report names it: relative to the inventoried\n' >&2
		printf '  directory, with no leading / and no `..`, and with no @ or : in it.\n' >&2
		exit 2
		;;
	esac
done

# A trailing slash would survive into every relative path below and make each one look
# like an absolute one. Stripped here rather than in the walk, so there is one spelling
# of the directory from this point down.
while [ "$dir" != "/" ] && [ "${dir%/}" != "$dir" ]; do
	dir=${dir%/}
done

if [ ! -d "$dir" ]; then
	printf '%s: %s is not a directory, so there is nothing to inventory.\n' "$self" "$dir" >&2
	printf '  On a box with no /etc/bacchus there is no env file and no key: a node that has\n' >&2
	printf '  never been installed, or a --purge that took the directory with it. That is a\n' >&2
	printf '  clean answer to a different question, and it is not this one.\n' >&2
	exit 3
fi

# ---------------------------------------------------------------------------
# Digests. The same two-tool fallback deploy/bacchus-pin.sh uses, for the same reason:
# sha256sum is coreutils and shasum is what a box without it has.
#
# digest_stdin is called ONLY from inside the subshells below, whose `set +x` is what
# keeps a value out of a trace. It reads from a pipe and takes no argument, so nothing
# it is given can appear in a command line either — not in a trace, not in this box's
# own /proc/<pid>/cmdline, which is world readable and is exactly the exposure
# ADR-0071 refused a -claim-code flag over.
# ---------------------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
	digest_stdin() { sha256sum | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	digest_stdin() { shasum -a 256 | cut -d' ' -f1; }
else
	printf '%s: neither sha256sum nor shasum is installed.\n' "$self" >&2
	printf '  Without one, "is this the same key?" can only be answered by looking at two\n' >&2
	printf '  keys, which is the thing this script exists not to do. Install coreutils.\n' >&2
	exit 3
fi

# file_mode prints a file's permission bits as octal, or an empty string if neither
# stat spelling works. An unknown mode is reported as unknown rather than as fine.
file_mode() {
	stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || printf ''
}

# ---------------------------------------------------------------------------
# THE MANIFEST — what each role's own deployment names.
#
# Fields: NAME <tab> CLASS <tab> NOTE.  CLASS is `secret` for a file whose contents are
# key material or a bearer value, `config` for one that is not, `dir` for a directory.
# `secret` is what earns a file the mode check below; everything is scanned for a
# duplicated secret regardless of class, because the copy is never the file the
# manifest names.
#
# The `secrets/…` rows are cmd/coordinator's RELATIVE flag defaults. They are not dead
# entries: bacchus-coordinator.service ships WorkingDirectory=/etc/bacchus precisely so
# those defaults land there (issue #247), so a coordinator that was never given
# absolute paths writes exactly these.
# ---------------------------------------------------------------------------
manifest_for() {
	case "$1" in
	exit)
		printf '%s\n' \
			'node.env	secret	the node env file — EXIT_KEY is this exit'\''s identity, and this file is the ONE copy of it (#227)'
		;;
	coordinator)
		printf '%s\n' \
			'coordinator.env	secret	the coordinator env file — holds TURN_PASS' \
			'coordinator-gates.env	config	the credential gates (ADR-0072); public keys and paths, no secret' \
			'bacchus-bootstrap.key	secret	the snapshot-signing key named by bacchus-coordinator.service' \
			'bacchus-bootstrap-secrets.json	secret	per-user cold-start bootstrap secrets (cmd/coldstart-issue)' \
			'admission-revocations.json	config	revoked admission serials; absent means NOTHING IS REVOKED' \
			'device-revocations.json	config	revoked device-credential serials; absent means NOTHING IS REVOKED' \
			'admission-revocations-state.json	secret	the admission namespace'\''s rollback floor — write access rolls it back a generation' \
			'device-revocations-state.json	secret	the device namespace'\''s rollback floor — same standing' \
			'policy-state.json	secret	the signed-policy rollback floor (issue #39)' \
			'operators.json	config	node -> operator tag assignments (issue #124)' \
			'country-overrides.json	config	the admin'\''s per-node country corrections (issue #113)' \
			'secrets	dir	where cmd/coordinator'\''s relative flag defaults land under WorkingDirectory=/etc/bacchus' \
			'secrets/coordinator-bootstrap.key	secret	-bootstrap-key'\''s default path' \
			'secrets/bootstrap-secrets.json	secret	-bootstrap-secrets'\'' default path' \
			'secrets/admission-root.key	secret	cmd/admission-issue'\''s signing key default path' \
			'secrets/admission-revocations.json	config	-admission-revocations'\'' default path' \
			'secrets/device-revocations.json	config	-device-revocations'\'' default path' \
			'secrets/admission-revocations-state.json	secret	-admission-revocations-state'\''s default path' \
			'secrets/device-revocations-state.json	secret	-device-revocations-state'\''s default path' \
			'secrets/policy-state.json	secret	-policy-state'\''s default path' \
			'secrets/operators.json	config	-operators'\'' default path' \
			'secrets/country-overrides.json	config	-country-overrides'\'' default path'
		;;
	esac
}

# The env variables whose VALUES are secrets. A second file carrying one of these is
# the #227 finding, whatever that file is called — which is why every readable regular
# file is scanned for them and not only the ones the manifest names.
secret_vars='EXIT_KEY TURN_PASS'

# ---------------------------------------------------------------------------
# The record stream. Everything below emits tab-separated records for the awk program
# at the foot of the file, which is the only thing that prints a report. The split is
# not decoration: the shell half touches secrets and prints nothing, the awk half
# prints everything and never sees one.
#
#   R  role
#   X  an --expect declaration
#   M  a manifest entry:  name, class, note
#   F  a found entry:     relative path, type, mode, readable
#   S  a secret found in a file: relative path, variable (or `file`), digest
#
# `sort -u` on the manifest lets two roles on one box share entries without either one
# reporting a duplicate row. Declaring both roles is itself reported, because a box
# running a coordinator and an exit is issue #60.
# ---------------------------------------------------------------------------
records() {
	for r in $roles; do
		printf 'R\t%s\n' "$r"
	done
	for e in $expect; do
		printf 'X\t%s\n' "$e"
	done

	for r in $roles; do
		manifest_for "$r"
	done | sort -u | while IFS='	' read -r name class note; do
		[ -n "$name" ] || continue
		printf 'M\t%s\t%s\t%s\n' "$name" "$class" "$note"
	done

	# The walk. Everything under the directory, at any depth: a copy tucked into a
	# subdirectory is the same finding as one beside the live file, and it is the one
	# a listing of the top level misses.
	#
	# Paths are printed relative to the inventoried directory, so the report never
	# names where the directory is. A file name containing a newline would confuse the
	# record stream; /etc/bacchus is a configuration directory written by this
	# project's own tools and by an operator's editor, and a name like that is not a
	# case being handled — it would be a finding of a different kind entirely.
	find "$dir" -mindepth 1 -print 2>/dev/null | LC_ALL=C sort | while IFS= read -r path; do
		rel=${path#"$dir"}
		rel=${rel#/}
		if [ -d "$path" ]; then
			printf 'F\t%s\t%s\t%s\t%s\n' "$rel" dir "$(file_mode "$path")" 1
			continue
		fi
		if [ ! -f "$path" ]; then
			# A symlink to nothing, a socket, a device node. Reported as found and
			# never opened: this script's job is to say what is there.
			printf 'F\t%s\t%s\t%s\t%s\n' "$rel" other "$(file_mode "$path")" 1
			continue
		fi
		if [ ! -r "$path" ]; then
			printf 'F\t%s\t%s\t%s\t%s\n' "$rel" file "$(file_mode "$path")" 0
			continue
		fi
		printf 'F\t%s\t%s\t%s\t%s\n' "$rel" file "$(file_mode "$path")" 1

		# ---- the only place a secret is ever touched. ----------------------
		# A subshell, with tracing OFF, so `sh -x` on this script cannot echo a
		# value or a digest of one. Each value goes from a file into a hash on a
		# pipe; it is never assigned, never interpolated and never an argument.
		(
			set +x
			found_var=0
			for v in $secret_vars; do
				# Non-empty values only. `EXIT_KEY=` with nothing after it is
				# what deploy/node.env.example ships and what an exit that
				# generates a fresh identity every start has; reporting two
				# files as sharing that would be reporting the absence of a
				# key as a duplicated one.
				grep -q "^$v=..*" "$path" 2>/dev/null || continue
				found_var=1
				printf 'S\t%s\t%s\t%s\n' "$rel" "$v" \
					"$(sed -n "s/^$v=//p" "$path" | digest_stdin)"
			done

			# A file that is key material rather than a file that CARRIES a value
			# in a variable: a PEM private key, a raw key file, anything the
			# manifest calls a secret. Digested whole. Skipped when the file
			# already yielded a variable, so one duplicated env file is one
			# finding and not two.
			[ "$found_var" -eq 0 ] || exit 0
			case "$rel" in
			*.key) ;;
			*)
				grep -q -- '-----BEGIN .*PRIVATE KEY-----' "$path" 2>/dev/null ||
					exit 0
				;;
			esac
			printf 'S\t%s\t%s\t%s\n' "$rel" file "$(digest_stdin <"$path")"
		)
	done
}

# shellcheck disable=SC2016
records | awk -F'\t' -v label="$label" '
	function pad(s, w,   out) {
		out = s
		while (length(out) < w) out = out " "
		return out
	}

	# group_other returns the group-and-other digits of an octal mode, left padding a
	# short one first: stat prints mode 0 as "0" and 0600 as "600" or "0600" depending
	# on which spelling answered. Comparing the string against a pattern instead read
	# "0" — no permissions at all — as wider than 0600, which is backwards.
	function group_other(m) {
		while (length(m) < 3) m = "0" m
		return substr(m, length(m) - 1)
	}

	# wrap prints a long space separated list under one label, broken at a width a
	# terminal and an issue comment can both hold. A coordinator names two dozen files
	# and a single line of them is a line nobody reads.
	function wrap(label, list, indent,   n, i, parts, line) {
		n = split(list, parts, " ")
		line = label
		for (i = 1; i <= n; i++) {
			if (length(line) + 1 + length(parts[i]) > 78) {
				print line
				line = indent
			}
			line = line (line == indent ? "" : " ") parts[i]
		}
		if (line != indent) print line
	}

	BEGIN {
		pfx = (label == "" ? "" : "box " label ": ")
		nrole = 0 ; nman = 0 ; nfound = 0 ; nsec = 0
	}

	$1 == "R" { roles[++nrole] = $2 ; next }
	$1 == "X" { declared[$2] = 1 ; next }
	$1 == "M" {
		mname[++nman] = $2 ; mclass[$2] = $3 ; mnote[$2] = $4 ; known[$2] = 1
		next
	}
	$1 == "F" {
		fname[++nfound] = $2 ; ftype[$2] = $3 ; fmode[$2] = $4 ; fread[$2] = $5
		present[$2] = 1
		next
	}
	$1 == "S" {
		# The digest is only ever an array KEY here and never a value that gets
		# printed: the report says which files share one, never what it is.
		#
		# Two groupings, because the two kinds of secret duplicate differently. A
		# NAMED VARIABLE groups by its name: EXIT_KEY in two files is a finding
		# whether or not the values match, and which of the two it is decides what
		# should happen to the copy. WHOLE-FILE key material groups by its digest
		# instead, because an operator CA key and an admission key are two unrelated
		# secrets that happen to be shaped alike — only a byte-identical pair is a
		# second copy of one thing.
		if ($3 == "file") {
			g = "f" SUBSEP $4
			glabel[g] = "key material, whole file"
		} else {
			g = "v" SUBSEP $3
			glabel[g] = $3
		}
		if (!(g in gcount)) gorder[++ngroup] = g
		gcount[g]++
		gfiles[g] = gfiles[g] (gfiles[g] == "" ? "" : " ") $2
		gdigests[g SUBSEP $4] = 1
		carries[$2] = 1
		next
	}

	END {
		rolelist = ""
		for (i = 1; i <= nrole; i++) rolelist = rolelist (i > 1 ? "," : "") roles[i]

		print pfx "bacchus-key-inventory: what this box holds, and what the deployment names"
		print pfx "  role(s): " rolelist "  ·  paths only, no contents — nothing below is a secret"
		print ""

		w = 12
		for (i = 1; i <= nfound; i++) if (length(fname[i]) > w) w = length(fname[i])

		unaccounted = 0
		unread = 0
		modebad = 0

		if (nfound == 0) {
			print "  the directory is empty"
		}
		for (i = 1; i <= nfound; i++) {
			f = fname[i]
			if (known[f] || declared[f]) {
				verdict = "accounted"
				note = declared[f] && !known[f] ? "declared with --expect" : mnote[f]
			} else {
				verdict = "UNACCOUNTED"
				unaccounted++
				note = "nothing in this deployment names it"
			}

			extra = ""
			if (fread[f] == "0") {
				unread++
				extra = "  [UNREAD — no permission to open it]"
			}
			if (ftype[f] == "dir") extra = extra "  [directory]"
			else if (ftype[f] == "other") extra = extra "  [not a regular file]"

			# The mode check applies to files that hold key material: one the
			# manifest calls a secret, and one this run actually found a secret in.
			# 0600 is what deploy/install.sh writes and what deploy/install-test.sh
			# asserts at install time; nothing until now looked again afterwards.
			if ((mclass[f] == "secret" || carries[f]) && ftype[f] == "file") {
				if (fmode[f] == "") {
					unread++
					extra = extra "  [mode UNREAD]"
				} else if (group_other(fmode[f]) != "00") {
					modebad++
					extra = extra "  [MODE " fmode[f] " — readable beyond its owner]"
				}
			}

			line = "  " pad(f, w) "  " pad(verdict, 11)
			if (note != "") line = line "  " note
			sub(/ +$/, "", line)
			print line extra
		}

		# Expected and absent. Informational and never a finding: a coordinator with
		# no revocation lists staged is the state every box ships in, and #251 is
		# about a box holding MORE than its role names.
		absent = ""
		for (i = 1; i <= nman; i++)
			if (!present[mname[i]]) absent = absent (absent == "" ? "" : " ") mname[i]
		if (absent != "") {
			print ""
			print "  named by this role and NOT on this box — not a finding, and the rest of"
			print "  what would have been accounted for had it been here:"
			wrap("   ", absent, "   ")
		}

		# The #227 question, answered without either key. A variable in more than one
		# file is the finding; whether the two values match decides what should happen
		# to the copy, which is why the card says to check before deleting.
		dup = 0
		for (i = 1; i <= ngroup; i++) {
			g = gorder[i]
			if (gcount[g] < 2) continue
			if (dup == 0) {
				print ""
				print "  MORE THAN ONE COPY OF A SECRET (issue #227):"
			}
			dup++
			distinct = 0
			for (k in gdigests) {
				split(k, kp, SUBSEP)
				if (kp[1] SUBSEP kp[2] == g) distinct++
			}
			printf "    %s  in %d files: %s\n", glabel[g], gcount[g], gfiles[g]
			if (distinct == 1)
				print "      the SAME value in each — one of these is a spare copy of a live key"
			else
				printf "      %d DIFFERENT values — at least one of these is a PREVIOUS identity, which\n      is worth knowing before it is destroyed (#227). Nothing here says which.\n", distinct
		}

		fflush()

		if (nrole > 1) {
			print pfx "bacchus-key-inventory: this box was declared as more than one role." > "/dev/stderr"
			print "  A machine running a coordinator and an exit sees the signaling for an" > "/dev/stderr"
			print "  assignment and the egress for it — both ends of the correlation the design" > "/dev/stderr"
			print "  spends its budget denying (issue #60). The inventory below is the union of" > "/dev/stderr"
			print "  both roles, so it accounts for more than either role alone would." > "/dev/stderr"
		}

		if (unaccounted > 0) {
			printf "%sbacchus-key-inventory: %d entr(y/ies) this deployment cannot account for.\n", pfx, unaccounted > "/dev/stderr"
			print "  Nothing was deleted, moved or changed — that decision is yours and it needs" > "/dev/stderr"
			print "  the answer to a question this cannot ask: is it a throwaway, or the start of" > "/dev/stderr"
			print "  a real configuration somebody stopped halfway (#251)? Destroy it, or record" > "/dev/stderr"
			print "  it and pass it as --expect so the next run is clean. Leaving it to expire" > "/dev/stderr"
			print "  quietly is the one option the card rules out." > "/dev/stderr"
		}
		if (dup > 0) {
			printf "%sbacchus-key-inventory: %d secret(s) exist in more than one file here.\n", pfx, dup > "/dev/stderr"
			print "  A second copy has none of the attention the live one gets: not rotated when" > "/dev/stderr"
			print "  it is, not removed when this box is, and in no inventory but this one. A" > "/dev/stderr"
			print "  file named .save or .bak is one restore away from reinstating an identity" > "/dev/stderr"
			print "  the signed directory does not name (#227). Keep ONE copy on this box and" > "/dev/stderr"
			print "  put any backup somewhere that is not this machine." > "/dev/stderr"
		}
		if (modebad > 0) {
			printf "%sbacchus-key-inventory: %d file(s) holding key material are readable beyond their owner.\n", pfx, modebad > "/dev/stderr"
			print "  deploy/install.sh writes these 0600 and deploy/install-test.sh asserts it at" > "/dev/stderr"
			print "  install time; nothing looked again afterwards, and an edit-and-restore is how" > "/dev/stderr"
			print "  a mode moves. `chmod 600` them." > "/dev/stderr"
		}
		if (unaccounted > 0 || dup > 0 || modebad > 0) exit 1

		if (unread > 0) {
			printf "%sbacchus-key-inventory: %d entr(y/ies) could not be read, so this box was not\n", pfx, unread > "/dev/stderr"
			print "  fully inventoried — and a directory that was half looked at is not a clean" > "/dev/stderr"
			print "  one (issue #248). /etc/bacchus is mode 0700, so an unprivileged run sees" > "/dev/stderr"
			print "  every NAME and no contents: a duplicated key is invisible from here. Re-run" > "/dev/stderr"
			print "  it under sudo." > "/dev/stderr"
			exit 4
		}

		print pfx "bacchus-key-inventory: every entry is accounted for, and no secret is here twice"
		exit 0
	}
'
