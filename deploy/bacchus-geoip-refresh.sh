#!/bin/sh
# Stage or refresh the IP-to-Country tables the coordinator derives node countries from
# (issue #136, ADR-0042). Run it once to close the staging gap on a host; after that
# bacchus-geoip-refresh.timer runs it on a cadence. docs/RUNNING.md ("GeoIP country
# database") covers what the coordinator does with the result and how to point it here.
#
# usage: bacchus-geoip-refresh.sh [DEST_DIR]      (default: /var/lib/bacchus/geoip)
#
# DEST_DIR must be the directory the coordinator's -geoip flag names.
#
# Why this is a script and not the three commands it runs. The coordinator reads these
# files once, at startup, and treats an unreadable or implausibly small table as fatal.
# Two properties follow, and between them they are the whole reason for the temporary
# paths below:
#
#   * A refresh running while a coordinator starts must not be able to hand it half a
#     table. Each family is fetched and decompressed under a temporary name INSIDE THE
#     DESTINATION DIRECTORY and renamed into place, so it appears complete or not at
#     all. The temporary path is in the destination on purpose: a rename is atomic only
#     within one filesystem, so staging through /tmp would make the final step a copy —
#     exactly the half-written window this exists to avoid.
#
#   * A refresh that FAILS must leave the working table where it was. Nothing is renamed
#     until both families have been fetched, decompressed and checked, so a bad download
#     replaces nothing. This matters more than it first looks: the fallback for a
#     missing country table is each node's own self-report, which is the thing deriving
#     country exists to remove — so a refresh able to destroy a good table would be
#     strictly worse than never refreshing at all.
#
# Nothing here is host-specific and nothing here is secret: the destination is an
# argument, and the source is a public, account-free feed (PDDL v1.0, the same publisher
# core/asn's table comes from).

set -eu

# Upstream. Overridable only so this script can be rehearsed against a local copy —
# there is no mirror and no second publisher. Redirects are deliberately not followed
# (there is no curl -L below): upstream serves these files directly, so a redirect means
# something changed, and that is worth an operator's attention rather than a silent
# follow to wherever it points.
base_url="${BACCHUS_GEOIP_BASE_URL:-https://iptoasn.com/data}"

# The two files upstream publishes, under the names core/geoip's loader looks for
# (geoip.FileRangesV4 / FileRangesV6) — which is why nothing here renames anything.
# Both are staged: without the v6 table an IPv6-registering node resolves to nothing and
# falls back to its own country hint.
families='ip2country-v4.tsv ip2country-v6.tsv'

# Fewest rows a family may hold and still be a published release. Each carries on the
# order of 10^5, so this sits three orders of magnitude below any real one and catches
# only a transfer that died in its first moments — the same floor, chosen for the same
# reason, as the coordinator's own minPlausibleBlocks. It is checked HERE as well so a
# truncated file is refused BEFORE it replaces a good one, rather than at the next
# coordinator start, when the good one is already gone.
min_rows=1000

usage() {
	printf 'usage: %s [DEST_DIR]   (default: /var/lib/bacchus/geoip)\n' "${0##*/}" >&2
	printf 'DEST_DIR must be the directory the coordinator'\''s -geoip flag names.\n' >&2
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
-*)
	printf 'bacchus-geoip-refresh: unknown option: %s\n' "$1" >&2
	usage
	exit 2
	;;
esac

if [ "$#" -gt 1 ]; then
	printf 'bacchus-geoip-refresh: expected at most one argument, got %s\n' "$#" >&2
	usage
	exit 2
fi

dest="${1:-/var/lib/bacchus/geoip}"

log() { printf 'bacchus-geoip-refresh: %s\n' "$*"; }

# fail is the loud half of "fail loudly and change nothing". It names what went wrong and
# then says what is still in place, because the operator reading this in the journal
# needs to know whether the coordinator is now running on nothing.
fail() {
	printf 'bacchus-geoip-refresh: ERROR: %s\n' "$*" >&2
	printf 'bacchus-geoip-refresh: nothing was replaced — whatever was already staged in %s is untouched.\n' "$dest" >&2
	exit 1
}

# Temporary paths are removed on every exit, successful or not. On success they have
# already been renamed away and this is a no-op; on failure — including a kill mid-fetch
# — it is what stops a dead run leaving debris beside a live table.
cleanup() {
	for _f in $families; do
		rm -f "$dest/$_f.tmp" "$dest/$_f.gz.tmp"
	done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in curl gunzip; do
	command -v "$tool" >/dev/null 2>&1 ||
		fail "$tool is not installed, and this cannot run without it"
done

mkdir -p "$dest" || fail "cannot create $dest"
[ -w "$dest" ] || fail "$dest is not writable"

# Pass one: fetch, decompress and check both families. Nothing in the destination is
# touched except the temporary paths, so any failure here leaves the staged table whole.
for f in $families; do
	gz_tmp="$dest/$f.gz.tmp"
	tsv_tmp="$dest/$f.tmp"

	log "fetching $base_url/$f.gz"
	curl -sSf -o "$gz_tmp" "$base_url/$f.gz" ||
		fail "download of $f.gz failed"

	# gunzip is the integrity check as well as the decompression: gzip carries a CRC32
	# and an uncompressed-length trailer, so a transfer truncated or corrupted anywhere
	# fails here rather than landing as a plausible-looking short table. It is not
	# authentication — TLS is what makes the bytes upstream's — but it is what makes a
	# broken transfer loud.
	gunzip -c "$gz_tmp" >"$tsv_tmp" ||
		fail "$f.gz did not decompress — the download is truncated or corrupt"
	rm -f "$gz_tmp"

	rows=$(($(wc -l <"$tsv_tmp")))
	[ "$rows" -ge "$min_rows" ] ||
		fail "$f holds only $rows rows, far below the ~10^5 a published release carries — refusing to stage it"
	log "$f: $rows rows"
done

# Pass two: rename each checked file over its predecessor. Individually atomic; not one
# transaction across the two, so a coordinator starting between the two renames can see a
# new v4 beside the previous v6. That is harmless — each file is complete at every
# instant and the loader takes the two families independently — and it is the reason the
# checks all happen above rather than between the renames.
#
# The staged files deliberately carry the time of THIS refresh rather than upstream's
# publication time (no curl -R, and gunzip -c writes a fresh file). It makes the
# coordinator's 90-day staleness warning measure time since the last successful refresh,
# which is the thing this timer keeps honest; upstream rebuilds hourly, so the two
# readings differ by minutes anyway.
for f in $families; do
	mv -f "$dest/$f.tmp" "$dest/$f" || fail "could not stage $f into $dest"
done

log "staged $families in $dest"
log "a running coordinator keeps the table it loaded at startup — restart it to pick this up"
