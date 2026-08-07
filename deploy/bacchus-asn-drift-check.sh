#!/bin/sh
# Detects drift between the live upstream IP-to-AS feed and the table committed at
# core/asn/table.tsv.gz (issue #150, ADR-0044's fourth amendment §5 and the amendment
# that closes it: ruled option C — detect, and do not commit).
#
# usage: bacchus-asn-drift-check.sh   (no arguments; run from the repository root)
#
# WHAT THIS DOES AND DOES NOT DO. It fetches upstream, runs it through cmd/asn-stage
# exactly as the documented manual refresh does (cmd/asn-stage/README.md,
# docs/RUNNING.md, core/asn/TABLE.md), and compares the result against the table
# already committed to this tree, byte for byte. That is the whole of it: no file in
# this repository is ever opened for writing, no branch, no commit, no credential.
# The one thing this script is allowed to do about a stale table is refuse loudly and
# say so — the refresh itself stays a human running the three commands this script's
# own failure message prints, exactly as it always has. ADR-0044 committed the table
# specifically so a reviewer can regenerate it from the same feed and compare byte for
# byte; this automates the compare half and nothing else.
#
# EXIT STATUS
#   0  the freshly staged table is byte-identical to the committed one — no drift.
#   1  the check is INCONCLUSIVE: the download, its integrity check, or the transform
#      failed. This is NOT evidence the committed table is stale, and the committed
#      table was never opened for writing.
#   2  the check ran to completion and the freshly staged table DIFFERS from the
#      committed one. This is the signal ADR-0044's fourth amendment §5 exists to
#      raise: somebody must refresh core/asn/table.tsv.gz and commit it.
#
# WHY THE FETCH HALF LOOKS LIKE bacchus-geoip-refresh.sh's. Same publisher, same
# failure shape to guard against — a transfer that dies partway must never be
# mistaken for a real answer. So the discipline carries over unchanged: fetch and
# decompress into a SCRATCH directory this script owns outright, never the checkout's
# own core/asn/table.tsv.gz; verify the decompression and a row-count floor before
# trusting a byte of it; and only then run the transform and compare. A bad download
# therefore cannot even reach the comparison, let alone the committed file. Unlike the
# geoip case there is no live process to hand a half-written table to — this runs in a
# disposable checkout — but the same ordering is what makes "the committed table was
# not touched" true by construction, on this path AND on every other one, rather than
# true by care on this one path alone.
#
# WHY A DIFFERENCE IS EXPECTED TO KEEP FIRING, not just near the two CI staleness
# bars. This is a byte-for-byte comparison against a feed upstream rebuilds hourly, not
# a calendar check like TestEmbeddedTableIsFresh — so once the committed table is even
# a day behind, this keeps failing on every scheduled run until somebody refreshes it,
# not only once the table crosses 90 or 30 days. That is deliberate, not a defect: it is
# what "somebody must act" being reasserted continuously looks like, and it is a single
# workflow staying red rather than a pile of filed issues (wave ruling R7). The cadence
# this runs on (see the workflow this script is called from) is chosen so the FIRST such
# failure lands well inside the tighter of the two bars, leaving most of the budget on
# the table for whoever sees it.

set -eu

# Overridable only so this script can be rehearsed against a local fixture instead of
# the real feed and the real 700,000-row table — there is no mirror and no second
# publisher for the real thing, and the real committed table is not something a test
# should have to reproduce byte for byte just to exercise the failure paths.
feed_url="${BACCHUS_ASN_FEED_URL:-https://iptoasn.com/data/ip2asn-combined.tsv.gz}"
table_path="${BACCHUS_ASN_TABLE_PATH:-core/asn/table.tsv.gz}"

# Same floor, same reasoning, as bacchus-geoip-refresh.sh's min_rows: three orders of
# magnitude below what a published release of this publisher's data carries —
# cmd/asn-stage's own README measures the real feed in the hundreds of thousands of
# ranges — so this catches only a transfer that died in its first moments, never
# legitimate size drift. Overridable so a test can trip it without a real feed.
min_rows="${BACCHUS_ASN_MIN_ROWS:-1000}"

usage() {
	printf 'usage: %s   (no arguments; run from the repository root)\n' "${0##*/}" >&2
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac
if [ "$#" -gt 0 ]; then
	printf 'bacchus-asn-drift-check: unknown argument: %s\n' "$1" >&2
	usage
	exit 2
fi

log() { printf 'bacchus-asn-drift-check: %s\n' "$*"; }

# fail is the "could not tell" half — exit 1. It never claims to know whether the
# committed table is stale, because at the point it runs, this script does not know.
fail() {
	printf 'bacchus-asn-drift-check: ERROR: %s\n' "$*" >&2
	printf 'bacchus-asn-drift-check: the check is inconclusive — %s was never opened for writing.\n' "$table_path" >&2
	exit 1
}

for tool in curl gunzip go; do
	command -v "$tool" >/dev/null 2>&1 ||
		fail "$tool is not installed, and this cannot run without it"
done

[ -f "cmd/asn-stage/main.go" ] ||
	fail "cmd/asn-stage/main.go not found — run this from the repository root"
[ -f "$table_path" ] ||
	fail "$table_path does not exist — run this from the repository root, or set BACCHUS_ASN_TABLE_PATH"

scratch=$(mktemp -d)
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Best-effort context, logged unconditionally on every run for the same reason
# TestEmbeddedTableIsFresh logs unconditionally in core/asn/embedded_test.go: a run —
# pass or fail — should be answerable from its own output. Never fatal: a line this
# cannot parse costs a line of context, not the check itself.
retrieved=$(grep -oE 'TableRetrieved = "[0-9]{4}-[0-9]{2}-[0-9]{2}"' core/asn/embedded.go 2>/dev/null | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)
if [ -n "$retrieved" ]; then
	retrieved_epoch=$(date -d "$retrieved" +%s 2>/dev/null || true)
	if [ -n "$retrieved_epoch" ]; then
		age_days=$(( ($(date +%s) - retrieved_epoch) / 86400 ))
		log "the committed table at $table_path was retrieved $retrieved, $age_days day(s) ago (build floor 90 days, release bar 30 days)"
	fi
fi

log "fetching $feed_url"
curl -sSf -o "$scratch/upstream.tsv.gz" "$feed_url" ||
	fail "download of the upstream feed failed"

# gunzip is the integrity check as well as the decompression, for the reason
# bacchus-geoip-refresh.sh's own comment gives: gzip carries a CRC32 and a length
# trailer, so a transfer truncated or corrupted anywhere fails here rather than
# landing as a plausible-looking short file.
gunzip -c "$scratch/upstream.tsv.gz" >"$scratch/upstream.tsv" ||
	fail "the downloaded feed did not decompress — the transfer is truncated or corrupt"

rows=$(($(wc -l <"$scratch/upstream.tsv")))
[ "$rows" -ge "$min_rows" ] ||
	fail "the downloaded feed holds only $rows rows, far below what a published release carries — refusing to stage it"
log "downloaded feed: $rows upstream rows"

# The transform, unchanged from the documented manual recipe (cmd/asn-stage/README.md,
# docs/RUNNING.md, core/asn/TABLE.md) — same flags, same order, so this script's
# invocation and the one a human runs by hand are the same command either side of
# different paths. A failure here is distinct from a download failure: the transfer
# and its integrity check already passed, so this more likely means upstream changed
# shape in a way asn-stage does not understand yet, not that the network was bad.
go run ./cmd/asn-stage -in "$scratch/upstream.tsv" -out "$scratch/staged.tsv.gz" -gzip ||
	fail "asn-stage could not turn the downloaded feed into a table — the download and its integrity check both passed, so this may mean upstream changed shape rather than that the transfer was bad"

if cmp -s "$scratch/staged.tsv.gz" "$table_path"; then
	log "no drift: $table_path matches what upstream produces today"
	exit 0
fi

# Drift confirmed. Everything above ran to completion, so this is not "could not
# tell" — it is the answer, and it is what this script exists to raise loudly. The
# line-count summary needs both sides decompressed; it is only paid for once drift is
# already certain, from the cheap gzip-byte comparison above.
gunzip -c "$scratch/staged.tsv.gz" >"$scratch/staged.tsv"
gunzip -c "$table_path" >"$scratch/committed.tsv"
changed=$(diff "$scratch/committed.tsv" "$scratch/staged.tsv" | grep -c '^[<>]' || true)

printf 'bacchus-asn-drift-check: DRIFT: %s differs from what upstream produces today (%s line(s) differ).\n' "$table_path" "$changed" >&2
printf 'bacchus-asn-drift-check: this is not a download failure — the fetch, its integrity check and the transform all succeeded.\n' >&2
printf 'bacchus-asn-drift-check: %s was NOT modified. Refresh it by hand and commit:\n' "$table_path" >&2
printf '\n' >&2
printf '    curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz\n' >&2
printf '    go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip\n' >&2
printf '    go test ./core/asn/ ./core/\n' >&2
printf '\n' >&2
printf 'bacchus-asn-drift-check: then, in the same commit, set TableRetrieved in core/asn/embedded.go\n' >&2
printf 'bacchus-asn-drift-check: to today and update the retrieval date, hashes and row counts in\n' >&2
printf 'bacchus-asn-drift-check: core/asn/TABLE.md (see docs/RUNNING.md, "Refreshing the table").\n' >&2
exit 2
