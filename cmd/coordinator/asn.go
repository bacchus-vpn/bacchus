package main

import (
	"fmt"
	"log"

	"github.com/bacchus-vpn/bacchus/core/asn"
)

// Coordinator-side AS resolution (issue #23, ADR-0044).
//
// This is the server half of the AS lookup, and it exists separately from the client
// half for one reason: a coordinator is an operator-run machine that already stages a
// database out of band (-geoip, issue #136), so it can simply be pointed at a table.
// A CLIENT cannot — nobody stages files on a user's laptop, and how a table reaches
// one is the open question ADR-0044 puts to the owner. The seam (core/asn.Lookup) is
// shared; only the way the table arrives differs, and only this side has an answer
// yet.
//
// What it feeds is observedAS (capacity_feed.go), and through it the ~4:1 AS bound
// the capacity estimator denominates Sybil cost in (design §6.4). ADR-0041 line 173
// recorded a real ASN lookup as required before the TRUSTED stream is fed; this is
// that lookup.

// asnTable is the loaded AS table, or nil when none was staged.
//
// Written once in setupASNTable before the packet loop starts and never mutated
// after, so the loop reads it without a lock — the same discipline as geoDB (#136)
// and operators (#124). Nil is a working value, not an error state: every read path
// is nil-safe and resolves every address to unknown, which is exactly the pre-#23
// behaviour (observedAS falls back to the masked prefix).
var asnTable *asn.Table

// setupASNTable loads the table at path, or leaves the coordinator with none.
//
// An unreadable or malformed table is a startup ERROR rather than a warning, which is
// the opposite of how it behaves when no path is given at all. The asymmetry is the
// point: an operator who passed no path has chosen the prefix-mask fallback, while an
// operator who passed a path that does not load has NOT chosen it — they believe AS
// resolution is running. Starting anyway would give them the fallback under the name
// of the real thing, silently, which is the failure mode this whole card is about.
func setupASNTable(path string) error {
	if path == "" {
		return nil
	}
	t, err := asn.Load(path)
	if err != nil {
		return fmt.Errorf("-asn-table: %w", err)
	}
	asnTable = t
	v4, v6 := t.Len()
	log.Printf("AS table: %s (%d IPv4 + %d IPv6 spans) — a capacity attester's AS is resolved from its observed address, not masked to a routing prefix (issue #23)", path, v4, v6)
	return nil
}
