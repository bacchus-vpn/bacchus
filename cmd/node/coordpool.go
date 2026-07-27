package main

import "strings"

// parseCoordinators splits a comma-separated -coordinators flag value into a
// trimmed, deduped, order-preserving list of endpoints (issue #6). The engine
// re-normalizes internally, but parsing at the flag layer keeps the CLI honest
// and gives the pool a clean, unit-testable list.
func parseCoordinators(s string) []string { return splitCSV(s) }

// splitCSV trims, drops blanks, and dedups a comma-separated flag value,
// preserving first-seen order. Shared by the coordinator pool (issue #6) and the
// transport pool (issue #15).
func splitCSV(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
