// Log redaction for OS-command diagnostics (issue #140).
//
// Every platform's osNet implementation logs failing OS commands — that is
// what made the IPv6-loopback firewall rejection visible at all — and every
// platform's OS commands carry the coordinator/exit/relay addresses as
// literal arguments. So the obligation is identical on all three, and so is
// the reasoning: the client's log is a disk file a user may hand over for
// support, and naming infra addresses on it is a forensic footprint for a
// tool whose whole point is running in a hostile jurisdiction.
//
// This lives outside the Windows build tag for that reason. It arrived as
// part of clients/internal/enforcement/routes_windows.go's runPS, but nothing in it is
// PowerShell-specific; a Linux implementation shelling out to `ip route` or
// `nft` inherits exactly the same problem, and re-deriving the answer is how
// a platform quietly ships without it.
package enforcement

import (
	"net"
	"regexp"
	"strings"
)

// firstLine returns s up to (not including) its first newline, or s
// unchanged if it has none.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ipCandidatePattern matches substrings shaped like an IPv4 or IPv6 literal —
// bare, or with a "/NN" prefix length — as candidates for redactIPs. It's
// intentionally loose: every match still has to parse via net.ParseIP before
// being redacted, so it can't mangle ordinary command text that merely
// contains a colon or a run of digits and dots (e.g. a DisplayName or a
// -RouteMetric value).
var ipCandidatePattern = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,3})?|[0-9A-Fa-f]*(?::[0-9A-Fa-f]*)+(?:/[0-9]{1,3})?`)

// redactIPs replaces every IP-literal-shaped substring in s with "<ip>".
// Applied to anything derived from an OS command or its output before it
// reaches the client's log (issue #140). Matches uniformly rather than trying
// to single out "sensitive" addresses from the client's own local
// gateway/TUN ones — that's what keeps it robust against whatever call site
// is added next, at the cost of also redacting addresses that were already
// harmless (e.g. the split-default 0.0.0.0/1 prefix).
func redactIPs(s string) string {
	return ipCandidatePattern.ReplaceAllStringFunc(s, func(tok string) string {
		host := tok
		if i := strings.IndexByte(tok, '/'); i >= 0 {
			host = tok[:i]
		}
		if net.ParseIP(host) == nil {
			return tok
		}
		return "<ip>"
	})
}
