// Address handling shared by every platform's osNet implementation:
// turning a configured endpoint into the set of addresses that must be kept
// outside the tunnel, and normalizing an address into the prefix form a route
// call wants.
//
// These came out of clients/internal/enforcement/routes_windows.go, which was 414 lines of which
// only the PowerShell shell-outs are actually Windows-specific. Nothing here
// touches an OS API — it is net.ParseIP, net.LookupHost and string handling —
// so a Linux or macOS implementation ([E10] bacchus#37, [E9] bacchus#36)
// re-deriving it would be re-deriving the same edge cases: hostOf's bracketed
// IPv6 form, ensureCIDR's /128, the IPv4/IPv6 split resolveExclusionsV6 exists
// for (issue #117). Two of those are fixes that were made once, after the
// original shipped; the point of moving them here rather than leaving them
// behind a build tag is that all three platforms get them, and their tests run
// on every push instead of only on a Windows runner.
package enforcement

import (
	"net"
	"strings"
)

// resolveExclusions resolves each "host:port" or "scheme:host:port" endpoint
// to its IPv4 addresses. Bad/unresolvable entries are skipped rather than
// failing the whole connect — losing one exclusion just means that one
// endpoint's own traffic rides the tunnel's default route, which is safe
// (if wasteful) as long as at least the ones that matter resolve.
func resolveExclusions(endpoints ...string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, ep := range endpoints {
		host := hostOf(ep)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			if !seen[ip.String()] {
				seen[ip.String()] = true
				ips = append(ips, ip.String())
			}
			continue
		}
		addrs, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil || ip.To4() == nil || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			ips = append(ips, ip.String())
		}
	}
	return ips
}

// resolveExclusionsV6 is resolveExclusions' IPv6 counterpart (issue #117): a
// separate function, rather than a parameter on resolveExclusions, so every
// existing caller (the control-plane/bypass exclusions, always IPv4 in
// practice) is untouched — only poolExcluder's reserve() calls this, for a
// reality exit address specifically. Physical IPv6 is disabled while the
// tunnel is up (osNet.disablePhysicalIPv6), so today this is defense in depth
// against that posture ever changing or a reselect landing in the narrow
// pre-disable window, not a currently reachable leak.
func resolveExclusionsV6(endpoints ...string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, ep := range endpoints {
		host := hostOf(ep)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() == nil && !seen[ip.String()] {
				seen[ip.String()] = true
				ips = append(ips, ip.String())
			}
			continue
		}
		addrs, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil || ip.To4() != nil || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			ips = append(ips, ip.String())
		}
	}
	return ips
}

// isIPv6Literal reports whether ip (already a parsed, resolved address string
// — as reserve()'s dedup set holds) is IPv6. Used to route an exclusion
// through addExclusionRoutes or its V6 counterpart (issue #117).
func isIPv6Literal(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// hostOf extracts the host from "host:port", "scheme:host:port" (STUN/TURN
// URL forms like "stun:1.2.3.4:3478"), or a bracketed IPv6 "[::1]:port".
// Returns "" if it can't parse one out.
func hostOf(endpoint string) string {
	s := endpoint
	switch {
	case strings.HasPrefix(s, "["):
		// A bracketed IPv6 host:port ("[2001:db8::1]:443") also has 2+ colons
		// but no scheme to strip — net.SplitHostPort below already understands
		// the bracket form directly, so it must be left untouched here rather
		// than falling into the scheme-stripping branch, which would slice
		// into the address itself at its first colon.
	case strings.Contains(s, "://"):
		s = s[strings.Index(s, "://")+3:]
	case strings.Count(s, ":") >= 2:
		// "stun:host:port" — drop the leading scheme.
		s = s[strings.Index(s, ":")+1:]
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return ""
	}
	return host
}

// ensureCIDR normalizes s to a CIDR prefix: a bare IP address becomes a host
// route — /32 for IPv4, /128 for a bare IPv6 literal (issue #117), since
// removeRoutes is family-agnostic and now also reaps IPv6 exclusions
// (poolroutes.go) through this same helper. A value that already has a "/" (a
// real CIDR) passes through unchanged.
func ensureCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
		return s + "/128"
	}
	return s + "/32"
}
