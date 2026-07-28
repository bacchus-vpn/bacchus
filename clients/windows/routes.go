//go:build windows

// OS-level network configuration for full-device routing: reading the
// current default route, excluding the coordinator/STUN/TURN endpoints from
// the tunnel (so the WebRTC session itself doesn't loop into the TUN
// device), installing the tunnel's split-default route, blocking IPv6 on the
// physical adapter, and (split-tunnel "include" mode only, issue #64) routing
// specific destinations *into* the tunnel adapter instead of the split-default
// capturing everything.
//
// Everything here shells out to PowerShell's NetTCPIP cmdlets rather than
// calling IP Helper API directly — structured, well-documented, and avoids
// hand-parsing `route print`/`netsh` text output. All of it requires the
// process to be running elevated (Administrator); see README.
package main

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const tunAdapterName = "Bacchus"

// gatewayInfo describes the default route in place before the tunnel comes
// up, so it can be restored / used for exclusion routes and so IPv6 can be
// disabled on the right physical adapter.
type gatewayInfo struct {
	nextHop string
	ifIndex int
	ifAlias string

	// nextHopV6 is the IPv6 default-gateway next hop on the same interface, if
	// any (issue #117) — "" when this interface has no IPv6 default route
	// (common: physical IPv6 is disabled for most of the tunnel's lifetime via
	// disablePhysicalIPv6, and many networks have no IPv6 at all). Populated
	// best-effort by defaultGateway; addExclusionRoutesV6 is a no-op without
	// it, since there is then nothing to route an IPv6 exclusion via.
	nextHopV6 string
}

// createNoWindow is the CREATE_NO_WINDOW process-creation flag. bacchus.exe is
// built -H=windowsgui and has no console of its own, so without this flag every
// child powershell.exe allocates and flashes its own console window. runPS
// fires constantly — route installs, gateway refreshes, kill-switch and
// per-domain split-tunnel updates — so the effect is a storm of console
// windows, not a one-off. CombinedOutput still captures the child's output via
// pipes; only the window is suppressed.
const createNoWindow = 0x08000000

// newPSCmd builds the powershell.exe invocation every OS-config call in this
// file runs, windowless (see createNoWindow).
func newPSCmd(script string) *exec.Cmd {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	return cmd
}

func runPS(script string) (string, error) {
	out, err := newPSCmd(script).CombinedOutput()
	if err != nil {
		// These OS-config calls aren't core.Events, so a failure otherwise leaves no
		// trace in the log — only a truncated tray status. Record the failing
		// command's first line plus PowerShell's actual message; the IPv6-loopback
		// firewall rejection that fail-closed the tunnel was invisible without this.
		//
		// Both are cut to their first line and redacted before logging (issue
		// #140): New-NetRoute and New-NetFirewallRule calls carry the
		// coordinator/exit/relay addresses as literal arguments, and
		// PowerShell's own multi-line error rendering re-echoes the failing
		// source line a second time as part of its "At line:N char:M" position
		// block — a redaction-bypassing copy, since it's PowerShell's own
		// reconstruction rather than anything that flows through redactIPs
		// upstream, and console-width truncation there can hand back a bare
		// fragment of an address (e.g. "203.0.113" with the last octet cut).
		// That block is in the target OS's display language, not necessarily
		// English, so pattern-matching its wording to strip just that part
		// isn't reliable either — first line only sidesteps it entirely. The
		// error message itself (the actual diagnostic value) is always that
		// first line; everything past it is position/category detail this
		// client has never needed to log. bacchus.log is a disk file a user
		// may hand over for support — naming infra addresses on it is a
		// forensic footprint for a client whose whole point is running in a
		// hostile jurisdiction. The returned error below is deliberately left
		// full and unredacted: it only ever reaches the live, ephemeral tray
		// status (setStatus in main.go), never the log file, so it keeps full
		// diagnostic value for the running session.
		first := redactIPs(firstLine(strings.TrimSpace(script)))
		outFirst := redactIPs(firstLine(strings.TrimSpace(string(out))))
		logLine("[tun] ps failed: %s | %s", first, outFirst)
		return "", fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

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
// Applied to anything derived from a PowerShell command or its output before
// it reaches bacchus.log (issue #140). Matches uniformly rather than trying
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

// defaultGateway returns the current best (lowest-metric) IPv4 default
// route: its next hop, and the physical interface carrying it. It also
// best-effort resolves that same interface's IPv6 default route, if any
// (issue #117, gatewayInfo.nextHopV6) — a missing/absent IPv6 route is not an
// error, since most networks and most of the tunnel's lifetime have none
// (disablePhysicalIPv6); only the IPv4 lookup is required to succeed.
func defaultGateway() (gatewayInfo, error) {
	out, err := runPS(`$r = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
		Sort-Object -Property RouteMetric | Select-Object -First 1
	$r6 = Get-NetRoute -DestinationPrefix "::/0" -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue |
		Sort-Object -Property RouteMetric | Select-Object -First 1
	"$($r.NextHop)|$($r.InterfaceIndex)|$($r.InterfaceAlias)|$($r6.NextHop)"`)
	if err != nil {
		return gatewayInfo{}, err
	}
	parts := strings.SplitN(out, "|", 4)
	if len(parts) != 4 {
		return gatewayInfo{}, fmt.Errorf("unexpected Get-NetRoute output: %q", out)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return gatewayInfo{}, fmt.Errorf("bad interface index %q: %v", parts[1], err)
	}
	return gatewayInfo{
		nextHop:   strings.TrimSpace(parts[0]),
		ifIndex:   idx,
		ifAlias:   strings.TrimSpace(parts[2]),
		nextHopV6: strings.TrimSpace(parts[3]),
	}, nil
}

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
// tunnel is up (disablePhysicalIPv6), so today this is defense in depth
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

// addExclusionRoutes routes each prefix via the real default gateway
// (bypassing the tunnel's split-default override) so traffic to it keeps
// flowing over the physical interface instead of looping into the TUN
// device. prefixes may be bare IPs (normalized to a /32 host route) or full
// CIDRs — the control-plane endpoints resolve to bare IPs, while
// destination-based split tunnelling (splittunnel.go) also has whole bypass
// CIDRs to exclude. Used unconditionally for the control-plane endpoints, and
// for the bypass/include set specifically in split-tunnel "exclude" mode.
func addExclusionRoutes(prefixes []string, gw gatewayInfo) {
	for _, p := range prefixes {
		_, _ = runPS(fmt.Sprintf(
			`New-NetRoute -DestinationPrefix "%s" -NextHop "%s" -InterfaceIndex %d -RouteMetric 1 -ErrorAction Stop | Out-Null`,
			ensureCIDR(p), gw.nextHop, gw.ifIndex))
	}
}

// addExclusionRoutesV6 is addExclusionRoutes' IPv6 counterpart (issue #117),
// used by poolExcluder for an IPv6 reality exit address. A no-op when gw has
// no IPv6 default route (nextHopV6 == "") — there is then nothing to route an
// exclusion via, which is safe: physical IPv6 is disabled while the tunnel is
// up regardless (disablePhysicalIPv6), so an unexcluded IPv6 dial fails
// closed rather than leaking.
func addExclusionRoutesV6(prefixes []string, gw gatewayInfo) {
	if gw.nextHopV6 == "" {
		return
	}
	for _, p := range prefixes {
		_, _ = runPS(fmt.Sprintf(
			`New-NetRoute -DestinationPrefix "%s" -NextHop "%s" -InterfaceIndex %d -RouteMetric 1 -ErrorAction Stop | Out-Null`,
			ensureCIDR(p), gw.nextHopV6, gw.ifIndex))
	}
}

// addInclusionRoutes is addExclusionRoutes' mirror for split-tunnel "include"
// mode (issue #64): instead of carving a destination *out* of the tunnel's
// split-default route, it routes the destination *into* the tunnel adapter —
// needed because include mode never installs a split-default in the first
// place (see addSplitDefaultRoute), so without this, the bypass/include set
// itself would never be captured by the netstack at all and would just
// follow the untouched physical default straight past the tunnel. Requires
// the tun adapter to already exist (New-NetIPAddress/CreateTUN), unlike
// addExclusionRoutes which only needs the physical gateway.
func addInclusionRoutes(prefixes []string, tunNextHop string) {
	for _, p := range prefixes {
		_, _ = runPS(fmt.Sprintf(
			`New-NetRoute -InterfaceAlias "%s" -DestinationPrefix "%s" -NextHop "%s" -RouteMetric 1 -ErrorAction Stop | Out-Null`,
			tunAdapterName, ensureCIDR(p), tunNextHop))
	}
}

// removeRoutes deletes each prefix's route, regardless of which direction
// added it (addExclusionRoutes' gateway/physical-interface routes and
// addInclusionRoutes' tun-adapter routes are both plain destination-prefix
// entries to Remove-NetRoute — it has no notion of "which side installed
// this"). In practice tun-bound routes are usually already gone by the time
// this runs: standard Windows adapter-deletion semantics remove every route
// bound to an interface when that interface disappears, so tunnel.go's
// teardown order (dev.Close() before this, in Close()) should already have
// cleared them — this is expected to be a no-op for those and to only do
// real work for the gateway-bound ones. This isn't a new assumption
// specific to include mode: exclude mode's split-default route has always
// been tun-adapter-bound with no explicit removal call of its own either, so
// it has depended on the exact same Windows behavior ever since ADR-0025
// first shipped — addInclusionRoutes' routes are cleaned up by the identical
// mechanism, not a new or less-tested one. Still, it's asserted here from
// documented Windows routing behavior, not verified against a live wintun
// adapter in this change; if a stale tun-bound route is ever observed
// surviving teardown, this is the first assumption to re-check.
//
// -DestinationPrefix alone also means this matches (and deletes) *any* route
// to that prefix, not just the one this package added — a route the user or
// another program independently created to the same destination would be
// removed too. Pre-existing behavior (unchanged by the rename here), not
// specific to include mode.
func removeRoutes(prefixes []string) {
	for _, p := range prefixes {
		_, _ = runPS(fmt.Sprintf(
			`Remove-NetRoute -DestinationPrefix "%s" -Confirm:$false -ErrorAction SilentlyContinue`, ensureCIDR(p)))
	}
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

// configureTunInterface assigns addr/prefixLen to the tunnel adapter.
func configureTunInterface(addr string, prefixLen int) error {
	if _, err := runPS(fmt.Sprintf(
		`New-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -PrefixLength %d -ErrorAction Stop | Out-Null`,
		tunAdapterName, addr, prefixLen)); err != nil {
		return fmt.Errorf("assign tunnel address: %w", err)
	}
	return nil
}

// addSplitDefaultRoute installs 0.0.0.0/1 + 128.0.0.0/1 via addr (treated as
// on-link) — the standard OpenVPN/WireGuard approach on Windows for
// overriding the real default route without removing it. Split-tunnel
// "exclude" mode (the default) needs this: it captures everything into the
// tunnel and relies on addExclusionRoutes to carve out the bypass set.
// "include" mode must NOT call this (issue #64) — it wants the opposite,
// capturing *nothing* by default and pulling only the bypass/include set in
// via addInclusionRoutes instead, so the real default route stays authoritative
// for everything else. Calling this in include mode is exactly the bug #64
// fixed: it would recapture every "direct" dial straight back into the tunnel.
func addSplitDefaultRoute(addr string) error {
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if _, err := runPS(fmt.Sprintf(
			`New-NetRoute -InterfaceAlias "%s" -DestinationPrefix "%s" -NextHop "%s" -ErrorAction Stop | Out-Null`,
			tunAdapterName, prefix, addr)); err != nil {
			return fmt.Errorf("add split-default route %s: %w", prefix, err)
		}
	}
	return nil
}

// disablePhysicalIPv6 turns off the IPv6 binding on the given physical
// adapter so nothing can leak out over IPv6 while the tunnel (IPv4-only in
// this pass) is up.
func disablePhysicalIPv6(ifAlias string) {
	_, _ = runPS(fmt.Sprintf(
		`Disable-NetAdapterBinding -InterfaceAlias "%s" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue`, ifAlias))
}

func enablePhysicalIPv6(ifAlias string) {
	_, _ = runPS(fmt.Sprintf(
		`Enable-NetAdapterBinding -InterfaceAlias "%s" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue`, ifAlias))
}
